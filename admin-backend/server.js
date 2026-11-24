
"use strict";

const express = require("express");
const cors = require("cors");
const helmet = require("helmet");
const rateLimit = require("express-rate-limit");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const { Pool } = require("pg");

const app = express();
app.disable("x-powered-by");
app.set("trust proxy", 1);

const PORT = process.env.PORT || 10000;
const JWT_SECRET = process.env.JWT_SECRET;
const DATABASE_URL = process.env.DATABASE_URL;

if (!DATABASE_URL) {
  throw new Error("DATABASE_URL is required");
}

if (!JWT_SECRET || JWT_SECRET.length < 32) {
  throw new Error("JWT_SECRET must contain at least 32 characters");
}

const allowedOrigins = (process.env.ADMIN_ORIGIN || "")
  .split(",")
  .map(v => v.trim().replace(/\/$/, ""))
  .filter(Boolean);

app.use(helmet({
  contentSecurityPolicy: false
}));

app.use(express.json({ limit: "20kb" }));

app.use(cors({
  origin(origin, callback) {
    if (!origin || allowedOrigins.includes(origin.replace(/\/$/, ""))) {
      return callback(null, true);
    }
    return callback(new Error("Origin not allowed"));
  },
  methods: ["GET", "POST"],
  allowedHeaders: ["Content-Type", "Authorization"]
}));

const db = new Pool({
  connectionString: DATABASE_URL,
  ssl: { rejectUnauthorized: false },
  max: 5,
  connectionTimeoutMillis: 10000,
  idleTimeoutMillis: 30000
});

const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 8,
  standardHeaders: "draft-7",
  legacyHeaders: false,
  message: { error: "محاولات كثيرة. حاول بعد 15 دقيقة." }
});

const trackLimiter = rateLimit({
  windowMs: 60 * 1000,
  limit: 30,
  standardHeaders: "draft-7",
  legacyHeaders: false
});

const actionLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 20,
  standardHeaders: "draft-7",
  legacyHeaders: false
});

async function init() {
  await db.query(`
    CREATE TABLE IF NOT EXISTS admin_account (
      id integer PRIMARY KEY,
      username text NOT NULL,
      password_hash text NOT NULL,
      version integer NOT NULL DEFAULT 1,
      must_change boolean NOT NULL DEFAULT true
    );

    CREATE TABLE IF NOT EXISTS admin_settings (
      key text PRIMARY KEY,
      value text NOT NULL
    );

    CREATE TABLE IF NOT EXISTS admin_logs (
      id bigserial PRIMARY KEY,
      action text,
      result text,
      created_at timestamptz DEFAULT now()
    );

    CREATE TABLE IF NOT EXISTS page_views (
      id bigserial PRIMARY KEY,
      created_at timestamptz DEFAULT now(),
      device text,
      browser text,
      source text
    );
  `);

  // ترقية قاعدة البيانات إذا كانت أنشئت بالنسخة السابقة
  await db.query(`
    ALTER TABLE admin_account
    ADD COLUMN IF NOT EXISTS must_change boolean NOT NULL DEFAULT true
  `);

  const found = await db.query(
    "SELECT id FROM admin_account WHERE id = 1"
  );

  if (!found.rowCount) {
    const username = process.env.ADMIN_USER || "1234";
    const password = process.env.ADMIN_PASS || "1234";
    const passwordHash = await bcrypt.hash(password, 12);

    await db.query(
      `INSERT INTO admin_account
       (id, username, password_hash, must_change)
       VALUES (1, $1, $2, true)`,
      [username, passwordHash]
    );
  }

  await db.query(`
    INSERT INTO admin_settings(key, value)
    VALUES ('maintenance', 'false')
    ON CONFLICT (key) DO NOTHING
  `);

  console.log("Database initialized");
}

async function log(action, result) {
  try {
    await db.query(
      "INSERT INTO admin_logs(action, result) VALUES($1, $2)",
      [action, result]
    );
  } catch (error) {
    console.error("Log error:", error.message);
  }
}

function createToken(account) {
  return jwt.sign(
    { version: account.version },
    JWT_SECRET,
    { expiresIn: "8h" }
  );
}

async function auth(req, res, next) {
  try {
    const header = req.headers.authorization || "";
    const token = header.startsWith("Bearer ")
      ? header.slice(7)
      : "";

    if (!token) {
      return res.status(401).json({
        error: "سجّل الدخول أولاً"
      });
    }

    const payload = jwt.verify(token, JWT_SECRET);

    const result = await db.query(
      `SELECT version, must_change
       FROM admin_account
       WHERE id = 1`
    );

    if (!result.rowCount ||
        result.rows[0].version !== payload.version) {
      return res.status(401).json({
        error: "انتهت الجلسة، سجّل الدخول مجددًا"
      });
    }

    req.admin = result.rows[0];

    if (req.admin.must_change &&
        req.path !== "/api/credentials") {
      return res.status(403).json({
        error: "يجب تغيير كلمة المرور الأولية أولاً",
        mustChangePassword: true
      });
    }

    next();
  } catch {
    return res.status(401).json({
      error: "الجلسة غير صالحة، سجّل الدخول مجددًا"
    });
  }
}

// فحص صحة الخادم وقاعدة البيانات
app.get("/health", async (req, res) => {
  try {
    await db.query("SELECT 1");
    res.json({ ok: true, database: "connected" });
  } catch {
    res.status(503).json({
      ok: false,
      database: "unavailable"
    });
  }
});

// تسجيل الدخول
app.post("/api/login", loginLimiter, async (req, res) => {
  try {
    const username = String(req.body.username || "");
    const password = String(req.body.password || "");

    const result = await db.query(
      "SELECT * FROM admin_account WHERE id = 1"
    );

    const account = result.rows[0];

    if (!account ||
        account.username !== username ||
        !(await bcrypt.compare(password, account.password_hash))) {
      await log("تسجيل الدخول", "مرفوض");

      return res.status(401).json({
        error: "اسم المستخدم أو كلمة المرور غير صحيحة"
      });
    }

    await log("تسجيل الدخول", "ناجح");

    return res.json({
      token: createToken(account),
      mustChangePassword: account.must_change
    });
  } catch (error) {
    console.error("Login error:", error.message);

    return res.status(500).json({
      error: "حدث خطأ داخلي"
    });
  }
});

// تغيير بيانات الدخول، ويستخدم أيضًا لأول دخول
app.post("/api/credentials", auth, actionLimiter, async (req, res) => {
  try {
    const username = String(req.body.username || "");
    const oldPassword = String(req.body.oldPassword || "");
    const newPassword = String(req.body.newPassword || "");

    if (!/^[a-zA-Z0-9_.-]{3,32}$/.test(username)) {
      return res.status(400).json({
        error: "اسم المستخدم يجب أن يكون 3 إلى 32 حرفًا أو رقمًا"
      });
    }

    if (newPassword.length < 12) {
      return res.status(400).json({
        error: "كلمة المرور الجديدة يجب أن تكون 12 حرفًا على الأقل"
      });
    }

    const result = await db.query(
      "SELECT * FROM admin_account WHERE id = 1"
    );

    const account = result.rows[0];

    if (!account ||
        !(await bcrypt.compare(oldPassword, account.password_hash))) {
      return res.status(401).json({
        error: "كلمة المرور الحالية غير صحيحة"
      });
    }

    const passwordHash = await bcrypt.hash(newPassword, 12);

    const updated = await db.query(
      `UPDATE admin_account
       SET username = $1,
           password_hash = $2,
           must_change = false,
           version = version + 1
       WHERE id = 1
       RETURNING version, must_change`,
      [username, passwordHash]
    );

    await log("تغيير بيانات الدخول", "ناجح");

    return res.json({
      token: createToken(updated.rows[0]),
      mustChangePassword: false,
      message: "تم تغيير بيانات الدخول"
    });
  } catch (error) {
    console.error("Credentials error:", error.message);

    return res.status(500).json({
      error: "تعذر تحديث بيانات الدخول"
    });
  }
});

// استقبال إحصائيات الزيارات عند ربط الموقع بها
app.post("/api/track", trackLimiter, async (req, res) => {
  try {
    const ua = req.headers["user-agent"] || "";

    const device =
      /Android|iPhone|Mobile|iPad/i.test(ua)
        ? "جوال"
        : "كمبيوتر";

    const browser =
      /Edg\//.test(ua) ? "Edge" :
      /Firefox\//.test(ua) ? "Firefox" :
      /Chrome\//.test(ua) ? "Chrome" :
      /Safari\//.test(ua) ? "Safari" :
      "غير معروف";

    let source = "مباشر";

    try {
      if (req.body && req.body.referrer) {
        source = new URL(req.body.referrer).hostname.slice(0, 150);
      }
    } catch {}

    await db.query(
      `INSERT INTO page_views(device, browser, source)
       VALUES($1, $2, $3)`,
      [device, browser, source]
    );

    return res.status(204).end();
  } catch (error) {
    console.error("Tracking error:", error.message);
    return res.status(204).end();
  }
});

// إحصائيات لوحة الإدارة
app.get("/api/overview", auth, async (req, res) => {
  try {
    const [today, month, active, visits, setting] = await Promise.all([
      db.query(`
        SELECT count(*)::int AS n
        FROM page_views
        WHERE created_at >= date_trunc('day', now())
      `),
      db.query(`
        SELECT count(*)::int AS n
        FROM page_views
        WHERE created_at >= now() - interval '30 days'
      `),
      db.query(`
        SELECT count(*)::int AS n
        FROM page_views
        WHERE created_at >= now() - interval '5 minutes'
      `),
      db.query(`
        SELECT *
        FROM page_views
        ORDER BY created_at DESC
        LIMIT 30
      `),
      db.query(`
        SELECT value
        FROM admin_settings
        WHERE key = 'maintenance'
      `)
    ]);

    return res.json({
      today: today.rows[0].n,
      month: month.rows[0].n,
      active: active.rows[0].n,
      visits: visits.rows,
      tracking: month.rows[0].n > 0,
      maintenance: setting.rows[0]?.value === "true",
      serverTime: new Date().toISOString()
    });
  } catch (error) {
    console.error("Overview error:", error.message);

    return res.status(500).json({
      error: "تعذر تحميل الإحصائيات"
    });
  }
});

// تفعيل أو إلغاء وضع الصيانة في إعدادات الإدارة
app.post("/api/maintenance", auth, actionLimiter, async (req, res) => {
  try {
    const enabled = req.body.enabled === true;

    await db.query(
      `INSERT INTO admin_settings(key, value)
       VALUES ('maintenance', $1)
       ON CONFLICT (key)
       DO UPDATE SET value = EXCLUDED.value`,
      [String(enabled)]
    );

    await log(
      "وضع الصيانة",
      enabled ? "تفعيل" : "إلغاء"
    );

    return res.json({
      maintenance: enabled,
      message: "تم حفظ حالة الصيانة"
    });
  } catch (error) {
    console.error("Maintenance error:", error.message);

    return res.status(500).json({
      error: "تعذر تحديث وضع الصيانة"
    });
  }
});

// سجل العمليات
app.get("/api/logs", auth, async (req, res) => {
  try {
    const result = await db.query(
      `SELECT *
       FROM admin_logs
       ORDER BY created_at DESC
       LIMIT 100`
    );

    return res.json({ logs: result.rows });
  } catch (error) {
    console.error("Logs error:", error.message);

    return res.status(500).json({
      error: "تعذر تحميل السجلات"
    });
  }
});

// إيقاف أو استئناف خدمة Render محددة
app.post("/api/site/:action", auth, actionLimiter, async (req, res) => {
  const action = req.params.action;

  if (!["suspend", "resume"].includes(action)) {
    return res.status(400).json({
      error: "عملية غير معروفة"
    });
  }

  const renderKey = process.env.RENDER_API_KEY;
  const serviceId = process.env.TARGET_SERVICE_ID;

  if (!renderKey || !serviceId) {
    return res.status(503).json({
      error: "لم يتم إعداد بيانات Render في الخادم"
    });
  }

  try {
    const response = await fetch(
      `https://api.render.com/v1/services/${encodeURIComponent(serviceId)}/${action}`,
      {
        method: "POST",
        headers: {
          Authorization: `Bearer ${renderKey}`,
          Accept: "application/json"
        }
      }
    );

    if (!response.ok) {
      const details = await response.text();

      console.error("Render API error:", response.status, details);

      return res.status(502).json({
        error: `تعذر تنفيذ العملية لدى Render (${response.status})`
      });
    }

    await log(
      action === "suspend" ? "إيقاف الخدمة" : "استئناف الخدمة",
      "تم إرسال الطلب"
    );

    return res.json({
      message: "تم إرسال الطلب إلى Render"
    });
  } catch (error) {
    console.error("Render request error:", error.message);

    return res.status(502).json({
      error: "تعذر الاتصال بـ Render"
    });
  }
});

// أخطاء CORS والطلبات غير المعالجة
app.use((err, req, res, next) => {
  if (res.headersSent) return next(err);

  if (err.message === "Origin not allowed") {
    return res.status(403).json({
      error: "هذا المصدر غير مسموح"
    });
  }

  console.error("Request error:", err.message);

  return res.status(500).json({
    error: "حدث خطأ داخلي"
  });
});

// لا يبدأ الخادم إلا بعد نجاح تهيئة قاعدة البيانات
async function start() {
  try {
    await init();

    app.listen(PORT, "0.0.0.0", () => {
      console.log(`BASAM ADMIN API running on port ${PORT}`);
    });
  } catch (error) {
    console.error("Startup failed:", error);
    process.exit(1);
  }
}

start();
