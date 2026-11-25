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

if (!DATABASE_URL) throw new Error("DATABASE_URL is required");

if (!JWT_SECRET || JWT_SECRET.length < 32) {
  throw new Error("JWT_SECRET must contain at least 32 characters");
}

const allowedOrigins = (process.env.ADMIN_ORIGIN || "")
  .split(",")
  .map(v => v.trim().replace(/\/$/, ""))
  .filter(Boolean);

app.use(helmet({ contentSecurityPolicy: false }));
app.use(express.json({ limit: "20kb" }));

app.use(cors({
  origin(origin, callback) {
    if (!origin || allowedOrigins.includes(origin.replace(/\/$/, ""))) {
      return callback(null, true);
    }
    return callback(new Error("Origin not allowed"));
  },
  methods: ["GET", "POST", "PATCH", "DELETE", "OPTIONS"],
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

// ========================================
// DATABASE
// ========================================

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

    CREATE TABLE IF NOT EXISTS admin_staff (
      id bigserial PRIMARY KEY,
      username text NOT NULL UNIQUE,
      password_hash text NOT NULL,
      role text NOT NULL
        CHECK (role IN ('ADMIN', 'MODERATOR')),
      active boolean NOT NULL DEFAULT true,
      version integer NOT NULL DEFAULT 1,
      must_change boolean NOT NULL DEFAULT true,
      created_at timestamptz DEFAULT now()
    );
  `);

  const found = await db.query(
    "SELECT id FROM admin_account WHERE id = 1"
  );

  if (!found.rowCount) {
    const username = process.env.ADMIN_USER;
    const password = process.env.ADMIN_PASS;

    if (!username || !password || password.length < 12) {
      throw new Error(
        "First setup requires ADMIN_USER and ADMIN_PASS (12+ characters)"
      );
    }

    const passwordHash = await bcrypt.hash(password, 12);

    await db.query(
      `INSERT INTO admin_account
       (id, username, password_hash, must_change)
       VALUES (1, $1, $2, true)`,
      [username, passwordHash]
    );

    console.log("Initial SUPER ADMIN created");
  }

  await db.query(`
    INSERT INTO admin_settings(key, value)
    VALUES ('maintenance', 'false')
    ON CONFLICT (key) DO NOTHING
  `);

  console.log("Database initialized");
}

// ========================================
// LOGGING
// ========================================

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

// ========================================
// TOKENS
// ========================================

function createToken(account) {
  return jwt.sign(
    {
      type: account.type,
      id: account.id,
      version: account.version
    },
    JWT_SECRET,
    { expiresIn: "8h" }
  );
}

// ========================================
// AUTHENTICATION
// ========================================

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

    let account;

    if (payload.type === "super" && payload.id === 1) {
      const result = await db.query(
        `SELECT id, username, version, must_change
         FROM admin_account WHERE id = 1`
      );

      account = result.rows[0];

      if (account) account.role = "SUPER_ADMIN";

    } else if (payload.type === "staff") {
      const result = await db.query(
        `SELECT id, username, role, active, version, must_change
         FROM admin_staff WHERE id = $1`,
        [payload.id]
      );

      account = result.rows[0];

      if (account && !account.active) {
        return res.status(403).json({
          error: "تم تعطيل هذا الحساب"
        });
      }
    }

    if (
      !account ||
      account.version !== payload.version
    ) {
      return res.status(401).json({
        error: "انتهت الجلسة، سجّل الدخول مجددًا"
      });
    }

    req.admin = {
      ...account,
      type: payload.type
    };

    if (
      req.admin.must_change &&
      req.path !== "/api/credentials"
    ) {
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

// ========================================
// ROLE PERMISSIONS
// ========================================

function requireSuperAdmin(req, res, next) {
  if (req.admin?.role !== "SUPER_ADMIN") {
    return res.status(403).json({
      error: "هذه الصلاحية خاصة بالسوبر أدمن"
    });
  }

  next();
}

// ========================================
// HEALTH
// ========================================

app.get("/health", async (req, res) => {
  try {
    await db.query("SELECT 1");

    res.json({
      ok: true,
      database: "connected",
      environment: "BASAM TEST"
    });

  } catch {
    res.status(503).json({
      ok: false,
      database: "unavailable"
    });
  }
});

// ========================================
// LOGIN
// ========================================

app.post("/api/login", loginLimiter, async (req, res) => {
  try {
    const username = String(req.body.username || "").trim();
    const password = String(req.body.password || "");

    if (!username || !password) {
      return res.status(400).json({
        error: "أدخل اسم المستخدم وكلمة المرور"
      });
    }

    // SUPER ADMIN
    const superResult = await db.query(
      "SELECT * FROM admin_account WHERE id = 1"
    );

    const superAccount = superResult.rows[0];

    if (
      superAccount &&
      superAccount.username === username &&
      await bcrypt.compare(password, superAccount.password_hash)
    ) {
      const account = {
        ...superAccount,
        type: "super"
      };

      await log("تسجيل دخول SUPER ADMIN", "ناجح");

      return res.json({
        token: createToken(account),
        username: account.username,
        role: "SUPER_ADMIN",
        mustChangePassword: account.must_change
      });
    }

    // STAFF
    const staffResult = await db.query(
      "SELECT * FROM admin_staff WHERE username = $1",
      [username]
    );

    const staff = staffResult.rows[0];

    if (
      staff &&
      staff.active &&
      await bcrypt.compare(password, staff.password_hash)
    ) {
      const account = {
        ...staff,
        type: "staff"
      };

      await log(
        `تسجيل دخول ${staff.role}`,
        "ناجح"
      );

      return res.json({
        token: createToken(account),
        username: staff.username,
        role: staff.role,
        mustChangePassword: staff.must_change
      });
    }

    await log("محاولة تسجيل دخول", "مرفوض");

    return res.status(401).json({
      error: "اسم المستخدم أو كلمة المرور غير صحيحة"
    });

  } catch (error) {
    console.error("Login error:", error.message);

    return res.status(500).json({
      error: "حدث خطأ داخلي"
    });
  }
});

// ========================================
// CURRENT ACCOUNT
// ========================================

app.get("/api/me", auth, async (req, res) => {
  res.json({
    id: req.admin.id,
    username: req.admin.username,
    role: req.admin.role,
    mustChangePassword: req.admin.must_change
  });
});

// ========================================
// STAFF MANAGEMENT
// SUPER ADMIN ONLY
// ========================================

// List accounts
app.get(
  "/api/admins",
  auth,
  requireSuperAdmin,
  async (req, res) => {
    try {
      const result = await db.query(`
        SELECT id, username, role, active,
               must_change, created_at
        FROM admin_staff
        ORDER BY created_at DESC
      `);

      res.json({
        admins: result.rows
      });

    } catch (error) {
      console.error("Admins list error:", error.message);

      res.status(500).json({
        error: "تعذر تحميل الحسابات"
      });
    }
  }
);

// Create ADMIN or MODERATOR
app.post(
  "/api/admins",
  auth,
  requireSuperAdmin,
  actionLimiter,
  async (req, res) => {
    try {
      const username = String(req.body.username || "").trim();
      const password = String(req.body.password || "");
      const role = String(req.body.role || "").toUpperCase();

      if (!/^[a-zA-Z0-9_.-]{3,32}$/.test(username)) {
        return res.status(400).json({
          error: "اسم المستخدم يجب أن يكون 3 إلى 32 حرفًا أو رقمًا"
        });
      }

      if (password.length < 12) {
        return res.status(400).json({
          error: "كلمة المرور يجب أن تكون 12 حرفًا على الأقل"
        });
      }

      if (!["ADMIN", "MODERATOR"].includes(role)) {
        return res.status(400).json({
          error: "الرتبة غير مسموحة"
        });
      }

      const superUser = await db.query(
        "SELECT id FROM admin_account WHERE username = $1",
        [username]
      );

      if (superUser.rowCount) {
        return res.status(409).json({
          error: "اسم المستخدم مستخدم بالفعل"
        });
      }

      const passwordHash = await bcrypt.hash(password, 12);

      const result = await db.query(
        `INSERT INTO admin_staff
         (username, password_hash, role, active, must_change)
         VALUES ($1, $2, $3, true, true)
         RETURNING id, username, role, active, created_at`,
        [username, passwordHash, role]
      );

      await log(
        "إنشاء حساب إداري",
        `${username} - ${role}`
      );

      res.status(201).json({
        message: "تم إنشاء الحساب",
        admin: result.rows[0]
      });

    } catch (error) {
      if (error.code === "23505") {
        return res.status(409).json({
          error: "اسم المستخدم مستخدم بالفعل"
        });
      }

      console.error("Create admin error:", error.message);

      res.status(500).json({
        error: "تعذر إنشاء الحساب"
      });
    }
  }
);

// Change role or activate/deactivate
app.patch(
  "/api/admins/:id",
  auth,
  requireSuperAdmin,
  actionLimiter,
  async (req, res) => {
    try {
      const id = Number(req.params.id);

      if (!Number.isInteger(id) || id <= 0) {
        return res.status(400).json({
          error: "رقم الحساب غير صحيح"
        });
      }

      const role = req.body.role === undefined
        ? undefined
        : String(req.body.role).toUpperCase();

      const active = req.body.active;

      if (
        role !== undefined &&
        !["ADMIN", "MODERATOR"].includes(role)
      ) {
        return res.status(400).json({
          error: "لا يمكن تعيين هذه الرتبة"
        });
      }

      if (
        active !== undefined &&
        typeof active !== "boolean"
      ) {
        return res.status(400).json({
          error: "حالة الحساب غير صحيحة"
        });
      }

      if (role === undefined && active === undefined) {
        return res.status(400).json({
          error: "لم يتم إرسال أي تعديل"
        });
      }

      const result = await db.query(
        `UPDATE admin_staff
         SET role = COALESCE($1, role),
             active = COALESCE($2, active),
             version = version + 1
         WHERE id = $3
         RETURNING id, username, role, active, created_at`,
        [role ?? null, active ?? null, id]
      );

      if (!result.rowCount) {
        return res.status(404).json({
          error: "الحساب غير موجود"
        });
      }

      await log(
        "تعديل حساب إداري",
        `${result.rows[0].username}`
      );

      res.json({
        message: "تم تحديث الحساب وإبطال جلساته",
        admin: result.rows[0]
      });

    } catch (error) {
      console.error("Update admin error:", error.message);

      res.status(500).json({
        error: "تعذر تحديث الحساب"
      });
    }
  }
);

// Delete staff account
app.delete(
  "/api/admins/:id",
  auth,
  requireSuperAdmin,
  actionLimiter,
  async (req, res) => {
    try {
      const id = Number(req.params.id);

      if (!Number.isInteger(id) || id <= 0) {
        return res.status(400).json({
          error: "رقم الحساب غير صحيح"
        });
      }

      const result = await db.query(
        `DELETE FROM admin_staff
         WHERE id = $1
         RETURNING username`,
        [id]
      );

      if (!result.rowCount) {
        return res.status(404).json({
          error: "الحساب غير موجود"
        });
      }

      await log(
        "حذف حساب إداري",
        result.rows[0].username
      );

      res.json({
        message: "تم حذف الحساب"
      });

    } catch (error) {
      console.error("Delete admin error:", error.message);

      res.status(500).json({
        error: "تعذر حذف الحساب"
      });
    }
  }
);

// ========================================
// CHANGE OWN CREDENTIALS
// ========================================

app.post(
  "/api/credentials",
  auth,
  actionLimiter,
  async (req, res) => {
    try {
      const username = String(req.body.username || "").trim();
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

      let table;
      let account;

      if (req.admin.type === "super") {
        const result = await db.query(
          "SELECT * FROM admin_account WHERE id = 1"
        );

        account = result.rows[0];
        table = "super";

      } else {
        const result = await db.query(
          "SELECT * FROM admin_staff WHERE id = $1",
          [req.admin.id]
        );

        account = result.rows[0];
        table = "staff";
      }

      if (
        !account ||
        !(await bcrypt.compare(oldPassword, account.password_hash))
      ) {
        return res.status(401).json({
          error: "كلمة المرور الحالية غير صحيحة"
        });
      }

      // Prevent duplicate usernames
      const duplicateSuper = await db.query(
        `SELECT id FROM admin_account
         WHERE username = $1 AND id <> $2`,
        [username, table === "super" ? 1 : -1]
      );

      const duplicateStaff = await db.query(
        `SELECT id FROM admin_staff
         WHERE username = $1 AND id <> $2`,
        [username, table === "staff" ? req.admin.id : -1]
      );

      if (duplicateSuper.rowCount || duplicateStaff.rowCount) {
        return res.status(409).json({
          error: "اسم المستخدم مستخدم بالفعل"
        });
      }

      const passwordHash = await bcrypt.hash(newPassword, 12);

      let updated;

      if (table === "super") {
        updated = await db.query(
          `UPDATE admin_account
           SET username = $1,
               password_hash = $2,
               must_change = false,
               version = version + 1
           WHERE id = 1
           RETURNING id, username, version, must_change`,
          [username, passwordHash]
        );

      } else {
        updated = await db.query(
          `UPDATE admin_staff
           SET username = $1,
               password_hash = $2,
               must_change = false,
               version = version + 1
           WHERE id = $3
           RETURNING id, username, role, version, must_change`,
          [username, passwordHash, req.admin.id]
        );
      }

      const newAccount = {
        ...updated.rows[0],
        type: table
      };

      await log(
        "تغيير بيانات الدخول",
        `${username} - ${req.admin.role}`
      );

      res.json({
        token: createToken(newAccount),
        username,
        role: req.admin.role,
        mustChangePassword: false,
        message: "تم تغيير بيانات الدخول"
      });

    } catch (error) {
      console.error("Credentials error:", error.message);

      res.status(500).json({
        error: "تعذر تحديث بيانات الدخول"
      });
    }
  }
);

// ========================================
// TRACKING
// ========================================

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

// ========================================
// OVERVIEW
// ========================================

app.get("/api/overview", auth, async (req, res) => {
  try {
    const tracker = await db.query(`
      SELECT to_regclass('public.tracker_visits') AS table_name
    `);

    let today;
    let month;
    let active;
    let visits;

    if (tracker.rows[0].table_name) {
      [today, month, active, visits] = await Promise.all([
        db.query(`
          SELECT count(*)::int AS n
          FROM tracker_visits
          WHERE visited_at >= date_trunc('day', now())
        `),
        db.query(`
          SELECT count(*)::int AS n
          FROM tracker_visits
          WHERE visited_at >= now() - interval '30 days'
        `),
        db.query(`
          SELECT count(*)::int AS n
          FROM tracker_visits
          WHERE visited_at >= now() - interval '5 minutes'
        `),
        db.query(`
          SELECT id, visited_at AS created_at,
                 page_path, referrer,
                 'غير متاح' AS device,
                 'غير متاح' AS browser,
                 COALESCE(NULLIF(referrer, ''), 'مباشر') AS source
          FROM tracker_visits
          ORDER BY visited_at DESC
          LIMIT 30
        `)
      ]);

    } else {
      [today, month, active, visits] = await Promise.all([
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
          SELECT id, created_at,
                 NULL::text AS page_path,
                 source AS referrer,
                 device, browser, source
          FROM page_views
          ORDER BY created_at DESC
          LIMIT 30
        `)
      ]);
    }

    const setting = await db.query(`
      SELECT value FROM admin_settings
      WHERE key = 'maintenance'
    `);

    res.json({
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

    res.status(500).json({
      error: "تعذر تحميل الإحصائيات"
    });
  }
});

// ========================================
// MAINTENANCE
// SUPER ADMIN ONLY
// ========================================

app.post(
  "/api/maintenance",
  auth,
  requireSuperAdmin,
  actionLimiter,
  async (req, res) => {
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

      res.json({
        maintenance: enabled,
        message: "تم حفظ حالة الصيانة"
      });

    } catch (error) {
      console.error("Maintenance error:", error.message);

      res.status(500).json({
        error: "تعذر تحديث وضع الصيانة"
      });
    }
  }
);

// ========================================
// LOGS
// ========================================

app.get("/api/logs", auth, async (req, res) => {
  try {
    const result = await db.query(
      `SELECT * FROM admin_logs
       ORDER BY created_at DESC
       LIMIT 100`
    );

    res.json({
      logs: result.rows
    });

  } catch (error) {
    console.error("Logs error:", error.message);

    res.status(500).json({
      error: "تعذر تحميل السجلات"
    });
  }
});

// ========================================
// RENDER CONTROL
// DISABLED BY DEFAULT
// ========================================

app.post(
  "/api/site/:action",
  auth,
  requireSuperAdmin,
  actionLimiter,
  async (req, res) => {
    const action = req.params.action;

    if (!["suspend", "resume"].includes(action)) {
      return res.status(400).json({
        error: "عملية غير معروفة"
      });
    }

    // Test environment safety lock
    if (process.env.ALLOW_RENDER_CONTROL !== "true") {
      return res.status(403).json({
        error: "التحكم في Render معطّل في نسخة الاختبار"
      });
    }

    const renderKey = process.env.RENDER_API_KEY;
    const serviceId = process.env.TARGET_SERVICE_ID;

    if (!renderKey || !serviceId) {
      return res.status(503).json({
        error: "لم يتم إعداد بيانات Render"
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

        console.error(
          "Render API error:",
          response.status,
          details
        );

        return res.status(502).json({
          error: `تعذر تنفيذ العملية لدى Render (${response.status})`
        });
      }

      await log(
        action === "suspend" ? "إيقاف الخدمة" : "استئناف الخدمة",
        "تم إرسال الطلب"
      );

      res.json({
        message: "تم إرسال الطلب إلى Render"
      });

    } catch (error) {
      console.error("Render request error:", error.message);

      res.status(502).json({
        error: "تعذر الاتصال بـ Render"
      });
    }
  }
);

// ========================================
// ERROR HANDLER
// ========================================

app.use((err, req, res, next) => {
  if (res.headersSent) return next(err);

  if (err.message === "Origin not allowed") {
    return res.status(403).json({
      error: "هذا المصدر غير مسموح"
    });
  }

  console.error("Request error:", err.message);

  res.status(500).json({
    error: "حدث خطأ داخلي"
  });
});

// ========================================
// START SERVER
// ========================================

async function start() {
  try {
    await init();

    app.listen(PORT, "0.0.0.0", () => {
      console.log(`BASAM TEST API running on port ${PORT}`);
    });

  } catch (error) {
    console.error("Startup failed:", error);
    process.exit(1);
  }
}
start();