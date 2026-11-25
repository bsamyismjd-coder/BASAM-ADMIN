"use strict";

const express = require("express");
const cors = require("cors");
const helmet = require("helmet");
const rateLimit = require("express-rate-limit");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const { Pool } = require("pg");
const os = require("os");

const app = express();
app.set("trust proxy", 1);

const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET;
const DATABASE_URL = process.env.DATABASE_URL;
const ADMIN_USER = process.env.ADMIN_USER;
const ADMIN_PASS = process.env.ADMIN_PASS;
const ALLOW_RENDER_CONTROL = process.env.ALLOW_RENDER_CONTROL === "true";

if (!JWT_SECRET || JWT_SECRET.length < 32) {
  throw new Error("JWT_SECRET must be at least 32 characters.");
}
if (!DATABASE_URL) {
  throw new Error("DATABASE_URL is required.");
}

const db = new Pool({
  connectionString: DATABASE_URL,
  ssl: { rejectUnauthorized: false },
  max: 5,
  idleTimeoutMillis: 30000,
  connectionTimeoutMillis: 10000
});

const allowedOrigins = (process.env.ADMIN_ORIGIN || "")
  .split(",")
  .map(x => x.trim())
  .filter(Boolean);

app.use(helmet({ contentSecurityPolicy: false }));
app.use(cors({
  origin(origin, callback) {
    if (!origin || allowedOrigins.length === 0 || allowedOrigins.includes(origin)) {
      return callback(null, true);
    }
    callback(new Error("Origin not allowed"));
  },
  credentials: true
}));
app.use(express.json({ limit: "1mb" }));

const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 10,
  standardHeaders: true,
  legacyHeaders: false
});

const actionLimiter = rateLimit({
  windowMs: 60 * 1000,
  limit: 60,
  standardHeaders: true,
  legacyHeaders: false
});

const publicLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 8,
  standardHeaders: true,
  legacyHeaders: false
});

const PERMISSION_CATALOG = {
  "overview.view": "عرض الرئيسية",
  "visitors.view": "عرض الزوار",
  "system.view": "مراقبة النظام",
  "security.view": "مركز الأمان",
  "logs.view": "سجل النشاط",
  "maintenance.manage": "إدارة وضع الصيانة",
  "review.manage": "قفل وفتح المراجعة",
  "notifications.view": "عرض الإشعارات",
  "notifications.manage": "إدارة الإشعارات",
  "users.view": "عرض المستخدمين",
  "chess.view": "تحليلات الشطرنج",
  "support.view": "عرض الدعم",
  "support.manage": "إدارة الدعم",
  "ads.view": "عرض الإعلانات",
  "ads.manage": "إدارة الإعلانات",
  "reports.view": "التقارير",
  "settings.view": "عرض الإعدادات",
  "settings.manage": "إدارة الإعدادات"
};

const DEFAULT_STAFF_PERMISSIONS = [
  "overview.view",
  "visitors.view",
  "system.view",
  "security.view",
  "logs.view"
];

const SAFE_SETTINGS = [
  "maintenance_enabled",
  "maintenance_message",
  "review_locked",
  "review_lock_message",
  "site_name",
  "support_email"
];

const asyncHandler = fn => (req, res, next) =>
  Promise.resolve(fn(req, res, next)).catch(next);

const isSuperAdmin = admin =>
  admin &&
  admin.type === "super" &&
  admin.role === "SUPER_ADMIN" &&
  Number(admin.id) === 1;

function maskIp(ip) {
  if (!ip) return null;
  ip = String(ip).replace(/^::ffff:/, "");
  if (ip.includes(".")) {
    const p = ip.split(".");
    if (p.length === 4) {
      p[3] = "xxx";
      return p.join(".");
    }
  }
  if (ip.includes(":")) return ip.split(":").slice(0, 3).join(":") + ":…";
  return null;
}

async function securityEvent(req, type, username, result) {
  try {
    await db.query(
      `INSERT INTO admin_security_events
       (event_type, username, result, masked_ip, user_agent)
       VALUES ($1,$2,$3,$4,$5)`,
      [
        type,
        String(username || "").slice(0, 100),
        String(result || "").slice(0, 40),
        maskIp(req.ip),
        String(req.headers["user-agent"] || "").slice(0, 300)
      ]
    );
  } catch (e) {
    console.error("Security event error:", e.message);
  }
}

async function getStaffPermissions(staffId, client = db) {
  const result = await client.query(
    "SELECT permission FROM admin_staff_permissions WHERE staff_id=$1",
    [staffId]
  );
  return result.rows.map(r => r.permission);
}

async function saveStaffPermissions(client, staffId, permissions) {
  await client.query(
    "DELETE FROM admin_staff_permissions WHERE staff_id=$1",
    [staffId]
  );

  for (const permission of permissions) {
    await client.query(
      `INSERT INTO admin_staff_permissions (staff_id, permission)
       VALUES ($1,$2) ON CONFLICT DO NOTHING`,
      [staffId, permission]
    );
  }
}

function validatePermissions(input) {
  if (!Array.isArray(input)) {
    throw new Error("permissions must be an array");
  }

  const permissions = [...new Set(input)];

  for (const permission of permissions) {
    if (
      typeof permission !== "string" ||
      !Object.prototype.hasOwnProperty.call(PERMISSION_CATALOG, permission)
    ) {
      throw new Error("Invalid permission: " + permission);
    }
  }

  return permissions;
}

async function auth(req, res, next) {
  try {
    const header = req.headers.authorization || "";
    const token = header.startsWith("Bearer ") ? header.slice(7) : "";

    if (!token) {
      return res.status(401).json({ error: "Authentication required" });
    }

    const decoded = jwt.verify(token, JWT_SECRET);

    let result;

    if (decoded.type === "super") {
      result = await db.query(
        `SELECT id, username, role, active, version, must_change
         FROM admin_account WHERE id=$1`,
        [decoded.id]
      );
    } else {
      result = await db.query(
        `SELECT id, username, role, active, version, must_change
         FROM admin_staff WHERE id=$1`,
        [decoded.id]
      );
    }

    if (!result.rows.length) {
      return res.status(401).json({ error: "Account not found" });
    }

    const row = result.rows[0];

    if (!row.active || Number(row.version) !== Number(decoded.version)) {
      return res.status(401).json({ error: "Session expired" });
    }

    let permissions = [];

    const admin = {
      id: Number(row.id),
      username: row.username,
      role: row.role,
      type: decoded.type,
      active: row.active,
      must_change: row.must_change,
      permissions: []
    };

    if (isSuperAdmin(admin)) {
      permissions = Object.keys(PERMISSION_CATALOG);
    } else if (decoded.type === "staff") {
      permissions = await getStaffPermissions(row.id);
    }

    admin.permissions = permissions;
    req.admin = admin;

    if (admin.must_change && req.path !== "/api/credentials") {
      return res.status(403).json({
        error: "Password change required",
        code: "MUST_CHANGE_PASSWORD"
      });
    }

    next();
  } catch (e) {
    if (e.name === "TokenExpiredError" || e.name === "JsonWebTokenError") {
      return res.status(401).json({ error: "Invalid or expired session" });
    }
    next(e);
  }
}

function requireSuperAdmin(req, res, next) {
  if (!isSuperAdmin(req.admin)) {
    return res.status(403).json({ error: "Super admin only" });
  }
  next();
}

function requirePermission(permission) {
  return (req, res, next) => {
    if (isSuperAdmin(req.admin)) return next();

    if (!req.admin.permissions.includes(permission)) {
      return res.status(403).json({
        error: "Permission denied",
        permission
      });
    }

    next();
  };
}

function issueToken(admin) {
  return jwt.sign({
    id: admin.id,
    type: admin.type,
    version: Number(admin.version)
  }, JWT_SECRET, { expiresIn: "8h" });
}

async function setting(key, fallback = null) {
  const result = await db.query(
    "SELECT value FROM admin_settings WHERE key=$1",
    [key]
  );
  return result.rows.length ? result.rows[0].value : fallback;
}

async function saveSetting(key, value) {
  await db.query(
    `INSERT INTO admin_settings (key,value)
     VALUES ($1,$2)
     ON CONFLICT (key) DO UPDATE SET value=EXCLUDED.value`,
    [key, String(value)]
  );
}

async function writeLog(req, action, details = "") {
  try {
    await db.query(
      `INSERT INTO admin_logs (admin_id, username, action, details, created_at)
       VALUES ($1,$2,$3,$4,NOW())`,
      [
        req.admin?.id || null,
        req.admin?.username || "system",
        String(action).slice(0, 100),
        String(details).slice(0, 1000)
      ]
    );
  } catch (e) {
    console.error("Log error:", e.message);
  }
}

async function init() {
  await db.query(`
    CREATE TABLE IF NOT EXISTS admin_account (
      id SERIAL PRIMARY KEY,
      username VARCHAR(100) UNIQUE NOT NULL,
      password_hash TEXT NOT NULL,
      role VARCHAR(50) NOT NULL DEFAULT 'SUPER_ADMIN',
      active BOOLEAN NOT NULL DEFAULT TRUE,
      version INTEGER NOT NULL DEFAULT 1,
      must_change BOOLEAN NOT NULL DEFAULT TRUE,
      created_at TIMESTAMPTZ DEFAULT NOW()
    );

    CREATE TABLE IF NOT EXISTS admin_settings (
      key VARCHAR(150) PRIMARY KEY,
      value TEXT
    );

    CREATE TABLE IF NOT EXISTS admin_logs (
      id SERIAL PRIMARY KEY,
      admin_id INTEGER,
      username VARCHAR(100),
      action VARCHAR(100),
      details TEXT,
      created_at TIMESTAMPTZ DEFAULT NOW()
    );

    CREATE TABLE IF NOT EXISTS page_views (
      id SERIAL PRIMARY KEY,
      page TEXT,
      ip TEXT,
      user_agent TEXT,
      created_at TIMESTAMPTZ DEFAULT NOW()
    );

    CREATE TABLE IF NOT EXISTS admin_staff (
      id SERIAL PRIMARY KEY,
      username VARCHAR(100) UNIQUE NOT NULL,
      password_hash TEXT NOT NULL,
      role VARCHAR(50) DEFAULT 'STAFF',
      active BOOLEAN DEFAULT TRUE,
      version INTEGER DEFAULT 1,
      must_change BOOLEAN DEFAULT TRUE,
      created_at TIMESTAMPTZ DEFAULT NOW()
    );

    CREATE TABLE IF NOT EXISTS admin_staff_permissions (
      id SERIAL PRIMARY KEY,
      staff_id INTEGER NOT NULL REFERENCES admin_staff(id) ON DELETE CASCADE,
      permission VARCHAR(100) NOT NULL,
      UNIQUE(staff_id, permission)
    );

    CREATE TABLE IF NOT EXISTS admin_security_events (
      id SERIAL PRIMARY KEY,
      event_type VARCHAR(60),
      username VARCHAR(100),
      result VARCHAR(40),
      masked_ip VARCHAR(80),
      user_agent TEXT,
      created_at TIMESTAMPTZ DEFAULT NOW()
    );

    CREATE TABLE IF NOT EXISTS admin_notifications (
      id SERIAL PRIMARY KEY,
      title VARCHAR(200) NOT NULL,
      body TEXT NOT NULL,
      audience VARCHAR(80) DEFAULT 'all',
      status VARCHAR(20) DEFAULT 'draft',
      scheduled_at TIMESTAMPTZ,
      created_by INTEGER,
      created_at TIMESTAMPTZ DEFAULT NOW(),
      updated_at TIMESTAMPTZ DEFAULT NOW()
    );

    CREATE TABLE IF NOT EXISTS admin_announcements (
      id SERIAL PRIMARY KEY,
      title VARCHAR(200) NOT NULL,
      body TEXT NOT NULL,
      status VARCHAR(20) DEFAULT 'draft',
      starts_at TIMESTAMPTZ,
      ends_at TIMESTAMPTZ,
      created_by INTEGER,
      created_at TIMESTAMPTZ DEFAULT NOW(),
      updated_at TIMESTAMPTZ DEFAULT NOW()
    );

    CREATE TABLE IF NOT EXISTS support_tickets (
      id SERIAL PRIMARY KEY,
      name VARCHAR(120),
      email VARCHAR(200),
      category VARCHAR(80),
      message TEXT NOT NULL,
      status VARCHAR(30) DEFAULT 'new',
      source VARCHAR(80) DEFAULT 'dashboard-api',
      created_at TIMESTAMPTZ DEFAULT NOW(),
      updated_at TIMESTAMPTZ DEFAULT NOW()
    );

    CREATE TABLE IF NOT EXISTS admin_backup_records (
      id SERIAL PRIMARY KEY,
      filename VARCHAR(200),
      exported_at TIMESTAMPTZ DEFAULT NOW(),
      exported_by INTEGER,
      rows_count INTEGER DEFAULT 0
    );

    CREATE INDEX IF NOT EXISTS idx_page_views_created
      ON page_views(created_at);

    CREATE INDEX IF NOT EXISTS idx_admin_logs_created
      ON admin_logs(created_at);

    CREATE INDEX IF NOT EXISTS idx_security_events_created
      ON admin_security_events(created_at);

    CREATE INDEX IF NOT EXISTS idx_support_tickets_created
      ON support_tickets(created_at);
  `);

  const count = await db.query("SELECT COUNT(*)::int AS n FROM admin_account");

  if (count.rows[0].n === 0 && ADMIN_USER && ADMIN_PASS) {
    const hash = await bcrypt.hash(ADMIN_PASS, 12);

    await db.query(
      `INSERT INTO admin_account
       (id, username, password_hash, role, active, version, must_change)
       VALUES (1,$1,$2,'SUPER_ADMIN',TRUE,1,TRUE)
       ON CONFLICT DO NOTHING`,
      [ADMIN_USER, hash]
    );
  }

  const staff = await db.query("SELECT id FROM admin_staff");

  for (const item of staff.rows) {
    for (const permission of DEFAULT_STAFF_PERMISSIONS) {
      await db.query(
        `INSERT INTO admin_staff_permissions (staff_id,permission)
         VALUES ($1,$2) ON CONFLICT DO NOTHING`,
        [item.id, permission]
      );
    }
  }

  console.log("BASAM database initialized.");
}

// HEALTH

app.get("/health", asyncHandler(async (req, res) => {
  const start = Date.now();
  await db.query("SELECT 1");
  res.json({
    status: "ok",
    database: "connected",
    database_latency_ms: Date.now() - start,
    uptime_seconds: Math.floor(process.uptime())
  });
}));

// LOGIN

app.post("/api/login", loginLimiter, asyncHandler(async (req, res) => {
  const username = String(req.body.username || "").trim();
  const password = String(req.body.password || "");

  if (!username || !password) {
    await securityEvent(req, "login", username, "missing_credentials");
    return res.status(400).json({ error: "Username and password required" });
  }

  let result = await db.query(
    "SELECT id,username,password_hash,role,active,version,must_change FROM admin_account WHERE username=$1",
    [username]
  );

  let type = "super";

  if (!result.rows.length) {
    result = await db.query(
      "SELECT id,username,password_hash,role,active,version,must_change FROM admin_staff WHERE username=$1",
      [username]
    );
    type = "staff";
  }

  if (!result.rows.length) {
    await securityEvent(req, "login", username, "failed");
    return res.status(401).json({ error: "Invalid credentials" });
  }

  const account = result.rows[0];
  const valid = await bcrypt.compare(password, account.password_hash);

  if (!valid || !account.active) {
    await securityEvent(req, "login", username, "failed");
    return res.status(401).json({ error: "Invalid credentials" });
  }

  const admin = {
    id: Number(account.id),
    username: account.username,
    role: account.role,
    type,
    version: account.version
  };

  const token = issueToken(admin);

  await securityEvent(req, "login", username, "success");

  res.json({
    token,
    must_change: account.must_change,
    admin: {
      id: admin.id,
      username: admin.username,
      role: admin.role,
      type
    }
  });
}));

// CURRENT ADMIN

app.get("/api/me", auth, asyncHandler(async (req, res) => {
  res.json({
    admin: req.admin,
    permissions: req.admin.permissions,
    is_super_admin: isSuperAdmin(req.admin)
  });
}));

app.get("/api/permissions/catalog", auth, requireSuperAdmin, (req, res) => {
  res.json(PERMISSION_CATALOG);
});

// CREDENTIALS

app.post("/api/credentials", auth, actionLimiter, asyncHandler(async (req, res) => {
  const username = String(req.body.username || req.admin.username).trim();
  const password = String(req.body.password || "");

  if (username.length < 3 || password.length < 10) {
    return res.status(400).json({
      error: "Username must be at least 3 characters and password at least 10."
    });
  }

  const duplicate = await db.query(
    `SELECT username FROM admin_account WHERE username=$1 AND id<>$2
     UNION ALL
     SELECT username FROM admin_staff WHERE username=$1`,
    [username, req.admin.type === "super" ? req.admin.id : -1]
  );

  if (duplicate.rows.length) {
    return res.status(409).json({ error: "Username already exists" });
  }

  const hash = await bcrypt.hash(password, 12);
  const table = req.admin.type === "super" ? "admin_account" : "admin_staff";

  await db.query(
    `UPDATE ${table}
     SET username=$1,password_hash=$2,must_change=FALSE,version=version+1
     WHERE id=$3`,
    [username, hash, req.admin.id]
  );

  await writeLog(req, "credentials_updated");

  const updated = await db.query(
    `SELECT id,username,role,version FROM ${table} WHERE id=$1`,
    [req.admin.id]
  );

  const account = {
    ...updated.rows[0],
    type: req.admin.type
  };

  res.json({
    success: true,
    token: issueToken(account),
    message: "Credentials updated. Please sign in again."
  });
}));

// STAFF MANAGEMENT

app.get("/api/admins", auth, requireSuperAdmin, asyncHandler(async (req, res) => {
  const result = await db.query(
    `SELECT id,username,role,active,version,must_change,created_at
     FROM admin_staff ORDER BY id DESC`
  );

  const admins = [];

  for (const row of result.rows) {
    admins.push({
      ...row,
      permissions: await getStaffPermissions(row.id)
    });
  }

  res.json(admins);
}));

app.post("/api/admins", auth, requireSuperAdmin, actionLimiter, asyncHandler(async (req, res) => {
  const username = String(req.body.username || "").trim();
  const password = String(req.body.password || "");
  const permissions = validatePermissions(req.body.permissions || []);

  if (username.length < 3 || password.length < 10) {
    return res.status(400).json({ error: "Invalid username or password" });
  }

  const exists = await db.query(
    `SELECT username FROM admin_account WHERE username=$1
     UNION ALL
     SELECT username FROM admin_staff WHERE username=$1`,
    [username]
  );

  if (exists.rows.length) {
    return res.status(409).json({ error: "Username already exists" });
  }

  const client = await db.connect();

  try {
    await client.query("BEGIN");

    const hash = await bcrypt.hash(password, 12);

    const created = await client.query(
      `INSERT INTO admin_staff
       (username,password_hash,role,active,version,must_change)
       VALUES ($1,$2,'STAFF',TRUE,1,TRUE)
       RETURNING id,username,role,active,created_at`,
      [username, hash]
    );

    await saveStaffPermissions(client, created.rows[0].id, permissions);

    await client.query("COMMIT");

    await writeLog(req, "staff_created", username);

    res.status(201).json({
      ...created.rows[0],
      permissions
    });
  } catch (e) {
    await client.query("ROLLBACK");
    throw e;
  } finally {
    client.release();
  }
}));

app.patch("/api/admins/:id", auth, requireSuperAdmin, actionLimiter, asyncHandler(async (req, res) => {
  const id = Number(req.params.id);

  if (!Number.isInteger(id) || id <= 0) {
    return res.status(400).json({ error: "Invalid staff ID" });
  }

  const client = await db.connect();

  try {
    await client.query("BEGIN");

    const current = await client.query(
      "SELECT id FROM admin_staff WHERE id=$1 FOR UPDATE",
      [id]
    );

    if (!current.rows.length) {
      await client.query("ROLLBACK");
      return res.status(404).json({ error: "Staff member not found" });
    }

    const fields = [];
    const values = [];
    let n = 1;

    if (req.body.username !== undefined) {
      const username = String(req.body.username).trim();

      if (username.length < 3) {
        throw new Error("Invalid username");
      }

      const duplicate = await client.query(
        `SELECT id FROM admin_account WHERE username=$1
         UNION ALL
         SELECT id FROM admin_staff WHERE username=$1 AND id<>$2`,
        [username, id]
      );

      if (duplicate.rows.length) {
        throw new Error("Username already exists");
      }

      fields.push(`username=$${n++}`);
      values.push(username);
    }

    if (req.body.active !== undefined) {
      fields.push(`active=$${n++}`);
      values.push(Boolean(req.body.active));
    }

    if (req.body.password) {
      if (String(req.body.password).length < 10) {
        throw new Error("Password must be at least 10 characters");
      }

      fields.push(`password_hash=$${n++}`);
      values.push(await bcrypt.hash(String(req.body.password), 12));

      fields.push(`must_change=TRUE`);
    }

    if (fields.length) {
      fields.push("version=version+1");
      values.push(id);

      await client.query(
        `UPDATE admin_staff SET ${fields.join(",")} WHERE id=$${n}`,
        values
      );
    }

    if (req.body.permissions !== undefined) {
      await saveStaffPermissions(
        client,
        id,
        validatePermissions(req.body.permissions)
      );
    }

    await client.query("COMMIT");

    await writeLog(req, "staff_updated", String(id));

    const result = await db.query(
      `SELECT id,username,role,active,version,must_change,created_at
       FROM admin_staff WHERE id=$1`,
      [id]
    );

    res.json({
      ...result.rows[0],
      permissions: await getStaffPermissions(id)
    });
  } catch (e) {
    await client.query("ROLLBACK");
    if (e.message.includes("already exists")) {
      return res.status(409).json({ error: e.message });
    }
    if (e.message.includes("Invalid") || e.message.includes("must be")) {
      return res.status(400).json({ error: e.message });
    }
    throw e;
  } finally {
    client.release();
  }
}));

app.delete("/api/admins/:id", auth, requireSuperAdmin, actionLimiter, asyncHandler(async (req, res) => {
  const id = Number(req.params.id);

  if (!Number.isInteger(id) || id <= 0) {
    return res.status(400).json({ error: "Invalid ID" });
  }

  const result = await db.query(
    "DELETE FROM admin_staff WHERE id=$1 RETURNING id,username",
    [id]
  );

  if (!result.rows.length) {
    return res.status(404).json({ error: "Staff member not found" });
  }

  await writeLog(req, "staff_deleted", result.rows[0].username);

  res.json({ success: true });
}));

// TRACKING

app.post("/api/track", publicLimiter, asyncHandler(async (req, res) => {
  const page = String(req.body.page || "/").slice(0, 300);

  await db.query(
    `INSERT INTO page_views (page,ip,user_agent,created_at)
     VALUES ($1,$2,$3,NOW())`,
    [
      page,
      maskIp(req.ip),
      String(req.headers["user-agent"] || "").slice(0, 300)
    ]
  );

  res.json({ success: true });
}));

// OVERVIEW

app.get("/api/overview", auth, requirePermission("overview.view"), asyncHandler(async (req, res) => {
  const result = await db.query(`
    SELECT
      COUNT(*) FILTER (WHERE created_at >= CURRENT_DATE)::int AS today,
      COUNT(*) FILTER (WHERE created_at >= NOW()-INTERVAL '30 days')::int AS last_30_days,
      COUNT(*) FILTER (WHERE created_at >= NOW()-INTERVAL '5 minutes')::int AS active_now
    FROM page_views
  `);

  const maintenance = await setting("maintenance_enabled", "false");

  res.json({
    visitors: result.rows[0],
    maintenance: maintenance === "true",
    generated_at: new Date().toISOString()
  });
}));

app.get("/api/visitors", auth, requirePermission("visitors.view"), asyncHandler(async (req, res) => {
  const limit = Math.min(Math.max(Number(req.query.limit) || 50, 1), 200);

  const result = await db.query(
    `SELECT id,page,ip,user_agent,created_at
     FROM page_views ORDER BY created_at DESC LIMIT $1`,
    [limit]
  );

  res.json(result.rows);
}));

// SYSTEM MONITORING

app.get("/api/system", auth, requirePermission("system.view"), asyncHandler(async (req, res) => {
  const start = Date.now();
  await db.query("SELECT 1");

  const memory = process.memoryUsage();

  res.json({
    api: "online",
    database: "connected",
    database_latency_ms: Date.now() - start,
    uptime_seconds: Math.floor(process.uptime()),
    node_version: process.version,
    platform: process.platform,
    hostname: os.hostname(),
    memory: {
      rss: memory.rss,
      heap_used: memory.heapUsed,
      heap_total: memory.heapTotal
    },
    cpu_count: os.cpus().length,
    load_average: os.loadavg(),
    render_control_enabled: false
  });
}));

// MAINTENANCE

app.get("/api/maintenance", auth, requirePermission("maintenance.manage"), asyncHandler(async (req, res) => {
  res.json({
    enabled: (await setting("maintenance_enabled", "false")) === "true",
    message: await setting("maintenance_message", "")
  });
}));

app.post("/api/maintenance", auth, requirePermission("maintenance.manage"), actionLimiter, asyncHandler(async (req, res) => {
  const enabled = Boolean(req.body.enabled);
  const message = String(req.body.message || "").slice(0, 500);

  await saveSetting("maintenance_enabled", enabled);
  await saveSetting("maintenance_message", message);

  await writeLog(req, "maintenance_updated", String(enabled));

  res.json({ success: true, enabled, message });
}));

// REVIEW LOCK

app.get("/api/review/status", asyncHandler(async (req, res) => {
  const locked = await setting("review_locked", "false");
  const message = await setting("review_lock_message", "");

  res.json({
    locked: locked === "true",
    message
  });
}));

app.post("/api/review/lock", auth, requirePermission("review.manage"), actionLimiter, asyncHandler(async (req, res) => {
  if (typeof req.body.locked !== "boolean") {
    return res.status(400).json({ error: "locked must be boolean" });
  }

  const message = String(req.body.message || "").slice(0, 500);

  await saveSetting("review_locked", req.body.locked);
  await saveSetting("review_lock_message", message);

  await writeLog(req, "review_lock_changed", String(req.body.locked));

  res.json({
    success: true,
    locked: req.body.locked,
    message
  });
}));

// SECURITY

app.get("/api/security/events", auth, requirePermission("security.view"), asyncHandler(async (req, res) => {
  const limit = Math.min(Math.max(Number(req.query.limit) || 100, 1), 300);

  const result = await db.query(
    `SELECT id,event_type,username,result,masked_ip,user_agent,created_at
     FROM admin_security_events ORDER BY created_at DESC LIMIT $1`,
    [limit]
  );

  res.json(result.rows);
}));

// LOGS

app.get("/api/logs", auth, requirePermission("logs.view"), asyncHandler(async (req, res) => {
  const limit = Math.min(Math.max(Number(req.query.limit) || 100, 1), 300);

  const result = await db.query(
    `SELECT id,admin_id,username,action,details,created_at
     FROM admin_logs ORDER BY created_at DESC LIMIT $1`,
    [limit]
  );

  res.json(result.rows);
}));

// NOTIFICATIONS

app.get("/api/notifications", auth, requirePermission("notifications.view"), asyncHandler(async (req, res) => {
  const result = await db.query(
    "SELECT * FROM admin_notifications ORDER BY created_at DESC LIMIT 200"
  );
  res.json(result.rows);
}));

app.post("/api/notifications", auth, requirePermission("notifications.manage"), actionLimiter, asyncHandler(async (req, res) => {
  const title = String(req.body.title || "").trim();
  const body = String(req.body.body || "").trim();
  const audience = String(req.body.audience || "all");
  const status = req.body.status || "draft";

  if (!title || !body) {
    return res.status(400).json({ error: "Title and body are required" });
  }

  if (!["draft", "scheduled"].includes(status)) {
    return res.status(400).json({ error: "Invalid notification status" });
  }

  const result = await db.query(
    `INSERT INTO admin_notifications
     (title,body,audience,status,scheduled_at,created_by)
     VALUES ($1,$2,$3,$4,$5,$6) RETURNING *`,
    [
      title.slice(0, 200),
      body.slice(0, 5000),
      audience.slice(0, 80),
      status,
      req.body.scheduled_at || null,
      req.admin.id
    ]
  );

  await writeLog(req, "notification_created", title);

  res.status(201).json(result.rows[0]);
}));

app.patch("/api/notifications/:id", auth, requirePermission("notifications.manage"), actionLimiter, asyncHandler(async (req, res) => {
  const id = Number(req.params.id);
  const current = await db.query(
    "SELECT * FROM admin_notifications WHERE id=$1",
    [id]
  );

  if (!current.rows.length) {
    return res.status(404).json({ error: "Notification not found" });
  }

  const old = current.rows[0];
  const title = req.body.title === undefined ? old.title : String(req.body.title).slice(0, 200);
  const body = req.body.body === undefined ? old.body : String(req.body.body).slice(0, 5000);
  const audience = req.body.audience === undefined ? old.audience : String(req.body.audience).slice(0, 80);
  const status = req.body.status === undefined ? old.status : req.body.status;

  if (!["draft", "scheduled"].includes(status)) {
    return res.status(400).json({ error: "Invalid status" });
  }

  const result = await db.query(
    `UPDATE admin_notifications
     SET title=$1,body=$2,audience=$3,status=$4,scheduled_at=$5,updated_at=NOW()
     WHERE id=$6 RETURNING *`,
    [title, body, audience, status, req.body.scheduled_at ?? old.scheduled_at, id]
  );

  await writeLog(req, "notification_updated", String(id));

  res.json(result.rows[0]);
}));

// USERS MODULE: NOT CONNECTED

app.get("/api/users", auth, requirePermission("users.view"), (req, res) => {
  res.json({
    connected: false,
    status: "unlinked",
    message: "لا يوجد مصدر بيانات مستخدمي الموقع مربوط بلوحة الإدارة."
  });
});

// CHESS ANALYTICS: NOT CONNECTED

app.get("/api/chess/analytics", auth, requirePermission("chess.view"), (req, res) => {
  res.json({
    connected: false,
    status: "unlinked",
    message: "تحليلات الشطرنج غير مربوطة بمصدر بيانات."
  });
});

// SUPPORT

app.get("/api/support", auth, requirePermission("support.view"), asyncHandler(async (req, res) => {
  const result = await db.query(
    "SELECT * FROM support_tickets ORDER BY created_at DESC LIMIT 200"
  );
  res.json(result.rows);
}));

app.post("/api/support", publicLimiter, asyncHandler(async (req, res) => {
  const name = String(req.body.name || "").trim().slice(0, 120);
  const email = String(req.body.email || "").trim().slice(0, 200);
  const category = String(req.body.category || "general").slice(0, 80);
  const message = String(req.body.message || "").trim();

  if (!message || message.length < 5 || message.length > 5000) {
    return res.status(400).json({ error: "Invalid message" });
  }

  const result = await db.query(
    `INSERT INTO support_tickets
     (name,email,category,message,status,source)
     VALUES ($1,$2,$3,$4,'new','public-api') RETURNING id,created_at`,
    [name, email, category, message]
  );

  res.status(201).json({
    success: true,
    ticket: result.rows[0]
  });
}));

app.patch("/api/support/:id", auth, requirePermission("support.manage"), actionLimiter, asyncHandler(async (req, res) => {
  const id = Number(req.params.id);
  const status = String(req.body.status || "");

  if (!["new", "in_progress", "resolved", "closed"].includes(status)) {
    return res.status(400).json({ error: "Invalid ticket status" });
  }

  const result = await db.query(
    `UPDATE support_tickets SET status=$1,updated_at=NOW()
     WHERE id=$2 RETURNING *`,
    [status, id]
  );

  if (!result.rows.length) {
    return res.status(404).json({ error: "Ticket not found" });
  }

  await writeLog(req, "support_ticket_updated", String(id));

  res.json(result.rows[0]);
}));

// ADVERTISEMENTS

app.get("/api/announcements", auth, requirePermission("ads.view"), asyncHandler(async (req, res) => {
  const result = await db.query(
    "SELECT * FROM admin_announcements ORDER BY created_at DESC LIMIT 200"
  );
  res.json(result.rows);
}));

app.post("/api/announcements", auth, requirePermission("ads.manage"), actionLimiter, asyncHandler(async (req, res) => {
  const title = String(req.body.title || "").trim();
  const body = String(req.body.body || "").trim();
  const status = req.body.status || "draft";

  if (!title || !body) {
    return res.status(400).json({ error: "Title and body are required" });
  }

  if (!["draft", "ready", "paused"].includes(status)) {
    return res.status(400).json({ error: "Invalid announcement status" });
  }

  const result = await db.query(
    `INSERT INTO admin_announcements
     (title,body,status,starts_at,ends_at,created_by)
     VALUES ($1,$2,$3,$4,$5,$6) RETURNING *`,
    [
      title.slice(0, 200),
      body.slice(0, 5000),
      status,
      req.body.starts_at || null,
      req.body.ends_at || null,
      req.admin.id
    ]
  );

  await writeLog(req, "announcement_created", title);

  res.status(201).json(result.rows[0]);
}));

app.patch("/api/announcements/:id", auth, requirePermission("ads.manage"), actionLimiter, asyncHandler(async (req, res) => {
  const id = Number(req.params.id);
  const current = await db.query(
    "SELECT * FROM admin_announcements WHERE id=$1",
    [id]
  );

  if (!current.rows.length) {
    return res.status(404).json({ error: "Announcement not found" });
  }

  const old = current.rows[0];
  const title = req.body.title === undefined ? old.title : String(req.body.title).slice(0, 200);
  const body = req.body.body === undefined ? old.body : String(req.body.body).slice(0, 5000);
  const status = req.body.status === undefined ? old.status : req.body.status;

  if (!["draft", "ready", "paused"].includes(status)) {
    return res.status(400).json({ error: "Invalid status" });
  }

  const result = await db.query(
    `UPDATE admin_announcements
     SET title=$1,body=$2,status=$3,starts_at=$4,ends_at=$5,updated_at=NOW()
     WHERE id=$6 RETURNING *`,
    [
      title,
      body,
      status,
      req.body.starts_at ?? old.starts_at,
      req.body.ends_at ?? old.ends_at,
      id
    ]
  );

  await writeLog(req, "announcement_updated", String(id));

  res.json(result.rows[0]);
}));

app.delete("/api/announcements/:id", auth, requirePermission("ads.manage"), actionLimiter, asyncHandler(async (req, res) => {
  const result = await db.query(
    "DELETE FROM admin_announcements WHERE id=$1 RETURNING id",
    [Number(req.params.id)]
  );

  if (!result.rows.length) {
    return res.status(404).json({ error: "Announcement not found" });
  }

  await writeLog(req, "announcement_deleted", req.params.id);

  res.json({ success: true });
}));

// REPORTS

app.get("/api/reports/summary", auth, requirePermission("reports.view"), asyncHandler(async (req, res) => {
  const result = await db.query(`
    SELECT
      (SELECT COUNT(*)::int FROM page_views) AS page_views,
      (SELECT COUNT(*)::int FROM admin_logs) AS admin_logs,
      (SELECT COUNT(*)::int FROM admin_notifications) AS notifications,
      (SELECT COUNT(*)::int FROM admin_announcements) AS announcements,
      (SELECT COUNT(*)::int FROM support_tickets) AS support_tickets
  `);

  res.json({
    ...result.rows[0],
    generated_at: new Date().toISOString()
  });
}));

// SETTINGS

app.get("/api/settings", auth, requirePermission("settings.view"), asyncHandler(async (req, res) => {
  const result = await db.query(
    "SELECT key,value FROM admin_settings WHERE key = ANY($1)",
    [SAFE_SETTINGS]
  );

  const settings = {};
  for (const row of result.rows) settings[row.key] = row.value;

  res.json(settings);
}));

app.patch("/api/settings", auth, requirePermission("settings.manage"), actionLimiter, asyncHandler(async (req, res) => {
  const entries = Object.entries(req.body || {});

  if (!entries.length || entries.length > 20) {
    return res.status(400).json({ error: "Invalid settings payload" });
  }

  for (const [key, value] of entries) {
    if (!SAFE_SETTINGS.includes(key)) {
      return res.status(400).json({ error: "Setting not allowed: " + key });
    }

    if (typeof value !== "string" && typeof value !== "boolean") {
      return res.status(400).json({ error: "Invalid setting value" });
    }

    await saveSetting(key, String(value).slice(0, 1000));
  }

  await writeLog(req, "settings_updated", entries.map(x => x[0]).join(","));

  res.json({ success: true });
}));

// MODULE STATUS

app.get("/api/modules/status", auth, async (req, res) => {
  res.json({
    users: { connected: false, status: "unlinked" },
    chess_analytics: { connected: false, status: "unlinked" },
    notifications: {
      connected: true,
      delivery_enabled: false,
      status: "drafts_only"
    },
    advertisements: {
      connected: true,
      site_integration: false,
      status: "dashboard_only"
    },
    support: {
      intake_api_available: true,
      website_form_linked: false
    },
    render_control: {
      enabled: false
    }
  });
});

// BACKUP EXPORT - SUPER ADMIN ONLY

app.get("/api/backups/export", auth, requireSuperAdmin, actionLimiter, asyncHandler(async (req, res) => {
  const tables = [
    "admin_settings",
    "admin_logs",
    "page_views",
    "admin_staff_permissions",
    "admin_security_events",
    "admin_notifications",
    "admin_announcements",
    "support_tickets",
    "admin_backup_records"
  ];

  const backup = {
    product: "BASAM COMMAND CENTER",
    exported_at: new Date().toISOString(),
    tables: {}
  };

  let rowsCount = 0;

  for (const table of tables) {
    const result = await db.query(`SELECT * FROM ${table}`);
    backup.tables[table] = result.rows;
    rowsCount += result.rows.length;
  }

  const filename = `basam-dashboard-backup-${Date.now()}.json`;

  await db.query(
    `INSERT INTO admin_backup_records (filename,exported_by,rows_count)
     VALUES ($1,$2,$3)`,
    [filename, req.admin.id, rowsCount]
  );

  await writeLog(req, "backup_exported", filename);

  res.setHeader("Content-Type", "application/json; charset=utf-8");
  res.setHeader("Content-Disposition", `attachment; filename="${filename}"`);

  res.send(JSON.stringify(backup, null, 2));
}));

// SITE CONTROL - DISABLED

app.post("/api/site/:action", auth, requireSuperAdmin, actionLimiter, (req, res) => {
  if (!ALLOW_RENDER_CONTROL) {
    return res.status(403).json({
      error: "Render control is disabled",
      enabled: false
    });
  }

  res.status(403).json({
    error: "Render control integration is not configured"
  });
});

// ERROR HANDLER

app.use((err, req, res, next) => {
  console.error("API error:", err.message);

  if (res.headersSent) return next(err);

  res.status(500).json({
    error: "Internal server error"
  });
});

// START

init()
  .then(() => {
    app.listen(PORT, () => {
      console.log(`BASAM API listening on port ${PORT}`);
    });
  })
  .catch(error => {
    console.error("Startup failed:", error);
    process.exit(1);
  });