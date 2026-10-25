require("dotenv").config();

const crypto = require("crypto");
const express = require("express");
const cors = require("cors");
const helmet = require("helmet");
const rateLimit = require("express-rate-limit");
const { Pool } = require("pg");

const app = express();
app.disable("x-powered-by");
app.set("trust proxy", 1);
app.use(helmet());
app.use(express.json({ limit: "32kb" }));

const PORT = Number(process.env.PORT || 10000);
const ADMIN_TOKEN = process.env.ADMIN_API_TOKEN || "";
const allowedOrigins = (process.env.ALLOWED_ORIGINS || "")
  .split(",").map(s => s.trim()).filter(Boolean);

if (!process.env.DATABASE_URL) {
  console.error("FATAL: DATABASE_URL is required.");
  process.exit(1);
}
if (ADMIN_TOKEN.length < 32) {
  console.error("FATAL: Set ADMIN_API_TOKEN to a random secret of at least 32 characters.");
  process.exit(1);
}

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.PGSSL === "true" ? { rejectUnauthorized: false } : undefined,
  max: 10,
  idleTimeoutMillis: 30000,
  connectionTimeoutMillis: 10000
});

app.use(cors({
  origin(origin, callback) {
    // Non-browser tools and same-origin requests may omit Origin. Admin auth is still required.
    if (!origin || allowedOrigins.includes(origin)) return callback(null, true);
    return callback(new Error("Origin not allowed by CORS"));
  },
  methods: ["GET", "POST", "PATCH", "DELETE", "OPTIONS"],
  allowedHeaders: ["Content-Type", "Authorization"],
  maxAge: 600
}));

const verifyLimiter = rateLimit({
  windowMs: 60 * 1000,
  limit: 20,
  standardHeaders: "draft-7",
  legacyHeaders: false,
  message: { ok: false, error: "Too many attempts. Please wait a minute and try again." }
});
const adminLimiter = rateLimit({
  windowMs: 60 * 1000,
  limit: 120,
  standardHeaders: "draft-7",
  legacyHeaders: false
});

const sha256 = value => crypto.createHash("sha256").update(value).digest("hex");
const safeEqual = (a, b) => {
  const aa = Buffer.from(String(a));
  const bb = Buffer.from(String(b));
  return aa.length === bb.length && crypto.timingSafeEqual(aa, bb);
};
const cleanKey = key => String(key || "").trim().toUpperCase();
const validKeyShape = key => /^VK-[A-Z0-9]{4}(?:-[A-Z0-9]{4}){3}$/.test(key);
const newKey = () => {
  const alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789";
  const chunk = () => Array.from(crypto.randomBytes(4), b => alphabet[b % alphabet.length]).join("");
  return `VK-${chunk()}-${chunk()}-${chunk()}-${chunk()}`;
};
const adminAuth = (req, res, next) => {
  const header = req.headers.authorization || "";
  const token = header.startsWith("Bearer ") ? header.slice(7) : "";
  if (!token || !safeEqual(token, ADMIN_TOKEN)) {
    return res.status(401).json({ ok: false, error: "Unauthorized. Admin token is missing or invalid." });
  }
  next();
};
const asyncRoute = fn => (req, res, next) => Promise.resolve(fn(req, res, next)).catch(next);

async function initDb() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS license_keys (
      id BIGSERIAL PRIMARY KEY,
      key_hash CHAR(64) UNIQUE NOT NULL,
      key_preview VARCHAR(24) NOT NULL,
      label VARCHAR(100) NOT NULL DEFAULT '',
      status VARCHAR(16) NOT NULL DEFAULT 'active' CHECK (status IN ('active','revoked')),
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      expires_at TIMESTAMPTZ,
      max_devices INTEGER NOT NULL DEFAULT 1 CHECK (max_devices BETWEEN 1 AND 100),
      metadata JSONB NOT NULL DEFAULT '{}'::jsonb
    );
    CREATE TABLE IF NOT EXISTS key_devices (
      id BIGSERIAL PRIMARY KEY,
      key_id BIGINT NOT NULL REFERENCES license_keys(id) ON DELETE CASCADE,
      device_hash CHAR(64) NOT NULL,
      first_seen_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      last_seen_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      UNIQUE(key_id, device_hash)
    );
    CREATE INDEX IF NOT EXISTS idx_license_keys_created ON license_keys(created_at DESC);
    CREATE INDEX IF NOT EXISTS idx_key_devices_key_id ON key_devices(key_id);
  `);
  console.log("Database tables are ready.");
}

app.get("/", (_req, res) => res.json({
  name: "VAULT Key Verification API",
  status: "online",
  version: "1.0.0",
  endpoints: { health: "/health", verify: "POST /api/verify" }
}));
app.get("/health", asyncRoute(async (_req, res) => {
  await pool.query("SELECT 1");
  res.json({ ok: true, service: "vault-key-verification-api", database: "connected" });
}));

// Public verification. Device ID is an installation identifier, not a secret.
app.post("/api/verify", verifyLimiter, asyncRoute(async (req, res) => {
  const key = cleanKey(req.body && req.body.key);
  const deviceId = String((req.body && req.body.deviceId) || "").trim();

  if (!validKeyShape(key) || deviceId.length < 8 || deviceId.length > 200) {
    return res.status(400).json({ ok: false, error: "Enter a valid key and try again." });
  }

  const client = await pool.connect();
  try {
    await client.query("BEGIN");
    const result = await client.query(
      "SELECT id, status, expires_at, max_devices FROM license_keys WHERE key_hash = $1 FOR UPDATE",
      [sha256(key)]
    );
    if (!result.rowCount) {
      await client.query("ROLLBACK");
      return res.status(200).json({ ok: false, error: "Invalid key." });
    }
    const row = result.rows[0];
    if (row.status !== "active") {
      await client.query("ROLLBACK");
      return res.status(200).json({ ok: false, error: "This key has been revoked." });
    }
    if (row.expires_at && new Date(row.expires_at).getTime() <= Date.now()) {
      await client.query("ROLLBACK");
      return res.status(200).json({ ok: false, error: "This key has expired." });
    }

    const deviceHash = sha256(deviceId);
    const existing = await client.query(
      "SELECT id FROM key_devices WHERE key_id = $1 AND device_hash = $2",
      [row.id, deviceHash]
    );
    if (!existing.rowCount) {
      const count = await client.query("SELECT COUNT(*)::int AS count FROM key_devices WHERE key_id = $1", [row.id]);
      if (count.rows[0].count >= row.max_devices) {
        await client.query("ROLLBACK");
        return res.status(200).json({ ok: false, error: "Device limit reached for this key." });
      }
      await client.query(
        "INSERT INTO key_devices (key_id, device_hash) VALUES ($1, $2)",
        [row.id, deviceHash]
      );
    } else {
      await client.query(
        "UPDATE key_devices SET last_seen_at = NOW() WHERE key_id = $1 AND device_hash = $2",
        [row.id, deviceHash]
      );
    }
    await client.query("COMMIT");
    return res.json({
      ok: true,
      message: "Key verified successfully.",
      expiresAt: row.expires_at,
      deviceLimit: row.max_devices
    });
  } catch (err) {
    await client.query("ROLLBACK").catch(() => {});
    throw err;
  } finally {
    client.release();
  }
}));

// All management endpoints require the secret admin bearer token.
app.use("/api/admin", adminLimiter, adminAuth);

app.get("/api/admin/stats", asyncRoute(async (_req, res) => {
  const r = await pool.query(`
    SELECT COUNT(*)::int AS total,
      COUNT(*) FILTER (WHERE status='active' AND (expires_at IS NULL OR expires_at > NOW()))::int AS active,
      COUNT(*) FILTER (WHERE status='revoked')::int AS revoked,
      COUNT(*) FILTER (WHERE expires_at IS NOT NULL AND expires_at <= NOW())::int AS expired
    FROM license_keys
  `);
  res.json({ ok: true, stats: r.rows[0] });
}));

app.get("/api/admin/keys", asyncRoute(async (req, res) => {
  const q = String(req.query.q || "").trim().slice(0, 100);
  const limit = Math.min(Math.max(parseInt(req.query.limit || "200", 10) || 200, 1), 500);
  const r = await pool.query(`
    SELECT k.id, k.key_preview AS "keyPreview", k.label, k.status,
      k.created_at AS "createdAt", k.expires_at AS "expiresAt", k.max_devices AS "maxDevices",
      (SELECT COUNT(*)::int FROM key_devices d WHERE d.key_id=k.id) AS "deviceCount"
    FROM license_keys k
    WHERE ($1 = '' OR k.key_preview ILIKE '%' || $1 || '%' OR k.label ILIKE '%' || $1 || '%')
    ORDER BY k.created_at DESC LIMIT $2
  `, [q, limit]);
  res.json({ ok: true, keys: r.rows });
}));

app.post("/api/admin/keys", asyncRoute(async (req, res) => {
  const label = String(req.body.label || "").trim().slice(0, 100);
  const maxDevices = Number(req.body.maxDevices ?? 1);
  const expiry = req.body.expiresAt ? new Date(req.body.expiresAt) : null;
  if (!Number.isInteger(maxDevices) || maxDevices < 1 || maxDevices > 100) {
    return res.status(400).json({ ok: false, error: "maxDevices must be an integer from 1 to 100." });
  }
  if (expiry && Number.isNaN(expiry.getTime())) {
    return res.status(400).json({ ok: false, error: "Invalid expiry date." });
  }
  if (expiry && expiry.getTime() <= Date.now()) {
    return res.status(400).json({ ok: false, error: "Expiry must be in the future." });
  }

  for (let attempt = 0; attempt < 5; attempt++) {
    const key = newKey();
    try {
      const r = await pool.query(`
        INSERT INTO license_keys (key_hash, key_preview, label, expires_at, max_devices)
        VALUES ($1, $2, $3, $4, $5)
        RETURNING id, key_preview AS "keyPreview", label, status, created_at AS "createdAt",
          expires_at AS "expiresAt", max_devices AS "maxDevices"
      `, [sha256(key), key, label, expiry, maxDevices]);
      return res.status(201).json({ ok: true, key, record: r.rows[0] });
    } catch (err) {
      if (err.code !== "23505") throw err;
    }
  }
  res.status(500).json({ ok: false, error: "Could not generate a unique key. Try again." });
}));

app.patch("/api/admin/keys/:id", asyncRoute(async (req, res) => {
  const id = Number(req.params.id);
  if (!Number.isSafeInteger(id) || id < 1) return res.status(400).json({ ok: false, error: "Invalid key ID." });

  const fields = [];
  const values = [];
  const add = (column, value) => { values.push(value); fields.push(`${column} = $${values.length}`); };

  if (Object.prototype.hasOwnProperty.call(req.body, "label")) {
    add("label", String(req.body.label || "").trim().slice(0, 100));
  }
  if (Object.prototype.hasOwnProperty.call(req.body, "status")) {
    if (!["active", "revoked"].includes(req.body.status)) {
      return res.status(400).json({ ok: false, error: "Status must be active or revoked." });
    }
    add("status", req.body.status);
  }
  if (Object.prototype.hasOwnProperty.call(req.body, "maxDevices")) {
    const n = Number(req.body.maxDevices);
    if (!Number.isInteger(n) || n < 1 || n > 100) return res.status(400).json({ ok: false, error: "maxDevices must be 1–100." });
    add("max_devices", n);
  }
  if (Object.prototype.hasOwnProperty.call(req.body, "expiresAt")) {
    if (req.body.expiresAt === null || req.body.expiresAt === "") add("expires_at", null);
    else {
      const d = new Date(req.body.expiresAt);
      if (Number.isNaN(d.getTime())) return res.status(400).json({ ok: false, error: "Invalid expiry date." });
      add("expires_at", d);
    }
  }
  if (!fields.length) return res.status(400).json({ ok: false, error: "No editable fields supplied." });
  values.push(id);
  const r = await pool.query(
    `UPDATE license_keys SET ${fields.join(", ")} WHERE id = $${values.length}
     RETURNING id, key_preview AS "keyPreview", label, status, created_at AS "createdAt",
       expires_at AS "expiresAt", max_devices AS "maxDevices"`,
    values
  );
  if (!r.rowCount) return res.status(404).json({ ok: false, error: "Key not found." });
  res.json({ ok: true, record: r.rows[0] });
}));

app.delete("/api/admin/keys/:id", asyncRoute(async (req, res) => {
  const id = Number(req.params.id);
  if (!Number.isSafeInteger(id) || id < 1) return res.status(400).json({ ok: false, error: "Invalid key ID." });
  const r = await pool.query("DELETE FROM license_keys WHERE id=$1 RETURNING id", [id]);
  if (!r.rowCount) return res.status(404).json({ ok: false, error: "Key not found." });
  res.json({ ok: true, message: "Key deleted permanently." });
}));

app.post("/api/admin/keys/:id/reset-devices", asyncRoute(async (req, res) => {
  const id = Number(req.params.id);
  if (!Number.isSafeInteger(id) || id < 1) return res.status(400).json({ ok: false, error: "Invalid key ID." });
  const r = await pool.query("DELETE FROM key_devices WHERE key_id=$1", [id]);
  res.json({ ok: true, removedDevices: r.rowCount });
}));

app.use((err, _req, res, _next) => {
  if (err && err.message === "Origin not allowed by CORS") {
    return res.status(403).json({ ok: false, error: "This website origin is not allowed." });
  }
  console.error("Request error:", err && (err.stack || err.message || err));
  res.status(500).json({ ok: false, error: "Internal server error." });
});

initDb().then(() => {
  app.listen(PORT, () => console.log(`VAULT Key Verification API listening on ${PORT}`));
}).catch(err => {
  console.error("Database initialization failed:", err);
  process.exit(1);
});
