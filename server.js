import "dotenv/config";
import express from "express";
import cors from "cors";
import helmet from "helmet";
import crypto from "node:crypto";
import pg from "pg";

const { Pool } = pg;
const app = express();

const PORT = Number(process.env.PORT || 3000);
const PREFIX = process.env.BHAI_API_KEY_PREFIX || "bhai_live_";
const pool = process.env.DATABASE_URL
  ? new Pool({ connectionString: process.env.DATABASE_URL, ssl: { rejectUnauthorized: false } })
  : null;

app.disable("x-powered-by");
app.use(helmet());
app.use(cors({ origin: process.env.CORS_ORIGIN || "*" }));
app.use(express.json({ limit: "2mb" }));

function requestId() {
  return "req_" + crypto.randomBytes(10).toString("hex");
}

app.use((req, res, next) => {
  const id = req.headers["x-request-id"] || requestId();
  res.setHeader("x-request-id", id);
  req.requestId = id;
  next();
});

const memoryKeys = new Map();

async function initDb() {
  if (!pool) return;
  await pool.query(`
    CREATE TABLE IF NOT EXISTS bhai_api_keys (
      id BIGSERIAL PRIMARY KEY,
      name TEXT NOT NULL,
      key_prefix TEXT NOT NULL,
      key_hash TEXT NOT NULL UNIQUE,
      scopes JSONB NOT NULL DEFAULT '["chat"]'::jsonb,
      status TEXT NOT NULL DEFAULT 'active',
      usage_count BIGINT NOT NULL DEFAULT 0,
      last_used_at TIMESTAMPTZ,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      revoked_at TIMESTAMPTZ
    );
    CREATE INDEX IF NOT EXISTS idx_bhai_api_keys_hash ON bhai_api_keys(key_hash);
  `);
}

function hashKey(key) {
  return crypto.createHash("sha256").update(key).digest("hex");
}

function makeKey() {
  return PREFIX + crypto.randomBytes(24).toString("base64url");
}

async function saveKey({ name, scopes }) {
  const raw = makeKey();
  const record = {
    id: crypto.randomUUID(),
    name,
    keyPrefix: raw.slice(0, 18),
    keyHash: hashKey(raw),
    scopes: Array.isArray(scopes) && scopes.length ? scopes : ["chat"],
    status: "active",
    usageCount: 0
  };

  if (pool) {
    await pool.query(
      `INSERT INTO bhai_api_keys
       (name,key_prefix,key_hash,scopes)
       VALUES ($1,$2,$3,$4::jsonb)`,
      [record.name, record.keyPrefix, record.keyHash, JSON.stringify(record.scopes)]
    );
  } else {
    memoryKeys.set(record.keyHash, record);
  }

  return { key: raw, ...record, keyHash: undefined };
}

async function authenticate(req, res, next) {
  const header = req.headers.authorization || "";
  const raw = header.startsWith("Bearer ") ? header.slice(7).trim() : "";
  if (!raw) {
    return res.status(401).json({
      error: { type: "authentication_error", message: "Missing Bearer API key." },
      request_id: req.requestId
    });
  }

  const keyHash = hashKey(raw);
  let record;

  if (pool) {
    const result = await pool.query(
      "SELECT id,name,scopes,status,usage_count FROM bhai_api_keys WHERE key_hash=$1 LIMIT 1",
      [keyHash]
    );
    record = result.rows[0];
    if (record) {
      record.scopes = Array.isArray(record.scopes) ? record.scopes : [];
    }
  } else {
    record = memoryKeys.get(keyHash);
  }

  if (!record || record.status !== "active") {
    return res.status(401).json({
      error: { type: "authentication_error", message: "Invalid or revoked API key." },
      request_id: req.requestId
    });
  }

  req.apiKey = record;
  next();
}

function requireScope(scope) {
  return (req, res, next) => {
    if (!req.apiKey?.scopes?.includes(scope) && !req.apiKey?.scopes?.includes("*")) {
      return res.status(403).json({
        error: { type: "permission_error", message: `API key does not have the '${scope}' scope.` },
        request_id: req.requestId
      });
    }
    next();
  };
}

async function recordUsage(req) {
  if (pool && req.apiKey?.id) {
    await pool.query(
      "UPDATE bhai_api_keys SET usage_count=usage_count+1,last_used_at=NOW() WHERE id=$1",
      [req.apiKey.id]
    );
  } else if (req.apiKey) {
    req.apiKey.usageCount = (req.apiKey.usageCount || 0) + 1;
  }
}

app.get("/health", (_req, res) => {
  res.json({ ok: true, service: "BHAI API", version: "1.0.0" });
});

app.get("/v1/health", (_req, res) => {
  res.json({
    ok: true,
    service: "BHAI API",
    api_version: "v1",
    database: Boolean(pool),
    timestamp: new Date().toISOString()
  });
});

app.post("/v1/keys", async (req, res) => {
  const admin = req.headers["x-bhai-admin-key"];
  if (!process.env.BHAI_ADMIN_KEY || admin !== process.env.BHAI_ADMIN_KEY) {
    return res.status(401).json({
      error: { type: "authentication_error", message: "Admin key required." },
      request_id: req.requestId
    });
  }

  const name = String(req.body?.name || "Developer Key").slice(0, 120);
  const scopes = Array.isArray(req.body?.scopes) ? req.body.scopes : ["chat"];
  const created = await saveKey({ name, scopes });

  res.status(201).json({
    object: "api_key",
    key: created.key,
    name: created.name,
    scopes: created.scopes,
    created_at: new Date().toISOString()
  });
});

app.post("/v1/chat", authenticate, requireScope("chat"), async (req, res) => {
  await recordUsage(req);

  const messages = Array.isArray(req.body?.messages) ? req.body.messages : [];
  if (!messages.length) {
    return res.status(400).json({
      error: { type: "invalid_request_error", message: "messages is required." },
      request_id: req.requestId
    });
  }

  // Provider routing is intentionally isolated here. Real providers will be
  // added behind this boundary so BHAI API remains provider-independent.
  res.json({
    id: "chat_" + crypto.randomBytes(10).toString("hex"),
    object: "chat.completion",
    created: Math.floor(Date.now() / 1000),
    provider: "router",
    model: req.body?.model || "auto",
    choices: [],
    status: "provider_not_configured",
    message: "BHAI API gateway is ready. Connect a provider in the next step.",
    request_id: req.requestId
  });
});

app.use((err, req, res, _next) => {
  console.error(err);
  res.status(500).json({
    error: { type: "internal_error", message: "Internal server error." },
    request_id: req.requestId
  });
});

initDb()
  .then(() => app.listen(PORT, () => console.log(`BHAI API listening on ${PORT}`)))
  .catch((err) => {
    console.error("Database initialization failed:", err);
    process.exit(1);
  });
