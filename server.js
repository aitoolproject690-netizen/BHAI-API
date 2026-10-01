import "dotenv/config";
import express from "express";
import cors from "cors";
import helmet from "helmet";
import crypto from "node:crypto";
import pg from "pg";

const { Pool } = pg;
const app = express();

const PORT = Number(process.env.PORT || 3000);
const HOST = "0.0.0.0";
const PREFIX = process.env.BHAI_API_KEY_PREFIX || "bhai_live_";
const GEMINI_MODEL = process.env.GEMINI_MODEL || "gemini-3.8-flash";
const pool = process.env.DATABASE_URL
  ? new Pool({
      connectionString: process.env.DATABASE_URL,
      ssl: { rejectUnauthorized: false },
      connectionTimeoutMillis: 5000,
    })
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

function putMemoryKey(raw, name = "BHAI Bootstrap Key", scopes = ["*"]) {
  const record = {
    id: "bootstrap",
    name,
    keyPrefix: raw.slice(0, 18),
    keyHash: hashKey(raw),
    scopes,
    status: "active",
    usageCount: 0
  };
  memoryKeys.set(record.keyHash, record);
  return record;
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
  try {
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
      if (record) record.scopes = Array.isArray(record.scopes) ? record.scopes : [];
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
  } catch (err) {
    next(err);
  }
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
  if (pool && req.apiKey?.id && req.apiKey.id !== "bootstrap") {
    await pool.query(
      "UPDATE bhai_api_keys SET usage_count=usage_count+1,last_used_at=NOW() WHERE id=$1",
      [req.apiKey.id]
    );
  } else if (req.apiKey) {
    req.apiKey.usageCount = (req.apiKey.usageCount || 0) + 1;
  }
}

function normalizeGeminiContents(messages) {
  return messages
    .filter((m) => m && m.role !== "system" && typeof m.content === "string")
    .map((m) => ({
      role: m.role === "assistant" ? "model" : "user",
      parts: [{ text: m.content }]
    }));
}

function getSystemInstruction(messages) {
  const system = messages
    .filter((m) => m?.role === "system" && typeof m.content === "string")
    .map((m) => m.content.trim())
    .filter(Boolean)
    .join("\n\n");
  return system || null;
}

async function callGemini({ messages, model, generationConfig }) {
  if (!process.env.GEMINI_API_KEY) {
    const err = new Error("GEMINI_API_KEY is not configured.");
    err.code = "provider_not_configured";
    throw err;
  }

  const contents = normalizeGeminiContents(messages);
  if (!contents.length) {
    const err = new Error("No usable user/assistant messages were provided.");
    err.code = "invalid_request";
    throw err;
  }

  const body = { contents };
  const systemInstruction = getSystemInstruction(messages);
  if (systemInstruction) body.systemInstruction = { parts: [{ text: systemInstruction }] };
  if (generationConfig && typeof generationConfig === "object") body.generationConfig = generationConfig;

  const response = await fetch(
    `https://generativelanguage.googleapis.com/v1beta/models/${encodeURIComponent(model)}:generateContent`,
    {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "x-goog-api-key": process.env.GEMINI_API_KEY
      },
      body: JSON.stringify(body)
    }
  );

  const data = await response.json().catch(() => ({}));

  if (!response.ok) {
    const providerMessage = data?.error?.message || `Gemini returned HTTP ${response.status}`;
    const err = new Error(providerMessage);
    err.code = "provider_error";
    err.status = response.status;
    err.provider = "gemini";
    throw err;
  }

  const text = (data?.candidates || [])
    .flatMap((candidate) => candidate?.content?.parts || [])
    .map((part) => part?.text)
    .filter(Boolean)
    .join("\n");

  return { text, raw: data };
}

app.get("/", (_req, res) => {
  res.json({
    ok: true,
    service: "BHAI API",
    version: "1.0.0",
    status: "online",
    health: "/health",
    api: "/v1"
  });
});

app.get("/health", (_req, res) => {
  res.status(200).json({ ok: true, service: "BHAI API", version: "1.0.0" });
});

app.get("/v1/health", (_req, res) => {
  res.json({
    ok: true,
    service: "BHAI API",
    api_version: "v1",
    database: Boolean(pool),
    gemini_configured: Boolean(process.env.GEMINI_API_KEY),
    bootstrap_key_configured: Boolean(process.env.BHAI_BOOTSTRAP_API_KEY),
    timestamp: new Date().toISOString()
  });
});

app.post("/v1/keys", async (req, res, next) => {
  try {
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
  } catch (err) {
    next(err);
  }
});

app.post("/v1/chat", authenticate, requireScope("chat"), async (req, res, next) => {
  try {
    const messages = Array.isArray(req.body?.messages) ? req.body.messages : [];
    if (!messages.length) {
      return res.status(400).json({
        error: { type: "invalid_request_error", message: "messages is required." },
        request_id: req.requestId
      });
    }

    const model = String(req.body?.model || GEMINI_MODEL);
    const result = await callGemini({
      messages,
      model,
      generationConfig: req.body?.generationConfig
    });

    await recordUsage(req);

    res.json({
      id: "chat_" + crypto.randomBytes(10).toString("hex"),
      object: "chat.completion",
      created: Math.floor(Date.now() / 1000),
      provider: "gemini",
      model,
      choices: [
        {
          index: 0,
          message: { role: "assistant", content: result.text },
          finish_reason: result.raw?.candidates?.[0]?.finishReason || "STOP"
        }
      ],
      usage: result.raw?.usageMetadata || null,
      status: "completed",
      request_id: req.requestId
    });
  } catch (err) {
    if (err.code === "invalid_request") {
      return res.status(400).json({
        error: { type: "invalid_request_error", message: err.message },
        request_id: req.requestId
      });
    }
    if (err.code === "provider_not_configured") {
      return res.status(503).json({
        error: { type: "provider_not_configured", message: "Gemini provider is not configured on BHAI API." },
        request_id: req.requestId
      });
    }
    if (err.code === "provider_error") {
      return res.status(502).json({
        error: { type: "provider_error", provider: err.provider, message: err.message },
        request_id: req.requestId
      });
    }
    next(err);
  }
});

app.use((err, req, res, _next) => {
  console.error("BHAI API error:", err);
  res.status(500).json({
    error: { type: "internal_error", message: "Internal server error." },
    request_id: req.requestId
  });
});

process.on("unhandledRejection", (err) => console.error("Unhandled rejection:", err));
process.on("uncaughtException", (err) => console.error("Uncaught exception:", err));

const server = app.listen(PORT, HOST, () => {
  console.log(`BHAI API listening on http://${HOST}:${PORT}`);
});

server.on("error", (err) => {
  console.error("HTTP server failed to start:", err);
});

if (process.env.BHAI_BOOTSTRAP_API_KEY) {
  putMemoryKey(process.env.BHAI_BOOTSTRAP_API_KEY, "BHAI Owner Key", ["*"]);
}

initDb()
  .then(() => console.log("BHAI API database initialization complete"))
  .catch((err) => console.error("Database initialization deferred:", err.message));
