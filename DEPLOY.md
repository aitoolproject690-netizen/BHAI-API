# BHAI API deployment

## Render

Create a Web Service from this repository.

Build command:
```
npm install
```

Start command:
```
npm start
```

Set these environment variables:

- PORT (Render provides this automatically)
- DATABASE_URL (PostgreSQL connection string)
- BHAI_ADMIN_KEY (private key used only to create developer API keys)
- CORS_ORIGIN (use the required frontend origins; `*` is acceptable only for initial testing)
- Provider keys will be added after the gateway health test.

## First test

```
GET /health
GET /v1/health
```

Create a developer key:

```
POST /v1/keys
X-Bhai-Admin-Key: YOUR_ADMIN_KEY
Content-Type: application/json

{"name":"BHAI X","scopes":["chat"]}
```

The raw API key is returned only on creation. Store it securely.
