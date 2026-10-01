# BHAI API

Standalone API gateway for the BHAI ecosystem.

## Architecture

BHAI X and external developer apps are clients of BHAI API.

```
BHAI X / Developer App
        |
        v
     BHAI API
        |
        +--> AI providers
        +--> Image providers
        +--> Video providers
        +--> GitHub / tools
```

## Current foundation

- Versioned API under `/v1`
- Secure API-key authentication
- Scope-based access control
- Request IDs
- Usage-ready API key storage
- Health endpoint
- Provider-neutral chat gateway foundation
- CORS + security headers
- PostgreSQL support

## Endpoints

- `GET /health`
- `GET /v1/health`
- `POST /v1/chat`

## API key

Send:

```
Authorization: Bearer bhai_live_xxxxxxxxx
```

The raw key is shown only when it is created. The server stores only its SHA-256 hash.

## Roadmap

1. Chat
2. Coding / code-fix
3. Image
4. Video
5. Files
6. Search
7. GitHub
8. Agent / Mission
9. Usage, quotas and billing
10. Developer dashboard and public documentation

Provider limits remain provider limits; BHAI API itself will not add an arbitrary personal-use monthly cap.
