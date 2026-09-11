---
title: HTTP mode
layout: default
parent: Operations
---

# HTTP Mode

The HTTP transport exposes the MCP server over Streamable HTTP (MCP spec rev 2025-03-26), allowing any compliant MCP client to connect by URL rather than requiring a local subprocess install.

---

## Architectural overview

Every authenticated request passes through five ordered gates before reaching a tool handler:

```
MCP Client
    |
    | POST /mcp  Authorization: Bearer <jwt>
    v
RequestIdMiddleware          -- generates X-Request-Id UUID
    |
JWTAuthMiddleware            -- validates JWT: sig, iss, aud, exp, scope
    |  401 if invalid
    v
ASGI context wrapper         -- maps JWT groups → role; builds ToolContext
    |                           (looks up per-user PCE creds from keystore
    |                            or uses shared env creds in shared mode)
    v
dispatcher (server.py)       -- enforces:
    |    1. Role allowlist (ToolSpec.roles)
    |    2. PCE-presence gate (ToolSpec.requires_pce)
    |    3. Confirm-token requirement (ToolSpec.requires_confirm)
    |    writes AuditEntry for every decision
    v
handler(ctx, arguments)      -- ctx.pce is ready; makes PCE API calls
```

---

## Per-user mode (default)

In `per_user` mode (`MCP_PCE_MODE=per_user`, the default), each authenticated user has their own PCE API key stored encrypted in a SQLite keystore. PCE-side audit logs attribute actions to the individual user.

### Required env vars

```bash
# OAuth
export MCP_PUBLIC_URL=https://mcp.illumio.example
export MCP_OAUTH_ISSUER=https://login.microsoftonline.com/<tenant-id>/v2.0
export MCP_OAUTH_JWKS_URL=https://login.microsoftonline.com/<tenant-id>/discovery/v2.0/keys
export MCP_OAUTH_AUDIENCE=https://mcp.illumio.example

# Keystore
export MCP_KEK=$(python -c 'import os, base64; print(base64.b64encode(os.urandom(32)).decode())')
export MCP_KEYSTORE_PATH=/var/lib/illumio-mcp/keys.db

# Confirm tokens
export MCP_CONFIRM_HMAC_KEY=$(python -c 'import os, base64; print(base64.b64encode(os.urandom(32)).decode())')

# Role mapping
export MCP_ROLE_GROUPS_ADMIN=sg-illumio-mcp-admin
export MCP_ROLE_GROUPS_OPERATOR=sg-illumio-mcp-operator,sg-illumio-mcp-admin
export MCP_ROLE_GROUPS_READER=sg-illumio-mcp-readonly,sg-illumio-mcp-operator,sg-illumio-mcp-admin

# Start
illumio-mcp-http --host 127.0.0.1 --port 8080
```

### User onboarding

First-time users land in the `no_pce_credentials` state. Two paths:

1. **Browser:** visit `https://mcp.illumio.example/setup` (after authenticating). Paste PCE host, port, org ID, API key, and API secret. The form writes encrypted credentials to the keystore.
2. **MCP client:** call the `register-pce-credentials` tool. This is the only tool that works before credentials are registered. Note that pasting a secret into a chat transcript leaves it in the LLM's context window — the browser path is preferred from a security standpoint.

After onboarding, all tools with the user's role become available immediately.

---

## Shared mode

In `shared` mode (`MCP_PCE_MODE=shared`), all authenticated users share one PCE service-account key loaded from env. No keystore, no `/setup` page, no `MCP_KEK` required. JWT auth, role-based authz, audit log, and confirm tokens all still apply.

The server-side audit log records per-human identity (`sub` from the JWT). PCE-side audit logs show only the service account.

### Required env vars

```bash
# PCE service account (same vars stdio uses)
export PCE_HOST=https://your-pce.example.com
export PCE_PORT=8443
export PCE_ORG_ID=1
export API_KEY=service_account_key
export API_SECRET=service_account_secret

# OAuth (same as per-user)
export MCP_PUBLIC_URL=https://mcp.illumio.example
export MCP_OAUTH_ISSUER=https://login.microsoftonline.com/<tenant-id>/v2.0
export MCP_OAUTH_JWKS_URL=https://login.microsoftonline.com/<tenant-id>/discovery/v2.0/keys
export MCP_OAUTH_AUDIENCE=https://mcp.illumio.example

# Confirm tokens (required in auth mode)
export MCP_CONFIRM_HMAC_KEY=$(python -c 'import os, base64; print(base64.b64encode(os.urandom(32)).decode())')

# Role mapping
export MCP_ROLE_GROUPS_ADMIN=sg-illumio-mcp-admin
export MCP_ROLE_GROUPS_OPERATOR=sg-illumio-mcp-operator

# Mode
export MCP_PCE_MODE=shared

illumio-mcp-http --host 127.0.0.1 --port 8080
```

In shared mode:
- `/setup` is not mounted.
- `register-pce-credentials` and `delete-pce-credentials` return a `shared_mode` error message.
- `check-pce-credentials-status` returns `{"registered": true, "mode": "shared", ...}`.

---

## Safety gates

The server performs several checks at startup and at request time to prevent common misconfigurations:

**Startup checks:**

- `Refusing to bind '<host>' without MCP_DEV_INSECURE=1` — the server will not bind a non-loopback address unless `MCP_DEV_INSECURE=1` is set. Production deployments must put TLS termination at a reverse proxy and forward to `127.0.0.1`.
- `Missing required OAuth env vars: MCP_OAUTH_ISSUER, ...` — lists every missing var so you can fix them all at once.
- `MCP_KEK env var is required` — in per-user mode with auth enabled, the key-encryption-key must be present.
- `MCP_PCE_MODE=shared requires PCE_HOST env var` — shared mode validates the PCE env vars at startup rather than at first request.

**Request-time checks:**

- A 401 with `WWW-Authenticate: Bearer resource_metadata="..."` means the JWT was missing, expired, or had the wrong issuer, audience, or signature.
- A `forbidden_no_role` error means the user's JWT groups matched none of the configured `MCP_ROLE_GROUPS_*` lists.

---

## Health endpoints

Both endpoints are always unauthenticated — no `Authorization` header required.

- `GET /healthz` — liveness: `{"status": "ok"}`
- `GET /readyz` — readiness: `{"status": "ready"}`

---

## Reverse-proxy guidance

In production, terminate TLS at your load balancer or ingress controller and proxy to the MCP server on loopback:

```
Internet → HTTPS (your proxy/ingress) → HTTP http://127.0.0.1:8080
```

Required proxy configuration:
- Pass the `Authorization` header through unchanged (do not strip it).
- Do not cache responses to `/mcp` — the Streamable HTTP transport uses chunked SSE responses that must not be cached or buffered. Set `Cache-Control: no-store` and `X-Accel-Buffering: no` if using nginx.
- Pass `X-Request-Id` through if your proxy sets it; the server respects it for trace correlation.

---

## Hybrid mode (future work)

Phase 3f will add `MCP_PCE_MODE=hybrid`: users who have registered per-user credentials use them; others fall back to the shared service account. This allows teams to roll out shared mode for fast onboarding and let individual users opt in to per-user attribution later. See the [spec](../superpowers/specs/2026-05-12-phase-3f-hybrid-pce-mode-spec.md) for the design. Track via GitHub issue #17.
