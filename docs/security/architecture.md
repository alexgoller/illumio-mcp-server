---
title: Architecture
layout: default
parent: Security
---

# Security Architecture

## Five-layer defense

Every tool call on the HTTP transport passes through five ordered gates. Failing any gate aborts the call and records an audit entry. Stdio mode skips layers 1–5 (the operator who launched the process is implicitly trusted as admin).

```
Layer 1: JWT validation
  Checks: signature (RS256/ES256 against JWKS), iss == MCP_OAUTH_ISSUER,
          aud == MCP_OAUTH_AUDIENCE, exp not past, nbf not future,
          scope contains MCP_OAUTH_REQUIRED_SCOPE (default: illumio-mcp.use)
  Failure: 401 with WWW-Authenticate: Bearer resource_metadata="..."
  Implementation: auth/jwt_validator.py JWTValidator.validate()

Layer 2: Role mapping
  Maps JWT groups/roles claim to {reader, operator, admin} using
  MCP_ROLE_GROUPS_{ADMIN,OPERATOR,READER}. Highest-matching role wins.
  MCP_ROLE_DEFAULT is a fallback if no group matches.
  Failure: denied, reason=forbidden_no_role
  Implementation: auth/roles.py map_user_role()

Layer 3: Per-tool role allowlist
  Each tool has explicit roles= in TOOL_REGISTRY (tools/__init__.py).
  Default-deny: a new tool without roles= fails at import time.
  Failure: denied, reason=forbidden
  Implementation: registry.py ToolSpec.roles, enforced in server.py dispatcher

Layer 4: PCE-presence gate
  Tools with requires_pce=True (the default) need ctx.pce to be non-None.
  In per_user mode, ctx.pce is None until the user registers credentials.
  Credential-management tools (register-pce-credentials etc.) have
  requires_pce=False and are always callable.
  Failure: denied, reason=no_pce_credentials
  Implementation: registry.py ToolSpec.requires_pce, enforced in server.py dispatcher

Layer 5: Confirm-token requirement
  Tools with requires_confirm=True (provision-policy, ringfence-batch) require
  a server-issued HMAC-SHA256 token in params._meta.confirm_token. Tokens are
  single-use (jti tracked in SQLite), scoped to (sub, tool, params_hash), and
  expire in MCP_CONFIRM_TTL_SECONDS (default 120s).
  Failure: denied, reason=confirm_required | invalid_confirm_token | confirm_token_replay
  Implementation: auth/confirm.py, auth/confirm_replay.py, transport/confirm_endpoint.py
```

---

## Cryptography choices

### Per-user keystore: AES-256-GCM envelope encryption

Each user's PCE API key and secret are stored with two-tier envelope encryption:

```
MCP_KEK (32 bytes, from env/KMS)
    |
    | AES-256-GCM (nonce: 12 bytes)
    v
Data Key (DK, 32 bytes, fresh per-record)
    |
    | AES-256-GCM (nonce: 12 bytes, AAD: "sub|iss")
    v
Encrypted payload (api_key_enc or api_secret_enc)
```

Wire format per blob: `nonce_dk(12) || dk_ciphertext(48) || nonce_payload(12) || payload_ciphertext(N+16)`.

The Additional Authentication Data (`sub|iss`) binds the ciphertext to its database row. If a ciphertext is copied to a different row, decryption fails — the AEAD tag will not verify.

Source: `src/illumio_mcp/auth/crypto.py`

### Confirm tokens: HMAC-SHA256

Token format: `<base64url(payload_json)>.<base64url(hmac_sha256)>`

Payload fields: `{sub, tool, params_hash, jti, exp}`. The HMAC covers the full payload. Any tampering (wrong sub, wrong tool, different params) invalidates the signature. Single-use is enforced by recording the `jti` in a SQLite table on first use.

Source: `src/illumio_mcp/auth/confirm.py`

### JWT validation: RS256/ES256 against JWKS

PyJWT's `PyJWKClient` fetches and caches the IdP's JWKS. The cache is refreshed on `kid` mismatch (key rotation). Supported algorithms: RS256, ES256. Token validation is local — no per-request calls to the IdP.

Source: `src/illumio_mcp/auth/jwt_validator.py`

---

## What is stored where

| Data | Location | Permissions | Notes |
|---|---|---|---|
| KEK | Process env only (`MCP_KEK`) | Never persisted | Loss = total keystore loss (intentional) |
| Per-user PCE creds (encrypted) | `MCP_KEYSTORE_PATH` SQLite (default `./data/keys.db`) | `chmod 600`, `umask 077` on create | Decryptable only with KEK |
| Audit log | `MCP_AUDIT_LOG_PATH` SQLite (default `./data/audit.db`) | `chmod 600`, `umask 077` on create | No secrets; safe to ship to SIEM |
| JTI replay store | `MCP_CONFIRM_JTI_PATH` SQLite (default alongside keystore) | `chmod 600`, `umask 077` on create | Used JTI values only; expires with TTL |
| HMAC key | Process env only (`MCP_CONFIRM_HMAC_KEY`) | Never persisted | Rotation invalidates outstanding tokens |
| IdP JWKS | In-process cache only | Never persisted | Auto-refreshed on key rotation |

The SQLite files are created with `os.umask(0o077)` before `sqlite3.connect()` and then `os.chmod(path, 0o600)`. This means they are readable and writable only by the process owner on POSIX systems.

---

## Unauthenticated endpoints

These endpoints intentionally require no `Authorization` header:

- `GET /healthz` — liveness check
- `GET /readyz` — readiness check
- `GET /.well-known/oauth-protected-resource` — RFC 9728 PRM document (tells clients where the AS is)

All other endpoints (including `/setup` and `/confirm`) are protected by `JWTAuthMiddleware`.
