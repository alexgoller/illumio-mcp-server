---
title: Troubleshooting
layout: default
parent: Operations
---

# Troubleshooting

Common errors, what they mean, and how to fix them.

---

## 401 with `WWW-Authenticate: Bearer resource_metadata=...`

**What it means:** The request to `/mcp` was rejected because the JWT was missing, malformed, expired, or had the wrong issuer, audience, or scope.

The `WWW-Authenticate` header points to `/.well-known/oauth-protected-resource`, which tells spec-compliant MCP clients where to find the Authorization Server and run PKCE auth code flow.

**How to diagnose:**

1. Decode the JWT at [jwt.io](https://jwt.io) and check:
   - `iss` matches `MCP_OAUTH_ISSUER` exactly (including the trailing `/v2.0` for Entra).
   - `aud` matches `MCP_OAUTH_AUDIENCE` exactly.
   - `exp` has not passed.
   - `scope` or `scp` contains `illumio-mcp.use` (or your configured `MCP_OAUTH_REQUIRED_SCOPE`).
2. Verify the server can reach the JWKS URL:
   ```bash
   curl -s $MCP_OAUTH_JWKS_URL | python -m json.tool | head -20
   ```
3. Check server logs for `InvalidTokenError` messages, which include a short reason code (`iss mismatch`, `aud mismatch`, `exp passed`, `missing required scope`, etc.).

---

## `forbidden_no_role`

**What it means:** The JWT is valid, but the user's groups (from the `groups` or `roles` claim) do not match any of the configured `MCP_ROLE_GROUPS_*` lists, and `MCP_ROLE_DEFAULT` is not set.

**How to fix:**

1. Decode the JWT and inspect the `groups` (Entra) or `roles` (Okta) claim. Copy one of the group values.
2. Check that the value exactly matches a group in `MCP_ROLE_GROUPS_READER`, `MCP_ROLE_GROUPS_OPERATOR`, or `MCP_ROLE_GROUPS_ADMIN`.
   - For Entra: you configured object IDs, not display names. Make sure you used the group's object ID, not its `cn` or display name.
3. If the user should have read access and no group-based provisioning is available yet, set `MCP_ROLE_DEFAULT=reader` as a temporary fallback.

---

## `forbidden`

**What it means:** The user has a role, but that role is not in the `roles=` allowlist for the tool they called. For example, a `reader` calling `create-workload` (which requires `operator` or `admin`).

**How to fix:** Either provision the user into a higher role group, or check that the tool's role metadata in `TOOL_REGISTRY` is correct for your use case.

---

## `no_pce_credentials`

**What it means (per-user mode only):** The authenticated user has no PCE credentials registered in the keystore. This is the expected state for new users who have not yet onboarded.

**How to fix:**

1. Direct the user to visit `https://<mcp-server>/setup` to register their PCE API key via the browser form.
2. Alternatively, the user can call the `register-pce-credentials` MCP tool — it is the only tool available in this state.

In shared mode, this error never appears (the shared service account is always available).

---

## `confirm_required`

**What it means:** The tool requires a single-use confirm token (it is marked `requires_confirm=True` in `TOOL_REGISTRY`). Currently: `provision-policy` and `ringfence-batch`.

**How to fix:**

1. The tool response includes a `params_hash` field (SHA-256 of canonical parameters).
2. Call `POST /confirm` with the JWT and the params_hash:
   ```bash
   curl -X POST https://mcp.illumio.example/confirm \
     -H "Authorization: Bearer $JWT" \
     -H "Content-Type: application/json" \
     -d '{"tool": "provision-policy", "params_hash": "<sha256-from-error>"}'
   # Response: {"confirm_token": "...", "expires_in": 120}
   ```
3. Re-call the tool with the token in `params._meta.confirm_token`.

Tokens expire in 120 seconds by default (configurable via `MCP_CONFIRM_TTL_SECONDS`).

---

## `confirm_token_replay`

**What it means:** The confirm token has already been used. Confirm tokens are single-use to prevent prompt-injection replay attacks.

**How to fix:** Mint a fresh token via `POST /confirm` and re-call the tool immediately.

---

## `MCP_KEK env var is required`

**What it means:** The server is starting in per-user HTTP mode (auth enabled, `MCP_PCE_MODE=per_user`) but `MCP_KEK` is not set. The server refuses to start because without a Key-Encryption-Key, it cannot decrypt stored per-user credentials.

**How to fix:**

```bash
export MCP_KEK=$(python -c 'import os, base64; print(base64.b64encode(os.urandom(32)).decode())')
```

Store this value securely — in KMS, Vault, or your deployment secrets manager. If you lose the KEK, all per-user PCE credentials stored in the keystore are permanently unrecoverable.

In shared mode (`MCP_PCE_MODE=shared`), `MCP_KEK` is not required.

---

## `Refusing to bind '0.0.0.0' without MCP_DEV_INSECURE=1`

**What it means:** The server refused to start because you attempted to bind a non-loopback address (`0.0.0.0`, a public IP, etc.) without explicitly opting in with `MCP_DEV_INSECURE=1`.

**Why this gate exists:** In dev-insecure mode there is no authentication. Accidentally binding `0.0.0.0` in dev-insecure mode would expose the server without auth to anyone on the network.

**In production:** Do not bind `0.0.0.0` directly. Instead, bind `127.0.0.1` and put a TLS-terminating reverse proxy in front:

```bash
illumio-mcp-http --host 127.0.0.1 --port 8080
# Reverse proxy handles TLS and forwards to 127.0.0.1:8080
```

**For local dev testing only:** If you genuinely need to expose the server on a network interface without auth (for example, to test from another machine in a lab), set `MCP_DEV_INSECURE=1`. This is not safe for production.

---

## Tests pass on `main` but fail with PCE

The integration test suite (`tests/test_mcp_tools.py`) requires a real PCE. Tests are skipped or fail if the PCE env vars are missing or incorrect.

**Checklist:**

1. Verify `.env` exists and contains correct values:
   ```bash
   cat .env
   ```
2. Verify the test runner loads `.env`:
   ```bash
   grep -r "dotenv" tests/conftest.py src/
   ```
3. Test PCE connectivity directly:
   ```bash
   python -c "from illumio_mcp.pce import get_pce_from_env; pce = get_pce_from_env(); print(pce)"
   ```
4. Run only the PCE-free unit tests to isolate the issue:
   ```bash
   pytest tests/test_auth_*.py tests/test_context.py tests/test_registry.py tests/test_pce_builder.py tests/test_tool_metadata.py -v
   ```

---

## `MCP_CONFIRM_HMAC_KEY env var is required`

**What it means:** The server is starting in HTTP auth mode but `MCP_CONFIRM_HMAC_KEY` is not set. The confirm-token system requires an HMAC key to sign tokens.

**How to fix:**

```bash
export MCP_CONFIRM_HMAC_KEY=$(python -c 'import os, base64; print(base64.b64encode(os.urandom(32)).decode())')
```

---

## Server starts but clients cannot connect

1. Verify the server is listening:
   ```bash
   curl http://127.0.0.1:8080/healthz
   ```
2. If using a reverse proxy, verify the proxy passes the `Authorization` header and does not cache `/mcp` responses.
3. Check that the MCP client is using transport type "Streamable HTTP" (not the deprecated SSE transport).
4. Check `illumio-mcp.log` for startup errors.
