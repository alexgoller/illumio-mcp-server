# Illumio MCP Server — HTTP Transport + Multi-User Authentication

**Status:** Draft for review
**Date:** 2026-05-12
**Author:** Alex Goller (with Claude)
**Driving customer:** T-Mobile — wants to expose the Illumio MCP server to many users without giving each one a `claude_desktop_config.json` and a copy of the PCE service-account key.

---

## 1. Problem & Goals

Today the Illumio MCP server runs only over **stdio**. Each user installs the package locally, drops PCE credentials into `.env`, and points Claude Desktop / Cursor / Codex at it. That model has three hard limits:

1. **No central control.** Every user has the same PCE service-account creds in plaintext on disk. Revocation = a phone call to every user.
2. **No identity in the audit trail.** PCE logs show "the MCP service account did X", not "alex@tmo.de did X".
3. **Doesn't scale to N users.** Onboarding is a per-laptop install + secret distribution. T-Mobile wants to "hand over control to more users" — that's not a stdio story.

### Goals

- Expose the MCP server over **HTTP** so any compliant MCP client can connect by URL.
- Authenticate **human users** via T-Mobile's IdP (SSO + MFA + revocation).
- Each user calls PCE with **their own** PCE API key, so PCE-side audit logs attribute correctly and PCE RBAC works.
- Defense in depth around **mutating** tools — at least one human-in-the-loop step before destructive policy changes.
- **Don't break stdio** — local power users (including the maintainer) keep their workflow.
- Keep it **operable by one team**. No microservice sprawl, no dependency on infrastructure T-Mobile may not have yet.

### Non-goals (v1)

- Becoming an OAuth Authorization Server. We are only a Resource Server; the IdP runs OAuth.
- Multi-PCE routing / SaaS. One MCP server fronts one PCE. Data model leaves room for multi-tenant later but no routing logic ships now.
- Replacing the PCE's own RBAC. We add layers *on top of* PCE RBAC, not in place of it.
- Per-tool fine-grained policy DSL. Roles + an allowlist + scope filters cover v1; a richer policy engine is a v2 conversation if needed.

---

## 2. Why HTTP, and which HTTP

The MCP spec has had three transports:

| Transport             | Spec status   | Notes                                                                |
|-----------------------|---------------|----------------------------------------------------------------------|
| stdio                 | Current       | Local only. What we have today.                                      |
| HTTP+SSE (two-endpoint) | **Deprecated** | The original network transport (`/sse` + `/messages?sessionId=...`). Replaced. |
| **Streamable HTTP**     | **Current** (2025-03-26 spec rev, refined 2025-06-18) | Single endpoint. Supersedes HTTP+SSE.    |

We implement **Streamable HTTP only**. Every modern MCP client (Claude Desktop, ChatGPT, Cursor, MCP Inspector, the SDKs) speaks it. Implementing the deprecated SSE transport would double the test matrix to support clients we don't have.

### Streamable HTTP in one paragraph

A single HTTP endpoint (we'll use `POST /mcp` and optional `GET /mcp`). The client `POST`s a JSON-RPC request. The server responds either with `application/json` (one message) **or** `text/event-stream` (a stream of events that ends in the final response) — the server picks per request based on whether streaming is useful for that call. The optional `GET /mcp` upgrades to a server→client SSE channel for unsolicited notifications (progress, logs). Sessions are identified by an opaque `Mcp-Session-Id` header that the server issues on `initialize` and the client echoes on every subsequent request. The server may rotate or invalidate that ID.

This is the only network transport we need to support.

---

## 3. Authentication: design decisions and why

### 3.1 Credential model — Hybrid: SSO to server + per-user PCE keys

**Decision.** Users authenticate to the MCP server via T-Mobile's IdP (SSO). The MCP server then calls PCE using a **PCE API key that belongs to that specific user**, stored encrypted on the server side and looked up by the IdP's stable `sub` claim.

**Why this and not the alternatives.**

- *Shared service account + per-user authz on the MCP server* would have made onboarding trivial but turns the MCP server into a single high-value target. One mistake in our authz code = "anyone can do anything in PCE as the service account". And PCE-side audit logs would be useless: every action looks like the service account.
- *Per-user PCE keys with the user supplying them per request (BYO at runtime)* gets us PCE attribution but throws away the SSO benefits — no MFA, no central revocation, no group-based access control.
- *True OAuth → PCE token-exchange* would be cleanest if PCE supported federated auth on its API. It doesn't (PCE API uses long-lived API key/secret pairs; SAML/OIDC sessions are for the UI, not the API). So we can't have it; we approximate it with stored per-user keys.

**The hybrid model gives us:**

- SSO + MFA + revocation from T-Mobile's IdP (server side: kill the JWT, kill access).
- PCE audit attribution per real human (PCE side: API key is per-user).
- Symmetric revocation: deleting a row in our key table also instantly cuts the user off without touching PCE.
- A clean place to layer additional authz (roles, scopes, confirm tokens) without depending on the IdP for every decision.

### 3.2 OAuth shape — Resource Server only, IdP-agnostic

**Decision.** The MCP server is **only an OAuth 2.1 Resource Server**. The Authorization Server is whatever IdP the operator configures — Entra ID, Okta, Auth0, Keycloak. We do JWT validation locally against a configured `issuer` + JWKS URL. We do not run our own AS, we do not federate, we do not implement Dynamic Client Registration on our side.

**Why.**

- The MCP spec's authorization section (2025-06-18) standardized exactly this: server publishes a Protected Resource Metadata document (RFC 9728), client discovers the AS from it, client does PKCE auth code flow against the AS, client presents the resulting access token to the resource. This is the path Claude Desktop, ChatGPT, Cursor, and MCP Inspector already take.
- T-Mobile is unlikely to want a new OAuth provider in their environment. Whatever IdP they already trust for workforce SSO is the one they want to keep using.
- IdP-agnostic = future-proof. No code changes to swap Entra for Okta; just point at a different `issuer`.

### 3.3 Fitting MCP clients into a closed enterprise IdP

The one operational footgun: most enterprise IdPs **disable open Dynamic Client Registration**. So Claude Desktop can't just register itself with T-Mobile's Entra tenant on first launch. Each MCP client (Claude Desktop, ChatGPT desktop, Cursor, custom T-Mobile clients) must be **pre-registered as an OAuth app** in the IdP, with the right redirect URIs. We document the exact values for each client we expect to support.

If/when we want zero-touch client onboarding, the answer is to insert a small **MCP-specific AS** in front of the corp IdP that does federation + DCR for us. That's a v2 conversation, not v1.

### 3.4 Wire-level auth flow

```
1. Client → MCP:   POST /mcp  (no auth)
   MCP → Client:   401
                   WWW-Authenticate: Bearer
                     resource_metadata="https://mcp.illumio.tmo/.well-known/oauth-protected-resource"

2. Client fetches /.well-known/oauth-protected-resource:
   {
     "resource": "https://mcp.illumio.tmo",
     "authorization_servers": ["https://login.microsoftonline.com/<tenant>/v2.0"],
     "bearer_methods_supported": ["header"],
     "scopes_supported": ["illumio-mcp.use"]
   }

3. Client fetches the AS metadata, runs PKCE auth code flow against the IdP,
   user authenticates (SSO + MFA), client gets a JWT access token.

4. Client → MCP:   POST /mcp  Authorization: Bearer <jwt>
   MCP validates locally:
     - Signature against cached JWKS (with rotation)
     - iss == configured issuer
     - aud == our resource indicator
     - exp not past, nbf not future
     - scope contains 'illumio-mcp.use'
   Failure → 401 with structured WWW-Authenticate.

5. MCP extracts sub → looks up user's PCE key in encrypted store →
   builds per-request PCE client → routes to handler.
```

**Performance.** JWKS is cached. Token validation is local — sub-millisecond per request. We never call the IdP per request.

---

## 4. Per-user PCE credentials

### 4.1 Storage — SQLite + envelope encryption

**Decision.** A single SQLite database file (default `./data/keys.db`, configurable via `MCP_KEYSTORE_PATH`). Per-user PCE credentials are stored with envelope encryption: a per-row data key encrypts the secret material, and the data key is encrypted by a Key-Encryption-Key (KEK) loaded at process startup from a configurable source.

**Why SQLite + envelope encryption.**

- Zero infrastructure dependency. Important because we don't yet know what infra is on offer at T-Mobile, and we want a dev-mode that runs from `pip install` with nothing else.
- Envelope encryption gives us KEK rotation without re-encrypting every row (rotate KEK → re-encrypt only data keys).
- The `KeyStore` is a small interface; swapping in **HashiCorp Vault** or **AWS KMS-backed Postgres** later is a config change, not a rewrite. T-Mobile probably already runs Vault — when they're ready to wire it up, we add a `VaultKeyStore` driver alongside `SQLiteKeyStore`.

**Schema.**

```sql
CREATE TABLE user_pce_credentials (
    sub               TEXT PRIMARY KEY,         -- IdP subject (stable per user)
    issuer            TEXT NOT NULL,            -- multi-IdP safe; (sub, iss) is the real identity
    pce_host          TEXT NOT NULL,
    pce_port          INTEGER NOT NULL,
    pce_org_id        INTEGER NOT NULL,
    api_key_enc       BLOB NOT NULL,            -- envelope-encrypted
    api_secret_enc    BLOB NOT NULL,
    nonce             BLOB NOT NULL,            -- per-row XChaCha20 nonce
    data_key_enc      BLOB NOT NULL,            -- data key encrypted by KEK
    created_at        TEXT NOT NULL,
    last_used_at      TEXT,
    label             TEXT
);

CREATE TABLE user_roles (
    sub               TEXT NOT NULL,
    issuer            TEXT NOT NULL,
    role              TEXT NOT NULL,            -- 'reader' | 'operator' | 'admin'
    PRIMARY KEY (sub, issuer, role)
);

CREATE TABLE user_scopes (
    sub               TEXT NOT NULL,
    issuer            TEXT NOT NULL,
    label_key         TEXT NOT NULL,            -- 'app' or 'env'
    label_value       TEXT NOT NULL,
    PRIMARY KEY (sub, issuer, label_key, label_value)
);

CREATE TABLE audit_log (
    id                INTEGER PRIMARY KEY,
    ts                TEXT NOT NULL,
    sub               TEXT,
    issuer            TEXT,
    tool              TEXT NOT NULL,
    decision          TEXT NOT NULL,            -- 'allowed' | 'denied' | 'error'
    reason            TEXT,
    request_id        TEXT NOT NULL,
    confirm_token_id  TEXT,
    pce_request_id    TEXT                      -- when we can extract it
);

CREATE INDEX idx_audit_sub_ts ON audit_log(sub, ts DESC);
```

**Crypto.** XChaCha20-Poly1305 (libsodium `crypto_secretbox_xchacha20poly1305`). 24-byte nonce per row, AEAD with the row's `(sub, issuer)` as additional data so a swapped row decrypts to garbage. Both `api_key_enc` and `api_secret_enc` are encrypted with the same row data key.

**KEK source.** Configurable: `MCP_KEK_SOURCE=env|file|aws-kms|vault-transit`. Default `env` reads a 32-byte base64 KEK from `MCP_KEK`. Production deployments use `aws-kms` (returns plaintext KEK from a KMS key) or `vault-transit` (Vault performs the unwrap server-side; KEK never leaves Vault). The KEK is **never** stored in SQLite. Loss of KEK = total loss of stored creds; this is intentional ("fail closed").

### 4.2 User onboarding flow

When a JWT-authenticated user makes any tool call and we have **no row** for their `(sub, issuer)`:

1. The server returns a structured MCP error with `code: "no_pce_credentials"` and a `data.setup_url` pointing at `/setup`.
2. The user opens `/setup` in a browser (the same OAuth flow gates it). They paste **PCE host, port, org ID, API key, API secret**, give it an optional label, and submit.
3. Server encrypts and writes the row. Subsequent tool calls succeed.

**MCP-native alternative path.** We also expose a `register-pce-credentials` tool that's the *only* tool callable in the no-creds-yet state. This lets users finish onboarding without leaving Claude. Both paths land in the same code; the browser path is documented as the recommended one for security review reasons (pasting a secret into a chat transcript leaves it in the LLM's context).

**Self-service rotation.** A `rotate-pce-credentials` tool and a `/setup` page that detects an existing row let users update their key without admin intervention — important when their PCE key expires.

---

## 5. Authorization — five composable layers

Every tool call goes through these checks in order. Failing any layer aborts the call with a structured error and an `audit_log` row. Layer 1 is the JWT check from §3.4, restated here for completeness; layers 2–5 are the additional checks chosen for this design.

### Layer 1 — JWT validation
Already covered in §3.4. Required `scope: illumio-mcp.use`. Failure → `401`.

### Layer 2 — Role assignment from IdP groups + DB override

The JWT `groups` (Entra) or `roles` (Okta) claim is mapped to one of three roles via operator config:

```yaml
role_mapping:
  reader:   ["sg-illumio-mcp-readonly", "sg-illumio-mcp-operator", "sg-illumio-mcp-admin"]
  operator: ["sg-illumio-mcp-operator", "sg-illumio-mcp-admin"]
  admin:    ["sg-illumio-mcp-admin"]
```

The user's effective role is the **highest** they qualify for. Users without group provisioning can be assigned a role directly via the `user_roles` table (an admin tool). No matching role → `403`.

Three roles is intentionally the minimum that makes the access story expressible:

| Role     | Meaning                                                                 |
|----------|-------------------------------------------------------------------------|
| reader   | Can call non-mutating tools. The "hand control to more users" baseline. |
| operator | reader + most mutating tools, except provisioning and bulk ops.         |
| admin    | All tools. Can grant scopes/roles. Required for `provision-policy`.     |

### Layer 3 — Per-tool allowlist

Declared next to each handler via decorator metadata:

```python
@tool(name="get-workloads", roles={"reader", "operator", "admin"})
@tool(name="create-workload", roles={"operator", "admin"}, mutating=True)
@tool(name="provision-policy", roles={"admin"}, mutating=True, requires_confirm=True)
@tool(name="ringfence-batch", roles={"admin"}, mutating=True, requires_confirm=True)
```

**Default-deny.** A tool with no `roles=` is admin-only. A new contributor adding a tool can't accidentally expose it to readers.

### Layer 4 — Scope restrictions (optional, per user)

Some users should only see/touch *their* apps. The `user_scopes` table maps `(sub, issuer)` → allowed `(label_key, label_value)` pairs (`app`, `env`).

Enforcement model:

- **Reads.** A small middleware injects the user's scope filter into list-style calls (`get-workloads`, `get-traffic-flows`) by AND-ing the user's allowed labels into the existing query.
- **Writes.** Handlers that mutate a workload/ruleset call `scope.assert_label_in_scope(href, user.scopes)` before sending the change to PCE. Failure → `403` with the offending label.
- **Unscopable tools.** Some tools (`get-policy-coverage-report`, `compliance-check`) return PCE-wide data we can't safely filter. These are explicitly tagged `unscopable=True` and refused for users with any scope restriction. They remain available to admins.

This layer is opt-in: users with no rows in `user_scopes` are unrestricted (subject to their role). Most reader-tier users in production will have scopes.

### Layer 5 — Confirmation token for mutating tools

The load-bearing layer for the "hand control safely to more users" goal.

For any tool marked `mutating=True`, the JSON-RPC `params._meta.confirm_token` field must contain a server-issued, single-use, scoped token. Tokens are minted by `POST /confirm`:

```
Client → MCP:   POST /confirm
                Authorization: Bearer <jwt>
                { "tool": "delete-workload", "params_hash": "<sha256 of canonical params>" }

MCP → IdP:      Re-prompt with prompt=login (or acr_values=urn:mfa) — step-up auth.

MCP → Client:   { "confirm_token": "...", "expires_in": 120 }
```

Token format: HMAC-SHA256 of `(sub, tool, params_hash, jti, exp)` with a server secret. Server records `jti` in `audit_log` on use to reject replays. TTL 120 seconds. Single-use.

**Why this matters.** The realistic threat model includes prompt injection: a malicious traffic-flow description in PCE could try to convince the LLM to call `delete-workload` or `provision-policy` on its own. The confirm token forces a synchronous human-in-the-loop step the LLM can't fake — even if it has the JWT, it can't mint the token without the user re-authenticating in their browser.

This adds friction. The mitigation is that **only mutating tools** require it, and the UX in Claude Desktop is "click the link, approve in a browser, return to chat" — same pattern as `gh auth refresh`.

---

## 6. Code restructuring

The current `pce.py` is the only structural blocker: it caches one `PolicyComputeEngine` keyed by process env. For HTTP we need per-request PCE clients without rewriting tool handlers. Surgical changes:

### 6.1 New `context.py`

```python
@dataclass
class ToolContext:
    pce: PolicyComputeEngine
    user_sub: str | None       # None in stdio mode
    user_iss: str | None
    role: Role                 # 'admin' for stdio
    scopes: list[Scope]        # [] in stdio mode = unrestricted
    request_id: str
    is_stdio: bool
```

One object, passed to every handler. The PCE client is built per request from the looked-up creds; in stdio mode it's the env-var singleton (preserving today's behavior exactly).

### 6.2 `pce.py` becomes a builder

```python
def build_pce_for(creds: PCECredentials) -> PolicyComputeEngine: ...

# stdio shim, preserves today's behavior:
def get_pce_from_env() -> PolicyComputeEngine: ...
```

Process-global singleton goes away. The stdio entrypoint still gets one PCE for the life of the process, but it's owned by the stdio adapter, not by `pce.py`.

### 6.3 Handlers take a context

```python
# Before
async def handle_get_workloads(arguments): ...

# After
async def handle_get_workloads(ctx: ToolContext, arguments): ...
```

Mechanical change across ~45 handlers. The body just swaps `get_pce()` → `ctx.pce`. No behavioral change. This is the boring, error-prone bit; it goes in its own commit so review is easy.

### 6.4 Tool registry carries metadata

`tools/__init__.py`'s `TOOL_HANDLERS` dict becomes a registry of `ToolSpec` objects:

```python
@dataclass
class ToolSpec:
    name: str
    handler: Callable
    roles: set[Role]
    mutating: bool = False
    requires_confirm: bool = False
    unscopable: bool = False
```

Auth middleware reads this to enforce roles, the confirm-token requirement, and unscopable handling.

### 6.5 Transport adapters

```
transport/
  stdio.py     # today's main(), refactored to use the registry
  http.py      # Starlette app + uvicorn, using the SDK's streamable_http_server helper
```

`http.py` builds on the `mcp` Python SDK's Streamable HTTP support (the `pyproject.toml` `mcp>=1.2.0` floor will need to be bumped to whatever shipping version exposes the helper — verified during Phase 2). It mounts:

| Route                                     | Purpose                                            |
|-------------------------------------------|----------------------------------------------------|
| `POST /mcp`                               | JSON-RPC requests (json or SSE response)           |
| `GET /mcp`                                | Server→client SSE (notifications) — optional       |
| `DELETE /mcp`                             | Session termination                                |
| `GET /.well-known/oauth-protected-resource` | RFC 9728 metadata                                |
| `GET /setup`, `POST /setup`               | Browser onboarding for PCE creds                   |
| `POST /confirm`                           | Step-up auth → confirm token                       |
| `GET /healthz`, `GET /readyz`             | Liveness/readiness                                 |
| `GET /metrics`                            | Prometheus metrics                                 |

### 6.6 Entrypoint

```bash
illumio-mcp                            # stdio (today's behavior)
illumio-mcp serve --http --port 8080   # HTTP server
```

`__main__.py` arg-parses; default is stdio so existing setups don't change.

---

## 7. Operations

### 7.1 Deployment shape

**Single-tenant per PCE** is what ships. One MCP server in front of one PCE, deployed close to that PCE (same cluster / same VPC). Multi-tenant is a v2 — the data model already carries `issuer` so adding a `tenant_id` column and routing by `aud`/path is a small addition when needed.

**Recommended deployment.** Container image (existing `Dockerfile` extended), Kubernetes Deployment behind an Ingress with TLS terminated by the Ingress. Two replicas for availability — sessions can be held in-process v1 (sticky sessions via Ingress hash on `Mcp-Session-Id`), moved to Redis if we ever need >2 replicas.

### 7.2 Configuration

All via env (12-factor):

```
# Auth
MCP_OAUTH_ISSUER=https://login.microsoftonline.com/<tenant>/v2.0
MCP_OAUTH_JWKS_URL=...           # auto-discovered if omitted
MCP_OAUTH_AUDIENCE=https://mcp.illumio.tmo
MCP_OAUTH_REQUIRED_SCOPE=illumio-mcp.use

# Key store
MCP_KEYSTORE_PATH=/var/lib/illumio-mcp/keys.db
MCP_KEK_SOURCE=aws-kms           # env | file | aws-kms | vault-transit
MCP_KEK_KMS_KEY_ID=arn:aws:kms:...

# Confirm tokens
MCP_CONFIRM_HMAC_KEY=...         # 32-byte base64
MCP_CONFIRM_TTL_SECONDS=120

# Server
MCP_HTTP_HOST=0.0.0.0
MCP_HTTP_PORT=8080
MCP_PUBLIC_URL=https://mcp.illumio.tmo
```

Role mapping in a small YAML file mounted as a ConfigMap.

### 7.3 Observability

- **Structured logs** (JSON) with `request_id`, `sub`, `tool`, `decision`, latency.
- **Audit log** rows are the source of truth for "who did what". They live in SQLite next to the keys; dump-and-ship to SIEM via cron or a Fluent Bit tail.
- **Prometheus metrics**: `mcp_requests_total{tool,decision}`, `mcp_request_duration_seconds`, `mcp_pce_call_duration_seconds`, `mcp_active_sessions`, `mcp_authz_failures_total{reason}`.
- **Tracing** via OpenTelemetry — out of v1 scope but the request_id pattern lines up so OTel adoption is later additive.

### 7.4 Secrets handling

- The KEK lives in env or KMS only; never in SQLite, never in logs, never in error messages.
- The `/setup` page sets `Cache-Control: no-store` and uses a CSRF token.
- PCE secrets are zeroed in memory after the per-request PCE client is built, where the SDK lets us.
- TLS is required in production. Server refuses to start with `MCP_PUBLIC_URL=http://...` unless `MCP_DEV_INSECURE=1`.

---

## 8. Testing strategy

Three layers:

### 8.1 Unit tests
- Crypto: `KeyStore` round-trip with envelope encryption, KEK rotation.
- Authz: each layer in isolation (JWT validation, role mapping, allowlist, scope, confirm tokens).
- Decorator metadata: every entry in `TOOL_HANDLERS` has explicit `roles=`; CI fails if a new tool is missing it.

### 8.2 Integration tests
- Existing `tests/test_mcp_tools.py` (stdio) **must keep passing unchanged** — that's our regression net for the handler refactor.
- New `tests/test_mcp_http.py` spins up the Starlette app with a fake JWT issuer (signing tokens with a test key) and a sqlite in-memory keystore, walks the full flow:
  1. Unauthenticated request → 401 with metadata pointer.
  2. JWT-authenticated user with no creds → setup error.
  3. Onboarding via tool → success.
  4. Reader calls a reader tool → ok.
  5. Reader calls a mutating tool → 403.
  6. Operator calls a mutating tool without confirm → 403.
  7. Operator with valid confirm token → ok.
  8. Confirm token replay → 403.
  9. Scoped user calls list tool → result is filtered.

### 8.3 Manual test plan (one-pager)
Run against a real PCE in a lab. Verify with MCP Inspector + Claude Desktop both end-to-end. This is the only way to catch IdP/redirect-URI configuration bugs.

---

## 9. Migration / rollout

Three phases, each independently shippable.

### Phase 1 — Refactor without behavior change
- `ToolContext` introduced.
- `pce.py` split into builder + stdio singleton.
- All handlers take `ctx`.
- `TOOL_HANDLERS` becomes registry of `ToolSpec` (every existing tool tagged with sensible defaults: reads = `{reader, operator, admin}`, writes = `{operator, admin}` + `mutating=True`, provisioning + ringfence-batch + admin tools = `{admin}` + `requires_confirm=True`).
- **Existing stdio behavior unchanged.** Existing tests pass unchanged. This phase ships as a normal release; no user sees anything different.

### Phase 2 — HTTP transport, no auth
- `transport/http.py` with `POST /mcp` (Streamable HTTP).
- No auth yet; gated behind `--insecure-no-auth` flag.
- Manual smoke test with MCP Inspector against a lab PCE.
- Not for production. Internal milestone only.

### Phase 3 — Auth + onboarding + audit
- JWT validation.
- KeyStore + `/setup` + `register-pce-credentials` tool.
- Authz middleware + audit log.
- `/confirm` endpoint + step-up.
- Documentation: how to register the OAuth app in Entra/Okta, how to provision groups, how to onboard users, how to operate.
- This is the version T-Mobile installs.

A possible **Phase 4** (post-launch): scope-restriction enforcement everywhere, Vault KEK driver, multi-tenant routing. Nothing here blocks shipping Phase 3.

---

## 10. Risks and open questions

### Risks

- **PCE key sprawl.** Now there's a PCE API key per human, not per service account. PCE has limits on API keys per user — we should sanity-check against T-Mobile's expected user count. Mitigation: a single PCE user can have multiple API keys, but very large user counts (~1000+) might want a different story.
- **IdP misconfiguration.** Most production failures will be IdP/redirect-URI/scope mistakes, not our bugs. We need a `/healthz` style "auth selftest" admin endpoint that tries a token validation end-to-end and returns a friendly diagnosis.
- **Prompt injection bypassing the confirm step.** If we ever forget `mutating=True` on a new write tool, it skips the confirm requirement. Mitigation: CI test that asserts every tool whose name starts with `create-/update-/delete-/provision-` is `mutating=True`.
- **Session fan-out.** With in-process session state, scale-out beyond ~2 replicas requires sticky sessions or Redis. Acceptable for v1; flagged for v2.

### Open questions

- **Which IdP, concretely.** "IdP-agnostic" gets us out of choosing today, but Phase 3 launch needs at least one fully tested integration. Best guess: Entra ID. Confirm with T-Mobile before Phase 3 starts.
- **Scope-restriction scope.** Layer 4 is described as opt-in. Whether T-Mobile *needs* scope restrictions on day one drives whether Phase 3 includes per-tool scope enforcement or punts it to Phase 4.
- **Step-up auth UX.** Re-prompting via `prompt=login` works but is a bit jarring. If the IdP supports `acr_values` or step-up profiles cleanly, prefer those. Needs IdP-specific tuning.
- **Where does this run?** Inside T-Mobile's network next to the PCE (most likely), in their cloud, or as a managed service we operate? Different answers change deployment specifics but not the design.

---

## 11. Decision summary (the receipts)

| Decision                                | Choice                                          | Rationale                                                                                       |
|-----------------------------------------|-------------------------------------------------|-------------------------------------------------------------------------------------------------|
| HTTP transport                          | Streamable HTTP only                            | Current spec; deprecates two-endpoint SSE; what every client uses.                              |
| Credential model                        | SSO + per-user PCE key (hybrid)                 | SSO benefits + PCE-side audit attribution + symmetric revocation.                               |
| OAuth role                              | Resource Server only, IdP-agnostic              | Standardized in MCP 2025-06-18 spec; T-Mobile uses their own IdP; future-proof.                 |
| Multi-tenancy                           | Single-tenant now, designed for multi-tenant    | YAGNI; data model leaves the door open with `issuer` already present.                           |
| Stdio                                   | Keep both transports                            | Don't break existing power users; cheap to maintain since handlers are transport-agnostic.      |
| Key storage                             | SQLite + envelope encryption, KEK from KMS      | Zero infra dependency for v1; pluggable to Vault later.                                         |
| Authz layers                            | All four (role allowlist + scope + groups + confirm token) | Defense in depth for the multi-user, prompt-injection-aware threat model.                |
| PCE singleton                           | Replaced with per-request build via `ToolContext` | Required for HTTP; preserved exactly for stdio via a thin shim.                                |
| Rollout                                 | Three phases, each independently shippable      | De-risks the refactor; gives us a no-auth integration milestone before mixing in OAuth.        |

---

## Appendix A — What we explicitly did *not* choose

- A custom OAuth Authorization Server (Authlib, Hydra, ory) in front of the corp IdP. Tempting because it gives us Dynamic Client Registration for free, but it's a whole extra service to operate and review. Defer until we feel the pain.
- A policy DSL (OPA, Cedar). Four hardcoded layers of authz are enough for v1 and easier to reason about than a policy engine.
- A central per-user key vault (HashiCorp Vault) at v1. Right answer eventually; ship SQLite first to avoid blocking on T-Mobile's Vault provisioning.
- SAML or LDAP as primary auth. OAuth/OIDC is what MCP standardized on; SAML is for older web apps.
- Replacing `python-illumio`'s `PolicyComputeEngine` with our own client. Not in scope.
