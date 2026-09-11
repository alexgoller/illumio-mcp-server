---
title: Security review (2026-05-13)
layout: default
parent: Security
---

# Security Review: illumio-mcp-server v0.2.0

**Scope:** External-facing HTTP + auth + crypto + persistence surfaces (transport/*, auth/*, server.py dispatcher, tools/credentials.py).
**Date:** 2026-05-13
**Reviewer:** Adversarial code inspection (static analysis; no runtime fuzzing; no dependency scan via pip-audit)
**Branch reviewed:** `feature/cloud-platform-api` (commits up to e29f668)

> **Remediation status (updated 2026-08-26).** This is a point-in-time snapshot;
> the findings below are recorded as they were assessed on 2026-05-13 and are not
> edited retroactively. Several have since been fixed:
>
> | Finding | Status |
> |---|---|
> | High (1) — tool arguments logged at DEBUG in plaintext | **Fixed.** Dispatcher scrubbing added in `bbc8441`; extended to every tool handler and made recursive in `24660e3` (`src/illumio_mcp/log_scrub.py`). Default log level is now `INFO` (`MCP_LOG_LEVEL`). Note the original text overstates the exposure: `tools/credentials.py` never logged its arguments, so PCE API keys were not in fact reaching the log — the real leak was `_meta.confirm_token` from the two `requires_confirm` handlers. |
> | High (2) — stored XSS in `/setup` | **Fixed** (see `tests/test_http_per_user.py` XSS regression test). |
> | Medium — no body-size limits | **Fixed** by the `mcp` 1.29.1 upgrade in `24660e3`; `RequestBodyLimitMiddleware` caps bodies at 4 MiB. |
> | Low — broken `auth_time`/fresh-auth feature | **Fixed** in `22f3a41`; `AuthenticatedUser.auth_time` is now populated from the OIDC claim. |
>
> Not yet addressed: request-rate limits, `Cache-Control: no-store` on
> `/setup`/`/confirm`, `X-Request-Id` sanitization, `used_jti` growth
> (`purge_expired` still uncalled), and the remaining Low/Informational items.

---

## Executive Summary

The v0.2.0 HTTP transport demonstrates strong security intent: JWTs are validated against a full RFC-compliant JWKS, all SQL is parameterized, envelope encryption uses AES-256-GCM with per-record data keys and AAD binding, and HMAC confirm tokens use `hmac.compare_digest`. The overall design is sound.

However, four issues require attention before the T-Mobile rollout:

- **High (2):** (1) All tool arguments — including PCE API keys and secrets passed to `register-pce-credentials` — are logged at DEBUG level in plaintext. (2) User-controlled `sub` and `iss` JWT claims are reflected unescaped into the `/setup` HTML page, creating a stored XSS vector that executes in the operator's browser session.
- **Medium (5):** No body-size limits, no request-rate limits, no `Cache-Control: no-store` on `/setup`/`/confirm`, `X-Request-Id` is accepted verbatim from the client without sanitization, and the `used_jti` table grows unboundedly because `purge_expired` is never called.
- **Low / Informational (8):** Broken `auth_time`/fresh-auth feature, user-controllable `tls_verify=false`, no HTTPS enforcement on JWKS URL, confirm endpoint mints tokens for any tool name including non-existent ones, missing security headers, and operational concerns around container volume persistence.

**Total: 0 Critical, 2 High, 5 Medium, 3 Low, 5 Informational.**

No pre-auth bypass or mass-data-exfiltration paths were found. The authz order (role → PCE-presence → confirm) is correct. All SQL is parameterized. Crypto primitives are sound.

---

## Findings

### [HIGH] PCE API credentials logged in plaintext at DEBUG level

- **Location:** `src/illumio_mcp/server.py:3266`
- **Evidence:**
  ```python
  logger.debug(f"Tool called: {name} with arguments: {arguments}")
  ```
  When `name == "register-pce-credentials"`, `arguments` contains `api_key` and `api_secret` in cleartext. The file handler at line 36-41 logs at `logging.DEBUG` to `./illumio-mcp.log` (or `/var/log/illumio-mcp/illumio-mcp.log` in Docker).
- **Impact:** Any user or process that can read the log file gains PCE API credentials for every user who has ever registered via the MCP tool. This defeats the envelope encryption entirely. In a shared multi-user deployment this is a cross-user credential leak.
- **Likelihood:** High. Debug logging is typically enabled during bring-up and often left on. Log files are frequently shipped to SIEM/Splunk in plaintext.
- **Recommendation:** Either scrub sensitive argument keys before logging (`api_key`, `api_secret`) or log only the tool name and a redacted argument set:
  ```python
  _SCRUB_KEYS = {"api_key", "api_secret", "confirm_token"}
  safe_args = {k: "***" if k in _SCRUB_KEYS else v for k, v in (arguments or {}).items()}
  logger.debug("Tool called: %s with arguments: %s", name, safe_args)
  ```
- **Effort:** Trivial

---

### [HIGH] Stored XSS via unescaped JWT `sub`/`iss` claims in `/setup` HTML

- **Location:** `src/illumio_mcp/transport/setup_page.py:33,69`
- **Evidence:**
  ```python
  # Line 33 in template:
  '<div class="meta">Authenticated as <code>{sub}</code> via <code>{iss}</code></div>'
  # Line 69:
  return HTMLResponse(_FORM_HTML.format(sub=user.sub, iss=user.iss))
  ```
  `user.sub` and `user.iss` come directly from the validated JWT payload (lines 112–113 of `jwt_validator.py`) with no HTML escaping. A crafted JWT containing `sub='<script>alert(document.cookie)</script>'` renders executable script in the operator's browser.
- **Impact:** An IdP that issues JWTs with HTML-containing `sub` values (or a compromised IdP) causes XSS executing in the operator's browser session on `/setup`. The operator is authenticated, so the attacker gains the ability to exfiltrate the current session JWT or submit credentials of their choosing via the form.
- **Likelihood:** Medium. Entra/Okta issue opaque GUID subs, making this hard to trigger in the reference deployment. However, if a non-standard IdP is configured (allowed by the open-ended `MCP_OAUTH_ISSUER` config), this is exploitable. Format-string collision (`{iss}` inside `sub`) produces confusing but not exploitable output.
- **Recommendation:** Use `html.escape()` before interpolation:
  ```python
  import html
  return HTMLResponse(_FORM_HTML.format(
      sub=html.escape(user.sub),
      iss=html.escape(user.iss),
  ))
  ```
  Also switch the template to use `{% ... %}` style with a proper templating engine (Jinja2 auto-escapes by default), or replace `.format()` with manual string construction using `html.escape`.
- **Effort:** Trivial

---

### [MEDIUM] No request body size limit on any HTTP endpoint (DoS via huge POST)

- **Location:** `src/illumio_mcp/transport/` (all endpoints), `src/illumio_mcp/transport/http.py:141`
- **Evidence:** No `ContentLength`, `LimitUpload`, or equivalent Starlette middleware is added to the app. `await request.json()` in `confirm_endpoint.py:57` and `await request.form()` in `setup_page.py:75` will buffer the entire request body into memory before processing.
- **Impact:** A single unauthenticated connection (before JWT validation completes) can send a multi-GB body to `/setup` or `/confirm` and exhaust server memory. Denial of service with no authentication required. (Note: the reverse proxy may impose limits — but this should not be relied upon exclusively.)
- **Likelihood:** Medium. Requires network-reachable endpoint. The reverse proxy likely caps body size; document this dependency.
- **Recommendation:** Add a `LimitUploadSize` middleware (available in `starlette.middleware.trustedhost` or custom) upstream of JWT auth:
  ```python
  from starlette.middleware.base import BaseHTTPMiddleware
  # Or use: pip install starlette[full] for built-in limits
  # Simplest: add a body cap via uvicorn's --limit-concurrency + a middleware
  ```
  Set a conservative limit (e.g., 64 KB) on `/setup`, `/confirm`, and `/mcp`.
- **Effort:** Small

---

### [MEDIUM] No request rate limiting anywhere (brute-force on `/confirm`, JWT spam)

- **Location:** `src/illumio_mcp/transport/` (all endpoints)
- **Evidence:** `grep -rn "rate\|throttle\|slowapi"` returns no results in the transport or auth directories.
- **Impact:** An attacker with a valid JWT (e.g., a compromised reader account) can hammer `/confirm` thousands of times per second. While individual confirm tokens have TTL=120s and single-use enforcement, unthrottled HMAC minting exhausts CPU and allows statistical timing analysis over many requests. More practically: a compromised account can perform keystore enumeration by calling `check-pce-credentials-status` at high rate.
- **Likelihood:** Medium. Authenticated attacker only.
- **Recommendation:** Add `slowapi` or equivalent rate limiting middleware. Suggested limits: 10 req/min per `sub` on `/confirm`, 60 req/min per `sub` on `/mcp`.
- **Effort:** Small

---

### [MEDIUM] `used_jti` table grows without bound — disk-exhaustion DoS

- **Location:** `src/illumio_mcp/auth/confirm_replay.py:55-59`, `src/illumio_mcp/auth/confirm_init.py`
- **Evidence:**
  ```python
  def purge_expired(self) -> int:
      now = int(time.time())
      with sqlite3.connect(self.db_path) as con:
          cur = con.execute("DELETE FROM used_jti WHERE exp <= ?", (now,))
          return cur.rowcount
  ```
  `purge_expired()` exists but is **never called** anywhere in the codebase (`grep -rn "purge_expired"` returns only the definition). Every redeemed confirm token adds a row that is never deleted.
- **Impact:** With `confirm_ttl=120s`, each user who performs a confirmed operation adds one row every two minutes. At scale this is slow, but if an attacker repeatedly calls `/confirm` to generate tokens (even without redeeming them, each redeemed token adds a row), the `jti.db` file grows without bound and eventually exhausts disk space, disabling all confirm-token enforcement. This effectively disables the only gate on destructive operations.
- **Likelihood:** Medium. Authenticated attacker with any role.
- **Recommendation:** Call `purge_expired()` periodically. Add a background task at app startup (asyncio periodic coroutine) or call it opportunistically inside `mark_used()` after every N operations. Also consider setting `SQLite PRAGMA max_page_count` or monitoring jti.db size.
- **Effort:** Small

---

### [MEDIUM] `Cache-Control: no-store` absent on `/setup` and `/confirm` responses

- **Location:** `src/illumio_mcp/transport/setup_page.py:69,89`, `src/illumio_mcp/transport/confirm_endpoint.py:71`
- **Evidence:** Neither handler adds `Cache-Control: no-store` or `Pragma: no-cache` to responses. `/setup` GET renders a page reflecting the user's identity. `/confirm` POST returns the confirm token in the response body.
- **Impact:** Browsers and shared proxies may cache the `/confirm` response containing a valid confirm token. A second user on the same browser profile (or a transparent proxy) could replay the cached token against `/mcp` before it expires (TTL=120s). The `/setup` GET page leaks the authenticated user's `sub`/`iss` from browser cache.
- **Likelihood:** Low for `/confirm` (POST responses aren't typically cached). Medium for `/setup` GET.
- **Recommendation:** Add `Cache-Control: no-store, no-cache` to all `/setup` and `/confirm` responses:
  ```python
  return HTMLResponse(
      _FORM_HTML.format(...),
      headers={"Cache-Control": "no-store"},
  )
  ```
- **Effort:** Trivial

---

### [MEDIUM] Client-controlled `X-Request-Id` header accepted without sanitization

- **Location:** `src/illumio_mcp/transport/request_id.py:21-24`
- **Evidence:**
  ```python
  rid = request.headers.get("x-request-id") or str(uuid.uuid4())
  request.state.request_id = rid
  response = await call_next(request)
  response.headers["X-Request-Id"] = rid
  ```
  Confirmed via testing: `Starlette.MutableHeaders` accepts CRLF characters in values. Although `h11` (HTTP/1.1 library) ultimately rejects CRLF in response headers with `LocalProtocolError`, the `rid` value is also stored into the SQLite audit log `request_id` column verbatim. If the audit log is exported to a text-based SIEM with ANSI-aware rendering, embedded ANSI escape sequences could corrupt terminal output or SIEM log parsing.
- **Impact:** Log injection / audit record corruption. CRLF in HTTP response headers is blocked by h11 at the wire level (confirmed), so no HTTP header injection in practice. But the audit log may contain attacker-controlled binary data.
- **Likelihood:** Low. Requires a network attacker sending a crafted `X-Request-Id`.
- **Recommendation:** Sanitize the header before use:
  ```python
  import re
  rid = request.headers.get("x-request-id", "")
  if not re.match(r'^[\w\-]{1,64}$', rid):
      rid = str(uuid.uuid4())
  ```
- **Effort:** Trivial

---

### [LOW] `MCP_CONFIRM_FRESH_AUTH_SECONDS` feature is permanently broken

- **Location:** `src/illumio_mcp/transport/confirm_endpoint.py:41`, `src/illumio_mcp/auth/jwt_validator.py:112-116`
- **Evidence:**
  ```python
  # confirm_endpoint.py:41
  payload_auth_time = getattr(user, "auth_time", None)
  ```
  `AuthenticatedUser` (jwt_validator.py lines 28-34) is a `@dataclass(frozen=True)` with fields: `sub`, `iss`, `scopes`, `groups`. There is no `auth_time` field. `getattr(user, "auth_time", None)` always returns `None`. When `MCP_CONFIRM_FRESH_AUTH_SECONDS` is set, the endpoint always returns 403 "Server requires a recent auth_time claim, but the JWT does not include one" — even for users who authenticated seconds ago.
- **Impact:** The intended security control (requiring recent interactive login before issuing confirm tokens, as a prompt-injection mitigation) is silently non-functional. Operators who enable `MCP_CONFIRM_FRESH_AUTH_SECONDS` will see all confirm requests rejected, breaking the confirm flow entirely.
- **Likelihood:** N/A — the feature is currently broken before anyone can rely on it.
- **Recommendation:** Add `auth_time: int | None = None` to `AuthenticatedUser` and extract it in `jwt_validator.py`:
  ```python
  auth_time = payload.get("auth_time")
  return AuthenticatedUser(
      sub=..., iss=..., scopes=..., groups=...,
      auth_time=int(auth_time) if auth_time is not None else None,
  )
  ```
- **Effort:** Small

---

### [LOW] User can disable TLS verification for their own PCE connection

- **Location:** `src/illumio_mcp/tools/credentials.py:52`, `src/illumio_mcp/transport/setup_page.py:83`
- **Evidence:**
  ```python
  tls_verify=bool(arguments.get("tls_verify", True)),  # credentials.py
  tls_verify=form.get("tls_verify") == "1",            # setup_page.py
  ```
  Both registration paths let a user store `tls_verify=False`. `build_pce_for()` (pce.py:54) then sets `pce._session.verify = False`, disabling certificate validation for all subsequent PCE API calls from that user's session.
- **Impact:** A user who registers a `pce_host` pointing to a corporate PCE over an untrusted path (or a compromised internal DNS) and sets `tls_verify=False` enables MITM of their own PCE traffic. In `shared` PCE mode this is irrelevant. In `per_user` mode: the user harms only themselves, but the server now makes outbound connections with no certificate validation, which could be used for SSRF if the `pce_host` is an attacker-controlled URL (see SSRF note below).
- **Likelihood:** Low. Self-harm only. But see SSRF finding below.
- **Recommendation:** Consider requiring `tls_verify=True` in production (enforced server-side) or at minimum logging a warning when `tls_verify=False` is registered. Add a `MCP_REQUIRE_TLS_VERIFY=1` env flag that overrides user choice.
- **Effort:** Trivial

---

### [LOW] SSRF via user-controlled `pce_host` in `register-pce-credentials`

- **Location:** `src/illumio_mcp/tools/credentials.py:47`, `src/illumio_mcp/pce.py:52-54`
- **Evidence:**
  ```python
  creds = PCECredentials(
      host=str(arguments["pce_host"]),  # no validation
      ...
  )
  # Later: pce.PolicyComputeEngine(creds.host, ...)
  ```
  No URL scheme or hostname validation is performed on `pce_host`. A user can register `pce_host="http://169.254.169.254"` (AWS IMDS), `http://10.0.0.1:8443` (internal service), or any other internal endpoint. The Illumio library will make HTTP requests to that host using the registered API key/secret as HTTP Basic auth credentials. The response is surfaced back to the user via tool errors or PCE exceptions.
- **Impact:** Authenticated SSRF. Any user with any role (ALL_ROLES for `register-pce-credentials`) can probe internal network services accessible from the server. Cloud metadata services, internal APIs, and other microservices reachable from the MCP server's network can be hit. If `tls_verify=False` is also set, HTTPS termination is bypassed. Response data may be partially visible in error messages.
- **Likelihood:** Medium for internal users with valid JWTs. No privilege escalation required beyond valid authentication.
- **Recommendation:** Validate `pce_host` on input: require `https://` scheme, validate the hostname is not a loopback/link-local/private-range address (use `ipaddress` module), and/or maintain an allowlist of permitted PCE hostnames via `MCP_ALLOWED_PCE_HOSTS`. Also restrict this tool to `operator`/`admin` roles rather than `ALL_ROLES`.
- **Effort:** Medium

---

### [INFORMATIONAL] JWKS URL not enforced to use HTTPS

- **Location:** `src/illumio_mcp/auth/config.py:44`, `src/illumio_mcp/auth/jwt_validator.py:71`
- **Evidence:** `MCP_OAUTH_JWKS_URL` is passed directly to `PyJWKClient` with no scheme check. An operator could misconfigure `MCP_OAUTH_JWKS_URL=http://...` allowing a network-level MITM to substitute the JWKS, enabling token forgery.
- **Impact:** Operator misconfiguration enabling forged JWT signing keys. Requires the attacker to be on the network path to the IdP.
- **Recommendation:** At startup, assert `config.jwks_url.startswith("https://")` and raise `MissingOAuthConfigError` if not.
- **Effort:** Trivial

---

### [INFORMATIONAL] Confirm endpoint mints tokens for arbitrary tool names

- **Location:** `src/illumio_mcp/transport/confirm_endpoint.py:60-70`
- **Evidence:** The `/confirm` endpoint checks only that `tool` is a non-empty string. It does not validate against `TOOL_REGISTRY` and does not check whether the tool `requires_confirm=True`. A reader-role user can request a confirm token for `provision-policy` (admin-only), which will be minted but then rejected by the dispatcher's role check.
- **Impact:** Minor logic gap; does not bypass role checks. Allows probing of tool names and produces meaningless tokens. Could be used for DoS by generating large numbers of tokens without redeeming them (combined with the unbounded JTI table issue if the token is redeemed).
- **Recommendation:** In `build_confirm_routes`, import `TOOL_REGISTRY` and validate that `tool` is a known `requires_confirm=True` tool, returning 400 otherwise. Also validate that the caller's role permits the tool.
- **Effort:** Small

---

### [INFORMATIONAL] AAD separator ambiguity in keystore (theoretical)

- **Location:** `src/illumio_mcp/auth/keystore.py:37-39`
- **Evidence:**
  ```python
  def _aad(sub: str, iss: str) -> bytes:
      return f"{sub}|{iss}".encode("utf-8")
  ```
  If `sub="evil|corp"` and `iss=""`, the AAD equals `"evil|corp|"`. This collides with `sub="evil"` and `iss="corp|"`. In practice the primary key `(sub, iss)` on the table means the DB row returned to the user is correctly keyed, so decryption uses the right AAD. A swap attack only works if a row is physically moved in the DB — which requires compromising the DB itself. If the DB is already compromised, the attacker has the ciphertext and KEK.
- **Impact:** Negligible under normal conditions. Could theoretically aid an attacker with physical DB access but no KEK.
- **Recommendation:** Use length-prefixed encoding: `f"{len(sub)}:{sub}|{len(iss)}:{iss}"`. Or use JSON: `json.dumps({"sub": sub, "iss": iss}, sort_keys=True).encode()`.
- **Effort:** Trivial

---

### [INFORMATIONAL] Missing HTTP security headers

- **Location:** `src/illumio_mcp/transport/setup_page.py`, `src/illumio_mcp/transport/http.py`
- **Evidence:** No `X-Content-Type-Options`, `X-Frame-Options`, `Referrer-Policy`, `Content-Security-Policy`, or `Strict-Transport-Security` headers are set on any response.
- **Impact:** Defense-in-depth gap. Without `X-Frame-Options: DENY`, the `/setup` page could be embedded in a cross-origin iframe (clickjacking). Without `Content-Security-Policy`, the XSS finding (HIGH above) has no secondary mitigation.
- **Recommendation:** Add a `SecurityHeadersMiddleware` that sets these on every response. At minimum for `/setup`:
  - `X-Frame-Options: DENY`
  - `X-Content-Type-Options: nosniff`
  - `Content-Security-Policy: default-src 'none'; style-src 'unsafe-inline'`
  - `Referrer-Policy: no-referrer`
- **Effort:** Small

---

### [INFORMATIONAL] `MCP_DEV_INSECURE` is logged as WARNING but log level may suppress it

- **Location:** `src/illumio_mcp/transport/http.py:139`
- **Evidence:**
  ```python
  logger.warning("MCP_DEV_INSECURE=1: HTTP server starting WITHOUT auth. Do not use in production.")
  ```
  This WARNING is in the `illumio_mcp.transport.http` logger. The startup INFO line (line 192-193) also appends `"DEV-INSECURE: no auth..."` to the startup message. Visibility is good if the operator reads logs. However, there is no runtime check at each request that re-asserts the insecure mode — a long-running process started with `MCP_DEV_INSECURE=1` has no periodic reminder.
- **Impact:** Accidental production deployment with no auth, no keystore, admin role for all callers.
- **Recommendation:** Also log at WARNING every 60 minutes if dev-insecure is set (use a background asyncio task). Consider rejecting `MCP_DEV_INSECURE=1` if `MCP_OAUTH_ISSUER` is also set (operator confusion).
- **Effort:** Small

---

## Not Applicable (Checklist Items)

The following checklist items were evaluated and found not to be issues:

| # | Item | Verdict |
|---|------|---------|
| 1 | Algorithm allowlist (RS256, ES256 only — no `none`, no HS256 confusion) | PASS |
| 2 | `exp`, `iat`, `iss`, `aud`, `sub` required in `options={"require": [...]}` | PASS |
| 3 | `nbf` validated when present (PyJWT default `verify_nbf=True`) | PASS |
| 5 | `kid` cache poisoning — PyJWKClient fetches from configured URL; no attacker-controlled key injection | PASS |
| 6 | Scope check: `required_scope not in scopes` uses list membership (exact match), not substring | PASS |
| 7 | Missing `kid` key raises exception, caught as `InvalidTokenError` | PASS |
| 8 | `get_unverified_header` errors are caught and re-raised as `InvalidTokenError` | PASS |
| 9 | Bearer parsing: `auth_header[len("bearer "):]`.strip()` handles case-insensitively; tab (`\t`) causes "missing_token" 401 — no bypass | PASS |
| 11 | Fresh 12-byte nonce via `token_bytes` per encrypt call | PASS |
| 12 | Nonce length is `_NONCE_BYTES = 12` — correct for GCM | PASS |
| 13 | AAD binding is meaningful; decrypt with wrong AAD raises `InvalidTag` | PASS |
| 14 | Wire format delimited by fixed-size fields (no length confusion) | PASS |
| 15 | `hmac.compare_digest` used in `ConfirmTokenManager.verify` | PASS |
| 16 | b64url uses standard `urlsafe_b64decode` with re-added padding | PASS |
| 17 | Token `exp` is inside the HMAC-signed payload — tampering breaks signature | PASS |
| 18 | All randomness via `secrets.token_bytes` / `uuid.uuid4` — no `random.random()` | PASS |
| 19 | All SQL is parameterized (`?` placeholders); no f-string SQL found | PASS |
| 20 | SQLite files created with `umask(0o077)` + `chmod(0o600)` | PASS |
| 21 | WAL mode + `IntegrityError` on JTI PK collision ensures atomic single-use | PASS |
| 22 | `check_same_thread` not set (defaults to `True`); each operation opens a new `connect()` — per-call connections are thread-safe | PASS |
| 24 | Decryption failure is caught in `build_http_context_for()`; partial plaintext not exposed | PASS |
| 26 | Dispatcher order: role → PCE-presence → confirm — correct; no bypass path | PASS |
| 27 | `_meta` extraction uses `isinstance(meta, dict)` guard — non-dict `_meta` safely treated as no token | PASS |
| 28 | `params_for_hash` strips only `_meta` — correct; other attacker keys change the hash, breaking token reuse | PASS |
| 29 | `requires_pce=False` tools (`register-pce-credentials`, etc.) do not access `ctx.pce` | PASS |
| 30 | `user_role` is set by `map_user_role(groups, role_config)` server-side; no JWT claim maps directly to role | PASS |
| 35 | Success page (`_DONE_HTML`) reflects no user input | PASS |
| 42 | KEK and HMAC key not logged; PCE keys encrypted before storage (except the debug-logging finding above) | PARTIAL — see HIGH finding |
| 43 | Exception stack traces are logged server-side; HTTP error responses return only JSON with `"error"` and `"message"` keys | PASS |
| 45 | `register-pce-credentials` response omits `api_key` and `api_secret` | PASS |
| 46 | PRM document (`build_prm_document`) returns only `resource`, `authorization_servers`, `bearer_methods_supported`, `scopes_supported` — no internal paths | PASS |

---

## Things That Were Good

- **Two-tier envelope encryption** (KEK wraps per-record DK, both with fresh 12-byte nonces and AAD) is a genuinely strong design for at-rest protection of per-user credentials.
- **Parameterized SQL everywhere** — no f-string SQL was found in any auth or persistence module.
- **`hmac.compare_digest`** used correctly in `ConfirmTokenManager.verify`, preventing timing oracle attacks on confirm tokens.
- **Algorithm allowlist** is tight (`RS256`, `ES256` only) and `alg:none` cannot be accepted.
- **Authz order** (role → PCE → confirm) is correct; there is no early-exit path that bypasses role enforcement.
- **Role mapping** is server-side (group → role via env config); users cannot escalate by claiming a role in their JWT.
- **Fail-closed default**: if no role groups match and no `MCP_ROLE_DEFAULT` is set, users get `role=None` and all tool calls are denied.
- **Single-use JTI enforcement** uses a PRIMARY KEY constraint + `IntegrityError` catch — correct and race-condition-safe under SQLite WAL.
- **SQLite file permissions** enforced via `umask(0o077)` + `chmod(0o600)`.
- **Secret generation** consistently uses `secrets.token_bytes` or `uuid.uuid4`.
- **Dev insecure mode** is gated behind public-bind protection AND a startup WARNING log AND an extras label in the startup INFO line — three independent signals.
- **Decryption failures** are caught server-side without leaking ciphertext or partial plaintext to callers.

---

## Recommendations Beyond Findings

1. **Pin dependency versions in `pyproject.toml`** with exact versions (`==`) rather than lower-bound specifiers (`>=`). The current `>=` pinning means a `pip install --upgrade` can silently pull in a vulnerable future version of `cryptography` or `pyjwt`.

2. **Add `pip-audit` to CI.** The project uses `uv` — add `uv run pip-audit` as a step in the CI pipeline to continuously check for CVEs in locked dependencies. The currently locked versions (PyJWT 2.12.1, cryptography 48.0.0, starlette, uvicorn, mcp 1.27.1) have no known critical CVEs as of this review date, but this must be checked continuously.

3. **Volume mount for `./data/`** must be declared explicitly in the `Dockerfile` and deployment manifests. The current `Dockerfile` has no `VOLUME /app/data` directive. On container restart, the `keys.db`, `jti.db`, and `audit.db` files in the default `./data/` path (relative to cwd inside the container) are lost, requiring all users to re-register credentials. This is a service-disruption risk, not a security vulnerability, but at T-Mobile scale it will be a recurring incident.

4. **Add `VOLUME /app/data`** to `Dockerfile` and document the expected persistent volume mount in the operations runbook.

5. **Consider restricting `register-pce-credentials` to `operator`/`admin` roles** (currently `ALL_ROLES`). Readers gaining the ability to register arbitrary PCE hosts creates the SSRF surface — see the LOW finding. If readers are only expected to query, they have no legitimate need to register credentials.

6. **Audit log write failures** (disk full, DB locked) propagate exceptions to the dispatcher, which catches them in the broad `except Exception` block and logs the error — but the audit entry for the call is lost. For a compliance deployment, consider wrapping `audit.record()` to catch and separately alert on write failures rather than silently losing audit records.

7. **Periodic `jti.purge_expired()` call** should be added as an asyncio background task in the app lifespan (e.g., every 10 minutes), not just available as a callable.

---

## Out of Scope / Not Reviewed

- **Runtime fuzzing / penetration testing:** This review is static analysis only. No actual HTTP requests were sent to a running server.
- **Dependency CVE scan:** `pip-audit` was not available in this environment. Package versions reviewed against known advisories manually: no critical CVEs found for the listed locked versions, but this is not a substitute for automated continuous scanning.
- **Illumio PCE library (`illumio>=1.1.3`) internals:** The PCE client library is treated as a black box. Its HTTP handling, authentication headers, and TLS behaviors were not reviewed.
- **Cloud platform API endpoints** (referenced in recent commits `b4e3385`, `d0309a3`): Not included in the stated review scope. The `CLOUD_API_*` environment variables and `CloudTrafficClient` were not reviewed.
- **Prompt injection mitigations in tool *responses*:** The dispatcher does not sanitize tool result content. If a PCE returns malicious data (e.g., a workload name containing `IGNORE PREVIOUS INSTRUCTIONS`), it will be passed verbatim to the LLM. This is a class of risk that is mostly outside the MCP server's control but worth noting.
- **MCP protocol-level security** (session management, tool listing, resource access): Not reviewed; treated as the MCP library's responsibility.
- **Network-level TLS termination** at the reverse proxy: Assumed to be configured correctly by the operator.
