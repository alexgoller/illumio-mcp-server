# Phase 3e: Shared-PCE-Key Mode — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a configurable mode where the HTTP server uses a single PCE service-account key (env-loaded, like stdio today) instead of per-user PCE credentials. SSO + JWT auth still required, role-based authz still enforced, audit log still records per-human identity. The trade-off is documented (PCE-side audit shows the service account, not the human; server becomes a higher-value target). Per-user mode (Phase 3b) remains the default.

**Architecture:** A new `auth/pce_mode.py` defines `PCEMode = Literal["per_user", "shared"]` and `load_pce_mode_from_env()`. `build_http_context_for` consults the mode: `shared` → use `get_pce_from_env()` (the existing stdio singleton) regardless of user; `per_user` → keystore lookup as today. In shared mode the keystore is not built, the `/setup` route is not mounted, and the credential-management tools refuse with a clear "not applicable in shared mode" error. Everything else (JWT, role, audit, confirm tokens) works identically.

**Tech Stack:** No new dependencies. Reuses Phase 1's `get_pce_from_env()`.

**Spec:** Extends [`docs/superpowers/specs/2026-05-12-http-transport-and-auth-design.md`](../specs/2026-05-12-http-transport-and-auth-design.md) §3.1 (originally rejected as "shared service account" option A; now offered as opt-in mode for teams that prefer it).

**Branch:** `feature/shared-pce-mode` off `feature/confirm-tokens` (or `main` once Phase 3 stack is merged).

---

## Working agreement

- **Per-user mode is the default.** New deployments without `MCP_PCE_MODE` set get `per_user` — preserves Phase 3b behavior.
- **Stdio is unchanged.** Stdio always uses env-loaded PCE; the mode selector only affects HTTP.
- Switching modes mid-flight is not supported. Restart the server to change.
- Shared mode requires the same `PCE_HOST` / `PCE_PORT` / `PCE_ORG_ID` / `API_KEY` / `API_SECRET` env vars that stdio uses today. HTTP startup refuses if shared is set but env is incomplete.
- `MCP_KEK` is **not required** in shared mode (no keystore = no envelope encryption). HTTP startup must accept this.
- Audit log still receives every per-user decision. PCE-side audit will show the shared service account; the server-side audit log is the source of truth for "who did what."
- Confirm tokens still apply. Defense against prompt injection is independent of how PCE creds are sourced.

---

## File structure

| File | Responsibility |
|---|---|
| `src/illumio_mcp/auth/pce_mode.py` (new) | `PCEMode` literal + `load_pce_mode_from_env()` + helper `is_shared_mode()` |
| `src/illumio_mcp/server.py` (modify) | `build_http_context_for` accepts `pce_mode`; in `shared` mode, always uses `get_pce_from_env()` regardless of user |
| `src/illumio_mcp/tools/credentials.py` (modify) | Three handlers return `{"error": "shared_mode"}` when ctx has `pce_mode="shared"` (added to ToolContext in this phase) |
| `src/illumio_mcp/context.py` (modify) | Add `pce_mode: str = "per_user"` |
| `src/illumio_mcp/transport/http.py` (modify) | Read mode at startup; in `shared` mode, skip `build_keystore_from_env()` (no MCP_KEK needed), don't mount `/setup`, pass `pce_mode="shared"` into per-request context |
| `tests/test_auth_pce_mode.py` (new) | Mode env loading + defaults |
| `tests/test_credentials_tools.py` (modify) | Add tests: in shared mode, credential tools return `shared_mode` error |
| `tests/test_http_shared_mode.py` (new) | e2e: shared mode, no keystore, user with no per-user creds can call PCE tools immediately |
| `README.md` (modify) | New "Two PCE modes" subsection with comparison table + when to use which |

---

## Task 0: Create the working branch

**Files:** git only

- [ ] **Step 1: Branch**

```bash
git checkout feature/confirm-tokens
git pull --ff-only origin feature/confirm-tokens
git checkout -b feature/shared-pce-mode
```

- [ ] **Step 2: Verify clean baseline**

```bash
git status
.venv/bin/python3 -m pytest tests/test_auth_confirm.py tests/test_auth_confirm_replay.py tests/test_http_confirm.py -q
```
Expected: all green.

---

## Task 1: `auth/pce_mode.py` + tests

**Files:**
- Create: `src/illumio_mcp/auth/pce_mode.py`
- Create: `tests/test_auth_pce_mode.py`

- [ ] **Step 1: Write failing tests**

Create `tests/test_auth_pce_mode.py`:

```python
"""Tests for PCE mode env loading."""
import pytest
from illumio_mcp.auth.pce_mode import (
    load_pce_mode_from_env, is_shared_mode, PER_USER, SHARED,
)


def test_constants_are_distinct_strings():
    assert PER_USER == "per_user"
    assert SHARED == "shared"
    assert PER_USER != SHARED


def test_default_is_per_user(monkeypatch):
    monkeypatch.delenv("MCP_PCE_MODE", raising=False)
    assert load_pce_mode_from_env() == PER_USER


def test_explicit_per_user(monkeypatch):
    monkeypatch.setenv("MCP_PCE_MODE", "per_user")
    assert load_pce_mode_from_env() == PER_USER


def test_explicit_shared(monkeypatch):
    monkeypatch.setenv("MCP_PCE_MODE", "shared")
    assert load_pce_mode_from_env() == SHARED


def test_unknown_value_raises(monkeypatch):
    monkeypatch.setenv("MCP_PCE_MODE", "bogus")
    with pytest.raises(ValueError, match="MCP_PCE_MODE"):
        load_pce_mode_from_env()


def test_is_shared_mode_helper():
    assert is_shared_mode("shared") is True
    assert is_shared_mode("per_user") is False
    assert is_shared_mode(None) is False
```

- [ ] **Step 2: Run, expect ImportError**

```bash
.venv/bin/python3 -m pytest tests/test_auth_pce_mode.py -v
```

- [ ] **Step 3: Implement `auth/pce_mode.py`**

Create `src/illumio_mcp/auth/pce_mode.py`:

```python
"""PCE mode selector — per-user keystore vs single shared service account.

Two modes:
  - "per_user" (default, Phase 3b): each authenticated user has their own
    PCE API key in the encrypted SQLite keystore. PCE-side audit logs
    attribute correctly per human.
  - "shared" (Phase 3e): the server uses a single PCE service-account key
    loaded from PCE_* env vars. SSO + JWT auth still required; role-based
    authz still enforced; the server-side audit log records per-human
    identity. PCE-side audit shows the service account.
"""
from __future__ import annotations

import os
from typing import Literal


PCEMode = Literal["per_user", "shared"]
PER_USER: PCEMode = "per_user"
SHARED: PCEMode = "shared"

_VALID = (PER_USER, SHARED)


def load_pce_mode_from_env() -> PCEMode:
    """Read MCP_PCE_MODE; default per_user. Raise on unknown value."""
    raw = os.getenv("MCP_PCE_MODE", PER_USER)
    if raw not in _VALID:
        raise ValueError(
            f"MCP_PCE_MODE must be one of {sorted(_VALID)}; got {raw!r}"
        )
    return raw  # type: ignore[return-value]


def is_shared_mode(mode: PCEMode | str | None) -> bool:
    return mode == SHARED
```

- [ ] **Step 4: Run tests**

```bash
.venv/bin/python3 -m pytest tests/test_auth_pce_mode.py -v
```
Expected: 6 PASSED.

- [ ] **Step 5: Commit**

```bash
git add src/illumio_mcp/auth/pce_mode.py tests/test_auth_pce_mode.py
git commit -m "feat(auth): MCP_PCE_MODE selector (per_user | shared)"
```

---

## Task 2: Add `pce_mode` to `ToolContext`

**Files:**
- Modify: `src/illumio_mcp/context.py`
- Modify: `tests/test_context.py`

- [ ] **Step 1: Replace `src/illumio_mcp/context.py`**

```python
"""ToolContext: the per-call object every tool handler receives.

Phase 3e: adds `pce_mode` so handlers (and the dispatcher) can branch on
shared vs per-user PCE behavior.
"""
from dataclasses import dataclass


@dataclass
class ToolContext:
    pce: object | None
    is_stdio: bool
    user_sub: str | None = None
    user_iss: str | None = None
    keystore: object | None = None
    user_role: str | None = None
    audit_log: object | None = None
    request_id: str | None = None
    confirm_manager: object | None = None
    jti_store: object | None = None
    pce_mode: str = "per_user"  # 'per_user' (default) | 'shared'
```

- [ ] **Step 2: Append to `tests/test_context.py`**

```python


def test_tool_context_pce_mode_default():
    ctx = ToolContext(pce=object(), is_stdio=True)
    assert ctx.pce_mode == "per_user"


def test_tool_context_carries_shared_mode():
    ctx = ToolContext(pce=object(), is_stdio=False, pce_mode="shared")
    assert ctx.pce_mode == "shared"
```

- [ ] **Step 3: Run tests**

```bash
.venv/bin/python3 -m pytest tests/test_context.py -v
```
Expected: all green.

- [ ] **Step 4: Verify stdio**

```bash
echo '{"jsonrpc":"2.0","id":0,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"test","version":"0"}}}' | timeout 5 .venv/bin/python3 -m illumio_mcp 2>&1 | head -3
```
Expected: response with `protocolVersion` AND `serverInfo`.

- [ ] **Step 5: Commit**

```bash
git add src/illumio_mcp/context.py tests/test_context.py
git commit -m "feat(context): add pce_mode field to ToolContext"
```

---

## Task 3: `build_http_context_for` honors shared mode

**Files:**
- Modify: `src/illumio_mcp/server.py`

- [ ] **Step 1: Update `build_http_context_for` to accept and honor `pce_mode`**

Find `build_http_context_for` and replace it with:

```python
def build_http_context_for(
    user_sub: str | None,
    user_iss: str | None,
    keystore: object | None,
    user_role: str | None,
    audit_log: object | None,
    request_id: str | None,
    confirm_manager: object | None = None,
    jti_store: object | None = None,
    pce_mode: str = "per_user",
) -> ToolContext:
    """Build a ToolContext for one HTTP request.

    In `per_user` mode (default), looks up the user's PCE creds in the keystore.
    In `shared` mode, every request uses the env-loaded PCE singleton — no
    keystore lookup, no per-user PCE attribution.
    """
    if pce_mode == "shared":
        # Shared service-account mode: every authenticated user uses the same
        # env-loaded PCE. SSO + role + audit + confirm still enforced.
        pce = get_pce_from_env()
    else:
        # per_user mode (Phase 3b)
        pce = None
        if keystore is not None and user_sub and user_iss:
            try:
                from .pce import build_pce_for
                creds = keystore.get(sub=user_sub, iss=user_iss)
                if creds is not None:
                    pce = build_pce_for(creds)
            except Exception:
                logger.exception("Failed to load PCE credentials for user %s", user_sub)
        elif keystore is None:
            # Dev-insecure mode: no keystore, fall back to env-loaded PCE
            pce = get_pce_from_env()
    return ToolContext(
        pce=pce,
        is_stdio=False,
        user_sub=user_sub,
        user_iss=user_iss,
        keystore=keystore,
        user_role=user_role,
        audit_log=audit_log,
        request_id=request_id,
        confirm_manager=confirm_manager,
        jti_store=jti_store,
        pce_mode=pce_mode,
    )
```

- [ ] **Step 2: Verify imports + new arg works**

```bash
.venv/bin/python3 -c "
from illumio_mcp.server import build_http_context_for
ctx_p = build_http_context_for('s', 'i', None, 'admin', None, 'r', None, None, 'per_user')
ctx_s = build_http_context_for('s', 'i', None, 'admin', None, 'r', None, None, 'shared')
print('per_user mode:', ctx_p.pce_mode)
print('shared mode:', ctx_s.pce_mode)
print('per_user pce is None:', ctx_p.pce is None)  # Should be False — falls back to env in dev-insecure
print('shared pce is None:', ctx_s.pce is None)    # Should be False — env-loaded
"
```
Expected: prints both mode values; both `pce` are non-None (env-loaded).

- [ ] **Step 3: Verify stdio**

```bash
echo '{"jsonrpc":"2.0","id":0,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"test","version":"0"}}}' | timeout 5 .venv/bin/python3 -m illumio_mcp 2>&1 | head -3
```

- [ ] **Step 4: Run unit tests as regression net**

```bash
.venv/bin/python3 -m pytest tests/ -q --ignore=tests/test_mcp_tools.py 2>&1 | tail -3
```
Expected: all green.

- [ ] **Step 5: Commit**

```bash
git add src/illumio_mcp/server.py
git commit -m "feat(http): build_http_context_for honors shared PCE mode"
```

---

## Task 4: Credential tools refuse in shared mode

**Files:**
- Modify: `src/illumio_mcp/tools/credentials.py`
- Modify: `tests/test_credentials_tools.py`

- [ ] **Step 1: Update each handler to short-circuit in shared mode**

In `src/illumio_mcp/tools/credentials.py`, find each of the three handlers (`handle_register_pce_credentials`, `handle_delete_pce_credentials`, `handle_check_pce_credentials_status`). At the top of each function (after the docstring, before any other check), add:

```python
    if getattr(ctx, "pce_mode", "per_user") == "shared":
        return _err(
            "Server is running in shared-PCE-key mode; per-user PCE credentials "
            "are not used. Contact your operator to switch to per_user mode if you "
            "need to register your own PCE key."
        )
```

So each function looks like (using `handle_register_pce_credentials` as the example shape — apply the same pattern to all three):

```python
def handle_register_pce_credentials(ctx, arguments: dict) -> list:
    """Store (or overwrite) the PCE credentials for the current authenticated user."""
    if getattr(ctx, "pce_mode", "per_user") == "shared":
        return _err(
            "Server is running in shared-PCE-key mode; per-user PCE credentials "
            "are not used. Contact your operator to switch to per_user mode if you "
            "need to register your own PCE key."
        )
    if ctx.keystore is None:
        return _err("Keystore not available — server not running in HTTP mode with auth enabled.")
    # ... (rest unchanged)
```

For `handle_check_pce_credentials_status`, the shared-mode response should be informative rather than an error. Replace the body with:

```python
def handle_check_pce_credentials_status(ctx, arguments: dict) -> list:
    """Tell the caller whether credentials are registered (without revealing them)."""
    if getattr(ctx, "pce_mode", "per_user") == "shared":
        return [types.TextContent(type="text", text=json.dumps({
            "registered": True,
            "mode": "shared",
            "message": "Server is in shared-PCE-key mode; the operator-configured PCE service account is used.",
        }))]
    if ctx.keystore is None:
        return _err("Keystore not available.")
    # ... (rest unchanged)
```

- [ ] **Step 2: Append tests to `tests/test_credentials_tools.py`**

```python


def _shared_ctx(*, sub="u", iss="i"):
    """ToolContext as it would look in shared-PCE mode."""
    sentinel_pce = object()
    return ToolContext(pce=sentinel_pce, is_stdio=False, user_sub=sub, user_iss=iss,
                       keystore=None, pce_mode="shared")


def test_register_in_shared_mode_returns_error():
    body = _parse(handle_register_pce_credentials(_shared_ctx(), {
        "pce_host": "h", "pce_port": 1, "pce_org_id": 1, "api_key": "k", "api_secret": "s",
    }))
    assert "error" in body
    assert "shared" in body["error"].lower()


def test_delete_in_shared_mode_returns_error():
    body = _parse(handle_delete_pce_credentials(_shared_ctx(), {}))
    assert "error" in body
    assert "shared" in body["error"].lower()


def test_status_in_shared_mode_reports_shared():
    body = _parse(handle_check_pce_credentials_status(_shared_ctx(), {}))
    assert body["registered"] is True
    assert body["mode"] == "shared"
```

- [ ] **Step 3: Run tests**

```bash
.venv/bin/python3 -m pytest tests/test_credentials_tools.py -v
```
Expected: all 8 original tests still pass + 3 new = 11 PASSED.

- [ ] **Step 4: Commit**

```bash
git add src/illumio_mcp/tools/credentials.py tests/test_credentials_tools.py
git commit -m "feat(tools): credential tools refuse in shared-PCE mode"
```

---

## Task 5: Wire mode into `transport/http.py`

In shared mode: skip keystore build (no `MCP_KEK` required), skip `/setup` route, pass `pce_mode="shared"` through.

**Files:**
- Modify: `src/illumio_mcp/transport/http.py`

- [ ] **Step 1: Add the import**

In the existing `..auth.*` imports block, add:

```python
from ..auth.pce_mode import load_pce_mode_from_env, is_shared_mode
```

- [ ] **Step 2: Update `_wrap_with_per_request_context` signature + body**

Find `_wrap_with_per_request_context` and replace it with:

```python
def _wrap_with_per_request_context(handle_request, keystore, role_config, audit_log, confirm_manager, jti_store, pce_mode):
    """Wrap the session manager's ASGI handler so it sets the per-request
    ToolContext (built from the authenticated user) before invoking MCP."""
    async def app(scope, receive, send):
        if scope["type"] != "http":
            await handle_request(scope, receive, send)
            return
        state = scope.get("state", {})
        user = state.get("user")
        sub = getattr(user, "sub", None) if user else None
        iss = getattr(user, "iss", None) if user else None
        groups = getattr(user, "groups", []) if user else []
        role = map_user_role(groups, role_config) if role_config is not None else "admin"
        request_id = state.get("request_id")
        ctx = build_http_context_for(
            sub, iss, keystore, role, audit_log, request_id,
            confirm_manager=confirm_manager, jti_store=jti_store,
            pce_mode=pce_mode,
        )
        token = set_http_context(ctx)
        try:
            await handle_request(scope, receive, send)
        finally:
            reset_http_context(token)
    return app
```

- [ ] **Step 3: Update `_build_app` to take `pce_mode` and gate the `/setup` route**

Find `_build_app` and replace it with:

```python
def _build_app(
    oauth_config: OAuthConfig | None,
    keystore: object | None,
    role_config: RoleConfig | None,
    audit_log: object | None,
    confirm_manager: object | None,
    jti_store: object | None,
    pce_mode: str = "per_user",
) -> Starlette:
    session_manager = _build_session_manager()

    @contextlib.asynccontextmanager
    async def lifespan(app: Starlette) -> AsyncIterator[None]:
        async with session_manager.run():
            logger.info("StreamableHTTPSessionManager started")
            yield
            logger.info("StreamableHTTPSessionManager stopped")

    async def healthz(_: Request) -> Response:
        return JSONResponse({"status": "ok"})

    async def readyz(_: Request) -> Response:
        return JSONResponse({"status": "ready"})

    mcp_handler = _wrap_with_per_request_context(
        session_manager.handle_request, keystore, role_config, audit_log,
        confirm_manager, jti_store, pce_mode,
    )
    routes = [
        Mount("/mcp", app=mcp_handler),
        Route("/healthz", healthz, methods=["GET"]),
        Route("/readyz", readyz, methods=["GET"]),
    ]

    middleware = [Middleware(RequestIdMiddleware)]
    if oauth_config is not None:
        async def prm(_: Request) -> Response:
            return JSONResponse(build_prm_document(oauth_config))
        routes.append(Route("/.well-known/oauth-protected-resource", prm, methods=["GET"]))
        # /setup only makes sense in per_user mode (it writes to the keystore)
        if keystore is not None and not is_shared_mode(pce_mode):
            routes.extend(build_setup_routes(keystore))
        if confirm_manager is not None:
            routes.extend(build_confirm_routes(confirm_manager, audit_log))

        validator = JWTValidator(oauth_config)
        middleware.append(Middleware(JWTAuthMiddleware, validator=validator, config=oauth_config))
    else:
        logger.warning("MCP_DEV_INSECURE=1: HTTP server starting WITHOUT auth. Do not use in production.")

    return Starlette(debug=False, routes=routes, lifespan=lifespan, middleware=middleware)
```

- [ ] **Step 4: Update `serve_http` to load mode and skip keystore in shared mode**

Replace `serve_http` with:

```python
def serve_http(host: str = "127.0.0.1", port: int = 8080) -> None:
    if host not in ("127.0.0.1", "::1", "localhost") and not is_dev_insecure():
        raise SystemExit(
            f"Refusing to bind {host!r} without MCP_DEV_INSECURE=1. "
            "Public bind requires Phase 3 auth + an explicit dev opt-in."
        )

    if is_dev_insecure():
        oauth_config = None
        keystore = None
        role_config = None
        audit_log = NullAuditLog()
        confirm_manager = None
        jti_store = None
        pce_mode = "per_user"  # irrelevant in dev-insecure
    else:
        try:
            oauth_config = load_oauth_config_from_env()
        except MissingOAuthConfigError as e:
            raise SystemExit(str(e))
        pce_mode = load_pce_mode_from_env()
        if is_shared_mode(pce_mode):
            # Shared-key mode: no keystore, no MCP_KEK required.
            # Verify the env vars stdio uses are present; fail-fast otherwise.
            for required in ("PCE_HOST", "PCE_PORT", "PCE_ORG_ID", "API_KEY", "API_SECRET"):
                if not os.getenv(required):
                    raise SystemExit(
                        f"MCP_PCE_MODE=shared requires {required} env var (same vars stdio uses)."
                    )
            keystore = None
        else:
            try:
                keystore = build_keystore_from_env()
            except MissingKEKError as e:
                raise SystemExit(str(e))
        role_config = load_role_config_from_env()
        audit_log = build_audit_log_from_env()
        try:
            confirm_manager, jti_store = build_confirm_manager_from_env()
        except MissingConfirmHmacKeyError as e:
            raise SystemExit(str(e))

    app = _build_app(oauth_config, keystore, role_config, audit_log, confirm_manager, jti_store, pce_mode)
    extras = []
    if oauth_config is None:
        extras.append("DEV-INSECURE: no auth, no keystore, admin role, no confirm")
    elif is_shared_mode(pce_mode):
        extras.append("PCE-MODE: shared (single service account)")
    logger.info(f"Starting HTTP transport on http://{host}:{port}/mcp"
                + (f"  [{'; '.join(extras)}]" if extras else ""))
    uvicorn.run(app, host=host, port=port, log_level="info")
```

- [ ] **Step 5: Update `tests/test_http_transport.py` for the new 7-arg signature**

Find the line:
```python
    config = uvicorn.Config(_build_app(None, None, None, NullAuditLog(), None, None), host="127.0.0.1", port=port, log_level="warning")
```
Replace with:
```python
    config = uvicorn.Config(_build_app(None, None, None, NullAuditLog(), None, None, "per_user"), host="127.0.0.1", port=port, log_level="warning")
```

- [ ] **Step 6: Verify dev-insecure builds**

```bash
MCP_DEV_INSECURE=1 .venv/bin/python3 -c "
from illumio_mcp.transport.http import _build_app
from illumio_mcp.auth.audit import NullAuditLog
app = _build_app(None, None, None, NullAuditLog(), None, None, 'per_user')
print('routes (dev):', sorted([getattr(r, 'path', '?') for r in app.routes]))
"
```

- [ ] **Step 7: Verify shared-mode startup succeeds without MCP_KEK**

```bash
unset MCP_DEV_INSECURE MCP_KEK MCP_KEYSTORE_PATH
MCP_OAUTH_ISSUER=https://idp.test/o \
MCP_OAUTH_JWKS_URL=https://idp.test/o/.well-known/jwks.json \
MCP_OAUTH_AUDIENCE=mcp.test \
MCP_PUBLIC_URL=http://127.0.0.1 \
MCP_PCE_MODE=shared \
PCE_HOST=https://pce.example PCE_PORT=8443 PCE_ORG_ID=1 API_KEY=k API_SECRET=s \
MCP_ROLE_GROUPS_ADMIN=sg-admin \
MCP_CONFIRM_HMAC_KEY=$(.venv/bin/python3 -c "import os, base64; print(base64.b64encode(os.urandom(32)).decode())") \
MCP_AUDIT_LOG_PATH=/tmp/test_p3e_audit.db \
MCP_CONFIRM_JTI_PATH=/tmp/test_p3e_jti.db \
  .venv/bin/python3 -c "
from illumio_mcp.transport.http import _build_app
from illumio_mcp.auth.config import load_oauth_config_from_env
from illumio_mcp.auth.audit_init import build_audit_log_from_env
from illumio_mcp.auth.roles import load_role_config_from_env
from illumio_mcp.auth.confirm_init import build_confirm_manager_from_env
mgr, jti = build_confirm_manager_from_env()
# In shared mode, keystore is None
app = _build_app(load_oauth_config_from_env(), None, load_role_config_from_env(), build_audit_log_from_env(), mgr, jti, 'shared')
routes = sorted([getattr(r, 'path', '?') for r in app.routes])
print('routes (shared):', routes)
assert '/setup' not in routes, 'shared mode should NOT mount /setup'
print('shared-mode build ok')
" && rm -f /tmp/test_p3e_*
```
Expected: `routes (shared): ['/.well-known/oauth-protected-resource', '/confirm', '/healthz', '/mcp', '/readyz']` — note `/setup` is absent.

- [ ] **Step 8: Verify per-user mode still mounts /setup**

```bash
unset MCP_DEV_INSECURE MCP_PCE_MODE
MCP_OAUTH_ISSUER=https://idp.test/o \
MCP_OAUTH_JWKS_URL=https://idp.test/o/.well-known/jwks.json \
MCP_OAUTH_AUDIENCE=mcp.test \
MCP_PUBLIC_URL=http://127.0.0.1 \
MCP_KEK=$(.venv/bin/python3 -c "import os, base64; print(base64.b64encode(os.urandom(32)).decode())") \
MCP_KEYSTORE_PATH=/tmp/test_p3e_ks.db \
MCP_AUDIT_LOG_PATH=/tmp/test_p3e_audit.db \
MCP_ROLE_GROUPS_ADMIN=sg-admin \
MCP_CONFIRM_HMAC_KEY=$(.venv/bin/python3 -c "import os, base64; print(base64.b64encode(os.urandom(32)).decode())") \
MCP_CONFIRM_JTI_PATH=/tmp/test_p3e_jti.db \
  .venv/bin/python3 -c "
from illumio_mcp.transport.http import _build_app
from illumio_mcp.auth.config import load_oauth_config_from_env
from illumio_mcp.auth.keystore_init import build_keystore_from_env
from illumio_mcp.auth.audit_init import build_audit_log_from_env
from illumio_mcp.auth.roles import load_role_config_from_env
from illumio_mcp.auth.confirm_init import build_confirm_manager_from_env
mgr, jti = build_confirm_manager_from_env()
app = _build_app(load_oauth_config_from_env(), build_keystore_from_env(), load_role_config_from_env(), build_audit_log_from_env(), mgr, jti, 'per_user')
routes = sorted([getattr(r, 'path', '?') for r in app.routes])
print('routes (per_user):', routes)
assert routes.count('/setup') == 2, 'per_user mode should mount GET+POST /setup'
print('per_user-mode build ok')
" && rm -f /tmp/test_p3e_*
```
Expected: `/setup` appears twice (GET + POST).

- [ ] **Step 9: Verify shared mode REFUSES without PCE_HOST**

```bash
unset MCP_DEV_INSECURE MCP_KEK PCE_HOST
MCP_OAUTH_ISSUER=https://idp.test/o \
MCP_OAUTH_JWKS_URL=https://idp.test/o/.well-known/jwks.json \
MCP_OAUTH_AUDIENCE=mcp.test \
MCP_PUBLIC_URL=http://127.0.0.1 \
MCP_PCE_MODE=shared \
MCP_ROLE_GROUPS_ADMIN=sg-admin \
MCP_CONFIRM_HMAC_KEY=$(.venv/bin/python3 -c "import os, base64; print(base64.b64encode(os.urandom(32)).decode())") \
  .venv/bin/python3 -c "
from illumio_mcp.transport.http import serve_http
try:
    serve_http()
    print('ERROR: should have refused')
except SystemExit as e:
    print('correctly refused:', str(e)[:120])
"
```
Expected: prints `correctly refused: MCP_PCE_MODE=shared requires PCE_HOST env var ...`.

- [ ] **Step 10: Verify stdio still works**

```bash
echo '{"jsonrpc":"2.0","id":0,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"test","version":"0"}}}' | timeout 5 .venv/bin/python3 -m illumio_mcp 2>&1 | head -3
```

- [ ] **Step 11: Run test_http_transport.py**

```bash
.venv/bin/python3 -m pytest tests/test_http_transport.py -v 2>&1 | tail -10
```
Expected: 5 PASSED.

- [ ] **Step 12: Commit**

```bash
git add src/illumio_mcp/transport/http.py tests/test_http_transport.py
git commit -m "feat(http): MCP_PCE_MODE=shared skips keystore + /setup, uses env PCE"
```

---

## Task 6: End-to-end shared-mode test

**Files:**
- Create: `tests/test_http_shared_mode.py`

- [ ] **Step 1: Write the test**

Create `tests/test_http_shared_mode.py`:

```python
"""End-to-end: shared-PCE-key mode.

Verifies that in MCP_PCE_MODE=shared:
  - The /setup route is NOT mounted
  - A user with NO per-user creds can immediately call PCE tools
  - register-pce-credentials returns the shared-mode error
  - check-pce-credentials-status returns mode=shared
"""
import json
import socket
import threading
import time
import urllib.request

import pytest
import jwt as pyjwt
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization

from illumio_mcp.auth.config import OAuthConfig
from illumio_mcp.auth.jwt_validator import JWTValidator
from illumio_mcp.auth.middleware import JWTAuthMiddleware
from illumio_mcp.auth.audit import NullAuditLog
from illumio_mcp.auth.roles import RoleConfig


pytestmark = pytest.mark.asyncio


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


@pytest.fixture(scope="module")
def rsa_key():
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


@pytest.fixture(scope="module")
def public_key_pem(rsa_key):
    return rsa_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )


@pytest.fixture(scope="module")
def private_key_pem(rsa_key):
    return rsa_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption(),
    )


def _mint(private_key_pem, sub="alice", groups=("sg-admin",)):
    return pyjwt.encode({
        "iss": "https://idp.test/o",
        "aud": "mcp.test",
        "sub": sub,
        "exp": int(time.time()) + 600,
        "iat": int(time.time()),
        "scope": "illumio-mcp.use",
        "groups": list(groups),
    }, private_key_pem, algorithm="RS256", headers={"kid": "test-kid"})


@pytest.fixture(scope="module")
def http_server(public_key_pem, tmp_path_factory):
    """Start the HTTP server in shared mode. Stub build_pce_for so the env-loaded
    PCE doesn't need a real Illumio."""
    import uvicorn
    from contextlib import asynccontextmanager
    from starlette.applications import Starlette
    from starlette.middleware import Middleware
    from starlette.responses import JSONResponse
    from starlette.routing import Mount, Route
    from mcp.server.streamable_http_manager import StreamableHTTPSessionManager
    from illumio_mcp.server import (
        server as mcp_server, set_http_context, reset_http_context,
        build_http_context_for,
    )
    from illumio_mcp.transport.request_id import RequestIdMiddleware
    from illumio_mcp.auth.roles import map_user_role
    import illumio_mcp.pce as pce_mod

    class FakePCE:
        def __init__(self, host):
            self.host = host

    original_build = pce_mod.build_pce_for
    pce_mod.build_pce_for = lambda creds: FakePCE(creds.host)
    # Also stub get_pce_from_env so we don't need real env vars
    original_env = pce_mod.get_pce_from_env
    pce_mod.get_pce_from_env = lambda: FakePCE("https://shared.pce.example")  # type: ignore[assignment]
    # Reset the singleton so the stub takes effect
    pce_mod._stdio_singleton = None

    port = _free_port()
    cfg = OAuthConfig(
        issuer="https://idp.test/o",
        jwks_url="https://idp.test/o/.well-known/jwks.json",
        audience="mcp.test",
        required_scope="illumio-mcp.use",
        resource_url=f"http://127.0.0.1:{port}",
    )
    validator = JWTValidator(cfg, key_resolver=lambda kid: public_key_pem)
    audit = NullAuditLog()
    role_config = RoleConfig(
        admin_groups=["sg-admin"],
        operator_groups=["sg-op", "sg-admin"],
        reader_groups=["sg-read", "sg-op", "sg-admin"],
        default_role=None,
    )

    session_manager = StreamableHTTPSessionManager(app=mcp_server, stateless=True)

    async def mcp_handler_wrapper(scope, receive, send):
        if scope["type"] != "http":
            await session_manager.handle_request(scope, receive, send)
            return
        state = scope.get("state", {})
        user = state.get("user")
        sub = getattr(user, "sub", None) if user else None
        iss = getattr(user, "iss", None) if user else None
        groups = getattr(user, "groups", []) if user else []
        role = map_user_role(groups, role_config)
        request_id = state.get("request_id")
        # SHARED MODE: keystore=None, pce_mode="shared"
        ctx = build_http_context_for(
            sub, iss, None, role, audit, request_id,
            confirm_manager=None, jti_store=None,
            pce_mode="shared",
        )
        token = set_http_context(ctx)
        try:
            await session_manager.handle_request(scope, receive, send)
        finally:
            reset_http_context(token)

    @asynccontextmanager
    async def lifespan(app):
        async with session_manager.run():
            yield

    async def healthz(_): return JSONResponse({"status": "ok"})

    app = Starlette(
        routes=[
            Mount("/mcp", app=mcp_handler_wrapper),
            Route("/healthz", healthz, methods=["GET"]),
        ],
        middleware=[
            Middleware(RequestIdMiddleware),
            Middleware(JWTAuthMiddleware, validator=validator, config=cfg),
        ],
        lifespan=lifespan,
    )

    config = uvicorn.Config(app, host="127.0.0.1", port=port, log_level="warning")
    server = uvicorn.Server(config)
    thread = threading.Thread(target=server.run, daemon=True)
    thread.start()

    deadline = time.monotonic() + 10
    while time.monotonic() < deadline:
        try:
            with urllib.request.urlopen(f"http://127.0.0.1:{port}/healthz", timeout=0.5) as resp:
                if resp.status == 200:
                    break
        except Exception:
            time.sleep(0.1)
    else:
        pytest.fail("HTTP server did not become ready within 10s")

    yield f"http://127.0.0.1:{port}"

    server.should_exit = True
    thread.join(timeout=5)
    pce_mod.build_pce_for = original_build
    pce_mod.get_pce_from_env = original_env  # type: ignore[assignment]


async def test_status_reports_shared_mode(http_server, private_key_pem):
    from mcp import ClientSession
    from mcp.client.streamable_http import streamablehttp_client

    token = _mint(private_key_pem, sub="alice", groups=["sg-admin"])
    async with streamablehttp_client(f"{http_server}/mcp", headers={"Authorization": f"Bearer {token}"}) as (read, write, _):
        async with ClientSession(read, write) as session:
            await session.initialize()
            result = await session.call_tool("check-pce-credentials-status", {})
            body = json.loads(result.content[0].text)
            assert body["registered"] is True
            assert body["mode"] == "shared"


async def test_register_returns_shared_error(http_server, private_key_pem):
    from mcp import ClientSession
    from mcp.client.streamable_http import streamablehttp_client

    token = _mint(private_key_pem, sub="alice", groups=["sg-admin"])
    async with streamablehttp_client(f"{http_server}/mcp", headers={"Authorization": f"Bearer {token}"}) as (read, write, _):
        async with ClientSession(read, write) as session:
            await session.initialize()
            result = await session.call_tool("register-pce-credentials", {
                "pce_host": "h", "pce_port": 1, "pce_org_id": 1, "api_key": "k", "api_secret": "s",
            })
            body = json.loads(result.content[0].text)
            assert "error" in body
            assert "shared" in body["error"].lower()


async def test_user_with_no_per_user_creds_can_call_pce_tools(http_server, private_key_pem):
    """In shared mode, the dispatcher's no_pce_credentials gate doesn't fire
    because ctx.pce is the env-loaded singleton."""
    from mcp import ClientSession
    from mcp.client.streamable_http import streamablehttp_client

    token = _mint(private_key_pem, sub="never-onboarded-user", groups=["sg-admin"])
    async with streamablehttp_client(f"{http_server}/mcp", headers={"Authorization": f"Bearer {token}"}) as (read, write, _):
        async with ClientSession(read, write) as session:
            await session.initialize()
            result = await session.call_tool("get-labels", {})
            body_text = result.content[0].text
            try:
                body = json.loads(body_text)
                # Either the call worked (unlikely with FakePCE), or it failed
                # at the handler with a tool-level error. EITHER way, the
                # dispatcher must NOT have returned no_pce_credentials.
                if isinstance(body, dict):
                    assert body.get("error") != "no_pce_credentials"
            except json.JSONDecodeError:
                # Non-JSON body (e.g. "Labels: ...") → handler ran, dispatcher passed
                pass
```

- [ ] **Step 2: Run the test**

```bash
.venv/bin/python3 -m pytest tests/test_http_shared_mode.py -v 2>&1 | tail -30
```
Expected: 3 PASSED.

- [ ] **Step 3: Commit**

```bash
git add tests/test_http_shared_mode.py
git commit -m "test: end-to-end shared-PCE-key mode"
```

---

## Task 7: README — document the two modes

**Files:**
- Modify: `README.md`

- [ ] **Step 1: Insert new "Two PCE modes" subsection after "Per-user PCE keys (Phase 3b)"**

Find the heading `### Per-user PCE keys (Phase 3b)` and insert this new subsection RIGHT BEFORE it (so the comparison table is the first thing readers see):

```markdown
### Two PCE modes (Phase 3b vs Phase 3e)

The HTTP server supports two ways to source PCE credentials, selected via
`MCP_PCE_MODE`:

| Mode | `MCP_PCE_MODE` | PCE creds | Onboarding | PCE-side audit |
|---|---|---|---|---|
| **Per-user** (default) | `per_user` | One PCE API key per authenticated user, encrypted in keystore | User registers via `/setup` page or `register-pce-credentials` tool | PCE logs show the real human via per-user API key |
| **Shared** | `shared` | One PCE service-account key from env (same as stdio) | None — works immediately for any authenticated user | PCE logs show the service account; the MCP audit log is the source of truth for "who did what" |

**Choose per-user when:**
- You want PCE-side audit attribution to identify the human
- Users are happy to provide their own PCE API key once
- You can tolerate the per-user PCE key sprawl (PCE has limits)

**Choose shared when:**
- The PCE limits API keys per user too aggressively for per-user mode
- You want zero-friction onboarding (no `/setup` step)
- You're OK relying on the MCP audit log alone for human-level attribution
- You operate the PCE service account yourself and rotate it on a schedule

In **shared** mode, `/setup` is not mounted, the credential-management tools
(`register-pce-credentials`, `delete-pce-credentials`) refuse with a friendly
error, and `MCP_KEK` is not required. SSO + JWT + role-based authz + audit
log + confirm tokens all still apply identically.

```bash
# Shared mode — same env that stdio uses today, plus auth/role config
export MCP_PCE_MODE=shared
export PCE_HOST=https://your-pce.example.com
export PCE_PORT=8443
export PCE_ORG_ID=1
export API_KEY=your_pce_api_key_name
export API_SECRET=your_pce_api_key_secret
# (other auth/role env vars from earlier sections still apply)
illumio-mcp-http
```
```

- [ ] **Step 2: Commit**

```bash
git add README.md
git commit -m "docs: two PCE modes — per_user (default) vs shared"
```

---

## Task 8: Open PR

- [ ] **Step 1: Push the branch**

```bash
git push -u origin feature/shared-pce-mode
```

- [ ] **Step 2: Open the PR**

```bash
gh pr create --base feature/confirm-tokens --title "feat: shared-PCE-key mode (Phase 3e, opt-in)" --body "$(cat <<'EOF'
## Summary

Phase 3e. Adds an opt-in mode where the HTTP server uses a single PCE service-account key from env vars instead of per-user keystored credentials. SSO + JWT + role-based authz + audit log + confirm tokens still apply identically. Per-user mode (Phase 3b) remains the default.

> **Stacked on #15 (Phase 3d).** When #15 merges, base auto-updates.

## What changed

- **`auth/pce_mode.py`** (new): `PCEMode` literal + `load_pce_mode_from_env()` + `is_shared_mode()`.
- **`ToolContext`** gains `pce_mode: str = "per_user"`.
- **`server.py`**: `build_http_context_for(...pce_mode=...)`; in shared mode, every request uses `get_pce_from_env()` regardless of user.
- **`tools/credentials.py`**: register/delete return a friendly `shared_mode` error; status reports `mode=shared` cleanly.
- **`transport/http.py`**: reads `MCP_PCE_MODE` at startup; in shared mode, skips `build_keystore_from_env()` (no `MCP_KEK` needed) and does not mount `/setup`. Refuses to start if `MCP_PCE_MODE=shared` but `PCE_*` env vars are missing.

## Test plan

- [x] `pytest tests/test_auth_pce_mode.py -v` — 6 passed (defaults, explicit values, validation, helper)
- [x] `pytest tests/test_credentials_tools.py -v` — 11 passed (8 original + 3 new for shared-mode behavior)
- [x] `pytest tests/test_http_shared_mode.py -v` — 3 passed end-to-end (status reports shared, register refuses, never-onboarded user can call PCE tools)
- [x] All Phase 1–3d tests still green
- [x] Stdio sanity check after every transport-touching commit

## When to use which mode

| Mode | Best for |
|---|---|
| **per_user** (default) | PCE-side audit attribution; users provide their own PCE key; small user counts |
| **shared** | PCE API-key limits; zero-friction onboarding; relying on MCP audit log alone |

Both modes ship in the same binary; switch with `MCP_PCE_MODE=shared` env var.

## What this PR does NOT do

- Mid-flight mode switch (restart required)
- Per-user PCE creds with shared-mode fallback (you pick one mode at startup)

🤖 Generated with [Claude Code](https://claude.com/claude-code)
EOF
)"
```

- [ ] **Step 3: Print the PR URL**

---

## Self-review checklist

- [x] **Spec coverage:** Originally rejected design option A (shared service account) is now offered as opt-in `MCP_PCE_MODE=shared`. All Phase 3a–3d invariants (auth, role, audit, confirm) preserved by design — none are gated on PCE mode.
- [x] **Placeholders:** None.
- [x] **Type consistency:** `PCEMode` defined Task 1, used Tasks 3, 5. `pce_mode` field on `ToolContext` (Task 2) consistent with `build_http_context_for(pce_mode=...)` (Task 3) consistent with `_build_app(pce_mode=...)` and `_wrap_with_per_request_context(pce_mode=...)` (Task 5).
- [x] **Stdio invariants:** Tasks 2, 3, 5 each include explicit stdio handshake check.
- [x] **No new dependencies.**
- [x] **Default preserves Phase 3b behavior:** `load_pce_mode_from_env()` returns `per_user` when `MCP_PCE_MODE` is unset.
- [x] **Failure modes are explicit:** shared mode refuses without `PCE_*` env vars; per_user mode still refuses without `MCP_KEK`.
