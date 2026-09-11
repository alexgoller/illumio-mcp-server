---
title: Code layout
layout: default
parent: Development
---

# Code Layout

Overview of the package structure for contributors. Every module has a single well-defined responsibility.

---

## Package tree

```
src/illumio_mcp/
  __init__.py          # Exports main() (stdio) and serve_http_cli() (HTTP)
  __main__.py          # python -m illumio_mcp arg parser; default = stdio
  server.py            # mcp.Server instance; ToolContext builders; dispatcher
  context.py           # ToolContext dataclass
  registry.py          # ToolSpec dataclass + Role constants
  pce.py               # PCECredentials; build_pce_for(); get_pce_from_env()

  auth/
    __init__.py        # Package docstring; no re-exports
    config.py          # OAuthConfig; load_oauth_config_from_env(); is_dev_insecure()
    jwt_validator.py   # JWTValidator; AuthenticatedUser; InvalidTokenError
    middleware.py      # JWTAuthMiddleware (Starlette BaseHTTPMiddleware)
    prm.py             # build_prm_document() — RFC 9728 PRM response
    keystore.py        # KeyStore protocol; SQLiteKeyStore (WAL, envelope-encrypted)
    keystore_init.py   # build_keystore_from_env() — reads MCP_KEYSTORE_PATH + MCP_KEK
    crypto.py          # EnvelopeCipher (AES-256-GCM two-tier); load_kek_from_env()
    roles.py           # RoleConfig; load_role_config_from_env(); map_user_role()
    audit.py           # AuditEntry; AuditLog protocol; SQLiteAuditLog; NullAuditLog
    audit_init.py      # build_audit_log_from_env() — reads MCP_AUDIT_LOG_PATH
    confirm.py         # ConfirmTokenManager; ConfirmTokenClaims; canonical_params_hash()
    confirm_replay.py  # JtiStore protocol; SQLiteJtiStore; NullJtiStore
    confirm_init.py    # build_confirm_manager_from_env() — reads MCP_CONFIRM_* vars
    pce_mode.py        # PCEMode literal; load_pce_mode_from_env(); is_shared_mode()

  transport/
    __init__.py        # Package docstring
    http.py            # Starlette app factory; serve_http(); main() CLI entry
    setup_page.py      # /setup GET+POST routes (HTML form for per-user onboarding)
    confirm_endpoint.py # /confirm POST route (mint confirm token)
    request_id.py      # RequestIdMiddleware — per-request UUID → X-Request-Id

  tools/
    __init__.py        # TOOL_REGISTRY: dict[str, ToolSpec] (the canonical list)
    workloads.py       # handle_get_workloads, handle_create_workload, ...
    labels.py          # handle_get_labels, handle_create_label, ...
    services.py        # handle_get_services, handle_create_service, ...
    iplists.py         # handle_get_iplists, handle_create_iplist, ...
    rulesets.py        # handle_get_rulesets, handle_create_ruleset, ..., handle_provision_policy
    deny_rules.py      # handle_create_deny_rule, handle_update_deny_rule, ...
    traffic.py         # handle_get_traffic_flows, ..., to_dataframe(pce, flows)
    policy.py          # handle_compliance_check, handle_enforcement_readiness, ...
    ringfence.py       # handle_create_ringfence, handle_ringfence_batch, ...
    containers.py      # handle_get_container_clusters, ...
    infra.py           # handle_check_pce_connection, handle_get_events, ...
    credentials.py     # handle_register_pce_credentials, handle_delete_pce_credentials, ...
```

---

## The dispatch flow

Understanding this flow is necessary for any change that touches authentication, authorization, or tool execution.

### HTTP request path

```
1. HTTP client sends: POST /mcp  Authorization: Bearer <jwt>

2. RequestIdMiddleware (transport/request_id.py)
   - Generates UUID or honors X-Request-Id header
   - Sets request.state.request_id
   - Adds X-Request-Id to response

3. JWTAuthMiddleware (auth/middleware.py)
   - Extracts Bearer token from Authorization header
   - Calls JWTValidator.validate(token) (auth/jwt_validator.py)
   - On failure: returns 401 with WWW-Authenticate header
   - On success: sets request.state.user = AuthenticatedUser(sub, iss, scopes, groups)

4. ASGI context wrapper (transport/http.py _wrap_with_per_request_context)
   - Reads request.state.user and request.state.request_id
   - Calls map_user_role(user.groups, role_config) (auth/roles.py)
   - Calls build_http_context_for(sub, iss, keystore, role, audit_log, request_id,
       confirm_manager=..., jti_store=..., pce_mode=...) (server.py)
     - In per_user mode: keystore.get(sub=sub, iss=iss) → PCECredentials
       → build_pce_for(creds) (pce.py)
     - In shared mode: get_pce_from_env() (pce.py)
     - Sets ctx.pce = None if no creds found (per_user, no row yet)
   - Calls set_http_context(ctx) — stores ctx in a ContextVar
   - Invokes StreamableHTTPSessionManager

5. mcp.Server (server.py) routes the JSON-RPC method to handle_call_tool()

6. dispatcher (server.py handle_call_tool)
   - ctx = get_active_context() — reads the ContextVar
   - spec = TOOL_REGISTRY.get(tool_name)
   - Gate 1: spec.roles — does ctx.user_role ∈ spec.roles?
     No → audit denied, return {"error": "forbidden"}
   - Gate 2: spec.requires_pce — is ctx.pce non-None?
     No → audit denied, return {"error": "no_pce_credentials", "setup_url": ...}
   - Gate 3: spec.requires_confirm (HTTP only) — is params._meta.confirm_token valid?
     No → audit denied, return {"error": "confirm_required", "params_hash": ...}
     Invalid/replayed → audit denied, return {"error": "..."}
   - All gates passed → audit allowed
   - result = await asyncio.to_thread(spec.handler, ctx, arguments)

7. Handler (e.g. tools/workloads.py handle_get_workloads)
   - Reads ctx.pce — the per-request PolicyComputeEngine client
   - Makes PCE API calls via python-illumio
   - Returns list[types.TextContent]
```

### Stdio path

The stdio path is simpler:

```
python -m illumio_mcp
  → __main__.py → main() → asyncio.run(server.run_stdio())
  → server.py run_stdio() starts MCP stdio loop
  → handle_call_tool: ctx = _get_stdio_context()
    (ToolContext with pce=get_pce_from_env(), is_stdio=True, role="admin",
     user_sub=None, user_iss=None, audit_log=NullAuditLog())
  → same dispatcher, but all gate checks pass for admin + is_stdio=True
```

---

## Key design decisions

**ContextVar for per-request ToolContext in HTTP mode**

The mcp SDK's `StreamableHTTPSessionManager` does not thread user context through to tool handlers. We use a `contextvars.ContextVar` (`_http_context_var` in `server.py`) to carry the per-request `ToolContext`. The ASGI wrapper sets it before invoking the session manager and resets it in a `finally` block. This is safe for asyncio (each Task has its own context copy).

**Default-deny in `TOOL_REGISTRY`**

`ToolSpec.__post_init__` raises `ValueError` if `roles=` is empty or contains an unknown role. This means the server fails to import if a tool is added without explicit roles. CI catches this with `test_tool_metadata.py`.

**Handlers are transport-agnostic**

Handlers in `tools/*.py` only receive `(ctx, arguments)`. They never import from `transport/` or `auth/`. All authz enforcement happens before the handler is called.
