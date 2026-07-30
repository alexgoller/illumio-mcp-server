# Illumio MCP Server — Migration to MCP spec revision 2026-07-28

**Status:** **Deferred — designed, not scheduled.** Do not implement yet. See §1.3 for the revival triggers.
**Date:** 2026-07-30
**Author:** Alex Goller (with Claude)
**Supersedes nothing.** Builds on `2026-05-12-http-transport-and-auth-design.md`.

---

## 1. Why this document exists, and why it is shelved

### 1.1 The change

MCP revision `2026-07-28` is the largest breaking revision since the protocol launched. It removes
the `initialize` handshake, removes protocol-level sessions, removes server-initiated requests, and
adds a mandatory `server/discover` RPC plus required caching and header metadata. The Python SDK
`mcp` 2.0.0 (released 2026-07-28) implements it.

This server currently runs on `mcp` 1.27.1 and speaks whatever the SDK negotiates — the protocol
version appears nowhere in our source.

### 1.2 Why we are not doing it now

**Nothing consumes it yet.** Anthropic's announcement states only that support is "rolling out
across Claude products soon" — no product named, no date. Research could not confirm that Claude
Code or Claude Desktop negotiate anything newer than `2025-11-25`. No VS Code / Cursor / Windsurf
announcement was found either.

Because `mcp` 2.0.0 serves **both** eras automatically (§3.2), a migrated server would keep serving
today's clients over the *legacy* path regardless. The entire 2026-era surface would therefore ship
exercised by nothing but our own tests. Waiting costs nothing and buys real client behaviour to test
against.

The Tasks extension (§9) is weaker still: `draft`-only schema, no Python SDK support, no client
support.

### 1.3 Revival triggers

Pick this up when **any** of these becomes true:

1. A client we actually serve (Claude Desktop, Claude Code, claude.ai connectors, Cursor, VS Code)
   announces or is observed negotiating `2026-07-28`.
2. `mcp` 1.x stops receiving fixes we need. As of 2026-07-30, 1.29.0 is the last v1 and is
   maintenance-only (security + critical bugfixes on the `v1.x` branch) — that is adequate for now.
3. A deprecated feature we depend on reaches removal. We depend on **none** (§2.3), so this is
   unlikely to fire.
4. A customer requires a stateless/horizontally-scalable deployment that protocol-level sessions
   would block. Note we already run `stateless=True`, so this is mostly already satisfied.

**Re-verify before implementing.** Everything in §3 was verified against `mcp` 2.0.0 on 2026-07-30
by installing it and introspecting. SDK internals will have moved. Re-run the §12 verification
checklist first.

---

## 2. Current state (audited 2026-07-30, commit `50767c4`)

### 2.1 What we have

| Aspect | State |
|---|---|
| SDK | `mcp>=1.8.0` in `pyproject.toml:11`, resolved to **1.27.1**. Stale `requirements.txt:16` says `mcp==1.2.0` |
| API style | Low-level `mcp.server.Server` with decorators. No `FastMCP` anywhere |
| Protocol version | **Never named in our source.** Entirely SDK-driven |
| Transports | stdio + Streamable HTTP via `StreamableHTTPSessionManager(stateless=True)` (`transport/http.py:60-61`) |
| Surface | 46 tools, 20 resources, 3 prompts |
| Handlers | 6, all in `server.py`: `list_resources` (1907), `read_resource` (1920), `list_prompts` (1928), `get_prompt` (1985), `list_tools` (2116), `call_tool` (3289) |
| `server.py` size | 3412 lines |

### 2.2 What is deliberately *not* registered

Beyond the six handlers in §2.1, nothing else is registered: no `set_logging_level`,
`subscribe_resource`, `unsubscribe_resource`, `list_resource_templates`, `complete`, or `progress`.
`ping` is handled internally by the SDK.

This narrow surface is why §2.3 comes out so favourably — most of what `2026-07-28` removes, we
never adopted.

### 2.3 Why the breaking changes barely touch us

This is the central finding of the audit and the reason this migration is tractable:

| Spec removal | Our exposure |
|---|---|
| `Mcp-Session-Id`, HTTP GET stream, `Last-Event-ID` resumability | **None.** `stateless=True` means we never issued session IDs, never had an event store, never supported resumability |
| Server-initiated `elicitation/create`, `sampling/createMessage`, `roots/list` | **None.** Exhaustive grep finds zero usage. Structurally impossible today — no `session`/`request_context` access anywhere |
| `resources/subscribe` / `unsubscribe` → `subscriptions/listen` | **None.** Not registered |
| `ping`, `logging/setLevel` | **None.** Not registered |
| `notifications/message`, `notifications/progress` | **None.** Our `logging.setLevel` at `server.py:23,39` is stdlib Python logging to a file, never MCP |
| Roots / Sampling / Logging deprecation (SEP-2577) | **None.** We use none of the three |
| HTTP+SSE transport deprecation | **None.** We use Streamable HTTP |
| DCR deprecation → Client ID Metadata Documents | **None.** We are a resource server, never a client. No `/register` endpoint |
| RFC 9207 `iss` validation, `application_type` | **None.** Both are client-side obligations |

Authorization for a *resource server* is essentially unchanged in `2026-07-28`: RFC 9728 Protected
Resource Metadata (`auth/prm.py:9-24`), `WWW-Authenticate` with `resource_metadata`
(`auth/middleware.py:67-75`), and audience-bound token validation
(`auth/jwt_validator.py:56-117`) all remain correct as written.

### 2.4 Pre-existing bugs (independent of this migration — fix regardless)

1. **`tests/test_mcp_tools.py:50-82`** asserts a hardcoded 43-name expected tool list;
   `handle_list_tools` returns 46. Missing: `register-pce-credentials`,
   `delete-pce-credentials`, `check-pce-credentials-status`. **This test fails as written.**
2. **`transport/confirm_endpoint.py:41`** reads `user.auth_time`, but `AuthenticatedUser`
   (`auth/jwt_validator.py:28-34`) never populates it. Enabling
   `MCP_CONFIRM_FRESH_AUTH_SECONDS` therefore makes `/confirm` return 403 unconditionally.

### 2.5 Structural observations that shape the design

- **Dual tool registration.** Every tool is declared twice: a `types.Tool(...)` literal inside
  `handle_list_tools` (`server.py:2122-3262`, ~1140 lines) and a `ToolSpec` in
  `tools/__init__.py:88-149`. Only test-level parity guards this — which is exactly how §2.4.1
  happened.
- **No `outputSchema`, `structuredContent`, `annotations`, `title`, or `icons`** on any tool.
- **Tool order** is source-order: deterministic and stable, but arbitrary.
- **Authz denials return success-shaped results.** `server.py:3310-3380` returns `TextContent`
  carrying an `error` key with JSON-RPC success. A denied call looks like a successful one.
- **Confirmation is out-of-band and not MCP.** `ToolSpec.requires_confirm` on 2 tools
  (`provision-policy`, `ringfence-batch`). The dispatcher returns
  `{"error":"confirm_required","params_hash":...}` instructing the caller to `POST /confirm`
  itself, then re-call with `arguments._meta.confirm_token`. Enforced **only** over HTTP
  (`server.py:3340`: `and not ctx.is_stdio`).
  **There is no human in this loop** — the model POSTs `/confirm` with the same bearer token, so
  the gate proves an authenticated round-trip, not human intent.
- **Server identity can drift.** `server.py:3405-3406` hardcodes `server_version="0.1.0"`; the HTTP
  path never builds `InitializationOptions`, letting `StreamableHTTPSessionManager` derive them.
- **Response caps.** `tools/constants.py`: `MCP_BUG_MAX_RESULTS = 500`
  ("Due to a condition in MCP…"), `MCP_MAX_RESPONSE_BYTES = 800_000`.
- **`conftest.py` requires a live PCE** for the whole suite.

---

## 3. Verified SDK facts (`mcp` 2.0.0, verified 2026-07-30)

Verified by installing `mcp==2.0.0` on Python 3.12 and introspecting. Our `requires-python` is
`>=3.12,<3.14`, so it installs cleanly.

### 3.1 Versions

```
mcp                          2.0.0     (GA 2026-07-28)
mcp-types                    2.0.0     (new standalone dist; mcp.types is a permanent alias)
last v1                      1.29.0    (maintenance-only)

SUPPORTED_PROTOCOL_VERSIONS  ('2024-11-05','2025-03-26','2025-06-18','2025-11-25','2026-07-28')
HANDSHAKE_PROTOCOL_VERSIONS  ('2024-11-05','2025-03-26','2025-06-18','2025-11-25')
MODERN_PROTOCOL_VERSIONS     ('2026-07-28',)
LATEST_PROTOCOL_VERSION       2026-07-28
```

One server, five revisions.

### 3.2 Dual-era is automatic — Python-specific advantage

`mcp/server/runner.py` `serve_dual_era_loop` decides the era from the client's **first request**.
`Server.run()` calls it. **No configuration.** TypeScript and Go require explicit opt-in; Python
does not.

`get_capabilities(protocol_version=...)` is era-honest: at modern versions the `listChanged` flags
and `resources.subscribe` derive from whether `subscriptions/listen` is served, ignoring
`NotificationOptions`; at handshake versions the v1 derivation applies unchanged.

### 3.3 `server/discover` — nothing to write

Registered by default in `Server.__init__`. The default handler derives
`supported_versions`, `capabilities`, and `instructions` from server state at call time.
Overridable via `add_request_handler("server/discover", ...)`.

### 3.4 Low-level `Server` survives

15 `on_*` handler kwargs: `on_list_tools`, `on_call_tool`, `on_list_resources`,
`on_list_resource_templates`, `on_read_resource`, `on_subscribe_resource`,
`on_unsubscribe_resource`, `on_subscriptions_listen`, `on_list_prompts`, `on_get_prompt`,
`on_completion`, `on_set_logging_level`, `on_ping`, `on_roots_list_changed`, `on_progress`.

Other constructor params: `name`, `version`, `title`, `description`, `instructions`,
`website_url`, `icons`, `cache_hints`, `lifespan`. All keyword-only. `add_request_handler` exists.

Handler shape is uniform: `(ctx: ServerRequestContext, params) -> Result`.

Carried over unchanged from v1: `stdio_server()`, `create_initialization_options()`,
`NotificationOptions`, `InitializationOptions`, `StreamableHTTPSessionManager`.

### 3.5 `ServerRequestContext`

Fields: `session`, `lifespan_context`, `protocol_version`, `method`, `params`, `request_id`,
`meta`, `request`, `close_sse_stream`, `close_standalone_sse_stream`.

- `ctx.protocol_version` → the era, per request.
- `ctx.meta` → the request `_meta` (`RequestParamsMeta`).
- `ctx.request` → the raw HTTP request. **This lets us delete the ContextVar bridge** (§6).
- `ctx.session.client_capabilities` and `ctx.session.check_client_capability(...)`
  (`mcp/server/session.py:70-137`) → capability branching.

### 3.6 MRTR is first-class on the low-level Server

`on_call_tool` is officially typed `Awaitable[CallToolResult | InputRequiredResult]`
(`mcp/server/lowlevel/server.py:153`). Same for `on_read_resource` (`:168`) and `on_get_prompt`
(`:193`). Returning an `InputRequiredResult` is the sanctioned path, not a workaround.

Typed shapes:

```
InputRequiredResult          (meta, result_type, input_requests, request_state)
InputResponseRequestParams   (meta, input_responses, request_state)
```

Elicitation types present: `ElicitRequestFormParams`, `ElicitRequestURLParams`,
`FormElicitationCapability`, `UrlElicitationCapability`, `ElicitResult`.

`mcp/server/runner.py:356` already implements the spec rule that `input_required` interim results
carry no cache hints.

### 3.7 Caching is turnkey

```python
from mcp.server.caching import CacheHint       # CacheHint(ttl_ms: int = 0, scope: "public"|"private" = "private")
```

`CACHEABLE_METHODS` = `prompts/list`, `resources/list`, `resources/read`,
`resources/templates/list`, `server/discover`, `tools/list`.

`apply_cache_hint` is **per-field**: a field the handler set explicitly — even to its default,
tracked via `model_fields_set` — is left alone. A server-wide hint never overrides a handler's
explicit choice. Handlers using `model_construct` bypass that tracking and count as having set
nothing.

### 3.8 v2 API changes that bite

| Change | Consequence for us |
|---|---|
| **Auto-wrapping of return values removed** | `handle_read_resource` returns a bare `str` today; must build `ReadResourceResult` |
| **Tool exceptions no longer become `is_error=True`** | They propagate as JSON-RPC errors. Our catch-all at `server.py:3389-3393` masks this, but the shape changes |
| **The `@call_tool()` decorator's `jsonschema` validation is gone, with no replacement** | **Silent regression risk.** Our 46 hand-written schemas would stop being enforced. Must rebuild explicitly (§5) |
| camelCase → snake_case on all Pydantic fields | `inputSchema`→`input_schema`, `isError`→`is_error`. Wire format unchanged via aliases; our own `model_dump()` needs `by_alias=True` |
| `McpError` → `MCPError`, now at `mcp.shared.exceptions`, args passed directly | Mechanical |
| `httpx` + `httpx-sse` → `httpx2` | **We import neither directly** (verified). Transitive only. But `httpx2` verifies TLS via **OS trust stores, not `certifi`** — verify PCE TLS from inside the container |
| `stdio_server()` claims fd 0/1, serving the wire from private duplicates | Safe for us: **no `print()` to stdout anywhere in `src/`** (verified); logging goes to a file |
| Request bodies capped at 4 MiB | Likely fine; confirm against largest tool payload |
| `streamablehttp_client` → `streamable_http_client`; `timeout` `timedelta` → `float` | Test-side updates |
| `Client` defaults to `mode='auto'` | **Gotcha:** an in-process client negotiates 2026-07-28 by default |
| Unknown request methods return `-32601` | Aligns with spec |

### 3.9 New error codes

| Code | Name |
|---|---|
| `-32020` | `HeaderMismatch` |
| `-32021` | `MissingRequiredClientCapability` |
| `-32022` | `UnsupportedProtocolVersion` |

`-32020`–`-32099` is reserved for the MCP spec; `-32000`–`-32019` is legacy and must not receive new
allocations. Resource-not-found moved `-32002` → `-32602`.

Header/version validation, `resultType`, and these codes are all handled **inside** the SDK.

---

## 4. Phasing

Six phases, each independently shippable and reviewable.

| Phase | Content | Client-visible |
|---|---|---|
| **P0** | Fix §2.4 bugs on v1; establish a green baseline | no |
| **P1** | SDK v2 port, behaviour-preserving | no |
| **P2** | Conformance surface | additive |
| **P3** | Registry unification, annotations, `structuredContent` | additive + one denial-shape change |
| **P4** | MRTR confirm gate | new rendering; legacy path preserved |
| **P5** | Tasks extension | new, capability-gated |

**P0 must land first.** The suite must be green *before* the port, or a migration regression is
indistinguishable from a pre-existing failure — and §2.4.1 guarantees at least one pre-existing
failure.

---

## 5. P1 — SDK v2 port

### 5.1 Splitting `server.py`

`server.py` is 3412 lines and P1 touches every handler in it. Of that, ~1740 lines are static
Markdown resource content (`ILLUMIO_RESOURCES`, `server.py:169-1905`) and ~1140 are the tool-schema
literal (`2122-3262`) that P3 relocates anyway.

```
src/illumio_mcp/resources/__init__.py   ILLUMIO_RESOURCES  (content unchanged, moved verbatim)
src/illumio_mcp/prompts.py              3 prompts + get_prompt logic
src/illumio_mcp/handlers/               the 6 on_* handler functions
src/illumio_mcp/server.py               Server construction + dispatcher  (~400 lines)
```

Justified as targeted improvement of code we are already rewriting — not opportunistic refactoring.

### 5.2 Server construction

```python
server = Server(
    "illumio-mcp",
    version=_pkg_version(),          # importlib.metadata — never hardcoded
    instructions=SERVER_INSTRUCTIONS,
    cache_hints=CACHE_HINTS,         # §7
    on_list_tools=handle_list_tools,
    on_call_tool=handle_call_tool,
    on_list_resources=handle_list_resources,
    on_read_resource=handle_read_resource,
    on_list_prompts=handle_list_prompts,
    on_get_prompt=handle_get_prompt,
)
```

Putting name/version/instructions on the constructor makes both transports read **one** source,
closing the §2.5 identity-drift gap.

### 5.3 Handler ports

| Handler | Change |
|---|---|
| `handle_list_tools` | `(ctx, params) -> ListToolsResult`; `inputSchema=` → `input_schema=` on all 46 |
| `handle_call_tool` | `(ctx, params) -> CallToolResult \| InputRequiredResult`; read `params.name` / `params.arguments` |
| `handle_list_resources` | `-> ListResourcesResult` |
| `handle_read_resource` | `-> ReadResourceResult(contents=[TextResourceContents(...)])`. **Also fix the declared mimeType** `text/plain` → `text/markdown` (`server.py:1916`) — the content is Markdown; this is simply wrong today |
| `handle_list_prompts` | `-> ListPromptsResult` |
| `handle_get_prompt` | `-> GetPromptResult`. **Also guard argument access** — `server.py:2002` and peers index `arguments['...']` unguarded, raising `KeyError` if a client omits a required arg |

Unknown tool: `raise ValueError` (`server.py:3292`) → `-32602`.

### 5.4 Rebuilding input validation (do not skip)

The decorator's `jsonschema` validation is gone with no replacement. Add an explicit validation step
in the dispatcher, against the schema from the tool's registry entry. Fail as an **`is_error` result,
not a protocol error** — per spec, input validation failures are "tool execution errors" that carry
actionable feedback the model can self-correct from.

This becomes natural once P3 unifies registration; in P1 it reads the schema from the tool list.

---

## 6. P1 — Deleting the ContextVar bridge

`transport/http.py:64-88` (`_wrap_with_per_request_context`) is a raw ASGI wrapper that reads
`scope["state"]["user"]`, builds `ToolContext`, stashes it in a `ContextVar`, and resets after. It
exists **only** because v1 handlers had no context parameter.

With `ctx.request` (§3.5), the dispatcher reads `ctx.request.state.user` and builds `ToolContext`
inline. The wrapper is deleted.

**Gate:** confirm `StreamableHTTPSessionManager` actually populates `ctx.request`. If not, retain
the wrapper — it works. Do not block the phase on this.

---

## 7. P2 — Cache hints, and the decision hiding inside them

```python
CACHE_HINTS = {
    "server/discover": CacheHint(ttl_ms=3_600_000, scope="public"),
    "tools/list":      CacheHint(ttl_ms=  300_000, scope="public"),
    "prompts/list":    CacheHint(ttl_ms=  300_000, scope="public"),
    "resources/list":  CacheHint(ttl_ms=3_600_000, scope="public"),
    "resources/read":  CacheHint(ttl_ms=3_600_000, scope="public"),
}
```

`resources/templates/list` is omitted — not registered.

### 7.1 `scope: "public"` is load-bearing

`public` is correct **only because our tool list does not vary by caller**: all 46 tools are always
returned and authz is enforced at call time.

**Decision: do not filter `tools/list` by role.** If we did, `cacheScope` would have to become
`private`, or a shared gateway could serve an admin's tool list to a reader. The spec is explicit
that a `public` response may be shared across authorization contexts even when it came from an
authenticated endpoint. Keeping the full list public and enforcing at call time is both simpler and
safer. **Document this in the code next to `CACHE_HINTS`, or someone will "improve" it later.**

Resources are static Markdown, hence the 1-hour TTL.

### 7.2 Tool ordering

Already deterministic (source order), satisfying the spec's SHOULD. **Add a test pinning stability
rather than sorting** — re-sorting would churn LLM prompt-cache keys for no benefit.

### 7.3 Documentation updates

Every place that names a protocol revision:

- `README.md:80-81` — "spec rev 2025-03-26"
- `docs/operations/http-mode.md:3`
- `src/illumio_mcp/transport/http.py:1` (module docstring)
- `src/illumio_mcp/auth/prm.py:12` — "Per the MCP 2025-06-18 spec"
- `tests/test_http_auth.py:4`

Replace with the supported **range**, not a single revision, since one server now speaks five.

### 7.4 Also in P2

- `WWW-Authenticate` on **403** `insufficient_scope` responses (currently only on 401 —
  `auth/middleware.py:67-75`).
- Delete or regenerate `requirements.txt` (says `mcp==1.2.0`).

---

## 8. P3 — Registry unification, annotations, structured content

### 8.1 One source of truth

`ToolSpec` (`registry.py:20-52`) absorbs `description`, `input_schema`, `output_schema`, `title`,
`annotations`. `handle_list_tools` becomes a projection over `TOOL_REGISTRY`.

This deletes the dual registration outright — the bug class that produced §2.4.1 — and removes
~1140 lines from `server.py`.

### 8.2 Annotations are derived, never hand-written

```python
readOnlyHint    = not spec.mutating
destructiveHint = spec.mutating and spec.requires_confirm
openWorldHint   = True
```

The spec requires clients to treat annotations as **untrusted**. These are UX hints only. Real
enforcement stays in the dispatcher, unchanged.

### 8.3 Authz denial shape — the one behaviour change

`server.py:3310-3380` returns authz denials as `TextContent` with an `error` key and JSON-RPC
**success**. Change to `CallToolResult(is_error=True, ...)`, **keeping the same JSON body** so the
model still receives a machine-readable reason.

Additive in substance. `tests/test_http_authz.py` asserts the current shape and needs a one-line
update per assertion.

### 8.4 `outputSchema` / `structuredContent` — selectively

Not all 46. Only tools whose output is already structured JSON and analytically valuable:

- `get-traffic-flows-summary`
- `get-policy-coverage-report`
- `enforcement-readiness`
- `identify-infrastructure-services`
- `compliance-check`

Emit `structured_content` **and** retain the serialized JSON `TextContent` block, as the spec
recommends for backwards compatibility.

---

## 9. P4 — MRTR confirm gate

### 9.1 One gate, three renderings

The gate itself is untouched: `ToolSpec.requires_confirm`, `ConfirmTokenManager`
(`auth/confirm.py:72-125`), `SQLiteJtiStore` (`auth/confirm_replay.py:29-59`). Only the
**rendering** changes, selected by era and client capability:

| Condition | Rendering |
|---|---|
| modern era + `elicitation.form` (default) | `InputRequiredResult` with form elicit; `request_state` = HMAC token |
| modern era + `elicitation.url` + explicitly configured | `InputRequiredResult` with URL elicit → `/confirm` page |
| legacy era, or no `elicitation` capability | Today's `confirm_required` blob + `POST /confirm`, **unchanged** |

Read capabilities via `ctx.session.check_client_capability(...)`; read era via
`ctx.protocol_version`.

### 9.2 Why our existing token is already a spec-conformant `requestState`

The spec requires `requestState` be treated as attacker-controlled and, where it influences
authorization, be integrity-protected — and SHOULD carry the authenticated principal, a short
expiry, and an identifier for the originating request.

Our token carries exactly that: HMAC-SHA256 integrity, `sub` (principal), `exp` (120s default),
and `tool` + `params_hash` (request identity). The spec further warns that these measures bound the
replay window but do not guarantee single use — which `SQLiteJtiStore.mark_used()` supplies via a
primary-key conflict.

The fit is genuine, not forced. `request_state` = the existing wire token, unchanged.

### 9.3 The critical retry check

On retry, read `params.input_responses["confirm"]` and `params.request_state`, then:

1. Verify the HMAC.
2. **Recompute `params_hash` from the retried arguments and compare.** Without this, a client could
   obtain approval for a benign policy push and execute a different one. This is the single most
   important check in the phase.
3. Verify `jti` unused; mark used.
4. `action != "accept"` → `CallToolResult(is_error=True, "confirmation declined")`.
5. Verification failure → `-32602`, **audit-logged** (attacker-controlled input).

### 9.4 What this actually buys

The first genuine human-in-the-loop. Today the model itself POSTs `/confirm` with the same bearer
token (§2.5), so the current gate proves an authenticated round-trip, not human intent. Form-mode
elicitation puts the decision in front of a person via the client's UI.

### 9.5 URL mode stays opt-in

URL mode obligates the spec's **mandatory** anti-phishing check: the server MUST verify that the
human who opens the URL is the same principal for whom the elicitation was generated (the
Alice-tricks-Bob account-takeover scenario). That needs a browser session mechanism — compare the
`sub` from the session cookie against the `sub` in the token.

**Refuse to enable URL mode without that mechanism** rather than shipping it half-done.

---

## 10. P5 — Tasks extension

> **Accepted risk, explicitly.** The extension is `draft`-only (the `modelcontextprotocol/ext-tasks`
> repo contains only `schema/draft`, no versioned release), has **no Python SDK support**, and has
> **no confirmed client support**. There is no `mcp-ext-tasks` package on PyPI (404). Correctness
> rests entirely on our own tests. This was accepted deliberately after the cost was corrected.

### 10.1 Do not reuse `mcp_types`' task types

`mcp_types` 2.0.0 ships task-shaped types, but they are the **superseded 2025-11-25 experimental
core-tasks** design retained for backwards compatibility:

| `mcp_types` ships | `2026-07-28` extension requires |
|---|---|
| `tasks/get`, `tasks/result`, `tasks/list`, `tasks/cancel` | `tasks/get`, `tasks/update`, `tasks/cancel` |
| `GetTaskPayloadRequest` (`tasks/result`) | removed — poll `tasks/get` |
| `ListTasksRequest` (`tasks/list`) | removed |
| `notifications/tasks/status` | `notifications/tasks` |
| `CreateTaskResult(meta, task)` — nested | `Result & Task` — **flat**, `resultType: "task"` |
| `Task(… ttl, poll_interval)` | `Task(… ttlMs, pollIntervalMs)` |
| — | **`tasks/update`: absent entirely** |

`tasks/update` is the defining method of the redesigned extension. Its absence is the tell. **Port
our own types from the pinned `ext-tasks` draft schema** (374 lines of TypeScript).

### 10.2 Layout

```
src/illumio_mcp/tasks/types.py   Pydantic ports; camelCase aliases (taskId, ttlMs, pollIntervalMs,
                                 createdAt, lastUpdatedAt, statusMessage, inputRequests)
src/illumio_mcp/tasks/store.py   SQLite, principal-scoped
src/illumio_mcp/tasks/runner.py  background worker owned by the app lifespan
src/illumio_mcp/tasks/rpc.py     add_request_handler for tasks/get, tasks/update, tasks/cancel
```

**Pin the `ext-tasks` commit SHA we ported from** in `types.py`, so schema drift is detectable.

### 10.3 Types to port

`TaskStatus` = `working` | `input_required` | `completed` | `failed` | `cancelled`
(last three terminal).

`Task` = `taskId`, `status`, `statusMessage?`, `createdAt`, `lastUpdatedAt`,
`ttlMs` (nullable = unlimited), `pollIntervalMs?`.

`DetailedTask` variants inline status-specific fields: `InputRequiredTask.inputRequests`,
`CompletedTask.result`, `FailedTask.error`.

`CreateTaskResult` = `Result & Task`, flat, `resultType: "task"`.
`GetTaskResult` = `Result & DetailedTask`.
`UpdateTaskRequest.params` = `{taskId, inputResponses}`; result is an empty ack.
`CancelTaskRequest.params` = `{taskId}`; result is an empty ack; cancellation is **cooperative**.

### 10.4 Store

Schema: `tasks(task_id PK, principal, method, tool_name, status, status_message, created_at,
last_updated_at, ttl_ms, poll_interval_ms, result_json, error_json, input_requests_json)`.

Sits beside the existing jti / audit / keystore SQLite DBs — consistent with established practice.

**Principal-scoped: every read and write filters on `sub`**, so a task ID is a name, not a bearer
token across users. This mirrors the spec's guidance on stateful handles.

### 10.5 Capability negotiation

Advertise `extensions={"io.modelcontextprotocol/tasks": {}}`.

Return `CreateTaskResult` **only** when the request's
`_meta.io.modelcontextprotocol/clientCapabilities.extensions` contains the extension. The spec is
explicit: never hand a task to a client that did not declare support. Otherwise run synchronously,
exactly as today.

### 10.6 Which tools, and where

`ToolSpec.long_running: bool` marks four:

| Tool | Why |
|---|---|
| `get-traffic-flows` | blocks on `pce.get_traffic_flows_async` (a polled PCE job) |
| `get-traffic-flows-summary` | same |
| `find-unmanaged-traffic` | same |
| `ringfence-batch` | loops over apps (`tools/ringfence.py:544`) |

**HTTP only.** On stdio a task is pointless — one process, no reconnect, nothing to resume. Do not
advertise the capability on stdio.

All tool handlers are currently sync, dispatched via `asyncio.to_thread`
(`server.py:3384`). A task must outlive its request, so the worker is owned by the app lifespan
(`transport/http.py:102-107` already has one).

### 10.7 P4 × P5 interaction

`ringfence-batch` is **both** `requires_confirm` and `long_running`. **Confirm must complete before
the task is created**, or unapproved work gets durably queued. Order: role gate → PCE gate →
confirm gate → task creation.

### 10.8 Honest scope note for the docs

Tasks fixes **duration**, not **size**. `MCP_BUG_MAX_RESULTS = 500` and
`MCP_MAX_RESPONSE_BYTES = 800_000` are unaffected. State this plainly so nobody expects the row cap
to lift.

---

## 11. Error handling summary

| Case | Result |
|---|---|
| Unknown tool | `-32602` |
| Input fails schema validation | `is_error=True` + message (model self-corrects) |
| Authz denial | `is_error=True` + JSON reason |
| Confirm declined / cancelled | `is_error=True` |
| `requestState` verification failure | `-32602`, **audit-logged** |
| `params_hash` mismatch on retry | `-32602`, **audit-logged** |
| Task execution failure | `FailedTask.error` |
| Internal error | `is_error=True` (not success-shaped JSON as today) |

---

## 12. Testing

### 12.1 The dual-era matrix is the whole safety net

Every protocol test runs under **both** `Client(mode="legacy")` and `mode="auto"` (which negotiates
`2026-07-28`).

Because no client demonstrably speaks `2026-07-28` (§1.2), our own tests are the *only* thing
exercising the modern path. This matrix is not optional.

Note the §3.8 gotcha: an in-process client defaults to `mode='auto'`, so a test that means to
exercise the legacy path must say so explicitly.

### 12.2 Conformance

- `server/discover` returns supported versions, capabilities, `serverInfo`.
- Every cacheable result carries `ttlMs` and `cacheScope`.
- Every result carries `resultType`.
- Header/body mismatch → `-32020`.
- Unsupported version → `-32022`.
- Missing required `_meta` → `-32602` / HTTP 400.

### 12.3 MRTR

Form-mode round trip; tampered `requestState` rejected; **`params_hash` mismatch rejected (approve A,
execute B)**; replay rejected; declined and cancelled handled; legacy fallback still uses
`POST /confirm`.

### 12.4 Tasks

create → poll → complete; `input_required` → `tasks/update` → resume; cancel; TTL expiry;
**cross-principal task access denied**; capability not declared → synchronous result; stdio does not
advertise the capability.

### 12.5 Structural fix

`conftest.py` requires a **live PCE** for the whole suite. Protocol conformance tests must not.
Give them their own fixtures so CI can run them without a PCE.

---

## 13. Verification checklist (run before implementing)

Everything in §3 was verified on 2026-07-30 against `mcp` 2.0.0. Re-verify:

1. `mcp` latest version; is 2.x still current, or is there a 3.x?
2. `SUPPORTED_PROTOCOL_VERSIONS` — still five? `2026-07-28` still `LATEST`?
3. `Server.__init__` `on_*` kwargs — still 15, same names?
4. `on_call_tool` still typed `CallToolResult | InputRequiredResult`?
5. `ServerRequestContext` still exposes `request`, `meta`, `protocol_version`?
6. Does `StreamableHTTPSessionManager` populate `ctx.request`? (§6 gate)
7. `CacheHint` signature and `CACHEABLE_METHODS` membership.
8. **Does the SDK now implement `io.modelcontextprotocol/tasks`?** If yes, §10 shrinks
   dramatically — check for `on_tasks_*` kwargs and for `tasks/update` in `mcp_types.methods`.
9. Has `ext-tasks` cut a versioned (non-draft) release?
10. **Do any of our clients speak `2026-07-28` yet?** (§1.3 trigger 1)
11. `httpx2` TLS against the PCE from inside the container image.

---

## 14. Risks

| Risk | Mitigation |
|---|---|
| No client speaks `2026-07-28`; modern path untested by real traffic | Dual-era matrix (§12.1). Primary reason this work is deferred |
| Tasks extension is `draft`, unsupported by SDK and clients | Pinned schema SHA; accepted deliberately |
| Lost input validation slips through unnoticed | §5.4 is a named deliverable, not a side effect |
| `httpx2` OS trust store vs `certifi` breaks container TLS | §13.11 |
| `server.py` split churns git history over ~2900 lines | Move content verbatim in its own commit, separate from behaviour changes, so review is a diff of moves |
| Authz denial shape change breaks a consumer | Keep the JSON body identical; only `is_error` flips |
| 4 MiB request body cap | Confirm against largest tool payload |

---

## 15. Decisions taken (for the record)

| Decision | Choice | Rationale |
|---|---|---|
| Scope | Full modernization | §4 |
| API target | Low-level `Server` now; `MCPServer` a separate later project | Keeps the dispatcher, `ToolSpec` authz, and `ToolContext` intact; avoids rewriting 46 tool registrations |
| Confirm rendering | Form mode default, URL mode opt-in, legacy path preserved | §9.1, §9.5 |
| Tasks | Hand-build the extension, all four tools | Cost corrected mid-discussion (§10 banner); reaffirmed |
| `tools/list` filtering | Do **not** filter by role | Preserves `cacheScope: public` (§7.1) |
| Authz denials | `is_error=True`, same JSON body | §8.3 |
| Timing | **Deferred** — no client consumes it | §1.2 |
