# Phase 1: ToolContext Refactor — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Refactor every tool handler to take a `ToolContext` parameter and replace the process-global PCE singleton with a per-call PCE client built from explicit credentials. Stdio behavior is preserved exactly. No HTTP transport, no auth — those are Phase 2 and Phase 3. This phase is the foundation that makes them possible.

**Architecture:** Three new modules (`context.py`, `registry.py`, refactored `pce.py`); 45 handlers across 12 files take a new `ctx` first argument and read PCE from it; `tools/__init__.py` becomes a typed registry of `ToolSpec` carrying role/mutating metadata; `server.py` builds a stdio `ToolContext` once per process and passes it on every call.

**Tech Stack:** Python 3.12+, MCP Python SDK ≥ 1.2, `python-illumio`, `pytest` + `pytest-asyncio`. No new runtime dependencies.

**Spec:** [`docs/superpowers/specs/2026-05-12-http-transport-and-auth-design.md`](../specs/2026-05-12-http-transport-and-auth-design.md) §6 (Code restructuring) and §9 Phase 1.

**Branch:** Work on a new branch `feature/tool-context-refactor` off `main`.

---

## Working agreement

- Existing integration tests in `tests/test_mcp_tools.py` **must keep passing unchanged** at every commit. They are the regression net.
- Each handler conversion is mechanical: signature gets `ctx` as first arg, body swaps `pce = get_pce()` → `pce = ctx.pce`. **Nothing else changes.** No "while we're here" cleanups.
- One commit per task. Conventional-commit style (`refactor:`, `feat:`, `test:`).
- After each task, run the test specified in the task's "Verify" step. If it fails, stop and diagnose — don't move on.

---

## Task 0: Create the working branch

**Files:**
- Modify: git only

- [ ] **Step 1: Branch off main**

```bash
git checkout main
git pull --ff-only
git checkout -b feature/tool-context-refactor
```

- [ ] **Step 2: Verify clean baseline**

Run: `git status`
Expected: `On branch feature/tool-context-refactor`, no staged or unstaged changes.

Run (sanity check that the test suite runs at all):
```bash
.venv/bin/python3 -m pytest tests/ --collect-only -q 2>&1 | tail -5
```
Expected: collects ~50+ tests, no errors.

---

## Task 1: Add `ToolContext` dataclass

`ToolContext` is the object every handler will receive. In Phase 1 it carries only what stdio needs: a PCE client and a mode flag. Phase 3 will extend it (user_sub, role, scopes, request_id) — design the dataclass so adding fields doesn't break anything.

**Files:**
- Create: `src/illumio_mcp/context.py`
- Create: `tests/test_context.py`

- [ ] **Step 1: Write the failing test**

Create `tests/test_context.py`:

```python
"""Tests for ToolContext dataclass."""
import pytest
from illumio_mcp.context import ToolContext


def test_tool_context_holds_pce_and_mode():
    sentinel_pce = object()
    ctx = ToolContext(pce=sentinel_pce, is_stdio=True)
    assert ctx.pce is sentinel_pce
    assert ctx.is_stdio is True


def test_tool_context_is_stdio_required():
    """is_stdio is required; we never want an ambiguous context."""
    with pytest.raises(TypeError):
        ToolContext(pce=object())  # missing is_stdio


def test_tool_context_can_be_extended_with_kwargs():
    """Future fields (user_sub, role, etc.) can be added as kwargs without
    breaking call sites that build a stdio context."""
    ctx = ToolContext(pce=object(), is_stdio=True)
    # If/when we add fields with defaults, existing callers must keep working.
    assert ctx.is_stdio is True
```

- [ ] **Step 2: Run test to verify it fails**

Run: `.venv/bin/python3 -m pytest tests/test_context.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'illumio_mcp.context'`

- [ ] **Step 3: Implement `context.py`**

Create `src/illumio_mcp/context.py`:

```python
"""ToolContext: the per-call object every tool handler receives.

In Phase 1 (this refactor) it carries only the PCE client and a flag indicating
whether we're running under stdio (the default today). Phases 2 and 3 will add
user identity, role, scope, and request-id fields. Existing call sites should
not break when those are added — they all have defaults.
"""
from dataclasses import dataclass


@dataclass
class ToolContext:
    """Everything a tool handler needs that is *not* the tool's own arguments.

    Build one per request (HTTP) or once at startup (stdio) and pass it to
    every handler. Handlers MUST read PCE from `ctx.pce` and never call
    process-global PCE accessors.
    """
    pce: object  # illumio.PolicyComputeEngine, but kept untyped to avoid import here
    is_stdio: bool
```

Note: we leave `pce` typed as `object` to avoid an `illumio` import inside `context.py` — the module stays cheap to import in tests and never pulls in HTTP/network deps.

- [ ] **Step 4: Run test to verify it passes**

Run: `.venv/bin/python3 -m pytest tests/test_context.py -v`
Expected: 3 PASSED.

- [ ] **Step 5: Commit**

```bash
git add src/illumio_mcp/context.py tests/test_context.py
git commit -m "feat: add ToolContext dataclass for per-call handler state"
```

---

## Task 2: Add `ToolSpec` registry

`ToolSpec` carries the metadata that Phase 3 authz needs: role allowlist, mutating flag, requires-confirm flag, unscopable flag. Phase 1 just stores it; nothing reads it yet except a CI test (Task 17) that asserts every tool has explicit metadata.

**Files:**
- Create: `src/illumio_mcp/registry.py`
- Create: `tests/test_registry.py`

- [ ] **Step 1: Write the failing test**

Create `tests/test_registry.py`:

```python
"""Tests for ToolSpec and role constants."""
import pytest
from illumio_mcp.registry import (
    ToolSpec, Role, READER, OPERATOR, ADMIN, ALL_ROLES,
)


def _h(ctx, arguments):
    return []


def test_role_constants_are_distinct_strings():
    assert {READER, OPERATOR, ADMIN} == {"reader", "operator", "admin"}


def test_all_roles_contains_three():
    assert ALL_ROLES == {READER, OPERATOR, ADMIN}


def test_toolspec_requires_non_empty_roles():
    """Default-deny: a tool with no roles is a configuration error."""
    with pytest.raises(ValueError, match="at least one role"):
        ToolSpec(handler=_h, roles=set())


def test_toolspec_rejects_unknown_role():
    with pytest.raises(ValueError, match="unknown role"):
        ToolSpec(handler=_h, roles={"superuser"})  # type: ignore[arg-type]


def test_toolspec_defaults():
    spec = ToolSpec(handler=_h, roles={ADMIN})
    assert spec.mutating is False
    assert spec.requires_confirm is False
    assert spec.unscopable is False


def test_toolspec_requires_confirm_implies_mutating():
    """requires_confirm only makes sense for mutating tools; we enforce it
    so a typo can't silently expose a confirm-required-but-not-mutating tool."""
    with pytest.raises(ValueError, match="mutating"):
        ToolSpec(handler=_h, roles={ADMIN}, requires_confirm=True)
```

- [ ] **Step 2: Run test to verify it fails**

Run: `.venv/bin/python3 -m pytest tests/test_registry.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'illumio_mcp.registry'`

- [ ] **Step 3: Implement `registry.py`**

Create `src/illumio_mcp/registry.py`:

```python
"""ToolSpec: per-tool metadata used by the dispatcher and Phase 3 authz.

In Phase 1 this metadata is recorded but only one consumer reads it (a CI test
that asserts every tool has explicit role assignment). Phase 3 authz middleware
will read `roles`, `mutating`, `requires_confirm`, and `unscopable` to decide
whether to allow a call.
"""
from dataclasses import dataclass, field
from typing import Callable, Literal

Role = Literal["reader", "operator", "admin"]
READER: Role = "reader"
OPERATOR: Role = "operator"
ADMIN: Role = "admin"
ALL_ROLES: frozenset[Role] = frozenset({READER, OPERATOR, ADMIN})

_VALID_ROLES = ALL_ROLES


@dataclass(frozen=True)
class ToolSpec:
    """Metadata for one MCP tool.

    Attributes:
        handler: The handler callable. Signature: (ctx, arguments) -> list.
        roles: Set of roles permitted to call this tool. Must be non-empty.
        mutating: True if the tool changes PCE state (create/update/delete/provision).
        requires_confirm: True if a step-up confirm token is required (Phase 3).
            Implies mutating=True.
        unscopable: True if the tool returns PCE-wide data that cannot be safely
            filtered to a user's allowed label scopes (Phase 3).
    """
    handler: Callable
    roles: frozenset[Role] | set[Role]
    mutating: bool = False
    requires_confirm: bool = False
    unscopable: bool = False

    def __post_init__(self):
        if not self.roles:
            raise ValueError("ToolSpec must have at least one role (default-deny)")
        unknown = set(self.roles) - _VALID_ROLES
        if unknown:
            raise ValueError(f"ToolSpec has unknown role(s): {sorted(unknown)}")
        if self.requires_confirm and not self.mutating:
            raise ValueError("requires_confirm is only valid for mutating tools")
        # Freeze the role set so it can't be mutated post-construction
        object.__setattr__(self, "roles", frozenset(self.roles))
```

- [ ] **Step 4: Run test to verify it passes**

Run: `.venv/bin/python3 -m pytest tests/test_registry.py -v`
Expected: 6 PASSED.

- [ ] **Step 5: Commit**

```bash
git add src/illumio_mcp/registry.py tests/test_registry.py
git commit -m "feat: add ToolSpec registry with default-deny role validation"
```

---

## Task 3: Refactor `pce.py` — add `build_pce_for`, keep `get_pce` shim

The current `pce.py` has a process-global `_pce_instance` built from env vars. We add a pure builder function `build_pce_for(creds)` that returns a fresh `PolicyComputeEngine` from explicit credentials. `get_pce()` becomes a backward-compat shim that uses the builder with env-loaded creds — so every existing call site keeps working until Task 16 wires the new path through.

**Files:**
- Modify: `src/illumio_mcp/pce.py`
- Create: `tests/test_pce_builder.py`

- [ ] **Step 1: Write the failing test**

Create `tests/test_pce_builder.py`:

```python
"""Tests for the PCE builder (per-credentials construction).

The builder must NOT cache. Each call returns a fresh client. This is what
makes per-user PCE clients possible in Phase 3.
"""
from illumio_mcp.pce import (
    PCECredentials, build_pce_for, get_pce_from_env, get_pce,
)


def test_build_pce_for_returns_fresh_instance_each_call():
    creds = PCECredentials(
        host="https://example.test",
        port=8443,
        org_id=1,
        api_key="api_key_123",
        api_secret="secret_abc",
        tls_verify=False,
    )
    a = build_pce_for(creds)
    b = build_pce_for(creds)
    assert a is not b


def test_build_pce_for_sets_credentials_and_tls_verify():
    creds = PCECredentials(
        host="https://example.test",
        port=8443,
        org_id=1,
        api_key="api_key_123",
        api_secret="secret_abc",
        tls_verify=False,
    )
    pce = build_pce_for(creds)
    assert pce._session.verify is False


def test_get_pce_from_env_caches_singleton(monkeypatch):
    """Stdio mode keeps a process-wide singleton — that's the existing
    behavior we must preserve."""
    monkeypatch.setenv("PCE_HOST", "https://example.test")
    monkeypatch.setenv("PCE_PORT", "8443")
    monkeypatch.setenv("PCE_ORG_ID", "1")
    monkeypatch.setenv("API_KEY", "k")
    monkeypatch.setenv("API_SECRET", "s")
    # Reset the singleton in case a previous test populated it
    import illumio_mcp.pce as pce_mod
    pce_mod._stdio_singleton = None

    a = get_pce_from_env()
    b = get_pce_from_env()
    assert a is b


def test_get_pce_is_alias_for_env_singleton(monkeypatch):
    """Existing call sites use get_pce(); it must keep returning the singleton
    so handlers continue to work until Task 16 swaps the dispatch path."""
    monkeypatch.setenv("PCE_HOST", "https://example.test")
    monkeypatch.setenv("PCE_PORT", "8443")
    monkeypatch.setenv("PCE_ORG_ID", "1")
    monkeypatch.setenv("API_KEY", "k")
    monkeypatch.setenv("API_SECRET", "s")
    import illumio_mcp.pce as pce_mod
    pce_mod._stdio_singleton = None

    a = get_pce()
    b = get_pce_from_env()
    assert a is b
```

- [ ] **Step 2: Run test to verify it fails**

Run: `.venv/bin/python3 -m pytest tests/test_pce_builder.py -v`
Expected: FAIL with `ImportError: cannot import name 'PCECredentials'` (or similar).

- [ ] **Step 3: Replace `src/illumio_mcp/pce.py`**

Replace the file contents with:

```python
"""PCE client construction.

Two entry points:

- `build_pce_for(creds)` — pure builder. Returns a fresh PolicyComputeEngine
  for the given credentials. This is what HTTP/per-user mode (Phase 3) uses.
- `get_pce_from_env()` — process-wide singleton built from env vars. This is
  what stdio mode uses. `get_pce()` is kept as an alias for back-compat with
  handlers that haven't been migrated yet (they will be in Tasks 4–14).

PCE_ORG_ID and `run_sync` are re-exported from this module to preserve the
existing import surface used by tools/infra.py, tools/containers.py, and
tools/traffic.py.
"""
import asyncio
import os
import urllib3
from dataclasses import dataclass
from typing import Optional

from illumio import PolicyComputeEngine

# Module-level env reads kept for back-compat with tools/infra.py and
# tools/containers.py which import PCE_ORG_ID directly.
PCE_HOST = os.getenv("PCE_HOST")
PCE_PORT = os.getenv("PCE_PORT")
PCE_ORG_ID = os.getenv("PCE_ORG_ID")
API_KEY = os.getenv("API_KEY")
API_SECRET = os.getenv("API_SECRET")
PCE_TLS_VERIFY = os.getenv("PCE_TLS_VERIFY", "true").lower() not in ("false", "0", "no")

if not PCE_TLS_VERIFY:
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


@dataclass(frozen=True)
class PCECredentials:
    host: str
    port: int
    org_id: int
    api_key: str
    api_secret: str
    tls_verify: bool = True


def build_pce_for(creds: PCECredentials) -> PolicyComputeEngine:
    """Construct a fresh PolicyComputeEngine. Does NOT cache.

    Each call returns a new client. This is required for per-user PCE access
    in Phase 3 — the same process talks to PCE as multiple users concurrently.
    """
    pce = PolicyComputeEngine(creds.host, port=creds.port, org_id=creds.org_id)
    pce.set_credentials(creds.api_key, creds.api_secret)
    pce._session.verify = creds.tls_verify
    return pce


_stdio_singleton: Optional[PolicyComputeEngine] = None


def get_pce_from_env() -> PolicyComputeEngine:
    """Return a process-wide PCE client built from PCE_* env vars.

    Used by stdio mode. Cached so we reuse the underlying HTTP session.
    """
    global _stdio_singleton
    if _stdio_singleton is None:
        creds = PCECredentials(
            host=os.getenv("PCE_HOST"),
            port=int(os.getenv("PCE_PORT")) if os.getenv("PCE_PORT") else None,
            org_id=int(os.getenv("PCE_ORG_ID")) if os.getenv("PCE_ORG_ID") else None,
            api_key=os.getenv("API_KEY"),
            api_secret=os.getenv("API_SECRET"),
            tls_verify=PCE_TLS_VERIFY,
        )
        _stdio_singleton = build_pce_for(creds)
    return _stdio_singleton


# Back-compat alias. Existing handler code calls `get_pce()`. Once Tasks 4–14
# convert handlers to read from `ctx.pce`, this alias is no longer used by
# handlers but is kept so any external callers (e.g. tests, scripts) keep
# working. Removing it can be a follow-up cleanup.
def get_pce() -> PolicyComputeEngine:
    return get_pce_from_env()


async def run_sync(func, *args, **kwargs):
    """Run a synchronous function in a thread pool to avoid blocking the event loop."""
    if kwargs:
        return await asyncio.to_thread(lambda: func(*args, **kwargs))
    return await asyncio.to_thread(func, *args)
```

- [ ] **Step 4: Run new tests to verify pass**

Run: `.venv/bin/python3 -m pytest tests/test_pce_builder.py -v`
Expected: 4 PASSED.

- [ ] **Step 5: Run existing integration tests as a regression net**

Run: `.venv/bin/python3 -m pytest tests/test_mcp_tools.py::TestConnection::test_check_pce_connection -v`
Expected: PASS. (One test is enough — we're confirming the back-compat shim works end-to-end against PCE.)

- [ ] **Step 6: Commit**

```bash
git add src/illumio_mcp/pce.py tests/test_pce_builder.py
git commit -m "refactor(pce): split PCE construction into builder + env singleton"
```

---

## Tasks 4–14: Convert all handlers to `(ctx, arguments)`

Each task converts one tool file. The change in every handler is identical:

1. **Signature.** `def handle_X(arguments: dict) -> list:` → `def handle_X(ctx, arguments: dict) -> list:`
2. **PCE access.** `pce = get_pce()` → `pce = ctx.pce`
3. **Imports.** Remove `from ..pce import get_pce` (keep other pce imports like `PCE_ORG_ID` and `run_sync` if the file uses them).

Nothing else in any handler changes. Do not refactor logic, error messages, or types. Each task is one commit per file.

After Task 14, `tests/test_mcp_tools.py` will not yet pass — `server.py` still calls handlers with the old signature. We fix that in Task 16. Between Task 4 and Task 16 the integration tests are knowingly broken.

For each file, the conversion follows this template (uses `labels.py` as the example).

### Task 4: `tools/labels.py`

**Files:**
- Modify: `src/illumio_mcp/tools/labels.py`

- [ ] **Step 1: Edit imports**

Find:
```python
from ..pce import get_pce
```
Replace with: (delete the line — no longer needed)

- [ ] **Step 2: Edit `handle_get_labels` (line 10)**

Change signature:
```python
def handle_get_labels(arguments: dict) -> list:
```
to:
```python
def handle_get_labels(ctx, arguments: dict) -> list:
```

Change body:
```python
        pce = get_pce()
```
to:
```python
        pce = ctx.pce
```

- [ ] **Step 3: Repeat Step 2 for the remaining handlers in this file**

Apply the exact same two edits to:
- `handle_create_label` (line 42)
- `handle_update_label` (line 62)
- `handle_delete_label` (line 130)

Verify with: `grep -n "get_pce\(\)" src/illumio_mcp/tools/labels.py`
Expected: no output (zero matches).

Verify with: `grep -nE "^def handle_" src/illumio_mcp/tools/labels.py`
Expected: every line shows `(ctx, arguments: dict)`.

- [ ] **Step 4: Verify the file imports cleanly**

Run: `.venv/bin/python3 -c "from illumio_mcp.tools import labels; print('ok')"`
Expected: `ok`

- [ ] **Step 5: Commit**

```bash
git add src/illumio_mcp/tools/labels.py
git commit -m "refactor(tools): labels handlers take ToolContext"
```

### Task 5: `tools/workloads.py`

Apply the same template. Handlers to convert:
- `handle_get_workloads` (line 156)
- `handle_create_workload` (line 194)
- `handle_update_workload` (line 247)
- `handle_delete_workload` (line 310)

Removable import: `from ..pce import get_pce` (line 6).

- [ ] **Step 1: Apply edits per the template above to all four handlers and remove the import**
- [ ] **Step 2: Verify**

Run: `grep -n "get_pce\(\)" src/illumio_mcp/tools/workloads.py`
Expected: no output.

Run: `.venv/bin/python3 -c "from illumio_mcp.tools import workloads; print('ok')"`
Expected: `ok`.

- [ ] **Step 3: Commit**

```bash
git add src/illumio_mcp/tools/workloads.py
git commit -m "refactor(tools): workloads handlers take ToolContext"
```

### Task 6: `tools/services.py`

Handlers: `handle_get_services` (9), `handle_create_service` (103), `handle_update_service` (128), `handle_delete_service` (173).
Removable import: `from ..pce import get_pce` (line 4).

- [ ] **Step 1: Apply edits**
- [ ] **Step 2: Verify** (`grep -n "get_pce\(\)" src/illumio_mcp/tools/services.py` returns nothing; module imports cleanly)
- [ ] **Step 3: Commit**

```bash
git add src/illumio_mcp/tools/services.py
git commit -m "refactor(tools): services handlers take ToolContext"
```

### Task 7: `tools/iplists.py`

Handlers: `handle_get_iplists` (9), `handle_create_iplist` (44), `handle_update_iplist` (132), `handle_delete_iplist` (233).
Removable import: `from ..pce import get_pce` (line 4).

- [ ] **Step 1: Apply edits**
- [ ] **Step 2: Verify**
- [ ] **Step 3: Commit**

```bash
git add src/illumio_mcp/tools/iplists.py
git commit -m "refactor(tools): iplists handlers take ToolContext"
```

### Task 8: `tools/rulesets.py`

Handlers: `handle_get_rulesets` (10), `handle_create_ruleset` (89), `handle_update_ruleset` (330), `handle_delete_ruleset` (446), `handle_provision_policy` (500).
Removable import: `from ..pce import get_pce` (line 5).

- [ ] **Step 1: Apply edits to all five handlers**
- [ ] **Step 2: Verify**
- [ ] **Step 3: Commit**

```bash
git add src/illumio_mcp/tools/rulesets.py
git commit -m "refactor(tools): rulesets handlers take ToolContext"
```

### Task 9: `tools/deny_rules.py`

Handlers: `handle_create_deny_rule` (9), `handle_update_deny_rule` (153), `handle_delete_deny_rule` (230).
Removable import: `from ..pce import get_pce` (line 4).

- [ ] **Step 1: Apply edits**
- [ ] **Step 2: Verify**
- [ ] **Step 3: Commit**

```bash
git add src/illumio_mcp/tools/deny_rules.py
git commit -m "refactor(tools): deny_rules handlers take ToolContext"
```

### Task 10: `tools/traffic.py`

This file imports both `get_pce` and `run_sync`. Keep `run_sync`, remove `get_pce`.

Handlers: `handle_get_traffic_flows` (205), `handle_get_traffic_flows_summary` (302), `handle_find_unmanaged_traffic` (380).

There is also one **module-level** helper `to_dataframe(flows)` at line 57 that calls `pce = get_pce()` internally (line 58). It is called from all three handlers (lines 267, 353, 406), so we have to thread the PCE through — change the helper's signature to `to_dataframe(pce, flows)` and update every call site.

- [ ] **Step 1: Convert `to_dataframe` to take `pce` as the first parameter**

Find at line 57:
```python
def to_dataframe(flows):
    pce = get_pce()
```
Replace with:
```python
def to_dataframe(pce, flows):
```
(Delete the now-unused `pce = get_pce()` line.)

- [ ] **Step 2: Update the three call sites in `traffic.py`**

At lines 267, 353, 406, change each:
```python
        df = to_dataframe(all_traffic)        # line 267 in handle_get_traffic_flows
        df = to_dataframe(all_traffic)        # line 353 in handle_get_traffic_flows_summary
        df = to_dataframe(flows)              # line 406 in handle_find_unmanaged_traffic
```
to:
```python
        df = to_dataframe(pce, all_traffic)   # line 267
        df = to_dataframe(pce, all_traffic)   # line 353
        df = to_dataframe(pce, flows)         # line 406
```

(`pce` is already in scope inside each handler — it's the local `pce = ctx.pce` you'll add in Step 4.)

- [ ] **Step 3: Edit imports**

Change:
```python
from ..pce import get_pce, run_sync
```
to:
```python
from ..pce import run_sync
```

- [ ] **Step 4: Apply the standard handler conversion to the three handlers**

For each of `handle_get_traffic_flows`, `handle_get_traffic_flows_summary`, `handle_find_unmanaged_traffic`: signature gets `ctx` as first arg, body's `pce = get_pce()` becomes `pce = ctx.pce`.

- [ ] **Step 5: Verify**

Run: `grep -n "get_pce" src/illumio_mcp/tools/traffic.py`
Expected: no output.

Run: `grep -n "to_dataframe(" src/illumio_mcp/tools/traffic.py`
Expected: 4 lines — one definition, three call sites — all with `(pce, ...)`.

Run: `.venv/bin/python3 -c "from illumio_mcp.tools import traffic; print('ok')"`
Expected: `ok`.

- [ ] **Step 6: Commit**

```bash
git add src/illumio_mcp/tools/traffic.py
git commit -m "refactor(tools): traffic handlers + to_dataframe take ToolContext"
```

### Task 11: `tools/policy.py`

Handlers: `handle_compliance_check` (16), `handle_enforcement_readiness` (333), `handle_get_policy_coverage_report` (519), `handle_compare_draft_active` (655), `handle_get_workload_enforcement_status` (734).
Removable import: `from ..pce import get_pce` (line 9).

- [ ] **Step 1: Apply edits to all five handlers**
- [ ] **Step 2: Verify**
- [ ] **Step 3: Commit**

```bash
git add src/illumio_mcp/tools/policy.py
git commit -m "refactor(tools): policy handlers take ToolContext"
```

### Task 12: `tools/ringfence.py`

Handlers: `handle_create_ringfence` (16), `handle_ringfence_batch` (514), `handle_identify_infrastructure_services` (593), `handle_detect_lateral_movement_paths` (855).
Removable import: `from ..pce import get_pce` (line 9).

If `handle_ringfence_batch` internally calls `handle_create_ringfence`, it must now pass `ctx` as the first argument. Inspect and update the call site.

- [ ] **Step 1: Check for internal calls between ringfence handlers**

Run: `grep -n "handle_create_ringfence\|handle_identify_infra" src/illumio_mcp/tools/ringfence.py`

If `handle_ringfence_batch` calls `handle_create_ringfence(args)`, change it to `handle_create_ringfence(ctx, args)`.

- [ ] **Step 2: Apply the standard handler conversion to all four handlers**
- [ ] **Step 3: Verify**

Run: `grep -n "get_pce\(\)" src/illumio_mcp/tools/ringfence.py`
Expected: no output.

- [ ] **Step 4: Commit**

```bash
git add src/illumio_mcp/tools/ringfence.py
git commit -m "refactor(tools): ringfence handlers take ToolContext"
```

### Task 13: `tools/containers.py`

This file imports `get_pce` and `PCE_ORG_ID`. Keep `PCE_ORG_ID`, remove `get_pce`.

Handlers: `handle_get_container_workload_profiles` (9), `handle_update_container_workload_profile` (69), `handle_get_kubernetes_workloads` (100), `handle_get_container_clusters` (146).

- [ ] **Step 1: Edit imports**

Change:
```python
from ..pce import get_pce, PCE_ORG_ID
```
to:
```python
from ..pce import PCE_ORG_ID
```

- [ ] **Step 2: Apply the standard handler conversion to all four handlers**
- [ ] **Step 3: Verify**

Run: `grep -n "get_pce\(\)" src/illumio_mcp/tools/containers.py`
Expected: no output.

- [ ] **Step 4: Commit**

```bash
git add src/illumio_mcp/tools/containers.py
git commit -m "refactor(tools): containers handlers take ToolContext"
```

### Task 14: `tools/infra.py`

This file imports `get_pce` and `PCE_ORG_ID`. Keep `PCE_ORG_ID`, remove `get_pce`.

Handlers: `handle_check_pce_connection` (9), `handle_get_events` (27), `handle_get_pairing_profiles` (80).

- [ ] **Step 1: Edit imports**

Change:
```python
from ..pce import get_pce, PCE_ORG_ID
```
to:
```python
from ..pce import PCE_ORG_ID
```

- [ ] **Step 2: Apply the standard handler conversion to all three handlers**
- [ ] **Step 3: Verify**

Run: `grep -n "get_pce\(\)" src/illumio_mcp/tools/infra.py`
Expected: no output.

- [ ] **Step 4: Final cross-file verification — no `get_pce()` calls remain in tools/**

Run: `grep -rn "get_pce()" src/illumio_mcp/tools/`
Expected: no output.

- [ ] **Step 5: Commit**

```bash
git add src/illumio_mcp/tools/infra.py
git commit -m "refactor(tools): infra handlers take ToolContext (last handler file)"
```

---

## Task 15: Convert `tools/__init__.py` to a `ToolSpec` registry

`TOOL_HANDLERS` becomes `TOOL_REGISTRY: dict[str, ToolSpec]` carrying the metadata. We also derive `TOOL_HANDLERS` from it for any external code that still references the old name.

The role/mutating/requires_confirm assignments come from spec §9 Phase 1: reads → all roles, writes → operator+admin + mutating, provision-policy and ringfence-batch → admin + mutating + requires_confirm. `compliance_check`, `enforcement_readiness`, `get_policy_coverage_report`, `compare_draft_active`, `find_unmanaged_traffic`, `detect_lateral_movement_paths`, `identify_infrastructure_services` are reads that span PCE-wide data → marked `unscopable=True`. Everything that lists/reads a single tenant's data with normal filters is scopable.

**Files:**
- Modify: `src/illumio_mcp/tools/__init__.py`

- [ ] **Step 1: Replace the file**

Replace the contents of `src/illumio_mcp/tools/__init__.py` with:

```python
"""Tool registry. Maps MCP tool names to ToolSpec (handler + authz metadata).

Add a new tool by:
  1. Implementing `def handle_X(ctx, arguments) -> list:` in the right module.
  2. Adding a ToolSpec entry below with explicit `roles=`. Default-deny: a tool
     with no roles will fail at import time.
"""
from typing import Callable

from ..registry import ToolSpec, READER, OPERATOR, ADMIN, ALL_ROLES

from .workloads import (
    handle_get_workloads,
    handle_create_workload,
    handle_update_workload,
    handle_delete_workload,
)
from .labels import (
    handle_get_labels,
    handle_create_label,
    handle_update_label,
    handle_delete_label,
)
from .services import (
    handle_get_services,
    handle_create_service,
    handle_update_service,
    handle_delete_service,
)
from .iplists import (
    handle_get_iplists,
    handle_create_iplist,
    handle_update_iplist,
    handle_delete_iplist,
)
from .rulesets import (
    handle_get_rulesets,
    handle_create_ruleset,
    handle_update_ruleset,
    handle_delete_ruleset,
    handle_provision_policy,
)
from .deny_rules import (
    handle_create_deny_rule,
    handle_update_deny_rule,
    handle_delete_deny_rule,
)
from .traffic import (
    handle_get_traffic_flows,
    handle_get_traffic_flows_summary,
    handle_find_unmanaged_traffic,
)
from .policy import (
    handle_compliance_check,
    handle_enforcement_readiness,
    handle_get_policy_coverage_report,
    handle_compare_draft_active,
    handle_get_workload_enforcement_status,
)
from .ringfence import (
    handle_create_ringfence,
    handle_ringfence_batch,
    handle_identify_infrastructure_services,
    handle_detect_lateral_movement_paths,
)
from .containers import (
    handle_get_container_clusters,
    handle_get_container_workload_profiles,
    handle_update_container_workload_profile,
    handle_get_kubernetes_workloads,
)
from .infra import (
    handle_check_pce_connection,
    handle_get_events,
    handle_get_pairing_profiles,
)


_OP_ADMIN = frozenset({OPERATOR, ADMIN})
_ADMIN_ONLY = frozenset({ADMIN})


TOOL_REGISTRY: dict[str, ToolSpec] = {
    # Workloads
    "get-workloads":              ToolSpec(handle_get_workloads,            roles=ALL_ROLES),
    "create-workload":            ToolSpec(handle_create_workload,          roles=_OP_ADMIN, mutating=True),
    "update-workload":            ToolSpec(handle_update_workload,          roles=_OP_ADMIN, mutating=True),
    "delete-workload":            ToolSpec(handle_delete_workload,          roles=_OP_ADMIN, mutating=True),
    # Labels
    "get-labels":                 ToolSpec(handle_get_labels,               roles=ALL_ROLES),
    "create-label":               ToolSpec(handle_create_label,             roles=_OP_ADMIN, mutating=True),
    "update-label":               ToolSpec(handle_update_label,             roles=_OP_ADMIN, mutating=True),
    "delete-label":               ToolSpec(handle_delete_label,             roles=_OP_ADMIN, mutating=True),
    # Services
    "get-services":               ToolSpec(handle_get_services,             roles=ALL_ROLES),
    "create-service":             ToolSpec(handle_create_service,           roles=_OP_ADMIN, mutating=True),
    "update-service":             ToolSpec(handle_update_service,           roles=_OP_ADMIN, mutating=True),
    "delete-service":             ToolSpec(handle_delete_service,           roles=_OP_ADMIN, mutating=True),
    # IP Lists
    "get-iplists":                ToolSpec(handle_get_iplists,              roles=ALL_ROLES),
    "create-iplist":              ToolSpec(handle_create_iplist,            roles=_OP_ADMIN, mutating=True),
    "update-iplist":              ToolSpec(handle_update_iplist,            roles=_OP_ADMIN, mutating=True),
    "delete-iplist":              ToolSpec(handle_delete_iplist,            roles=_OP_ADMIN, mutating=True),
    # Rulesets + provisioning
    "get-rulesets":               ToolSpec(handle_get_rulesets,             roles=ALL_ROLES),
    "create-ruleset":             ToolSpec(handle_create_ruleset,           roles=_OP_ADMIN, mutating=True),
    "update-ruleset":             ToolSpec(handle_update_ruleset,           roles=_OP_ADMIN, mutating=True),
    "delete-ruleset":             ToolSpec(handle_delete_ruleset,           roles=_OP_ADMIN, mutating=True),
    "provision-policy":           ToolSpec(handle_provision_policy,         roles=_ADMIN_ONLY, mutating=True, requires_confirm=True),
    # Deny Rules
    "create-deny-rule":           ToolSpec(handle_create_deny_rule,         roles=_OP_ADMIN, mutating=True),
    "update-deny-rule":           ToolSpec(handle_update_deny_rule,         roles=_OP_ADMIN, mutating=True),
    "delete-deny-rule":           ToolSpec(handle_delete_deny_rule,         roles=_OP_ADMIN, mutating=True),
    # Traffic
    "get-traffic-flows":          ToolSpec(handle_get_traffic_flows,        roles=ALL_ROLES),
    "get-traffic-flows-summary":  ToolSpec(handle_get_traffic_flows_summary,roles=ALL_ROLES),
    "find-unmanaged-traffic":     ToolSpec(handle_find_unmanaged_traffic,   roles=ALL_ROLES, unscopable=True),
    # Policy reports (PCE-wide; not safely scopable)
    "compliance-check":           ToolSpec(handle_compliance_check,         roles=ALL_ROLES, unscopable=True),
    "enforcement-readiness":      ToolSpec(handle_enforcement_readiness,    roles=ALL_ROLES, unscopable=True),
    "get-policy-coverage-report": ToolSpec(handle_get_policy_coverage_report,roles=ALL_ROLES, unscopable=True),
    "compare-draft-active":       ToolSpec(handle_compare_draft_active,     roles=ALL_ROLES, unscopable=True),
    "get-workload-enforcement-status": ToolSpec(handle_get_workload_enforcement_status, roles=ALL_ROLES),
    # Ringfence
    "create-ringfence":           ToolSpec(handle_create_ringfence,         roles=_OP_ADMIN, mutating=True),
    "ringfence-batch":            ToolSpec(handle_ringfence_batch,          roles=_ADMIN_ONLY, mutating=True, requires_confirm=True),
    "identify-infrastructure-services": ToolSpec(handle_identify_infrastructure_services, roles=ALL_ROLES, unscopable=True),
    "detect-lateral-movement-paths":    ToolSpec(handle_detect_lateral_movement_paths,    roles=ALL_ROLES, unscopable=True),
    # Containers
    "get-container-clusters":     ToolSpec(handle_get_container_clusters,   roles=ALL_ROLES),
    "get-container-workload-profiles": ToolSpec(handle_get_container_workload_profiles, roles=ALL_ROLES),
    "update-container-workload-profile": ToolSpec(handle_update_container_workload_profile, roles=_OP_ADMIN, mutating=True),
    "get-kubernetes-workloads":   ToolSpec(handle_get_kubernetes_workloads, roles=ALL_ROLES),
    # Infrastructure
    "check-pce-connection":       ToolSpec(handle_check_pce_connection,     roles=ALL_ROLES),
    "get-events":                 ToolSpec(handle_get_events,               roles=ALL_ROLES),
    "get-pairing-profiles":       ToolSpec(handle_get_pairing_profiles,     roles=ALL_ROLES),
}


# Back-compat: derived map of name → callable. Some external code (and the
# previous server.py) referenced TOOL_HANDLERS directly. After Task 16 this is
# no longer used internally; kept as a derived export to avoid breaking any
# downstream importers.
TOOL_HANDLERS: dict[str, Callable] = {name: spec.handler for name, spec in TOOL_REGISTRY.items()}
```

- [ ] **Step 2: Verify the registry imports cleanly and ToolSpec validation runs at import time**

Run:
```bash
.venv/bin/python3 -c "from illumio_mcp.tools import TOOL_REGISTRY, TOOL_HANDLERS; print(f'{len(TOOL_REGISTRY)} tools, {len(TOOL_HANDLERS)} handlers')"
```
Expected: `45 tools, 45 handlers`

- [ ] **Step 3: Commit**

```bash
git add src/illumio_mcp/tools/__init__.py
git commit -m "refactor(tools): TOOL_REGISTRY of ToolSpec carries authz metadata"
```

---

## Task 16: Wire `server.py` to build a stdio `ToolContext` and dispatch via the registry

This is the change that re-connects the dots: `handle_call_tool` builds a `ToolContext` once at module load (stdio uses one PCE for the process) and passes it into every handler. After this commit the existing integration tests pass again.

**Files:**
- Modify: `src/illumio_mcp/server.py`

- [ ] **Step 1: Edit imports near the top (around line 13)**

Find:
```python
from .tools import TOOL_HANDLERS
```
Replace with:
```python
from .context import ToolContext
from .pce import get_pce_from_env
from .tools import TOOL_REGISTRY
```

- [ ] **Step 2: Add a stdio context builder near the top of the module (just below the `dotenv.load_dotenv()` call)**

Insert this just after `dotenv.load_dotenv()` (around line 48):

```python
def _build_stdio_context() -> ToolContext:
    """Build the single ToolContext used for the lifetime of the stdio process.

    Stdio mode has one user (the operator who launched the process) and one PCE
    (built from PCE_* env vars). The ToolContext is created lazily on first use
    so that test setups can override env before the PCE is constructed.
    """
    return ToolContext(pce=get_pce_from_env(), is_stdio=True)


_stdio_ctx: ToolContext | None = None


def _get_stdio_context() -> ToolContext:
    global _stdio_ctx
    if _stdio_ctx is None:
        _stdio_ctx = _build_stdio_context()
    return _stdio_ctx
```

- [ ] **Step 3: Replace the body of `handle_call_tool` (around line 3122)**

Find:
```python
@server.call_tool()
async def handle_call_tool(name: str, arguments: dict) -> list[types.TextContent | types.ImageContent | types.EmbeddedResource]:
    logger.debug(f"Tool called: {name} with arguments: {arguments}")
    handler = TOOL_HANDLERS.get(name)
    if handler is None:
        raise ValueError(f"Unknown tool: {name}")
    try:
        t0 = time.monotonic()
        result = await asyncio.to_thread(handler, arguments or {})
        elapsed = time.monotonic() - t0
        logger.info(f"Tool {name} completed in {elapsed:.2f}s")
        return result
    except Exception as e:
        error_msg = f"Tool {name} failed: {str(e)}"
        logger.error(error_msg, exc_info=True)
        return [types.TextContent(type="text", text=json.dumps({"error": error_msg}, indent=2))]
```

Replace with:
```python
@server.call_tool()
async def handle_call_tool(name: str, arguments: dict) -> list[types.TextContent | types.ImageContent | types.EmbeddedResource]:
    logger.debug(f"Tool called: {name} with arguments: {arguments}")
    spec = TOOL_REGISTRY.get(name)
    if spec is None:
        raise ValueError(f"Unknown tool: {name}")
    ctx = _get_stdio_context()
    try:
        t0 = time.monotonic()
        result = await asyncio.to_thread(spec.handler, ctx, arguments or {})
        elapsed = time.monotonic() - t0
        logger.info(f"Tool {name} completed in {elapsed:.2f}s")
        return result
    except Exception as e:
        error_msg = f"Tool {name} failed: {str(e)}"
        logger.error(error_msg, exc_info=True)
        return [types.TextContent(type="text", text=json.dumps({"error": error_msg}, indent=2))]
```

- [ ] **Step 4: Verify the module imports cleanly**

Run:
```bash
.venv/bin/python3 -c "import illumio_mcp.server; print('ok')"
```
Expected: `ok`.

- [ ] **Step 5: Run the full integration suite — this is the regression net**

Run:
```bash
.venv/bin/python3 -m pytest tests/test_mcp_tools.py -v
```
Expected: all tests that passed before this branch still pass. Any newly failing test means a handler conversion was wrong — diagnose with:

```bash
.venv/bin/python3 -m pytest tests/test_mcp_tools.py::TestConnection::test_check_pce_connection -v -s
```

If a single handler is failing, the most likely cause is a missed `pce = ctx.pce` swap or a helper function still calling `get_pce()`. Use `grep -n "get_pce" src/illumio_mcp/tools/<file>.py` to locate.

- [ ] **Step 6: Commit**

```bash
git add src/illumio_mcp/server.py
git commit -m "feat(server): dispatch via TOOL_REGISTRY with ToolContext"
```

---

## Task 17: Add CI test asserting every tool has explicit metadata

Default-deny only works if we can't accidentally ship a tool without a role assignment. This test catches that at CI time.

**Files:**
- Create: `tests/test_tool_metadata.py`

- [ ] **Step 1: Write the test**

Create `tests/test_tool_metadata.py`:

```python
"""Guard tests for the TOOL_REGISTRY.

These run fast (no PCE) and exist to keep the registry self-consistent as new
tools are added. If you're tempted to skip one, write a comment in this file
explaining why instead.
"""
import inspect
import re

from illumio_mcp.tools import TOOL_REGISTRY
from illumio_mcp.registry import ToolSpec, ALL_ROLES


def test_every_tool_has_a_toolspec():
    """If this fails, someone added a handler to TOOL_HANDLERS by mistake or
    forgot to migrate to TOOL_REGISTRY."""
    for name, spec in TOOL_REGISTRY.items():
        assert isinstance(spec, ToolSpec), f"{name!r} is not a ToolSpec"


def test_every_tool_has_explicit_roles():
    for name, spec in TOOL_REGISTRY.items():
        assert spec.roles, f"{name!r} has no roles assigned (default-deny violated)"
        assert set(spec.roles).issubset(ALL_ROLES), \
            f"{name!r} has unknown roles: {spec.roles}"


def test_handlers_have_ctx_first_argument():
    """Every handler must accept (ctx, arguments). Catches missed conversions."""
    for name, spec in TOOL_REGISTRY.items():
        sig = inspect.signature(spec.handler)
        params = list(sig.parameters.keys())
        assert len(params) >= 2, f"{name!r} handler has fewer than 2 params: {params}"
        assert params[0] == "ctx", f"{name!r} handler's first param is {params[0]!r}, expected 'ctx'"


def test_destructive_tool_names_are_marked_mutating():
    """A tool whose name starts with create-/update-/delete-/provision-
    must be `mutating=True`. Catches a contributor adding e.g. delete-foo
    and forgetting the mutating flag."""
    pattern = re.compile(r"^(create|update|delete|provision)-")
    for name, spec in TOOL_REGISTRY.items():
        if pattern.match(name):
            assert spec.mutating, f"{name!r} looks destructive but mutating=False"


def test_ringfence_batch_requires_confirm():
    """ringfence-batch and provision-policy are explicit confirm-required tools
    per spec §9. If the metadata gets edited by mistake, this catches it."""
    for name in ("provision-policy", "ringfence-batch"):
        spec = TOOL_REGISTRY[name]
        assert spec.requires_confirm, f"{name!r} should require confirm token"


def test_count_matches_expected():
    """Sanity check: tool count is stable. Bump this when you intentionally
    add or remove a tool."""
    assert len(TOOL_REGISTRY) == 45, \
        f"Tool count drifted to {len(TOOL_REGISTRY)}; update this test if intentional"
```

- [ ] **Step 2: Run the test**

Run: `.venv/bin/python3 -m pytest tests/test_tool_metadata.py -v`
Expected: 6 PASSED.

If `test_count_matches_expected` fails, recount the entries in `TOOL_REGISTRY` and update both the registry (if you forgot one) or the assertion (if the count is intentionally different).

- [ ] **Step 3: Commit**

```bash
git add tests/test_tool_metadata.py
git commit -m "test: guard TOOL_REGISTRY consistency (default-deny, ctx-first, mutating)"
```

---

## Task 18: Full regression run against PCE

Final confidence check before opening a PR. The unit tests caught structural problems; this catches semantic ones.

- [ ] **Step 1: Run the full test suite**

Run:
```bash
.venv/bin/python3 -m pytest tests/ -v 2>&1 | tail -50
```
Expected: same pass/fail/skip counts as on `main` (run `.venv/bin/python3 -m pytest tests/ --collect-only -q | tail -3` on main first to know the baseline). Brand-new tests (`test_context.py`, `test_registry.py`, `test_pce_builder.py`, `test_tool_metadata.py`) all pass.

- [ ] **Step 2: If any test fails**

For each failure, the diagnosis pattern is:
1. Identify the handler being exercised (from the test name and assertion).
2. `grep -n "get_pce\|ctx.pce" src/illumio_mcp/tools/<that-file>.py` — confirm `get_pce()` is gone and `ctx.pce` is in use.
3. If the handler calls a helper, check the helper's PCE access too.

Fix in place, re-run only that test, then re-run the full suite.

- [ ] **Step 3: Confirm stdio invocation still works end-to-end with an MCP client**

Run a manual sanity check from outside the test runner:
```bash
.venv/bin/python3 -m illumio_mcp < /dev/null
```
Expected: server starts, logs `Starting server` to `illumio-mcp.log`, exits cleanly when stdin closes (after a few seconds). No tracebacks.

---

## Task 19: Open PR

- [ ] **Step 1: Push the branch**

```bash
git push -u origin feature/tool-context-refactor
```

- [ ] **Step 2: Open the PR**

```bash
gh pr create --title "refactor: ToolContext + TOOL_REGISTRY (Phase 1 of HTTP transport)" --body "$(cat <<'EOF'
## Summary

Phase 1 of the HTTP transport + multi-user auth work (see `docs/superpowers/specs/2026-05-12-http-transport-and-auth-design.md`). Pure refactor — no user-visible behavior change.

- Every tool handler now takes `(ctx, arguments)` instead of `(arguments)`.
- `pce.py` split into `build_pce_for(creds)` (per-credentials builder) and `get_pce_from_env()` (stdio singleton).
- `tools/__init__.py` is now `TOOL_REGISTRY: dict[str, ToolSpec]`, carrying role/mutating/requires-confirm metadata that Phase 3 authz will read.
- New CI guards: every tool has explicit roles; destructive-named tools must be `mutating=True`; `provision-policy` and `ringfence-batch` must require confirm tokens.

Stdio entry point is unchanged. Existing integration tests pass unchanged.

## Test plan

- [ ] `pytest tests/test_context.py tests/test_registry.py tests/test_pce_builder.py tests/test_tool_metadata.py -v` (unit tests — fast, no PCE)
- [ ] `pytest tests/test_mcp_tools.py -v` (integration tests against PCE)
- [ ] Manual: launch via `python -m illumio_mcp` from Claude Desktop, run `check-pce-connection`, `get-labels`, `get-workloads`

🤖 Generated with [Claude Code](https://claude.com/claude-code)
EOF
)"
```

- [ ] **Step 3: Print PR URL** (output of the previous `gh pr create` command)

---

## What this plan does NOT do

These are intentionally out of scope for Phase 1 and will be planned separately:

- HTTP transport (`POST /mcp`, Streamable HTTP) — **Phase 2**.
- OAuth Resource Server / JWT validation — **Phase 3**.
- Per-user PCE key storage (`KeyStore`, SQLite + envelope encryption) — **Phase 3**.
- Authz enforcement (the `roles=` metadata is recorded but no middleware reads it yet) — **Phase 3**.
- Confirm-token endpoint (`POST /confirm`) — **Phase 3**.
- Audit log table and persistence — **Phase 3**.

After Phase 1 ships, write `2026-MM-DD-phase-2-streamable-http-transport.md` next.

---

## Self-review checklist

(Performed before this plan was finalized; left here so reviewers can see what was checked.)

- [x] **Spec coverage:** Phase 1 of spec §9 maps to Tasks 1–18. The "no behavior change" promise is enforced by Task 18 running the existing integration tests.
- [x] **Placeholders:** No "TBD", "TODO", or "implement appropriate X". Every step shows the actual code or command.
- [x] **Type consistency:** `ToolContext` defined in Task 1 is the same type used in Tasks 4–14, 16, 17. `ToolSpec` defined in Task 2 is the same type used in Task 15, 17. `PCECredentials` defined in Task 3 is used in Task 3's tests.
- [x] **One concern per task:** Tasks 4–14 each touch exactly one file. Task 15 (registry) and Task 16 (server.py) are deliberately separated so a registry edit can be reviewed without conflating the server change.
- [x] **Frequent commits:** 18 commits across the plan. Each is mechanical and reviewable in isolation.
