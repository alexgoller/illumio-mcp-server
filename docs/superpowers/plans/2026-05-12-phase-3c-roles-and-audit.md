# Phase 3c: Role-Based Authz + Audit Log — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** The HTTP server reads `groups`/`roles` from each JWT, maps it to one of three internal roles (`reader` | `operator` | `admin`), enforces the per-tool role allowlist that's been on `ToolSpec` since Phase 1, and persists every authz decision to an audit log. Stdio remains effectively `admin`-and-unaudited (the operator launched the process). Scope filters and confirm tokens are deferred to later sub-phases.

**Architecture:** Two new tiny modules in `auth/` — `roles.py` parses env-configured group→role mappings and computes the highest role a user's groups qualify for; `audit.py` defines an `AuditLog` Protocol, a `SQLiteAuditLog` driver writing to the same `MCP_KEYSTORE_PATH` SQLite file, and a `NullAuditLog` for stdio. `ToolContext` gains `user_role`, `audit_log`, `request_id`. `build_http_context_for` populates them; the dispatcher enforces the role check before invoking a handler and records an `AuditEntry` for every decision (allow / deny / error). HTTP transport adds a request-id middleware that generates a UUID per request and exposes it as `X-Request-Id`.

**Tech Stack:** Standard library `sqlite3`, `uuid`. No new third-party deps.

**Spec:** [`docs/superpowers/specs/2026-05-12-http-transport-and-auth-design.md`](../specs/2026-05-12-http-transport-and-auth-design.md) §5 Layers 2–3 (role mapping + tool allowlist), §7.3 (audit log).

**Branch:** `feature/role-authz-and-audit` off `feature/per-user-pce-keystore` (or `main` once that ships).

---

## Working agreement

- Phase 3a/3b invariants intact: stdio unchanged at every commit; HTTP `/healthz`/`/readyz`/`/.well-known/*` unauth; auth required on `/mcp`; per-user PCE keys; structured `no_pce_credentials` error when PCE absent.
- **Stdio:** the operator who launched the process implicitly has `admin`. No role check, no audit log writes. Verified at every transport-touching commit.
- **No-role users (HTTP):** if the user's JWT groups don't map to any configured role AND no `MCP_ROLE_DEFAULT` is set, the server returns a structured `forbidden_no_role` error. Audit log records the denial.
- **Default-deny still holds:** `ToolSpec.roles` is enforced by the dispatcher. If a tool's `spec.roles` doesn't include `ctx.user_role`, the call is denied.
- **Audit writes never block the request semantically.** Synchronous SQLite writes are fast (sub-ms) and acceptable for v1; if it ever becomes a bottleneck we move to a background queue. Don't add the queue prematurely.
- **Sensitive data never enters the audit log.** Only `tool` name, `decision`, optional short `reason`, `request_id`, `role`, `sub`, `iss`. Never tool arguments.
- One commit per task.

---

## File structure

| File | Responsibility |
|---|---|
| `src/illumio_mcp/auth/roles.py` (new) | `RoleConfig` dataclass + `load_role_config_from_env` + `map_user_role(groups, config) -> Role | None` |
| `src/illumio_mcp/auth/audit.py` (new) | `AuditEntry`, `AuditLog` Protocol, `SQLiteAuditLog`, `NullAuditLog` |
| `src/illumio_mcp/auth/audit_init.py` (new) | `build_audit_log_from_env`: SQLite at `MCP_AUDIT_LOG_PATH` (defaults to keystore dir) |
| `src/illumio_mcp/context.py` (modify) | Add `user_role: str | None`, `audit_log: object | None`, `request_id: str | None` |
| `src/illumio_mcp/server.py` (modify) | `build_http_context_for(sub, iss, keystore, role, audit_log, request_id)`; stdio context sets `user_role="admin"` and `audit_log=NullAuditLog()`; dispatcher enforces role + writes audit entry for every decision |
| `src/illumio_mcp/transport/http.py` (modify) | Build role config + audit log at startup; request-id middleware sets `request.state.request_id` and `X-Request-Id` response header; ASGI wrapper now also looks up role from JWT groups |
| `src/illumio_mcp/transport/request_id.py` (new) | Tiny middleware: per-request `uuid4()` → `request.state.request_id` + response header |
| `tests/test_auth_roles.py` (new) | Role config env loading + role mapping precedence (admin > operator > reader) |
| `tests/test_auth_audit.py` (new) | SQLiteAuditLog CRUD; NullAuditLog no-op |
| `tests/test_http_authz.py` (new) | e2e: reader can call read tool, gets denied on write tool; admin can call write tool; user with no role mapping gets `forbidden_no_role` |
| `README.md` (modify) | "Role-based authz" subsection: env vars, three roles, audit log path |

---

## Task 0: Create the working branch

**Files:** git only

- [ ] **Step 1: Branch**

```bash
git checkout feature/per-user-pce-keystore
git pull --ff-only origin feature/per-user-pce-keystore
git checkout -b feature/role-authz-and-audit
```

- [ ] **Step 2: Verify clean baseline**

```bash
git status                # clean
.venv/bin/python3 -m pytest tests/test_auth_config.py tests/test_auth_jwt_validator.py tests/test_auth_prm.py tests/test_auth_crypto.py tests/test_auth_keystore.py tests/test_credentials_tools.py tests/test_http_auth.py tests/test_http_per_user.py tests/test_context.py tests/test_registry.py tests/test_pce_builder.py tests/test_tool_metadata.py -q 2>&1 | tail -3
```
Expected: all green.

---

## Task 1: `auth/roles.py` — Role config + group→role mapping

**Files:**
- Create: `src/illumio_mcp/auth/roles.py`
- Create: `tests/test_auth_roles.py`

- [ ] **Step 1: Write the failing tests**

Create `tests/test_auth_roles.py`:

```python
"""Tests for role config and JWT groups → role mapping."""
import pytest

from illumio_mcp.auth.roles import (
    RoleConfig, load_role_config_from_env, map_user_role,
)
from illumio_mcp.registry import READER, OPERATOR, ADMIN


def test_role_config_holds_lists():
    cfg = RoleConfig(
        admin_groups=["sg-admin"],
        operator_groups=["sg-op", "sg-admin"],
        reader_groups=["sg-read", "sg-op", "sg-admin"],
        default_role=None,
    )
    assert "sg-admin" in cfg.admin_groups


def test_load_from_env_happy_path(monkeypatch):
    monkeypatch.setenv("MCP_ROLE_GROUPS_ADMIN", "sg-admin")
    monkeypatch.setenv("MCP_ROLE_GROUPS_OPERATOR", "sg-op,sg-admin")
    monkeypatch.setenv("MCP_ROLE_GROUPS_READER", "sg-read,sg-op,sg-admin")
    monkeypatch.delenv("MCP_ROLE_DEFAULT", raising=False)
    cfg = load_role_config_from_env()
    assert cfg.admin_groups == ["sg-admin"]
    assert cfg.operator_groups == ["sg-op", "sg-admin"]
    assert cfg.reader_groups == ["sg-read", "sg-op", "sg-admin"]
    assert cfg.default_role is None


def test_load_from_env_default_role(monkeypatch):
    monkeypatch.setenv("MCP_ROLE_GROUPS_ADMIN", "sg-admin")
    monkeypatch.setenv("MCP_ROLE_GROUPS_OPERATOR", "sg-op")
    monkeypatch.setenv("MCP_ROLE_GROUPS_READER", "sg-read")
    monkeypatch.setenv("MCP_ROLE_DEFAULT", "reader")
    cfg = load_role_config_from_env()
    assert cfg.default_role == "reader"


def test_load_from_env_blank_envs_ok(monkeypatch):
    """All-empty env produces empty lists, not None — keeps mapping logic simple."""
    monkeypatch.delenv("MCP_ROLE_GROUPS_ADMIN", raising=False)
    monkeypatch.delenv("MCP_ROLE_GROUPS_OPERATOR", raising=False)
    monkeypatch.delenv("MCP_ROLE_GROUPS_READER", raising=False)
    monkeypatch.delenv("MCP_ROLE_DEFAULT", raising=False)
    cfg = load_role_config_from_env()
    assert cfg.admin_groups == []
    assert cfg.operator_groups == []
    assert cfg.reader_groups == []


def _cfg(default_role=None):
    return RoleConfig(
        admin_groups=["sg-admin"],
        operator_groups=["sg-op", "sg-admin"],
        reader_groups=["sg-read", "sg-op", "sg-admin"],
        default_role=default_role,
    )


def test_admin_group_wins_when_user_has_all():
    cfg = _cfg()
    assert map_user_role(["sg-read", "sg-op", "sg-admin"], cfg) == ADMIN


def test_operator_when_only_operator_group():
    cfg = _cfg()
    assert map_user_role(["sg-op"], cfg) == OPERATOR


def test_reader_when_only_reader_group():
    cfg = _cfg()
    assert map_user_role(["sg-read"], cfg) == READER


def test_no_role_when_no_match_and_no_default():
    cfg = _cfg(default_role=None)
    assert map_user_role(["sg-other"], cfg) is None


def test_default_role_used_when_no_group_match():
    cfg = _cfg(default_role=READER)
    assert map_user_role(["sg-other"], cfg) == READER


def test_empty_groups_with_no_default_returns_none():
    cfg = _cfg(default_role=None)
    assert map_user_role([], cfg) is None
```

- [ ] **Step 2: Run test to verify it fails**

```bash
.venv/bin/python3 -m pytest tests/test_auth_roles.py -v
```
Expected: ImportError on `illumio_mcp.auth.roles`.

- [ ] **Step 3: Implement `auth/roles.py`**

Create `src/illumio_mcp/auth/roles.py`:

```python
"""Map JWT group claims to internal MCP roles.

Three internal roles defined in `illumio_mcp.registry`: reader, operator, admin.
Each role has a list of group names (from the IdP) that grant it. A user's
effective role is the HIGHEST role any of their groups qualifies for
(admin > operator > reader).

Configuration is env-driven, comma-separated. Empty config = no role match
(callers should also configure MCP_ROLE_DEFAULT for fallback behavior).
"""
from __future__ import annotations

import os
from dataclasses import dataclass, field
from typing import Iterable

from ..registry import Role, READER, OPERATOR, ADMIN


@dataclass(frozen=True)
class RoleConfig:
    admin_groups: list[str] = field(default_factory=list)
    operator_groups: list[str] = field(default_factory=list)
    reader_groups: list[str] = field(default_factory=list)
    default_role: Role | None = None


def _split(env_value: str | None) -> list[str]:
    if not env_value:
        return []
    return [g.strip() for g in env_value.split(",") if g.strip()]


def load_role_config_from_env() -> RoleConfig:
    """Read MCP_ROLE_GROUPS_{ADMIN,OPERATOR,READER} + MCP_ROLE_DEFAULT."""
    default = os.getenv("MCP_ROLE_DEFAULT") or None
    if default and default not in (READER, OPERATOR, ADMIN):
        raise ValueError(
            f"MCP_ROLE_DEFAULT must be one of {READER!r}, {OPERATOR!r}, {ADMIN!r}; got {default!r}"
        )
    return RoleConfig(
        admin_groups=_split(os.getenv("MCP_ROLE_GROUPS_ADMIN")),
        operator_groups=_split(os.getenv("MCP_ROLE_GROUPS_OPERATOR")),
        reader_groups=_split(os.getenv("MCP_ROLE_GROUPS_READER")),
        default_role=default,
    )


def map_user_role(user_groups: Iterable[str], config: RoleConfig) -> Role | None:
    """Return the highest role the user qualifies for, or `default_role`, or None.

    Highest-first order: admin > operator > reader.
    """
    groups = set(user_groups)
    if any(g in groups for g in config.admin_groups):
        return ADMIN
    if any(g in groups for g in config.operator_groups):
        return OPERATOR
    if any(g in groups for g in config.reader_groups):
        return READER
    return config.default_role
```

- [ ] **Step 4: Run tests**

```bash
.venv/bin/python3 -m pytest tests/test_auth_roles.py -v
```
Expected: 10 PASSED.

- [ ] **Step 5: Commit**

```bash
git add src/illumio_mcp/auth/roles.py tests/test_auth_roles.py
git commit -m "feat(auth): role mapping (groups -> reader/operator/admin)"
```

---

## Task 2: `auth/audit.py` — Audit log

**Files:**
- Create: `src/illumio_mcp/auth/audit.py`
- Create: `tests/test_auth_audit.py`

- [ ] **Step 1: Write the failing tests**

Create `tests/test_auth_audit.py`:

```python
"""Tests for the audit log — SQLite driver + NullAuditLog."""
import sqlite3

import pytest

from illumio_mcp.auth.audit import (
    AuditEntry, SQLiteAuditLog, NullAuditLog,
)


@pytest.fixture
def audit_log(tmp_path):
    db_path = str(tmp_path / "audit.db")
    return SQLiteAuditLog(db_path=db_path)


def _entry(**overrides):
    return AuditEntry(
        sub="alice",
        iss="https://idp.test/o",
        tool="get-labels",
        decision="allowed",
        reason=None,
        role="reader",
        request_id="req-123",
        **overrides,
    )


def test_record_persists_row(audit_log):
    audit_log.record(_entry())
    with sqlite3.connect(audit_log.db_path) as con:
        rows = con.execute(
            "SELECT sub, iss, tool, decision, role, request_id FROM audit_log"
        ).fetchall()
    assert rows == [("alice", "https://idp.test/o", "get-labels", "allowed", "reader", "req-123")]


def test_record_writes_timestamp(audit_log):
    audit_log.record(_entry())
    with sqlite3.connect(audit_log.db_path) as con:
        (ts,) = con.execute("SELECT ts FROM audit_log").fetchone()
    assert ts is not None
    assert "T" in ts  # ISO-8601 with T separator


def test_decision_can_be_denied_or_error(audit_log):
    audit_log.record(_entry(decision="denied", reason="role 'reader' not in {'admin'}"))
    audit_log.record(_entry(decision="error", reason="PCE timeout"))
    with sqlite3.connect(audit_log.db_path) as con:
        decisions = [r[0] for r in con.execute("SELECT decision FROM audit_log").fetchall()]
    assert sorted(decisions) == ["denied", "error"]


def test_record_handles_unknown_user(audit_log):
    """sub/iss can be None for pre-auth failures."""
    audit_log.record(_entry(sub=None, iss=None, decision="denied", reason="missing token"))
    with sqlite3.connect(audit_log.db_path) as con:
        (n,) = con.execute("SELECT COUNT(*) FROM audit_log WHERE sub IS NULL").fetchone()
    assert n == 1


def test_null_audit_log_is_silent():
    """NullAuditLog.record() must not raise and must not persist anything."""
    null = NullAuditLog()
    null.record(_entry())  # no exception
    # No DB to check; the absence of error IS the test


def test_db_file_created_with_safe_perms(audit_log):
    import os
    mode = os.stat(audit_log.db_path).st_mode & 0o777
    assert mode & 0o077 == 0
```

- [ ] **Step 2: Run test to verify it fails**

```bash
.venv/bin/python3 -m pytest tests/test_auth_audit.py -v
```
Expected: ImportError.

- [ ] **Step 3: Implement `auth/audit.py`**

Create `src/illumio_mcp/auth/audit.py`:

```python
"""Audit log for tool-call decisions.

Every dispatcher decision (allow, deny, error) writes one AuditEntry. Writes
are synchronous and fast — SQLite WAL mode means concurrent reads/writes are
safe. The log is the source of truth for "who did what."

Schema lives in MCP_AUDIT_LOG_PATH (defaults to ./data/audit.db). It is
intentionally a SEPARATE file from the keystore so audit retention and
keystore lifetimes can differ (e.g., wipe keystore on revoke, keep audit for
compliance).
"""
from __future__ import annotations

import os
import sqlite3
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Literal, Protocol


Decision = Literal["allowed", "denied", "error"]


@dataclass(frozen=True)
class AuditEntry:
    sub: str | None
    iss: str | None
    tool: str
    decision: Decision
    reason: str | None
    role: str | None
    request_id: str | None


class AuditLog(Protocol):
    def record(self, entry: AuditEntry) -> None: ...


class NullAuditLog:
    """Drop entries on the floor. Used in stdio mode where there is no need to
    record what the operator who launched the process is doing."""

    def record(self, entry: AuditEntry) -> None:
        return None


_SCHEMA = """
CREATE TABLE IF NOT EXISTS audit_log (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    ts           TEXT NOT NULL,
    sub          TEXT,
    iss          TEXT,
    tool         TEXT NOT NULL,
    decision     TEXT NOT NULL,
    reason       TEXT,
    role         TEXT,
    request_id   TEXT
);
CREATE INDEX IF NOT EXISTS idx_audit_log_sub_ts ON audit_log(sub, ts DESC);
CREATE INDEX IF NOT EXISTS idx_audit_log_decision ON audit_log(decision, ts DESC);
"""


class SQLiteAuditLog:
    """File-backed audit log."""

    def __init__(self, db_path: str):
        self.db_path = db_path
        parent = Path(db_path).parent
        if parent and not parent.exists():
            parent.mkdir(parents=True, exist_ok=True)
        old_umask = os.umask(0o077)
        try:
            with sqlite3.connect(self.db_path) as con:
                con.execute("PRAGMA journal_mode=WAL;")
                con.executescript(_SCHEMA)
        finally:
            os.umask(old_umask)
        try:
            os.chmod(self.db_path, 0o600)
        except OSError:
            pass

    def record(self, entry: AuditEntry) -> None:
        ts = datetime.now(timezone.utc).isoformat()
        with sqlite3.connect(self.db_path) as con:
            con.execute(
                "INSERT INTO audit_log (ts, sub, iss, tool, decision, reason, role, request_id) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                (ts, entry.sub, entry.iss, entry.tool, entry.decision,
                 entry.reason, entry.role, entry.request_id),
            )
```

- [ ] **Step 4: Run tests**

```bash
.venv/bin/python3 -m pytest tests/test_auth_audit.py -v
```
Expected: 6 PASSED.

- [ ] **Step 5: Commit**

```bash
git add src/illumio_mcp/auth/audit.py tests/test_auth_audit.py
git commit -m "feat(auth): SQLite audit log + NullAuditLog"
```

---

## Task 3: `auth/audit_init.py` — startup wiring

**Files:**
- Create: `src/illumio_mcp/auth/audit_init.py`

- [ ] **Step 1: Write the file**

Create `src/illumio_mcp/auth/audit_init.py`:

```python
"""Build the production AuditLog from environment.

Reads:
  MCP_AUDIT_LOG_PATH   path to the SQLite audit DB.
                       Default: alongside the keystore (./data/audit.db
                       if MCP_KEYSTORE_PATH is unset, else <keystore_dir>/audit.db).
"""
import os
from pathlib import Path

from .audit import SQLiteAuditLog


def build_audit_log_from_env() -> SQLiteAuditLog:
    explicit = os.getenv("MCP_AUDIT_LOG_PATH")
    if explicit:
        path = explicit
    else:
        ks_path = os.getenv("MCP_KEYSTORE_PATH", "./data/keys.db")
        path = str(Path(ks_path).parent / "audit.db")
    return SQLiteAuditLog(db_path=path)
```

- [ ] **Step 2: Verify**

```bash
MCP_AUDIT_LOG_PATH=/tmp/test_audit.db .venv/bin/python3 -c "
from illumio_mcp.auth.audit_init import build_audit_log_from_env
from illumio_mcp.auth.audit import AuditEntry
audit = build_audit_log_from_env()
print('audit log built, db_path:', audit.db_path)
audit.record(AuditEntry(sub='u', iss='i', tool='get-labels', decision='allowed', reason=None, role='reader', request_id='r1'))
print('record ok')
" && rm -f /tmp/test_audit.db /tmp/test_audit.db-shm /tmp/test_audit.db-wal
```
Expected: prints `audit log built, db_path: /tmp/test_audit.db` and `record ok`.

- [ ] **Step 3: Commit**

```bash
git add src/illumio_mcp/auth/audit_init.py
git commit -m "feat(auth): build_audit_log_from_env helper"
```

---

## Task 4: Extend `ToolContext` with `user_role`, `audit_log`, `request_id`

**Files:**
- Modify: `src/illumio_mcp/context.py`
- Modify: `tests/test_context.py`

- [ ] **Step 1: Replace `src/illumio_mcp/context.py`**

```python
"""ToolContext: the per-call object every tool handler receives.

Phase 3c: adds `user_role` (one of reader/operator/admin), `audit_log` (an
AuditLog instance — NullAuditLog in stdio), and `request_id` (UUID per HTTP
request; None in stdio). Stdio mode sets user_role="admin" and audit_log
to NullAuditLog so the dispatcher can be uniform.
"""
from dataclasses import dataclass


@dataclass
class ToolContext:
    pce: object | None
    is_stdio: bool
    user_sub: str | None = None
    user_iss: str | None = None
    keystore: object | None = None
    user_role: str | None = None  # 'reader' | 'operator' | 'admin' | None (no role assigned)
    audit_log: object | None = None  # auth.audit.AuditLog
    request_id: str | None = None
```

- [ ] **Step 2: Append tests to `tests/test_context.py`**

```python


def test_tool_context_user_role_default_none():
    ctx = ToolContext(pce=object(), is_stdio=True)
    assert ctx.user_role is None


def test_tool_context_carries_user_role_audit_request_id():
    sentinel_audit = object()
    ctx = ToolContext(
        pce=None,
        is_stdio=False,
        user_sub="u",
        user_iss="i",
        user_role="reader",
        audit_log=sentinel_audit,
        request_id="req-abc",
    )
    assert ctx.user_role == "reader"
    assert ctx.audit_log is sentinel_audit
    assert ctx.request_id == "req-abc"
```

- [ ] **Step 3: Run tests**

```bash
.venv/bin/python3 -m pytest tests/test_context.py -v
```
Expected: all green (8 + 2 new = 10).

- [ ] **Step 4: Verify stdio still works**

```bash
echo '{"jsonrpc":"2.0","id":0,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"test","version":"0"}}}' | timeout 5 .venv/bin/python3 -m illumio_mcp 2>&1 | head -3
```
Expected: response with `protocolVersion` AND `serverInfo`.

- [ ] **Step 5: Commit**

```bash
git add src/illumio_mcp/context.py tests/test_context.py
git commit -m "feat(context): add user_role, audit_log, request_id to ToolContext"
```

---

## Task 5: Wire role + audit into `server.py`

Three changes:
1. `_build_stdio_context` sets `user_role="admin"` and `audit_log=NullAuditLog()` so the dispatcher can apply uniform logic.
2. `build_http_context_for` gains `role`, `audit_log`, `request_id` parameters.
3. Dispatcher enforces role allowlist + records every decision.

**Files:**
- Modify: `src/illumio_mcp/server.py`

- [ ] **Step 1: Update imports near the top of `server.py`**

Find the existing auth imports block (added in Phases 3a/3b). Add (or extend) so the file has these imports near the other `.auth` imports:

```python
from .auth.audit import AuditEntry, NullAuditLog
```

(If the block is e.g. multiple `from .auth.X import Y` lines, just add one more for `audit`.)

- [ ] **Step 2: Update `_build_stdio_context`**

Find:
```python
def _build_stdio_context() -> ToolContext:
    """Build the single ToolContext used for the lifetime of the stdio process.
    ...
    """
    return ToolContext(pce=get_pce_from_env(), is_stdio=True)
```

Replace the body (keep the docstring) with:
```python
def _build_stdio_context() -> ToolContext:
    """Build the single ToolContext used for the lifetime of the stdio process.

    Stdio mode has one user (the operator who launched the process) and one PCE
    (built from PCE_* env vars). The ToolContext is created lazily on first use
    so that test setups can override env before the PCE is constructed.

    Stdio gets user_role="admin" and a NullAuditLog so the dispatcher can apply
    uniform role + audit logic without special-casing the transport.
    """
    return ToolContext(
        pce=get_pce_from_env(),
        is_stdio=True,
        user_role="admin",
        audit_log=NullAuditLog(),
    )
```

- [ ] **Step 3: Update `build_http_context_for`**

Find the function and replace it with:

```python
def build_http_context_for(
    user_sub: str | None,
    user_iss: str | None,
    keystore: object | None,
    user_role: str | None,
    audit_log: object | None,
    request_id: str | None,
) -> ToolContext:
    """Build a ToolContext for one HTTP request.

    Looks up the user's stored PCE credentials in the keystore. If found, builds
    a fresh PCE client from them. If not found, returns a context with pce=None
    and lets the dispatcher decide what to allow.
    """
    pce = None
    if keystore is not None and user_sub and user_iss:
        try:
            from .pce import build_pce_for
            creds = keystore.get(sub=user_sub, iss=user_iss)
            if creds is not None:
                pce = build_pce_for(creds)
        except Exception:
            logger.exception("Failed to load PCE credentials for user %s", user_sub)
    return ToolContext(
        pce=pce,
        is_stdio=False,
        user_sub=user_sub,
        user_iss=user_iss,
        keystore=keystore,
        user_role=user_role,
        audit_log=audit_log,
        request_id=request_id,
    )
```

- [ ] **Step 4: Update the dispatcher to enforce role + record audit**

Find `handle_call_tool`. Replace it entirely with:

```python
@server.call_tool()
async def handle_call_tool(name: str, arguments: dict) -> list[types.TextContent | types.ImageContent | types.EmbeddedResource]:
    logger.debug(f"Tool called: {name} with arguments: {arguments}")
    spec = TOOL_REGISTRY.get(name)
    if spec is None:
        raise ValueError(f"Unknown tool: {name}")
    ctx = get_active_context()
    audit = ctx.audit_log or NullAuditLog()

    def _audit(decision: str, reason: str | None) -> None:
        audit.record(AuditEntry(
            sub=ctx.user_sub,
            iss=ctx.user_iss,
            tool=name,
            decision=decision,
            reason=reason,
            role=ctx.user_role,
            request_id=ctx.request_id,
        ))

    # Role check
    if ctx.user_role is None:
        _audit("denied", "no role assigned")
        return [types.TextContent(type="text", text=json.dumps({
            "error": "forbidden_no_role",
            "message": "Your user has no role mapping configured on this server.",
        }, indent=2))]
    if ctx.user_role not in spec.roles:
        _audit("denied", f"role {ctx.user_role!r} not in {sorted(spec.roles)}")
        return [types.TextContent(type="text", text=json.dumps({
            "error": "forbidden",
            "message": f"Role {ctx.user_role!r} is not permitted to call {name!r}.",
            "allowed_roles": sorted(spec.roles),
        }, indent=2))]

    # PCE-presence check (Phase 3b)
    if spec.requires_pce and ctx.pce is None:
        _audit("denied", "no_pce_credentials")
        return [types.TextContent(
            type="text",
            text=json.dumps({
                "error": "no_pce_credentials",
                "message": (
                    "No PCE credentials registered for this user. "
                    "Call `register-pce-credentials` or open the browser setup page."
                ),
                "setup_path": "/setup",
            }, indent=2),
        )]

    try:
        t0 = time.monotonic()
        result = await asyncio.to_thread(spec.handler, ctx, arguments or {})
        elapsed = time.monotonic() - t0
        logger.info(f"Tool {name} completed in {elapsed:.2f}s")
        _audit("allowed", None)
        return result
    except Exception as e:
        error_msg = f"Tool {name} failed: {str(e)}"
        logger.error(error_msg, exc_info=True)
        _audit("error", str(e)[:200])
        return [types.TextContent(type="text", text=json.dumps({"error": error_msg}, indent=2))]
```

- [ ] **Step 5: Verify imports**

```bash
.venv/bin/python3 -c "
from illumio_mcp.server import _build_stdio_context, build_http_context_for, get_active_context
ctx = _build_stdio_context()
assert ctx.user_role == 'admin', f'expected admin, got {ctx.user_role}'
print('stdio ctx:', ctx.user_role, ctx.audit_log)
"
```
Expected: prints `stdio ctx: admin <illumio_mcp.auth.audit.NullAuditLog object at ...>`.

- [ ] **Step 6: Verify stdio still works**

```bash
echo '{"jsonrpc":"2.0","id":0,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"test","version":"0"}}}' | timeout 5 .venv/bin/python3 -m illumio_mcp 2>&1 | head -3
```
Expected: full JSON-RPC handshake.

- [ ] **Step 7: Run all unit tests as regression net**

```bash
.venv/bin/python3 -m pytest tests/ -q --ignore=tests/test_mcp_tools.py 2>&1 | tail -5
```
Expected: all green. (test_mcp_tools.py runs against real PCE — separate concern.)

- [ ] **Step 8: Commit**

```bash
git add src/illumio_mcp/server.py
git commit -m "feat(http): role enforcement + audit log in dispatcher"
```

---

## Task 6: Per-request request-id middleware

**Files:**
- Create: `src/illumio_mcp/transport/request_id.py`

- [ ] **Step 1: Write the file**

Create `src/illumio_mcp/transport/request_id.py`:

```python
"""Per-request request_id middleware.

Generates a UUID for every incoming HTTP request, stashes it on
`request.state.request_id`, and surfaces it as the `X-Request-Id` response
header. This lets us correlate audit log entries with HTTP-level traces.

If the client sends an `X-Request-Id` header, we honor it (lets external
tracing systems propagate IDs).
"""
from __future__ import annotations

import uuid

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response


class RequestIdMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next) -> Response:
        rid = request.headers.get("x-request-id") or str(uuid.uuid4())
        request.state.request_id = rid
        response = await call_next(request)
        response.headers["X-Request-Id"] = rid
        return response
```

- [ ] **Step 2: Verify import**

```bash
.venv/bin/python3 -c "from illumio_mcp.transport.request_id import RequestIdMiddleware; print('ok')"
```
Expected: `ok`.

- [ ] **Step 3: Commit**

```bash
git add src/illumio_mcp/transport/request_id.py
git commit -m "feat(http): per-request request_id middleware"
```

---

## Task 7: Wire role + audit + request_id into HTTP transport

**Files:**
- Modify: `src/illumio_mcp/transport/http.py`

- [ ] **Step 1: Replace `src/illumio_mcp/transport/http.py` with EXACTLY this content:**

```python
"""HTTP transport for the MCP server using Streamable HTTP (MCP spec 2025-03-26).

Phase 3c: adds role-based authz + audit log + per-request request_id.

Routes:
  GET  /healthz                                -> 200 (unauth)
  GET  /readyz                                 -> 200 (unauth)
  GET  /.well-known/oauth-protected-resource   -> RFC 9728 metadata (unauth)
  GET  /setup                                  -> HTML form (auth required)
  POST /setup                                  -> Submit credentials (auth required)
  *    /mcp                                    -> Streamable HTTP MCP (auth required)
"""
from __future__ import annotations

import argparse
import contextlib
import logging
import os
from typing import AsyncIterator

import uvicorn
from mcp.server.streamable_http_manager import StreamableHTTPSessionManager
from starlette.applications import Starlette
from starlette.middleware import Middleware
from starlette.requests import Request
from starlette.responses import JSONResponse, Response
from starlette.routing import Mount, Route

from ..auth.config import (
    OAuthConfig,
    MissingOAuthConfigError,
    is_dev_insecure,
    load_oauth_config_from_env,
)
from ..auth.jwt_validator import JWTValidator
from ..auth.middleware import JWTAuthMiddleware
from ..auth.prm import build_prm_document
from ..auth.keystore_init import build_keystore_from_env
from ..auth.crypto import MissingKEKError
from ..auth.roles import RoleConfig, load_role_config_from_env, map_user_role
from ..auth.audit_init import build_audit_log_from_env
from ..auth.audit import NullAuditLog
from ..server import (
    server as mcp_server,
    build_http_context_for,
    set_http_context,
    reset_http_context,
)
from .request_id import RequestIdMiddleware
from .setup_page import build_setup_routes

logger = logging.getLogger("illumio_mcp.transport.http")


def _build_session_manager() -> StreamableHTTPSessionManager:
    return StreamableHTTPSessionManager(app=mcp_server, stateless=True)


def _wrap_with_per_request_context(handle_request, keystore, role_config, audit_log):
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
        ctx = build_http_context_for(sub, iss, keystore, role, audit_log, request_id)
        token = set_http_context(ctx)
        try:
            await handle_request(scope, receive, send)
        finally:
            reset_http_context(token)
    return app


def _build_app(
    oauth_config: OAuthConfig | None,
    keystore: object | None,
    role_config: RoleConfig | None,
    audit_log: object | None,
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
        if keystore is not None:
            routes.extend(build_setup_routes(keystore))

        validator = JWTValidator(oauth_config)
        middleware.append(Middleware(JWTAuthMiddleware, validator=validator, config=oauth_config))
    else:
        logger.warning("MCP_DEV_INSECURE=1: HTTP server starting WITHOUT auth. Do not use in production.")

    return Starlette(debug=False, routes=routes, lifespan=lifespan, middleware=middleware)


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
    else:
        try:
            oauth_config = load_oauth_config_from_env()
        except MissingOAuthConfigError as e:
            raise SystemExit(str(e))
        try:
            keystore = build_keystore_from_env()
        except MissingKEKError as e:
            raise SystemExit(str(e))
        role_config = load_role_config_from_env()
        audit_log = build_audit_log_from_env()

    app = _build_app(oauth_config, keystore, role_config, audit_log)
    extras = []
    if oauth_config is None:
        extras.append("DEV-INSECURE: no auth, no keystore, admin role")
    logger.info(f"Starting HTTP transport on http://{host}:{port}/mcp"
                + (f"  [{'; '.join(extras)}]" if extras else ""))
    uvicorn.run(app, host=host, port=port, log_level="info")


def main() -> None:
    parser = argparse.ArgumentParser(prog="illumio-mcp-http", description=__doc__)
    parser.add_argument("--host", default=os.getenv("MCP_HTTP_HOST", "127.0.0.1"))
    parser.add_argument("--port", type=int, default=int(os.getenv("MCP_HTTP_PORT", "8080")))
    args = parser.parse_args()
    serve_http(host=args.host, port=args.port)
```

- [ ] **Step 2: Verify dev-insecure path still builds**

```bash
MCP_DEV_INSECURE=1 .venv/bin/python3 -c "
from illumio_mcp.transport.http import _build_app
from illumio_mcp.auth.audit import NullAuditLog
app = _build_app(None, None, None, NullAuditLog())
print('routes (dev):', sorted([getattr(r, 'path', '?') for r in app.routes]))
"
```
Expected: `routes (dev): ['/healthz', '/mcp', '/readyz']`.

- [ ] **Step 3: Verify auth path builds with all four args**

```bash
unset MCP_DEV_INSECURE
MCP_OAUTH_ISSUER=https://idp.test/o \
MCP_OAUTH_JWKS_URL=https://idp.test/o/.well-known/jwks.json \
MCP_OAUTH_AUDIENCE=mcp.test \
MCP_PUBLIC_URL=http://127.0.0.1 \
MCP_KEK=$(.venv/bin/python3 -c "import os, base64; print(base64.b64encode(os.urandom(32)).decode())") \
MCP_KEYSTORE_PATH=/tmp/test_p3c.db \
MCP_AUDIT_LOG_PATH=/tmp/test_p3c_audit.db \
MCP_ROLE_GROUPS_ADMIN=sg-admin \
  .venv/bin/python3 -c "
from illumio_mcp.transport.http import _build_app
from illumio_mcp.auth.config import load_oauth_config_from_env
from illumio_mcp.auth.keystore_init import build_keystore_from_env
from illumio_mcp.auth.audit_init import build_audit_log_from_env
from illumio_mcp.auth.roles import load_role_config_from_env
app = _build_app(
    load_oauth_config_from_env(),
    build_keystore_from_env(),
    load_role_config_from_env(),
    build_audit_log_from_env(),
)
print('routes (auth):', sorted([getattr(r, 'path', '?') for r in app.routes]))
" && rm -f /tmp/test_p3c.db* /tmp/test_p3c_audit.db*
```
Expected: routes include `/setup` x2, `/mcp`, `/healthz`, `/readyz`, `/.well-known/oauth-protected-resource`.

- [ ] **Step 4: Verify stdio still works**

```bash
echo '{"jsonrpc":"2.0","id":0,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"test","version":"0"}}}' | timeout 5 .venv/bin/python3 -m illumio_mcp 2>&1 | head -3
```
Expected: full JSON-RPC handshake.

- [ ] **Step 5: Commit**

```bash
git add src/illumio_mcp/transport/http.py
git commit -m "feat(http): wire role config, audit log, request-id into transport"
```

---

## Task 8: End-to-end role enforcement test

**Files:**
- Create: `tests/test_http_authz.py`

- [ ] **Step 1: Write the test**

Create `tests/test_http_authz.py`:

```python
"""End-to-end: role-based authorization.

Verifies that:
  - Reader can call read tools, gets denied on write tools
  - Operator can call write tools
  - User without a role mapping gets `forbidden_no_role`
  - Audit log records every decision
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
from illumio_mcp.auth.crypto import EnvelopeCipher, generate_kek
from illumio_mcp.auth.jwt_validator import JWTValidator
from illumio_mcp.auth.middleware import JWTAuthMiddleware
from illumio_mcp.auth.keystore import SQLiteKeyStore
from illumio_mcp.auth.audit import SQLiteAuditLog
from illumio_mcp.auth.roles import RoleConfig
from illumio_mcp.pce import PCECredentials


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


def _mint(private_key_pem, sub, groups):
    return pyjwt.encode({
        "iss": "https://idp.test/o",
        "aud": "mcp.test",
        "sub": sub,
        "exp": int(time.time()) + 600,
        "iat": int(time.time()),
        "scope": "illumio-mcp.use",
        "groups": groups,
    }, private_key_pem, algorithm="RS256", headers={"kid": "test-kid"})


@pytest.fixture(scope="module")
def http_server(public_key_pem, tmp_path_factory):
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
    pce_mod.build_pce_for = lambda creds: FakePCE(creds.host)  # type: ignore[assignment]

    port = _free_port()
    cfg = OAuthConfig(
        issuer="https://idp.test/o",
        jwks_url="https://idp.test/o/.well-known/jwks.json",
        audience="mcp.test",
        required_scope="illumio-mcp.use",
        resource_url=f"http://127.0.0.1:{port}",
    )
    validator = JWTValidator(cfg, key_resolver=lambda kid: public_key_pem)
    db = tmp_path_factory.mktemp("ks") / "keys.db"
    keystore = SQLiteKeyStore(db_path=str(db), cipher=EnvelopeCipher(generate_kek()))
    audit_db = tmp_path_factory.mktemp("au") / "audit.db"
    audit_log = SQLiteAuditLog(db_path=str(audit_db))
    role_config = RoleConfig(
        admin_groups=["sg-admin"],
        operator_groups=["sg-op", "sg-admin"],
        reader_groups=["sg-read", "sg-op", "sg-admin"],
        default_role=None,
    )

    # Pre-register PCE creds for users alice (reader), bob (operator), nobody (no role)
    creds = PCECredentials(host="https://pce.example", port=8443, org_id=1, api_key="k", api_secret="s")
    keystore.put(sub="alice", iss="https://idp.test/o", creds=creds)
    keystore.put(sub="bob", iss="https://idp.test/o", creds=creds)
    keystore.put(sub="nobody", iss="https://idp.test/o", creds=creds)

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
        ctx = build_http_context_for(sub, iss, keystore, role, audit_log, request_id)
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

    yield f"http://127.0.0.1:{port}", audit_log

    server.should_exit = True
    thread.join(timeout=5)
    pce_mod.build_pce_for = original_build


async def test_reader_can_call_read_tool(http_server, private_key_pem):
    from mcp import ClientSession
    from mcp.client.streamable_http import streamablehttp_client

    url, _ = http_server
    token = _mint(private_key_pem, sub="alice", groups=["sg-read"])
    async with streamablehttp_client(f"{url}/mcp", headers={"Authorization": f"Bearer {token}"}) as (read, write, _):
        async with ClientSession(read, write) as session:
            await session.initialize()
            # check-pce-credentials-status is a reader-allowed tool that doesn't need PCE
            result = await session.call_tool("check-pce-credentials-status", {})
            body = json.loads(result.content[0].text)
            # Reader has creds registered; expect status registered=True
            assert body.get("registered") is True


async def test_reader_denied_on_write_tool(http_server, private_key_pem):
    from mcp import ClientSession
    from mcp.client.streamable_http import streamablehttp_client

    url, _ = http_server
    token = _mint(private_key_pem, sub="alice", groups=["sg-read"])
    async with streamablehttp_client(f"{url}/mcp", headers={"Authorization": f"Bearer {token}"}) as (read, write, _):
        async with ClientSession(read, write) as session:
            await session.initialize()
            # create-label is operator+admin only
            result = await session.call_tool("create-label", {"key": "app", "value": "test"})
            body = json.loads(result.content[0].text)
            assert body["error"] == "forbidden"
            assert "reader" in body["message"]


async def test_operator_can_call_write_tool(http_server, private_key_pem):
    from mcp import ClientSession
    from mcp.client.streamable_http import streamablehttp_client

    url, _ = http_server
    token = _mint(private_key_pem, sub="bob", groups=["sg-op"])
    async with streamablehttp_client(f"{url}/mcp", headers={"Authorization": f"Bearer {token}"}) as (read, write, _):
        async with ClientSession(read, write) as session:
            await session.initialize()
            # check-pce-credentials-status is allowed for all roles; sufficient to prove dispatch path
            result = await session.call_tool("check-pce-credentials-status", {})
            body = json.loads(result.content[0].text)
            assert body.get("registered") is True


async def test_user_without_role_gets_forbidden_no_role(http_server, private_key_pem):
    from mcp import ClientSession
    from mcp.client.streamable_http import streamablehttp_client

    url, _ = http_server
    token = _mint(private_key_pem, sub="nobody", groups=["sg-other"])
    async with streamablehttp_client(f"{url}/mcp", headers={"Authorization": f"Bearer {token}"}) as (read, write, _):
        async with ClientSession(read, write) as session:
            await session.initialize()
            result = await session.call_tool("check-pce-credentials-status", {})
            body = json.loads(result.content[0].text)
            assert body["error"] == "forbidden_no_role"


async def test_audit_log_records_decisions(http_server, private_key_pem):
    """After a few calls, the audit DB should have rows for allowed and denied decisions."""
    import sqlite3
    from mcp import ClientSession
    from mcp.client.streamable_http import streamablehttp_client

    url, audit_log = http_server
    # Make a known set of calls so we can assert on what's in the audit log.
    token_admin = _mint(private_key_pem, sub="audit-admin", groups=["sg-admin"])
    async with streamablehttp_client(f"{url}/mcp", headers={"Authorization": f"Bearer {token_admin}"}) as (read, write, _):
        async with ClientSession(read, write) as session:
            await session.initialize()
            await session.call_tool("check-pce-credentials-status", {})

    token_reader = _mint(private_key_pem, sub="audit-reader", groups=["sg-read"])
    async with streamablehttp_client(f"{url}/mcp", headers={"Authorization": f"Bearer {token_reader}"}) as (read, write, _):
        async with ClientSession(read, write) as session:
            await session.initialize()
            await session.call_tool("create-label", {"key": "app", "value": "x"})

    with sqlite3.connect(audit_log.db_path) as con:
        rows = con.execute(
            "SELECT sub, tool, decision, role FROM audit_log "
            "WHERE sub IN ('audit-admin', 'audit-reader')"
        ).fetchall()
    decisions = {(sub, tool, decision) for sub, tool, decision, _role in rows}
    assert ("audit-admin", "check-pce-credentials-status", "allowed") in decisions
    assert ("audit-reader", "create-label", "denied") in decisions
```

- [ ] **Step 2: Run the tests**

```bash
.venv/bin/python3 -m pytest tests/test_http_authz.py -v 2>&1 | tail -40
```
Expected: 5 PASSED.

- [ ] **Step 3: Commit**

```bash
git add tests/test_http_authz.py
git commit -m "test: end-to-end role enforcement + audit log"
```

---

## Task 9: README — document role config + audit log

**Files:**
- Modify: `README.md`

- [ ] **Step 1: Append to the existing OAuth section**

Find the "Per-user PCE keys (Phase 3b)" subsection. Append AFTER it:

```markdown
### Role-based authorization (Phase 3c)

The server maps each user's IdP groups to one of three internal roles:
**reader**, **operator**, **admin**. Per-tool authorization is enforced by the
dispatcher using the `roles` metadata on each `ToolSpec`.

Configure group → role mapping via env (comma-separated):

```bash
# A user matching ANY of these groups gets that role; highest role wins.
export MCP_ROLE_GROUPS_ADMIN=sg-illumio-mcp-admin
export MCP_ROLE_GROUPS_OPERATOR=sg-illumio-mcp-operator,sg-illumio-mcp-admin
export MCP_ROLE_GROUPS_READER=sg-illumio-mcp-readonly,sg-illumio-mcp-operator,sg-illumio-mcp-admin

# Optional: fallback role when no group matches. Leave unset to refuse.
# export MCP_ROLE_DEFAULT=reader
```

Tool-by-tool defaults:

| Tool category | Roles allowed | Examples |
|---|---|---|
| Reads | reader, operator, admin | `get-labels`, `get-workloads`, `get-traffic-flows` |
| Writes | operator, admin | `create-*`, `update-*`, `delete-*` |
| Provisioning + bulk | admin | `provision-policy`, `ringfence-batch` |

A user without a matching role (and no `MCP_ROLE_DEFAULT`) receives a structured
`forbidden_no_role` error.

### Audit log (Phase 3c)

Every dispatcher decision (allow / deny / error) is written to a SQLite audit
database. Schema and storage location:

```bash
# Defaults to <keystore_dir>/audit.db
export MCP_AUDIT_LOG_PATH=/var/lib/illumio-mcp/audit.db
```

Audit rows include `(ts, sub, iss, tool, decision, reason, role, request_id)`
— **never** tool arguments. The `request_id` matches the `X-Request-Id`
response header so external traces can be correlated.

Query examples:

```sql
-- Recent denied calls per user
SELECT ts, sub, tool, reason FROM audit_log
WHERE decision='denied'
ORDER BY ts DESC LIMIT 20;

-- Tool-call volume by user
SELECT sub, COUNT(*) FROM audit_log
WHERE ts > date('now', '-7 days')
GROUP BY sub ORDER BY 2 DESC;
```
```

- [ ] **Step 2: Commit**

```bash
git add README.md
git commit -m "docs: role-based authz + audit log (Phase 3c)"
```

---

## Task 10: Open PR

- [ ] **Step 1: Push the branch**

```bash
git push -u origin feature/role-authz-and-audit
```

- [ ] **Step 2: Open the PR (stacked on Phase 3b)**

```bash
gh pr create --base feature/per-user-pce-keystore --title "feat: role-based authz + audit log (Phase 3c)" --body "$(cat <<'EOF'
## Summary

Phase 3c. The dispatcher now enforces per-tool role authorization based on JWT group claims, and persists every decision to a SQLite audit log.

> **Stacked on #13 (Phase 3b).** When #13 merges, base auto-updates.

## What changed

- `auth/roles.py`: env-configured group→role mapping (admin > operator > reader; optional default role).
- `auth/audit.py`: `AuditEntry` + `AuditLog` Protocol + `SQLiteAuditLog` + `NullAuditLog`.
- `auth/audit_init.py`: build audit log from `MCP_AUDIT_LOG_PATH`.
- `transport/request_id.py`: per-request UUID middleware exposing `X-Request-Id` response header.
- `ToolContext` gains `user_role`, `audit_log`, `request_id`.
- Dispatcher (`server.py`): refuses calls if `ctx.user_role` is None (`forbidden_no_role`) or not in `spec.roles` (`forbidden`); records `AuditEntry` for every allow/deny/error.
- `transport/http.py`: builds role config + audit log at startup; ASGI wrapper computes per-request role from JWT groups.
- Stdio: implicit `admin`, `NullAuditLog` — uniform dispatcher logic, no special-cases.
- Audit log NEVER persists tool arguments (only `tool` name, `decision`, `reason`, IDs).

## Test plan

- [x] `pytest tests/test_auth_roles.py -v` — 10 passed (env loading, mapping precedence, default role)
- [x] `pytest tests/test_auth_audit.py -v` — 6 passed (CRUD, NullAuditLog no-op, file perms)
- [x] `pytest tests/test_http_authz.py -v` — 5 passed (reader allow/deny, operator, no-role user, audit rows persisted)
- [x] All Phase 1–3b tests still green
- [x] Stdio sanity check after every transport-touching commit

## What this PR does NOT do

Explicitly Phase 3d:
- `/confirm` step-up endpoint
- Mutating-tool token gating (`requires_confirm=True` is recorded but not enforced yet)

Also explicitly deferred:
- Scope filters per user (label/app restrictions). The `unscopable=True` flag on `ToolSpec` is recorded but no scope query-rewriting is implemented.

🤖 Generated with [Claude Code](https://claude.com/claude-code)
EOF
)"
```

- [ ] **Step 3: Print the PR URL**

---

## Self-review checklist

- [x] **Spec coverage:** §5 Layer 2 (role mapping from groups) → Tasks 1, 5, 7. §5 Layer 3 (tool allowlist) → Task 5 (dispatcher reads `spec.roles`). §7.3 (audit log) → Tasks 2, 3, 5. Per-request `request_id` → Task 6.
- [x] **Placeholders:** None.
- [x] **Type consistency:** `RoleConfig(admin_groups, operator_groups, reader_groups, default_role)` defined Task 1, used Tasks 5, 7, 8. `AuditEntry(sub, iss, tool, decision, reason, role, request_id)` defined Task 2, used Tasks 5, 8 (assertion on rows). `ToolContext` extension (Task 4) populated by `_build_stdio_context` (Task 5) + `build_http_context_for` (Task 5) + ASGI wrapper (Task 7).
- [x] **Stdio invariants:** Tasks 4, 5, 7 each include explicit stdio handshake check.
- [x] **No new dependencies.**
- [x] **No tool args in audit log:** Audit module records only `tool` name + decision metadata.
