# Phase 3d: Confirm Tokens for Mutating Tools — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Tools marked `requires_confirm=True` (currently `provision-policy`, `ringfence-batch`, `delete-pce-credentials`, etc.) require a server-issued single-use confirm token in `params._meta.confirm_token`. Tokens are minted by a separate `POST /confirm` HTTP endpoint after the user re-asserts intent. Defense against prompt injection: the LLM cannot mint these tokens autonomously from inside the MCP session, and (when `MCP_CONFIRM_FRESH_AUTH_SECONDS` is set) the server requires the user's JWT `auth_time` to be recent — forcing a human-in-the-loop step-up.

**Architecture:** A new `auth/confirm.py` module provides `ConfirmTokenManager` (HMAC-SHA256 over `(sub, tool, params_hash, jti, exp)`). A new `auth/confirm_replay.py` exposes `SQLiteJtiStore` that records every used `jti` so replays are rejected. A new `transport/confirm_endpoint.py` mounts `POST /confirm` on the Starlette app — the endpoint is JWT-protected by the existing middleware and optionally checks `auth_time` against `MCP_CONFIRM_FRESH_AUTH_SECONDS`. The dispatcher reads `params._meta.confirm_token`, verifies it via `ConfirmTokenManager.verify()`, marks the `jti` as used, and proceeds. Stdio mode is unchanged — confirm-required tools still work in stdio (the operator launched the process; we don't gate them).

**Tech Stack:** Standard library (`hmac`, `hashlib`, `secrets`, `base64`, `json`, `sqlite3`, `uuid`). No new third-party deps.

**Spec:** [`docs/superpowers/specs/2026-05-12-http-transport-and-auth-design.md`](../specs/2026-05-12-http-transport-and-auth-design.md) §5 Layer 5.

**Branch:** `feature/confirm-tokens` off `feature/role-authz-and-audit` (or `main` once that ships).

---

## Working agreement

- **Stdio is unchanged.** Confirm-token enforcement only kicks in when `ctx.is_stdio == False`. Stdio admin can still call mutating tools without tokens (the operator launched the process). Verified at every commit that touches `server.py`.
- **Tokens are HMAC, not JWT.** Lighter weight, no per-token DB lookup for verify (only for replay tracking). Server holds a single shared HMAC key from `MCP_CONFIRM_HMAC_KEY` (32-byte base64). HTTP refuses to start in auth mode without it.
- **Tokens are single-use.** Replay attempts are rejected even within the TTL.
- **`auth_time` check is optional.** If `MCP_CONFIRM_FRESH_AUTH_SECONDS` is set (e.g. `300`), `/confirm` requires the JWT's `auth_time` claim to be within that window. If unset, /confirm just requires a valid JWT — useful for IdPs that don't issue `auth_time`.
- **Audit log records confirm-related decisions.** Every `/confirm` mint = `decision=allowed, tool="_confirm", reason="minted token for X"`. Every dispatcher rejection for missing/bad token = `decision=denied, reason="missing_confirm_token" | "invalid_confirm_token" | "confirm_token_replay"`.
- **No tool args in audit.** The `params_hash` is recorded but not the params themselves.

---

## File structure

| File | Responsibility |
|---|---|
| `src/illumio_mcp/auth/confirm.py` (new) | `ConfirmToken` dataclass + `ConfirmTokenManager` (mint, verify, canonical_params_hash) + `load_hmac_key_from_env` |
| `src/illumio_mcp/auth/confirm_replay.py` (new) | `JtiStore` Protocol + `SQLiteJtiStore` (mark_used → bool, has been used, with TTL-based GC) + `NullJtiStore` (allows everything; for tests) |
| `src/illumio_mcp/auth/confirm_init.py` (new) | `build_confirm_manager_from_env`: returns `(ConfirmTokenManager, JtiStore)` ready to plug into the transport |
| `src/illumio_mcp/transport/confirm_endpoint.py` (new) | `build_confirm_routes(manager, audit_log)`: returns the Starlette routes for `POST /confirm` |
| `src/illumio_mcp/context.py` (modify) | Add `confirm_manager: object | None`, `jti_store: object | None` |
| `src/illumio_mcp/server.py` (modify) | Dispatcher: when `spec.requires_confirm and not ctx.is_stdio`, require a valid `params._meta.confirm_token`; mark its jti as used |
| `src/illumio_mcp/transport/http.py` (modify) | Build manager + jti store at startup; wire into per-request context; mount `/confirm` route |
| `tests/test_auth_confirm.py` (new) | Mint/verify happy path + every failure mode (sig, expiry, wrong tool, wrong sub, wrong params hash) |
| `tests/test_auth_confirm_replay.py` (new) | SQLiteJtiStore: mark_used returns True first time, False on replay |
| `tests/test_http_confirm.py` (new) | e2e: provision-policy without token → denied; with valid token → allowed; replay → denied |
| `README.md` (modify) | "Confirm tokens (Phase 3d)" subsection |

---

## Task 0: Create the working branch

**Files:** git only

- [ ] **Step 1: Branch**

```bash
git checkout feature/role-authz-and-audit
git pull --ff-only origin feature/role-authz-and-audit
git checkout -b feature/confirm-tokens
```

- [ ] **Step 2: Verify clean baseline**

```bash
git status
.venv/bin/python3 -m pytest tests/test_auth_roles.py tests/test_auth_audit.py tests/test_http_authz.py -q
```
Expected: all green.

---

## Task 1: `auth/confirm.py` — ConfirmTokenManager

**Files:**
- Create: `src/illumio_mcp/auth/confirm.py`
- Create: `tests/test_auth_confirm.py`

- [ ] **Step 1: Write the failing tests**

Create `tests/test_auth_confirm.py`:

```python
"""Tests for ConfirmTokenManager (HMAC mint + verify)."""
import os
import time
import base64
import pytest

from illumio_mcp.auth.confirm import (
    ConfirmTokenManager,
    InvalidConfirmTokenError,
    canonical_params_hash,
    generate_hmac_key,
    load_hmac_key_from_env,
    MissingConfirmHmacKeyError,
)


@pytest.fixture
def mgr():
    return ConfirmTokenManager(generate_hmac_key(), ttl_seconds=120)


def _mint(mgr, **overrides):
    args = {
        "sub": "user-42",
        "tool": "provision-policy",
        "params_hash": "h" * 64,
        **overrides,
    }
    return mgr.mint(**args)


def test_mint_then_verify_round_trip(mgr):
    token = _mint(mgr)
    claims = mgr.verify(token, sub="user-42", tool="provision-policy", params_hash="h" * 64)
    assert claims.sub == "user-42"
    assert claims.tool == "provision-policy"
    assert claims.jti  # non-empty


def test_verify_wrong_sub_rejected(mgr):
    token = _mint(mgr)
    with pytest.raises(InvalidConfirmTokenError, match="sub"):
        mgr.verify(token, sub="other-user", tool="provision-policy", params_hash="h" * 64)


def test_verify_wrong_tool_rejected(mgr):
    token = _mint(mgr)
    with pytest.raises(InvalidConfirmTokenError, match="tool"):
        mgr.verify(token, sub="user-42", tool="delete-workload", params_hash="h" * 64)


def test_verify_wrong_params_hash_rejected(mgr):
    token = _mint(mgr)
    with pytest.raises(InvalidConfirmTokenError, match="params"):
        mgr.verify(token, sub="user-42", tool="provision-policy", params_hash="x" * 64)


def test_verify_tampered_signature_rejected(mgr):
    token = _mint(mgr)
    # Flip a byte in the middle of the token
    parts = token.split(".")
    tampered_payload = parts[0][:-1] + ("a" if parts[0][-1] != "a" else "b")
    bad = tampered_payload + "." + parts[1]
    with pytest.raises(InvalidConfirmTokenError):
        mgr.verify(bad, sub="user-42", tool="provision-policy", params_hash="h" * 64)


def test_verify_expired_token_rejected():
    # Use a tiny TTL so we can wait past it.
    mgr = ConfirmTokenManager(generate_hmac_key(), ttl_seconds=1)
    token = _mint(mgr)
    time.sleep(1.5)
    with pytest.raises(InvalidConfirmTokenError, match="expired"):
        mgr.verify(token, sub="user-42", tool="provision-policy", params_hash="h" * 64)


def test_verify_with_different_key_rejected():
    mgr_a = ConfirmTokenManager(generate_hmac_key(), ttl_seconds=120)
    mgr_b = ConfirmTokenManager(generate_hmac_key(), ttl_seconds=120)
    token = _mint(mgr_a)
    with pytest.raises(InvalidConfirmTokenError):
        mgr_b.verify(token, sub="user-42", tool="provision-policy", params_hash="h" * 64)


def test_canonical_params_hash_is_stable():
    """Same params -> same hash regardless of dict ordering."""
    h1 = canonical_params_hash({"a": 1, "b": [2, 3]})
    h2 = canonical_params_hash({"b": [2, 3], "a": 1})
    assert h1 == h2
    assert len(h1) == 64  # sha256 hex


def test_canonical_params_hash_differs_for_different_params():
    assert canonical_params_hash({"a": 1}) != canonical_params_hash({"a": 2})


def test_load_hmac_key_from_env_happy_path(monkeypatch):
    raw = os.urandom(32)
    monkeypatch.setenv("MCP_CONFIRM_HMAC_KEY", base64.b64encode(raw).decode())
    assert load_hmac_key_from_env() == raw


def test_load_hmac_key_from_env_missing_raises(monkeypatch):
    monkeypatch.delenv("MCP_CONFIRM_HMAC_KEY", raising=False)
    with pytest.raises(MissingConfirmHmacKeyError):
        load_hmac_key_from_env()


def test_load_hmac_key_from_env_wrong_length_raises(monkeypatch):
    monkeypatch.setenv("MCP_CONFIRM_HMAC_KEY", base64.b64encode(b"only-16-bytes-aaa").decode())
    with pytest.raises(ValueError, match="32"):
        load_hmac_key_from_env()
```

- [ ] **Step 2: Run test to verify it fails**

```bash
.venv/bin/python3 -m pytest tests/test_auth_confirm.py -v
```
Expected: ImportError on `illumio_mcp.auth.confirm`.

- [ ] **Step 3: Implement `auth/confirm.py`**

Create `src/illumio_mcp/auth/confirm.py`:

```python
"""ConfirmTokenManager — HMAC-signed single-use tokens for mutating tools.

Wire format: `<base64url(payload_json)>.<base64url(hmac_sha256)>`

Payload is a JSON object: {"sub": "...", "tool": "...", "params_hash": "...",
"jti": "...", "exp": 1234567890}. The HMAC is computed over the base64url
of the payload (so verify is cheap: re-encode and compare).

Verify rejects on any of:
  - wrong signature
  - exp passed
  - sub mismatch with caller
  - tool mismatch with caller
  - params_hash mismatch with caller

Replay rejection is the JtiStore's job — see auth/confirm_replay.py.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import time
import uuid
from dataclasses import dataclass
from secrets import token_bytes


class MissingConfirmHmacKeyError(RuntimeError):
    """Raised when MCP_CONFIRM_HMAC_KEY is not set and DEV_INSECURE is off."""


class InvalidConfirmTokenError(Exception):
    """Raised when a confirm token fails verification."""


_KEY_BYTES = 32


@dataclass(frozen=True)
class ConfirmTokenClaims:
    sub: str
    tool: str
    params_hash: str
    jti: str
    exp: int


def generate_hmac_key() -> bytes:
    return token_bytes(_KEY_BYTES)


def load_hmac_key_from_env() -> bytes:
    raw = os.getenv("MCP_CONFIRM_HMAC_KEY")
    if not raw:
        raise MissingConfirmHmacKeyError(
            "MCP_CONFIRM_HMAC_KEY env var is required (32-byte base64). "
            "Generate with: python -c 'import os, base64; print(base64.b64encode(os.urandom(32)).decode())'"
        )
    try:
        key = base64.b64decode(raw)
    except Exception as e:
        raise ValueError(f"MCP_CONFIRM_HMAC_KEY is not valid base64: {e}") from e
    if len(key) != _KEY_BYTES:
        raise ValueError(f"MCP_CONFIRM_HMAC_KEY must decode to exactly 32 bytes, got {len(key)}")
    return key


def canonical_params_hash(params: dict) -> str:
    """Stable SHA-256 hex digest of params.

    Sorted keys + tight separators ensure the same params always produce the
    same hash regardless of how the client constructs the dict.
    """
    canonical = json.dumps(params, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def _b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _b64url_decode(s: str) -> bytes:
    padding = "=" * (-len(s) % 4)
    return base64.urlsafe_b64decode(s + padding)


class ConfirmTokenManager:
    """Stateless HMAC-token mint/verify."""

    def __init__(self, hmac_key: bytes, *, ttl_seconds: int = 120):
        if len(hmac_key) != _KEY_BYTES:
            raise ValueError(f"HMAC key must be {_KEY_BYTES} bytes, got {len(hmac_key)}")
        self._key = hmac_key
        self._ttl = ttl_seconds

    def mint(self, *, sub: str, tool: str, params_hash: str) -> str:
        claims = {
            "sub": sub,
            "tool": tool,
            "params_hash": params_hash,
            "jti": uuid.uuid4().hex,
            "exp": int(time.time()) + self._ttl,
        }
        payload = _b64url_encode(json.dumps(claims, sort_keys=True, separators=(",", ":")).encode("utf-8"))
        sig = _b64url_encode(hmac.new(self._key, payload.encode("ascii"), hashlib.sha256).digest())
        return f"{payload}.{sig}"

    def verify(self, token: str, *, sub: str, tool: str, params_hash: str) -> ConfirmTokenClaims:
        try:
            payload_b64, sig_b64 = token.split(".")
        except ValueError as e:
            raise InvalidConfirmTokenError(f"malformed token: {e}") from e

        # 1) Verify signature with constant-time compare
        expected_sig = _b64url_encode(
            hmac.new(self._key, payload_b64.encode("ascii"), hashlib.sha256).digest()
        )
        if not hmac.compare_digest(sig_b64, expected_sig):
            raise InvalidConfirmTokenError("invalid signature")

        # 2) Decode + parse payload
        try:
            claims_dict = json.loads(_b64url_decode(payload_b64))
        except Exception as e:
            raise InvalidConfirmTokenError(f"malformed payload: {e}") from e

        # 3) Field-level checks
        if claims_dict.get("exp", 0) <= int(time.time()):
            raise InvalidConfirmTokenError("token expired")
        if claims_dict.get("sub") != sub:
            raise InvalidConfirmTokenError(f"sub mismatch (token={claims_dict.get('sub')!r}, caller={sub!r})")
        if claims_dict.get("tool") != tool:
            raise InvalidConfirmTokenError(f"tool mismatch (token={claims_dict.get('tool')!r}, caller={tool!r})")
        if claims_dict.get("params_hash") != params_hash:
            raise InvalidConfirmTokenError("params_hash mismatch")

        return ConfirmTokenClaims(
            sub=claims_dict["sub"],
            tool=claims_dict["tool"],
            params_hash=claims_dict["params_hash"],
            jti=claims_dict["jti"],
            exp=claims_dict["exp"],
        )
```

- [ ] **Step 4: Run tests**

```bash
.venv/bin/python3 -m pytest tests/test_auth_confirm.py -v
```
Expected: 12 PASSED.

- [ ] **Step 5: Commit**

```bash
git add src/illumio_mcp/auth/confirm.py tests/test_auth_confirm.py
git commit -m "feat(auth): ConfirmTokenManager (HMAC mint + verify)"
```

---

## Task 2: `auth/confirm_replay.py` — JtiStore for single-use enforcement

**Files:**
- Create: `src/illumio_mcp/auth/confirm_replay.py`
- Create: `tests/test_auth_confirm_replay.py`

- [ ] **Step 1: Write the failing tests**

Create `tests/test_auth_confirm_replay.py`:

```python
"""Tests for the JTI replay tracker."""
import os
import time
import pytest

from illumio_mcp.auth.confirm_replay import SQLiteJtiStore, NullJtiStore


@pytest.fixture
def jti_store(tmp_path):
    return SQLiteJtiStore(db_path=str(tmp_path / "jti.db"))


def test_first_use_returns_true(jti_store):
    assert jti_store.mark_used("jti-123", exp=int(time.time()) + 60) is True


def test_replay_returns_false(jti_store):
    jti_store.mark_used("jti-123", exp=int(time.time()) + 60)
    assert jti_store.mark_used("jti-123", exp=int(time.time()) + 60) is False


def test_different_jtis_independent(jti_store):
    assert jti_store.mark_used("jti-a", exp=int(time.time()) + 60) is True
    assert jti_store.mark_used("jti-b", exp=int(time.time()) + 60) is True
    assert jti_store.mark_used("jti-a", exp=int(time.time()) + 60) is False


def test_purge_removes_expired(jti_store):
    """purge_expired should clean rows whose exp has passed."""
    jti_store.mark_used("old", exp=int(time.time()) - 60)
    jti_store.mark_used("new", exp=int(time.time()) + 60)
    removed = jti_store.purge_expired()
    assert removed == 1
    # 'new' is still tracked
    assert jti_store.mark_used("new", exp=int(time.time()) + 60) is False


def test_null_jti_store_always_allows():
    null = NullJtiStore()
    assert null.mark_used("jti-1", exp=int(time.time()) + 60) is True
    assert null.mark_used("jti-1", exp=int(time.time()) + 60) is True


def test_db_file_perms(jti_store):
    mode = os.stat(jti_store.db_path).st_mode & 0o777
    assert mode & 0o077 == 0
```

- [ ] **Step 2: Run test to verify it fails**

```bash
.venv/bin/python3 -m pytest tests/test_auth_confirm_replay.py -v
```
Expected: ImportError.

- [ ] **Step 3: Implement `auth/confirm_replay.py`**

Create `src/illumio_mcp/auth/confirm_replay.py`:

```python
"""JTI replay tracker — enforces single-use of confirm tokens.

The JtiStore records every (jti, exp) the dispatcher has accepted. A second
attempt with the same jti is rejected. Expired rows can be purged in bulk
(call `purge_expired` periodically; for v1 a one-shot purge at startup is
fine since rows accumulate slowly).
"""
from __future__ import annotations

import os
import sqlite3
import time
from pathlib import Path
from typing import Protocol


_SCHEMA = """
CREATE TABLE IF NOT EXISTS used_jti (
    jti  TEXT PRIMARY KEY,
    exp  INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_used_jti_exp ON used_jti(exp);
"""


class JtiStore(Protocol):
    def mark_used(self, jti: str, *, exp: int) -> bool: ...


class NullJtiStore:
    """No-op store; allows every mark_used. Used in stdio mode (no confirm enforcement)
    and in tests that don't care about replay."""

    def mark_used(self, jti: str, *, exp: int) -> bool:
        return True


class SQLiteJtiStore:
    """File-backed JTI tracker."""

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

    def mark_used(self, jti: str, *, exp: int) -> bool:
        """Atomically record this jti. Returns True if first use, False if replay."""
        with sqlite3.connect(self.db_path) as con:
            try:
                con.execute("INSERT INTO used_jti (jti, exp) VALUES (?, ?)", (jti, exp))
                return True
            except sqlite3.IntegrityError:
                return False

    def purge_expired(self) -> int:
        """Delete rows whose exp has already passed. Returns rowcount."""
        now = int(time.time())
        with sqlite3.connect(self.db_path) as con:
            cur = con.execute("DELETE FROM used_jti WHERE exp <= ?", (now,))
            return cur.rowcount
```

- [ ] **Step 4: Run tests**

```bash
.venv/bin/python3 -m pytest tests/test_auth_confirm_replay.py -v
```
Expected: 6 PASSED.

- [ ] **Step 5: Commit**

```bash
git add src/illumio_mcp/auth/confirm_replay.py tests/test_auth_confirm_replay.py
git commit -m "feat(auth): SQLiteJtiStore for confirm-token replay prevention"
```

---

## Task 3: `auth/confirm_init.py` — startup wiring helper

**Files:**
- Create: `src/illumio_mcp/auth/confirm_init.py`

- [ ] **Step 1: Write the file**

Create `src/illumio_mcp/auth/confirm_init.py`:

```python
"""Build (ConfirmTokenManager, JtiStore) from environment.

Reads:
  MCP_CONFIRM_HMAC_KEY    32-byte base64 HMAC key (required in auth mode)
  MCP_CONFIRM_TTL_SECONDS confirm-token TTL (default: 120)
  MCP_CONFIRM_JTI_PATH    SQLite file for jti tracking
                          (default: alongside keystore — <ks_dir>/jti.db)
"""
import os
from pathlib import Path

from .confirm import ConfirmTokenManager, load_hmac_key_from_env
from .confirm_replay import SQLiteJtiStore


def build_confirm_manager_from_env() -> tuple[ConfirmTokenManager, SQLiteJtiStore]:
    key = load_hmac_key_from_env()
    ttl = int(os.getenv("MCP_CONFIRM_TTL_SECONDS", "120"))
    manager = ConfirmTokenManager(key, ttl_seconds=ttl)

    explicit_jti = os.getenv("MCP_CONFIRM_JTI_PATH")
    if explicit_jti:
        jti_path = explicit_jti
    else:
        ks_path = os.getenv("MCP_KEYSTORE_PATH", "./data/keys.db")
        jti_path = str(Path(ks_path).parent / "jti.db")
    jti_store = SQLiteJtiStore(db_path=jti_path)
    return manager, jti_store
```

- [ ] **Step 2: Verify**

```bash
MCP_CONFIRM_HMAC_KEY=$(.venv/bin/python3 -c "import os, base64; print(base64.b64encode(os.urandom(32)).decode())") \
MCP_CONFIRM_JTI_PATH=/tmp/test_jti.db \
  .venv/bin/python3 -c "
from illumio_mcp.auth.confirm_init import build_confirm_manager_from_env
mgr, jti = build_confirm_manager_from_env()
token = mgr.mint(sub='u', tool='t', params_hash='h'*64)
print('token len:', len(token))
print('jti db_path:', jti.db_path)
" && rm -f /tmp/test_jti.db /tmp/test_jti.db-shm /tmp/test_jti.db-wal
```
Expected: prints a token length and the jti db path.

- [ ] **Step 3: Commit**

```bash
git add src/illumio_mcp/auth/confirm_init.py
git commit -m "feat(auth): build_confirm_manager_from_env helper"
```

---

## Task 4: Extend `ToolContext` with confirm-related fields

**Files:**
- Modify: `src/illumio_mcp/context.py`
- Modify: `tests/test_context.py`

- [ ] **Step 1: Replace `src/illumio_mcp/context.py` with EXACTLY this:**

```python
"""ToolContext: the per-call object every tool handler receives.

Phase 3d: adds `confirm_manager` and `jti_store`. The dispatcher uses these
to validate the params._meta.confirm_token on `requires_confirm=True` tools
when running over HTTP. Stdio leaves both None and skips the check.
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
    confirm_manager: object | None = None  # auth.confirm.ConfirmTokenManager
    jti_store: object | None = None        # auth.confirm_replay.JtiStore
```

- [ ] **Step 2: Append to `tests/test_context.py`:**

```python


def test_tool_context_confirm_fields_default_none():
    ctx = ToolContext(pce=object(), is_stdio=True)
    assert ctx.confirm_manager is None
    assert ctx.jti_store is None


def test_tool_context_carries_confirm_fields():
    sentinel_mgr = object()
    sentinel_jti = object()
    ctx = ToolContext(
        pce=None, is_stdio=False, user_sub="u", user_iss="i",
        confirm_manager=sentinel_mgr, jti_store=sentinel_jti,
    )
    assert ctx.confirm_manager is sentinel_mgr
    assert ctx.jti_store is sentinel_jti
```

- [ ] **Step 3: Run tests**

```bash
.venv/bin/python3 -m pytest tests/test_context.py -v
```
Expected: all green.

- [ ] **Step 4: Verify stdio still works**

```bash
echo '{"jsonrpc":"2.0","id":0,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"test","version":"0"}}}' | timeout 5 .venv/bin/python3 -m illumio_mcp 2>&1 | head -3
```
Expected: response with `protocolVersion` AND `serverInfo`.

- [ ] **Step 5: Commit**

```bash
git add src/illumio_mcp/context.py tests/test_context.py
git commit -m "feat(context): add confirm_manager and jti_store to ToolContext"
```

---

## Task 5: Dispatcher enforces `requires_confirm`

**Files:**
- Modify: `src/illumio_mcp/server.py`

- [ ] **Step 1: Update `build_http_context_for` to accept the new args**

Replace the function with:

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
) -> ToolContext:
    """Build a ToolContext for one HTTP request."""
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
        # Dev-insecure mode: no keystore, fall back to env-loaded PCE (same as stdio)
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
    )
```

- [ ] **Step 2: Update `handle_call_tool` to enforce confirm tokens**

Find the `handle_call_tool` function. Insert the confirm-token check **after** the requires_pce check but **before** the try-block that invokes the handler:

```python
    # Confirm-token check (Phase 3d) — only enforced over HTTP
    if spec.requires_confirm and not ctx.is_stdio:
        from .auth.confirm import canonical_params_hash, InvalidConfirmTokenError
        meta = (arguments or {}).get("_meta") or {}
        confirm_token = meta.get("confirm_token") if isinstance(meta, dict) else None
        if not confirm_token:
            _audit("denied", "missing_confirm_token")
            return [types.TextContent(type="text", text=json.dumps({
                "error": "confirm_required",
                "message": (
                    f"Tool {name!r} requires a confirm token. "
                    f"POST /confirm with {{\"tool\":\"{name}\",\"params_hash\":\"<sha256>\"}} "
                    "to mint one, then re-call the tool with the token in params._meta.confirm_token."
                ),
                "params_hash": canonical_params_hash({k: v for k, v in (arguments or {}).items() if k != "_meta"}),
            }, indent=2))]
        if ctx.confirm_manager is None or ctx.jti_store is None:
            _audit("denied", "confirm_not_configured")
            return [types.TextContent(type="text", text=json.dumps({
                "error": "server_misconfigured",
                "message": "Confirm-token enforcement is requested but the server has no manager configured.",
            }, indent=2))]
        params_for_hash = {k: v for k, v in (arguments or {}).items() if k != "_meta"}
        try:
            claims = ctx.confirm_manager.verify(
                confirm_token,
                sub=ctx.user_sub or "",
                tool=name,
                params_hash=canonical_params_hash(params_for_hash),
            )
        except InvalidConfirmTokenError as e:
            _audit("denied", f"invalid_confirm_token: {e}")
            return [types.TextContent(type="text", text=json.dumps({
                "error": "invalid_confirm_token",
                "message": str(e),
            }, indent=2))]
        if not ctx.jti_store.mark_used(claims.jti, exp=claims.exp):
            _audit("denied", "confirm_token_replay")
            return [types.TextContent(type="text", text=json.dumps({
                "error": "confirm_token_replay",
                "message": "This confirm token has already been used. Mint a fresh one.",
            }, indent=2))]
```

The check goes **inside** `handle_call_tool`, after the existing PCE-presence block and before `try: t0 = time.monotonic()`. Do not change anything else in the function.

- [ ] **Step 3: Verify imports clean**

```bash
.venv/bin/python3 -c "from illumio_mcp.server import build_http_context_for; ctx = build_http_context_for('s', 'i', None, 'admin', None, 'r', None, None); print('ok, conf_mgr:', ctx.confirm_manager, 'jti:', ctx.jti_store)"
```
Expected: prints `ok, conf_mgr: None jti: None`.

- [ ] **Step 4: Verify stdio still works**

```bash
echo '{"jsonrpc":"2.0","id":0,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"test","version":"0"}}}' | timeout 5 .venv/bin/python3 -m illumio_mcp 2>&1 | head -3
```
Expected: response includes `protocolVersion` AND `serverInfo`.

- [ ] **Step 5: Run unit-test regression**

```bash
.venv/bin/python3 -m pytest tests/ -q --ignore=tests/test_mcp_tools.py 2>&1 | tail -3
```
Expected: all green.

- [ ] **Step 6: Commit**

```bash
git add src/illumio_mcp/server.py
git commit -m "feat(http): enforce confirm tokens for requires_confirm tools"
```

---

## Task 6: `transport/confirm_endpoint.py` — POST /confirm

**Files:**
- Create: `src/illumio_mcp/transport/confirm_endpoint.py`

- [ ] **Step 1: Write the file**

Create `src/illumio_mcp/transport/confirm_endpoint.py`:

```python
"""POST /confirm — mints a single-use confirm token for a mutating tool.

Request:
  POST /confirm
  Authorization: Bearer <jwt>
  Content-Type: application/json
  Body: {"tool": "delete-workload", "params_hash": "<sha256 hex>"}

Response (200):
  {"confirm_token": "<token>", "expires_in": 120}

Errors:
  401  missing/invalid JWT (handled by JWTAuthMiddleware before we run)
  400  body missing "tool" or "params_hash"
  403  fresh-auth required and JWT auth_time too old (only when
       MCP_CONFIRM_FRESH_AUTH_SECONDS is set)
"""
from __future__ import annotations

import json
import os
import time

from starlette.requests import Request
from starlette.responses import JSONResponse, Response
from starlette.routing import Route

from ..auth.confirm import ConfirmTokenManager


def build_confirm_routes(manager: ConfirmTokenManager, audit_log) -> list[Route]:
    fresh_auth_seconds_env = os.getenv("MCP_CONFIRM_FRESH_AUTH_SECONDS")
    fresh_auth_seconds = int(fresh_auth_seconds_env) if fresh_auth_seconds_env else None

    async def post_confirm(request: Request) -> Response:
        user = getattr(request.state, "user", None)
        if user is None:
            return JSONResponse({"error": "unauthorized"}, status_code=401)

        # Optional: enforce that the JWT was issued recently (true step-up).
        # Requires the IdP to issue an `auth_time` claim.
        if fresh_auth_seconds is not None:
            payload_auth_time = getattr(user, "auth_time", None)
            if payload_auth_time is None:
                return JSONResponse({
                    "error": "fresh_auth_required",
                    "message": "Server requires a recent auth_time claim, but the JWT does not include one.",
                }, status_code=403)
            if int(time.time()) - int(payload_auth_time) > fresh_auth_seconds:
                return JSONResponse({
                    "error": "fresh_auth_required",
                    "message": (
                        f"Authentication is too old (max {fresh_auth_seconds}s). "
                        "Re-authenticate and try again."
                    ),
                }, status_code=403)

        try:
            body = await request.json()
        except json.JSONDecodeError:
            return JSONResponse({"error": "invalid_json"}, status_code=400)
        tool = body.get("tool")
        params_hash = body.get("params_hash")
        if not tool or not isinstance(tool, str):
            return JSONResponse({"error": "missing_field", "message": "'tool' is required"}, status_code=400)
        if not params_hash or not isinstance(params_hash, str) or len(params_hash) != 64:
            return JSONResponse(
                {"error": "missing_field", "message": "'params_hash' must be a 64-char sha256 hex string"},
                status_code=400,
            )

        token = manager.mint(sub=user.sub, tool=tool, params_hash=params_hash)
        return JSONResponse({"confirm_token": token, "expires_in": manager._ttl})

    return [Route("/confirm", post_confirm, methods=["POST"])]
```

- [ ] **Step 2: Verify import**

```bash
.venv/bin/python3 -c "from illumio_mcp.transport.confirm_endpoint import build_confirm_routes; print('ok')"
```
Expected: `ok`.

- [ ] **Step 3: Commit**

```bash
git add src/illumio_mcp/transport/confirm_endpoint.py
git commit -m "feat(http): POST /confirm endpoint mints single-use tokens"
```

---

## Task 7: Wire confirm into HTTP transport

**Files:**
- Modify: `src/illumio_mcp/transport/http.py`

- [ ] **Step 1: Replace `src/illumio_mcp/transport/http.py` — add confirm + jti to the build path**

Find the existing imports block and add:
```python
from ..auth.confirm import ConfirmTokenManager, MissingConfirmHmacKeyError
from ..auth.confirm_init import build_confirm_manager_from_env
from ..auth.confirm_replay import NullJtiStore
from .confirm_endpoint import build_confirm_routes
```

Find `_wrap_with_per_request_context`. Update its signature and body to thread the new args:

```python
def _wrap_with_per_request_context(handle_request, keystore, role_config, audit_log, confirm_manager, jti_store):
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
        )
        token = set_http_context(ctx)
        try:
            await handle_request(scope, receive, send)
        finally:
            reset_http_context(token)
    return app
```

Update `_build_app` to take the two new args + mount the route:

```python
def _build_app(
    oauth_config: OAuthConfig | None,
    keystore: object | None,
    role_config: RoleConfig | None,
    audit_log: object | None,
    confirm_manager: object | None,
    jti_store: object | None,
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
        confirm_manager, jti_store,
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
        if confirm_manager is not None:
            routes.extend(build_confirm_routes(confirm_manager, audit_log))

        validator = JWTValidator(oauth_config)
        middleware.append(Middleware(JWTAuthMiddleware, validator=validator, config=oauth_config))
    else:
        logger.warning("MCP_DEV_INSECURE=1: HTTP server starting WITHOUT auth. Do not use in production.")

    return Starlette(debug=False, routes=routes, lifespan=lifespan, middleware=middleware)
```

Update `serve_http` to load the confirm manager + jti store in auth mode and pass them through:

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
        try:
            confirm_manager, jti_store = build_confirm_manager_from_env()
        except MissingConfirmHmacKeyError as e:
            raise SystemExit(str(e))

    app = _build_app(oauth_config, keystore, role_config, audit_log, confirm_manager, jti_store)
    extras = []
    if oauth_config is None:
        extras.append("DEV-INSECURE: no auth, no keystore, admin role, no confirm")
    logger.info(f"Starting HTTP transport on http://{host}:{port}/mcp"
                + (f"  [{'; '.join(extras)}]" if extras else ""))
    uvicorn.run(app, host=host, port=port, log_level="info")
```

- [ ] **Step 2: Update `tests/test_http_transport.py` for the new signature**

The existing call is `_build_app(None, None, None, NullAuditLog())`. Update to `_build_app(None, None, None, NullAuditLog(), None, None)`.

Find the line:
```python
    config = uvicorn.Config(_build_app(None, None, None, NullAuditLog()), host="127.0.0.1", port=port, log_level="warning")
```
Replace with:
```python
    config = uvicorn.Config(_build_app(None, None, None, NullAuditLog(), None, None), host="127.0.0.1", port=port, log_level="warning")
```

- [ ] **Step 3: Verify dev-insecure builds**

```bash
MCP_DEV_INSECURE=1 .venv/bin/python3 -c "
from illumio_mcp.transport.http import _build_app
from illumio_mcp.auth.audit import NullAuditLog
app = _build_app(None, None, None, NullAuditLog(), None, None)
print('routes (dev):', sorted([getattr(r, 'path', '?') for r in app.routes]))
"
```
Expected: `routes (dev): ['/healthz', '/mcp', '/readyz']`.

- [ ] **Step 4: Verify auth path builds with confirm**

```bash
unset MCP_DEV_INSECURE
MCP_OAUTH_ISSUER=https://idp.test/o \
MCP_OAUTH_JWKS_URL=https://idp.test/o/.well-known/jwks.json \
MCP_OAUTH_AUDIENCE=mcp.test \
MCP_PUBLIC_URL=http://127.0.0.1 \
MCP_KEK=$(.venv/bin/python3 -c "import os, base64; print(base64.b64encode(os.urandom(32)).decode())") \
MCP_KEYSTORE_PATH=/tmp/test_p3d.db \
MCP_AUDIT_LOG_PATH=/tmp/test_p3d_audit.db \
MCP_ROLE_GROUPS_ADMIN=sg-admin \
MCP_CONFIRM_HMAC_KEY=$(.venv/bin/python3 -c "import os, base64; print(base64.b64encode(os.urandom(32)).decode())") \
MCP_CONFIRM_JTI_PATH=/tmp/test_p3d_jti.db \
  .venv/bin/python3 -c "
from illumio_mcp.transport.http import _build_app
from illumio_mcp.auth.config import load_oauth_config_from_env
from illumio_mcp.auth.keystore_init import build_keystore_from_env
from illumio_mcp.auth.audit_init import build_audit_log_from_env
from illumio_mcp.auth.roles import load_role_config_from_env
from illumio_mcp.auth.confirm_init import build_confirm_manager_from_env
mgr, jti = build_confirm_manager_from_env()
app = _build_app(
    load_oauth_config_from_env(),
    build_keystore_from_env(),
    load_role_config_from_env(),
    build_audit_log_from_env(),
    mgr, jti,
)
print('routes (auth):', sorted([getattr(r, 'path', '?') for r in app.routes]))
" && rm -f /tmp/test_p3d.db* /tmp/test_p3d_audit.db* /tmp/test_p3d_jti.db*
```
Expected: routes include `/confirm` (along with /mcp, /setup x2, /healthz, /readyz, /.well-known/oauth-protected-resource).

- [ ] **Step 5: Verify stdio**

```bash
echo '{"jsonrpc":"2.0","id":0,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"test","version":"0"}}}' | timeout 5 .venv/bin/python3 -m illumio_mcp 2>&1 | head -3
```
Expected: `protocolVersion` AND `serverInfo`.

- [ ] **Step 6: Run test_http_transport.py to confirm fix works**

```bash
.venv/bin/python3 -m pytest tests/test_http_transport.py -v 2>&1 | tail -10
```
Expected: 5 PASSED.

- [ ] **Step 7: Commit**

```bash
git add src/illumio_mcp/transport/http.py tests/test_http_transport.py
git commit -m "feat(http): wire confirm manager + jti store + /confirm route"
```

---

## Task 8: End-to-end confirm flow test

**Files:**
- Create: `tests/test_http_confirm.py`

- [ ] **Step 1: Write the test**

Create `tests/test_http_confirm.py`:

```python
"""End-to-end: confirm-token enforcement on requires_confirm tools.

Verifies:
  - Calling provision-policy without a token → confirm_required error
  - POST /confirm mints a token
  - Calling provision-policy WITH the token → handler runs (gets PCE error since
    we stub PCE to raise — proves we got past the dispatcher gate)
  - Replaying the token → confirm_token_replay error
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
from illumio_mcp.auth.audit import NullAuditLog
from illumio_mcp.auth.roles import RoleConfig
from illumio_mcp.auth.confirm import ConfirmTokenManager, generate_hmac_key, canonical_params_hash
from illumio_mcp.auth.confirm_replay import SQLiteJtiStore
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
    from illumio_mcp.transport.confirm_endpoint import build_confirm_routes
    from illumio_mcp.auth.roles import map_user_role
    import illumio_mcp.pce as pce_mod

    class FakePCE:
        def __init__(self, host):
            self.host = host
        # Provisioning + ringfence handlers will hit attribute methods on this
        # — we don't care about the result. We only want to verify the dispatcher
        # let the call through.

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
    audit = NullAuditLog()
    role_config = RoleConfig(
        admin_groups=["sg-admin"],
        operator_groups=["sg-op", "sg-admin"],
        reader_groups=["sg-read", "sg-op", "sg-admin"],
        default_role=None,
    )
    confirm_manager = ConfirmTokenManager(generate_hmac_key(), ttl_seconds=120)
    jti_store = SQLiteJtiStore(db_path=str(tmp_path_factory.mktemp("jti") / "jti.db"))

    creds = PCECredentials(host="https://pce.example", port=8443, org_id=1, api_key="k", api_secret="s")
    keystore.put(sub="alice", iss="https://idp.test/o", creds=creds)

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
        ctx = build_http_context_for(
            sub, iss, keystore, role, audit, request_id,
            confirm_manager=confirm_manager, jti_store=jti_store,
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

    routes = [
        Mount("/mcp", app=mcp_handler_wrapper),
        Route("/healthz", healthz, methods=["GET"]),
        *build_confirm_routes(confirm_manager, audit),
    ]

    app = Starlette(
        routes=routes,
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

    yield f"http://127.0.0.1:{port}", confirm_manager

    server.should_exit = True
    thread.join(timeout=5)
    pce_mod.build_pce_for = original_build


async def test_provision_policy_without_token_is_denied(http_server, private_key_pem):
    from mcp import ClientSession
    from mcp.client.streamable_http import streamablehttp_client

    url, _ = http_server
    token = _mint(private_key_pem, sub="alice", groups=["sg-admin"])
    async with streamablehttp_client(f"{url}/mcp", headers={"Authorization": f"Bearer {token}"}) as (read, write, _):
        async with ClientSession(read, write) as session:
            await session.initialize()
            result = await session.call_tool("provision-policy", {"description": "test"})
            body = json.loads(result.content[0].text)
            assert body["error"] == "confirm_required"
            # The dispatcher should have computed the params_hash for us.
            assert "params_hash" in body
            assert len(body["params_hash"]) == 64


async def test_post_confirm_mints_token(http_server, private_key_pem):
    url, _ = http_server
    jwt_token = _mint(private_key_pem, sub="alice", groups=["sg-admin"])
    body_in = json.dumps({"tool": "provision-policy", "params_hash": "h" * 64}).encode()
    req = urllib.request.Request(
        f"{url}/confirm",
        method="POST",
        data=body_in,
        headers={"Authorization": f"Bearer {jwt_token}", "Content-Type": "application/json"},
    )
    with urllib.request.urlopen(req) as resp:
        assert resp.status == 200
        body = json.loads(resp.read())
        assert body["confirm_token"]
        assert body["expires_in"] == 120


async def test_provision_with_valid_token_passes_dispatcher(http_server, private_key_pem):
    """Mints a token for specific params, then calls the tool with that token.
    The handler will fail (FakePCE doesn't really provision), but the failure
    should be a tool-level error, NOT a confirm-related dispatcher rejection."""
    from mcp import ClientSession
    from mcp.client.streamable_http import streamablehttp_client

    url, _ = http_server
    jwt_token = _mint(private_key_pem, sub="alice", groups=["sg-admin"])

    # The arguments we'll send to provision-policy
    args = {"description": "phase-3d-test"}
    params_hash = canonical_params_hash(args)

    # Mint the token
    body_in = json.dumps({"tool": "provision-policy", "params_hash": params_hash}).encode()
    req = urllib.request.Request(
        f"{url}/confirm",
        method="POST",
        data=body_in,
        headers={"Authorization": f"Bearer {jwt_token}", "Content-Type": "application/json"},
    )
    with urllib.request.urlopen(req) as resp:
        confirm_token = json.loads(resp.read())["confirm_token"]

    # Call the tool with the token
    args_with_meta = {**args, "_meta": {"confirm_token": confirm_token}}
    async with streamablehttp_client(f"{url}/mcp", headers={"Authorization": f"Bearer {jwt_token}"}) as (read, write, _):
        async with ClientSession(read, write) as session:
            await session.initialize()
            result = await session.call_tool("provision-policy", args_with_meta)
            body = json.loads(result.content[0].text)
            # The dispatcher must have let us through. Tool-level errors are fine.
            assert body.get("error") not in ("confirm_required", "invalid_confirm_token", "confirm_token_replay")


async def test_replay_of_confirm_token_is_denied(http_server, private_key_pem):
    from mcp import ClientSession
    from mcp.client.streamable_http import streamablehttp_client

    url, _ = http_server
    jwt_token = _mint(private_key_pem, sub="alice", groups=["sg-admin"])

    args = {"description": "replay-test"}
    params_hash = canonical_params_hash(args)
    body_in = json.dumps({"tool": "provision-policy", "params_hash": params_hash}).encode()
    req = urllib.request.Request(
        f"{url}/confirm",
        method="POST",
        data=body_in,
        headers={"Authorization": f"Bearer {jwt_token}", "Content-Type": "application/json"},
    )
    with urllib.request.urlopen(req) as resp:
        confirm_token = json.loads(resp.read())["confirm_token"]

    args_with_meta = {**args, "_meta": {"confirm_token": confirm_token}}

    # First use: passes the dispatcher gate
    async with streamablehttp_client(f"{url}/mcp", headers={"Authorization": f"Bearer {jwt_token}"}) as (read, write, _):
        async with ClientSession(read, write) as session:
            await session.initialize()
            await session.call_tool("provision-policy", args_with_meta)

    # Replay: dispatcher should refuse before the handler runs
    async with streamablehttp_client(f"{url}/mcp", headers={"Authorization": f"Bearer {jwt_token}"}) as (read, write, _):
        async with ClientSession(read, write) as session:
            await session.initialize()
            result = await session.call_tool("provision-policy", args_with_meta)
            body = json.loads(result.content[0].text)
            assert body["error"] == "confirm_token_replay"
```

- [ ] **Step 2: Run the test**

```bash
.venv/bin/python3 -m pytest tests/test_http_confirm.py -v 2>&1 | tail -30
```
Expected: 4 PASSED.

- [ ] **Step 3: Commit**

```bash
git add tests/test_http_confirm.py
git commit -m "test: end-to-end confirm-token enforcement (mint, use, replay)"
```

---

## Task 9: README — document confirm tokens

**Files:**
- Modify: `README.md`

- [ ] **Step 1: Append after the "Audit log" subsection**

```markdown
### Confirm tokens for mutating tools (Phase 3d)

Tools marked `requires_confirm=True` (currently `provision-policy`,
`ringfence-batch`, `register-pce-credentials`, `delete-pce-credentials`) require
a server-issued single-use confirm token in `params._meta.confirm_token` when
called over HTTP. Stdio mode is unaffected — the operator who launched the
process can call mutating tools directly.

Required env in auth mode:

```bash
export MCP_CONFIRM_HMAC_KEY=$(python -c 'import os, base64; print(base64.b64encode(os.urandom(32)).decode())')
# Optional:
# export MCP_CONFIRM_TTL_SECONDS=120
# export MCP_CONFIRM_JTI_PATH=/var/lib/illumio-mcp/jti.db
# export MCP_CONFIRM_FRESH_AUTH_SECONDS=300   # require JWT auth_time within 5 min
```

#### How a client uses it

1. Call the mutating tool without a token → server returns:
   ```json
   {"error": "confirm_required", "params_hash": "<sha256>", "message": "..."}
   ```
2. Call `POST /confirm` with the JWT and the params_hash:
   ```bash
   curl -X POST https://mcp.illumio.example/confirm \
     -H "Authorization: Bearer $JWT" \
     -H "Content-Type: application/json" \
     -d '{"tool":"provision-policy","params_hash":"<sha256>"}'
   # → {"confirm_token": "...", "expires_in": 120}
   ```
3. Re-call the tool with the token in `params._meta.confirm_token`.

Tokens are **single-use** (replays return `confirm_token_replay`) and **scoped**
to `(sub, tool, params_hash)`. Tampering with any field invalidates the token.

#### Step-up auth (optional, recommended for production)

Set `MCP_CONFIRM_FRESH_AUTH_SECONDS=300` to require the JWT's `auth_time`
claim to be within the last 5 minutes. Forces the user to re-authenticate
before minting a token — the strongest prompt-injection defense available
without an interactive session model. Requires the IdP to issue `auth_time`
(Entra and Okta both do for OIDC sign-in flows).
```

- [ ] **Step 2: Commit**

```bash
git add README.md
git commit -m "docs: confirm tokens for mutating tools (Phase 3d)"
```

---

## Task 10: Open PR

- [ ] **Step 1: Push the branch**

```bash
git push -u origin feature/confirm-tokens
```

- [ ] **Step 2: Open the PR**

```bash
gh pr create --base feature/role-authz-and-audit --title "feat: confirm tokens for mutating tools (Phase 3d)" --body "$(cat <<'EOF'
## Summary

Phase 3d completes the multi-user rollout. Tools marked `requires_confirm=True` now require a server-issued single-use HMAC token in `params._meta.confirm_token` when called over HTTP. Tokens are minted by `POST /confirm` after the user re-asserts intent. Stdio is unchanged — the operator who launched the process can call mutating tools directly.

> **Stacked on #14 (Phase 3c).** When #14 merges, base auto-updates.

## What changed

- **`auth/confirm.py`**: `ConfirmTokenManager` mints + verifies HMAC-SHA256 tokens scoped to `(sub, tool, params_hash, jti, exp)`. `canonical_params_hash` provides a stable SHA-256 over a sorted-keys JSON serialization so client and server agree on the params hash.
- **`auth/confirm_replay.py`**: `SQLiteJtiStore` records every accepted `jti` so replays are rejected even within TTL. `NullJtiStore` for stdio.
- **`auth/confirm_init.py`**: `build_confirm_manager_from_env` reads `MCP_CONFIRM_HMAC_KEY`, `MCP_CONFIRM_TTL_SECONDS`, `MCP_CONFIRM_JTI_PATH`.
- **`transport/confirm_endpoint.py`**: `POST /confirm` mints tokens. Optionally enforces `auth_time` freshness via `MCP_CONFIRM_FRESH_AUTH_SECONDS` for true step-up.
- **`ToolContext`** gains `confirm_manager` + `jti_store`.
- **Dispatcher** (`server.py`): for `requires_confirm=True` tools, requires `params._meta.confirm_token`, verifies it, marks the jti as used. Returns structured `confirm_required` / `invalid_confirm_token` / `confirm_token_replay` errors. Audit log records every dispatch decision as before.
- **`transport/http.py`**: builds confirm manager + jti store at startup; mounts `/confirm` route; threads both into per-request context.

## Test plan

- [x] `pytest tests/test_auth_confirm.py -v` — 12 passed (mint/verify happy path, every failure mode, params hash stability, env loader)
- [x] `pytest tests/test_auth_confirm_replay.py -v` — 6 passed (CRUD, replay rejection, expiry purge, file perms)
- [x] `pytest tests/test_http_confirm.py -v` — 4 passed end-to-end (no-token denied, /confirm mints, valid token passes dispatcher, replay denied)
- [x] All Phase 1–3c tests still green
- [x] Stdio sanity check after every transport-touching commit (full JSON-RPC handshake with protocolVersion + serverInfo)

## What this PR does NOT do

Possible Phase 4 work:
- Per-user scope filters (label/app restrictions). The `unscopable=True` flag exists but is not enforced.
- Vault/KMS-backed KeyStore + ConfirmHmacKey driver (currently env-only).
- Stateful Streamable HTTP sessions (we use `stateless=True` — fine for v1, but limits server→client notifications).

🤖 Generated with [Claude Code](https://claude.com/claude-code)
EOF
)"
```

- [ ] **Step 3: Print the PR URL**

---

## Self-review checklist

- [x] **Spec coverage:** §5 Layer 5 (confirm tokens for mutating tools) → Tasks 1, 2, 3, 5, 6. `/confirm` endpoint → Task 6. Replay rejection via jti → Task 2. Audit-log integration for confirm decisions → Task 5 (uses existing `_audit()` from Phase 3c).
- [x] **Placeholders:** None.
- [x] **Type consistency:** `ConfirmTokenManager(hmac_key, ttl_seconds)` defined Task 1, used Tasks 5, 6, 7, 8. `mint(sub, tool, params_hash) → str` and `verify(token, sub, tool, params_hash) → ConfirmTokenClaims` consistent across all callers. `canonical_params_hash(params)` defined Task 1, used in Task 5 dispatcher and Task 8 tests. `JtiStore.mark_used(jti, exp) → bool` defined Task 2, called in Task 5 dispatcher.
- [x] **Stdio invariants:** Tasks 4, 5, 7 each have explicit stdio handshake check.
- [x] **No new dependencies.**
- [x] **No tool args in audit log:** Dispatcher records `params_hash` (already not the args themselves); tool args never written.
- [x] **HMAC key never logged:** Crypto module + audit module both isolated from logging paths.
