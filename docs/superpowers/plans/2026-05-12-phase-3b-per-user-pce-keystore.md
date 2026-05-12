# Phase 3b: Per-User PCE Keystore + Onboarding — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Store PCE credentials per authenticated user in a SQLite keystore with envelope encryption, build the per-request PCE client from those creds, and let users onboard via either an MCP tool (`register-pce-credentials`) or a browser endpoint (`/setup`). After this phase, each authenticated user uses their own PCE API key — PCE-side audit logs attribute correctly per human, and revoking a user is a single row delete.

**Architecture:** New `auth/crypto.py` provides envelope-encryption primitives (AES-256-GCM data key wrapped by a KEK loaded from `MCP_KEK` env var). New `auth/keystore.py` defines a `KeyStore` protocol and a `SQLiteKeyStore` driver that persists encrypted `PCECredentials` rows keyed by `(user_sub, user_iss)`. The HTTP context builder in `server.py` now looks up the user's creds; if absent, it returns a `NoCredentialsError` ToolContext that the dispatcher uses to permit only credential-management tools. Two new tools (`register-pce-credentials`, `delete-pce-credentials`) live in `tools/credentials.py` and are marked `requires_pce=False` on `ToolSpec`. A small `/setup` HTML form lets users onboard without leaving the browser. Stdio is unchanged.

**Tech Stack:** `cryptography` (already a transitive dep via PyJWT[crypto]), Python `sqlite3` stdlib. No new dependencies.

**Spec:** [`docs/superpowers/specs/2026-05-12-http-transport-and-auth-design.md`](../specs/2026-05-12-http-transport-and-auth-design.md) §3.1 (credential model), §4 (per-user PCE storage), §6 (code restructuring).

**Branch:** `feature/per-user-pce-keystore` off `feature/oauth-resource-server` (or `main` if Phase 3a is merged).

---

## Working agreement

- Phase 3a invariants: `/healthz`, `/readyz`, `/.well-known/oauth-protected-resource` stay unauth; `/mcp` requires Bearer; stdio unchanged. Verify after every commit that touches transport.
- The KEK is loaded once at startup from `MCP_KEK` env var (32 bytes, base64-encoded). If absent AND `MCP_DEV_INSECURE` is not set, the HTTP server refuses to start.
- KeyStore writes are crash-safe: SQLite WAL mode, single-row transactions.
- Encrypted material is **never** logged. Error messages mention the user `sub` and a generic "decryption failed" — no plaintext leakage.
- Stdio mode never reads the keystore — it uses `get_pce_from_env()` exactly as before.
- One commit per task.

---

## File structure

| File | Responsibility |
|---|---|
| `src/illumio_mcp/auth/crypto.py` (new) | `EnvelopeCipher`: AES-256-GCM + per-row data key wrapped by KEK; `load_kek_from_env()` |
| `src/illumio_mcp/auth/keystore.py` (new) | `KeyStore` Protocol + `SQLiteKeyStore` driver; CRUD on `(sub, iss) -> PCECredentials` |
| `src/illumio_mcp/auth/keystore_init.py` (new) | `build_keystore_from_env()`: opens SQLite at `MCP_KEYSTORE_PATH`, runs DDL, returns SQLiteKeyStore wired with the KEK envelope |
| `src/illumio_mcp/context.py` (modify) | Make `pce` `Optional`; add `keystore: object | None = None` |
| `src/illumio_mcp/registry.py` (modify) | Add `requires_pce: bool = True` field to `ToolSpec` |
| `src/illumio_mcp/server.py` (modify) | New `NoCredentialsError`; `build_http_context_for(user_sub, user_iss, keystore)` looks up creds, returns ctx with `pce=None` when missing |
| `src/illumio_mcp/server.py` (modify) | Dispatcher: if `ctx.pce is None` AND `spec.requires_pce`, return structured "no_pce_credentials" error pointing at `/setup` |
| `src/illumio_mcp/tools/credentials.py` (new) | `handle_register_pce_credentials`, `handle_delete_pce_credentials`, `handle_check_pce_credentials_status` |
| `src/illumio_mcp/tools/__init__.py` (modify) | Register the three new tools (with `requires_pce=False`) |
| `src/illumio_mcp/transport/http.py` (modify) | Build keystore at startup; pass into per-request context builder; mount `/setup` GET+POST |
| `src/illumio_mcp/transport/setup_page.py` (new) | Tiny inline-HTML form + handler; no Jinja, no template dir |
| `tests/test_auth_crypto.py` (new) | EnvelopeCipher round-trip + tampering rejection |
| `tests/test_auth_keystore.py` (new) | SQLiteKeyStore CRUD + duplicate handling + non-existent reads |
| `tests/test_credentials_tools.py` (new) | The three new tool handlers (using a fake keystore) |
| `tests/test_http_per_user.py` (new) | End-to-end: user with no creds → no_pce_credentials error; register via tool → subsequent tool calls succeed |
| `README.md` (modify) | Add "Per-user PCE keys" subsection with KEK env var + `/setup` URL |

---

## Task 0: Create the working branch

**Files:** git only

- [ ] **Step 1: Branch**

```bash
git checkout feature/oauth-resource-server
git pull --ff-only origin feature/oauth-resource-server
git checkout -b feature/per-user-pce-keystore
```

If both Phase 3a and earlier are merged to main, branch from main.

- [ ] **Step 2: Verify clean baseline**

```bash
git status                                                     # clean
.venv/bin/python3 -m pytest tests/test_auth_config.py tests/test_auth_jwt_validator.py tests/test_auth_prm.py tests/test_http_auth.py tests/test_context.py tests/test_registry.py tests/test_pce_builder.py tests/test_tool_metadata.py -q
```
Expected: all green (Phase 3a tests).

- [ ] **Step 3: Verify cryptography is available**

```bash
.venv/bin/python3 -c "from cryptography.hazmat.primitives.ciphers.aead import AESGCM; from secrets import token_bytes; print('crypto ok')"
```
Expected: `crypto ok`. (`cryptography` is a transitive dep of `pyjwt[crypto]` from Phase 3a — no new dep needed.)

---

## Task 1: `auth/crypto.py` — Envelope encryption

Two-tier crypto: each record gets a fresh 32-byte AES-256 data key (DK). The DK is itself wrapped by the KEK (Key-Encryption-Key). Storage: `nonce_dk || dk_ciphertext || nonce_payload || payload_ciphertext`. To rotate the KEK we re-wrap data keys without re-encrypting payloads.

**Files:**
- Create: `src/illumio_mcp/auth/crypto.py`
- Create: `tests/test_auth_crypto.py`

- [ ] **Step 1: Write the failing tests**

Create `tests/test_auth_crypto.py`:

```python
"""Tests for envelope encryption used by the keystore."""
import os
import base64
import pytest

from illumio_mcp.auth.crypto import EnvelopeCipher, generate_kek, load_kek_from_env, MissingKEKError


def test_round_trip():
    kek = generate_kek()
    cipher = EnvelopeCipher(kek)
    blob = cipher.encrypt(b"PCE_API_SECRET_xyz_42", aad=b"user-42|https://idp.test/o")
    plaintext = cipher.decrypt(blob, aad=b"user-42|https://idp.test/o")
    assert plaintext == b"PCE_API_SECRET_xyz_42"


def test_decrypt_with_wrong_aad_fails():
    kek = generate_kek()
    cipher = EnvelopeCipher(kek)
    blob = cipher.encrypt(b"secret", aad=b"correct-aad")
    with pytest.raises(Exception):
        cipher.decrypt(blob, aad=b"wrong-aad")


def test_decrypt_with_wrong_kek_fails():
    cipher_a = EnvelopeCipher(generate_kek())
    cipher_b = EnvelopeCipher(generate_kek())
    blob = cipher_a.encrypt(b"secret", aad=b"x")
    with pytest.raises(Exception):
        cipher_b.decrypt(blob, aad=b"x")


def test_tampered_ciphertext_rejected():
    kek = generate_kek()
    cipher = EnvelopeCipher(kek)
    blob = bytearray(cipher.encrypt(b"secret", aad=b"x"))
    # Flip a byte deep inside the ciphertext
    blob[-5] ^= 0x01
    with pytest.raises(Exception):
        cipher.decrypt(bytes(blob), aad=b"x")


def test_each_encryption_uses_a_fresh_data_key_and_nonce():
    """Two encrypts of the same plaintext + AAD produce different ciphertexts."""
    kek = generate_kek()
    cipher = EnvelopeCipher(kek)
    a = cipher.encrypt(b"same", aad=b"x")
    b = cipher.encrypt(b"same", aad=b"x")
    assert a != b


def test_load_kek_from_env_happy_path(monkeypatch):
    raw = os.urandom(32)
    monkeypatch.setenv("MCP_KEK", base64.b64encode(raw).decode())
    kek = load_kek_from_env()
    assert kek == raw


def test_load_kek_from_env_missing_raises(monkeypatch):
    monkeypatch.delenv("MCP_KEK", raising=False)
    with pytest.raises(MissingKEKError):
        load_kek_from_env()


def test_load_kek_from_env_wrong_length_raises(monkeypatch):
    monkeypatch.setenv("MCP_KEK", base64.b64encode(b"only-16-bytes-aaa").decode())
    with pytest.raises(ValueError, match="32"):
        load_kek_from_env()
```

- [ ] **Step 2: Run test to verify it fails**

```bash
.venv/bin/python3 -m pytest tests/test_auth_crypto.py -v
```
Expected: ImportError on `illumio_mcp.auth.crypto`.

- [ ] **Step 3: Implement `auth/crypto.py`**

Create `src/illumio_mcp/auth/crypto.py`:

```python
"""Envelope encryption for the per-user PCE keystore.

Two-tier:
  - Each record has a fresh 32-byte AES-256 data key (DK).
  - The DK is encrypted ("wrapped") by the KEK loaded from MCP_KEK at startup.

Wire format (single bytes blob):
  nonce_dk(12) || dk_ciphertext(48) || nonce_payload(12) || payload_ciphertext(N+16)
                                                            \-- includes GCM tag --/

Both layers use AES-256-GCM with AAD binding. Tampering anywhere is detected.

KEK rotation is not implemented in this phase but the layout supports it: rotate
KEK, re-wrap each row's `dk_ciphertext` (no payload re-encryption needed).
"""
from __future__ import annotations

import base64
import os
from secrets import token_bytes

from cryptography.hazmat.primitives.ciphers.aead import AESGCM


class MissingKEKError(RuntimeError):
    """Raised when MCP_KEK is not set and DEV_INSECURE is off."""


_KEY_BYTES = 32      # AES-256
_NONCE_BYTES = 12    # standard for GCM


def generate_kek() -> bytes:
    """Return 32 random bytes suitable for use as a KEK."""
    return token_bytes(_KEY_BYTES)


def load_kek_from_env() -> bytes:
    """Read base64-encoded 32-byte KEK from MCP_KEK. Raise on absence or wrong length."""
    raw = os.getenv("MCP_KEK")
    if not raw:
        raise MissingKEKError(
            "MCP_KEK env var is required (32-byte base64 KEK). "
            "Generate with: python -c 'import os, base64; print(base64.b64encode(os.urandom(32)).decode())'"
        )
    try:
        kek = base64.b64decode(raw)
    except Exception as e:
        raise ValueError(f"MCP_KEK is not valid base64: {e}") from e
    if len(kek) != _KEY_BYTES:
        raise ValueError(f"MCP_KEK must decode to exactly 32 bytes, got {len(kek)}")
    return kek


class EnvelopeCipher:
    """AES-256-GCM envelope cipher. Stateless after construction."""

    def __init__(self, kek: bytes):
        if len(kek) != _KEY_BYTES:
            raise ValueError(f"KEK must be {_KEY_BYTES} bytes, got {len(kek)}")
        self._kek = AESGCM(kek)

    def encrypt(self, plaintext: bytes, *, aad: bytes) -> bytes:
        """Encrypt with a fresh data key, wrap the data key under KEK, return the
        single concatenated blob."""
        dk = token_bytes(_KEY_BYTES)
        nonce_dk = token_bytes(_NONCE_BYTES)
        dk_ciphertext = self._kek.encrypt(nonce_dk, dk, aad)

        nonce_payload = token_bytes(_NONCE_BYTES)
        payload_ciphertext = AESGCM(dk).encrypt(nonce_payload, plaintext, aad)
        return nonce_dk + dk_ciphertext + nonce_payload + payload_ciphertext

    def decrypt(self, blob: bytes, *, aad: bytes) -> bytes:
        """Inverse of `encrypt`. Raises on any integrity failure."""
        # Layout: 12 + 48 + 12 + (N+16). We know dk_ciphertext is 48 bytes
        # (32-byte DK + 16-byte GCM tag).
        if len(blob) < _NONCE_BYTES + 48 + _NONCE_BYTES + 16:
            raise ValueError("ciphertext too short")
        nonce_dk = blob[:_NONCE_BYTES]
        dk_ciphertext = blob[_NONCE_BYTES:_NONCE_BYTES + 48]
        nonce_payload = blob[_NONCE_BYTES + 48:_NONCE_BYTES + 48 + _NONCE_BYTES]
        payload_ciphertext = blob[_NONCE_BYTES + 48 + _NONCE_BYTES:]
        dk = self._kek.decrypt(nonce_dk, dk_ciphertext, aad)
        return AESGCM(dk).decrypt(nonce_payload, payload_ciphertext, aad)
```

- [ ] **Step 4: Run tests**

```bash
.venv/bin/python3 -m pytest tests/test_auth_crypto.py -v
```
Expected: 8 PASSED.

- [ ] **Step 5: Commit**

```bash
git add src/illumio_mcp/auth/crypto.py tests/test_auth_crypto.py
git commit -m "feat(auth): EnvelopeCipher (AES-256-GCM with wrapped data keys)"
```

---

## Task 2: `auth/keystore.py` — KeyStore protocol + SQLiteKeyStore

The keystore reuses `PCECredentials` from `pce.py` (defined in Phase 1). The `(sub, iss)` pair forms the row key — using both is "multi-IdP safe."

**Files:**
- Create: `src/illumio_mcp/auth/keystore.py`
- Create: `tests/test_auth_keystore.py`

- [ ] **Step 1: Write the failing tests**

Create `tests/test_auth_keystore.py`:

```python
"""Tests for SQLiteKeyStore CRUD."""
import os
import sqlite3
import tempfile

import pytest

from illumio_mcp.auth.crypto import EnvelopeCipher, generate_kek
from illumio_mcp.auth.keystore import SQLiteKeyStore
from illumio_mcp.pce import PCECredentials


@pytest.fixture
def keystore(tmp_path):
    db_path = str(tmp_path / "keys.db")
    cipher = EnvelopeCipher(generate_kek())
    return SQLiteKeyStore(db_path=db_path, cipher=cipher)


def _creds():
    return PCECredentials(
        host="https://pce.example",
        port=8443,
        org_id=1,
        api_key="api_key_xyz",
        api_secret="api_secret_abc",
        tls_verify=True,
    )


def test_get_returns_none_for_unknown_user(keystore):
    assert keystore.get(sub="nobody", iss="https://idp.test/o") is None


def test_put_then_get_round_trip(keystore):
    creds = _creds()
    keystore.put(sub="alice", iss="https://idp.test/o", creds=creds)
    fetched = keystore.get(sub="alice", iss="https://idp.test/o")
    assert fetched == creds


def test_put_overwrites_existing(keystore):
    keystore.put(sub="alice", iss="https://idp.test/o", creds=_creds())
    new_creds = PCECredentials(
        host="https://pce.example",
        port=8443,
        org_id=2,                    # different org
        api_key="new_key",
        api_secret="new_secret",
        tls_verify=True,
    )
    keystore.put(sub="alice", iss="https://idp.test/o", creds=new_creds)
    fetched = keystore.get(sub="alice", iss="https://idp.test/o")
    assert fetched == new_creds
    # Only one row exists for this (sub, iss)
    assert keystore.count_for(sub="alice", iss="https://idp.test/o") == 1


def test_delete_removes_row(keystore):
    keystore.put(sub="alice", iss="https://idp.test/o", creds=_creds())
    assert keystore.delete(sub="alice", iss="https://idp.test/o") is True
    assert keystore.get(sub="alice", iss="https://idp.test/o") is None


def test_delete_missing_returns_false(keystore):
    assert keystore.delete(sub="ghost", iss="https://idp.test/o") is False


def test_users_with_same_sub_different_iss_are_isolated(keystore):
    keystore.put(sub="alice", iss="https://idp1.test/o", creds=_creds())
    keystore.put(sub="alice", iss="https://idp2.test/o", creds=PCECredentials(
        host="https://other.pce", port=443, org_id=99, api_key="k", api_secret="s",
    ))
    assert keystore.get(sub="alice", iss="https://idp1.test/o").org_id == 1
    assert keystore.get(sub="alice", iss="https://idp2.test/o").org_id == 99


def test_decryption_failure_raises_on_get(keystore, tmp_path):
    """Tamper with a stored row and verify the keystore raises on read."""
    keystore.put(sub="alice", iss="https://idp.test/o", creds=_creds())
    db_path = keystore.db_path
    with sqlite3.connect(db_path) as con:
        # Flip a byte in api_secret_enc
        row = con.execute("SELECT api_secret_enc FROM user_pce_credentials WHERE sub='alice'").fetchone()
        tampered = bytearray(row[0])
        tampered[-3] ^= 0x01
        con.execute("UPDATE user_pce_credentials SET api_secret_enc=? WHERE sub='alice'", (bytes(tampered),))
    with pytest.raises(Exception):
        keystore.get(sub="alice", iss="https://idp.test/o")


def test_db_file_created_with_sane_perms(keystore):
    """The SQLite DB should not be world-readable."""
    mode = os.stat(keystore.db_path).st_mode & 0o777
    assert mode & 0o077 == 0, f"db file is world/group-readable: {oct(mode)}"
```

- [ ] **Step 2: Run test to verify it fails**

```bash
.venv/bin/python3 -m pytest tests/test_auth_keystore.py -v
```
Expected: ImportError on `illumio_mcp.auth.keystore`.

- [ ] **Step 3: Implement `auth/keystore.py`**

Create `src/illumio_mcp/auth/keystore.py`:

```python
"""KeyStore: persistent storage for per-user PCE credentials.

Phase 3b ships a single SQLite-backed driver. Phase 3 (later) may add a Vault
or KMS-backed driver behind the same Protocol — adding a new driver does not
require touching the dispatcher.
"""
from __future__ import annotations

import os
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Protocol

from ..pce import PCECredentials
from .crypto import EnvelopeCipher


_SCHEMA = """
CREATE TABLE IF NOT EXISTS user_pce_credentials (
    sub               TEXT NOT NULL,
    iss               TEXT NOT NULL,
    pce_host          TEXT NOT NULL,
    pce_port          INTEGER NOT NULL,
    pce_org_id        INTEGER NOT NULL,
    api_key_enc       BLOB NOT NULL,
    api_secret_enc    BLOB NOT NULL,
    tls_verify        INTEGER NOT NULL,
    created_at        TEXT NOT NULL,
    last_used_at      TEXT,
    label             TEXT,
    PRIMARY KEY (sub, iss)
);
"""


def _aad(sub: str, iss: str) -> bytes:
    """AAD binds a row's ciphertext to its (sub, iss) — swapping rows breaks decryption."""
    return f"{sub}|{iss}".encode("utf-8")


class KeyStore(Protocol):
    """Per-user PCE credential storage."""

    def get(self, *, sub: str, iss: str) -> PCECredentials | None: ...
    def put(self, *, sub: str, iss: str, creds: PCECredentials, label: str | None = None) -> None: ...
    def delete(self, *, sub: str, iss: str) -> bool: ...


class SQLiteKeyStore:
    """File-backed KeyStore using SQLite + envelope encryption.

    Concurrent reads/writes are safe via SQLite WAL mode + per-call connections.
    """

    def __init__(self, db_path: str, cipher: EnvelopeCipher):
        self.db_path = db_path
        self._cipher = cipher
        self._init_db()

    def _init_db(self) -> None:
        # Ensure parent dir exists with safe perms
        parent = Path(self.db_path).parent
        if parent and not parent.exists():
            parent.mkdir(parents=True, exist_ok=True)
        # Create or open with restrictive umask
        old_umask = os.umask(0o077)
        try:
            with sqlite3.connect(self.db_path) as con:
                con.execute("PRAGMA journal_mode=WAL;")
                con.executescript(_SCHEMA)
        finally:
            os.umask(old_umask)
        # Re-chmod in case the file existed already
        try:
            os.chmod(self.db_path, 0o600)
        except OSError:
            pass

    def get(self, *, sub: str, iss: str) -> PCECredentials | None:
        with sqlite3.connect(self.db_path) as con:
            row = con.execute(
                "SELECT pce_host, pce_port, pce_org_id, api_key_enc, api_secret_enc, tls_verify "
                "FROM user_pce_credentials WHERE sub=? AND iss=?",
                (sub, iss),
            ).fetchone()
        if row is None:
            return None
        host, port, org_id, api_key_enc, api_secret_enc, tls_verify = row
        aad = _aad(sub, iss)
        api_key = self._cipher.decrypt(api_key_enc, aad=aad).decode("utf-8")
        api_secret = self._cipher.decrypt(api_secret_enc, aad=aad).decode("utf-8")
        return PCECredentials(
            host=host,
            port=port,
            org_id=org_id,
            api_key=api_key,
            api_secret=api_secret,
            tls_verify=bool(tls_verify),
        )

    def put(self, *, sub: str, iss: str, creds: PCECredentials, label: str | None = None) -> None:
        aad = _aad(sub, iss)
        api_key_enc = self._cipher.encrypt(creds.api_key.encode("utf-8"), aad=aad)
        api_secret_enc = self._cipher.encrypt(creds.api_secret.encode("utf-8"), aad=aad)
        now = datetime.now(timezone.utc).isoformat()
        with sqlite3.connect(self.db_path) as con:
            con.execute(
                "INSERT INTO user_pce_credentials "
                "(sub, iss, pce_host, pce_port, pce_org_id, api_key_enc, api_secret_enc, tls_verify, created_at, last_used_at, label) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, NULL, ?) "
                "ON CONFLICT(sub, iss) DO UPDATE SET "
                "pce_host=excluded.pce_host, "
                "pce_port=excluded.pce_port, "
                "pce_org_id=excluded.pce_org_id, "
                "api_key_enc=excluded.api_key_enc, "
                "api_secret_enc=excluded.api_secret_enc, "
                "tls_verify=excluded.tls_verify, "
                "label=excluded.label",
                (sub, iss, creds.host, creds.port, creds.org_id,
                 api_key_enc, api_secret_enc, int(creds.tls_verify), now, label),
            )

    def delete(self, *, sub: str, iss: str) -> bool:
        with sqlite3.connect(self.db_path) as con:
            cur = con.execute("DELETE FROM user_pce_credentials WHERE sub=? AND iss=?", (sub, iss))
            return cur.rowcount > 0

    def count_for(self, *, sub: str, iss: str) -> int:
        """Test helper — count rows for a given (sub, iss)."""
        with sqlite3.connect(self.db_path) as con:
            (n,) = con.execute(
                "SELECT COUNT(*) FROM user_pce_credentials WHERE sub=? AND iss=?", (sub, iss)
            ).fetchone()
            return n
```

- [ ] **Step 4: Run tests**

```bash
.venv/bin/python3 -m pytest tests/test_auth_keystore.py -v
```
Expected: 8 PASSED.

- [ ] **Step 5: Commit**

```bash
git add src/illumio_mcp/auth/keystore.py tests/test_auth_keystore.py
git commit -m "feat(auth): SQLiteKeyStore for per-user PCE credentials"
```

---

## Task 3: `auth/keystore_init.py` — startup wiring

A small module that combines KEK loading + SQLite path resolution. Kept separate from `keystore.py` so unit tests of the keystore don't have to deal with env vars.

**Files:**
- Create: `src/illumio_mcp/auth/keystore_init.py`

- [ ] **Step 1: Create the file**

Create `src/illumio_mcp/auth/keystore_init.py`:

```python
"""Build the production KeyStore from environment variables.

Reads:
  MCP_KEYSTORE_PATH   path to the SQLite file (default: ./data/keys.db)
  MCP_KEK             32-byte base64 Key-Encryption-Key (required)

Returns a configured SQLiteKeyStore. Called once at HTTP server startup.
"""
import os

from .crypto import EnvelopeCipher, load_kek_from_env
from .keystore import SQLiteKeyStore


_DEFAULT_PATH = "./data/keys.db"


def build_keystore_from_env() -> SQLiteKeyStore:
    """Load KEK + path from env, return a SQLiteKeyStore."""
    kek = load_kek_from_env()
    db_path = os.getenv("MCP_KEYSTORE_PATH", _DEFAULT_PATH)
    return SQLiteKeyStore(db_path=db_path, cipher=EnvelopeCipher(kek))
```

- [ ] **Step 2: Verify**

```bash
MCP_KEK=$(.venv/bin/python3 -c "import os, base64; print(base64.b64encode(os.urandom(32)).decode())") \
MCP_KEYSTORE_PATH=/tmp/test_ks.db \
  .venv/bin/python3 -c "
from illumio_mcp.auth.keystore_init import build_keystore_from_env
ks = build_keystore_from_env()
print('keystore built, db_path:', ks.db_path)
assert ks.get(sub='nobody', iss='nowhere') is None
print('empty get returns None: ok')
" && rm -f /tmp/test_ks.db /tmp/test_ks.db-shm /tmp/test_ks.db-wal
```
Expected: prints `keystore built, db_path: /tmp/test_ks.db` and `empty get returns None: ok`.

- [ ] **Step 3: Commit**

```bash
git add src/illumio_mcp/auth/keystore_init.py
git commit -m "feat(auth): build_keystore_from_env helper"
```

---

## Task 4: Make `pce` Optional and add `keystore` to `ToolContext`; add `requires_pce` to `ToolSpec`

**Files:**
- Modify: `src/illumio_mcp/context.py`
- Modify: `src/illumio_mcp/registry.py`
- Modify: `tests/test_context.py`
- Modify: `tests/test_registry.py`

- [ ] **Step 1: Update `src/illumio_mcp/context.py`**

Replace the file contents with EXACTLY this:

```python
"""ToolContext: the per-call object every tool handler receives.

Phase 3b: `pce` is now Optional — users who haven't onboarded yet have no PCE
client. The dispatcher only routes them to credential-management tools
(`requires_pce=False`). `keystore` is provided so those tools can write rows.
"""
from dataclasses import dataclass


@dataclass
class ToolContext:
    """Everything a tool handler needs that is *not* the tool's own arguments.

    Build one per request (HTTP) or once at startup (stdio) and pass it to
    every handler. Handlers MUST read PCE from `ctx.pce` and never call
    process-global PCE accessors. If `ctx.pce is None`, the dispatcher will
    have already refused to route any tool with `requires_pce=True`.
    """
    pce: object | None  # illumio.PolicyComputeEngine, or None if user hasn't onboarded
    is_stdio: bool
    user_sub: str | None = None
    user_iss: str | None = None
    keystore: object | None = None  # auth.keystore.KeyStore in HTTP mode; None in stdio
```

- [ ] **Step 2: Append a test for the new field**

Append to `tests/test_context.py`:

```python


def test_tool_context_pce_can_be_none():
    """A user without registered PCE creds gets ctx.pce=None."""
    ctx = ToolContext(pce=None, is_stdio=False, user_sub="u", user_iss="i")
    assert ctx.pce is None


def test_tool_context_keystore_default_none():
    ctx = ToolContext(pce=object(), is_stdio=True)
    assert ctx.keystore is None


def test_tool_context_can_carry_keystore():
    sentinel = object()
    ctx = ToolContext(pce=None, is_stdio=False, user_sub="u", user_iss="i", keystore=sentinel)
    assert ctx.keystore is sentinel
```

- [ ] **Step 3: Update `src/illumio_mcp/registry.py`**

Find the `@dataclass(frozen=True)` block for `ToolSpec`. Replace the dataclass body with:

```python
@dataclass(frozen=True)
class ToolSpec:
    """Metadata for one MCP tool.

    Attributes:
        handler: The handler callable. Signature: (ctx, arguments) -> list.
        roles: Set of roles permitted to call this tool. Must be non-empty.
        mutating: True if the tool changes PCE state (create/update/delete/provision).
        requires_confirm: True if a step-up confirm token is required (Phase 3d).
            Implies mutating=True.
        unscopable: True if the tool returns PCE-wide data that cannot be safely
            filtered to a user's allowed label scopes (Phase 3c).
        requires_pce: True if the tool needs ctx.pce to be non-None. Defaults
            True. Set to False for credential-management tools that run before
            a user has onboarded (e.g., register-pce-credentials).
    """
    handler: Callable
    roles: frozenset[Role] | set[Role]
    mutating: bool = False
    requires_confirm: bool = False
    unscopable: bool = False
    requires_pce: bool = True
```

(Keep the `__post_init__` validation unchanged.)

- [ ] **Step 4: Append a test to `tests/test_registry.py`**

Append:

```python


def test_toolspec_requires_pce_default_true():
    spec = ToolSpec(handler=_h, roles={ADMIN})
    assert spec.requires_pce is True


def test_toolspec_can_opt_out_of_pce():
    spec = ToolSpec(handler=_h, roles={ADMIN}, requires_pce=False)
    assert spec.requires_pce is False
```

- [ ] **Step 5: Run tests**

```bash
.venv/bin/python3 -m pytest tests/test_context.py tests/test_registry.py tests/test_tool_metadata.py -v
```
Expected: all green (3 + 8 + 6 = 17 + new tests).

- [ ] **Step 6: Verify stdio still works**

```bash
echo '{"jsonrpc":"2.0","id":0,"method":"initialize","params":{}}' | timeout 5 .venv/bin/python3 -m illumio_mcp 2>&1 | head -3
```
Expected: valid JSON-RPC initialize response.

- [ ] **Step 7: Commit**

```bash
git add src/illumio_mcp/context.py src/illumio_mcp/registry.py tests/test_context.py tests/test_registry.py
git commit -m "feat(context): pce becomes Optional; ToolSpec gains requires_pce"
```

---

## Task 5: Per-user PCE context lookup; dispatcher carve-out

The HTTP context builder now consults the keystore. The dispatcher refuses non-credential tools when `pce is None`.

**Files:**
- Modify: `src/illumio_mcp/server.py`

- [ ] **Step 1: Update `build_http_context_for` in `src/illumio_mcp/server.py`**

Find the `build_http_context_for` function (added in Phase 3a). Replace it with:

```python
def build_http_context_for(
    user_sub: str | None,
    user_iss: str | None,
    keystore: object | None,
) -> ToolContext:
    """Build a ToolContext for one HTTP request.

    Looks up the user's stored PCE credentials in the keystore. If found, builds
    a fresh PCE client from them. If not found, returns a context with pce=None
    and lets the dispatcher decide what to allow (credential-management tools
    are still routable).
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
    )
```

- [ ] **Step 2: Update the dispatcher to handle `requires_pce`**

Find `handle_call_tool` (Phase 1 added it). Replace its body with:

```python
@server.call_tool()
async def handle_call_tool(name: str, arguments: dict) -> list[types.TextContent | types.ImageContent | types.EmbeddedResource]:
    logger.debug(f"Tool called: {name} with arguments: {arguments}")
    spec = TOOL_REGISTRY.get(name)
    if spec is None:
        raise ValueError(f"Unknown tool: {name}")
    ctx = _get_stdio_context()
    if spec.requires_pce and ctx.pce is None:
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
        return result
    except Exception as e:
        error_msg = f"Tool {name} failed: {str(e)}"
        logger.error(error_msg, exc_info=True)
        return [types.TextContent(type="text", text=json.dumps({"error": error_msg}, indent=2))]
```

(The check is functionally a no-op for stdio because stdio context always has `pce` set from env. It only kicks in for HTTP requests where the keystore lookup returned None.)

- [ ] **Step 3: Verify stdio still works**

```bash
echo '{"jsonrpc":"2.0","id":0,"method":"initialize","params":{}}' | timeout 5 .venv/bin/python3 -m illumio_mcp 2>&1 | head -3
```
Expected: valid response.

- [ ] **Step 4: Commit**

```bash
git add src/illumio_mcp/server.py
git commit -m "feat(http): per-user PCE lookup + dispatcher requires_pce gate"
```

---

## Task 6: Credential-management tools

Three tools, all `requires_pce=False`. Reader role gets `check-pce-credentials-status`; operator+admin get the full set so users can register their own creds.

**Files:**
- Create: `src/illumio_mcp/tools/credentials.py`
- Create: `tests/test_credentials_tools.py`

- [ ] **Step 1: Write the failing tests**

Create `tests/test_credentials_tools.py`:

```python
"""Tests for credential-management tool handlers (using a fake keystore)."""
import json
import pytest

from illumio_mcp.context import ToolContext
from illumio_mcp.pce import PCECredentials
from illumio_mcp.tools.credentials import (
    handle_register_pce_credentials,
    handle_delete_pce_credentials,
    handle_check_pce_credentials_status,
)


class FakeKeyStore:
    def __init__(self):
        self.rows: dict[tuple[str, str], PCECredentials] = {}

    def get(self, *, sub, iss):
        return self.rows.get((sub, iss))

    def put(self, *, sub, iss, creds, label=None):
        self.rows[(sub, iss)] = creds

    def delete(self, *, sub, iss):
        return self.rows.pop((sub, iss), None) is not None


def _ctx(keystore, *, sub="u", iss="i"):
    return ToolContext(pce=None, is_stdio=False, user_sub=sub, user_iss=iss, keystore=keystore)


def _parse(result):
    return json.loads(result[0].text)


def test_register_writes_to_keystore():
    ks = FakeKeyStore()
    result = handle_register_pce_credentials(_ctx(ks), {
        "pce_host": "https://pce.example",
        "pce_port": 8443,
        "pce_org_id": 7,
        "api_key": "k",
        "api_secret": "s",
    })
    body = _parse(result)
    assert body["status"] == "ok"
    assert ks.get(sub="u", iss="i").org_id == 7


def test_register_accepts_optional_label_and_tls_verify():
    ks = FakeKeyStore()
    handle_register_pce_credentials(_ctx(ks), {
        "pce_host": "https://pce.example",
        "pce_port": 8443,
        "pce_org_id": 1,
        "api_key": "k",
        "api_secret": "s",
        "label": "lab cluster",
        "tls_verify": False,
    })
    creds = ks.get(sub="u", iss="i")
    assert creds.tls_verify is False


def test_register_overwrites_existing():
    ks = FakeKeyStore()
    handle_register_pce_credentials(_ctx(ks), {
        "pce_host": "h", "pce_port": 1, "pce_org_id": 1, "api_key": "k1", "api_secret": "s1",
    })
    handle_register_pce_credentials(_ctx(ks), {
        "pce_host": "h", "pce_port": 1, "pce_org_id": 1, "api_key": "k2", "api_secret": "s2",
    })
    assert ks.get(sub="u", iss="i").api_key == "k2"


def test_register_requires_user_identity_in_ctx():
    """Stdio mode (no user_sub) cannot register — would have nowhere to write."""
    ks = FakeKeyStore()
    bad_ctx = ToolContext(pce=None, is_stdio=True, user_sub=None, user_iss=None, keystore=ks)
    result = handle_register_pce_credentials(bad_ctx, {
        "pce_host": "h", "pce_port": 1, "pce_org_id": 1, "api_key": "k", "api_secret": "s",
    })
    body = _parse(result)
    assert "error" in body
    assert "stdio" in body["error"].lower() or "identity" in body["error"].lower()


def test_status_reports_registered_when_present():
    ks = FakeKeyStore()
    handle_register_pce_credentials(_ctx(ks), {
        "pce_host": "h", "pce_port": 1, "pce_org_id": 1, "api_key": "k", "api_secret": "s",
    })
    body = _parse(handle_check_pce_credentials_status(_ctx(ks), {}))
    assert body["registered"] is True
    assert body["pce_host"] == "h"
    assert body["pce_org_id"] == 1


def test_status_reports_not_registered_when_absent():
    ks = FakeKeyStore()
    body = _parse(handle_check_pce_credentials_status(_ctx(ks), {}))
    assert body["registered"] is False


def test_delete_removes_row():
    ks = FakeKeyStore()
    handle_register_pce_credentials(_ctx(ks), {
        "pce_host": "h", "pce_port": 1, "pce_org_id": 1, "api_key": "k", "api_secret": "s",
    })
    body = _parse(handle_delete_pce_credentials(_ctx(ks), {}))
    assert body["status"] == "ok"
    assert ks.get(sub="u", iss="i") is None


def test_delete_idempotent_on_missing():
    ks = FakeKeyStore()
    body = _parse(handle_delete_pce_credentials(_ctx(ks), {}))
    assert body["status"] == "noop"
```

- [ ] **Step 2: Run test to verify it fails**

```bash
.venv/bin/python3 -m pytest tests/test_credentials_tools.py -v
```
Expected: ImportError.

- [ ] **Step 3: Implement `tools/credentials.py`**

Create `src/illumio_mcp/tools/credentials.py`:

```python
"""Credential-management tools — let an authenticated user register, inspect,
and delete the PCE credentials this server uses on their behalf.

These tools do NOT need a PCE client (`requires_pce=False`). They are the
escape hatch that lets a freshly-onboarded user finish bootstrap without
leaving the MCP client.
"""
import json
import logging
from typing import Any

import mcp.types as types

from ..pce import PCECredentials

logger = logging.getLogger("illumio_mcp")


def _err(message: str) -> list:
    return [types.TextContent(type="text", text=json.dumps({"error": message}))]


def _identity(ctx) -> tuple[str, str] | None:
    """Return (sub, iss) if both present in ctx; otherwise None."""
    if ctx.user_sub and ctx.user_iss:
        return ctx.user_sub, ctx.user_iss
    return None


def handle_register_pce_credentials(ctx, arguments: dict) -> list:
    """Store (or overwrite) the PCE credentials for the current authenticated user."""
    if ctx.keystore is None:
        return _err("Keystore not available — server not running in HTTP mode with auth enabled.")
    ident = _identity(ctx)
    if ident is None:
        return _err("Cannot register credentials in stdio mode (no user identity).")
    sub, iss = ident

    try:
        creds = PCECredentials(
            host=str(arguments["pce_host"]),
            port=int(arguments["pce_port"]),
            org_id=int(arguments["pce_org_id"]),
            api_key=str(arguments["api_key"]),
            api_secret=str(arguments["api_secret"]),
            tls_verify=bool(arguments.get("tls_verify", True)),
        )
    except (KeyError, ValueError, TypeError) as e:
        return _err(f"Invalid arguments: {e}")

    label = arguments.get("label")
    ctx.keystore.put(sub=sub, iss=iss, creds=creds, label=label)
    logger.info("Registered PCE credentials for sub=%s iss=%s", sub, iss)
    return [types.TextContent(type="text", text=json.dumps({
        "status": "ok",
        "message": f"PCE credentials registered for {sub}.",
        "pce_host": creds.host,
        "pce_org_id": creds.org_id,
        "label": label,
    }, indent=2))]


def handle_delete_pce_credentials(ctx, arguments: dict) -> list:
    """Remove the current user's PCE credentials. Idempotent."""
    if ctx.keystore is None:
        return _err("Keystore not available.")
    ident = _identity(ctx)
    if ident is None:
        return _err("Cannot delete credentials in stdio mode (no user identity).")
    sub, iss = ident
    deleted = ctx.keystore.delete(sub=sub, iss=iss)
    return [types.TextContent(type="text", text=json.dumps({
        "status": "ok" if deleted else "noop",
        "message": (
            f"Deleted PCE credentials for {sub}." if deleted
            else "No credentials were registered for this user."
        ),
    }))]


def handle_check_pce_credentials_status(ctx, arguments: dict) -> list:
    """Tell the caller whether credentials are registered (without revealing them)."""
    if ctx.keystore is None:
        return _err("Keystore not available.")
    ident = _identity(ctx)
    if ident is None:
        return [types.TextContent(type="text", text=json.dumps({
            "registered": True,
            "mode": "stdio",
            "message": "stdio mode uses env-loaded PCE credentials; per-user registration is HTTP-only.",
        }))]
    sub, iss = ident
    creds = ctx.keystore.get(sub=sub, iss=iss)
    if creds is None:
        return [types.TextContent(type="text", text=json.dumps({"registered": False}))]
    return [types.TextContent(type="text", text=json.dumps({
        "registered": True,
        "pce_host": creds.host,
        "pce_port": creds.port,
        "pce_org_id": creds.org_id,
        "tls_verify": creds.tls_verify,
    }))]
```

- [ ] **Step 4: Run tests**

```bash
.venv/bin/python3 -m pytest tests/test_credentials_tools.py -v
```
Expected: 8 PASSED.

- [ ] **Step 5: Commit**

```bash
git add src/illumio_mcp/tools/credentials.py tests/test_credentials_tools.py
git commit -m "feat(tools): register/delete/check pce-credentials tools"
```

---

## Task 7: Register the new tools in `TOOL_REGISTRY`

Two adds; one bump to the count test.

**Files:**
- Modify: `src/illumio_mcp/tools/__init__.py`
- Modify: `tests/test_tool_metadata.py`

- [ ] **Step 1: Edit `src/illumio_mcp/tools/__init__.py`**

Find the imports block (around the top). Add this import after the existing `from .infra import ...` line:

```python
from .credentials import (
    handle_register_pce_credentials,
    handle_delete_pce_credentials,
    handle_check_pce_credentials_status,
)
```

Find the `TOOL_REGISTRY` dict. Add this section just before the closing `}`, immediately after the Infrastructure block:

```python
    # Credentials (HTTP mode only; do NOT need ctx.pce)
    "register-pce-credentials":   ToolSpec(handle_register_pce_credentials,    roles=ALL_ROLES, requires_pce=False),
    "delete-pce-credentials":     ToolSpec(handle_delete_pce_credentials,      roles=ALL_ROLES, requires_pce=False),
    "check-pce-credentials-status": ToolSpec(handle_check_pce_credentials_status, roles=ALL_ROLES, requires_pce=False),
```

- [ ] **Step 2: Bump the count in `tests/test_tool_metadata.py`**

Find the line:
```python
    assert len(TOOL_REGISTRY) == 43, \
```
Replace with:
```python
    assert len(TOOL_REGISTRY) == 46, \
```

- [ ] **Step 3: Verify**

```bash
.venv/bin/python3 -m pytest tests/test_tool_metadata.py -v
```
Expected: 6 PASSED.

```bash
.venv/bin/python3 -c "from illumio_mcp.tools import TOOL_REGISTRY; print(len(TOOL_REGISTRY), 'tools'); print('register-pce-credentials' in TOOL_REGISTRY); print(TOOL_REGISTRY['register-pce-credentials'].requires_pce)"
```
Expected: `46 tools`, `True`, `False`.

- [ ] **Step 4: Verify stdio still works (regression net)**

```bash
echo '{"jsonrpc":"2.0","id":0,"method":"initialize","params":{}}' | timeout 5 .venv/bin/python3 -m illumio_mcp 2>&1 | head -3
```
Expected: valid response.

- [ ] **Step 5: Commit**

```bash
git add src/illumio_mcp/tools/__init__.py tests/test_tool_metadata.py
git commit -m "feat(tools): register credential-management tools (requires_pce=False)"
```

---

## Task 8: Wire keystore into HTTP transport + per-request context

The HTTP server now builds a keystore at startup, and the per-request handler passes it (along with the authenticated user) into `build_http_context_for`. **The current `_build_session_manager` uses the same `Server` for every request — so the per-request user must be threaded another way.** We add a per-request HTTP-side dispatcher that overrides the stdio context with an HTTP context built from `request.state.user`.

The cleanest place is to wrap `session_manager.handle_request` with a small Starlette handler that builds the ToolContext for this request and stashes it in a `contextvars.ContextVar` that the dispatcher reads.

**Files:**
- Modify: `src/illumio_mcp/server.py`
- Modify: `src/illumio_mcp/transport/http.py`

- [ ] **Step 1: Add a per-request context override mechanism in `server.py`**

Find the `_get_stdio_context()` function. Add this just below it:

```python
import contextvars  # Standard library — add to existing imports if not present

_http_context: contextvars.ContextVar["ToolContext | None"] = contextvars.ContextVar(
    "_http_context", default=None
)


def get_active_context() -> ToolContext:
    """Return the ToolContext for the current call.

    HTTP requests set the ContextVar before invoking the dispatcher; stdio
    falls through to the singleton.
    """
    http_ctx = _http_context.get()
    if http_ctx is not None:
        return http_ctx
    return _get_stdio_context()


def set_http_context(ctx: ToolContext) -> contextvars.Token:
    """HTTP middleware sets the per-request context. Returned token is used to
    reset() after the request completes."""
    return _http_context.set(ctx)


def reset_http_context(token: contextvars.Token) -> None:
    _http_context.reset(token)
```

- [ ] **Step 2: Update the dispatcher to use `get_active_context()`**

Find `handle_call_tool` again. Replace the line:
```python
    ctx = _get_stdio_context()
```
with:
```python
    ctx = get_active_context()
```

(Everything else stays the same.)

- [ ] **Step 3: Update `transport/http.py` to set the per-request context**

Replace the contents of `src/illumio_mcp/transport/http.py` with EXACTLY this:

```python
"""HTTP transport for the MCP server using Streamable HTTP (MCP spec 2025-03-26).

Phase 3b: per-request ToolContext built from the authenticated user's stored
PCE credentials. Stdio is unaffected.

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
from ..server import (
    server as mcp_server,
    build_http_context_for,
    set_http_context,
    reset_http_context,
)
from .setup_page import build_setup_routes

logger = logging.getLogger("illumio_mcp.transport.http")


def _build_session_manager() -> StreamableHTTPSessionManager:
    return StreamableHTTPSessionManager(app=mcp_server, stateless=True)


def _wrap_with_per_request_context(handle_request, keystore):
    """Wrap the session manager's ASGI handler so it sets the per-request
    ToolContext (built from the authenticated user) before invoking MCP."""
    async def app(scope, receive, send):
        if scope["type"] != "http":
            await handle_request(scope, receive, send)
            return
        # JWTAuthMiddleware ran before us, so request.state.user is set if
        # the request was authenticated. Build a ToolContext from it.
        user = scope.get("state", {}).get("user")
        sub = getattr(user, "sub", None) if user else None
        iss = getattr(user, "iss", None) if user else None
        ctx = build_http_context_for(sub, iss, keystore)
        token = set_http_context(ctx)
        try:
            await handle_request(scope, receive, send)
        finally:
            reset_http_context(token)
    return app


def _build_app(oauth_config: OAuthConfig | None, keystore: object | None) -> Starlette:
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

    mcp_handler = _wrap_with_per_request_context(session_manager.handle_request, keystore)
    routes = [
        Mount("/mcp", app=mcp_handler),
        Route("/healthz", healthz, methods=["GET"]),
        Route("/readyz", readyz, methods=["GET"]),
    ]

    middleware = []
    if oauth_config is not None:
        async def prm(_: Request) -> Response:
            return JSONResponse(build_prm_document(oauth_config))
        routes.append(Route("/.well-known/oauth-protected-resource", prm, methods=["GET"]))
        routes.extend(build_setup_routes(keystore))

        validator = JWTValidator(oauth_config)
        from starlette.middleware import Middleware
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
    else:
        try:
            oauth_config = load_oauth_config_from_env()
        except MissingOAuthConfigError as e:
            raise SystemExit(str(e))
        try:
            keystore = build_keystore_from_env()
        except MissingKEKError as e:
            raise SystemExit(str(e))

    app = _build_app(oauth_config, keystore)
    logger.info(f"Starting HTTP transport on http://{host}:{port}/mcp"
                + ("  [DEV-INSECURE: no auth, no keystore]" if oauth_config is None else ""))
    uvicorn.run(app, host=host, port=port, log_level="info")


def main() -> None:
    parser = argparse.ArgumentParser(prog="illumio-mcp-http", description=__doc__)
    parser.add_argument("--host", default=os.getenv("MCP_HTTP_HOST", "127.0.0.1"))
    parser.add_argument("--port", type=int, default=int(os.getenv("MCP_HTTP_PORT", "8080")))
    args = parser.parse_args()
    serve_http(host=args.host, port=args.port)
```

- [ ] **Step 4: Verify imports (the test for `_build_app` needs a stub keystore)**

```bash
MCP_DEV_INSECURE=1 .venv/bin/python3 -c "
from illumio_mcp.transport.http import _build_app
app = _build_app(None, None)
print('routes:', sorted([getattr(r, 'path', '?') for r in app.routes]))
"
```
Expected: `routes: ['/healthz', '/mcp', '/readyz']`.

```bash
unset MCP_DEV_INSECURE
MCP_OAUTH_ISSUER=https://idp.test/o \
MCP_OAUTH_JWKS_URL=https://idp.test/o/.well-known/jwks.json \
MCP_OAUTH_AUDIENCE=mcp.test \
MCP_PUBLIC_URL=http://127.0.0.1 \
MCP_KEK=$(.venv/bin/python3 -c "import os, base64; print(base64.b64encode(os.urandom(32)).decode())") \
MCP_KEYSTORE_PATH=/tmp/test_p3b.db \
  .venv/bin/python3 -c "
from illumio_mcp.transport.http import serve_http
# We can't actually run uvicorn from this script, but we can verify the build path
from illumio_mcp.transport.http import _build_app
from illumio_mcp.auth.config import load_oauth_config_from_env
from illumio_mcp.auth.keystore_init import build_keystore_from_env
app = _build_app(load_oauth_config_from_env(), build_keystore_from_env())
print('routes:', sorted([getattr(r, 'path', '?') for r in app.routes]))
" && rm -f /tmp/test_p3b.db /tmp/test_p3b.db-shm /tmp/test_p3b.db-wal
```
Expected: routes include `/setup`, `/mcp`, `/healthz`, `/readyz`, `/.well-known/oauth-protected-resource`.

- [ ] **Step 5: Verify stdio still works**

```bash
echo '{"jsonrpc":"2.0","id":0,"method":"initialize","params":{}}' | timeout 5 .venv/bin/python3 -m illumio_mcp 2>&1 | head -3
```
Expected: valid response.

- [ ] **Step 6: Commit**

```bash
git add src/illumio_mcp/server.py src/illumio_mcp/transport/http.py
git commit -m "feat(http): per-request ToolContext from keystore via ContextVar"
```

---

## Task 9: `/setup` browser endpoint

A minimal HTML form. No JS, no template engine — just an `<form>` posted back to `/setup`. Auth-protected by the existing JWT middleware.

**Files:**
- Create: `src/illumio_mcp/transport/setup_page.py`

- [ ] **Step 1: Create the file**

Create `src/illumio_mcp/transport/setup_page.py`:

```python
"""Browser onboarding page for per-user PCE credentials.

GET  /setup  -> HTML form
POST /setup  -> Process form, write to keystore, show success page

Auth is handled by the JWTAuthMiddleware mounted at the app level, so by the
time these handlers run, request.state.user is populated.
"""
from __future__ import annotations

from starlette.requests import Request
from starlette.responses import HTMLResponse, Response
from starlette.routing import Route

from ..pce import PCECredentials


_FORM_HTML = """\
<!doctype html>
<html><head>
<title>Illumio MCP — Register PCE Credentials</title>
<style>
  body { font-family: system-ui, sans-serif; max-width: 540px; margin: 3em auto; padding: 0 1em; color: #222; }
  h1 { font-size: 1.4em; margin-bottom: 0.2em; }
  .meta { color: #666; font-size: 0.9em; margin-bottom: 2em; }
  label { display: block; margin-top: 1em; font-weight: 600; }
  input { width: 100%; padding: 0.5em; font-size: 1em; box-sizing: border-box; border: 1px solid #ccc; border-radius: 4px; }
  button { margin-top: 2em; padding: 0.7em 1.5em; font-size: 1em; background: #1f6feb; color: white; border: 0; border-radius: 4px; cursor: pointer; }
  .note { background: #fff3cd; padding: 1em; border-radius: 4px; font-size: 0.9em; margin-top: 1em; }
</style>
</head><body>
<h1>Register PCE Credentials</h1>
<div class="meta">Authenticated as <code>{sub}</code> via <code>{iss}</code></div>
<form method="post" action="/setup" autocomplete="off">
  <label>PCE Host (URL)<input name="pce_host" placeholder="https://your-pce.example.com" required></label>
  <label>PCE Port<input name="pce_port" type="number" value="8443" required></label>
  <label>PCE Org ID<input name="pce_org_id" type="number" value="1" required></label>
  <label>API Key<input name="api_key" required></label>
  <label>API Secret<input name="api_secret" type="password" required></label>
  <label>Label (optional)<input name="label" placeholder="e.g. EMEA-prod"></label>
  <label><input type="checkbox" name="tls_verify" value="1" checked> Verify TLS</label>
  <button type="submit">Register</button>
</form>
<div class="note">
  Credentials are stored encrypted at rest. They will be used to authenticate
  this MCP server to PCE on your behalf. To remove them later, call the
  <code>delete-pce-credentials</code> MCP tool or visit <a href="/setup">/setup</a> again.
</div>
</body></html>
"""

_DONE_HTML = """\
<!doctype html>
<html><head><title>Illumio MCP — Registered</title>
<style>body{font-family:system-ui,sans-serif;max-width:540px;margin:3em auto;padding:0 1em;}</style>
</head><body>
<h1>PCE credentials registered</h1>
<p>You can now close this tab and use the MCP server from your client.</p>
<p><a href="/setup">Update credentials</a></p>
</body></html>
"""


def build_setup_routes(keystore) -> list[Route]:
    async def get_setup(request: Request) -> Response:
        user = getattr(request.state, "user", None)
        if user is None:
            return HTMLResponse("Unauthorized", status_code=401)
        return HTMLResponse(_FORM_HTML.format(sub=user.sub, iss=user.iss))

    async def post_setup(request: Request) -> Response:
        user = getattr(request.state, "user", None)
        if user is None:
            return HTMLResponse("Unauthorized", status_code=401)
        form = await request.form()
        try:
            creds = PCECredentials(
                host=str(form["pce_host"]),
                port=int(form["pce_port"]),
                org_id=int(form["pce_org_id"]),
                api_key=str(form["api_key"]),
                api_secret=str(form["api_secret"]),
                tls_verify=form.get("tls_verify") == "1",
            )
        except (KeyError, ValueError) as e:
            return HTMLResponse(f"Bad form: {e}", status_code=400)
        label = str(form.get("label") or "") or None
        keystore.put(sub=user.sub, iss=user.iss, creds=creds, label=label)
        return HTMLResponse(_DONE_HTML)

    return [
        Route("/setup", get_setup, methods=["GET"]),
        Route("/setup", post_setup, methods=["POST"]),
    ]
```

- [ ] **Step 2: Verify import**

```bash
.venv/bin/python3 -c "from illumio_mcp.transport.setup_page import build_setup_routes; print('ok')"
```
Expected: `ok`.

- [ ] **Step 3: Commit**

```bash
git add src/illumio_mcp/transport/setup_page.py
git commit -m "feat(http): /setup browser onboarding page"
```

---

## Task 10: End-to-end per-user PCE test

One integration test: spin up the HTTP server with an in-process keystore + JWT signer; an authenticated user with no creds calls a tool → gets `no_pce_credentials`; the user calls `register-pce-credentials` → success; the user re-calls the original tool → success.

**Files:**
- Create: `tests/test_http_per_user.py`

- [ ] **Step 1: Write the test**

Create `tests/test_http_per_user.py`:

```python
"""End-to-end: per-user PCE keystore behavior.

Simulates a fresh user logging in for the first time, getting the
`no_pce_credentials` error, registering creds via the MCP tool, then making
another tool call that succeeds.

Note: this test does NOT call PCE for real — it stubs build_pce_for so we can
verify the dispatcher path without an Illumio dependency. The real PCE
integration is exercised by `tests/test_http_auth.py` and `tests/test_mcp_tools.py`.
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
from illumio_mcp.auth.prm import build_prm_document


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


def _mint(private_key_pem, sub="alice", **overrides):
    claims = {
        "iss": "https://idp.test/o",
        "aud": "mcp.test",
        "sub": sub,
        "exp": int(time.time()) + 600,
        "iat": int(time.time()),
        "scope": "illumio-mcp.use",
        **overrides,
    }
    return pyjwt.encode(claims, private_key_pem, algorithm="RS256", headers={"kid": "test-kid"})


@pytest.fixture(scope="module")
def http_server(public_key_pem, tmp_path_factory, monkeypatch_module := None):
    """Start the HTTP server bound to a free port, with an in-process keystore
    and an in-process JWT validator. Stub build_pce_for so we don't need PCE."""
    import uvicorn
    from contextlib import asynccontextmanager
    from starlette.applications import Starlette
    from starlette.middleware import Middleware
    from starlette.responses import JSONResponse
    from starlette.routing import Mount, Route
    from mcp.server.streamable_http_manager import StreamableHTTPSessionManager
    import illumio_mcp.server as server_mod
    from illumio_mcp.server import (
        server as mcp_server, set_http_context, reset_http_context,
        build_http_context_for,
    )
    from illumio_mcp.transport.setup_page import build_setup_routes

    # Stub build_pce_for so we don't need the illumio package to talk to a real PCE.
    # We give every "PCE" a sentinel object so ctx.pce is non-None when registered.
    import illumio_mcp.pce as pce_mod
    original_build = pce_mod.build_pce_for
    def fake_build(creds):
        sentinel = object()
        sentinel.host = creds.host  # for assertion-friendly tracing
        return sentinel
    pce_mod.build_pce_for = fake_build  # type: ignore[assignment]

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

    session_manager = StreamableHTTPSessionManager(app=mcp_server, stateless=True)

    async def mcp_handler_wrapper(scope, receive, send):
        if scope["type"] != "http":
            await session_manager.handle_request(scope, receive, send)
            return
        user = scope.get("state", {}).get("user")
        sub = getattr(user, "sub", None) if user else None
        iss = getattr(user, "iss", None) if user else None
        ctx = build_http_context_for(sub, iss, keystore)
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
            *build_setup_routes(keystore),
        ],
        middleware=[Middleware(JWTAuthMiddleware, validator=validator, config=cfg)],
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
    pce_mod.build_pce_for = original_build  # restore


async def test_user_with_no_creds_gets_no_credentials_error(http_server, private_key_pem):
    from mcp import ClientSession
    from mcp.client.streamable_http import streamablehttp_client

    token = _mint(private_key_pem, sub="alice")
    async with streamablehttp_client(f"{http_server}/mcp", headers={"Authorization": f"Bearer {token}"}) as (read, write, _):
        async with ClientSession(read, write) as session:
            await session.initialize()
            result = await session.call_tool("get-labels", {})
            body = json.loads(result.content[0].text)
            assert body["error"] == "no_pce_credentials"
            assert body["setup_path"] == "/setup"


async def test_register_then_call_succeeds(http_server, private_key_pem):
    from mcp import ClientSession
    from mcp.client.streamable_http import streamablehttp_client

    token = _mint(private_key_pem, sub="bob")
    async with streamablehttp_client(f"{http_server}/mcp", headers={"Authorization": f"Bearer {token}"}) as (read, write, _):
        async with ClientSession(read, write) as session:
            await session.initialize()
            # status: not registered
            status = await session.call_tool("check-pce-credentials-status", {})
            assert json.loads(status.content[0].text) == {"registered": False}

            # register
            reg = await session.call_tool("register-pce-credentials", {
                "pce_host": "https://pce.example",
                "pce_port": 8443,
                "pce_org_id": 1,
                "api_key": "k",
                "api_secret": "s",
            })
            reg_body = json.loads(reg.content[0].text)
            assert reg_body["status"] == "ok"

            # status: registered
            status2 = await session.call_tool("check-pce-credentials-status", {})
            status2_body = json.loads(status2.content[0].text)
            assert status2_body["registered"] is True
            assert status2_body["pce_host"] == "https://pce.example"


async def test_setup_page_get_returns_html(http_server, private_key_pem):
    token = _mint(private_key_pem, sub="carol")
    req = urllib.request.Request(
        f"{http_server}/setup",
        headers={"Authorization": f"Bearer {token}"},
    )
    with urllib.request.urlopen(req) as resp:
        assert resp.status == 200
        body = resp.read().decode()
        assert "PCE Credentials" in body
        assert "carol" in body
```

- [ ] **Step 2: Run the tests**

```bash
.venv/bin/python3 -m pytest tests/test_http_per_user.py -v 2>&1 | tail -30
```
Expected: 3 PASSED.

If `test_user_with_no_creds_gets_no_credentials_error` fails because `get-labels` actually attempts a PCE call: the dispatcher should reject before reaching the handler (because `requires_pce=True` and `ctx.pce is None`). If you see the handler error message instead, the dispatcher gate isn't firing — re-check Task 5 step 2.

- [ ] **Step 3: Commit**

```bash
git add tests/test_http_per_user.py
git commit -m "test: end-to-end per-user PCE keystore + onboarding"
```

---

## Task 11: README update

**Files:**
- Modify: `README.md`

- [ ] **Step 1: Append a "Per-user PCE keys" subsection**

Find the "HTTP transport with OAuth Resource Server (Phase 3a)" section. Append this just before the next top-level section:

```markdown
### Per-user PCE keys (Phase 3b)

Each authenticated user has their own PCE API key/secret stored in an
encrypted SQLite keystore. PCE-side audit logs attribute correctly per human;
revoking a user is a single tool call.

Additional env required when running with auth:

```bash
export MCP_KEK=$(python -c 'import os, base64; print(base64.b64encode(os.urandom(32)).decode())')
export MCP_KEYSTORE_PATH=/var/lib/illumio-mcp/keys.db   # default: ./data/keys.db
```

The KEK is **never** stored next to the database. Loss of KEK = total loss of
stored creds (intentional, fail-closed). For production, source MCP_KEK from
KMS or Vault rather than the operator's shell.

Onboarding paths (either works):

1. **Browser** — visit `/setup` after authenticating; paste credentials in the form.
2. **MCP client** — call the `register-pce-credentials` tool; the only tool
   available before credentials are registered.

Other credential tools:
- `check-pce-credentials-status` — does this user have credentials registered?
- `delete-pce-credentials` — remove this user's credentials.
```

- [ ] **Step 2: Commit**

```bash
git add README.md
git commit -m "docs: per-user PCE keys + KEK env + /setup onboarding"
```

---

## Task 12: Open PR

- [ ] **Step 1: Push the branch**

```bash
git push -u origin feature/per-user-pce-keystore
```

- [ ] **Step 2: Open the PR (stacked on Phase 3a)**

```bash
gh pr create --base feature/oauth-resource-server --title "feat: per-user PCE keystore + onboarding (Phase 3b)" --body "$(cat <<'EOF'
## Summary

Phase 3b. Each authenticated user uses their own PCE API key, stored encrypted at rest. Onboarding via either MCP tool or browser form.

> **Stacked on #12 (Phase 3a).** When #12 merges, this PR's base auto-updates.

## What changed

- New `auth/crypto.py`: AES-256-GCM envelope encryption (per-record data key wrapped by KEK).
- New `auth/keystore.py`: `KeyStore` Protocol + `SQLiteKeyStore` driver. Single `user_pce_credentials` table keyed by `(sub, iss)`.
- New `auth/keystore_init.py`: builds the production keystore from `MCP_KEK` + `MCP_KEYSTORE_PATH`.
- `ToolContext`: `pce` is now `Optional`; new `keystore` field. `ToolSpec` gains `requires_pce: bool = True`.
- `server.py`: per-request HTTP context built from the user's stored creds via `ContextVar`. Dispatcher refuses tools with `requires_pce=True` when `ctx.pce is None`, returning a structured `no_pce_credentials` error pointing at `/setup`.
- New `tools/credentials.py`: `register-pce-credentials`, `delete-pce-credentials`, `check-pce-credentials-status`. Marked `requires_pce=False`.
- New `transport/setup_page.py`: `GET /setup` HTML form, `POST /setup` writes to the keystore. Auth-protected.
- `transport/http.py`: builds keystore at startup; refuses to start without `MCP_KEK` (unless `MCP_DEV_INSECURE=1`).
- Stdio unchanged. `test_tool_metadata.py` count bumped to 46 (was 43, +3 credential tools).

## Test plan

- [x] `pytest tests/test_auth_crypto.py -v` — 8 passed (round trip, AAD enforcement, tamper rejection, KEK env loading)
- [x] `pytest tests/test_auth_keystore.py -v` — 8 passed (CRUD, multi-IdP isolation, decryption-failure detection, file perms)
- [x] `pytest tests/test_credentials_tools.py -v` — 8 passed (3 tool handlers with fake keystore)
- [x] `pytest tests/test_http_per_user.py -v` — 3 passed (e2e: no-creds error → register → success; /setup form returns HTML)
- [x] All Phase 1-3a tests still green
- [x] Stdio sanity check after every transport-touching commit
- [ ] (recommended before merge) Manual: register creds via /setup against a real PCE, then run a real tool

## What this PR does NOT do

Explicitly Phase 3c/3d:
- Role mapping from groups + tool-allowlist enforcement (Phase 3c)
- Scope filters (Phase 3c)
- Audit log (Phase 3c)
- `/confirm` step-up + mutating-tool token gating (Phase 3d)

🤖 Generated with [Claude Code](https://claude.com/claude-code)
EOF
)"
```

---

## Self-review checklist

- [x] **Spec coverage:** Storage (§4.1) → Tasks 1, 2, 3. Onboarding (§4.2) → Tasks 6, 9. Per-user PCE in dispatch (§3.1) → Tasks 4, 5, 8. Tool registration (§5 Layer 3 partial) → Task 7.
- [x] **Placeholders:** None. Every step has exact content.
- [x] **Type consistency:** `EnvelopeCipher(kek)` defined Task 1, used in Tasks 2, 3, 8, 10. `SQLiteKeyStore(db_path, cipher)` defined Task 2, used Tasks 3, 8, 10. `KeyStore` Protocol defined Task 2; conforming `FakeKeyStore` in Task 6 tests has matching signatures. `ToolSpec.requires_pce` added Task 4, read by dispatcher in Task 5, set on credential tools in Task 7. `ToolContext.keystore` added Task 4, populated by `build_http_context_for` in Task 5, read by handlers in Task 6, threaded by transport wrapper in Task 8.
- [x] **Stdio invariants:** Tasks 4, 5, 7, 8 each have an explicit stdio sanity check.
- [x] **No new dependencies:** Uses `cryptography` (already transitive via PyJWT[crypto]) and stdlib `sqlite3`.
- [x] **KEK never logged:** Error messages show `sub`, never the KEK or plaintext credentials.
