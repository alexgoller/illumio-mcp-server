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
