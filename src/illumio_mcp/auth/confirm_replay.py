"""JTI replay tracker — enforces single-use of confirm tokens."""
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
    def mark_used(self, jti: str, *, exp: int) -> bool:
        return True


class SQLiteJtiStore:
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
        with sqlite3.connect(self.db_path) as con:
            try:
                con.execute("INSERT INTO used_jti (jti, exp) VALUES (?, ?)", (jti, exp))
                return True
            except sqlite3.IntegrityError:
                return False

    def purge_expired(self) -> int:
        now = int(time.time())
        with sqlite3.connect(self.db_path) as con:
            cur = con.execute("DELETE FROM used_jti WHERE exp <= ?", (now,))
            return cur.rowcount
