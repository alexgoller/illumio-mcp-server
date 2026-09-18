"""JTI replay tracker — enforces single-use of confirm tokens."""
from __future__ import annotations

import logging
import os
import sqlite3
import time
from pathlib import Path
from typing import Protocol


logger = logging.getLogger(__name__)

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
        # Purge on the first write rather than waiting out the interval, so a
        # restart reclaims whatever the previous process left behind.
        self._last_purge = float("-inf")
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

    # Purge at most this often. Every row is a consumed confirm token, so the
    # table grows one row per privileged action forever -- slow, unbounded disk
    # growth. purge_expired existed but nothing ever called it, so it deleted
    # nothing for the life of the server.
    PURGE_INTERVAL_SECONDS = 300

    def mark_used(self, jti: str, *, exp: int) -> bool:
        self._maybe_purge()
        with sqlite3.connect(self.db_path) as con:
            try:
                con.execute("INSERT INTO used_jti (jti, exp) VALUES (?, ?)", (jti, exp))
                return True
            except sqlite3.IntegrityError:
                return False

    def _maybe_purge(self) -> None:
        """Opportunistic cleanup on write.

        Deliberately not a background thread or a scheduler: this store is
        touched only when a confirm token is consumed, so piggybacking on that
        write keeps the table bounded without adding a moving part. Expired
        rows carry no security value -- the token they record can no longer be
        replayed because it has expired on its own.
        """
        now = time.monotonic()
        if now - self._last_purge < self.PURGE_INTERVAL_SECONDS:
            return
        self._last_purge = now
        try:
            removed = self.purge_expired()
            if removed:
                logger.debug("purged %d expired jti rows", removed)
        except sqlite3.Error as e:
            # Cleanup must never break the security-relevant write that
            # triggered it.
            logger.warning("jti purge failed (non-fatal): %s", e)

    def purge_expired(self) -> int:
        now = int(time.time())
        with sqlite3.connect(self.db_path) as con:
            cur = con.execute("DELETE FROM used_jti WHERE exp <= ?", (now,))
            return cur.rowcount
