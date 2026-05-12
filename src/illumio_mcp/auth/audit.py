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
