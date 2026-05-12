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
    defaults = dict(
        sub="alice",
        iss="https://idp.test/o",
        tool="get-labels",
        decision="allowed",
        reason=None,
        role="reader",
        request_id="req-123",
    )
    defaults.update(overrides)
    return AuditEntry(**defaults)


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
