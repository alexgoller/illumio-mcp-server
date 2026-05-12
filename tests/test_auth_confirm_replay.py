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
