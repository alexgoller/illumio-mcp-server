"""The two gaps the security model documented as open, now closed.

Both were listed in docs/security-model.md as "Open". Both were verified to be
genuinely open before being fixed -- one of them after an earlier check of mine
wrongly reported it as already handled.
"""
import os
import sqlite3
import tempfile
import time
from unittest import mock

import pytest

from illumio_mcp.auth.confirm_replay import SQLiteJtiStore
from illumio_mcp.transport import http as H


# ----- gap: used_jti grows unboundedly -----

@pytest.fixture
def store(tmp_path):
    return SQLiteJtiStore(str(tmp_path / "jti.db"))


def _rows(store) -> int:
    with sqlite3.connect(store.db_path) as con:
        return con.execute("SELECT COUNT(*) FROM used_jti").fetchone()[0]


def test_purge_is_actually_called_on_write():
    """purge_expired existed but had NO callers, so it deleted nothing for the
    life of the server. Grepping for the DELETE statement finds it inside the
    method and looks like pruning exists -- which is how this was previously
    mis-reported as fixed. The test is that it RUNS, not that it exists."""
    with mock.patch.object(SQLiteJtiStore, "purge_expired", return_value=0) as purge:
        with tempfile.TemporaryDirectory() as d:
            s = SQLiteJtiStore(os.path.join(d, "jti.db"))
            s.mark_used("a", exp=int(time.time()) + 60)
    assert purge.called, "mark_used must trigger cleanup"


def test_expired_rows_are_removed_and_live_rows_kept(store):
    now = int(time.time())
    for i in range(20):
        store.mark_used(f"old-{i}", exp=now - 3600)
    for i in range(3):
        store.mark_used(f"live-{i}", exp=now + 3600)
    assert _rows(store) == 23

    store._last_purge = float("-inf")
    store.mark_used("trigger", exp=now + 3600)
    assert _rows(store) == 4, "expired rows should be gone, live rows kept"


def test_single_use_is_still_enforced_after_purging(store):
    """Cleanup must not weaken replay protection for tokens still valid."""
    exp = int(time.time()) + 3600
    assert store.mark_used("token", exp=exp) is True
    store._last_purge = float("-inf")
    assert store.mark_used("token", exp=exp) is False


def test_purge_is_rate_limited(store):
    """Deleting on every write would put a DELETE in front of every privileged
    action for no benefit."""
    with mock.patch.object(store, "purge_expired", return_value=0) as purge:
        for i in range(10):
            store.mark_used(f"t{i}", exp=int(time.time()) + 60)
    assert purge.call_count == 1


def test_purge_failure_does_not_break_the_write(store, monkeypatch):
    """Cleanup is housekeeping; it must never fail the security-relevant write
    that triggered it."""
    monkeypatch.setattr(store, "purge_expired",
                        lambda: (_ for _ in ()).throw(sqlite3.Error("disk full")))
    store._last_purge = float("-inf")
    assert store.mark_used("still-works", exp=int(time.time()) + 60) is True


# ----- gap: public bind and authentication were mutually exclusive -----

def _serve(host, dev_insecure):
    env = {k: "x" for k in ("PCE_HOST", "PCE_PORT", "PCE_ORG_ID", "API_KEY", "API_SECRET")}
    with mock.patch.object(H, "is_dev_insecure", lambda: dev_insecure), \
         mock.patch.object(H, "uvicorn"), \
         mock.patch.object(H, "_build_app", lambda *a, **k: object()), \
         mock.patch.object(H, "load_oauth_config_from_env", lambda: object()), \
         mock.patch.object(H, "load_pce_mode_from_env", lambda: "shared"), \
         mock.patch.dict(os.environ, env), \
         mock.patch.object(H, "load_role_config_from_env", lambda: None), \
         mock.patch.object(H, "build_audit_log_from_env", lambda: None), \
         mock.patch.object(H, "build_confirm_manager_from_env", lambda: (None, None)):
        try:
            H.serve_http(host=host, port=1)
            return None
        except SystemExit as e:
            return str(e)


def test_public_bind_with_auth_is_allowed():
    """The guard was inverted: it refused every non-loopback bind unless
    MCP_DEV_INSECURE=1, and that flag is what turns auth OFF. The only way to
    serve a network interface was to serve it unauthenticated, which made the
    whole OAuth/keystore/RBAC/confirm stack unreachable in the deployment it
    exists for."""
    assert _serve("0.0.0.0", dev_insecure=False) is None


def test_public_bind_without_auth_is_refused():
    """The combination that is actually dangerous -- an unauthenticated MCP
    server with PCE access, on a network interface."""
    err = _serve("0.0.0.0", dev_insecure=True)
    assert err is not None
    assert "MCP_DEV_INSECURE" in err


def test_loopback_is_allowed_either_way():
    assert _serve("127.0.0.1", dev_insecure=True) is None
    assert _serve("127.0.0.1", dev_insecure=False) is None
