"""Phase 3f (#17): MCP_PCE_MODE=hybrid.

Per-user keystore lookup first; the env-loaded shared service account when
the user has not registered (or their stored key cannot build a client). The
dispatcher's no_pce_credentials gate never fires. Every tool call records
which credentials it actually used, because the confused-deputy case -- "I
thought that ran as me" -- is the real risk of the mode.
"""
import json
import sqlite3
from types import SimpleNamespace as NS

import pytest

from illumio_mcp import server as srv
from illumio_mcp.auth import pce_mode as pm
from illumio_mcp.auth.audit import AuditEntry, SQLiteAuditLog
from illumio_mcp.context import ToolContext
from illumio_mcp.pce import PCECredentials
from illumio_mcp.tools.credentials import (handle_check_pce_credentials_status,
                                           handle_delete_pce_credentials,
                                           handle_register_pce_credentials)

from test_credentials_tools import FakeKeyStore

CREDS = PCECredentials(host="https://pce.user", port=8443, org_id=7, api_key="k",
                       api_secret="s", tls_verify=True)
ENV_PCE = NS(name="shared-env-pce")
USER_PCE = NS(name="per-user-pce")


# --- mode selector ---------------------------------------------------------

def test_hybrid_is_a_valid_mode(monkeypatch):
    monkeypatch.setenv("MCP_PCE_MODE", "hybrid")
    assert pm.load_pce_mode_from_env() == pm.HYBRID == "hybrid"
    assert pm.is_hybrid_mode("hybrid") and not pm.is_shared_mode("hybrid")
    assert pm.uses_keystore("hybrid") and pm.uses_keystore("per_user") and not pm.uses_keystore("shared")


# --- context construction --------------------------------------------------

@pytest.fixture
def pces(monkeypatch):
    monkeypatch.setattr(srv, "get_pce_from_env", lambda: ENV_PCE)
    import illumio_mcp.pce as pce_mod
    monkeypatch.setattr(pce_mod, "build_pce_for", lambda creds: USER_PCE)


def _ctx(keystore, mode, sub="alice"):
    return srv.build_http_context_for(sub, "https://idp", keystore, "admin", None, "r1", pce_mode=mode)


def test_registered_user_gets_their_own_pce(pces):
    ks = FakeKeyStore(); ks.put(sub="alice", iss="https://idp", creds=CREDS)
    ctx = _ctx(ks, "hybrid")
    assert ctx.pce is USER_PCE and ctx.effective_pce_mode == "per_user"


def test_unregistered_user_falls_through_to_shared(pces):
    """The gate never fires: an unregistered user is on the shared account."""
    ctx = _ctx(FakeKeyStore(), "hybrid")
    assert ctx.pce is ENV_PCE and ctx.effective_pce_mode == "shared"


def test_unusable_stored_key_falls_back_and_says_so(pces, monkeypatch):
    """The confused-deputy case: a row exists, the client cannot be built
    (expired key, bad host). Hybrid falls back -- and the context records
    that this call ran as the service account, not the human."""
    import illumio_mcp.pce as pce_mod
    def boom(creds): raise RuntimeError("key expired")
    monkeypatch.setattr(pce_mod, "build_pce_for", boom)
    ks = FakeKeyStore(); ks.put(sub="alice", iss="https://idp", creds=CREDS)
    ctx = _ctx(ks, "hybrid")
    assert ctx.pce is ENV_PCE and ctx.effective_pce_mode == "shared"


def test_per_user_mode_is_unchanged(pces):
    ctx = _ctx(FakeKeyStore(), "per_user")
    assert ctx.pce is None and ctx.effective_pce_mode is None
    ks = FakeKeyStore(); ks.put(sub="alice", iss="https://idp", creds=CREDS)
    assert _ctx(ks, "per_user").effective_pce_mode == "per_user"


def test_shared_mode_is_unchanged(pces):
    ctx = _ctx(None, "shared")
    assert ctx.pce is ENV_PCE and ctx.effective_pce_mode == "shared"


# --- audit log -------------------------------------------------------------

def test_audit_entry_records_which_credentials_were_used(tmp_path):
    log = SQLiteAuditLog(str(tmp_path / "a.db"))
    log.record(AuditEntry(sub="alice", iss="i", tool="get-labels", decision="allowed",
                          reason=None, role="reader", request_id="r", effective_pce_mode="shared"))
    with sqlite3.connect(log.db_path) as con:
        assert con.execute("SELECT effective_pce_mode FROM audit_log").fetchone() == ("shared",)


def test_existing_audit_db_is_migrated_in_place(tmp_path):
    """Operators upgrading keep their audit history; the column is added."""
    db = str(tmp_path / "old.db")
    with sqlite3.connect(db) as con:
        con.executescript("""CREATE TABLE audit_log (id INTEGER PRIMARY KEY AUTOINCREMENT, ts TEXT NOT NULL,
            sub TEXT, iss TEXT, tool TEXT NOT NULL, decision TEXT NOT NULL, reason TEXT, role TEXT, request_id TEXT);
            INSERT INTO audit_log (ts, tool, decision) VALUES ('2026-01-01T00:00:00Z', 'get-labels', 'allowed');""")
    log = SQLiteAuditLog(db)
    log.record(AuditEntry(sub="bob", iss="i", tool="get-labels", decision="allowed",
                          reason=None, role="reader", request_id="r", effective_pce_mode="per_user"))
    with sqlite3.connect(db) as con:
        rows = con.execute("SELECT tool, effective_pce_mode FROM audit_log ORDER BY id").fetchall()
    assert rows == [("get-labels", None), ("get-labels", "per_user")]


def test_old_style_entries_without_the_field_still_record(tmp_path):
    log = SQLiteAuditLog(str(tmp_path / "a.db"))
    log.record(AuditEntry(sub="a", iss="i", tool="t", decision="allowed", reason=None, role="r", request_id="q"))
    with sqlite3.connect(log.db_path) as con:
        assert con.execute("SELECT effective_pce_mode FROM audit_log").fetchone() == (None,)


# --- credential tools in hybrid mode ---------------------------------------

def _tool_ctx(ks, effective, sub="alice"):
    return ToolContext(pce=ENV_PCE, is_stdio=False, user_sub=sub, user_iss="i", keystore=ks,
                       pce_mode="hybrid", effective_pce_mode=effective)


def _parse(r): return json.loads(r[0].text)


def test_status_unregistered_reports_shared_with_the_opt_in_hint():
    body = _parse(handle_check_pce_credentials_status(_tool_ctx(FakeKeyStore(), "shared"), {}))
    assert body["registered"] is True and body["mode"] == "shared"
    assert "register-pce-credentials" in body["message"]


def test_status_registered_reports_per_user_with_host():
    ks = FakeKeyStore(); ks.put(sub="alice", iss="i", creds=CREDS)
    body = _parse(handle_check_pce_credentials_status(_tool_ctx(ks, "per_user"), {}))
    assert body["mode"] == "per_user" and body["pce_host"] == "https://pce.user"


def test_status_warns_when_registered_but_this_call_ran_as_shared():
    """Row exists, but the request fell back. The user must not believe the
    PCE audit log shows their name for what they are about to do."""
    ks = FakeKeyStore(); ks.put(sub="alice", iss="i", creds=CREDS)
    body = _parse(handle_check_pce_credentials_status(_tool_ctx(ks, "shared"), {}))
    assert body["mode"] == "shared" and body["registered"] is True
    assert "could not be used" in body["message"] and "shared" in body["message"]


def test_register_and_delete_work_in_hybrid_mode():
    ks = FakeKeyStore()
    r = _parse(handle_register_pce_credentials(_tool_ctx(ks, "shared"), {
        "pce_host": "https://pce.user", "pce_port": 8443, "pce_org_id": 7, "api_key": "k", "api_secret": "s"}))
    assert r["status"] == "ok" and ks.get(sub="alice", iss="i") is not None
    d = _parse(handle_delete_pce_credentials(_tool_ctx(ks, "per_user"), {}))
    assert d["status"] == "ok" and ks.get(sub="alice", iss="i") is None


def test_shared_mode_still_refuses_registration():
    ctx = ToolContext(pce=ENV_PCE, is_stdio=False, user_sub="a", user_iss="i", keystore=None, pce_mode="shared")
    assert "error" in _parse(handle_register_pce_credentials(ctx, {}))


# --- startup validation ----------------------------------------------------

def test_hybrid_requires_the_shared_env_vars(monkeypatch):
    from illumio_mcp.transport.http import require_shared_pce_env
    for v in ("PCE_HOST", "PCE_PORT", "PCE_ORG_ID", "API_KEY", "API_SECRET"):
        monkeypatch.setenv(v, "x")
    require_shared_pce_env("hybrid")                       # all present: fine
    monkeypatch.delenv("API_SECRET")
    with pytest.raises(SystemExit, match="MCP_PCE_MODE=hybrid requires API_SECRET"):
        require_shared_pce_env("hybrid")
