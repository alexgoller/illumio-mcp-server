"""Tests for the PCE builder (per-credentials construction).

The builder must NOT cache. Each call returns a fresh client. This is what
makes per-user PCE clients possible in Phase 3.
"""
from illumio_mcp.pce import (
    PCECredentials, build_pce_for, get_pce_from_env, get_pce,
)


def test_build_pce_for_returns_fresh_instance_each_call():
    creds = PCECredentials(
        host="https://example.test",
        port=8443,
        org_id=1,
        api_key="api_key_123",
        api_secret="secret_abc",
        tls_verify=False,
    )
    a = build_pce_for(creds)
    b = build_pce_for(creds)
    assert a is not b


def test_build_pce_for_sets_credentials_and_tls_verify():
    creds = PCECredentials(
        host="https://example.test",
        port=8443,
        org_id=1,
        api_key="api_key_123",
        api_secret="secret_abc",
        tls_verify=False,
    )
    pce = build_pce_for(creds)
    assert pce._session.verify is False


def test_get_pce_from_env_caches_singleton(monkeypatch):
    """Stdio mode keeps a process-wide singleton — that's the existing
    behavior we must preserve."""
    monkeypatch.setenv("PCE_HOST", "https://example.test")
    monkeypatch.setenv("PCE_PORT", "8443")
    monkeypatch.setenv("PCE_ORG_ID", "1")
    monkeypatch.setenv("API_KEY", "k")
    monkeypatch.setenv("API_SECRET", "s")
    # Reset the singleton in case a previous test populated it
    import illumio_mcp.pce as pce_mod
    pce_mod._stdio_singleton = None

    a = get_pce_from_env()
    b = get_pce_from_env()
    assert a is b


def test_get_pce_is_alias_for_env_singleton(monkeypatch):
    """Existing call sites use get_pce(); it must keep returning the singleton
    so handlers continue to work until Task 16 swaps the dispatch path."""
    monkeypatch.setenv("PCE_HOST", "https://example.test")
    monkeypatch.setenv("PCE_PORT", "8443")
    monkeypatch.setenv("PCE_ORG_ID", "1")
    monkeypatch.setenv("API_KEY", "k")
    monkeypatch.setenv("API_SECRET", "s")
    import illumio_mcp.pce as pce_mod
    pce_mod._stdio_singleton = None

    a = get_pce()
    b = get_pce_from_env()
    assert a is b
