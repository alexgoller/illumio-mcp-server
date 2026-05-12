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
