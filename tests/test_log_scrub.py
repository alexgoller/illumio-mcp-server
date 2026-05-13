"""Tests for argument scrubbing before debug logging.

Backstop for the High-severity finding in the 2026-05-13 security review:
the dispatcher's debug log must not echo PCE secrets passed to
register-pce-credentials, nor confirm tokens passed to mutating tools.
"""
from illumio_mcp.server import _scrub_arguments_for_log, _SENSITIVE_ARG_KEYS


def test_empty_arguments_returns_empty_dict():
    assert _scrub_arguments_for_log(None) == {}
    assert _scrub_arguments_for_log({}) == {}


def test_register_pce_credentials_args_get_scrubbed():
    args = {
        "pce_host": "https://pce.example",
        "pce_port": 8443,
        "pce_org_id": 1,
        "api_key": "totally-secret-key-name",
        "api_secret": "totally-secret-secret-value",
        "label": "lab",
    }
    result = _scrub_arguments_for_log(args)
    assert result["api_key"] == "***"
    assert result["api_secret"] == "***"
    # Non-sensitive fields pass through unchanged
    assert result["pce_host"] == "https://pce.example"
    assert result["pce_port"] == 8443
    assert result["pce_org_id"] == 1
    assert result["label"] == "lab"
    # Original dict is not mutated
    assert args["api_key"] == "totally-secret-key-name"


def test_confirm_token_in_meta_is_scrubbed():
    """confirm_token lives under params._meta — must be scrubbed there too."""
    args = {
        "description": "deploy",
        "_meta": {
            "confirm_token": "header.payload.signature",
            "trace_id": "trace-not-secret",
        },
    }
    result = _scrub_arguments_for_log(args)
    assert result["_meta"]["confirm_token"] == "***"
    assert result["_meta"]["trace_id"] == "trace-not-secret"
    assert result["description"] == "deploy"


def test_non_dict_meta_does_not_crash():
    """A malicious caller might send _meta as a string. Don't crash."""
    args = {"_meta": "not-a-dict", "x": 1}
    result = _scrub_arguments_for_log(args)
    assert result == {"_meta": "not-a-dict", "x": 1}


def test_sensitive_keys_set_includes_known_secrets():
    """Lock-in test: the scrub set must include all currently-known secrets."""
    assert "api_key" in _SENSITIVE_ARG_KEYS
    assert "api_secret" in _SENSITIVE_ARG_KEYS
    assert "confirm_token" in _SENSITIVE_ARG_KEYS


def test_no_secrets_when_serialized():
    """The result, when serialized as a string (mimicking %-formatting in
    the logger), must not contain any of the secret values."""
    args = {
        "api_key": "SENSITIVE_KEY_XYZ",
        "api_secret": "SENSITIVE_SECRET_ABC",
        "_meta": {"confirm_token": "SENSITIVE_TOKEN_123"},
        "ordinary": "fine-to-log",
    }
    serialized = str(_scrub_arguments_for_log(args))
    assert "SENSITIVE_KEY_XYZ" not in serialized
    assert "SENSITIVE_SECRET_ABC" not in serialized
    assert "SENSITIVE_TOKEN_123" not in serialized
    assert "fine-to-log" in serialized
