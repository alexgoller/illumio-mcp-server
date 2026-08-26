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


# ---------------------------------------------------------------------------
# Handler-level scrubbing (2026-08 security review)
#
# The dispatcher scrubbed its own debug log, but every tool handler that logged
# json.dumps(arguments) went straight around that control. Both requires_confirm
# tools did exactly that, so single-use HMAC confirm tokens -- which authorise a
# policy push -- were written to the log in plaintext.
# ---------------------------------------------------------------------------

import ast
import json
import pathlib

from illumio_mcp.log_scrub import scrub_arguments_for_log


def test_no_tool_handler_dumps_raw_arguments():
    """No handler may serialise `arguments` without scrubbing it first.

    A source-level guard rather than a behavioural one: the risk is a *new*
    handler reintroducing the pattern, which only a grep-style check catches.
    """
    # Anchor to this file, not the cwd: a relative path silently scans nothing
    # when pytest runs from elsewhere, and the guard would pass vacuously.
    src = pathlib.Path(__file__).resolve().parents[1] / "src" / "illumio_mcp"
    scanned = 0
    offenders = []
    for path in sorted(src.rglob("*.py")):
        scanned += 1
        if path.name == "log_scrub.py":
            continue  # the module that defines the control describes the pattern
        for n, line in enumerate(path.read_text().splitlines(), 1):
            stripped = line.strip()
            if stripped.startswith("#"):
                continue
            # Catch both the direct form and dumps of values derived from
            # arguments (rule_def, scopes, ...), which the narrower grep missed.
            if "json.dumps(" not in line:
                continue
            if "scrub" in line or "ScrubbedArgs" in line:
                continue
            dumped = line.split("json.dumps(", 1)[1]
            if dumped.startswith(("arguments", "rule_def", "rule_payload", "scope", "rule", "label", "creds", "payload")):
                offenders.append(f"{path}:{n}: {stripped}")
    assert scanned > 10, f"guard scanned only {scanned} files -- it is not looking at the source tree"
    assert not offenders, "unscrubbed argument logging:\n  " + "\n  ".join(offenders)


def test_confirm_token_never_survives_serialization():
    """The exact payload shape the confirm-gated tools receive."""
    args = {"scopes": [{"app": "pos"}], "_meta": {"confirm_token": "SECRET.TOKEN.VALUE"}}
    assert "SECRET.TOKEN.VALUE" not in json.dumps(scrub_arguments_for_log(args))


def test_scrubbing_recurses_into_nested_structures():
    """Sensitive keys are redacted wherever they appear, not just at known spots."""
    args = {"outer": {"inner": [{"api_secret": "nested-secret"}]}}
    assert "nested-secret" not in json.dumps(scrub_arguments_for_log(args))


def test_scrubbing_does_not_mutate_the_caller_arguments():
    """Handlers log and then use `arguments`; redaction must not corrupt them."""
    args = {"api_key": "real-key", "_meta": {"confirm_token": "real-token"}}
    scrub_arguments_for_log(args)
    assert args["api_key"] == "real-key"
    assert args["_meta"]["confirm_token"] == "real-token"


def test_log_level_defaults_to_info_not_debug(monkeypatch):
    """DEBUG echoes full tool arguments, so it must be opt-in, not the default."""
    import logging
    from illumio_mcp.server import _resolve_log_level
    monkeypatch.delenv("MCP_LOG_LEVEL", raising=False)
    assert _resolve_log_level() == logging.INFO


def test_log_level_is_configurable(monkeypatch):
    import logging
    from illumio_mcp.server import _resolve_log_level
    monkeypatch.setenv("MCP_LOG_LEVEL", "debug")
    assert _resolve_log_level() == logging.DEBUG
    monkeypatch.setenv("MCP_LOG_LEVEL", "WARNING")
    assert _resolve_log_level() == logging.WARNING


def test_invalid_log_level_falls_back_to_info(monkeypatch):
    """A typo must not silently leave the server running at DEBUG."""
    import logging
    from illumio_mcp.server import _resolve_log_level
    monkeypatch.setenv("MCP_LOG_LEVEL", "verbose-please")
    assert _resolve_log_level() == logging.INFO


# ---------------------------------------------------------------------------
# Lazy evaluation. bbc8441 deliberately moved to %-formatting so the work is
# skipped when the record is discarded; the scrubbing sweep initially undid
# that with eager f-strings. Since the default level is now INFO, an eager form
# means every tool call pays for a recursive copy plus pretty-printed JSON that
# is thrown away.
# ---------------------------------------------------------------------------

import io
import logging as _logging

from illumio_mcp.log_scrub import ScrubbedArgs


def _counting_logger(level):
    calls = {"n": 0}

    class Counting(ScrubbedArgs):
        def __str__(self):
            calls["n"] += 1
            return super().__str__()

    log = _logging.getLogger(f"scrubtest.{level}")
    log.handlers[:] = [_logging.StreamHandler(io.StringIO())]
    log.propagate = False
    log.setLevel(level)
    return log, Counting, calls


def test_scrubbed_args_does_no_work_when_record_is_discarded():
    log, Counting, calls = _counting_logger(_logging.INFO)
    log.debug("args: %s", Counting({"a": 1}))
    assert calls["n"] == 0, "ScrubbedArgs serialised despite DEBUG being suppressed"


def test_scrubbed_args_does_work_when_record_is_emitted():
    log, Counting, calls = _counting_logger(_logging.DEBUG)
    log.debug("args: %s", Counting({"a": 1}))
    assert calls["n"] == 1


def test_scrubbed_args_redacts_when_emitted():
    buf = io.StringIO()
    log = _logging.getLogger("scrubtest.emit")
    log.handlers[:] = [_logging.StreamHandler(buf)]
    log.propagate = False
    log.setLevel(_logging.DEBUG)
    log.debug("args: %s", ScrubbedArgs({"_meta": {"confirm_token": "LEAKED"}}))
    assert "LEAKED" not in buf.getvalue()
    assert "***" in buf.getvalue()


def test_scrubbed_args_supports_sub_key_selection():
    assert "rule-a" in str(ScrubbedArgs({"rules": ["rule-a"]}, "rules"))


def test_scrubbed_args_does_not_mutate_caller_arguments():
    args = {"api_key": "real-key", "_meta": {"confirm_token": "real-token"}}
    str(ScrubbedArgs(args))
    assert args["api_key"] == "real-key"
    assert args["_meta"]["confirm_token"] == "real-token"
