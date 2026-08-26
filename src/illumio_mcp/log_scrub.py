"""Redaction of sensitive tool arguments before they reach the logs.

This lives in its own module rather than in `server.py` so that tool handlers
can use it too. The dispatcher scrubbed its own debug log, but every handler
that logged `json.dumps(arguments)` directly bypassed that control -- which
leaked confirm tokens for the two `requires_confirm` tools, since the token
travels in `arguments["_meta"]["confirm_token"]`.
"""
from __future__ import annotations

# Argument keys whose values must NEVER appear in logs. Verified by
# tests/test_log_scrub.py. When adding a new sensitive arg, add it here too.
SENSITIVE_ARG_KEYS = frozenset({"api_key", "api_secret", "confirm_token"})

_REDACTED = "***"


def scrub_arguments_for_log(arguments: dict | None) -> dict:
    """Return a copy of `arguments` with sensitive values replaced by '***'.

    Recurses through nested dicts and lists, so a sensitive key is redacted
    wherever it appears -- not just at the top level or inside `_meta`. Handlers
    pass whole tool-argument payloads of arbitrary shape, and a scrubber that
    only checks known locations fails open the moment an argument nests deeper.
    """
    if not arguments:
        return {}
    scrubbed = _scrub_value(arguments)
    return scrubbed if isinstance(scrubbed, dict) else {}


def _scrub_value(value):
    if isinstance(value, dict):
        return {
            k: (_REDACTED if k in SENSITIVE_ARG_KEYS else _scrub_value(v))
            for k, v in value.items()
        }
    if isinstance(value, list):
        return [_scrub_value(v) for v in value]
    if isinstance(value, tuple):
        return tuple(_scrub_value(v) for v in value)
    return value
