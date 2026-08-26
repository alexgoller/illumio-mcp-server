"""Redaction of sensitive tool arguments before they reach the logs.

This lives in its own module rather than in `server.py` so that tool handlers
can use it too. The dispatcher scrubbed its own debug log, but every handler
that logged `json.dumps(arguments)` directly bypassed that control -- which
leaked confirm tokens for the two `requires_confirm` tools, since the token
travels in `arguments["_meta"]["confirm_token"]`.
"""
from __future__ import annotations

import json

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


def scrub_value_for_log(value):
    """Scrub an arbitrary value (not just a top-level argument dict)."""
    return _scrub_value(value)


class ScrubbedArgs:
    """Lazily scrubbed, JSON-serialised arguments for `logger.debug("...%s", ...)`.

    Deliberately lazy. `logger.debug(f"...{json.dumps(scrub(args))}")` runs the
    recursive copy and the serialisation on every call even when the record is
    discarded -- and since the default level is INFO, that is the normal path.
    Deferring the work into __str__ means it only happens if a handler actually
    formats the record. Restores the lazy %-formatting bbc8441 introduced.
    """

    __slots__ = ("_value", "_key")

    def __init__(self, value, key: str | None = None):
        self._value = value
        self._key = key

    def __str__(self) -> str:
        scrubbed = _scrub_value(self._value)
        if self._key is not None:
            scrubbed = scrubbed.get(self._key) if isinstance(scrubbed, dict) else None
        return json.dumps(scrubbed, indent=2, default=str)

    __repr__ = __str__
