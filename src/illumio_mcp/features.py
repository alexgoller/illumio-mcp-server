"""Optional features that exist only when configured.

A feature that is not configured is invisible: its tools are not advertised,
calling one is an ordinary unknown tool, the docs generator does not list it,
and nothing in an error message mentions it. Configuration is read at call
time, not import time, so tests can flip it without reloading modules.

MCP_HIDE_FEATURES="cloud,..." forces features off even when configured; the
docs generator uses it so docs/tools.md never depends on who ran it.
"""
from __future__ import annotations

import os

CLOUD = "cloud"
CLOUD_ENV = ("CLOUD_API_HOST", "CLOUD_API_KEY", "CLOUD_API_SECRET", "CLOUD_TENANT_ID")


def _hidden() -> set[str]:
    return {f.strip() for f in os.getenv("MCP_HIDE_FEATURES", "").split(",") if f.strip()}


def feature_enabled(name: str) -> bool:
    if name in _hidden():
        return False
    if name == CLOUD:
        return all(os.getenv(v) for v in CLOUD_ENV)
    return False
