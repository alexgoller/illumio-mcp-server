"""PCE mode selector — per-user keystore vs single shared service account.

Two modes:
  - "per_user" (default, Phase 3b): each authenticated user has their own
    PCE API key in the encrypted SQLite keystore. PCE-side audit logs
    attribute correctly per human.
  - "shared" (Phase 3e): the server uses a single PCE service-account key
    loaded from PCE_* env vars. SSO + JWT auth still required; role-based
    authz still enforced; the server-side audit log records per-human
    identity. PCE-side audit shows the service account.
"""
from __future__ import annotations

import os
from typing import Literal


PCEMode = Literal["per_user", "shared"]
PER_USER: PCEMode = "per_user"
SHARED: PCEMode = "shared"

_VALID = (PER_USER, SHARED)


def load_pce_mode_from_env() -> PCEMode:
    """Read MCP_PCE_MODE; default per_user. Raise on unknown value."""
    raw = os.getenv("MCP_PCE_MODE", PER_USER)
    if raw not in _VALID:
        raise ValueError(
            f"MCP_PCE_MODE must be one of {sorted(_VALID)}; got {raw!r}"
        )
    return raw  # type: ignore[return-value]


def is_shared_mode(mode: PCEMode | str | None) -> bool:
    return mode == SHARED
