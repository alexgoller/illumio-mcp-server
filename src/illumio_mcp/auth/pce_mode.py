"""PCE mode selector — per-user keystore, shared service account, or both.

Three modes:
  - "per_user" (default, Phase 3b): each authenticated user has their own
    PCE API key in the encrypted SQLite keystore. PCE-side audit logs
    attribute correctly per human.
  - "shared" (Phase 3e): the server uses a single PCE service-account key
    loaded from PCE_* env vars. SSO + JWT auth still required; role-based
    authz still enforced; the server-side audit log records per-human
    identity. PCE-side audit shows the service account.
  - "hybrid" (Phase 3f): per-user keystore lookup first; users who have not
    registered -- or whose stored key cannot build a client -- fall through
    to the shared service account. PCE-side audit is therefore MIXED by
    design: some calls show the human, some the service account. Every
    tool call records `effective_pce_mode` in the server audit log so an
    operator can tell which, and check-pce-credentials-status tells the
    user which they are about to be.
"""
from __future__ import annotations

import os
from typing import Literal


PCEMode = Literal["per_user", "shared", "hybrid"]
PER_USER: PCEMode = "per_user"
SHARED: PCEMode = "shared"
HYBRID: PCEMode = "hybrid"

_VALID = (PER_USER, SHARED, HYBRID)


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


def is_hybrid_mode(mode: PCEMode | str | None) -> bool:
    return mode == HYBRID


def uses_keystore(mode: PCEMode | str | None) -> bool:
    """per_user and hybrid read the keystore; shared never does."""
    return mode in (PER_USER, HYBRID)


def uses_shared_env(mode: PCEMode | str | None) -> bool:
    """shared and hybrid need the PCE_* env the stdio transport uses."""
    return mode in (SHARED, HYBRID)
