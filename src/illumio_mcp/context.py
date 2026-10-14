"""ToolContext: the per-call object every tool handler receives.

Phase 3e: adds `pce_mode` so handlers (and the dispatcher) can branch on
shared vs per-user PCE behavior.
"""
from dataclasses import dataclass


@dataclass
class ToolContext:
    pce: object | None
    is_stdio: bool
    user_sub: str | None = None
    user_iss: str | None = None
    keystore: object | None = None
    user_role: str | None = None
    audit_log: object | None = None
    request_id: str | None = None
    confirm_manager: object | None = None
    jti_store: object | None = None
    pce_mode: str = "per_user"  # 'per_user' (default) | 'shared' | 'hybrid'
    # Which credentials THIS request's pce was actually built from:
    # 'per_user' | 'shared' | None (no PCE). In hybrid mode the two differ
    # per user and per call; the audit log and the status tool report it.
    effective_pce_mode: str | None = None
