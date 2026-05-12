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
    pce_mode: str = "per_user"  # 'per_user' (default) | 'shared'
