"""ToolContext: the per-call object every tool handler receives.

Phase 3d: adds `confirm_manager` and `jti_store`. The dispatcher uses these
to validate the params._meta.confirm_token on `requires_confirm=True` tools
when running over HTTP. Stdio leaves both None and skips the check.
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
