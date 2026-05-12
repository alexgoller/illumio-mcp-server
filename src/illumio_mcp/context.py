"""ToolContext: the per-call object every tool handler receives.

Phase 3c: adds `user_role` (one of reader/operator/admin), `audit_log` (an
AuditLog instance — NullAuditLog in stdio), and `request_id` (UUID per HTTP
request; None in stdio). Stdio mode sets user_role="admin" and audit_log
to NullAuditLog so the dispatcher can be uniform.
"""
from dataclasses import dataclass


@dataclass
class ToolContext:
    pce: object | None
    is_stdio: bool
    user_sub: str | None = None
    user_iss: str | None = None
    keystore: object | None = None
    user_role: str | None = None  # 'reader' | 'operator' | 'admin' | None (no role assigned)
    audit_log: object | None = None  # auth.audit.AuditLog
    request_id: str | None = None
