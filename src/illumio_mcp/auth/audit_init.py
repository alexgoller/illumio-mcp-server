"""Build the production AuditLog from environment.

Reads:
  MCP_AUDIT_LOG_PATH   path to the SQLite audit DB.
                       Default: alongside the keystore (./data/audit.db
                       if MCP_KEYSTORE_PATH is unset, else <keystore_dir>/audit.db).
"""
import os
from pathlib import Path

from .audit import SQLiteAuditLog


def build_audit_log_from_env() -> SQLiteAuditLog:
    explicit = os.getenv("MCP_AUDIT_LOG_PATH")
    if explicit:
        path = explicit
    else:
        ks_path = os.getenv("MCP_KEYSTORE_PATH", "./data/keys.db")
        path = str(Path(ks_path).parent / "audit.db")
    return SQLiteAuditLog(db_path=path)
