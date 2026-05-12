"""Build (ConfirmTokenManager, JtiStore) from environment."""
import os
from pathlib import Path

from .confirm import ConfirmTokenManager, load_hmac_key_from_env
from .confirm_replay import SQLiteJtiStore


def build_confirm_manager_from_env() -> tuple[ConfirmTokenManager, SQLiteJtiStore]:
    key = load_hmac_key_from_env()
    ttl = int(os.getenv("MCP_CONFIRM_TTL_SECONDS", "120"))
    manager = ConfirmTokenManager(key, ttl_seconds=ttl)

    explicit_jti = os.getenv("MCP_CONFIRM_JTI_PATH")
    if explicit_jti:
        jti_path = explicit_jti
    else:
        ks_path = os.getenv("MCP_KEYSTORE_PATH", "./data/keys.db")
        jti_path = str(Path(ks_path).parent / "jti.db")
    jti_store = SQLiteJtiStore(db_path=jti_path)
    return manager, jti_store
