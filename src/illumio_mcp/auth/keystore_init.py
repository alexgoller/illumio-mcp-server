"""Build the production KeyStore from environment variables.

Reads:
  MCP_KEYSTORE_PATH   path to the SQLite file (default: ./data/keys.db)
  MCP_KEK             32-byte base64 Key-Encryption-Key (required)

Returns a configured SQLiteKeyStore. Called once at HTTP server startup.
"""
import os

from .crypto import EnvelopeCipher, load_kek_from_env
from .keystore import SQLiteKeyStore


_DEFAULT_PATH = "./data/keys.db"


def build_keystore_from_env() -> SQLiteKeyStore:
    """Load KEK + path from env, return a SQLiteKeyStore."""
    kek = load_kek_from_env()
    db_path = os.getenv("MCP_KEYSTORE_PATH", _DEFAULT_PATH)
    return SQLiteKeyStore(db_path=db_path, cipher=EnvelopeCipher(kek))
