"""PCE client construction.

Two entry points:

- `build_pce_for(creds)` — pure builder. Returns a fresh PolicyComputeEngine
  for the given credentials. This is what HTTP/per-user mode (Phase 3) uses.
- `get_pce_from_env()` — process-wide singleton built from env vars. This is
  what stdio mode uses. `get_pce()` is kept as an alias for back-compat with
  handlers that haven't been migrated yet (they will be in Tasks 4–14).

PCE_ORG_ID and `run_sync` are re-exported from this module to preserve the
existing import surface used by tools/infra.py, tools/containers.py, and
tools/traffic.py.
"""
import asyncio
import os
import urllib3
from dataclasses import dataclass
from typing import Optional

from illumio import PolicyComputeEngine

# Module-level env reads kept for back-compat with tools/infra.py and
# tools/containers.py which import PCE_ORG_ID directly.
PCE_HOST = os.getenv("PCE_HOST")
PCE_PORT = os.getenv("PCE_PORT")
PCE_ORG_ID = os.getenv("PCE_ORG_ID")
API_KEY = os.getenv("API_KEY")
API_SECRET = os.getenv("API_SECRET")
PCE_TLS_VERIFY = os.getenv("PCE_TLS_VERIFY", "true").lower() not in ("false", "0", "no")

if not PCE_TLS_VERIFY:
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


@dataclass(frozen=True)
class PCECredentials:
    host: str
    port: int
    org_id: int
    api_key: str
    api_secret: str
    tls_verify: bool = True


def build_pce_for(creds: PCECredentials) -> PolicyComputeEngine:
    """Construct a fresh PolicyComputeEngine. Does NOT cache.

    Each call returns a new client. This is required for per-user PCE access
    in Phase 3 — the same process talks to PCE as multiple users concurrently.
    """
    pce = PolicyComputeEngine(creds.host, port=creds.port, org_id=creds.org_id)
    pce.set_credentials(creds.api_key, creds.api_secret)
    pce._session.verify = creds.tls_verify
    return pce


_stdio_singleton: Optional[PolicyComputeEngine] = None


def get_pce_from_env() -> PolicyComputeEngine:
    """Return a process-wide PCE client built from PCE_* env vars.

    Used by stdio mode. Cached so we reuse the underlying HTTP session.
    """
    global _stdio_singleton
    if _stdio_singleton is None:
        creds = PCECredentials(
            host=os.getenv("PCE_HOST"),
            port=int(os.getenv("PCE_PORT")) if os.getenv("PCE_PORT") else None,
            org_id=int(os.getenv("PCE_ORG_ID")) if os.getenv("PCE_ORG_ID") else None,
            api_key=os.getenv("API_KEY"),
            api_secret=os.getenv("API_SECRET"),
            tls_verify=PCE_TLS_VERIFY,
        )
        _stdio_singleton = build_pce_for(creds)
    return _stdio_singleton


# Back-compat alias. Existing handler code calls `get_pce()`. Once Tasks 4–14
# convert handlers to read from `ctx.pce`, this alias is no longer used by
# handlers but is kept so any external callers (e.g. tests, scripts) keep
# working. Removing it can be a follow-up cleanup.
def get_pce() -> PolicyComputeEngine:
    return get_pce_from_env()


async def run_sync(func, *args, **kwargs):
    """Run a synchronous function in a thread pool to avoid blocking the event loop."""
    if kwargs:
        return await asyncio.to_thread(lambda: func(*args, **kwargs))
    return await asyncio.to_thread(func, *args)
