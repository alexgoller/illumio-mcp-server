import asyncio
import os
import urllib3
from illumio import PolicyComputeEngine

PCE_HOST = os.getenv("PCE_HOST")
PCE_PORT = os.getenv("PCE_PORT")
PCE_ORG_ID = os.getenv("PCE_ORG_ID")
API_KEY = os.getenv("API_KEY")
API_SECRET = os.getenv("API_SECRET")
PCE_TLS_VERIFY = os.getenv("PCE_TLS_VERIFY", "true").lower() not in ("false", "0", "no")

if not PCE_TLS_VERIFY:
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

_pce_instance = None


def get_pce() -> PolicyComputeEngine:
    global _pce_instance
    if _pce_instance is None:
        _pce_instance = PolicyComputeEngine(PCE_HOST, port=PCE_PORT, org_id=PCE_ORG_ID)
        _pce_instance.set_credentials(API_KEY, API_SECRET)
        _pce_instance._session.verify = PCE_TLS_VERIFY
    return _pce_instance


async def run_sync(func, *args, **kwargs):
    """Run a synchronous function in a thread pool to avoid blocking the event loop."""
    if kwargs:
        return await asyncio.to_thread(lambda: func(*args, **kwargs))
    return await asyncio.to_thread(func, *args)
