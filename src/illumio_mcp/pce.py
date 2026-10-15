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
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

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



def _install_async_query_resilience(pce: PolicyComputeEngine) -> None:
    """Replace the SDK's async poll with one that tolerates a PCE race.

    illumio's PolicyComputeEngine._async_poll has a completed branch of

        elif poll_status == 'completed':
            collection_href = poll_result['result']

    and the PCE can report `status: completed` a moment BEFORE `result` is
    populated. The SDK turns that into `KeyError: 'result'`, which reaches the
    caller as a failed traffic query on perfectly valid input.

    It was observed intermittently across several full-suite runs, failing a
    DIFFERENT tool each time -- ringfence, then infrastructure services -- which
    is exactly why it read as "the PCE is unstable" instead of as one fixable
    race. The empty-message problem hid it further: until error reporting
    followed the exception chain, the symptom was a message with no cause at all.

    Patched on the instance rather than the class so it cannot leak into
    unrelated SDK users in the same process, and applied here so every caller
    benefits -- our own fetch_flows_raw and the SDK's own
    get_traffic_flows_async alike.
    """
    from .tools.traffic import poll_async_query

    def _poll(job_location: str, retry_time=1.0) -> str:
        return poll_async_query(pce, job_location)

    pce._async_poll = _poll
# How long one PCE request may take before the caller hears about it.
#
# Measured 2026-10-15 against demo100: its front end answered 504 Gateway
# Timeout after ~18s on every request. The SDK's default policy -- 5 retries,
# backoff 2/4/8/16/32s, 504 in the forcelist, 30s per attempt, Retry-After
# honoured without a cap -- turned that into ~3 minutes per request, and
# check-pce-connection makes two. A Claude Desktop session saw six minutes
# of nothing and reported "tools/call never answers". Silence is the bug;
# a dead PCE must become an error quickly, with the status named.
PCE_REQUEST_TIMEOUT = int(os.getenv("MCP_PCE_REQUEST_TIMEOUT", "30"))
PCE_RETRIES = int(os.getenv("MCP_PCE_RETRIES", "1"))
PCE_RETRY_AFTER_CAP = float(os.getenv("MCP_PCE_RETRY_AFTER_CAP", "15"))
PCE_BACKOFF_MAX = 10.0


class BoundedRetry(Retry):
    """urllib3 Retry that will not sleep longer than PCE_RETRY_AFTER_CAP on a
    Retry-After header. A PCE that is down says "Retry-After: 600"; honouring
    that silently inside a tool call is indistinguishable from a hang."""

    def get_retry_after(self, response):
        value = super().get_retry_after(response)
        if value is None:
            return None
        cap = float(os.getenv("MCP_PCE_RETRY_AFTER_CAP", PCE_RETRY_AFTER_CAP))
        return min(value, cap)


def _bounded_retry() -> Retry:
    return BoundedRetry(
        total=int(os.getenv("MCP_PCE_RETRIES", PCE_RETRIES)),
        backoff_factor=1,
        backoff_max=PCE_BACKOFF_MAX,
        status_forcelist=[429, 500, 502, 503, 504],
        respect_retry_after_header=True,
    )


def _install_bounded_waits(pce: PolicyComputeEngine) -> None:
    """Replace the SDK's retry adapter and request timeout with bounded ones."""
    pce.set_timeout(int(os.getenv("MCP_PCE_REQUEST_TIMEOUT", PCE_REQUEST_TIMEOUT)))
    adapter = HTTPAdapter(max_retries=_bounded_retry())
    pce._session.mount("https://", adapter)
    pce._session.mount("http://", adapter)


def retry_budget_seconds(pce: PolicyComputeEngine) -> float:
    """Worst case for ONE request: every attempt times out, every backoff is
    taken at its ceiling. What a caller can be made to wait before an error."""
    retry = pce._session.get_adapter("https://").max_retries
    attempts = (retry.total or 0) + 1
    backoff = sum(min(retry.backoff_factor * (2 ** (n - 1)), retry.backoff_max)
                  for n in range(1, attempts))
    return attempts * pce._timeout + backoff


def build_pce_for(creds: PCECredentials) -> PolicyComputeEngine:
    """Construct a fresh PolicyComputeEngine. Does NOT cache.

    Each call returns a new client. This is required for per-user PCE access
    in Phase 3 — the same process talks to PCE as multiple users concurrently.
    """
    pce = PolicyComputeEngine(creds.host, port=creds.port, org_id=creds.org_id)
    _install_bounded_waits(pce)
    _install_async_query_resilience(pce)
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
