"""Per-subject request rate limiting.

From the 2026-05-13 review: an authenticated attacker -- a compromised reader
account is enough -- could hammer /confirm, exhausting CPU on HMAC minting and
enumerating the keystore via check-pce-credentials-status at high rate. Confirm
tokens are single-use with a 120s TTL, so the risk is throughput, not any one
token.

Keyed by JWT `sub`, not by IP: every client behind a corporate egress NAT shares
an IP, so an IP-keyed limit either throttles a whole office or is set so high it
throttles nobody. The identity is the thing being abused.

The review suggested slowapi. This is a token bucket in ~40 lines and no new
dependency, which matters for a server people self-deploy from source.

KNOWN LIMIT, stated rather than hidden: the bucket lives in this process. Run N
workers and the effective ceiling is N x the configured limit. For a
single-process deployment -- what the Docker image ships -- it is exact. A
multi-worker deployment that needs a hard global ceiling wants a shared store
(Redis) instead; documented in docs/operations/configuration.md.
"""
from __future__ import annotations

import logging
import os
import threading
import time

logger = logging.getLogger(__name__)

# requests per minute, per subject
DEFAULT_LIMITS = {
    "/confirm": 10,   # mints capability tokens; the expensive, sensitive path
    "/mcp": 60,       # ordinary tool traffic
}


def _limit_from_env(path: str, fallback: int) -> int:
    var = "MCP_RATE_LIMIT_" + path.strip("/").upper().replace("-", "_")
    raw = os.environ.get(var)
    if raw is None:
        return fallback
    try:
        value = int(raw)
    except ValueError:
        logger.warning("%s=%r is not an integer; using %d/min", var, raw, fallback)
        return fallback
    if value <= 0:
        logger.warning("%s=%d disables rate limiting for %s", var, value, path)
    return value


class TokenBucket:
    """Fixed-rate refilling bucket. Thread-safe; Starlette runs handlers in a
    threadpool, so two requests for one subject can land concurrently."""

    __slots__ = ("capacity", "tokens", "refill_per_sec", "updated")

    def __init__(self, capacity: int, refill_per_sec: float):
        self.capacity = float(capacity)
        self.tokens = float(capacity)
        self.refill_per_sec = refill_per_sec
        self.updated = time.monotonic()

    def take(self) -> bool:
        now = time.monotonic()
        self.tokens = min(self.capacity,
                          self.tokens + (now - self.updated) * self.refill_per_sec)
        self.updated = now
        if self.tokens >= 1.0:
            self.tokens -= 1.0
            return True
        return False

    def retry_after(self) -> int:
        if self.refill_per_sec <= 0:
            return 60
        return max(1, int((1.0 - self.tokens) / self.refill_per_sec) + 1)


class RateLimiter:
    """Buckets per (subject, path-prefix), created on demand."""

    def __init__(self, limits: dict[str, int] | None = None):
        base = dict(limits if limits is not None else DEFAULT_LIMITS)
        self.limits = {p: _limit_from_env(p, n) for p, n in base.items()}
        self._buckets: dict[tuple[str, str], TokenBucket] = {}
        self._lock = threading.Lock()

    def limit_for(self, path: str) -> tuple[str, int] | None:
        """Longest matching prefix, so /mcp/anything inherits /mcp's limit."""
        best = None
        for prefix, per_min in self.limits.items():
            if path == prefix or path.startswith(prefix + "/"):
                if best is None or len(prefix) > len(best[0]):
                    best = (prefix, per_min)
        return best

    def check(self, subject: str, path: str) -> tuple[bool, int]:
        """(allowed, retry_after_seconds). Unlimited paths always allow."""
        match = self.limit_for(path)
        if match is None:
            return True, 0
        prefix, per_min = match
        if per_min <= 0:                      # explicitly disabled
            return True, 0

        key = (subject, prefix)
        with self._lock:
            bucket = self._buckets.get(key)
            if bucket is None:
                bucket = TokenBucket(per_min, per_min / 60.0)
                self._buckets[key] = bucket
            if bucket.take():
                return True, 0
            return False, bucket.retry_after()

    def prune(self, max_idle_seconds: float = 3600) -> int:
        """Drop buckets idle long enough to be full again.

        Without this the dict grows one entry per subject seen, forever -- the
        same unbounded-growth shape the review flagged for used_jti.
        """
        cutoff = time.monotonic() - max_idle_seconds
        with self._lock:
            stale = [k for k, b in self._buckets.items() if b.updated < cutoff]
            for k in stale:
                del self._buckets[k]
        return len(stale)
