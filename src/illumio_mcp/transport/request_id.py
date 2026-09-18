"""Per-request request_id middleware.

Generates a UUID for every incoming HTTP request, stashes it on
`request.state.request_id`, and surfaces it as the `X-Request-Id` response
header. This lets us correlate audit log entries with HTTP-level traces.

If the client sends an `X-Request-Id` header, we honor it (lets external
tracing systems propagate IDs).
"""
from __future__ import annotations

import uuid

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response



# Request ids reach the audit log, so a client-supplied one is untrusted input.
# h11 blocks CRLF at the wire level, so there is no header-injection path, but
# an attacker could still write control characters or megabytes of junk into
# audit records. Restrict to a conservative id alphabet and a sane length.
_ID_SAFE = set(
    "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_.:"
)
MAX_REQUEST_ID_LEN = 128


def sanitize_request_id(value):
    """Keep a client id only if it is entirely safe; otherwise discard it.

    Discarding beats scrubbing: a partially-rewritten id no longer correlates
    with anything on the client side, so it is worse than a fresh uuid.
    """
    if not value or len(value) > MAX_REQUEST_ID_LEN:
        return None
    return value if all(c in _ID_SAFE for c in value) else None


class RequestIdMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next) -> Response:
        rid = sanitize_request_id(request.headers.get("x-request-id")) or str(uuid.uuid4())
        request.state.request_id = rid
        response = await call_next(request)
        response.headers["X-Request-Id"] = rid
        return response
