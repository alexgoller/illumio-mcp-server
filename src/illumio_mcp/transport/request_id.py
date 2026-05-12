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


class RequestIdMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next) -> Response:
        rid = request.headers.get("x-request-id") or str(uuid.uuid4())
        request.state.request_id = rid
        response = await call_next(request)
        response.headers["X-Request-Id"] = rid
        return response
