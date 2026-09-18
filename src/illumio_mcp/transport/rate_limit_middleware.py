"""Applies the per-subject rate limiter to incoming requests.

Mounted AFTER JWTAuthMiddleware in the middleware list so request.state.user is
already populated -- limiting by identity is the whole point, and an unauthorised
request never reaches here because auth rejects it first.
"""
from __future__ import annotations

import logging

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse, Response

from ..auth.rate_limit import RateLimiter

logger = logging.getLogger(__name__)


class RateLimitMiddleware(BaseHTTPMiddleware):
    def __init__(self, app, limiter: RateLimiter | None = None):
        super().__init__(app)
        self.limiter = limiter or RateLimiter()

    async def dispatch(self, request: Request, call_next) -> Response:
        user = getattr(request.state, "user", None)
        subject = getattr(user, "sub", None)

        # No identity means auth is disabled (MCP_DEV_INSECURE) or this is an
        # unauthenticated route such as /healthz. Nothing stable to key on, and
        # inventing one would rate-limit every anonymous caller as a single
        # client, so let it through -- the exposure the finding describes
        # requires a valid JWT anyway.
        if not subject:
            return await call_next(request)

        allowed, retry_after = self.limiter.check(subject, request.url.path)
        if not allowed:
            logger.warning("rate limit hit: sub=%s path=%s", subject, request.url.path)
            return JSONResponse(
                {"error": "rate_limited",
                 "message": (f"Too many requests to {request.url.path}. "
                             f"Retry in {retry_after}s.")},
                status_code=429,
                headers={"Retry-After": str(retry_after)},
            )
        return await call_next(request)
