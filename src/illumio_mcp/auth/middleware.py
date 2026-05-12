"""Starlette middleware that enforces JWT auth on selected paths.

The middleware:
  - Skips paths in `unauthenticated_paths` (default: /healthz, /readyz, /.well-known/*)
  - For other paths, requires `Authorization: Bearer <jwt>`. Validates via the
    injected JWTValidator. On success: stores AuthenticatedUser at
    `request.state.user`. On failure: returns 401 with
    `WWW-Authenticate: Bearer resource_metadata="<prm-url>"` pointing at the
    RFC 9728 document so MCP clients can discover the AS.

This is intentionally not class-based: Starlette middleware composability is
better with simple async callables.
"""
from __future__ import annotations

from typing import Iterable

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse, Response

from .config import OAuthConfig
from .jwt_validator import InvalidTokenError, JWTValidator


_DEFAULT_UNAUTHENTICATED_PREFIXES: tuple[str, ...] = (
    "/healthz",
    "/readyz",
    "/.well-known/",
)


class JWTAuthMiddleware(BaseHTTPMiddleware):
    """Enforce JWT bearer auth on /mcp and other protected paths."""

    def __init__(
        self,
        app,
        *,
        validator: JWTValidator,
        config: OAuthConfig,
        unauthenticated_prefixes: Iterable[str] = _DEFAULT_UNAUTHENTICATED_PREFIXES,
    ):
        super().__init__(app)
        self._validator = validator
        self._prm_url = config.resource_url.rstrip("/") + "/.well-known/oauth-protected-resource"
        self._unauthenticated = tuple(unauthenticated_prefixes)

    async def dispatch(self, request: Request, call_next) -> Response:
        path = request.url.path
        if any(path == p or path.startswith(p) for p in self._unauthenticated):
            return await call_next(request)

        auth_header = request.headers.get("authorization", "")
        if not auth_header.lower().startswith("bearer "):
            return self._challenge("missing_token")

        token = auth_header[len("bearer "):].strip()
        try:
            user = self._validator.validate(token)
        except InvalidTokenError as e:
            return self._challenge("invalid_token", str(e))

        request.state.user = user
        return await call_next(request)

    def _challenge(self, error: str, description: str | None = None) -> Response:
        params = [f'error="{error}"', f'resource_metadata="{self._prm_url}"']
        if description:
            params.append(f'error_description="{description}"')
        return JSONResponse(
            {"error": error, "error_description": description or ""},
            status_code=401,
            headers={"WWW-Authenticate": "Bearer " + ", ".join(params)},
        )
