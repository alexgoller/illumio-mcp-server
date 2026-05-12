"""HTTP transport for the MCP server using Streamable HTTP (MCP spec 2025-03-26).

Phase 3c: adds role-based authz + audit log + per-request request_id.

Routes:
  GET  /healthz                                -> 200 (unauth)
  GET  /readyz                                 -> 200 (unauth)
  GET  /.well-known/oauth-protected-resource   -> RFC 9728 metadata (unauth)
  GET  /setup                                  -> HTML form (auth required)
  POST /setup                                  -> Submit credentials (auth required)
  *    /mcp                                    -> Streamable HTTP MCP (auth required)
"""
from __future__ import annotations

import argparse
import contextlib
import logging
import os
from typing import AsyncIterator

import uvicorn
from mcp.server.streamable_http_manager import StreamableHTTPSessionManager
from starlette.applications import Starlette
from starlette.middleware import Middleware
from starlette.requests import Request
from starlette.responses import JSONResponse, Response
from starlette.routing import Mount, Route

from ..auth.config import (
    OAuthConfig,
    MissingOAuthConfigError,
    is_dev_insecure,
    load_oauth_config_from_env,
)
from ..auth.jwt_validator import JWTValidator
from ..auth.middleware import JWTAuthMiddleware
from ..auth.prm import build_prm_document
from ..auth.keystore_init import build_keystore_from_env
from ..auth.crypto import MissingKEKError
from ..auth.roles import RoleConfig, load_role_config_from_env, map_user_role
from ..auth.audit_init import build_audit_log_from_env
from ..auth.audit import NullAuditLog
from ..auth.confirm import ConfirmTokenManager, MissingConfirmHmacKeyError
from ..auth.confirm_init import build_confirm_manager_from_env
from ..auth.confirm_replay import NullJtiStore
from ..server import (
    server as mcp_server,
    build_http_context_for,
    set_http_context,
    reset_http_context,
)
from .request_id import RequestIdMiddleware
from .setup_page import build_setup_routes
from .confirm_endpoint import build_confirm_routes

logger = logging.getLogger("illumio_mcp.transport.http")


def _build_session_manager() -> StreamableHTTPSessionManager:
    return StreamableHTTPSessionManager(app=mcp_server, stateless=True)


def _wrap_with_per_request_context(handle_request, keystore, role_config, audit_log, confirm_manager, jti_store):
    """Wrap the session manager's ASGI handler so it sets the per-request
    ToolContext (built from the authenticated user) before invoking MCP."""
    async def app(scope, receive, send):
        if scope["type"] != "http":
            await handle_request(scope, receive, send)
            return
        state = scope.get("state", {})
        user = state.get("user")
        sub = getattr(user, "sub", None) if user else None
        iss = getattr(user, "iss", None) if user else None
        groups = getattr(user, "groups", []) if user else []
        role = map_user_role(groups, role_config) if role_config is not None else "admin"
        request_id = state.get("request_id")
        ctx = build_http_context_for(
            sub, iss, keystore, role, audit_log, request_id,
            confirm_manager=confirm_manager, jti_store=jti_store,
        )
        token = set_http_context(ctx)
        try:
            await handle_request(scope, receive, send)
        finally:
            reset_http_context(token)
    return app


def _build_app(
    oauth_config: OAuthConfig | None,
    keystore: object | None,
    role_config: RoleConfig | None,
    audit_log: object | None,
    confirm_manager: object | None,
    jti_store: object | None,
) -> Starlette:
    session_manager = _build_session_manager()

    @contextlib.asynccontextmanager
    async def lifespan(app: Starlette) -> AsyncIterator[None]:
        async with session_manager.run():
            logger.info("StreamableHTTPSessionManager started")
            yield
            logger.info("StreamableHTTPSessionManager stopped")

    async def healthz(_: Request) -> Response:
        return JSONResponse({"status": "ok"})

    async def readyz(_: Request) -> Response:
        return JSONResponse({"status": "ready"})

    mcp_handler = _wrap_with_per_request_context(
        session_manager.handle_request, keystore, role_config, audit_log,
        confirm_manager, jti_store,
    )
    routes = [
        Mount("/mcp", app=mcp_handler),
        Route("/healthz", healthz, methods=["GET"]),
        Route("/readyz", readyz, methods=["GET"]),
    ]

    middleware = [Middleware(RequestIdMiddleware)]
    if oauth_config is not None:
        async def prm(_: Request) -> Response:
            return JSONResponse(build_prm_document(oauth_config))
        routes.append(Route("/.well-known/oauth-protected-resource", prm, methods=["GET"]))
        if keystore is not None:
            routes.extend(build_setup_routes(keystore))
        if confirm_manager is not None:
            routes.extend(build_confirm_routes(confirm_manager, audit_log))

        validator = JWTValidator(oauth_config)
        middleware.append(Middleware(JWTAuthMiddleware, validator=validator, config=oauth_config))
    else:
        logger.warning("MCP_DEV_INSECURE=1: HTTP server starting WITHOUT auth. Do not use in production.")

    return Starlette(debug=False, routes=routes, lifespan=lifespan, middleware=middleware)


def serve_http(host: str = "127.0.0.1", port: int = 8080) -> None:
    if host not in ("127.0.0.1", "::1", "localhost") and not is_dev_insecure():
        raise SystemExit(
            f"Refusing to bind {host!r} without MCP_DEV_INSECURE=1. "
            "Public bind requires Phase 3 auth + an explicit dev opt-in."
        )

    if is_dev_insecure():
        oauth_config = None
        keystore = None
        role_config = None
        audit_log = NullAuditLog()
        confirm_manager = None
        jti_store = None
    else:
        try:
            oauth_config = load_oauth_config_from_env()
        except MissingOAuthConfigError as e:
            raise SystemExit(str(e))
        try:
            keystore = build_keystore_from_env()
        except MissingKEKError as e:
            raise SystemExit(str(e))
        role_config = load_role_config_from_env()
        audit_log = build_audit_log_from_env()
        try:
            confirm_manager, jti_store = build_confirm_manager_from_env()
        except MissingConfirmHmacKeyError as e:
            raise SystemExit(str(e))

    app = _build_app(oauth_config, keystore, role_config, audit_log, confirm_manager, jti_store)
    extras = []
    if oauth_config is None:
        extras.append("DEV-INSECURE: no auth, no keystore, admin role, no confirm")
    logger.info(f"Starting HTTP transport on http://{host}:{port}/mcp"
                + (f"  [{'; '.join(extras)}]" if extras else ""))
    uvicorn.run(app, host=host, port=port, log_level="info")


def main() -> None:
    parser = argparse.ArgumentParser(prog="illumio-mcp-http", description=__doc__)
    parser.add_argument("--host", default=os.getenv("MCP_HTTP_HOST", "127.0.0.1"))
    parser.add_argument("--port", type=int, default=int(os.getenv("MCP_HTTP_PORT", "8080")))
    args = parser.parse_args()
    serve_http(host=args.host, port=args.port)
