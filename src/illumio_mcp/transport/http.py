"""HTTP transport for the MCP server using Streamable HTTP (MCP spec 2025-03-26).

Phase 2: NO AUTHENTICATION. Internal milestone only. Production auth is Phase 3.

The server uses `mcp.server.streamable_http_manager.StreamableHTTPSessionManager`
to wrap the existing `mcp.server.Server` instance and expose it as a Starlette
ASGI route at `/mcp` (POST/GET/DELETE). Health endpoints are also mounted.

Usage:
    illumio-mcp-http                                    # 127.0.0.1:8080
    illumio-mcp serve --http --host 0.0.0.0 --port 80   # requires MCP_DEV_INSECURE=1
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
from starlette.requests import Request
from starlette.responses import JSONResponse, Response
from starlette.routing import Mount, Route

from ..server import server as mcp_server  # the mcp.server.Server instance

logger = logging.getLogger("illumio_mcp.transport.http")


def _build_session_manager() -> StreamableHTTPSessionManager:
    """Build the session manager.

    `stateless=True` for Phase 2 — every request creates a fresh transport with
    no replay state. Simpler operationally (no session GC, no need for sticky
    sessions) and sufficient for the tools we expose. Phase 3 may switch to
    stateful if we need server-initiated notifications (progress, log streams).
    """
    return StreamableHTTPSessionManager(app=mcp_server, stateless=True)


def _build_app() -> Starlette:
    """Construct the ASGI app with the MCP route and health endpoints."""
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
        # In Phase 2 readiness == liveness. Phase 3 will add PCE reachability +
        # JWKS reachability checks here.
        return JSONResponse({"status": "ready"})

    return Starlette(
        debug=False,
        routes=[
            Mount("/mcp", app=session_manager.handle_request),
            Route("/healthz", healthz, methods=["GET"]),
            Route("/readyz", readyz, methods=["GET"]),
        ],
        lifespan=lifespan,
    )


def serve_http(host: str = "127.0.0.1", port: int = 8080) -> None:
    """Run the HTTP transport via uvicorn. Blocks until SIGINT/SIGTERM.

    Refuses to bind 0.0.0.0 unless MCP_DEV_INSECURE=1 — Phase 2 has no auth, so
    a public-bound server would be a critical exposure.
    """
    if host not in ("127.0.0.1", "::1", "localhost") and os.getenv("MCP_DEV_INSECURE") != "1":
        raise SystemExit(
            f"Refusing to bind {host!r} without auth. "
            "Phase 2 ships no authentication. To bypass for dev, set "
            "MCP_DEV_INSECURE=1. Production deployments must wait for Phase 3."
        )

    app = _build_app()
    logger.info(f"Starting HTTP transport on http://{host}:{port}/mcp")
    uvicorn.run(app, host=host, port=port, log_level="info")


def main() -> None:
    """CLI entry point. Parses --host and --port, then calls serve_http."""
    parser = argparse.ArgumentParser(prog="illumio-mcp-http", description=__doc__)
    parser.add_argument("--host", default=os.getenv("MCP_HTTP_HOST", "127.0.0.1"))
    parser.add_argument("--port", type=int, default=int(os.getenv("MCP_HTTP_PORT", "8080")))
    args = parser.parse_args()
    serve_http(host=args.host, port=args.port)
