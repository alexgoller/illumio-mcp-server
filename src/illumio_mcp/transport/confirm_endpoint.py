"""POST /confirm — mints a single-use confirm token for a mutating tool.

Request:
  POST /confirm
  Authorization: Bearer <jwt>
  Content-Type: application/json
  Body: {"tool": "delete-workload", "params_hash": "<sha256 hex>"}

Response (200):
  {"confirm_token": "<token>", "expires_in": 120}

Errors:
  401  missing/invalid JWT (handled by JWTAuthMiddleware before we run)
  400  body missing "tool" or "params_hash"
  403  fresh-auth required and JWT auth_time too old (only when
       MCP_CONFIRM_FRESH_AUTH_SECONDS is set)
"""
from __future__ import annotations

import json
import os
import time

from starlette.requests import Request
from starlette.responses import JSONResponse, Response
from starlette.routing import Route

from ..auth.confirm import ConfirmTokenManager


def build_confirm_routes(manager: ConfirmTokenManager, audit_log) -> list[Route]:
    fresh_auth_seconds_env = os.getenv("MCP_CONFIRM_FRESH_AUTH_SECONDS")
    fresh_auth_seconds = int(fresh_auth_seconds_env) if fresh_auth_seconds_env else None

    async def post_confirm(request: Request) -> Response:
        user = getattr(request.state, "user", None)
        if user is None:
            return JSONResponse({"error": "unauthorized"}, status_code=401)

        if fresh_auth_seconds is not None:
            payload_auth_time = getattr(user, "auth_time", None)
            if payload_auth_time is None:
                return JSONResponse({
                    "error": "fresh_auth_required",
                    "message": "Server requires a recent auth_time claim, but the JWT does not include one.",
                }, status_code=403)
            if int(time.time()) - int(payload_auth_time) > fresh_auth_seconds:
                return JSONResponse({
                    "error": "fresh_auth_required",
                    "message": (
                        f"Authentication is too old (max {fresh_auth_seconds}s). "
                        "Re-authenticate and try again."
                    ),
                }, status_code=403)

        try:
            body = await request.json()
        except json.JSONDecodeError:
            return JSONResponse({"error": "invalid_json"}, status_code=400)
        tool = body.get("tool")
        params_hash = body.get("params_hash")
        if not tool or not isinstance(tool, str):
            return JSONResponse({"error": "missing_field", "message": "'tool' is required"}, status_code=400)
        if not params_hash or not isinstance(params_hash, str) or len(params_hash) != 64:
            return JSONResponse(
                {"error": "missing_field", "message": "'params_hash' must be a 64-char sha256 hex string"},
                status_code=400,
            )

        token = manager.mint(sub=user.sub, tool=tool, params_hash=params_hash)
        return JSONResponse({"confirm_token": token, "expires_in": manager._ttl})

    return [Route("/confirm", post_confirm, methods=["POST"])]
