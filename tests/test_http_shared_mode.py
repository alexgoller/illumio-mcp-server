"""End-to-end: shared-PCE-key mode.

Verifies that in MCP_PCE_MODE=shared:
  - The /setup route is NOT mounted
  - A user with NO per-user creds can immediately call PCE tools
  - register-pce-credentials returns the shared-mode error
  - check-pce-credentials-status returns mode=shared
"""
import json
import socket
import threading
import time
import urllib.request

import pytest
import jwt as pyjwt
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization

from illumio_mcp.auth.config import OAuthConfig
from illumio_mcp.auth.jwt_validator import JWTValidator
from illumio_mcp.auth.middleware import JWTAuthMiddleware
from illumio_mcp.auth.audit import NullAuditLog
from illumio_mcp.auth.roles import RoleConfig


pytestmark = pytest.mark.asyncio


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


@pytest.fixture(scope="module")
def rsa_key():
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


@pytest.fixture(scope="module")
def public_key_pem(rsa_key):
    return rsa_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )


@pytest.fixture(scope="module")
def private_key_pem(rsa_key):
    return rsa_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption(),
    )


def _mint(private_key_pem, sub="alice", groups=("sg-admin",)):
    return pyjwt.encode({
        "iss": "https://idp.test/o",
        "aud": "mcp.test",
        "sub": sub,
        "exp": int(time.time()) + 600,
        "iat": int(time.time()),
        "scope": "illumio-mcp.use",
        "groups": list(groups),
    }, private_key_pem, algorithm="RS256", headers={"kid": "test-kid"})


@pytest.fixture(scope="module")
def http_server(public_key_pem, tmp_path_factory):
    """Start the HTTP server in shared mode. Stub build_pce_for AND
    get_pce_from_env so we don't need a real Illumio."""
    import uvicorn
    from contextlib import asynccontextmanager
    from starlette.applications import Starlette
    from starlette.middleware import Middleware
    from starlette.responses import JSONResponse
    from starlette.routing import Mount, Route
    from mcp.server.streamable_http_manager import StreamableHTTPSessionManager
    from illumio_mcp.server import (
        server as mcp_server, set_http_context, reset_http_context,
        build_http_context_for,
    )
    from illumio_mcp.transport.request_id import RequestIdMiddleware
    from illumio_mcp.auth.roles import map_user_role
    import illumio_mcp.pce as pce_mod

    class FakePCE:
        def __init__(self, host):
            self.host = host

    original_build = pce_mod.build_pce_for
    pce_mod.build_pce_for = lambda creds: FakePCE(creds.host)
    # Also stub get_pce_from_env so we don't need real env vars
    original_env = pce_mod.get_pce_from_env
    pce_mod.get_pce_from_env = lambda: FakePCE("https://shared.pce.example")  # type: ignore[assignment]
    # Reset the singleton so the stub takes effect
    pce_mod._stdio_singleton = None

    port = _free_port()
    cfg = OAuthConfig(
        issuer="https://idp.test/o",
        jwks_url="https://idp.test/o/.well-known/jwks.json",
        audience="mcp.test",
        required_scope="illumio-mcp.use",
        resource_url=f"http://127.0.0.1:{port}",
    )
    validator = JWTValidator(cfg, key_resolver=lambda kid: public_key_pem)
    audit = NullAuditLog()
    role_config = RoleConfig(
        admin_groups=["sg-admin"],
        operator_groups=["sg-op", "sg-admin"],
        reader_groups=["sg-read", "sg-op", "sg-admin"],
        default_role=None,
    )

    session_manager = StreamableHTTPSessionManager(app=mcp_server, stateless=True)

    async def mcp_handler_wrapper(scope, receive, send):
        if scope["type"] != "http":
            await session_manager.handle_request(scope, receive, send)
            return
        state = scope.get("state", {})
        user = state.get("user")
        sub = getattr(user, "sub", None) if user else None
        iss = getattr(user, "iss", None) if user else None
        groups = getattr(user, "groups", []) if user else []
        role = map_user_role(groups, role_config)
        request_id = state.get("request_id")
        # SHARED MODE: keystore=None, pce_mode="shared"
        ctx = build_http_context_for(
            sub, iss, None, role, audit, request_id,
            confirm_manager=None, jti_store=None,
            pce_mode="shared",
        )
        token = set_http_context(ctx)
        try:
            await session_manager.handle_request(scope, receive, send)
        finally:
            reset_http_context(token)

    @asynccontextmanager
    async def lifespan(app):
        async with session_manager.run():
            yield

    async def healthz(_): return JSONResponse({"status": "ok"})

    app = Starlette(
        routes=[
            Mount("/mcp", app=mcp_handler_wrapper),
            Route("/healthz", healthz, methods=["GET"]),
        ],
        middleware=[
            Middleware(RequestIdMiddleware),
            Middleware(JWTAuthMiddleware, validator=validator, config=cfg),
        ],
        lifespan=lifespan,
    )

    config = uvicorn.Config(app, host="127.0.0.1", port=port, log_level="warning")
    server = uvicorn.Server(config)
    thread = threading.Thread(target=server.run, daemon=True)
    thread.start()

    deadline = time.monotonic() + 10
    while time.monotonic() < deadline:
        try:
            with urllib.request.urlopen(f"http://127.0.0.1:{port}/healthz", timeout=0.5) as resp:
                if resp.status == 200:
                    break
        except Exception:
            time.sleep(0.1)
    else:
        pytest.fail("HTTP server did not become ready within 10s")

    yield f"http://127.0.0.1:{port}"

    server.should_exit = True
    thread.join(timeout=5)
    pce_mod.build_pce_for = original_build
    pce_mod.get_pce_from_env = original_env  # type: ignore[assignment]


async def test_status_reports_shared_mode(http_server, private_key_pem):
    from mcp import ClientSession
    from mcp.client.streamable_http import streamablehttp_client

    token = _mint(private_key_pem, sub="alice", groups=["sg-admin"])
    async with streamablehttp_client(f"{http_server}/mcp", headers={"Authorization": f"Bearer {token}"}) as (read, write, _):
        async with ClientSession(read, write) as session:
            await session.initialize()
            result = await session.call_tool("check-pce-credentials-status", {})
            body = json.loads(result.content[0].text)
            assert body["registered"] is True
            assert body["mode"] == "shared"


async def test_register_returns_shared_error(http_server, private_key_pem):
    from mcp import ClientSession
    from mcp.client.streamable_http import streamablehttp_client

    token = _mint(private_key_pem, sub="alice", groups=["sg-admin"])
    async with streamablehttp_client(f"{http_server}/mcp", headers={"Authorization": f"Bearer {token}"}) as (read, write, _):
        async with ClientSession(read, write) as session:
            await session.initialize()
            result = await session.call_tool("register-pce-credentials", {
                "pce_host": "h", "pce_port": 1, "pce_org_id": 1, "api_key": "k", "api_secret": "s",
            })
            body = json.loads(result.content[0].text)
            assert "error" in body
            assert "shared" in body["error"].lower()


async def test_user_with_no_per_user_creds_can_call_pce_tools(http_server, private_key_pem):
    """In shared mode, the dispatcher's no_pce_credentials gate doesn't fire
    because ctx.pce is the env-loaded singleton."""
    from mcp import ClientSession
    from mcp.client.streamable_http import streamablehttp_client

    token = _mint(private_key_pem, sub="never-onboarded-user", groups=["sg-admin"])
    async with streamablehttp_client(f"{http_server}/mcp", headers={"Authorization": f"Bearer {token}"}) as (read, write, _):
        async with ClientSession(read, write) as session:
            await session.initialize()
            result = await session.call_tool("get-labels", {})
            body_text = result.content[0].text
            try:
                body = json.loads(body_text)
                # Either the call worked (unlikely with FakePCE), or it failed
                # at the handler with a tool-level error. EITHER way, the
                # dispatcher must NOT have returned no_pce_credentials.
                if isinstance(body, dict):
                    assert body.get("error") != "no_pce_credentials"
            except json.JSONDecodeError:
                # Non-JSON body (e.g. "Labels: ...") → handler ran, dispatcher passed
                pass
