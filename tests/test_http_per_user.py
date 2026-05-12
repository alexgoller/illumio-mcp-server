"""End-to-end: per-user PCE keystore behavior.

Simulates a fresh user logging in for the first time, getting the
`no_pce_credentials` error, registering creds via the MCP tool, then making
another tool call that succeeds.

Note: this test does NOT call PCE for real — it stubs build_pce_for so we can
verify the dispatcher path without an Illumio dependency. The real PCE
integration is exercised by `tests/test_http_auth.py` and `tests/test_mcp_tools.py`.
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
from illumio_mcp.auth.crypto import EnvelopeCipher, generate_kek
from illumio_mcp.auth.jwt_validator import JWTValidator
from illumio_mcp.auth.middleware import JWTAuthMiddleware
from illumio_mcp.auth.keystore import SQLiteKeyStore
from illumio_mcp.auth.prm import build_prm_document


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


def _mint(private_key_pem, sub="alice", **overrides):
    claims = {
        "iss": "https://idp.test/o",
        "aud": "mcp.test",
        "sub": sub,
        "exp": int(time.time()) + 600,
        "iat": int(time.time()),
        "scope": "illumio-mcp.use",
        **overrides,
    }
    return pyjwt.encode(claims, private_key_pem, algorithm="RS256", headers={"kid": "test-kid"})


@pytest.fixture(scope="module")
def http_server(public_key_pem, tmp_path_factory):
    """Start the HTTP server bound to a free port, with an in-process keystore
    and an in-process JWT validator. Stub build_pce_for so we don't need PCE."""
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
    from illumio_mcp.transport.setup_page import build_setup_routes

    # Stub build_pce_for so we don't need the illumio package to talk to a real PCE.
    # We give every "PCE" a sentinel object so ctx.pce is non-None when registered.
    import illumio_mcp.pce as pce_mod

    class FakePCE:
        def __init__(self, host):
            self.host = host

    original_build = pce_mod.build_pce_for
    def fake_build(creds):
        return FakePCE(creds.host)
    pce_mod.build_pce_for = fake_build  # type: ignore[assignment]

    port = _free_port()
    cfg = OAuthConfig(
        issuer="https://idp.test/o",
        jwks_url="https://idp.test/o/.well-known/jwks.json",
        audience="mcp.test",
        required_scope="illumio-mcp.use",
        resource_url=f"http://127.0.0.1:{port}",
    )
    validator = JWTValidator(cfg, key_resolver=lambda kid: public_key_pem)
    db = tmp_path_factory.mktemp("ks") / "keys.db"
    keystore = SQLiteKeyStore(db_path=str(db), cipher=EnvelopeCipher(generate_kek()))

    session_manager = StreamableHTTPSessionManager(app=mcp_server, stateless=True)

    async def mcp_handler_wrapper(scope, receive, send):
        if scope["type"] != "http":
            await session_manager.handle_request(scope, receive, send)
            return
        user = scope.get("state", {}).get("user")
        sub = getattr(user, "sub", None) if user else None
        iss = getattr(user, "iss", None) if user else None
        from illumio_mcp.auth.audit import NullAuditLog
        ctx = build_http_context_for(sub, iss, keystore, user_role="admin", audit_log=NullAuditLog(), request_id=None)
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
            *build_setup_routes(keystore),
        ],
        middleware=[Middleware(JWTAuthMiddleware, validator=validator, config=cfg)],
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
    pce_mod.build_pce_for = original_build  # restore


async def test_user_with_no_creds_gets_no_credentials_error(http_server, private_key_pem):
    from mcp import ClientSession
    from mcp.client.streamable_http import streamablehttp_client

    token = _mint(private_key_pem, sub="alice")
    async with streamablehttp_client(f"{http_server}/mcp", headers={"Authorization": f"Bearer {token}"}) as (read, write, _):
        async with ClientSession(read, write) as session:
            await session.initialize()
            result = await session.call_tool("get-labels", {})
            body = json.loads(result.content[0].text)
            assert body["error"] == "no_pce_credentials"
            assert body["setup_path"] == "/setup"


async def test_register_then_call_succeeds(http_server, private_key_pem):
    from mcp import ClientSession
    from mcp.client.streamable_http import streamablehttp_client

    token = _mint(private_key_pem, sub="bob")
    async with streamablehttp_client(f"{http_server}/mcp", headers={"Authorization": f"Bearer {token}"}) as (read, write, _):
        async with ClientSession(read, write) as session:
            await session.initialize()
            # status: not registered
            status = await session.call_tool("check-pce-credentials-status", {})
            assert json.loads(status.content[0].text) == {"registered": False}

            # register
            reg = await session.call_tool("register-pce-credentials", {
                "pce_host": "https://pce.example",
                "pce_port": 8443,
                "pce_org_id": 1,
                "api_key": "k",
                "api_secret": "s",
            })
            reg_body = json.loads(reg.content[0].text)
            assert reg_body["status"] == "ok"

            # status: registered
            status2 = await session.call_tool("check-pce-credentials-status", {})
            status2_body = json.loads(status2.content[0].text)
            assert status2_body["registered"] is True
            assert status2_body["pce_host"] == "https://pce.example"


async def test_setup_page_get_returns_html(http_server, private_key_pem):
    token = _mint(private_key_pem, sub="carol")
    req = urllib.request.Request(
        f"{http_server}/setup",
        headers={"Authorization": f"Bearer {token}"},
    )
    with urllib.request.urlopen(req) as resp:
        assert resp.status == 200
        body = resp.read().decode()
        assert "PCE Credentials" in body
        assert "carol" in body
