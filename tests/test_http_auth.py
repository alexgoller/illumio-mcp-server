"""End-to-end tests for OAuth Resource Server behavior on the HTTP transport.

Spins up the server with an in-process JWT validator (no real IdP needed) and
verifies the auth-related routes work as specified in MCP 2025-06-18.
"""
import socket
import threading
import time
import urllib.request
import urllib.error
import json

import pytest
import jwt as pyjwt
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization

from illumio_mcp.auth.config import OAuthConfig
from illumio_mcp.auth.jwt_validator import JWTValidator
from illumio_mcp.auth.middleware import JWTAuthMiddleware
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


@pytest.fixture(scope="module")
def cfg():
    return OAuthConfig(
        issuer="https://idp.test/o",
        jwks_url="https://idp.test/o/.well-known/jwks.json",
        audience="mcp.test",
        required_scope="illumio-mcp.use",
        resource_url="http://127.0.0.1",  # rewritten per-test below
    )


@pytest.fixture(scope="module")
def http_server(cfg, public_key_pem):
    """Start the HTTP server on a free port with an in-process JWT validator."""
    import uvicorn
    from contextlib import asynccontextmanager
    from starlette.applications import Starlette
    from starlette.middleware import Middleware
    from starlette.responses import JSONResponse
    from starlette.routing import Mount, Route
    from mcp.server.streamable_http_manager import StreamableHTTPSessionManager
    from illumio_mcp.server import server as mcp_server

    port = _free_port()
    test_cfg = OAuthConfig(
        issuer=cfg.issuer,
        jwks_url=cfg.jwks_url,
        audience=cfg.audience,
        required_scope=cfg.required_scope,
        resource_url=f"http://127.0.0.1:{port}",
    )
    validator = JWTValidator(test_cfg, key_resolver=lambda kid: public_key_pem)

    session_manager = StreamableHTTPSessionManager(app=mcp_server, stateless=True)

    @asynccontextmanager
    async def lifespan(app):
        async with session_manager.run():
            yield

    async def healthz(_): return JSONResponse({"status": "ok"})
    async def prm(_): return JSONResponse(build_prm_document(test_cfg))

    app = Starlette(
        routes=[
            Mount("/mcp", app=session_manager.handle_request),
            Route("/healthz", healthz, methods=["GET"]),
            Route("/.well-known/oauth-protected-resource", prm, methods=["GET"]),
        ],
        middleware=[Middleware(JWTAuthMiddleware, validator=validator, config=test_cfg)],
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

    yield f"http://127.0.0.1:{port}", test_cfg

    server.should_exit = True
    thread.join(timeout=5)


def _mint(private_key_pem, **overrides):
    claims = {
        "iss": "https://idp.test/o",
        "aud": "mcp.test",
        "sub": "user-42",
        "exp": int(time.time()) + 600,
        "iat": int(time.time()),
        "scope": "illumio-mcp.use",
        **overrides,
    }
    return pyjwt.encode(claims, private_key_pem, algorithm="RS256", headers={"kid": "test-kid"})


async def test_healthz_does_not_require_auth(http_server):
    url, _ = http_server
    with urllib.request.urlopen(f"{url}/healthz") as resp:
        assert resp.status == 200


async def test_prm_endpoint_returns_metadata(http_server):
    url, cfg = http_server
    with urllib.request.urlopen(f"{url}/.well-known/oauth-protected-resource") as resp:
        body = json.loads(resp.read())
        assert body["resource"] == cfg.resource_url
        assert body["authorization_servers"] == [cfg.issuer]
        assert "illumio-mcp.use" in body["scopes_supported"]


async def test_mcp_unauthenticated_returns_401_with_metadata_pointer(http_server):
    url, cfg = http_server
    req = urllib.request.Request(
        f"{url}/mcp",
        method="POST",
        data=b'{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}',
        headers={"Content-Type": "application/json"},
    )
    with pytest.raises(urllib.error.HTTPError) as exc_info:
        urllib.request.urlopen(req)
    assert exc_info.value.code == 401
    www_auth = exc_info.value.headers.get("WWW-Authenticate", "")
    assert www_auth.startswith("Bearer")
    assert 'resource_metadata="' in www_auth
    assert "/.well-known/oauth-protected-resource" in www_auth


async def test_mcp_with_valid_jwt_works(http_server, private_key_pem):
    """The same MCP initialize request, with a valid Bearer token, succeeds."""
    from mcp import ClientSession
    from mcp.client.streamable_http import streamablehttp_client

    url, _ = http_server
    token = _mint(private_key_pem)
    headers = {"Authorization": f"Bearer {token}"}
    async with streamablehttp_client(f"{url}/mcp", headers=headers) as (read, write, _get_session_id):
        async with ClientSession(read, write) as session:
            init = await session.initialize()
            assert init.serverInfo.name == "illumio-mcp"


async def test_mcp_with_invalid_jwt_returns_401(http_server):
    url, _ = http_server
    req = urllib.request.Request(
        f"{url}/mcp",
        method="POST",
        data=b'{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}',
        headers={"Content-Type": "application/json", "Authorization": "Bearer not-a-real-jwt"},
    )
    with pytest.raises(urllib.error.HTTPError) as exc_info:
        urllib.request.urlopen(req)
    assert exc_info.value.code == 401
