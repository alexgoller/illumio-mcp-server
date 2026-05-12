"""End-to-end: confirm-token enforcement on requires_confirm tools.

Verifies:
  - Calling provision-policy without a token → confirm_required error
  - POST /confirm mints a token
  - Calling provision-policy WITH the token → handler runs (gets PCE error since
    we stub PCE to raise — proves we got past the dispatcher gate)
  - Replaying the token → confirm_token_replay error
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
from illumio_mcp.auth.audit import NullAuditLog
from illumio_mcp.auth.roles import RoleConfig
from illumio_mcp.auth.confirm import ConfirmTokenManager, generate_hmac_key, canonical_params_hash
from illumio_mcp.auth.confirm_replay import SQLiteJtiStore
from illumio_mcp.pce import PCECredentials


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
    from illumio_mcp.transport.confirm_endpoint import build_confirm_routes
    from illumio_mcp.auth.roles import map_user_role
    import illumio_mcp.pce as pce_mod

    class FakePCE:
        def __init__(self, host):
            self.host = host

    original_build = pce_mod.build_pce_for
    pce_mod.build_pce_for = lambda creds: FakePCE(creds.host)  # type: ignore[assignment]

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
    audit = NullAuditLog()
    role_config = RoleConfig(
        admin_groups=["sg-admin"],
        operator_groups=["sg-op", "sg-admin"],
        reader_groups=["sg-read", "sg-op", "sg-admin"],
        default_role=None,
    )
    confirm_manager = ConfirmTokenManager(generate_hmac_key(), ttl_seconds=120)
    jti_store = SQLiteJtiStore(db_path=str(tmp_path_factory.mktemp("jti") / "jti.db"))

    creds = PCECredentials(host="https://pce.example", port=8443, org_id=1, api_key="k", api_secret="s")
    keystore.put(sub="alice", iss="https://idp.test/o", creds=creds)

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
        ctx = build_http_context_for(
            sub, iss, keystore, role, audit, request_id,
            confirm_manager=confirm_manager, jti_store=jti_store,
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

    routes = [
        Mount("/mcp", app=mcp_handler_wrapper),
        Route("/healthz", healthz, methods=["GET"]),
        *build_confirm_routes(confirm_manager, audit),
    ]

    app = Starlette(
        routes=routes,
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

    yield f"http://127.0.0.1:{port}", confirm_manager

    server.should_exit = True
    thread.join(timeout=5)
    pce_mod.build_pce_for = original_build


async def test_provision_policy_without_token_is_denied(http_server, private_key_pem):
    from mcp import ClientSession
    from mcp.client.streamable_http import streamablehttp_client

    url, _ = http_server
    token = _mint(private_key_pem, sub="alice", groups=["sg-admin"])
    async with streamablehttp_client(f"{url}/mcp", headers={"Authorization": f"Bearer {token}"}) as (read, write, _):
        async with ClientSession(read, write) as session:
            await session.initialize()
            result = await session.call_tool("provision-policy", {"description": "test"})
            body = json.loads(result.content[0].text)
            assert body["error"] == "confirm_required"
            assert "params_hash" in body
            assert len(body["params_hash"]) == 64


async def test_post_confirm_mints_token(http_server, private_key_pem):
    url, _ = http_server
    jwt_token = _mint(private_key_pem, sub="alice", groups=["sg-admin"])
    body_in = json.dumps({"tool": "provision-policy", "params_hash": "h" * 64}).encode()
    req = urllib.request.Request(
        f"{url}/confirm",
        method="POST",
        data=body_in,
        headers={"Authorization": f"Bearer {jwt_token}", "Content-Type": "application/json"},
    )
    with urllib.request.urlopen(req) as resp:
        assert resp.status == 200
        body = json.loads(resp.read())
        assert body["confirm_token"]
        assert body["expires_in"] == 120


async def test_provision_with_valid_token_passes_dispatcher(http_server, private_key_pem):
    """Mints a token for specific params, then calls the tool with that token.
    The handler will fail (FakePCE doesn't really provision), but the failure
    should be a tool-level error, NOT a confirm-related dispatcher rejection."""
    from mcp import ClientSession
    from mcp.client.streamable_http import streamablehttp_client

    url, _ = http_server
    jwt_token = _mint(private_key_pem, sub="alice", groups=["sg-admin"])

    args = {"description": "phase-3d-test"}
    params_hash = canonical_params_hash(args)

    body_in = json.dumps({"tool": "provision-policy", "params_hash": params_hash}).encode()
    req = urllib.request.Request(
        f"{url}/confirm",
        method="POST",
        data=body_in,
        headers={"Authorization": f"Bearer {jwt_token}", "Content-Type": "application/json"},
    )
    with urllib.request.urlopen(req) as resp:
        confirm_token = json.loads(resp.read())["confirm_token"]

    args_with_meta = {**args, "_meta": {"confirm_token": confirm_token}}
    async with streamablehttp_client(f"{url}/mcp", headers={"Authorization": f"Bearer {jwt_token}"}) as (read, write, _):
        async with ClientSession(read, write) as session:
            await session.initialize()
            result = await session.call_tool("provision-policy", args_with_meta)
            body = json.loads(result.content[0].text)
            assert body.get("error") not in ("confirm_required", "invalid_confirm_token", "confirm_token_replay")


async def test_replay_of_confirm_token_is_denied(http_server, private_key_pem):
    from mcp import ClientSession
    from mcp.client.streamable_http import streamablehttp_client

    url, _ = http_server
    jwt_token = _mint(private_key_pem, sub="alice", groups=["sg-admin"])

    args = {"description": "replay-test"}
    params_hash = canonical_params_hash(args)
    body_in = json.dumps({"tool": "provision-policy", "params_hash": params_hash}).encode()
    req = urllib.request.Request(
        f"{url}/confirm",
        method="POST",
        data=body_in,
        headers={"Authorization": f"Bearer {jwt_token}", "Content-Type": "application/json"},
    )
    with urllib.request.urlopen(req) as resp:
        confirm_token = json.loads(resp.read())["confirm_token"]

    args_with_meta = {**args, "_meta": {"confirm_token": confirm_token}}

    # First use: passes the dispatcher gate
    async with streamablehttp_client(f"{url}/mcp", headers={"Authorization": f"Bearer {jwt_token}"}) as (read, write, _):
        async with ClientSession(read, write) as session:
            await session.initialize()
            await session.call_tool("provision-policy", args_with_meta)

    # Replay: dispatcher should refuse before the handler runs
    async with streamablehttp_client(f"{url}/mcp", headers={"Authorization": f"Bearer {jwt_token}"}) as (read, write, _):
        async with ClientSession(read, write) as session:
            await session.initialize()
            result = await session.call_tool("provision-policy", args_with_meta)
            body = json.loads(result.content[0].text)
            assert body["error"] == "confirm_token_replay"
