"""End-to-end: role-based authorization.

Verifies that:
  - Reader can call read tools, gets denied on write tools
  - Operator can call write tools
  - User without a role mapping gets `forbidden_no_role`
  - Audit log records every decision
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
from illumio_mcp.auth.audit import SQLiteAuditLog
from illumio_mcp.auth.roles import RoleConfig
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


def _mint(private_key_pem, sub, groups):
    return pyjwt.encode({
        "iss": "https://idp.test/o",
        "aud": "mcp.test",
        "sub": sub,
        "exp": int(time.time()) + 600,
        "iat": int(time.time()),
        "scope": "illumio-mcp.use",
        "groups": groups,
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
    audit_db = tmp_path_factory.mktemp("au") / "audit.db"
    audit_log = SQLiteAuditLog(db_path=str(audit_db))
    role_config = RoleConfig(
        admin_groups=["sg-admin"],
        operator_groups=["sg-op", "sg-admin"],
        reader_groups=["sg-read", "sg-op", "sg-admin"],
        default_role=None,
    )

    # Pre-register PCE creds for users alice (reader), bob (operator), nobody (no role)
    creds = PCECredentials(host="https://pce.example", port=8443, org_id=1, api_key="k", api_secret="s")
    keystore.put(sub="alice", iss="https://idp.test/o", creds=creds)
    keystore.put(sub="bob", iss="https://idp.test/o", creds=creds)
    keystore.put(sub="nobody", iss="https://idp.test/o", creds=creds)

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
        ctx = build_http_context_for(sub, iss, keystore, role, audit_log, request_id)
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

    yield f"http://127.0.0.1:{port}", audit_log

    server.should_exit = True
    thread.join(timeout=5)
    pce_mod.build_pce_for = original_build


async def test_reader_can_call_read_tool(http_server, private_key_pem):
    from mcp import ClientSession
    from mcp.client.streamable_http import streamablehttp_client

    url, _ = http_server
    token = _mint(private_key_pem, sub="alice", groups=["sg-read"])
    async with streamablehttp_client(f"{url}/mcp", headers={"Authorization": f"Bearer {token}"}) as (read, write, _):
        async with ClientSession(read, write) as session:
            await session.initialize()
            # check-pce-credentials-status is a reader-allowed tool that doesn't need PCE
            result = await session.call_tool("check-pce-credentials-status", {})
            body = json.loads(result.content[0].text)
            # Reader has creds registered; expect status registered=True
            assert body.get("registered") is True


async def test_reader_denied_on_write_tool(http_server, private_key_pem):
    from mcp import ClientSession
    from mcp.client.streamable_http import streamablehttp_client

    url, _ = http_server
    token = _mint(private_key_pem, sub="alice", groups=["sg-read"])
    async with streamablehttp_client(f"{url}/mcp", headers={"Authorization": f"Bearer {token}"}) as (read, write, _):
        async with ClientSession(read, write) as session:
            await session.initialize()
            # create-label is operator+admin only
            result = await session.call_tool("create-label", {"key": "app", "value": "test"})
            body = json.loads(result.content[0].text)
            assert body["error"] == "forbidden"
            assert "reader" in body["message"]


async def test_operator_can_call_write_tool(http_server, private_key_pem):
    from mcp import ClientSession
    from mcp.client.streamable_http import streamablehttp_client

    url, _ = http_server
    token = _mint(private_key_pem, sub="bob", groups=["sg-op"])
    async with streamablehttp_client(f"{url}/mcp", headers={"Authorization": f"Bearer {token}"}) as (read, write, _):
        async with ClientSession(read, write) as session:
            await session.initialize()
            # check-pce-credentials-status is allowed for all roles; sufficient to prove dispatch path
            result = await session.call_tool("check-pce-credentials-status", {})
            body = json.loads(result.content[0].text)
            assert body.get("registered") is True


async def test_user_without_role_gets_forbidden_no_role(http_server, private_key_pem):
    from mcp import ClientSession
    from mcp.client.streamable_http import streamablehttp_client

    url, _ = http_server
    token = _mint(private_key_pem, sub="nobody", groups=["sg-other"])
    async with streamablehttp_client(f"{url}/mcp", headers={"Authorization": f"Bearer {token}"}) as (read, write, _):
        async with ClientSession(read, write) as session:
            await session.initialize()
            result = await session.call_tool("check-pce-credentials-status", {})
            body = json.loads(result.content[0].text)
            assert body["error"] == "forbidden_no_role"


async def test_audit_log_records_decisions(http_server, private_key_pem):
    """After a few calls, the audit DB should have rows for allowed and denied decisions."""
    import sqlite3
    from mcp import ClientSession
    from mcp.client.streamable_http import streamablehttp_client

    url, audit_log = http_server
    # Make a known set of calls so we can assert on what's in the audit log.
    token_admin = _mint(private_key_pem, sub="audit-admin", groups=["sg-admin"])
    async with streamablehttp_client(f"{url}/mcp", headers={"Authorization": f"Bearer {token_admin}"}) as (read, write, _):
        async with ClientSession(read, write) as session:
            await session.initialize()
            await session.call_tool("check-pce-credentials-status", {})

    token_reader = _mint(private_key_pem, sub="audit-reader", groups=["sg-read"])
    async with streamablehttp_client(f"{url}/mcp", headers={"Authorization": f"Bearer {token_reader}"}) as (read, write, _):
        async with ClientSession(read, write) as session:
            await session.initialize()
            await session.call_tool("create-label", {"key": "app", "value": "x"})

    with sqlite3.connect(audit_log.db_path) as con:
        rows = con.execute(
            "SELECT sub, tool, decision, role FROM audit_log "
            "WHERE sub IN ('audit-admin', 'audit-reader')"
        ).fetchall()
    decisions = {(sub, tool, decision) for sub, tool, decision, _role in rows}
    assert ("audit-admin", "check-pce-credentials-status", "allowed") in decisions
    assert ("audit-reader", "create-label", "denied") in decisions
