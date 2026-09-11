"""End-to-end tests for the Streamable HTTP transport.

Spins up the HTTP server in a background thread on a random port, then uses the
official MCP SDK streamable-http client to call a tool. Verifies the wiring
from HTTP request -> StreamableHTTPSessionManager -> ToolContext dispatcher ->
tool handler -> response -> HTTP response works end-to-end.

These tests REQUIRE a reachable PCE (same env as test_mcp_tools.py). One test
exists per important behavior; this is not a substitute for the per-tool
integration suite — it's the proof that the HTTP transport is wired correctly.
"""
import asyncio
import socket
import threading
import time

import pytest
from mcp import ClientSession
from mcp.client.streamable_http import streamablehttp_client


pytestmark = pytest.mark.asyncio


def _free_port() -> int:
    """Find an unused TCP port for the test server."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


@pytest.fixture(scope="module")
def http_server_url():
    """Start the HTTP transport on a free local port for the duration of the
    test module. Yields the base URL (no trailing slash)."""
    import uvicorn
    from illumio_mcp.transport.http import _build_app

    port = _free_port()
    from illumio_mcp.auth.audit import NullAuditLog
    config = uvicorn.Config(_build_app(None, None, None, NullAuditLog(), None, None, "per_user"), host="127.0.0.1", port=port, log_level="warning")
    server = uvicorn.Server(config)

    thread = threading.Thread(target=server.run, daemon=True)
    thread.start()

    # Wait for the server to be ready (poll /healthz)
    import urllib.request
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


async def test_healthz(http_server_url):
    """Liveness check responds 200 with status=ok."""
    import urllib.request, json
    with urllib.request.urlopen(f"{http_server_url}/healthz") as resp:
        assert resp.status == 200
        body = json.loads(resp.read())
        assert body == {"status": "ok"}


async def test_readyz(http_server_url):
    import urllib.request, json
    with urllib.request.urlopen(f"{http_server_url}/readyz") as resp:
        assert resp.status == 200
        body = json.loads(resp.read())
        assert body == {"status": "ready"}


async def test_initialize_and_list_tools_over_http(http_server_url):
    """The MCP initialize handshake works and list_tools returns the same set
    of tools as the stdio transport."""
    async with streamablehttp_client(f"{http_server_url}/mcp") as (read, write, _get_session_id):
        async with ClientSession(read, write) as session:
            await session.initialize()
            tools = await session.list_tools()
            tool_names = {t.name for t in tools.tools}
            # Sanity: a handful of well-known tools from the registry
            for expected in ("get-labels", "get-workloads", "check-pce-connection", "provision-policy"):
                assert expected in tool_names, f"Missing {expected!r} in HTTP-transport tool list"
            # Derived, not hardcoded: a literal count is another place to forget
            # when a tool is added (see tests/test_mcp_protocol.py).
            from illumio_mcp.tools import TOOL_REGISTRY
            assert set(tool_names) == set(TOOL_REGISTRY)


async def test_check_pce_connection_over_http(http_server_url, requires_pce):
    """A real tool call round-trips through HTTP. Uses check-pce-connection
    because it's fast and proves the PCE handshake reaches Illumio via the
    same ToolContext path that stdio uses."""
    async with streamablehttp_client(f"{http_server_url}/mcp") as (read, write, _get_session_id):
        async with ClientSession(read, write) as session:
            await session.initialize()
            result = await session.call_tool("check-pce-connection", {})
            text = result.content[0].text
            assert "successful" in text.lower() or "True" in text, \
                f"check-pce-connection returned unexpected text: {text!r}"


async def test_get_labels_over_http(http_server_url, requires_pce):
    """Non-trivial tool call returns a non-empty body."""
    async with streamablehttp_client(f"{http_server_url}/mcp") as (read, write, _get_session_id):
        async with ClientSession(read, write) as session:
            await session.initialize()
            result = await session.call_tool("get-labels", {})
            text = result.content[0].text
            assert "Labels:" in text, f"get-labels output missing 'Labels:' prefix: {text[:200]!r}"


async def test_list_tools_works_without_any_pce_configuration(http_server_url, monkeypatch):
    """tools/list must not require a PCE.

    Regression: in dev-insecure mode the per-request context builder called
    get_pce_from_env() unconditionally, so with no PCE_* env vars
    PolicyComputeEngine(None) raised straight out of the ASGI handler and the
    MCP endpoint answered 500 -- for a request that needs no PCE at all.

    Only CI caught this: a local .env always supplies a host string, which
    constructs fine and fails later at request time.
    """
    from illumio_mcp import pce as pce_mod

    for var in ("PCE_HOST", "PCE_PORT", "PCE_ORG_ID", "API_KEY", "API_SECRET"):
        monkeypatch.delenv(var, raising=False)
    monkeypatch.setattr(pce_mod, "_stdio_singleton", None)  # defeat memoisation

    async with streamablehttp_client(f"{http_server_url}/mcp") as (read, write, _):
        async with ClientSession(read, write) as session:
            await session.initialize()
            tools = await session.list_tools()

    from illumio_mcp.tools import TOOL_REGISTRY
    assert {t.name for t in tools.tools} == set(TOOL_REGISTRY)
