"""MCP protocol-surface tests that do NOT require a live PCE.

Everything here talks to the server over real MCP stdio but only exercises
discovery (`tools/list`) -- no tool is actually invoked, so no PCE call happens.
Kept separate from `test_mcp_tools.py` (which drives real PCE CRUD) so these
keep running in CI, and on any laptop, without credentials.

Run with: .venv/bin/python3 -m pytest tests/test_mcp_protocol.py -v
"""
import pytest
from mcp import ClientSession
from mcp.client.stdio import stdio_client
from conftest import get_server_params
from illumio_mcp.tools import TOOL_REGISTRY


pytestmark = pytest.mark.asyncio


async def _list_tools():
    """Start the server over stdio and return its advertised tools."""
    async with stdio_client(get_server_params()) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()
            return (await session.list_tools()).tools


async def test_advertised_tools_match_registry():
    """The tools advertised over MCP must exactly match TOOL_REGISTRY.

    Tools are declared in two independent places: the `types.Tool(...)` literals
    in `handle_list_tools` (the schema and description the client sees) and
    `TOOL_REGISTRY` (the handler plus authz metadata). Nothing in the code keeps
    them in sync, so this test is the only thing standing between us and a tool
    that is advertised but unroutable, or registered but invisible.

    Deliberately derived rather than a hardcoded list: a literal list is a third
    place to forget, which is exactly how it silently drifted to 43 names while
    the server advertised 46.
    """
    advertised = {t.name for t in await _list_tools()}
    registered = set(TOOL_REGISTRY)

    assert advertised == registered, (
        "tools/list and TOOL_REGISTRY have drifted.\n"
        f"  advertised but not registered (unroutable): {sorted(advertised - registered)}\n"
        f"  registered but not advertised (invisible):  {sorted(registered - advertised)}"
    )

    # Non-vacuity guard: a derived assertion would also pass if both sides were
    # empty, e.g. if the registry failed to import its tool modules.
    assert len(advertised) >= 40, f"suspiciously few tools: {len(advertised)}"
    for core in ("check-pce-connection", "get-workloads", "get-labels"):
        assert core in advertised, f"core tool missing: {core}"


async def test_tools_have_input_schemas():
    for tool in await _list_tools():
        assert tool.inputSchema is not None, f"{tool.name} missing inputSchema"
        assert tool.inputSchema.get("type") == "object", \
            f"{tool.name} schema type should be 'object'"
