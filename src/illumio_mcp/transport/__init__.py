"""Transport adapters for the MCP server.

Each adapter (stdio, http) wraps the same `mcp.server.Server` instance and
ToolContext-aware dispatcher. Stdio currently lives in `illumio_mcp.server`
for historical reasons; future cleanup may move it to `transport.stdio`.
"""
