"""Entry point for `python -m illumio_mcp`.

Default behavior: run stdio (preserves today's UX).
With `serve --http`: run the HTTP server.
"""
import argparse
import sys


def _run() -> None:
    parser = argparse.ArgumentParser(prog="python -m illumio_mcp")
    sub = parser.add_subparsers(dest="command")

    serve = sub.add_parser("serve", help="Run a network server")
    serve.add_argument("--http", action="store_true", help="Run the Streamable HTTP transport")
    serve.add_argument("--host", default=None, help="Bind host (default 127.0.0.1; env MCP_HTTP_HOST)")
    serve.add_argument("--port", type=int, default=None, help="Bind port (default 8080; env MCP_HTTP_PORT)")

    args = parser.parse_args()

    if args.command is None:
        # Default: stdio, just like before.
        from . import main as stdio_main
        stdio_main()
        return

    if args.command == "serve":
        if not args.http:
            parser.error("`serve` requires --http (no other transports available)")
        from .transport.http import serve_http
        import os
        host = args.host or os.getenv("MCP_HTTP_HOST", "127.0.0.1")
        port = args.port if args.port is not None else int(os.getenv("MCP_HTTP_PORT", "8080"))
        serve_http(host=host, port=port)
        return

    parser.error(f"Unknown command: {args.command!r}")


_run()
