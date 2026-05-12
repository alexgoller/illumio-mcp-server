from . import server
import asyncio


def main() -> None:
    """Stdio entry point. Default behavior — what `illumio-mcp` runs."""
    asyncio.run(server.run_stdio())


def serve_http_cli() -> None:
    """HTTP entry point. What `illumio-mcp-http` runs.

    Defined here as a stable import target for pyproject.toml's [project.scripts].
    The actual implementation lives in `illumio_mcp.transport.http` and is
    imported lazily so stdio users don't pay the Starlette/uvicorn import cost.
    """
    from .transport.http import main as http_main
    http_main()


__all__ = ["main", "serve_http_cli", "server"]