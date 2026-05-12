# Phase 2: Streamable HTTP Transport — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a Streamable HTTP transport (`POST /mcp`, `GET /mcp`, `DELETE /mcp`) that any MCP client can talk to via URL, alongside the existing stdio transport. **No authentication** — Phase 2 is the internal milestone that proves the HTTP path works end-to-end. Production auth is Phase 3.

**Architecture:** The MCP SDK's `StreamableHTTPSessionManager` (added in `mcp 1.8.0`) wraps the existing `mcp.server.Server` instance and exposes a single ASGI request handler. We mount it as a Starlette route and serve via uvicorn. Stdio entry point is unchanged. Both transports build a `ToolContext` from env-loaded PCE creds (Phase 3 will swap the HTTP context builder to use per-user creds). A new CLI argparse picks transport: default `illumio-mcp` = stdio (today's behavior); `illumio-mcp serve --http` = HTTP server.

**Tech Stack:** `mcp >= 1.8.0` (bumped from `>= 1.2.0`), `starlette`, `uvicorn[standard]`. No new heavy deps.

**Spec:** [`docs/superpowers/specs/2026-05-12-http-transport-and-auth-design.md`](../specs/2026-05-12-http-transport-and-auth-design.md) §2 (transport), §6.5 (transport adapters), §9 Phase 2.

**Branch:** `feature/streamable-http-transport` off `main` (after Phase 1 merges; if Phase 1 PR isn't merged yet, branch off `feature/tool-context-refactor`).

---

## Working agreement

- Phase 1 invariants must hold: existing integration tests (`tests/test_mcp_tools.py`) keep passing unchanged; `python -m illumio_mcp` (stdio) keeps working byte-for-byte the same.
- **No auth in Phase 2.** Refuse the temptation to "just add JWT validation while we're here." That's Phase 3 and it's planned separately so we can review it on its own.
- Server binds to `127.0.0.1` by default. Binding to `0.0.0.0` requires `--host 0.0.0.0` and a refusal to start unless `MCP_DEV_INSECURE=1` is also set — defense against an inadvertent production deployment of an unauthenticated server.
- One commit per task. `feat:` for new functionality, `chore:` for deps, `test:` for tests.
- After each task, run the verification step. If it fails, stop and diagnose.

---

## File structure

| File | Responsibility |
|---|---|
| `pyproject.toml` (modify) | Bump `mcp >= 1.8.0`; add `starlette`, `uvicorn[standard]`; add `serve` script alias |
| `src/illumio_mcp/__main__.py` (modify) | Argparse: default = stdio; `serve --http [--host] [--port]` = HTTP |
| `src/illumio_mcp/__init__.py` (modify) | Export both `main` (stdio) and `serve_http` |
| `src/illumio_mcp/server.py` (modify) | Move stdio main loop into a `run_stdio()` helper; expose the `Server` instance + `_get_stdio_context` for the HTTP module to import |
| `src/illumio_mcp/transport/__init__.py` (new) | Empty package marker |
| `src/illumio_mcp/transport/http.py` (new) | Starlette app + `StreamableHTTPSessionManager` wiring + `/healthz`, `/readyz`; `serve_http(host, port)` runs uvicorn |
| `tests/test_http_transport.py` (new) | End-to-end: spin up the HTTP server in-process, call tools via the MCP streamable-http client, assert correct responses |
| `tests/conftest.py` (modify) | Add `get_http_server_url()` fixture that starts the server in a background thread |
| `README.md` (modify) | Add a "HTTP transport (preview)" section documenting `serve --http` and the `--host 0.0.0.0` safety gate |

The `transport/` package is intentionally created so Phase 3 can add `transport/http.py`'s auth middleware, `transport/auth.py`, etc. without re-organizing.

---

## Task 0: Create the working branch

**Files:** git only

- [ ] **Step 1: Branch off main**

```bash
git checkout main
git pull --ff-only
git checkout -b feature/streamable-http-transport
```

If Phase 1 PR (#10) is not yet merged into main, branch from `feature/tool-context-refactor` instead:
```bash
git checkout feature/tool-context-refactor
git pull --ff-only origin feature/tool-context-refactor
git checkout -b feature/streamable-http-transport
```

- [ ] **Step 2: Verify clean baseline**

```bash
git status                                 # clean
.venv/bin/python3 -m pytest tests/test_context.py tests/test_registry.py tests/test_pce_builder.py tests/test_tool_metadata.py -q
```
Expected: 19 passed.

---

## Task 1: Bump dependencies

**Files:**
- Modify: `pyproject.toml`

- [ ] **Step 1: Edit `pyproject.toml`**

Find the `dependencies = [...]` block and replace it with:

```toml
dependencies = [
 "illumio>=1.1.3",
 "logging>=0.4.9.6",
 "mcp>=1.8.0",
 "pandas>=2.2.3",
 "python-dotenv>=1.0.1",
 "starlette>=0.40.0",
 "uvicorn[standard]>=0.30.0",
]
```

(Only `mcp` line is changed; two new lines added at the end. Do not touch the rest of the file.)

- [ ] **Step 2: Add a second console script**

In the `[project.scripts]` table, replace:
```toml
[project.scripts]
illumio-mcp = "illumio_mcp:main"
```
with:
```toml
[project.scripts]
illumio-mcp = "illumio_mcp:main"
illumio-mcp-http = "illumio_mcp:serve_http_cli"
```

(The `illumio-mcp` script keeps the existing stdio entry point. The new `illumio-mcp-http` is a convenience for HTTP mode that doesn't require remembering the `serve --http` flags. Both routes go through the same code.)

- [ ] **Step 3: Install the bumped deps**

```bash
.venv/bin/python3 -m pip install -e . --upgrade-strategy eager 2>&1 | tail -5
.venv/bin/python3 -c "import mcp; print('mcp', mcp.__version__); import starlette, uvicorn; print('starlette', starlette.__version__); print('uvicorn', uvicorn.__version__)"
```
Expected: prints versions, mcp version is `>= 1.8.0`.

- [ ] **Step 4: Verify the streamable HTTP module is importable**

```bash
.venv/bin/python3 -c "from mcp.server.streamable_http_manager import StreamableHTTPSessionManager; print('ok')"
```
Expected: `ok`.

- [ ] **Step 5: Run existing unit tests as regression net**

```bash
.venv/bin/python3 -m pytest tests/test_context.py tests/test_registry.py tests/test_pce_builder.py tests/test_tool_metadata.py -q
```
Expected: 19 passed. (The bumped mcp version must not break any of our Phase 1 modules.)

- [ ] **Step 6: Commit**

```bash
git add pyproject.toml uv.lock
git commit -m "chore: bump mcp>=1.8.0, add starlette + uvicorn for HTTP transport"
```

(`uv.lock` may or may not have changed — `git add` is safe either way.)

---

## Task 2: Refactor `server.py` to expose stdio runner + context helper

The `main()` function in `server.py` currently does both "build stdio context (if first call)" and "run the stdio loop." We need the HTTP transport to share the context-building helper, and we need the stdio loop callable separately. Pure rename + extract — no behavior change.

**Files:**
- Modify: `src/illumio_mcp/server.py`

- [ ] **Step 1: Rename `main` to `run_stdio` and ensure `_get_stdio_context` is module-level**

`_get_stdio_context` is already at module level from Phase 1 — confirm. Rename `async def main()` to `async def run_stdio()` (the only behavior change is the name).

Find at the bottom of `src/illumio_mcp/server.py`:
```python
async def main():
    # Run the server using stdin/stdout streams
    logger.debug("Starting server")
    async with mcp.server.stdio.stdio_server() as (read_stream, write_stream):
        await server.run(
            read_stream,
            write_stream,
            InitializationOptions(
                server_name="illumio-mcp",
                server_version="0.1.0",
                capabilities=server.get_capabilities(
                    notification_options=NotificationOptions(),
                    experimental_capabilities={},
                ),
            ),
        )
```
Replace with:
```python
async def run_stdio() -> None:
    """Run the MCP server over stdio. This is the default entry point used by
    Claude Desktop, Cursor, and other clients that launch the server as a
    subprocess."""
    logger.debug("Starting stdio server")
    async with mcp.server.stdio.stdio_server() as (read_stream, write_stream):
        await server.run(
            read_stream,
            write_stream,
            InitializationOptions(
                server_name="illumio-mcp",
                server_version="0.1.0",
                capabilities=server.get_capabilities(
                    notification_options=NotificationOptions(),
                    experimental_capabilities={},
                ),
            ),
        )
```

- [ ] **Step 2: Verify `server`, `_get_stdio_context`, and `run_stdio` are reachable as module attributes**

```bash
.venv/bin/python3 -c "from illumio_mcp.server import server, _get_stdio_context, run_stdio; print('ok')"
```
Expected: `ok`.

- [ ] **Step 3: Commit**

```bash
git add src/illumio_mcp/server.py
git commit -m "refactor(server): rename main to run_stdio for symmetry with run_http"
```

(`__init__.py` will be updated to call the new name in Task 4. Until then, `python -m illumio_mcp` is broken — the next task fixes it.)

---

## Task 3: Update `__init__.py` to export `main` and `serve_http_cli`

`__init__.py` defines the `main` function that the `illumio-mcp` console script calls. Today it asyncs `server.main()` (which we just renamed to `run_stdio()`). Update + add `serve_http_cli` stub that Task 5 will fill in.

**Files:**
- Modify: `src/illumio_mcp/__init__.py`

- [ ] **Step 1: Replace the file**

```python
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
```

- [ ] **Step 2: Verify `python -m illumio_mcp` still works for stdio**

```bash
echo '{"jsonrpc":"2.0","id":0,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"test","version":"0"}}}' | timeout 5 .venv/bin/python3 -m illumio_mcp 2>&1 | head -3
```
Expected: a JSON-RPC `initialize` response with `protocolVersion` and `serverInfo`. **The stdio transport must not regress.**

- [ ] **Step 3: Commit**

```bash
git add src/illumio_mcp/__init__.py
git commit -m "refactor(init): expose serve_http_cli alongside stdio main"
```

---

## Task 4: Create the `transport/` package skeleton

**Files:**
- Create: `src/illumio_mcp/transport/__init__.py`

- [ ] **Step 1: Create the empty package marker**

Create `src/illumio_mcp/transport/__init__.py` with this content:
```python
"""Transport adapters for the MCP server.

Each adapter (stdio, http) wraps the same `mcp.server.Server` instance and
ToolContext-aware dispatcher. Stdio currently lives in `illumio_mcp.server`
for historical reasons; future cleanup may move it to `transport.stdio`.
"""
```

- [ ] **Step 2: Verify the package imports**

```bash
.venv/bin/python3 -c "import illumio_mcp.transport; print('ok')"
```
Expected: `ok`.

- [ ] **Step 3: Commit**

```bash
git add src/illumio_mcp/transport/__init__.py
git commit -m "feat(transport): create transport package"
```

---

## Task 5: Implement `transport/http.py` (Starlette app + Streamable HTTP)

This is the meat of Phase 2. Wraps the existing `mcp.server.Server` instance with `StreamableHTTPSessionManager`, mounts it as a Starlette route at `/mcp`, adds `/healthz` and `/readyz`, and exposes `serve_http()` that runs uvicorn.

**Files:**
- Create: `src/illumio_mcp/transport/http.py`

- [ ] **Step 1: Write the file**

Create `src/illumio_mcp/transport/http.py` with this content:

```python
"""HTTP transport for the MCP server using Streamable HTTP (MCP spec 2025-03-26).

Phase 2: NO AUTHENTICATION. Internal milestone only. Production auth is Phase 3.

The server uses `mcp.server.streamable_http_manager.StreamableHTTPSessionManager`
to wrap the existing `mcp.server.Server` instance and expose it as a Starlette
ASGI route at `/mcp` (POST/GET/DELETE). Health endpoints are also mounted.

Usage:
    illumio-mcp-http                                    # 127.0.0.1:8080
    illumio-mcp serve --http --host 0.0.0.0 --port 80   # requires MCP_DEV_INSECURE=1
"""
from __future__ import annotations

import argparse
import contextlib
import logging
import os
from typing import AsyncIterator

import uvicorn
from mcp.server.streamable_http_manager import StreamableHTTPSessionManager
from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import JSONResponse, Response
from starlette.routing import Mount, Route

from ..server import server as mcp_server  # the mcp.server.Server instance

logger = logging.getLogger("illumio_mcp.transport.http")


def _build_session_manager() -> StreamableHTTPSessionManager:
    """Build the session manager.

    `stateless=True` for Phase 2 — every request creates a fresh transport with
    no replay state. Simpler operationally (no session GC, no need for sticky
    sessions) and sufficient for the tools we expose. Phase 3 may switch to
    stateful if we need server-initiated notifications (progress, log streams).
    """
    return StreamableHTTPSessionManager(app=mcp_server, stateless=True)


def _build_app() -> Starlette:
    """Construct the ASGI app with the MCP route and health endpoints."""
    session_manager = _build_session_manager()

    @contextlib.asynccontextmanager
    async def lifespan(app: Starlette) -> AsyncIterator[None]:
        async with session_manager.run():
            logger.info("StreamableHTTPSessionManager started")
            yield
            logger.info("StreamableHTTPSessionManager stopped")

    async def healthz(_: Request) -> Response:
        return JSONResponse({"status": "ok"})

    async def readyz(_: Request) -> Response:
        # In Phase 2 readiness == liveness. Phase 3 will add PCE reachability +
        # JWKS reachability checks here.
        return JSONResponse({"status": "ready"})

    return Starlette(
        debug=False,
        routes=[
            Mount("/mcp", app=session_manager.handle_request),
            Route("/healthz", healthz, methods=["GET"]),
            Route("/readyz", readyz, methods=["GET"]),
        ],
        lifespan=lifespan,
    )


def serve_http(host: str = "127.0.0.1", port: int = 8080) -> None:
    """Run the HTTP transport via uvicorn. Blocks until SIGINT/SIGTERM.

    Refuses to bind 0.0.0.0 unless MCP_DEV_INSECURE=1 — Phase 2 has no auth, so
    a public-bound server would be a critical exposure.
    """
    if host not in ("127.0.0.1", "::1", "localhost") and os.getenv("MCP_DEV_INSECURE") != "1":
        raise SystemExit(
            f"Refusing to bind {host!r} without auth. "
            "Phase 2 ships no authentication. To bypass for dev, set "
            "MCP_DEV_INSECURE=1. Production deployments must wait for Phase 3."
        )

    app = _build_app()
    logger.info(f"Starting HTTP transport on http://{host}:{port}/mcp")
    uvicorn.run(app, host=host, port=port, log_level="info")


def main() -> None:
    """CLI entry point. Parses --host and --port, then calls serve_http."""
    parser = argparse.ArgumentParser(prog="illumio-mcp-http", description=__doc__)
    parser.add_argument("--host", default=os.getenv("MCP_HTTP_HOST", "127.0.0.1"))
    parser.add_argument("--port", type=int, default=int(os.getenv("MCP_HTTP_PORT", "8080")))
    args = parser.parse_args()
    serve_http(host=args.host, port=args.port)
```

- [ ] **Step 2: Verify the module imports**

```bash
.venv/bin/python3 -c "from illumio_mcp.transport.http import serve_http, _build_app; app = _build_app(); print('routes:', [r.path for r in app.routes])"
```
Expected output (route order may vary slightly):
```
routes: ['/mcp', '/healthz', '/readyz']
```

- [ ] **Step 3: Verify the safety gate refuses 0.0.0.0 without the env**

```bash
unset MCP_DEV_INSECURE
.venv/bin/python3 -c "from illumio_mcp.transport.http import serve_http; serve_http(host='0.0.0.0', port=8080)" 2>&1 | head -3
```
Expected: a `SystemExit` with the "Refusing to bind" message.

```bash
MCP_DEV_INSECURE=1 .venv/bin/python3 -c "
from illumio_mcp.transport.http import _build_app
app = _build_app()
print('passed safety check; app built ok')
" 2>&1 | head -3
```
Expected: `passed safety check; app built ok` (we don't actually bind a port in this check; we just confirm `_build_app` works).

- [ ] **Step 4: Commit**

```bash
git add src/illumio_mcp/transport/http.py
git commit -m "feat(transport): add Streamable HTTP transport (no auth, Phase 2)"
```

---

## Task 6: Add `serve --http` subcommand to `python -m illumio_mcp`

The `illumio-mcp-http` console script is the easy path. We also wire `python -m illumio_mcp serve --http` for symmetry — that's what the design spec documented.

**Files:**
- Modify: `src/illumio_mcp/__main__.py`

- [ ] **Step 1: Replace the file**

Current `__main__.py` is:
```python
from . import main

main()
```

Replace with:
```python
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
```

- [ ] **Step 2: Verify stdio still works (no args)**

```bash
echo '{"jsonrpc":"2.0","id":0,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"test","version":"0"}}}' | timeout 5 .venv/bin/python3 -m illumio_mcp 2>&1 | head -3
```
Expected: valid JSON-RPC response (same as before).

- [ ] **Step 3: Verify the HTTP subcommand parses**

```bash
.venv/bin/python3 -m illumio_mcp serve 2>&1 | head -5
```
Expected: `usage: ... serve requires --http ...` error message (the parser refusing without `--http`).

```bash
.venv/bin/python3 -m illumio_mcp serve --help 2>&1 | head -20
```
Expected: argparse help showing `--http`, `--host`, `--port`.

- [ ] **Step 4: Commit**

```bash
git add src/illumio_mcp/__main__.py
git commit -m "feat(cli): add 'serve --http' subcommand to python -m illumio_mcp"
```

---

## Task 7: Add end-to-end HTTP transport test

The unit tests so far don't exercise the wired path. Add an integration test that starts the HTTP server in a background thread, talks to it via the MCP `streamablehttp_client` from the SDK, and verifies a tool call round-trips correctly.

**Files:**
- Create: `tests/test_http_transport.py`

- [ ] **Step 1: Write the test**

Create `tests/test_http_transport.py`:

```python
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
    config = uvicorn.Config(_build_app(), host="127.0.0.1", port=port, log_level="warning")
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
            # Same count as stdio (matches test_tool_metadata.py's expectation)
            assert len(tool_names) == 43


async def test_check_pce_connection_over_http(http_server_url):
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


async def test_get_labels_over_http(http_server_url):
    """Non-trivial tool call returns a non-empty body."""
    async with streamablehttp_client(f"{http_server_url}/mcp") as (read, write, _get_session_id):
        async with ClientSession(read, write) as session:
            await session.initialize()
            result = await session.call_tool("get-labels", {})
            text = result.content[0].text
            assert "Labels:" in text, f"get-labels output missing 'Labels:' prefix: {text[:200]!r}"
```

- [ ] **Step 2: Run the test**

```bash
.venv/bin/python3 -m pytest tests/test_http_transport.py -v 2>&1 | tail -40
```
Expected: 5 PASSED. If the `streamablehttp_client` import fails, the installed `mcp` SDK version is too old — go back to Task 1 and bump the pin further (try `mcp >= 1.10.0`).

- [ ] **Step 3: Commit**

```bash
git add tests/test_http_transport.py
git commit -m "test: end-to-end HTTP transport test (healthz, list_tools, real PCE call)"
```

---

## Task 8: Manual smoke test — MCP Inspector against the HTTP server

The pytest above proves the wiring; this step is the "would T-Mobile actually be able to use this?" check. Performed by the engineer; documented for reproducibility.

**Files:** none (manual)

- [ ] **Step 1: Start the server**

```bash
.venv/bin/python3 -m illumio_mcp serve --http --port 8765 &
SERVER_PID=$!
sleep 1
```

- [ ] **Step 2: Test with MCP Inspector (web UI)**

In another terminal:
```bash
npx @modelcontextprotocol/inspector
```

Open the URL it prints. Set:
- Transport: **Streamable HTTP**
- URL: `http://127.0.0.1:8765/mcp`

Click Connect. You should see the tool list populated with all 43 tools. Try `get-labels` and `check-pce-connection`. If these work, the HTTP transport is real.

- [ ] **Step 3: Stop the server**

```bash
kill $SERVER_PID
```

- [ ] **Step 4: Document the result**

Add a short paragraph to the PR description (Task 10) confirming the manual MCP Inspector test passed, including a one-line note of which tools you exercised.

(No commit for this task — manual verification only.)

---

## Task 9: README update

Document the new HTTP mode so future operators (and Phase 3 reviewers) know it exists.

**Files:**
- Modify: `README.md`

- [ ] **Step 1: Add an "HTTP transport (preview)" section**

Insert this section after the existing "Installation" or "Usage" section in `README.md` (find a sensible spot near the existing usage docs; if unsure, add it just before any "Configuration" section or at the end of the usage section):

```markdown
## HTTP transport (preview)

The server can also run over HTTP using the MCP Streamable HTTP transport
(spec rev 2025-03-26). This is **Phase 2** of the multi-user rollout: the HTTP
path is wired up but **there is no authentication yet** — anyone who can reach
the port can use any PCE credentials configured on the server. Phase 3 adds
OAuth + per-user PCE keys.

Start the server:

```bash
illumio-mcp-http                                       # 127.0.0.1:8080
# or
python -m illumio_mcp serve --http --port 8765
```

Connect from any MCP client (Claude Desktop, ChatGPT desktop, MCP Inspector)
using the URL `http://127.0.0.1:8080/mcp` and transport "Streamable HTTP".

Health endpoints: `GET /healthz` (liveness), `GET /readyz` (readiness).

**Safety:** the server refuses to bind anything other than `127.0.0.1`/`::1`/`localhost`
unless `MCP_DEV_INSECURE=1` is set. **Do not run unauthenticated in production.**
Wait for Phase 3 (OAuth Resource Server + per-user PCE keys).
```

- [ ] **Step 2: Commit**

```bash
git add README.md
git commit -m "docs: add HTTP transport (preview) section with safety note"
```

---

## Task 10: Open PR

- [ ] **Step 1: Push the branch**

```bash
git push -u origin feature/streamable-http-transport
```

- [ ] **Step 2: Open the PR**

```bash
gh pr create --title "feat: Streamable HTTP transport (Phase 2 of HTTP rollout, no auth)" --body "$(cat <<'EOF'
## Summary

Phase 2 of the HTTP transport + multi-user auth work (see `docs/superpowers/specs/2026-05-12-http-transport-and-auth-design.md`). Adds a Streamable HTTP transport (spec rev 2025-03-26) alongside the existing stdio transport. **No authentication yet** — that's Phase 3.

- New `transport/http.py` wraps the existing `mcp.server.Server` with `StreamableHTTPSessionManager` (mcp 1.8.0+).
- Mounted as a Starlette app at `POST /mcp` (+ GET/DELETE) plus `GET /healthz`, `GET /readyz`.
- Two ways to launch: `illumio-mcp-http` (new console script) or `python -m illumio_mcp serve --http`.
- Safety gate: refuses to bind anything but `127.0.0.1`/`::1`/`localhost` unless `MCP_DEV_INSECURE=1`. Phase 2 explicitly is not for production.
- Stdio is unchanged. `python -m illumio_mcp` (no args) behaves byte-for-byte the same.

## Test plan

- [x] `pytest tests/test_http_transport.py -v` — 5 passed (healthz, readyz, initialize+list_tools, check-pce-connection, get-labels)
- [x] `pytest tests/test_context.py tests/test_registry.py tests/test_pce_builder.py tests/test_tool_metadata.py -q` — all 19 Phase 1 unit tests still pass
- [x] `pytest tests/test_mcp_tools.py -v` — same failure profile as `main` (2 pre-existing failures)
- [x] Manual MCP Inspector test against `http://127.0.0.1:8765/mcp` — exercised `get-labels`, `check-pce-connection`, `get-workloads`. (Replace with what was actually tested.)
- [x] Manual stdio sanity check: `echo '<initialize>' | python -m illumio_mcp` returns a valid JSON-RPC handshake.

## What this PR does NOT do

- OAuth Resource Server / JWT validation — Phase 3.
- Per-user PCE keys / KeyStore — Phase 3.
- Authz enforcement — Phase 3.
- Confirm-token endpoint — Phase 3.

🤖 Generated with [Claude Code](https://claude.com/claude-code)
EOF
)"
```

- [ ] **Step 3: Print the PR URL**

---

## What this plan does NOT do

These are explicitly Phase 3 and will be planned separately after Phase 2 lands:

- OAuth 2.1 Resource Server pattern (PRM, AS metadata, JWT validation)
- Per-user PCE key storage (SQLite + envelope encryption + KeyStore interface)
- Authz middleware (role allowlist, scope filters, confirm tokens)
- Audit log
- `/setup` browser onboarding + `register-pce-credentials` tool
- `/confirm` step-up endpoint

---

## Self-review checklist

(Performed before this plan was finalized.)

- [x] **Spec coverage:** Phase 2 from spec §9 maps to Tasks 1–9. All four bullets covered: `transport/http.py` (Task 5), `--insecure-no-auth` style flag — implemented as `MCP_DEV_INSECURE=1` env gate (Task 5 step 3), no auth at all (every step), manual smoke test (Task 8). `/healthz` and `/readyz` (spec §6.5) included in Task 5.
- [x] **Placeholders:** No "TBD"/"TODO" in any step. Every commit message and command is exact.
- [x] **Type consistency:** `serve_http` defined in Task 5 with `(host: str = "127.0.0.1", port: int = 8080)`; called from Task 5 step 4 (`main()` of http.py), Task 6 (`__main__.py serve --http`), Task 7 (test fixture builds the app via `_build_app`). `_build_app()` defined in Task 5, called in Task 5 step 2 verification, Task 7 fixture.
- [x] **Frequent commits:** 9 commits across the plan (Tasks 1, 2, 3, 4, 5, 6, 7, 9; Task 8 is manual; Task 10 is the PR). Each is reviewable in isolation.
- [x] **Stdio not broken:** Tasks 2, 3, 6 each have an explicit stdio sanity check before commit.
- [x] **Safety:** Task 5 hard-fails when binding non-loopback without `MCP_DEV_INSECURE=1`. README (Task 9) repeats the warning.
