"""A dead PCE must produce an error in bounded time, not silence.

Measured 2026-10-15: demo100's front end answered 504 Gateway Timeout after
~18s on every request. The SDK's retry policy (5 retries, backoff 2/4/8/16/32s,
504 in the forcelist, 30s per attempt) turned that into ~3 minutes per request
and check-pce-connection makes two -- six minutes of nothing, which a Claude
Desktop session reported as "tools/call never answers".
"""
import asyncio
import json
import threading
import time
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest

from illumio_mcp import pce as pce_mod
from illumio_mcp.context import ToolContext


class _Handler(BaseHTTPRequestHandler):
    mode = "504"
    def log_message(self, *a): pass
    def do_GET(self):
        if self.mode == "hang":
            time.sleep(6)            # longer than any timeout a test sets
            return
        self.send_response(504)
        self.send_header("Retry-After", "600")
        self.send_header("Content-Type", "text/plain")
        self.end_headers()
        self.wfile.write(b"upstream request timeout")


@pytest.fixture
def dead_pce(request):
    mode = getattr(request, "param", "504")
    handler = type("H", (_Handler,), {"mode": mode})
    srv = HTTPServer(("127.0.0.1", 0), handler)
    t = threading.Thread(target=srv.serve_forever, daemon=True); t.start()
    yield f"http://127.0.0.1:{srv.server_port}"
    srv.shutdown()


def _client(monkeypatch, url, **env):
    for k, v in env.items():
        monkeypatch.setenv(k, str(v))
    creds = pce_mod.PCECredentials(host=url, port=int(url.rsplit(":", 1)[1]), org_id=1,
                                   api_key="k", api_secret="s", tls_verify=False)
    return pce_mod.build_pce_for(creds)


# --- bounded retries ----------------------------------------------------------

def test_504_with_a_long_retry_after_fails_fast_and_names_the_status(monkeypatch, dead_pce):
    """Retry-After: 600 must not be honoured for ten minutes."""
    pce = _client(monkeypatch, dead_pce, MCP_PCE_RETRIES=1, MCP_PCE_REQUEST_TIMEOUT=5,
                  MCP_PCE_RETRY_AFTER_CAP=1)
    t = time.monotonic()
    with pytest.raises(Exception) as ei:
        pce.get("/health", include_org=False)
    assert time.monotonic() - t < 8
    from illumio_mcp.errors import describe_error
    assert "504" in describe_error(ei.value)


@pytest.mark.parametrize("dead_pce", ["hang"], indirect=True)
def test_a_pce_that_never_answers_fails_within_the_request_timeout(monkeypatch, dead_pce):
    pce = _client(monkeypatch, dead_pce, MCP_PCE_RETRIES=1, MCP_PCE_REQUEST_TIMEOUT=1)
    t = time.monotonic()
    with pytest.raises(Exception) as ei:
        pce.get("/health", include_org=False)
    assert time.monotonic() - t < 6          # 2 attempts x 1s + 1s backoff
    from illumio_mcp.errors import describe_error
    assert "timed out" in describe_error(ei.value).lower()


def test_defaults_are_bounded(monkeypatch):
    for k in ("MCP_PCE_RETRIES", "MCP_PCE_REQUEST_TIMEOUT", "MCP_PCE_RETRY_AFTER_CAP"):
        monkeypatch.delenv(k, raising=False)
    pce = _client(monkeypatch, "http://127.0.0.1:9")
    retry = pce._session.get_adapter("http://").max_retries
    assert retry.total <= 2 and retry.backoff_max <= 15
    assert pce_mod.retry_budget_seconds(pce) < 120, "a single request must be able to fail in under two minutes"


# --- check-pce-connection answers quickly ------------------------------------

def test_check_pce_connection_reports_the_504_within_seconds(monkeypatch, dead_pce):
    from illumio_mcp.tools.infra import handle_check_pce_connection
    pce = _client(monkeypatch, dead_pce, MCP_PCE_RETRIES=1, MCP_PCE_REQUEST_TIMEOUT=5, MCP_PCE_RETRY_AFTER_CAP=1)
    t = time.monotonic()
    out = handle_check_pce_connection(ToolContext(pce=pce, is_stdio=True), {})[0].text
    assert time.monotonic() - t < 15
    assert "504" in out and "/health" in out
    assert "seconds" in out                  # says how long it waited


# --- dispatcher deadline ------------------------------------------------------

@pytest.mark.asyncio
async def test_a_tool_that_exceeds_the_deadline_gets_an_error_not_silence(monkeypatch):
    from illumio_mcp import server as srv
    from illumio_mcp.registry import ToolSpec, ALL_ROLES
    monkeypatch.setenv("MCP_TOOL_TIMEOUT_SECONDS", "1")
    def slow(ctx, args):
        time.sleep(3); return []
    monkeypatch.setitem(srv.TOOL_REGISTRY, "slow-tool", ToolSpec(slow, roles=ALL_ROLES, requires_pce=False))
    token = srv.set_http_context(ToolContext(pce=object(), is_stdio=False, user_role="admin"))
    try:
        t = time.monotonic()
        out = await srv.handle_call_tool("slow-tool", {})
    finally:
        srv.reset_http_context(token)
    body = json.loads(out[0].text)
    assert time.monotonic() - t < 2.5
    assert body["error"] == "tool_timeout" and body["tool"] == "slow-tool" and body["after_seconds"] == 1
    assert "check-pce-connection" in body["message"]


@pytest.mark.asyncio
async def test_tool_start_is_logged_at_info(monkeypatch, caplog):
    """The laptop log showed only the client side; the server log at INFO
    recorded completions only, so a hung tool left no trace of which it was."""
    import logging
    from illumio_mcp import server as srv
    from illumio_mcp.registry import ToolSpec, ALL_ROLES
    monkeypatch.setitem(srv.TOOL_REGISTRY, "quick-tool", ToolSpec(lambda c, a: [], roles=ALL_ROLES, requires_pce=False))
    token = srv.set_http_context(ToolContext(pce=object(), is_stdio=False, user_role="admin"))
    log = logging.getLogger("illumio_mcp")      # has its own file handler, no propagation
    log.addHandler(caplog.handler)
    try:
        with caplog.at_level(logging.INFO, logger="illumio_mcp"):
            await srv.handle_call_tool("quick-tool", {})
    finally:
        log.removeHandler(caplog.handler)
        srv.reset_http_context(token)
    assert any("quick-tool" in r.message and "called" in r.message and r.levelno == logging.INFO for r in caplog.records)
