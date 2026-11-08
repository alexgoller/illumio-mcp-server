"""The Illumio Cloud Platform feature: present only when configured.

Ported from feature/cloud-platform-api (April 2026) onto the ToolSpec registry.
The contract the user asked for: with CLOUD_API_HOST/KEY/SECRET/TENANT_ID set
the six cloud tools exist; without them the server behaves as if they were
never written -- not advertised, not routable, not documented, not mentioned.
"""
import asyncio
import base64
import json
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from types import SimpleNamespace as NS

import pytest

from illumio_mcp import cloud_client, features
from illumio_mcp.context import ToolContext
from illumio_mcp.tools import TOOL_REGISTRY, visible_tools
from illumio_mcp.tools import cloud_inventory, cloud_labeling, cloud_traffic

CLOUD_NAMES = {"cloud-get-resources", "cloud-assign-labels", "cloud-remove-labels",
               "cloud-get-traffic-queries", "cloud-create-traffic-query", "cloud-get-traffic-flows"}
ENV = {"CLOUD_API_HOST": "https://cloud.example", "CLOUD_API_KEY": "k", "CLOUD_API_SECRET": "s", "CLOUD_TENANT_ID": "t-1"}


@pytest.fixture
def unconfigured(monkeypatch):
    for v in ENV: monkeypatch.delenv(v, raising=False)
    monkeypatch.delenv("MCP_HIDE_FEATURES", raising=False)
    cloud_client.reset_clients()


@pytest.fixture
def configured(monkeypatch):
    for k, v in ENV.items(): monkeypatch.setenv(k, v)
    monkeypatch.delenv("MCP_HIDE_FEATURES", raising=False)
    cloud_client.reset_clients()


async def _advertised():
    from illumio_mcp import server as srv
    import mcp.types as t
    return {x.name for x in await srv.handle_list_tools()}


# --- gating -------------------------------------------------------------------

def test_registry_always_carries_the_specs_but_marks_them_as_a_feature():
    assert CLOUD_NAMES <= set(TOOL_REGISTRY)
    assert all(TOOL_REGISTRY[n].feature == "cloud" and not TOOL_REGISTRY[n].requires_pce for n in CLOUD_NAMES)
    assert TOOL_REGISTRY["cloud-assign-labels"].mutating and TOOL_REGISTRY["cloud-create-traffic-query"].mutating
    assert not TOOL_REGISTRY["cloud-get-resources"].mutating


def test_unconfigured_feature_is_invisible_everywhere(unconfigured):
    assert not features.feature_enabled("cloud")
    assert not (CLOUD_NAMES & set(visible_tools()))
    assert not (CLOUD_NAMES & asyncio.run(_advertised()))


@pytest.mark.asyncio
async def test_unconfigured_cloud_tool_is_an_ordinary_unknown_tool(unconfigured):
    """No hint that the tool could exist: the same error any typo gets."""
    from illumio_mcp import server as srv
    token = srv.set_http_context(ToolContext(pce=object(), is_stdio=False, user_role="admin"))
    try:
        with pytest.raises(ValueError, match="Unknown tool: cloud-get-resources"):
            await srv.handle_call_tool("cloud-get-resources", {})
    finally:
        srv.reset_http_context(token)


def test_configured_feature_is_visible_and_advertised(configured):
    assert features.feature_enabled("cloud")
    assert CLOUD_NAMES <= set(visible_tools())
    assert CLOUD_NAMES <= asyncio.run(_advertised())


def test_partial_configuration_is_not_configured(monkeypatch, unconfigured):
    monkeypatch.setenv("CLOUD_API_HOST", "https://cloud.example"); monkeypatch.setenv("CLOUD_API_KEY", "k")
    assert not features.feature_enabled("cloud")


def test_hide_switch_overrides_configuration(configured, monkeypatch):
    monkeypatch.setenv("MCP_HIDE_FEATURES", "cloud")
    assert not features.feature_enabled("cloud") and not (CLOUD_NAMES & set(visible_tools()))


def test_docs_generator_never_lists_feature_tools():
    import pathlib
    text = pathlib.Path("docs/tools.md").read_text()
    assert "cloud-get-resources" not in text and "All 55 tools" in text


# --- client -------------------------------------------------------------------

class _Handler(BaseHTTPRequestHandler):
    seen = []
    def log_message(self, *a): pass
    def _reply(self, body):
        data = json.dumps(body).encode(); self.send_response(200); self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data))); self.end_headers(); self.wfile.write(data)
    def do_GET(self):
        _Handler.seen.append(("GET", self.path, dict(self.headers), None)); self._reply({"info": [{"query_id": "q1", "status": "completed"}]})
    def do_POST(self):
        n = int(self.headers.get("Content-Length") or 0); body = json.loads(self.rfile.read(n) or b"{}")
        _Handler.seen.append(("POST", self.path, dict(self.headers), body)); self._reply({"items": [], "total_size": 0})


@pytest.fixture
def cloud_server(monkeypatch):
    srv = HTTPServer(("127.0.0.1", 0), _Handler); t = threading.Thread(target=srv.serve_forever, daemon=True); t.start()
    _Handler.seen.clear()
    monkeypatch.setenv("CLOUD_API_HOST", f"http://127.0.0.1:{srv.server_port}/"); monkeypatch.setenv("CLOUD_API_KEY", "key1")
    monkeypatch.setenv("CLOUD_API_SECRET", "sec1"); monkeypatch.setenv("CLOUD_TENANT_ID", "tenant-9")
    cloud_client.reset_clients()
    yield srv
    srv.shutdown()


def test_platform_client_uses_basic_auth_and_tenant_header(cloud_server):
    cloud_client.get_cloud_platform_client().post_inventory({"max_results": 1})
    method, path, headers, body = _Handler.seen[-1]
    assert (method, path) == ("POST", "/api/v1/inventory/resources")
    assert headers["Authorization"] == "Basic " + base64.b64encode(b"key1:sec1").decode()
    assert headers["X-Tenant-Id"] == "tenant-9" and body == {"max_results": 1}


def test_traffic_client_uses_the_same_basic_auth_as_inventory(cloud_server):
    """The April branch sent x-api-key/x-api-secret; cloud.illum.io answers
    401 to that and authenticates Basic + X-Tenant-Id (measured 2026-11-08)."""
    cloud_client.get_cloud_traffic_client().get_queries()
    method, path, headers, _ = _Handler.seen[-1]
    assert (method, path) == ("GET", "/api/v1/fqs/async_queries/flows")
    assert headers["Authorization"] == "Basic " + base64.b64encode(b"key1:sec1").decode()
    assert headers["X-Tenant-Id"] == "tenant-9" and "x-api-key" not in headers


def test_clients_carry_bounded_retries_and_a_timeout(cloud_server):
    c = cloud_client.get_cloud_platform_client()
    retry = c._session.get_adapter("http://").max_retries
    assert type(retry).__name__ == "BoundedRetry" and retry.total <= 2 and c._timeout <= 30


def test_missing_host_is_a_clear_error(monkeypatch):
    for v in ENV: monkeypatch.delenv(v, raising=False)
    cloud_client.reset_clients()
    with pytest.raises(RuntimeError, match="CLOUD_API_HOST"):
        cloud_client.get_cloud_platform_client()


# --- handlers (fake client) ----------------------------------------------------

def _ctx(): return ToolContext(pce=None, is_stdio=True)


def test_inventory_paginates_and_flattens_labels(monkeypatch):
    pages = [{"items": [{"id": "r1", "name": "web-1", "csp_id": "i-1", "cloud": "aws", "object_type": "AWS::EC2::Instance",
                         "labels": [{"key": "app", "value": "shop"}], "ips": {"private": ["10.0.0.1"]}}],
              "total_size": 2, "next_page_token": "p2"},
             {"items": [{"id": "r2", "name": "db-1", "csp_id": "i-2", "cloud": "aws", "labels": []}], "total_size": 2}]
    calls = []
    class Fake:
        def post_inventory(self, body): calls.append(dict(body)); return pages[len(calls) - 1]
    monkeypatch.setattr(cloud_inventory, "get_cloud_platform_client", lambda: Fake())
    out = json.loads(cloud_inventory.handle_cloud_get_resources(_ctx(), {"clouds": ["aws"], "max_results": 10})[0].text)
    assert out["total_fetched"] == 2 and out["total_available"] == 2 and len(calls) == 2
    assert calls[0]["clouds"] == ["aws"] and calls[0]["with_total_count"] is True and calls[1]["page_token"] == "p2"
    rows = [dict(zip(out["columns"], r)) for r in out["data"]]
    assert rows[0]["app"] == "shop" and rows[0]["ip_addresses"] == "10.0.0.1" and rows[1]["name"] == "db-1"


def test_labeling_builds_add_and_remove_payloads(monkeypatch):
    sent = []
    class Fake:
        def post_label_assignments(self, body): sent.append(body); return {"failed_resources": [{"csp_id": "i-9"}]}
    monkeypatch.setattr(cloud_labeling, "get_cloud_platform_client", lambda: Fake())
    out = json.loads(cloud_labeling.handle_cloud_assign_labels(_ctx(), {"assignments": [
        {"csp_id": "i-1", "labels": [{"key": "app", "value": "shop"}]}, {"csp_id": "i-9", "labels": [{"key": "env", "value": "prod"}]}]})[0].text)
    assert sent[0] == {"label_assignments": [{"csp_id": "i-1", "add": [{"key": "app", "value": "shop"}]},
                                             {"csp_id": "i-9", "add": [{"key": "env", "value": "prod"}]}]}
    assert out == {"action": "add", "submitted": 2, "failed": 1, "succeeded": 1, "failed_resources": [{"csp_id": "i-9"}]}
    cloud_labeling.handle_cloud_remove_labels(_ctx(), {"assignments": [{"csp_id": "i-1", "labels": [{"key": "app", "value": "shop"}]}]})
    assert sent[1]["label_assignments"][0] == {"csp_id": "i-1", "remove": [{"key": "app", "value": "shop"}]}
    assert "error" in json.loads(cloud_labeling.handle_cloud_assign_labels(_ctx(), {"assignments": []})[0].text)


def test_traffic_query_lifecycle_and_flow_grouping(monkeypatch):
    created = []
    class Fake:
        def get_queries(self): return {"info": [{"query_id": "q1", "status": "completed", "matches_count": 3, "result": "/dl/q1",
                                                  "query_parameters": {"query_name": "n"}}]}
        def create_query(self, body): created.append(body); return {"info": [{"query_id": "q2", "status": "running"}]}
        def download_flows(self, uuid, offset=0, limit=5000):
            f = lambda n: {"src": {"ip": "10.0.0.1", "workload": {"hostname": "web01"}}, "dst": {"ip": "10.0.0.2", "cloud_resource": {"resource_uuid": "r-db", "type": "rds"}},
                           "service": {"port": 5432, "proto": 6}, "policy_decision": "allowed", "num_connections": n, "timestamp_range": {}}
            return {"flows": [f(5), f(7)]}
    monkeypatch.setattr(cloud_traffic, "get_cloud_traffic_client", lambda: Fake())
    q = json.loads(cloud_traffic.handle_cloud_get_traffic_queries(_ctx(), {})[0].text)
    assert q["total_queries"] == 1 and q["queries"][0] == {"query_id": "q1", "status": "completed", "query_name": "n", "matches_count": 3,
                                                           "flows_count": None, "created_at": None, "updated_at": None, "download_url": "/dl/q1"}
    c = json.loads(cloud_traffic.handle_cloud_create_traffic_query(_ctx(), {"start_date": "2026-11-01T00:00:00Z", "end_date": "2026-11-07T00:00:00Z",
                                                                             "policy_decisions": ["blocked"]})[0].text)
    assert c["query_id"] == "q2" and created[0]["policy_decisions"] == ["blocked"] and created[0]["sources"] == {"include": []}
    assert "error" in json.loads(cloud_traffic.handle_cloud_create_traffic_query(_ctx(), {"start_date": "x"})[0].text)
    d = json.loads(cloud_traffic.handle_cloud_get_traffic_flows(_ctx(), {"query_id": "q1"})[0].text)
    rows = [dict(zip(d["columns"], r)) for r in d["data"]]
    assert d["total_flows"] == 2 and d["total_grouped_rows"] == 1 and rows[0]["num_connections"] == 12
    assert rows[0]["src_name"] == "web01" and rows[0]["dst_type"] == "cloud:rds"
