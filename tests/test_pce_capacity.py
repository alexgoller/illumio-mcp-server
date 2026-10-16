"""get-pce-capacity: how full is this PCE, and can we read its object limits.

Shapes measured on demo100 (26.30.4) on 2026-10-15:
  GET  /traffic_flows/database_metrics              200, per-source size/days with limits
  POST /reports/time_series_statistics              201 for num_managed_workloads; 406
                                                    unsupported_property for the others
  GET  /events?event_type=soft_limit_exceeded       200 []
  GET  /api/v2/object_limit_profiles                403, empty body -- exists, key not allowed
  GET  /api/v2/api_usage_limit_profiles             403
"""
import json
from types import SimpleNamespace as NS

import pytest

from illumio_mcp.context import ToolContext
from illumio_mcp.tools import TOOL_REGISTRY
from illumio_mcp.tools.capacity import handle_get_pce_capacity

DB = {"org_id": 1, "server": {"flows_size_gb": 13.0, "num_flows_days": 33, "flows_size_gb_limit": 26, "num_flow_days_limit": 90},
      "endpoint": {"flows_size_gb": 0.07, "num_flows_days": 18, "num_flow_days_limit": 14},
      "scanner": {"flows_size_gb": 0.02, "num_flows_days": 12},
      "flows_days": 33, "flows_size_gb": 13.1, "flows_days_limit": 90, "flows_size_gb_limit": 26,
      "flows_per_second": 3.17, "updated_at": "2026-10-15T15:29:01Z", "backlog": {"total_disk_used_gb": 0.0, "total_file_count": 0}}
TS = [{"property": "num_managed_workloads", "time_series": [
    {"start_date": "2026-10-15", "end_date": "2026-10-15", "data": {"count": 170}},
    {"start_date": "2026-10-14", "end_date": "2026-10-14", "data": {"count": 168}},
    {"start_date": "2026-10-06", "end_date": "2026-10-06", "data": {"count": 160}}]}]


class FakeResponse:
    def __init__(self, status, body=None, text=""):
        self.status_code = status; self._body = body; self.text = text if body is None else json.dumps(body)
        self.headers = {"X-Request-ID": "req-1"}
    def json(self):
        if self._body is None: raise ValueError("no json")
        return self._body


class FakePCE:
    def __init__(self, routes):
        self.routes = routes; self.calls = []; self.org_id = 1; self._hostname = "pce.test"; self._port = 443; self._timeout = 30
        self._session = NS(request=self._request)
    def _build_url(self, endpoint, include_org):
        endpoint = endpoint.lstrip("/")
        if include_org and not endpoint.startswith("orgs/"): endpoint = f"orgs/{self.org_id}/{endpoint}"
        return f"https://pce.test:443/api/v2/{endpoint}"
    def _request(self, method, url, **kw):
        path = url.split("/api/v2", 1)[1]
        self.calls.append((method, path, kw.get("params"), kw.get("json")))
        for key, resp in self.routes.items():
            if path.startswith(key): return resp() if callable(resp) else resp
        return FakeResponse(404, text="<html>404 Not Found</html>")


def _routes(**over):
    base = {
        "/product_version": FakeResponse(200, {"version": "26.30.4", "long_display": "26.30.4-52"}),
        "/orgs/1/traffic_flows/database_metrics": FakeResponse(200, DB),
        "/orgs/1/reports/time_series_statistics": FakeResponse(201, TS),
        "/orgs/1/events": FakeResponse(200, []),
        "/object_limit_profiles": FakeResponse(403, text=""),
        "/api_usage_limit_profiles": FakeResponse(403, text=""),
    }
    base.update(over); return base


def _run(routes, args=None):
    pce = FakePCE(routes)
    out = handle_get_pce_capacity(ToolContext(pce=pce, is_stdio=True), args or {})
    return json.loads(out[0].text), pce


def test_tool_is_registered_read_only():
    spec = TOOL_REGISTRY["get-pce-capacity"]
    assert not spec.mutating and not spec.requires_confirm and spec.requires_pce


def test_database_metrics_are_reported_as_percent_of_limit():
    body, _ = _run(_routes())
    db = body["traffic_database"]
    assert db["flows_size_gb"] == 13.1 and db["flows_size_gb_limit"] == 26 and db["size_percent_of_limit"] == 50.4
    assert db["flows_days"] == 33 and db["days_percent_of_limit"] == 36.7
    srv = db["sources"]["server"]
    assert srv["size_percent_of_limit"] == 50.0 and srv["days_percent_of_limit"] == 36.7
    # endpoint retention is over its own limit -- say so, do not hide it
    assert db["sources"]["endpoint"]["days_percent_of_limit"] == 128.6
    assert any("endpoint" in w for w in body["warnings"])


def test_managed_workload_trend_uses_the_window():
    body, pce = _run(_routes(), {"lookback_days": 10})
    ts = body["managed_workloads"]
    assert ts["latest"] == 170 and ts["earliest"] == 160 and ts["change"] == 10
    assert ts["latest_date"] == "2026-10-15" and ts["earliest_date"] == "2026-10-06"
    call = [c for c in pce.calls if "time_series_statistics" in c[1]][0]
    assert call[3] == [{"property": "num_managed_workloads", "resolution": "day", "max_results": 10}]


def test_unsupported_time_series_property_is_reported_not_fatal():
    body, _ = _run(_routes(**{"/orgs/1/reports/time_series_statistics":
        FakeResponse(406, [{"token": "unsupported_property", "message": "Invalid property"}])}))
    assert body["managed_workloads"]["available"] is False and "unsupported_property" in body["managed_workloads"]["reason"]
    assert "traffic_database" in body       # the rest still came back


def test_limit_events_are_counted_for_the_window():
    ev = [{"href": "/orgs/1/events/a", "timestamp": "2026-10-14T10:00:00Z", "event_type": "soft_limit_exceeded",
           "notifications": [{"info": {"object_type": "total_labels", "soft_limit": 20000, "current": 20010}}]}]
    body, pce = _run(_routes(**{"/orgs/1/events": FakeResponse(200, ev)}), {"lookback_days": 7})
    assert body["limit_events"]["soft_limit_exceeded"]["count"] == 1
    assert body["limit_events"]["soft_limit_exceeded"]["latest"]["timestamp"] == "2026-10-14T10:00:00Z"
    params = [c[2] for c in pce.calls if c[1].startswith("/orgs/1/events")]
    assert all("timestamp[gte]" in p and p["event_type"] in ("soft_limit_exceeded", "hard_limit_exceeded") for p in params)


def test_object_limits_403_is_reported_as_gated_not_absent():
    """demo100: 403 with an empty body and a request.authorization_failed audit
    event. The route exists; the key is not allowed. Say exactly that."""
    body, _ = _run(_routes())
    ol = body["object_limits"]
    assert ol["status"] == "forbidden" and ol["endpoint"] == "/api/v2/object_limit_profiles"
    assert "exists" in ol["message"] and "audit" in ol["message"].lower()
    assert body["api_usage_limits"]["status"] == "forbidden"


def test_object_limits_404_means_the_pce_does_not_have_it():
    body, _ = _run(_routes(**{"/object_limit_profiles": FakeResponse(404, text="<html>404</html>")}))
    assert body["object_limits"]["status"] == "not_present"


def test_object_limits_200_is_passed_through_and_summarised():
    """Shape unknown until a key with access returns one; pass the body through
    and summarise anything that looks like name/soft/hard/current."""
    prof = [{"name": "default", "limits": [
        {"object_type": "total_labels", "soft_limit": 20000, "hard_limit": 25000, "current": 1200},
        {"object_type": "total_rules", "soft_limit": 40000, "hard_limit": 50000, "current": 41000}]}]
    body, _ = _run(_routes(**{"/object_limit_profiles": FakeResponse(200, prof)}))
    ol = body["object_limits"]
    assert ol["status"] == "ok" and ol["raw"] == prof
    rows = {r["object"]: r for r in ol["summary"]}
    assert rows["total_rules"]["percent_of_hard"] == 82.0 and rows["total_rules"]["above_soft"] is True
    assert rows["total_labels"]["percent_of_hard"] == 4.8 and rows["total_labels"]["above_soft"] is False
    assert any("total_rules" in w and "soft limit" in w for w in body["warnings"])
    assert not any("total_labels" in w for w in body["warnings"])


def test_version_and_headline_are_present():
    body, _ = _run(_routes())
    assert body["pce"]["version"] == "26.30.4"
    assert "headline" in body and "26 GB" in body["headline"] or "50" in body["headline"]


def test_capacity_tool_is_registered():
    assert "get-pce-capacity" in TOOL_REGISTRY
