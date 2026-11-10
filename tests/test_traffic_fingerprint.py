"""Traffic fingerprints: a snapshot of who talks to whom on which service, for
an org, an environment or an app, and the drift between two of them.

The rules come from illumio-tui's traffic compare (#77-80) and snapshot
compare (#85): keys are matched on identity, never on counts (Explorer's
counters are lifetime values); `first_detected` never says "new"; a
truncated side is recorded and named because it inflates "new"; a compare
across PCEs, orgs, scopes or identity labels is refused, not fudged.

No PCE required.
"""
import json

import pytest

from illumio_mcp import fingerprint as fp
from illumio_mcp.context import ToolContext
from illumio_mcp.tools import TOOL_REGISTRY, traffic
from illumio_mcp.tools import fingerprint as tool
from illumio_mcp.tools.traffic import raw_flows_to_dataframe

from test_traffic_tools import FakeLabel, FakePCE

LABELS = [FakeLabel("/orgs/1/labels/1", "app", "shop"),
          FakeLabel("/orgs/1/labels/2", "env", "prod"),
          FakeLabel("/orgs/1/labels/3", "app", "db"),
          FakeLabel("/orgs/1/labels/5", "app", "crm"),
          FakeLabel("/orgs/1/labels/6", "env", "dev")]

SHOP = [{"href": "/orgs/1/labels/1"}, {"href": "/orgs/1/labels/2"}]
DB = [{"href": "/orgs/1/labels/3"}, {"href": "/orgs/1/labels/2"}]
CRM_DEV = [{"href": "/orgs/1/labels/5"}, {"href": "/orgs/1/labels/6"}]


def _wl(host, labels):
    return {"ip": "10.0.0.1", "workload": {"hostname": host, "labels": labels}}


def _flow(src=None, dst=None, port=443, proto=6, decision="allowed", n=5, **over):
    flow = {
        "src": src or _wl("web01", SHOP),
        "dst": dst or _wl("db01", DB),
        "service": {"port": port, "proto": proto, "process_name": "httpd"},
        "policy_decision": decision,
        "flow_direction": "outbound",
        "num_connections": n,
        "timestamp_range": {"first_detected": "2026-11-01T00:00:00Z",
                            "last_detected": "2026-11-07T00:00:00Z"},
    }
    flow.update(over)
    return flow


def _df(*flows):
    return raw_flows_to_dataframe(FakePCE(LABELS), list(flows))


def _print(flows, scope=None, window=None, coverage=None, **over):
    return fp.build_fingerprint(_df(*flows), pce={"host": "pce:8443", "org_id": 1},
                                scope=scope or {"kind": "org"},
                                window=window or {"start": "2026-11-01", "end": "2026-11-08"},
                                coverage=coverage or {"pce_flows": len(flows), "truncated": False},
                                **over)


def _keys(print_):
    return {tuple(k[:3]): k[3] for k in print_["keys"]}


# =========================================================================
# build: the key is app pair x service, decisions a set, counts absent
# =========================================================================

def test_key_is_app_pair_and_service_with_decisions_as_a_set():
    print_ = _print([_flow(), _flow(decision="potentially_blocked", n=99),
                     _flow(port=5432)])
    keys = _keys(print_)
    assert keys == {("shop (prod)", "db (prod)", "tcp/443"): "AP",
                    ("shop (prod)", "db (prod)", "tcp/5432"): "A"}
    assert print_["key_columns"] == ["src", "dst", "service", "decisions"]
    # No counter travels in a key: lifetime counters make them useless for compare.
    assert all(len(k) == 4 for k in print_["keys"])


def test_process_user_and_time_do_not_split_a_key():
    """Flow-level detail is not part of the fingerprint: an app pair on a
    service is one key however many processes or days produced it."""
    a = _flow(service={"port": 443, "proto": 6, "process_name": "httpd", "user_name": "root"})
    b = _flow(service={"port": 443, "proto": 6, "process_name": "nginx", "user_name": "www"},
              timestamp_range={"first_detected": "2026-11-06T00:00:00Z",
                               "last_detected": "2026-11-07T00:00:00Z"})
    assert len(_print([a, b])["keys"]) == 1


def test_external_endpoints_are_named_stably_fqdn_then_provider_then_ip(monkeypatch):
    monkeypatch.setattr(fp, "classify_destination",
                        lambda ip: ("openai", "likely") if ip == "20.0.0.1" else (None, None))
    print_ = _print([
        _flow(dst={"ip": "1.1.1.1", "fqdn": "api.stripe.com", "ip_lists": [{"name": "internet"}]}),
        _flow(dst={"ip": "20.0.0.1", "ip_lists": [{"name": "internet"}]}),
        _flow(dst={"ip": "198.51.100.9"}),
    ])
    dsts = {k[1] for k in print_["keys"]}
    assert dsts == {"api.stripe.com", "openai", "198.51.100.9"}
    app = print_["apps"]["shop (prod)"]
    assert app["external_destinations"] == 3
    assert app["providers"] == ["openai"]


def test_inbound_from_the_internet_is_an_external_source():
    print_ = _print([_flow(src={"ip": "203.0.113.8", "ip_lists": [{"name": "internet"}]},
                           dst=_wl("web01", SHOP))])
    assert _keys(print_) == {("203.0.113.8", "shop (prod)", "tcp/443"): "A"}
    assert print_["apps"]["shop (prod)"]["external_sources"] == 1
    assert print_["totals"]["external_sources"] == 1


def test_per_app_shape_metrics():
    print_ = _print([
        _flow(),                                            # shop -> db 443
        _flow(port=5432),                                   # shop -> db 5432
        _flow(src=_wl("c1", CRM_DEV), dst=_wl("web", SHOP)),  # crm -> shop
        _flow(dst={"ip": "198.51.100.9"}, decision="blocked"),   # shop -> internet, blocked
    ])
    shop = print_["apps"]["shop (prod)"]
    assert shop["peers_out"] == 2            # db, 9.9.9.9
    assert shop["peers_in"] == 1             # crm
    assert shop["external_destinations"] == 1
    assert shop["services"] == 2             # 443, 5432 (the inbound 443 counts once)
    assert shop["records"] == 4
    assert shop["blocked_share"] == 0.25
    db = print_["apps"]["db (prod)"]
    assert db["peers_in"] == 1 and db["peers_out"] == 0
    assert print_["totals"] == {"keys": 4, "apps": 3, "apps_in_scope": 3,
                                "external_destinations": 1, "external_sources": 0,
                                "blocked_share": 0.25}


def test_remote_apps_in_a_narrower_scope_are_marked_out_of_scope():
    """An app scope only sees flows touching the app, so a remote app's
    metrics are its side of that traffic, not the app's shape."""
    flows = [_flow(), _flow(src=_wl("c1", CRM_DEV), dst=_wl("web", SHOP))]
    by_app = _print(flows, scope={"kind": "app", "app": "shop", "env": "prod"})
    assert by_app["apps"]["shop (prod)"]["in_scope"] is True
    assert by_app["apps"]["db (prod)"]["in_scope"] is False
    assert by_app["totals"]["apps_in_scope"] == 1
    by_env = _print(flows, scope={"kind": "env", "env": "prod"})
    assert {n: a["in_scope"] for n, a in by_env["apps"].items()} == {
        "shop (prod)": True, "db (prod)": True, "crm (dev)": False}
    assert all(a["in_scope"] for a in _print(flows)["apps"].values())


def test_unlabelled_workloads_are_one_identity_per_hostname_not_one_bucket():
    print_ = _print([_flow(dst={"ip": "10.9.9.1", "workload": {"hostname": "legacy01"}}),
                     _flow(dst={"ip": "10.9.9.2", "workload": {"hostname": "legacy02"}})])
    assert {k[1] for k in print_["keys"]} == {"unlabelled:legacy01", "unlabelled:legacy02"}
    assert "unlabelled:legacy01" not in print_["apps"]


def test_empty_frame_is_an_empty_fingerprint_not_an_error():
    import pandas as pd
    print_ = fp.build_fingerprint(pd.DataFrame(), pce={"host": "p", "org_id": 1},
                                  scope={"kind": "org"}, window={"start": "a", "end": "b"},
                                  coverage={"pce_flows": 0, "truncated": False})
    assert print_["keys"] == [] and print_["apps"] == {}
    assert print_["totals"]["keys"] == 0


def test_identity_labels_choose_the_axis():
    print_ = _print([_flow()], identity_labels=("env",))
    assert _keys(print_) == {("prod", "prod", "tcp/443"): "A"}
    assert print_["scope"]["identity_labels"] == ["env"]


def test_fingerprint_carries_its_basis():
    print_ = _print([_flow()], scope={"kind": "app", "app": "shop", "env": "prod"})
    assert print_["fingerprint_version"] == fp.FINGERPRINT_VERSION == 1
    assert print_["pce"] == {"host": "pce:8443", "org_id": 1}
    assert print_["scope"] == {"kind": "app", "app": "shop", "env": "prod",
                               "identity_labels": ["app", "env"]}
    assert print_["basis"]["window"] == {"start": "2026-11-01", "end": "2026-11-08"}
    assert print_["basis"]["window_days"] == 7
    assert print_["coverage"]["truncated"] is False
    assert print_["generated_at"].endswith("Z")


# =========================================================================
# compare: new / changed / gone / same on the key, never on counts
# =========================================================================

def _two(now_flows, then_flows, **then_over):
    now = _print(now_flows)
    then = _print(then_flows, **then_over)
    return now, then, fp.compare_fingerprints(now, then)


def test_new_changed_gone_same():
    now, then, cmp = _two(
        [_flow(), _flow(port=5432, decision="blocked"), _flow(port=8080)],
        [_flow(n=1000), _flow(port=5432), _flow(port=22)])
    assert cmp["basis"]["comparable"] is True
    assert cmp["counts"] == {"new": 1, "changed": 1, "gone": 1, "same": 1}
    assert cmp["new"] == [["shop (prod)", "db (prod)", "tcp/8080", "A"]]
    assert cmp["changed"] == [["shop (prod)", "db (prod)", "tcp/5432", "A", "B"]]
    assert cmp["gone"] == [["shop (prod)", "db (prod)", "tcp/22", "A"]]
    assert cmp["changed_columns"] == ["src", "dst", "service", "was", "now"]
    # 3 differences over a baseline of 3 keys
    assert cmp["drift"] == 1.0


def test_identical_fingerprints_have_no_drift_whatever_the_counts():
    _, _, cmp = _two([_flow(n=1)], [_flow(n=100000)])
    assert cmp["counts"] == {"new": 0, "changed": 0, "gone": 0, "same": 1}
    assert cmp["drift"] == 0.0


def test_per_app_drift_names_the_peers_that_came_and_went(monkeypatch):
    monkeypatch.setattr(fp, "classify_destination",
                        lambda ip: ("anthropic", "likely") if ip == "20.0.0.1" else (None, None))
    _, _, cmp = _two(
        [_flow(), _flow(dst={"ip": "20.0.0.1"}), _flow(src=_wl("c", CRM_DEV), dst=_wl("w", SHOP))],
        [_flow(), _flow(dst={"ip": "198.51.100.9"})])
    shop = cmp["by_app"]["shop (prod)"]
    assert shop["new"] == 2 and shop["gone"] == 1 and shop["changed"] == 0
    assert shop["new_peers"] == ["anthropic", "crm (dev)"]
    assert shop["gone_peers"] == ["198.51.100.9"]
    assert shop["new_external"] == ["anthropic"]
    assert shop["drift"] == 1.5                   # 3 differences over 2 baseline keys
    assert cmp["new_providers"] == ["anthropic"]
    # An app only in the recent window has no baseline keys: drift over 1.
    assert cmp["by_app"]["crm (dev)"]["drift"] == 1.0


def test_lists_are_capped_but_counts_are_not():
    now = _print([_flow(port=p) for p in range(1, 51)])
    then = _print([])
    cmp = fp.compare_fingerprints(now, then, max_list=10)
    assert cmp["counts"]["new"] == 50 and len(cmp["new"]) == 10
    assert cmp["lists_capped_at"] == 10


# --- basis: refuse what cannot be compared, warn about what inflates -------

def test_another_pce_or_org_is_refused():
    now = _print([_flow()])
    then = dict(_print([_flow()]), pce={"host": "other:8443", "org_id": 1})
    cmp = fp.compare_fingerprints(now, then)
    assert cmp["basis"]["comparable"] is False
    assert any("pce" in p for p in cmp["basis"]["problems"])
    assert "counts" not in cmp and "new" not in cmp


def test_another_scope_or_axis_is_refused():
    now = _print([_flow()], scope={"kind": "app", "app": "shop", "env": "prod"})
    then = _print([_flow()], scope={"kind": "env", "env": "prod"})
    assert fp.compare_fingerprints(now, then)["basis"]["comparable"] is False
    then = _print([_flow()], scope={"kind": "app", "app": "shop", "env": "prod"},
                  identity_labels=("app",))
    assert fp.compare_fingerprints(now, then)["basis"]["comparable"] is False


def test_a_baseline_without_keys_or_of_another_version_is_refused():
    now = _print([_flow()])
    then = dict(_print([_flow()]), keys=[], keys_omitted=True)
    cmp = fp.compare_fingerprints(now, then)
    assert cmp["basis"]["comparable"] is False
    assert any("keys" in p for p in cmp["basis"]["problems"])
    then = dict(_print([_flow()]), fingerprint_version=99)
    assert fp.compare_fingerprints(now, then)["basis"]["comparable"] is False


def test_garbage_baseline_is_refused_not_a_crash():
    now = _print([_flow()])
    for bad in (None, 42, "x", {}, {"fingerprint_version": 1}):
        cmp = fp.compare_fingerprints(now, bad)
        assert cmp["basis"]["comparable"] is False, bad


def test_truncation_and_unequal_windows_warn_that_new_and_gone_inflate():
    now = _print([_flow()])
    then = _print([_flow()], window={"start": "2026-10-01", "end": "2026-10-15"},
                  coverage={"pce_flows": 500, "truncated": True})
    cmp = fp.compare_fingerprints(now, then)
    assert cmp["basis"]["comparable"] is True
    warnings = " ".join(cmp["basis"]["warnings"])
    assert "truncated" in warnings and "new" in warnings
    assert "14" in warnings and "7" in warnings


# =========================================================================
# the tool
# =========================================================================

class _PCE(FakePCE):
    _hostname, _port, org_id = "pce", 8443, 1


def _run(monkeypatch, flows, args, *, baseline_flows=None):
    calls = []

    def fake_fetch(pce, query, name, meta=None):
        calls.append(query)
        if meta is not None:
            meta["returned"] = len(flows)
        return baseline_flows if (baseline_flows is not None and len(calls) == 2) else flows

    monkeypatch.setattr(tool, "fetch_flows_raw", fake_fetch)
    out = tool.handle_get_traffic_fingerprint(ToolContext(pce=_PCE(LABELS), is_stdio=True), args)
    return json.loads(out[0].text), calls


def test_tool_is_registered_read_only_for_every_role():
    spec = TOOL_REGISTRY["get-traffic-fingerprint"]
    assert spec.mutating is False and spec.roles == frozenset({"reader", "operator", "admin"})


def test_org_scope_runs_one_unfiltered_query_over_the_window(monkeypatch):
    body, calls = _run(monkeypatch, [_flow()], {"start_date": "2026-11-01", "end_date": "2026-11-08"})
    assert len(calls) == 1
    q = calls[0]
    assert q.start_date.startswith("2026-11-01") and q.end_date.startswith("2026-11-08")
    assert q.sources.include == [[]] and q.destinations.include == [[]]
    print_ = body["fingerprint"]
    assert print_["scope"]["kind"] == "org"
    assert print_["pce"] == {"host": "pce:8443", "org_id": 1}
    assert print_["totals"]["keys"] == 1
    assert "compare" not in body


def test_app_scope_filters_both_sides_with_or(monkeypatch):
    body, calls = _run(monkeypatch, [_flow()],
                       {"scope": {"app": "shop", "env": "prod"}, "lookback_days": 7})
    q = calls[0]
    assert q.sources_destinations_query_op == "or"
    hrefs = {x["label"]["href"] for x in q.sources.include[0]}
    assert hrefs == {"/orgs/1/labels/1", "/orgs/1/labels/2"}
    assert q.destinations.include[0] == q.sources.include[0]
    assert body["fingerprint"]["scope"] == {"kind": "app", "app": "shop", "env": "prod",
                                            "identity_labels": ["app", "env"]}


def test_env_scope_filters_on_env_only(monkeypatch):
    body, calls = _run(monkeypatch, [_flow()], {"scope": {"env": "prod"}})
    hrefs = {x["label"]["href"] for x in calls[0].sources.include[0]}
    assert hrefs == {"/orgs/1/labels/2"}
    assert body["fingerprint"]["scope"]["kind"] == "env"


def test_unknown_scope_label_is_an_error_not_a_silent_org_fingerprint(monkeypatch):
    body, calls = _run(monkeypatch, [_flow()], {"scope": {"app": "nosuch", "env": "prod"}})
    assert "error" in body and "nosuch" in json.dumps(body)
    assert body["unresolved"] == ["app=nosuch"]       # once, not once per side
    assert calls == []


def test_default_window_is_exactly_lookback_days_so_the_default_compare_is_like_for_like(monkeypatch):
    body, calls = _run(monkeypatch, [_flow()], {"lookback_days": 7, "baseline_days": 7})
    recent, base = calls
    assert (fp._parse(recent.end_date) - fp._parse(recent.start_date)).days == 7
    assert base.end_date == recent.start_date
    assert (fp._parse(base.end_date) - fp._parse(base.start_date)).days == 7
    assert body["compare"]["basis"]["warnings"] == []
    assert body["fingerprint"]["basis"]["window_days"] == 7


def test_baseline_days_runs_the_window_before_and_compares(monkeypatch):
    body, calls = _run(monkeypatch, [_flow(), _flow(port=8080)],
                       {"start_date": "2026-11-01", "end_date": "2026-11-08", "baseline_days": 14},
                       baseline_flows=[_flow()])
    assert len(calls) == 2
    base = calls[1]
    assert base.start_date.startswith("2026-10-18") and base.end_date.startswith("2026-11-01")
    cmp = body["compare"]
    assert cmp["counts"] == {"new": 1, "changed": 0, "gone": 0, "same": 1}
    assert cmp["baseline"]["window"]["start"].startswith("2026-10-18")
    assert any("14" in w for w in cmp["basis"]["warnings"])   # 7d vs 14d, said out loud


def test_a_supplied_baseline_is_compared_without_a_second_query(monkeypatch):
    first, _ = _run(monkeypatch, [_flow()], {"start_date": "2026-10-01", "end_date": "2026-10-08"})
    body, calls = _run(monkeypatch, [_flow(), _flow(port=22)],
                       {"start_date": "2026-11-01", "end_date": "2026-11-08",
                        "baseline": first["fingerprint"]})
    assert len(calls) == 1
    assert body["compare"]["counts"]["new"] == 1
    assert body["compare"]["baseline"]["generated_at"] == first["fingerprint"]["generated_at"]


def test_baseline_and_baseline_days_together_is_an_error(monkeypatch):
    body, calls = _run(monkeypatch, [_flow()], {"baseline_days": 7, "baseline": {"x": 1}})
    assert "error" in body and calls == []


def test_truncated_query_is_recorded_in_coverage(monkeypatch):
    flows = [_flow(port=p) for p in range(1, 4)]
    body, _ = _run(monkeypatch, flows, {"max_results": 3})
    cov = body["fingerprint"]["coverage"]
    assert cov["truncated"] is True and cov["truncated_at"] == 3
    assert "partial" in cov["note"]


def test_oversized_fingerprint_drops_keys_and_says_so(monkeypatch):
    monkeypatch.setattr(tool, "MCP_MAX_RESPONSE_BYTES", 2_000)
    body, _ = _run(monkeypatch, [_flow(port=p) for p in range(1, 60)], {})
    print_ = body["fingerprint"]
    assert print_["keys_omitted"] is True and print_["keys"] == []
    assert print_["totals"]["keys"] == 59          # the metrics survive
    assert "baseline_days" in print_["keys_note"]


def test_window_sanity_is_enforced(monkeypatch):
    body, calls = _run(monkeypatch, [_flow()], {"start_date": "2026-11-08", "end_date": "2026-11-01"})
    assert "error" in body and calls == []
