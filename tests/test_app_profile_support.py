"""Issues #43, #44, #45: what the illumio-app-profile skill needs from the
server. No PCE required; the live checks are in the PR.

#44 get-workloads compact carries VEN status, health and heartbeat.
#45 get-rulesets resolves label filters, reads draft OR active and says
    which, filters rules by actor labels, and renders actors as data.
#43 get-traffic-timeline buckets one query's flows by time.
"""
import json
from types import SimpleNamespace as NS

import pytest

from illumio_mcp.context import ToolContext
from illumio_mcp.tools import TOOL_REGISTRY, traffic
from illumio_mcp.tools.rulesets import handle_get_rulesets
from illumio_mcp.tools.workloads import handle_get_workloads

from test_traffic_tools import LABELS, FakeLabel, FakeLabels, FakePCE, _flow


# =========================================================================
# #44 workloads compact
# =========================================================================

def _workload(name, agent=None, ven=None, online=True):
    return NS(href=f"/orgs/1/workloads/{name}", name=name, hostname=name,
              interfaces=[NS(address="10.0.0.1")], os_type="linux", online=online,
              agent=agent, ven=ven, enforcement_mode="visibility_only",
              visibility_level="flow_summary", labels=[NS(href="/orgs/1/labels/1")])


def _agent(status="active", heartbeat="2026-10-13T21:20:47Z", version="23.2.31",
           sync="applied", health=()):
    return NS(status=NS(status=status, last_heartbeat_on=heartbeat, agent_version=version,
                        security_policy_sync_state=sync, agent_health=list(health)))


class _WorkloadPCE(FakePCE):
    def __init__(self, workloads):
        super().__init__(LABELS)
        self.workloads = NS(get=lambda params=None: workloads)


def _compact(workloads):
    out = handle_get_workloads(ToolContext(pce=_WorkloadPCE(workloads), is_stdio=True),
                               {"detail_level": "compact"})
    env = json.loads(out[0].text)
    return [dict(zip(env["columns"], row)) for row in env["data"]]


def test_compact_carries_ven_status_health_and_heartbeat():
    """The skill reports stale VENs. compact had online/managed only, so it
    had to pull `full` -- the whole SDK object -- to read three fields."""
    rows = _compact([_workload("web01", agent=_agent(
        health=[NS(type="firewall_stale", severity="warning")]))])
    row = rows[0]
    assert row["ven_status"] == "active"
    assert row["last_heartbeat_on"] == "2026-10-13T21:20:47Z"
    assert row["agent_version"] == "23.2.31"
    assert row["policy_sync_state"] == "applied"
    assert row["health_errors"] == 1
    assert row["health_error_types"] == "firewall_stale"


def test_compact_ven_columns_are_null_for_unmanaged_workloads():
    row = _compact([_workload("printer", agent=None, ven=None)])[0]
    assert row["managed"] is False
    assert row["ven_status"] is None and row["last_heartbeat_on"] is None
    assert row["health_errors"] == 0


def test_compact_falls_back_to_ven_status_when_agent_status_is_absent():
    row = _compact([_workload("legacy", agent=NS(status=None), ven=NS(status="suspended"))])[0]
    assert row["ven_status"] == "suspended"


# =========================================================================
# #45 rulesets
# =========================================================================

L = {"app=shop": "/orgs/1/labels/10", "env=prod": "/orgs/1/labels/11",
     "app=web": "/orgs/1/labels/12", "role=db": "/orgs/1/labels/13"}
RS_LABELS = [FakeLabel(href, *kv.split("=")) for kv, href in L.items()]


def _ruleset(name, scopes, rules, version="draft"):
    return {
        "href": f"/orgs/1/sec_policy/{version}/rule_sets/{name}",
        "name": name, "enabled": True, "description": "",
        "scopes": scopes, "rules": rules,
    }


def _rule(href, consumers, providers, services):
    return {"href": href, "enabled": True, "description": "", "resolve_labels_as":
            {"consumers": ["workloads"], "providers": ["workloads"]},
            "consumers": consumers, "providers": providers, "ingress_services": services}


class _Obj:
    """SDK objects expose to_json(); the handler must not depend on anything else."""
    def __init__(self, d): self._d = d; self.href = d["href"]
    def to_json(self): return self._d


class _RulesetPCE(FakePCE):
    def __init__(self, rulesets, deny=None, ip_lists=(), services=()):
        super().__init__(RS_LABELS)
        self.calls = []
        self._rulesets = rulesets
        self._deny = deny or {}
        self.rule_sets = NS(get=self._get, get_all=lambda **kw: self._get(**kw))
        self.ip_lists = NS(get=lambda params=None, **kw: [NS(href=h, name=n) for h, n in ip_lists])
        self.services = NS(get=lambda params=None, **kw: [NS(href=h, name=n) for h, n in services])

    def _get(self, policy_version="draft", params=None, **kw):
        self.calls.append({"policy_version": policy_version, "params": dict(params or {})})
        return [_Obj({**r, "href": r["href"].replace("/draft/", f"/{policy_version}/")})
                for r in self._rulesets]

    def get(self, path):
        return NS(json=lambda: self._deny.get(path.split("/rule_sets/")[-1].split("/")[0], []))


SHOP = _ruleset("shop", scopes=[[{"label": {"href": L["app=shop"]}}, {"label": {"href": L["env=prod"]}}]],
                rules=[_rule("/r1", consumers=[{"label": {"href": L["app=web"]}}],
                             providers=[{"label": {"href": L["role=db"]}}],
                             services=[{"port": 3306, "proto": 6},
                                       {"port": 8000, "to_port": 8010, "proto": 17},
                                       {"href": "/orgs/1/sec_policy/draft/services/5"}])])
OTHER = _ruleset("other", scopes=[[{"label": {"href": L["app=web"]}}]],
                 rules=[_rule("/r2", consumers=[{"actors": "ams"}],
                              providers=[{"label": {"href": L["app=shop"]}},
                                         {"ip_list": {"href": "/orgs/1/sec_policy/draft/ip_lists/9"}}],
                              services=[{"port": 443, "proto": 6}])])


def _rulesets(pce, args):
    out = handle_get_rulesets(ToolContext(pce=pce, is_stdio=True), args)
    return json.loads(out[0].text)


def test_label_filter_accepts_key_value_and_is_encoded_for_the_pce():
    """Reported: get-rulesets passed `labels` through raw, so the caller had to
    build '[["/orgs/1/labels/5"]]' by hand -- the same 406 that get-workloads
    already fixed."""
    pce = _RulesetPCE([SHOP])
    _rulesets(pce, {"labels": ["app=shop", "env=prod"]})
    assert pce.calls[0]["params"]["labels"] == json.dumps([[L["app=shop"], L["env=prod"]]])


def test_unknown_label_filter_fails_fast():
    out = _rulesets(_RulesetPCE([SHOP]), {"labels": ["app=nope"]})
    assert out["error"] == "unresolved_label_filter" and out["unresolved"] == ["app=nope"]


def test_pre_encoded_label_filter_still_works():
    pce = _RulesetPCE([SHOP])
    _rulesets(pce, {"labels": '[["/orgs/1/labels/10"]]'})
    assert pce.calls[0]["params"]["labels"] == '[["/orgs/1/labels/10"]]'


def test_policy_version_is_selectable_and_echoed():
    pce = _RulesetPCE([SHOP])
    out = _rulesets(pce, {"pversion": "active"})
    assert pce.calls[0]["policy_version"] == "active"
    assert out["policy_version"] == "active"
    assert "/active/" in out["rulesets"][0]["href"]
    assert _rulesets(_RulesetPCE([SHOP]), {})["policy_version"] == "draft"


def test_bad_policy_version_is_rejected():
    out = _rulesets(_RulesetPCE([SHOP]), {"pversion": "yesterday"})
    assert "error" in out and "draft" in out["error"] and "active" in out["error"]


def test_actors_and_scopes_are_rendered_as_data_not_dataclass_reprs():
    """Reported: scopes/consumers/providers were str() of SDK objects, label
    hrefs only, deny rules str() of dicts with single quotes."""
    out = _rulesets(_RulesetPCE([SHOP, OTHER], ip_lists=[("/orgs/1/sec_policy/draft/ip_lists/9", "corp-dns")],
                                services=[("/orgs/1/sec_policy/draft/services/5", "MySQL")]), {})
    shop, other = out["rulesets"]
    assert shop["scopes"] == [[{"key": "app", "value": "shop", "href": L["app=shop"]},
                              {"key": "env", "value": "prod", "href": L["env=prod"]}]]
    r1 = shop["rules"][0]
    assert r1["href"] == "/r1"
    assert r1["consumers"] == [{"label": {"key": "app", "value": "web", "href": L["app=web"]}}]
    assert r1["providers"] == [{"label": {"key": "role", "value": "db", "href": L["role=db"]}}]
    assert r1["ingress_services"] == [{"port": 3306, "proto": "tcp"},
                                      {"port": 8000, "to_port": 8010, "proto": "udp"},
                                      {"service": {"name": "MySQL", "href": "/orgs/1/sec_policy/draft/services/5"}}]
    r2 = other["rules"][0]
    assert r2["consumers"] == [{"all_workloads": True}]
    assert r2["providers"][1] == {"ip_list": {"name": "corp-dns", "href": "/orgs/1/sec_policy/draft/ip_lists/9"}}
    assert "Actor(" not in json.dumps(out) and "LabelSet(" not in json.dumps(out)


def test_deny_rules_render_in_the_same_shape():
    deny = {"shop": [{"href": "/d1", "enabled": True, "override": True, "description": "",
                      "consumers": [{"actors": "ams"}],
                      "providers": [{"label": {"href": L["app=shop"]}}],
                      "ingress_services": [{"port": 22, "proto": 6}]}]}
    out = _rulesets(_RulesetPCE([SHOP], deny=deny), {})
    d = [r for r in out["rulesets"][0]["rules"] if r["rule_type"] == "override_deny"][0]
    assert d["consumers"] == [{"all_workloads": True}]
    assert d["providers"] == [{"label": {"key": "app", "value": "shop", "href": L["app=shop"]}}]
    assert d["ingress_services"] == [{"port": 22, "proto": "tcp"}]


def test_actor_labels_keep_only_rules_naming_them():
    """Reported: finding "rules that name app=shop" meant fetching everything
    and regexing hrefs. OTHER names app=shop as a provider; SHOP does not."""
    out = _rulesets(_RulesetPCE([SHOP, OTHER]), {"actor_labels": ["app=shop"]})
    assert [r["name"] for r in out["rulesets"]] == ["other"]
    assert [r["href"] for r in out["rulesets"][0]["rules"]] == ["/r2"]
    assert out["actor_filter"] == {"labels": ["app=shop"], "side": "any", "rules_matched": 1}


def test_actor_side_narrows_to_consumer_or_provider():
    assert _rulesets(_RulesetPCE([SHOP, OTHER]),
                     {"actor_labels": ["app=shop"], "actor_side": "consumer"})["rulesets"] == []
    out = _rulesets(_RulesetPCE([SHOP, OTHER]), {"actor_labels": ["app=web"], "actor_side": "consumer"})
    assert [r["name"] for r in out["rulesets"]] == ["shop"]


def test_actor_labels_are_anded():
    out = _rulesets(_RulesetPCE([SHOP, OTHER]), {"actor_labels": ["app=shop", "role=db"]})
    assert out["rulesets"] == [] and out["actor_filter"]["rules_matched"] == 0


# =========================================================================
# #43 traffic timeline
# =========================================================================

def _at(first, last=None, **over):
    return _flow(timestamp_range={"first_detected": first, "last_detected": last or first}, **over)


def _timeline(monkeypatch, flows, args):
    monkeypatch.setattr(traffic, "fetch_flows_raw", lambda *a, **k: flows)
    out = traffic.handle_get_traffic_timeline(ToolContext(pce=FakePCE(LABELS), is_stdio=True), args)
    return json.loads(out[0].text)


def test_timeline_is_registered_read_only():
    spec = TOOL_REGISTRY["get-traffic-timeline"]
    assert not spec.mutating and not spec.requires_confirm


def test_flows_are_bucketed_by_first_detected_with_empty_buckets_present(monkeypatch):
    """Reported: 24 queries for one day at 1h buckets, 28 for a week at 6h,
    x2 for both directions. One query, bucketed client-side."""
    out = _timeline(monkeypatch, [
        _at("2026-10-12T14:05:00Z", num_connections=10),
        _at("2026-10-12T14:50:00Z", num_connections=5),
        _at("2026-10-12T16:10:00Z", num_connections=1),
    ], {"start_date": "2026-10-12T14:00:00Z", "end_date": "2026-10-12T17:59:59Z", "bucket": "1h"})
    assert out["bucket"] == "1h"
    assert [b["bucket_start"] for b in out["series"]] == [
        "2026-10-12T14:00:00Z", "2026-10-12T15:00:00Z", "2026-10-12T16:00:00Z", "2026-10-12T17:00:00Z"]
    assert [(b["flows"], b["connections"]) for b in out["series"]] == [(2, 15), (0, 0), (1, 1), (0, 0)]
    assert out["totals"] == {"flows": 3, "connections": 16, "pce_flows": 3, "flows_truncated": False}


def test_split_by_policy_decision(monkeypatch):
    out = _timeline(monkeypatch, [
        _at("2026-10-12T14:05:00Z", policy_decision="blocked"),
        _at("2026-10-12T14:06:00Z", policy_decision="blocked"),
        _at("2026-10-12T14:07:00Z", policy_decision="potentially_blocked"),
    ], {"start_date": "2026-10-12T14:00:00Z", "end_date": "2026-10-12T14:59:59Z",
        "bucket": "1h", "split_by": "policy_decision"})
    assert out["series"][0]["by_policy_decision"] == {"blocked": 2, "potentially_blocked": 1}


def test_buckets_align_to_wall_clock_not_to_the_window_start(monkeypatch):
    out = _timeline(monkeypatch, [_at("2026-10-12T14:20:00Z")],
                    {"start_date": "2026-10-12T14:10:00Z", "end_date": "2026-10-12T14:40:00Z", "bucket": "15m"})
    assert [b["bucket_start"] for b in out["series"]] == [
        "2026-10-12T14:00:00Z", "2026-10-12T14:15:00Z", "2026-10-12T14:30:00Z"]


def test_spikes_use_three_times_the_median_of_non_zero_buckets(monkeypatch):
    """The rule the skill and illumio-tui share: >= 3x the median of the
    non-zero buckets, worst spike named with its multiple."""
    flows = []
    for hour, n in [(0, 2), (1, 2), (2, 2), (3, 14), (5, 2)]:        # hour 4 empty
        flows += [_at(f"2026-10-12T{hour:02d}:0{i % 10}:00Z") for i in range(n)]
    out = _timeline(monkeypatch, flows, {"start_date": "2026-10-12T00:00:00Z",
                                         "end_date": "2026-10-12T05:59:59Z", "bucket": "1h", "spikes": True})
    s = out["spikes"]
    assert s["metric"] == "flows" and s["median_nonzero"] == 2 and s["threshold"] == 6
    assert [b["bucket_start"] for b in s["buckets"]] == ["2026-10-12T03:00:00Z"]
    assert s["buckets"][0]["multiple"] == 7.0
    assert s["worst"]["bucket_start"] == "2026-10-12T03:00:00Z"


def test_no_spikes_when_nothing_exceeds_the_threshold(monkeypatch):
    out = _timeline(monkeypatch, [_at("2026-10-12T00:05:00Z"), _at("2026-10-12T01:05:00Z")],
                    {"start_date": "2026-10-12T00:00:00Z", "end_date": "2026-10-12T01:59:59Z",
                     "bucket": "1h", "spikes": True})
    assert out["spikes"]["buckets"] == [] and out["spikes"]["worst"] is None


def test_rows_spanning_buckets_are_disclosed(monkeypatch):
    """Explorer aggregates older flows into multi-day rows; those land in the
    bucket they began in and the response says how many did."""
    out = _timeline(monkeypatch, [_at("2026-10-12T00:05:00Z", "2026-10-12T03:00:00Z"),
                                  _at("2026-10-12T01:05:00Z")],
                    {"start_date": "2026-10-12T00:00:00Z", "end_date": "2026-10-12T03:59:59Z", "bucket": "1h"})
    assert out["rows_spanning_buckets"] == 1 and "aggregate" in out["resolution_note"]


def test_spikes_are_caveated_when_rows_are_wider_than_the_bucket(monkeypatch):
    """Live: 54 of 69 blocked rows in the 00:00 bucket, every one a day-wide
    aggregate -- a 27x 'spike' that was the aggregation. Say so."""
    flows = [_at("2026-10-12T00:00:01Z", "2026-10-12T23:59:59Z") for _ in range(20)]
    flows += [_at("2026-10-12T03:05:00Z"), _at("2026-10-12T07:05:00Z")]
    out = _timeline(monkeypatch, flows, {"start_date": "2026-10-12T00:00:00Z",
                                         "end_date": "2026-10-12T23:59:59Z", "bucket": "1h", "spikes": True})
    assert out["effective_bucket"] == "1d"
    assert "finer" in out["resolution_note"]
    assert "bucket=1d" in out["spikes"]["caveat"]
    fine = _timeline(monkeypatch, [_at("2026-10-12T03:05:00Z")] * 3,
                     {"start_date": "2026-10-12T00:00:00Z", "end_date": "2026-10-12T23:59:59Z",
                      "bucket": "1h", "spikes": True})
    assert fine["effective_bucket"] == "15m" and "caveat" not in fine["spikes"]


def test_spike_in_the_first_bucket_is_caveated_as_the_window_edge(monkeypatch):
    """Live, 7 days at 1d: 1719 rows on the first day, then 590/589/466. The
    first bucket collects aggregates that began before the window."""
    flows = [_at("2026-10-06T00:00:00Z", "2026-10-07T12:00:00Z") for _ in range(12)]
    flows += [_at(f"2026-10-{d:02d}T10:00:00Z") for d in (7, 8, 9)]
    out = _timeline(monkeypatch, flows, {"start_date": "2026-10-06", "end_date": "2026-10-09",
                                         "bucket": "1d", "spikes": True})
    assert out["spikes"]["worst"]["bucket_start"] == "2026-10-06T00:00:00Z"
    assert "first of the window" in out["spikes"]["caveat"]


def test_invalid_bucket_is_rejected(monkeypatch):
    out = _timeline(monkeypatch, [], {"start_date": "2026-10-12", "end_date": "2026-10-12", "bucket": "2h"})
    assert "error" in out and "15m" in out["error"]


def test_too_many_buckets_is_rejected_with_a_coarser_suggestion(monkeypatch):
    out = _timeline(monkeypatch, [], {"start_date": "2026-01-01", "end_date": "2026-12-31", "bucket": "15m"})
    assert "error" in out and "coarser" in out["error"].lower()


def test_tool_count_is_now_52():
    assert len(TOOL_REGISTRY) == 52
