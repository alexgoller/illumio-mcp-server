"""Issue #54: collect-compliance-evidence, per-test evidence instead of a
score, from active policy for a label-pair scope. No PCE required; the live
check is owed in the PR.

The fake estate: two scope pairs (pay/prod, paydb/prod), workloads in mixed
modes with one stale VEN and one unmanaged, a ringfence ruleset with a broad
consumer, a default-list consumer, an undescribed all-services rule and a port
range, an unscoped monitoring ruleset that names the pairs, flows with
intra-scope rows, approved and unapproved crossings, a potentially blocked
crossing, and a 500-row capped pull for the second pair.
"""
import asyncio
import json
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace as NS

import pytest

from illumio_mcp.context import ToolContext
from illumio_mcp.tools import TOOL_REGISTRY, compliance_evidence as ce
from illumio_mcp.tools.compliance_evidence import handle_collect_compliance_evidence
from illumio_mcp.tools.policy import handle_compliance_check, _label_filter
from illumio_mcp.label_refs import encode_label_filter


# ---------------------------------------------------------------------------
# Fake estate
# ---------------------------------------------------------------------------

L = {"app=pay": "/orgs/1/labels/10", "env=prod": "/orgs/1/labels/11",
     "app=paydb": "/orgs/1/labels/12", "app=web": "/orgs/1/labels/13",
     "env=dev": "/orgs/1/labels/14", "role=db": "/orgs/1/labels/15"}
LABELS = [NS(href=h, key=kv.split("=")[0], value=kv.split("=")[1]) for kv, h in L.items()]

NOW = datetime.now(timezone.utc)
FRESH = (NOW - timedelta(hours=1)).strftime("%Y-%m-%dT%H:%M:%SZ")
STALE = (NOW - timedelta(days=3)).strftime("%Y-%m-%dT%H:%M:%SZ")


def _agent(heartbeat=FRESH, sync="synced", health=(), status="active"):
    return NS(status=NS(status=status, last_heartbeat_on=heartbeat, agent_version="23.2.31",
                        security_policy_sync_state=sync, agent_health=list(health)))


def _wl(name, labels, ip, mode="full", agent="healthy"):
    agent = _agent() if agent == "healthy" else agent
    return NS(href=f"/orgs/1/workloads/{name}", name=name, hostname=name,
              interfaces=[NS(address=ip)], os_type="linux", online=True, agent=agent, ven=None,
              enforcement_mode=mode, visibility_level="flow_summary",
              labels=[NS(href=L[l]) for l in labels])


WORKLOADS = [
    _wl("pay-web-01", ["app=pay", "env=prod"], "10.1.0.1"),
    _wl("pay-web-02", ["app=pay", "env=prod"], "10.1.0.2", mode="selective"),
    _wl("pay-web-03", ["app=pay", "env=prod"], "10.1.0.3",
        agent=_agent(heartbeat=STALE, sync="syncing", health=[NS(type="firewall_stale")])),
    _wl("pay-printer", ["app=pay", "env=prod"], "10.1.0.9", agent=None),
    _wl("paydb-01", ["app=paydb", "env=prod"], "10.1.1.1"),
    _wl("web-01", ["app=web", "env=prod"], "10.2.0.1"),
]


class _Obj:
    def __init__(self, d): self._d = d; self.href = d["href"]
    def to_json(self): return self._d


def _ruleset(num, name, scopes, rules):
    return _Obj({"href": f"/orgs/1/sec_policy/active/rule_sets/{num}", "name": name, "enabled": True,
                 "description": "", "scopes": scopes, "rules": rules})


def _rule(href, consumers, providers, services, description="", unscoped=False):
    r = {"href": href, "enabled": True, "description": description,
         "resolve_labels_as": {"consumers": ["workloads"], "providers": ["workloads"]},
         "consumers": consumers, "providers": providers, "ingress_services": services}
    if unscoped:
        r["unscoped_consumers"] = True
    return r


def _label(kv): return {"label": {"href": L[kv]}}
def _ipl(n): return {"ip_list": {"href": f"/orgs/1/sec_policy/active/ip_lists/{n}"}}
AMS = {"actors": "ams"}

RULESETS = [
    _ruleset(1, "RF-pay-prod", [[_label("app=pay"), _label("env=prod")]], [
        _rule("/r1", [_label("app=web")], [AMS], [{"port": 443, "proto": 6}], "web to pay API"),
        _rule("/r2", [AMS], [AMS], [], ""),                                   # intra-scope, all services, no description
        _rule("/r3", [_ipl(1)], [AMS], [{"port": 22, "proto": 6}], "jump hosts"),   # Any (0.0.0.0/0)
        _rule("/r4", [_ipl(2)], [AMS], [{"port": 8000, "to_port": 8010, "proto": 17}], "corp dns range"),
        _rule("/r8", [_ipl(3)], [AMS], [{"port": 80, "proto": 6}], "ranged default list"),
    ]),
    _ruleset(2, "global-monitoring", [[]], [
        _rule("/r5", [AMS], [_label("app=pay"), _label("env=prod")],
              [{"href": "/orgs/1/sec_policy/active/services/5"}], "monitoring"),
        _rule("/r6", [AMS], [_label("app=paydb"), _label("env=prod")],
              [{"port": 5432, "proto": 6}], "db monitoring", unscoped=True),
    ]),
    _ruleset(3, "other", [[_label("app=web")]], [
        _rule("/r7", [AMS], [_label("app=web")], [{"port": 80, "proto": 6}], "web"),
    ]),
]

DENY = {"/orgs/1/sec_policy/active/rule_sets/1": [
    {"href": "/d1", "enabled": True, "override": False, "description": "ringfence deny",
     "consumers": [AMS], "providers": [AMS], "ingress_services": []}]}

IP_LISTS = [
    NS(href="/orgs/1/sec_policy/draft/ip_lists/1", name="Any (0.0.0.0/0)",
       ip_ranges=[NS(from_ip="0.0.0.0/0", to_ip=None, exclusion=False)]),
    NS(href="/orgs/1/sec_policy/draft/ip_lists/2", name="corp-dns",
       ip_ranges=[NS(from_ip="10.0.0.0/8", to_ip=None, exclusion=False)]),
    NS(href="/orgs/1/sec_policy/draft/ip_lists/3", name="everything",
       ip_ranges=[NS(from_ip="0.0.0.0", to_ip="255.255.255.255", exclusion=False)]),
]

SERVICES = [_Obj({"href": "/orgs/1/sec_policy/active/services/5", "name": "MySQL",
                  "service_ports": [{"port": 3306, "proto": 6}]})]

EVENTS = [
    NS(timestamp="2026-10-03T10:00:00Z", event_type="sec_policy.provision", status="success",
       severity="info", created_by={"user": {"username": "alex"}}),
    NS(timestamp="2026-10-04T10:00:00Z", event_type="user.login", status="success",
       severity="info", created_by={"user": {"username": "alex"}}),
]


def _node(ip, hostname=None, labels=(), ip_lists=(), fqdn=None):
    n = {"ip": ip}
    if hostname:
        n["workload"] = {"hostname": hostname, "labels": [{"href": L[l]} for l in labels]}
    if ip_lists:
        n["ip_lists"] = [{"name": x} for x in ip_lists]
    if fqdn:
        n["fqdn"] = fqdn
    return n


def _flow(src, dst, port, proto=6, decision="allowed", n=10, day="2026-10-02"):
    return {"src": src, "dst": dst, "service": {"port": port, "proto": proto},
            "policy_decision": decision, "flow_direction": "inbound", "num_connections": n,
            "timestamp_range": {"first_detected": f"{day}T08:00:00Z", "last_detected": f"{day}T09:00:00Z"}}


PAY = ("pay-web-01", ["app=pay", "env=prod"])
PAYDB = ("paydb-01", ["app=paydb", "env=prod"])
WEB = ("web-01", ["app=web", "env=prod"])

FLOWS = {
    "compliance-evidence:T8:pay/prod:allowed": [
        _flow(_node("10.2.0.1", *WEB), _node("10.1.0.1", *PAY), 443, n=100),
        _flow(_node("10.1.1.1", *PAYDB), _node("10.1.0.1", *PAY), 5432),          # intra-scope
        _flow(_node("10.1.0.2", *PAY), _node("10.1.0.1", *PAY), 8080),            # intra-scope
        _flow(_node("10.9.9.9"), _node("10.1.0.1", *PAY), 22, n=5),               # not a workload
        _flow(_node("203.0.113.5", ip_lists=["corp-dns"]), _node("10.1.0.1", *PAY), 8005, proto=17),
    ],
    "compliance-evidence:T8:pay/prod:potentially_blocked": [
        _flow(_node("10.2.0.1", *WEB), _node("10.1.0.2", *PAY), 8443, decision="potentially_blocked"),
    ],
    "compliance-evidence:T8:pay/prod:blocked": [
        _flow(_node("10.2.0.1", *WEB), _node("10.1.0.1", *PAY), 3389, decision="blocked", day="2026-10-02"),
        _flow(_node("10.9.9.9"), _node("10.1.0.1", *PAY), 3389, decision="blocked", day="2026-10-02"),
        _flow(_node("10.9.9.9"), _node("10.1.0.1", *PAY), 445, decision="blocked", day="2026-10-05"),
    ],
    "compliance-evidence:T8:paydb/prod:allowed": [
        _flow(_node("10.1.0.1", *PAY), _node("10.1.1.1", *PAYDB), 5432) for _ in range(500)],   # capped, all intra
    "compliance-evidence:T9:pay/prod:allowed": [
        _flow(_node("10.1.0.1", *PAY), _node("10.0.0.53"), 53, proto=17, n=41200),
        _flow(_node("10.1.0.1", *PAY), _node("8.8.8.8"), 53, proto=17, n=7),
        _flow(_node("10.1.0.1", *PAY), _node("1.2.3.4", ip_lists=["corp-dns"], fqdn="dns.example"), 443, n=3),
        _flow(_node("10.1.0.1", *PAY), _node("10.1.1.1", *PAYDB), 5432),           # intra-scope
    ],
}


class FakePCE:
    def __init__(self, pending=None):
        self.calls = []
        self._pending = pending if pending is not None else []
        self.labels = NS(get=self._labels)
        self.workloads = NS(get=self._workloads)
        self.rule_sets = NS(get_all=self._rulesets, get=self._rulesets)
        self.ip_lists = NS(get=self._ip_lists)
        self.services = NS(get=lambda policy_version="draft", params=None: self._log("services") or SERVICES)
        self.events = NS(get=lambda params=None: self._log("events", params) or EVENTS)

    def _log(self, what, params=None):
        self.calls.append((what, params))

    def _labels(self, params=None):
        self._log("labels", params)
        key, value = (params or {}).get("key"), (params or {}).get("value")
        return [l for l in LABELS if (key is None or l.key == key) and (value is None or value in l.value)]

    def _workloads(self, params=None):
        self._log("workloads", params)
        wanted = {h for block in json.loads(params["labels"]) for h in block}
        return [w for w in WORKLOADS if wanted <= {l.href for l in w.labels}]

    def _ip_lists(self, policy_version="draft", params=None):
        self._log("ip_lists", {"policy_version": policy_version})
        return [NS(href=i.href.replace("/draft/", f"/{policy_version}/"), name=i.name, ip_ranges=i.ip_ranges)
                for i in IP_LISTS]

    def _rulesets(self, policy_version="draft", params=None, **kw):
        self._log("rule_sets", {"policy_version": policy_version})
        return RULESETS

    def get(self, path, **kw):
        self._log("get", path)
        if path.endswith("/deny_rules"):
            return NS(json=lambda: DENY.get(path[:-len("/deny_rules")], []))
        if path == "/sec_policy/pending":
            return NS(json=lambda: self._pending)
        raise AssertionError(path)


@pytest.fixture(autouse=True)
def _flows(monkeypatch):
    monkeypatch.setattr(ce, "fetch_flows_raw", lambda pce, q, name, meta=None: FLOWS.get(name, []))


SCOPE = [{"app": "pay", "env": "prod"}, {"app": "paydb", "env": "prod"}]
WINDOW = {"start_date": "2026-10-01", "end_date": "2026-10-10"}
APPROVED = [{"port": 443, "proto": "tcp", "direction": "in", "justification": "API"},
            {"port": 8005, "proto": "udp", "direction": "in"},
            {"port": 53, "proto": "udp", "direction": "out"},
            {"port": 443, "proto": "tcp", "direction": "out"}]


def run(args=None, pce=None):
    pce = pce or FakePCE()
    out = handle_collect_compliance_evidence(ToolContext(pce=pce, is_stdio=True),
                                             {"scope": SCOPE, **WINDOW, **(args or {})})
    return json.loads(out[0].text), pce


def pick(payload, tid):
    return next(t for t in payload["tests"] if t["id"] == tid)


# ---------------------------------------------------------------------------
# Registration and inputs
# ---------------------------------------------------------------------------

def test_registered_read_only():
    spec = TOOL_REGISTRY["collect-compliance-evidence"]
    assert not spec.mutating and not spec.requires_confirm and spec.unscopable


def test_unknown_scope_label_is_an_error_not_an_estate_wide_run():
    out, pce = run({"scope": [{"app": "pay", "env": "prod"}, {"app": "nope", "env": "prod"}]})
    assert out["error"] == "unresolved_scope_labels"
    assert out["unresolved"] == ["app=nope"]
    assert "pay" in out["valid_values"]["app"]
    assert not [c for c in pce.calls if c[0] == "workloads"], "nothing collected on a bad scope"


def test_scope_must_be_pairs():
    out, _ = run({"scope": ["pay"]})
    assert out["error"] == "invalid_scope"


def test_bad_pversion_and_window_are_rejected():
    assert "draft" in run({"pversion": "yesterday"})[0]["error"]
    assert run({"start_date": "2026-10-10", "end_date": "2026-10-01"})[0]["error"] == "invalid_window"


def test_unknown_test_id_is_rejected_and_names_the_not_run_set():
    out, _ = run({"tests": ["T1", "T10"]})
    assert out["error"] == "unknown_tests" and out["unknown"] == ["T10"]
    assert "T10" in out["not_run"]


# ---------------------------------------------------------------------------
# Envelope
# ---------------------------------------------------------------------------

def test_envelope_scope_window_policy_version_and_not_run():
    out, _ = run()
    assert out["policy_version"] == "active"
    assert out["window"] == {"start": "2026-10-01", "end": "2026-10-10", "days": 9}
    pay, paydb = out["scope"]["pairs"]
    assert pay == {"app": "pay", "env": "prod", "app_href": L["app=pay"], "env_href": L["env=prod"],
                   "workloads": 4, "managed": 3}
    assert paydb["workloads"] == 1
    assert set(out["not_run"]) == {"T10", "T12", "T13"}
    assert [t["id"] for t in out["tests"]] == ["T1", "T2", "T3", "T4", "T5", "T6", "T7", "T8", "T9", "T11", "T14"]
    assert out["overall"] == "FAIL"
    assert "compliance_score" not in json.dumps(out)


def test_every_test_has_rule_result_and_per_pair_evidence():
    out, _ = run()
    for t in out["tests"]:
        assert t["rule"] and t["result"] in ce.RESULT_ORDER
        assert set(t["per_pair"]) == {"pay/prod", "paydb/prod"}
        for pp in t["per_pair"].values():
            assert pp["result"] in ce.RESULT_ORDER and "measured" in pp and "rows" in pp
            assert pp["evidence"], f"{t['id']} cites no query"
        assert t["result"] == ce.worst(pp["result"] for pp in t["per_pair"].values())


def test_query_count_is_the_number_of_pce_reads():
    out, pce = run()
    # labels 1, workloads 2, rule_sets 1, ip_lists 1, services 1, deny rules for the 2 matched
    # rulesets (cached across pairs), flows 3+3+1+1, pending 1, events 1
    assert out["queries"] == 1 + 2 + 1 + 1 + 1 + 2 + 8 + 1 + 1
    assert out["queries"] == len(pce.calls) + 8                       # flows are monkeypatched


def test_pversion_is_passed_to_the_ruleset_read():
    _, pce = run({"pversion": "draft"})
    assert ("rule_sets", {"policy_version": "draft"}) in pce.calls


# ---------------------------------------------------------------------------
# T1 to T4: inventory
# ---------------------------------------------------------------------------

def test_t1_inventory_pulls_both_labels_anded_and_returns_rows():
    out, pce = run()
    t1 = pick(out, "T1")
    assert t1["result"] == "PASS"
    assert len(t1["per_pair"]["pay/prod"]["rows"]) == 4
    row = t1["per_pair"]["pay/prod"]["rows"][0]
    assert {"href", "name", "hostname", "ip_addresses", "managed", "enforcement_mode", "ven_status",
            "last_heartbeat_on", "policy_sync_state", "health_errors"} <= set(row)
    pulls = [p for what, p in pce.calls if what == "workloads"]
    assert pulls[0]["labels"] == encode_label_filter([L["app=pay"], L["env=prod"]])
    assert json.loads(pulls[0]["labels"]) == [[L["app=pay"], L["env=prod"]]], "one AND block"


def test_empty_pair_fails_t1_and_makes_the_rest_not_tested_without_traffic_queries():
    out, pce = run({"scope": [{"app": "web", "env": "dev"}, {"app": "paydb", "env": "prod"}]})
    assert pick(out, "T1")["per_pair"]["web/dev"]["result"] == "FAIL"
    for tid in ("T2", "T3", "T5", "T8", "T9", "T11", "T14"):
        assert pick(out, tid)["per_pair"]["web/dev"]["result"] == "NOT_TESTED"
    assert pick(out, "T1")["per_pair"]["paydb/prod"]["result"] == "PASS"
    assert out["scope"]["pairs"][0]["workloads"] == 0


def test_t2_enforcement_lists_every_managed_workload_not_in_full():
    out, _ = run()
    t2 = pick(out, "T2")
    pay = t2["per_pair"]["pay/prod"]
    assert pay["result"] == "FAIL"
    assert [r["workload"] for r in pay["rows"]] == ["pay-web-02"]
    assert pay["rows"][0]["mode"] == "selective" and pay["rows"][0]["justification"] is None
    assert t2["per_pair"]["paydb/prod"]["result"] == "PASS"
    assert "unmanaged" not in json.dumps(pay["rows"]), "the printer is not a managed row"


def test_t3_ven_health_names_the_failing_field():
    out, _ = run()
    pay = pick(out, "T3")["per_pair"]["pay/prod"]
    assert pay["result"] == "FAIL"
    assert {(r["workload"], r["field"]) for r in pay["rows"]} == {
        ("pay-web-03", "last_heartbeat_on"), ("pay-web-03", "policy_sync_state"), ("pay-web-03", "health_errors")}
    assert pick(out, "T3")["per_pair"]["paydb/prod"]["result"] == "PASS"


def test_t4_unmanaged_in_scope():
    out, _ = run()
    pay = pick(out, "T4")["per_pair"]["pay/prod"]
    assert pay["result"] == "FAIL" and [r["workload"] for r in pay["rows"]] == ["pay-printer"]
    assert pick(out, "T4")["per_pair"]["paydb/prod"]["result"] == "PASS"


def test_rows_are_capped_by_max_rows_and_say_so():
    out, _ = run({"max_rows": 2})
    pay = pick(out, "T1")["per_pair"]["pay/prod"]
    assert len(pay["rows"]) == 2 and pay["rows_total"] == 4 and pay["rows_truncated"] is True


# ---------------------------------------------------------------------------
# T5 to T7: active policy
# ---------------------------------------------------------------------------

def test_t5_unions_scoped_and_actor_matched_rulesets_and_lists_undescribed_rules():
    out, _ = run()
    pay = pick(out, "T5")["per_pair"]["pay/prod"]
    assert pay["result"] == "FAIL"
    assert [r["rule"] for r in pay["rows"]] == ["/r2"]
    assert pay["rows"][0]["ruleset"] == "RF-pay-prod"
    assert "5 of 6 providing rules described; 2 rulesets" in pay["measured"]   # r1-r4, r8 scoped; r5 names the pair
    paydb = pick(out, "T5")["per_pair"]["paydb/prod"]
    assert paydb["result"] == "PASS" and "1 rulesets" in paydb["measured"]


def test_t6_broad_consumers_name_three_kinds_and_spare_the_scoped_ams():
    out, _ = run()
    pay = pick(out, "T6")["per_pair"]["pay/prod"]
    assert pay["result"] == "FAIL"
    hits = {r["rule"]: r["why"] for r in pay["rows"]}
    assert set(hits) == {"/r3", "/r8", "/r5"}, hits
    assert "0.0.0.0/0" in hits["/r3"]                 # by name
    assert "everything" in hits["/r8"] and "active ranges" in hits["/r8"]   # by ranges, same version as the rules
    assert "unscoped ruleset" in hits["/r5"]          # all workloads, estate-wide
    assert "/r2" not in hits, "all_workloads inside a ruleset scoped to the pair is the pair itself"
    assert "/r4" not in hits
    paydb = pick(out, "T6")["per_pair"]["paydb/prod"]
    assert [r["rule"] for r in paydb["rows"]] == ["/r6"] and "unscoped_consumers" in paydb["rows"][0]["why"]
    assert {"tool": "get-iplists", "arguments": {"pversion": "active"}, "returned": 3, "capped": False} in pay["evidence"]


def test_t7_expands_ranges_and_service_objects_flags_cleartext_and_all_services():
    out, _ = run({"approved_services": APPROVED})
    pay = pick(out, "T7")["per_pair"]["pay/prod"]
    assert pay["result"] == "FAIL"
    assert pay["clauses"] == {"no_all_services_rule": "FAIL", "every_service_object_expanded": "PASS",
                              "every_port_approved": "FAIL"}
    assert [r["rule"] for r in pay["all_services_rules"]] == ["/r2"]
    by_rule = {(r["rule"], r["port"]): r for r in pay["rows"]}
    assert by_rule[("/r1", 443)]["approved"] is True
    assert by_rule[("/r3", 22)]["approved"] is False
    assert by_rule[("/r4", 8000)]["to_port"] == 8010 and by_rule[("/r4", 8000)]["approved"] is False
    assert by_rule[("/r8", 80)]["cleartext"] == [80]
    assert by_rule[("/r5", 3306)]["service"] == "MySQL" and by_rule[("/r5", 3306)]["proto"] == "tcp"
    assert pay["unexpanded"] == []


def test_t7_without_an_approved_list_is_not_tested_on_that_clause_only():
    out, _ = run()
    pay = pick(out, "T7")["per_pair"]["pay/prod"]
    assert pay["clauses"]["every_port_approved"] == "NOT_TESTED"
    assert pay["result"] == "FAIL"                     # the all-services rule still fails
    assert all(r["approved"] is None for r in pay["rows"])
    paydb = pick(out, "T7")["per_pair"]["paydb/prod"]
    assert paydb["result"] == "NOT_TESTED" and paydb["clauses"]["no_all_services_rule"] == "PASS"


# ---------------------------------------------------------------------------
# T8, T9: boundary traffic
# ---------------------------------------------------------------------------

def test_t8_drops_intra_scope_rows_and_judges_each_crossing():
    out, _ = run({"approved_services": APPROVED})
    pay = pick(out, "T8")["per_pair"]["pay/prod"]
    assert pay["result"] == "FAIL"
    assert "2 intra-scope rows dropped" in pay["measured"]
    rows = {(r["src_ip"], r["port"]): r for r in pay["rows"]}
    assert set(rows) == {("10.2.0.1", 443), ("10.9.9.9", 22), ("203.0.113.5", 8005)}
    assert rows[("10.2.0.1", 443)]["source"] == "web (prod)" and rows[("10.2.0.1", 443)]["approved"] is True
    assert rows[("10.2.0.1", 443)]["connections"] == 100 and rows[("10.2.0.1", 443)]["findings"] == []
    assert "not in approved list" in rows[("10.9.9.9", 22)]["findings"]
    assert any("not a workload" in f for f in rows[("10.9.9.9", 22)]["findings"])
    assert rows[("203.0.113.5", 8005)]["findings"] == [], "public, but inside corp-dns which /r4 uses"
    assert pay["clauses"]["zero_potentially_blocked"] == "FAIL"
    assert [r["port"] for r in pay["potentially_blocked"]] == [8443]
    assert pay["blocked"] == {"rows": 3, "connections": 30, "capped": False}
    assert [e["query_name"] for e in pay["evidence"]] == [
        "compliance-evidence:T8:pay/prod:allowed", "compliance-evidence:T8:pay/prod:potentially_blocked",
        "compliance-evidence:T8:pay/prod:blocked"]
    assert all(e["arguments"]["start_date"] == "2026-10-01T00:00:00Z" for e in pay["evidence"])


def test_t8_timeline_is_per_day_over_the_window_with_the_spike_rule():
    out, _ = run()
    tl = pick(out, "T8")["per_pair"]["pay/prod"]["timeline"]
    assert tl["bucket"] == "1d" and len(tl["series"]) == 10
    by_day = {b["bucket_start"][:10]: b for b in tl["series"]}
    assert by_day["2026-10-02"]["blocked"] == 2 and by_day["2026-10-02"]["potentially_blocked"] == 1
    assert by_day["2026-10-05"]["blocked"] == 1 and by_day["2026-10-07"]["flows"] == 0
    assert tl["worst_spike"] is None and "median" in tl["spike_rule"]


def test_capped_pull_is_exception_never_pass():
    out, _ = run({"approved_services": APPROVED})
    paydb = pick(out, "T8")["per_pair"]["paydb/prod"]
    assert paydb["result"] == "EXCEPTION"
    assert paydb["rows"] == [] and "capped" in paydb["measured"]
    assert paydb["evidence"][0]["capped"] is True and paydb["evidence"][0]["returned"] == 500
    assert pick(out, "T8")["result"] == "FAIL", "the other pair's FAIL still wins"


def test_raising_max_results_uncaps_the_same_pull():
    out, _ = run({"approved_services": APPROVED, "max_results": 1000})
    assert pick(out, "T8")["per_pair"]["paydb/prod"]["result"] == "PASS"


def test_t9_public_destinations_first_and_named_ip_list_exempts_them():
    out, _ = run({"approved_services": APPROVED})
    pay = pick(out, "T9")["per_pair"]["pay/prod"]
    assert pay["result"] == "FAIL"
    assert [r["dst_ip"] for r in pay["rows"]] == ["8.8.8.8", "1.2.3.4", "10.0.0.53"], "public first, then by volume"
    rows = {r["dst_ip"]: r for r in pay["rows"]}
    assert rows["8.8.8.8"]["public"] and not rows["8.8.8.8"]["in_named_ip_list"]
    assert any("public destination" in f for f in rows["8.8.8.8"]["findings"])
    assert rows["1.2.3.4"]["in_named_ip_list"] and rows["1.2.3.4"]["findings"] == []
    assert rows["1.2.3.4"]["destination"] == "dns.example"
    assert rows["10.0.0.53"]["approved"] is True and rows["10.0.0.53"]["outside_estate"] is True
    assert "1 intra-scope rows dropped" in pay["measured"]
    assert pick(out, "T9")["per_pair"]["paydb/prod"]["result"] == "PASS"


def test_t9_without_approved_list():
    out, _ = run()
    pay = pick(out, "T9")["per_pair"]["pay/prod"]
    assert pay["clauses"]["every_destination_approved"] == "NOT_TESTED"
    assert pay["result"] == "FAIL"                      # 8.8.8.8 still a finding


# ---------------------------------------------------------------------------
# T11, T14: change control and logging
# ---------------------------------------------------------------------------

def test_t11_in_sync_passes():
    out, _ = run()
    t11 = pick(out, "T11")
    assert t11["result"] == "PASS"
    assert "in sync" in t11["per_pair"]["pay/prod"]["measured"]


def test_t11_pending_change_to_a_scope_ruleset_is_exception_and_unrelated_ones_are_not():
    pending = [{"href": "/orgs/1/sec_policy/draft/rule_sets/1", "change_type": "update", "name": "RF-pay-prod"},
               {"href": "/orgs/1/sec_policy/draft/rule_sets/99", "change_type": "create", "name": "unrelated"},
               {"href": "/orgs/1/sec_policy/draft/ip_lists/2", "change_type": "update", "name": "corp-dns"}]
    out, _ = run(pce=FakePCE(pending=pending))
    t11 = pick(out, "T11")
    pay = t11["per_pair"]["pay/prod"]
    assert pay["result"] == "EXCEPTION" and [r["name"] for r in pay["rows"]] == ["RF-pay-prod"]
    assert "3 pending in total" in pay["measured"]
    assert t11["per_pair"]["paydb/prod"]["result"] == "PASS", "global-monitoring is not pending"
    assert t11["result"] == "EXCEPTION" and out["overall"] == "FAIL"


def test_t14_events_and_flows_present_with_policy_events_as_rows():
    out, pce = run()
    t14 = pick(out, "T14")
    assert t14["result"] == "PASS"
    pay = t14["per_pair"]["pay/prod"]
    assert [r["event_type"] for r in pay["rows"]] == ["sec_policy.provision"]
    assert pay["rows"][0]["actor"] == "alex" and pay["rows"][0]["status"] == "success"
    assert "2 events in the window (1 policy" in pay["measured"]
    params = next(p for what, p in pce.calls if what == "events")
    assert params["timestamp[gte]"] == "2026-10-01T00:00:00Z" and params["timestamp[lte]"] == "2026-10-10T23:59:59Z"


def test_t14_alone_cannot_judge_flows():
    out, _ = run({"tests": ["T14"]})
    assert pick(out, "T14")["per_pair"]["pay/prod"]["result"] == "NOT_TESTED"


# ---------------------------------------------------------------------------
# Subsets and worst-of
# ---------------------------------------------------------------------------

def test_subset_runs_only_what_is_asked_and_spends_fewer_queries():
    out, pce = run({"tests": ["T1", "T2"]})
    assert [t["id"] for t in out["tests"]] == ["T1", "T2"]
    assert out["queries"] == 3                         # labels + two workload pulls
    assert not [c for c in pce.calls if c[0] in ("rule_sets", "events", "ip_lists")]
    assert out["overall"] == "FAIL"                    # T2 pay/prod


def test_overall_is_worst_of_in_order():
    assert ce.worst(["PASS", "NOT_TESTED"]) == "NOT_TESTED"
    assert ce.worst(["PASS", "EXCEPTION", "NOT_TESTED"]) == "EXCEPTION"
    assert ce.worst(["EXCEPTION", "FAIL"]) == "FAIL"
    assert ce.worst([]) == "PASS"
    out, _ = run({"tests": ["T1"]})
    assert out["overall"] == "PASS"


# ---------------------------------------------------------------------------
# compliance-check: nis2 and the unknown-label fix; the label filter
# ---------------------------------------------------------------------------

def test_compliance_check_accepts_nis2_and_the_resource_exists():
    from illumio_mcp.server import handle_list_tools, ILLUMIO_RESOURCES, handle_read_resource
    tool = next(t for t in asyncio.run(handle_list_tools()) if t.name == "compliance-check")
    assert "nis2" in tool.inputSchema["properties"]["framework"]["enum"]
    body = asyncio.run(handle_read_resource("illumio://compliance/nis2"))
    assert "2022/2555" in body and "2024/2690" in body
    for section in ("3.2", "6.7", "6.8", "11", "12.4"):
        assert section in body
    assert ILLUMIO_RESOURCES["illumio://compliance/nis2"]["name"]


def test_compliance_check_errors_on_an_unknown_scope_label_instead_of_running_unscoped():
    pce = FakePCE()
    out = json.loads(handle_compliance_check(ToolContext(pce=pce, is_stdio=True),
                                             {"framework": "nis2", "app_name": "nope", "env_name": "prod"})[0].text)
    assert out["error"] == "unresolved_label_filter" and out["unresolved"] == ["app=nope"]
    assert "pay" in out["valid_values"]["app"]
    assert not [c for c in pce.calls if c[0] == "workloads"]


def test_compliance_check_label_match_is_exact_not_substring():
    """The PCE matches ?value= as a substring: app=pay would otherwise also
    accept paydb's label as pay's."""
    pce = FakePCE()
    out = json.loads(handle_compliance_check(ToolContext(pce=pce, is_stdio=True),
                                             {"app_name": "payd", "env_name": "prod"})[0].text)
    assert out["error"] == "unresolved_label_filter" and out["unresolved"] == ["app=payd"]


def test_label_filter_and_encode_label_filter_agree():
    hrefs = [L["app=pay"], L["env=prod"]]
    assert _label_filter(hrefs) == encode_label_filter(hrefs)
    assert json.loads(_label_filter(hrefs)) == [hrefs], "one inner list: AND"
