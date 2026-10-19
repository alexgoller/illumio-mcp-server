"""Issue #48: find-unknown-endpoints. No PCE required.

Unknown = Explorer attached no workload to that side AND the IP is not an
interface address of any inventoried workload. The fixture estate below has
one of everything the definition has to get right: a managed VEN, an
unmanaged workload with a hostname, an unmanaged workload with no hostname
but an inventoried IP, an unlabelled VEN, a link-local source, a public
destination, a scanner, a fan-in DNS server, an admin-port source, and a
default IP list that matches everything next to a named one.
"""
import json
from types import SimpleNamespace as NS

import pytest

from illumio_mcp.context import ToolContext
from illumio_mcp.tools import TOOL_REGISTRY, unknown_endpoints as U
from illumio_mcp.tools.unknown_endpoints import (
    address_class, covering_ip_lists, handle_find_unknown_endpoints,
)

from test_traffic_tools import FakeLabel, FakeLabels


# ---------------------------------------------------------------------------
# Fixture estate
# ---------------------------------------------------------------------------

L = {"app=web": "/orgs/1/labels/10", "env=prod": "/orgs/1/labels/11", "app=db": "/orgs/1/labels/12",
     **{f"app=a{i}": f"/orgs/1/labels/{20 + i}" for i in range(1, 7)}}
LABELS = [FakeLabel(href, *kv.split("=")) for kv, href in L.items()]


def _wl(name, ip, *labels, managed=True, enforcement="visibility_only", hostname=None):
    return NS(href=f"/orgs/1/workloads/{name}", name=name,
              hostname=name if hostname is None else hostname,
              interfaces=[NS(address=ip)], agent=NS(status=None) if managed else None, ven=None,
              enforcement_mode=enforcement, labels=[NS(href=L[l]) for l in labels])


WORKLOADS = [
    _wl("web01", "10.0.0.1", "app=web", "env=prod", enforcement="full"),
    _wl("db01", "10.0.0.2", "app=db", "env=prod"),
    _wl("bare01", "10.0.0.9"),                                    # VEN, no app label
    _wl("printer01", "10.0.0.7", managed=False),                  # unmanaged, has hostname
    _wl("nameless", "10.0.0.8", managed=False, hostname=""),      # unmanaged, no hostname
] + [_wl(f"a{i}", f"10.0.1.{i}", f"app=a{i}", "env=prod") for i in range(1, 7)]


def _range(from_ip, to_ip=None, exclusion=False):
    return NS(from_ip=from_ip, to_ip=to_ip, exclusion=exclusion)


IP_LISTS = [
    NS(href="/ipl/any", name="Any (0.0.0.0/0 and ::/0)", ip_ranges=[_range("0.0.0.0/0"), _range("::/0")]),
    NS(href="/ipl/dns", name="corp-dns", ip_ranges=[_range("10.1.1.0/24"), _range("10.1.1.70", exclusion=True)]),
    NS(href="/ipl/anth", name="anthropic", ip_ranges=[_range("160.79.104.0/21")]),
    NS(href="/ipl/span", name="lab-span", ip_ranges=[_range("10.5.0.10", "10.5.0.20")]),
]


def _side(ip, workload=None, fqdn=None, ip_lists=()):
    side = {"ip": ip}
    if workload is not None:
        side["workload"] = workload
    if fqdn:
        side["fqdn"] = fqdn
    if ip_lists:
        side["ip_lists"] = [{"name": n} for n in ip_lists]
    return side


def _wl_ref(name, *labels):
    return {"hostname": name, "labels": [{"href": L[l]} for l in labels]}


WEB = _wl_ref("web01", "app=web", "env=prod")
DB = _wl_ref("db01", "app=db", "env=prod")
BARE = _wl_ref("bare01")


def _flow(src, dst, port, proto=6, policy="allowed", n=1, first="2026-10-14T10:00:00Z", last=None):
    return {"src": src, "dst": dst, "service": {"port": port, "proto": proto},
            "policy_decision": policy, "flow_direction": "outbound", "num_connections": n,
            "timestamp_range": {"first_detected": first, "last_detected": last or first}}


def _flows():
    flows = [
        _flow(_side("10.0.0.1", WEB), _side("10.9.9.9"), 443, n=5),                          # managed -> unknown
        _flow(_side("10.1.1.50"), _side("10.0.0.1", WEB), 8443, n=2),                         # unknown -> managed
        _flow(_side("10.0.0.1", WEB), _side("10.0.0.7", _wl_ref("printer01")), 9100, n=4),   # unmanaged, hostname
        _flow(_side("10.0.0.1", WEB), _side("10.0.0.8"), 445, n=4),                           # inventoried IP, no workload
        _flow(_side("169.254.1.1"), _side("10.0.0.1", WEB), 67, proto=17, n=3),               # link-local noise
        _flow(_side("10.0.0.1", WEB), _side("160.79.104.100", fqdn="api.anthropic.com",
                                            ip_lists=["Any (0.0.0.0/0 and ::/0)", "anthropic"]), 443, n=7),
        _flow(_side("10.0.0.9", BARE), _side("10.9.9.10"), 443, n=1),                         # unlabelled VEN -> unknown
        _flow(_side("10.1.1.70"), _side("10.0.0.1", WEB), 3389, n=2),                         # admin port, enforced peer
        _flow(_side("10.0.0.99"), _side("10.0.0.2", DB), 5432, policy="blocked", n=2),        # inside managed /24
        _flow(_side("10.1.1.80"), _side("10.0.0.1", WEB), 443, n=500),                        # volume outlier
    ]
    # Scanner: 12 peer x port pairs, one connection each, 10 blocked + 2 potentially blocked.
    for i, (peer, port) in enumerate((p, port) for p in (("10.0.0.1", WEB), ("10.0.0.2", DB))
                                     for port in (21, 22, 23, 25, 80, 110)):
        flows.append(_flow(_side("10.1.1.66"), _side(*peer), port,
                           policy="potentially_blocked" if i < 2 else "blocked",
                           first=f"2026-10-1{3 + i % 3}T0{i % 6}:00:00Z"))
    # Fan-in DNS: six apps on one port.
    for i in range(1, 7):
        flows.append(_flow(_side(f"10.0.1.{i}", _wl_ref(f"a{i}", f"app=a{i}", "env=prod")),
                           _side("10.1.1.53", ip_lists=["Any (0.0.0.0/0 and ::/0)", "corp-dns"]),
                           53, proto=17, n=4))
    return flows


class FakePCE:
    def __init__(self, flows, workloads=WORKLOADS, ip_lists=IP_LISTS):
        self.labels = FakeLabels(LABELS)
        self.flows = flows
        self.calls = []
        self.workloads = NS(get=lambda params=None: workloads[:(params or {}).get("max_results", 10000)])
        self.ip_lists = NS(get=lambda params=None, **kw: ip_lists[:(params or {}).get("max_results", 1000)])

    def fetch(self, query, name):
        """Stand-in for fetch_flows_raw that honours ip_address filter blocks."""
        self.calls.append(query)
        out = self.flows
        for side, blocks in (("src", query.sources.include), ("dst", query.destinations.include)):
            wanted = {c["ip_address"] for b in blocks for c in b if isinstance(c, dict) and "ip_address" in c}
            if wanted:
                out = [f for f in out if f[side]["ip"] in wanted]
        return out[:query.max_results]


@pytest.fixture
def run(monkeypatch):
    def _run(args, flows=None, **pce_kw):
        pce = FakePCE(_flows() if flows is None else flows, **pce_kw)
        monkeypatch.setattr(U, "fetch_flows_raw", lambda _pce, q, name, meta=None: pce.fetch(q, name))
        out = handle_find_unknown_endpoints(ToolContext(pce=pce, is_stdio=True),
                                            {"start_date": "2026-10-12", "end_date": "2026-10-18", **args})
        payload = json.loads(out[0].text)
        payload["_pce"] = pce
        return payload
    return _run


def _by_ip(payload, key="endpoints"):
    return {e["ip"]: e for e in payload[key]}


# ---------------------------------------------------------------------------
# Registration
# ---------------------------------------------------------------------------

def test_registered_read_only_and_advertised():
    spec = TOOL_REGISTRY["find-unknown-endpoints"]
    assert not spec.mutating and not spec.requires_confirm and spec.requires_pce
    import asyncio
    from illumio_mcp.server import handle_list_tools
    tool = next(t for t in asyncio.run(handle_list_tools()) if t.name == "find-unknown-endpoints")
    props = tool.inputSchema["properties"]
    assert {"start_date", "end_date", "lookback_days", "direction", "min_connections", "top_n",
            "ip", "include_noise", "policy_decisions", "include_services"} <= set(props)
    assert "WRITE OPERATION" not in tool.description


# ---------------------------------------------------------------------------
# Classification: what is unknown, and what is not
# ---------------------------------------------------------------------------

def test_unknown_means_no_workload_and_not_in_inventory(run):
    """printer01 has a workload object; 10.0.0.8 has none but is inventoried.
    Neither is unknown. 10.9.9.9 and 10.1.1.50 are."""
    out = run({})
    ips = set(_by_ip(out))
    assert {"10.9.9.9", "10.1.1.50"} <= ips
    assert "10.0.0.7" not in ips and "10.0.0.8" not in ips
    assert out["totals"]["known_by_inventory_only"] == 1          # 10.0.0.8
    assert out["totals"]["unlabelled_workloads_seen"] == 3        # bare01, printer01, nameless


def test_unlabelled_vens_are_not_unknown_unlike_find_unmanaged_traffic(run):
    """bare01 is a VEN without an app label. find-unmanaged-traffic lists it;
    this tool counts it as a workload and profiles the address it talked to."""
    out = run({})
    assert "10.0.0.9" not in _by_ip(out)
    assert _by_ip(out)["10.9.9.10"]["as_destination"]["peer_apps"] == ["unlabelled"]


def test_direction_is_relative_to_workloads(run):
    inbound = _by_ip(run({"direction": "inbound"}))
    outbound = _by_ip(run({"direction": "outbound"}))
    assert "10.1.1.50" in inbound and "10.9.9.9" not in inbound
    assert "10.9.9.9" in outbound and "10.1.1.50" not in outbound
    assert "as_destination" not in inbound["10.1.1.50"]
    assert "as_source" not in outbound["10.9.9.9"]


def test_noise_is_counted_but_listed_only_on_request(run):
    out = run({})
    assert "169.254.1.1" not in _by_ip(out)
    assert out["totals"]["noise_endpoints"] == 1
    assert out["totals"]["noise_connections"] == 3
    assert "noise" not in out
    with_noise = run({"include_noise": True})
    noise = _by_ip(with_noise, "noise")
    assert noise["169.254.1.1"]["address_class"] == "link_local"
    assert noise["169.254.1.1"]["noise"] is True
    assert with_noise["totals"]["unknown_connections"] == sum(
        e["connections"] for e in with_noise["endpoints"])


@pytest.mark.parametrize("ip,klass", [
    ("10.1.2.3", "private"), ("172.20.0.1", "private"), ("192.168.9.9", "private"),
    ("100.64.1.1", "private"), ("fd00::1", "private"),
    ("8.8.8.8", "public"), ("2606:4700::1111", "public"),
    ("169.254.1.1", "link_local"), ("fe80::1", "link_local"),
    ("224.0.0.251", "multicast"), ("ff02::1", "multicast"),
    ("255.255.255.255", "broadcast"), ("127.0.0.1", "loopback"), ("::1", "loopback"),
    ("not-an-ip", None),
])
def test_address_classes(ip, klass):
    assert address_class(ip) == klass


def test_dot_255_is_broadcast_only_inside_a_managed_slash_24():
    assert address_class("10.0.0.255", {"10.0.0.0/24": 3}) == "broadcast"
    assert address_class("10.0.0.255", {}) == "private"


# ---------------------------------------------------------------------------
# Enrichment: IP lists, provider, neighbourhood, inventory join
# ---------------------------------------------------------------------------

def test_default_ip_list_is_dropped_and_named_lists_kept(run):
    out = run({})
    eps = _by_ip(out)
    assert eps["10.1.1.53"]["ip_lists"] == ["corp-dns"]
    assert eps["160.79.104.100"]["ip_lists"] == ["anthropic"]
    assert eps["10.9.9.9"]["ip_lists"] == []
    assert out["totals"]["default_ip_lists"] == ["Any (0.0.0.0/0 and ::/0)"]
    assert "Any (0.0.0.0/0" not in json.dumps(out["endpoints"])


def test_ip_list_exclusions_and_spans_are_honoured():
    lists, truncated = U.load_ip_lists(FakePCE([]))
    import ipaddress as ia
    assert not truncated
    assert covering_ip_lists(ia.ip_address("10.1.1.53"), lists) == ["corp-dns"]
    assert covering_ip_lists(ia.ip_address("10.1.1.70"), lists) == []        # excluded
    assert covering_ip_lists(ia.ip_address("10.5.0.15"), lists) == ["lab-span"]
    assert covering_ip_lists(ia.ip_address("10.5.0.21"), lists) == []
    assert covering_ip_lists(ia.ip_address("8.8.8.8"), lists) == []         # default only


def test_public_destination_carries_fqdn_and_provider(run):
    ep = _by_ip(run({}))["160.79.104.100"]
    assert ep["address_class"] == "public"
    assert ep["fqdn"] == "api.anthropic.com"
    assert ep["likely_provider"] == "anthropic" and ep["provider_confidence"] == "likely"
    assert _by_ip(run({}))["10.9.9.9"]["likely_provider"] is None


def test_neighbourhood_names_the_managed_prefix(run):
    eps = _by_ip(run({}))
    # web01, db01, bare01 are managed in 10.0.0.0/24; printer01/nameless are not.
    assert eps["10.0.0.99"]["neighbourhood"] == {"prefix": "10.0.0.0/24", "managed_workloads": 3}
    assert eps["10.1.1.50"]["neighbourhood"] is None


def test_peers_enforced_and_allowed_into_enforced(run):
    """web01 is in full enforcement, so allowed traffic there means a rule admits
    the unknown address."""
    eps = _by_ip(run({}))
    admin = eps["10.1.1.70"]
    assert admin["peers_enforced"] == 1
    assert admin["as_source"]["allowed_into_enforced"] == 2
    assert eps["10.0.0.99"]["peers_enforced"] == 0          # db01 is visibility_only


# ---------------------------------------------------------------------------
# Per-direction blocks
# ---------------------------------------------------------------------------

def test_side_block_shape(run):
    ep = _by_ip(run({}))["10.1.1.53"]
    dst = ep["as_destination"]
    assert dst["connections"] == 24 and dst["flows"] == 6
    assert dst["peer_workloads"] == 6
    assert dst["peer_apps"] == [f"a{i} (prod)" for i in range(1, 7)]
    assert dst["ports"] == [{"port": 53, "proto": "udp", "connections": 24, "flows": 6, "peers": 6,
                             "admin": False, "policy": {"allowed": 24, "potentially_blocked": 0, "blocked": 0}}]
    assert dst["policy"] == {"allowed": 24, "potentially_blocked": 0, "blocked": 0}
    assert dst["first_seen"] == "2026-10-14T10:00:00Z" and dst["last_seen"] == "2026-10-14T10:00:00Z"
    assert "as_source" not in ep
    assert "peers" not in dst                                 # full table only with ip


def test_endpoints_are_sorted_by_connections_and_top_n_applies(run):
    out = run({})
    conns = [e["connections"] for e in out["endpoints"]]
    assert conns == sorted(conns, reverse=True) and conns[0] == 500
    top = run({"top_n": 2})
    assert len(top["endpoints"]) == 2 and top["totals"]["unknown_endpoints"] == out["totals"]["unknown_endpoints"]
    assert top["totals"]["returned"] == 2


def test_min_connections_filters_endpoints(run):
    out = run({"min_connections": 3})
    ips = set(_by_ip(out))
    assert "10.1.1.50" not in ips and "10.9.9.9" in ips


# ---------------------------------------------------------------------------
# Profile shapes
# ---------------------------------------------------------------------------

def test_scanner_shape(run):
    ep = _by_ip(run({}))["10.1.1.66"]
    assert "scanner" in ep["profile"]
    assert ep["profile_evidence"]["scanner"] == {"peer_port_pairs": 12, "median_connections_per_pair": 1,
                                                 "denied_share": 1.0}
    assert "high_volume" not in ep["profile"]                 # 12 < 10x median of 2
    assert ep["as_source"]["policy"] == {"allowed": 0, "potentially_blocked": 2, "blocked": 10}


def test_fan_in_server_shape(run):
    ep = _by_ip(run({}))["10.1.1.53"]
    assert ep["profile"] == ["fan_in_server"]
    assert ep["profile_evidence"]["fan_in_server"] == {"peer_apps": 6, "ports": 1}


def test_admin_reach_shape(run):
    ep = _by_ip(run({}))["10.1.1.70"]
    assert "admin_reach" in ep["profile"] and "single_peer" in ep["profile"]
    assert ep["profile_evidence"]["admin_reach"] == {"admin_ports": ["3389/tcp"], "allowed_connections": 2}
    assert ep["as_source"]["ports"][0]["admin"] is True
    blocked = _by_ip(run({}))["10.0.0.99"]
    assert blocked["profile_evidence"]["admin_reach"] == {"admin_ports": ["5432/tcp"], "allowed_connections": 0}


def test_high_volume_shape_needs_five_endpoints_and_ten_times_the_median(run):
    eps = _by_ip(run({}))
    assert "high_volume" in eps["10.1.1.80"]["profile"]
    assert eps["10.1.1.80"]["profile_evidence"]["high_volume"]["as_source"] == {
        "connections": 500, "median": 2, "multiple": 250.0}
    # Outbound has only three unknown destinations: no median, no outlier.
    assert "high_volume" not in eps["160.79.104.100"]["profile"]


def test_single_peer_shape(run):
    eps = _by_ip(run({}))
    assert eps["10.9.9.9"]["profile"] == ["single_peer"]
    assert eps["10.9.9.9"]["profile_evidence"]["single_peer"] == {"peer": "web01"}
    assert "single_peer" not in eps["10.1.1.66"]["profile"]


# ---------------------------------------------------------------------------
# Truncation
# ---------------------------------------------------------------------------

def test_truncation_flags_and_coverage_note(run):
    out = run({})
    assert out["totals"]["flows_truncated"] is False and out["totals"]["inventory_truncated"] is False
    assert out["coverage_note"].startswith("Complete")
    out = run({"max_results": 5})
    assert out["totals"]["flows_truncated"] is True and "cap" in out["coverage_note"]
    out = run({"max_workloads": 2})
    assert out["totals"]["inventory_truncated"] is True and out["totals"]["inventory_workloads"] == 2
    assert "possibly known" in out["coverage_note"]


def test_empty_window(run):
    out = run({}, flows=[])
    assert out["endpoints"] == [] and out["totals"]["unknown_endpoints"] == 0
    assert out["totals"]["pce_flows"] == 0


def test_backwards_window_is_rejected(run):
    out = run({"start_date": "2026-10-18", "end_date": "2026-10-12"})
    assert "error" in out and "backwards" in out["error"]


def test_explorer_pull_is_one_query_with_all_three_decisions(run):
    out = run({})
    pce = out["_pce"]
    assert len(pce.calls) == 1 and out["totals"]["pce_queries"] == 1
    q = pce.calls[0]
    assert set(q.policy_decisions) == {"allowed", "potentially_blocked", "blocked"}
    assert q.start_date == "2026-10-12T00:00:00Z" and q.end_date == "2026-10-18T23:59:59Z"
    assert q.exclude_workloads_from_ip_list_query is False


# ---------------------------------------------------------------------------
# ip mode
# ---------------------------------------------------------------------------

def test_ip_mode_profiles_one_endpoint_with_full_peer_table_and_timeline(run):
    out = run({"ip": "10.1.1.66"})
    assert out["ip"] == "10.1.1.66" and len(out["endpoints"]) == 1
    ep = out["endpoints"][0]
    peers = ep["as_source"]["peers"]
    assert len(peers) == 12
    assert {p["peer"] for p in peers} == {"web01", "db01"}
    assert {p["port"] for p in peers} == {21, 22, 23, 25, 80, 110}
    assert peers[0].keys() >= {"peer", "peer_app", "peer_enforcement_mode", "port", "proto", "admin",
                               "connections", "flows", "policy", "first_seen", "last_seen"}
    assert "scanner" in ep["profile"]
    tl = out["timeline"]
    assert tl["bucket"] == "1d"                                   # 7-day window
    assert [b["bucket_start"] for b in tl["series"]][:2] == ["2026-10-12T00:00:00Z", "2026-10-13T00:00:00Z"]
    assert sum(b["flows"] for b in tl["series"]) == 12
    assert tl["series"][1]["by_policy_decision"]                  # split by decision
    assert tl["spikes"]["rule"].startswith(">= 3x")


def test_ip_mode_filters_server_side_per_direction(run):
    out = run({"ip": "10.1.1.66", "direction": "inbound"})
    q = out["_pce"].calls
    assert len(q) == 1 and out["totals"]["pce_queries"] == 1
    assert q[0].sources.include == [[{"ip_address": "10.1.1.66"}]]
    both = run({"ip": "10.1.1.66"})
    assert len(both["_pce"].calls) == 2 and both["totals"]["pce_queries"] == 2
    assert both["_pce"].calls[1].destinations.include == [[{"ip_address": "10.1.1.66"}]]


def test_ip_mode_uses_hourly_buckets_for_short_windows(run):
    out = run({"ip": "10.1.1.80", "start_date": "2026-10-14", "end_date": "2026-10-14"})
    assert out["timeline"]["bucket"] == "1h" and len(out["timeline"]["series"]) == 24
    assert out["timeline"]["series"][10]["connections"] == 500


def test_ip_mode_reports_an_inventoried_address_as_known_without_a_query(run):
    out = run({"ip": "10.0.0.8"})
    assert out["known"] is True and out["workload"]["managed"] is False
    assert out["_pce"].calls == []
    assert run({"ip": "10.0.0.1"})["workload"]["hostname"] == "web01"


def test_ip_mode_with_no_flows_says_so(run):
    out = run({"ip": "10.77.77.77"})
    assert out["endpoints"] == [] and "No flows" in out["message"] and "timeline" not in out


def test_ip_mode_rejects_a_non_address(run):
    assert "error" in run({"ip": "web01"})


def test_ip_mode_profiles_noise_when_asked_explicitly(run):
    out = run({"ip": "169.254.1.1"})
    assert out["endpoints"][0]["noise"] is True and out["endpoints"][0]["address_class"] == "link_local"
