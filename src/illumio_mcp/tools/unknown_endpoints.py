"""find-unknown-endpoints: addresses in traffic that the PCE does not know at all.

An endpoint is **unknown** when both hold (issue #48):

  1. Explorer attached no workload to that side of the flow. Managed and
     unmanaged workloads both carry a workload object, so an inventoried
     unmanaged workload is not unknown.
  2. Its IP is not an interface address of any workload in the inventory.
     This catches workloads created after the flows were recorded and
     unmanaged workloads whose hostname and name are empty.

IP-list membership does not make an endpoint known. It is reported, because
"covered by IP list X" changes the finding, but a /8 in a list is not an
inventory entry, and the default 0.0.0.0/0 list is never coverage.

`find-unmanaged-traffic` answers a different question: its test is "no app
label", so it lists unlabelled VENs and drops labelled unmanaged workloads.
"""
import ipaddress
import json
import logging
import statistics
from collections import Counter, defaultdict
from datetime import datetime, timedelta, timezone

import pandas as pd
import mcp.types as types
from illumio import TrafficQuery

from ..log_scrub import ScrubbedArgs
from ..errors import describe_error
from .constants import MCP_QUERY_MAX_RESULTS
from .traffic import (
    NA, TIMELINE_BUCKETS, _bucket_series, _effective_bucket, _int, _normalise_filter,
    _proto, _spikes, check_window, classify_destination, fetch_flows_raw,
    raw_flows_to_dataframe, to_query_end, to_query_start,
)
from .workloads import _build_label_map

logger = logging.getLogger('illumio_mcp')


# ---------------------------------------------------------------------------
# Thresholds. Shared with the illumio-unknown-endpoints skill's rubric; change
# them there too or the report and the tool will name different scanners.
# ---------------------------------------------------------------------------

# (port, proto). tcp unless noted; 161/udp is SNMP.
ADMIN_PORTS = frozenset({(p, 6) for p in (
    21, 22, 23, 88, 135, 139, 389, 445, 636, 1433, 1521, 2049, 3306, 3389,
    5432, 5900, 5985, 5986, 6379, 9200, 27017)} | {(161, 17)})

SCANNER_MIN_PAIRS = 10          # distinct peer x port/proto pairs
SCANNER_MAX_MEDIAN = 3          # median connections per pair
SCANNER_BLOCKED_SHARE = 0.7     # of connections with a known decision
FAN_IN_MIN_APPS = 5
FAN_IN_MAX_PORTS = 3
HIGH_VOLUME_MULTIPLE = 10
HIGH_VOLUME_MIN_ENDPOINTS = 5

NOISE_CLASSES = ("link_local", "multicast", "broadcast", "loopback")
POLICY_DECISIONS = ("allowed", "potentially_blocked", "blocked")
DEFAULT_LIST_RANGES = frozenset({"0.0.0.0/0", "::/0"})

# RFC 1918, carrier NAT and ULA. Python's is_private says False for 100.64/10
# and True for TEST-NET and reserved space, neither of which is what "private"
# means to someone reading an inventory gap report.
_PRIVATE_NETS = tuple(ipaddress.ip_network(n) for n in (
    "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "100.64.0.0/10", "fc00::/7"))
_V4_BROADCAST = ipaddress.ip_address("255.255.255.255")

DEFAULT_WORKLOADS = 10000
DEFAULT_IP_LISTS = 1000


# ---------------------------------------------------------------------------
# Addresses
# ---------------------------------------------------------------------------

def _addr(value):
    try:
        return ipaddress.ip_address(str(value).strip())
    except (ValueError, TypeError):
        return None


def _prefix(addr) -> str:
    """The /24 (IPv4) or /64 (IPv6) containing an address."""
    bits = 24 if addr.version == 4 else 64
    return str(ipaddress.ip_network(f"{addr}/{bits}", strict=False))


def address_class(ip, managed_prefixes=()) -> str | None:
    """private | public | link_local | multicast | broadcast | loopback.

    None when the value is not an IP address. Broadcast is 255.255.255.255 or
    the .255 of a /24 that holds a managed workload: a .255 in some other
    range is just an address.
    """
    addr = _addr(ip)
    if addr is None:
        return None
    if addr.is_loopback:
        return "loopback"
    if addr.is_link_local:
        return "link_local"
    if addr.is_multicast:
        return "multicast"
    if addr.version == 4:
        if addr == _V4_BROADCAST:
            return "broadcast"
        net = ipaddress.ip_network(f"{addr}/24", strict=False)
        if addr == net.broadcast_address and str(net) in managed_prefixes:
            return "broadcast"
    if any(addr in net for net in _PRIVATE_NETS if net.version == addr.version):
        return "private"
    return "public"


# ---------------------------------------------------------------------------
# Inventory and IP lists: one pull each
# ---------------------------------------------------------------------------

def _attr(obj, name, default=None):
    if obj is None:
        return default
    if isinstance(obj, dict):
        return obj.get(name, default)
    return getattr(obj, name, default)


def load_inventory(pce, max_workloads: int = DEFAULT_WORKLOADS) -> dict:
    """Every workload's interface addresses, managed flag, enforcement and labels.

    Returns the known-IP set, a hostname index, and the managed prefixes (/24
    or /64 with the number of managed workloads in each).
    """
    workloads = pce.workloads.get(params={"include": "labels", "max_results": max_workloads})
    label_map = _build_label_map(pce)
    known: dict = {}
    by_hostname: dict = {}
    prefixes: dict = defaultdict(set)
    for w in workloads:
        labels = {}
        for l in (_attr(w, "labels") or []):
            info = label_map.get(_attr(l, "href"))
            if info:
                labels[info["key"]] = info["value"]
        entry = {
            "href": _attr(w, "href"),
            "hostname": _attr(w, "hostname") or _attr(w, "name") or None,
            "managed": bool(_attr(w, "agent") or _attr(w, "ven")),
            "enforcement_mode": _attr(w, "enforcement_mode"),
            "app": labels.get("app"),
            "env": labels.get("env"),
        }
        if entry["hostname"]:
            by_hostname.setdefault(entry["hostname"], entry)
        for intf in (_attr(w, "interfaces") or []):
            address = _attr(intf, "address")
            addr = _addr(address)
            if addr is None:
                continue
            known.setdefault(str(addr), entry)
            if entry["managed"]:
                prefixes[_prefix(addr)].add(entry["href"] or id(w))
    return {
        "known": known,
        "by_hostname": by_hostname,
        "managed_prefixes": {p: len(s) for p, s in prefixes.items()},
        "count": len(workloads),
        "truncated": len(workloads) >= max_workloads,
    }


def _parse_range(from_ip, to_ip):
    """A CIDR when to_ip is empty, else the span from_ip..to_ip. None if unparseable."""
    if not from_ip:
        return None
    try:
        if to_ip:
            lo, hi = ipaddress.ip_address(str(from_ip)), ipaddress.ip_address(str(to_ip))
            return (lo, hi) if lo.version == hi.version else None
        return ipaddress.ip_network(str(from_ip).strip(), strict=False)
    except ValueError:
        return None


def _range_contains(rng, addr) -> bool:
    if isinstance(rng, tuple):
        lo, hi = rng
        return lo.version == addr.version and lo <= addr <= hi
    return rng.version == addr.version and addr in rng


def load_ip_lists(pce, max_lists: int = DEFAULT_IP_LISTS) -> tuple[list, bool]:
    """Draft IP lists with their ranges parsed; `default` marks 0.0.0.0/0 or ::/0."""
    lists = pce.ip_lists.get(params={"max_results": max_lists})
    parsed = []
    for ipl in lists:
        includes, excludes, is_default = [], [], False
        for r in (_attr(ipl, "ip_ranges") or []):
            rng = _parse_range(_attr(r, "from_ip"), _attr(r, "to_ip"))
            if rng is None:
                continue
            if _attr(r, "exclusion"):
                excludes.append(rng)
                continue
            includes.append(rng)
            if not isinstance(rng, tuple) and str(rng) in DEFAULT_LIST_RANGES:
                is_default = True
        parsed.append({"name": _attr(ipl, "name"), "href": _attr(ipl, "href"),
                       "includes": includes, "excludes": excludes, "default": is_default})
    return parsed, len(lists) >= max_lists


def covering_ip_lists(addr, ip_lists: list) -> list:
    """Names of the named lists containing addr, exclusions honoured, default dropped."""
    names = []
    for ipl in ip_lists:
        if ipl["default"]:
            continue
        if any(_range_contains(r, addr) for r in ipl["includes"]) and \
                not any(_range_contains(r, addr) for r in ipl["excludes"]):
            names.append(ipl["name"])
    return names


# ---------------------------------------------------------------------------
# Flow aggregation
# ---------------------------------------------------------------------------

def _clean(value):
    if value is None or value == NA:
        return None
    try:
        if pd.isna(value):
            return None
    except (TypeError, ValueError):
        pass
    return value


def _new_side() -> dict:
    return {"connections": 0, "flows": 0, "peers": {}, "apps": set(), "ports": {},
            "pairs": {}, "policy": Counter(), "first_seen": None, "last_seen": None,
            "allowed_into_enforced": 0}


def _new_endpoint(ip) -> dict:
    return {"ip": ip, "fqdns": Counter(), "flow_ip_lists": set(),
            "as_source": _new_side(), "as_destination": _new_side()}


def _peer_identity(row, prefix, inventory) -> dict:
    """Who the workload side of the flow is: hostname, app/env, enforcement."""
    ip = _clean(row.get(f"{prefix}_ip"))
    inv = inventory["known"].get(ip) if ip else None
    hostname = _clean(row.get(f"{prefix}_hostname")) or (inv or {}).get("hostname") or ip
    if inv is None and hostname:
        inv = inventory["by_hostname"].get(hostname)
    app = _clean(row.get(f"{prefix}_app")) or (inv or {}).get("app")
    env = _clean(row.get(f"{prefix}_env")) or (inv or {}).get("env")
    return {"key": hostname or ip, "hostname": hostname, "ip": ip, "app": app, "env": env,
            "enforcement_mode": (inv or {}).get("enforcement_mode")}


def _app_label(peer: dict) -> str:
    if not peer["app"]:
        return "unlabelled"
    return f"{peer['app']} ({peer['env']})" if peer["env"] else peer["app"]


def _min_ts(a, b):
    return b if a is None else a if b is None else min(a, b)


def _max_ts(a, b):
    return b if a is None else a if b is None else max(a, b)


def _record(side: dict, row: dict, peer: dict) -> None:
    conns = int(_clean(row.get("num_connections")) or 0)
    port, proto = _int(_clean(row.get("port"))), _int(_clean(row.get("proto")))
    decision = _clean(row.get("policy_decision")) or "unknown"
    first, last = _clean(row.get("first_detected")), _clean(row.get("last_detected"))
    first = str(first) if first is not None else None
    last = str(last) if last is not None else None

    side["connections"] += conns
    side["flows"] += 1
    side["policy"][decision] += conns
    side["first_seen"] = _min_ts(side["first_seen"], first)
    side["last_seen"] = _max_ts(side["last_seen"], last)
    side["peers"].setdefault(peer["key"], peer)
    side["apps"].add(_app_label(peer))
    if decision == "allowed" and peer["enforcement_mode"] == "full":
        side["allowed_into_enforced"] += conns

    p = side["ports"].setdefault((port, proto), {"connections": 0, "flows": 0,
                                                 "policy": Counter(), "peers": set()})
    p["connections"] += conns
    p["flows"] += 1
    p["policy"][decision] += conns
    p["peers"].add(peer["key"])

    pair = side["pairs"].setdefault((peer["key"], port, proto), {
        "connections": 0, "flows": 0, "policy": Counter(), "first_seen": None,
        "last_seen": None, "peer": peer})
    pair["connections"] += conns
    pair["flows"] += 1
    pair["policy"][decision] += conns
    pair["first_seen"] = _min_ts(pair["first_seen"], first)
    pair["last_seen"] = _max_ts(pair["last_seen"], last)


def aggregate_endpoints(df: pd.DataFrame, inventory: dict) -> tuple[dict, dict]:
    """Group flows by the unknown side. Returns (endpoints by ip, counters).

    A side is known when the flow carries a workload for it OR its IP is an
    interface address in the inventory. Only flows with a known peer on the
    other side are profiled; a flow between two unknowns has no workload to
    anchor it and is counted separately.
    """
    endpoints: dict = {}
    unlabelled: set = set()
    inventory_only: set = set()
    counts = Counter()
    if df is None or df.empty:
        return endpoints, {"unlabelled_workloads_seen": 0, "known_by_inventory_only": 0,
                           "rows_between_unknowns": 0, "rows_without_ip": 0}

    known_ips = inventory["known"]
    for row in df.to_dict("records"):
        sides = {}
        for prefix in ("src", "dst"):
            ip = _clean(row.get(f"{prefix}_ip"))
            hostname = _clean(row.get(f"{prefix}_hostname"))
            inv = known_ips.get(ip) if ip else None
            known = bool(hostname) or inv is not None
            sides[prefix] = (ip, known)
            if not known:
                continue
            if not hostname and inv is not None:
                inventory_only.add(ip)
            app = _clean(row.get(f"{prefix}_app")) or (inv or {}).get("app")
            if not app:
                unlabelled.add(hostname or (inv or {}).get("hostname") or ip)

        (src_ip, src_known), (dst_ip, dst_known) = sides["src"], sides["dst"]
        if src_known and dst_known:
            continue
        if not src_known and not dst_known:
            counts["rows_between_unknowns"] += 1
            continue
        if not src_known:
            if not src_ip:
                counts["rows_without_ip"] += 1
                continue
            ep = endpoints.setdefault(src_ip, _new_endpoint(src_ip))
            _record(ep["as_source"], row, _peer_identity(row, "dst", inventory))
            fqdn, lists = _clean(row.get("src_fqdn")), _clean(row.get("src_ip_lists"))
        else:
            if not dst_ip:
                counts["rows_without_ip"] += 1
                continue
            ep = endpoints.setdefault(dst_ip, _new_endpoint(dst_ip))
            _record(ep["as_destination"], row, _peer_identity(row, "src", inventory))
            fqdn, lists = _clean(row.get("dst_fqdn")), _clean(row.get("dst_ip_lists"))
        if fqdn:
            ep["fqdns"][str(fqdn)] += 1
        if lists:
            ep["flow_ip_lists"].update(n.strip() for n in str(lists).split(",") if n.strip())

    return endpoints, {
        "unlabelled_workloads_seen": len(unlabelled),
        "known_by_inventory_only": len(inventory_only),
        "rows_between_unknowns": counts["rows_between_unknowns"],
        "rows_without_ip": counts["rows_without_ip"],
    }


# ---------------------------------------------------------------------------
# Profiles and rendering
# ---------------------------------------------------------------------------

def _policy(counter: Counter) -> dict:
    out = {k: int(counter.get(k, 0)) for k in POLICY_DECISIONS}
    for k, v in counter.items():
        if k not in out:
            out[k] = int(v)
    return out


def _render_side(side: dict, full_pairs: bool) -> dict:
    ports = sorted(side["ports"].items(), key=lambda kv: (-kv[1]["connections"], str(kv[0])))
    out = {
        "connections": int(side["connections"]),
        "flows": int(side["flows"]),
        "peer_workloads": len(side["peers"]),
        "peer_apps": sorted(side["apps"]),
        "distinct_ports": len(ports),
        "ports": [
            {"port": port, "proto": _proto(proto), "connections": int(p["connections"]),
             "flows": int(p["flows"]), "peers": len(p["peers"]),
             "admin": (port, proto) in ADMIN_PORTS, "policy": _policy(p["policy"])}
            for (port, proto), p in ports[:10]
        ],
        "policy": _policy(side["policy"]),
        "allowed_into_enforced": int(side["allowed_into_enforced"]),
        "first_seen": side["first_seen"],
        "last_seen": side["last_seen"],
    }
    if full_pairs:
        pairs = sorted(side["pairs"].items(), key=lambda kv: (-kv[1]["connections"], str(kv[0])))
        out["peers"] = [
            {"peer": peer_key, "peer_app": _app_label(pr["peer"]),
             "peer_enforcement_mode": pr["peer"]["enforcement_mode"],
             "port": port, "proto": _proto(proto), "admin": (port, proto) in ADMIN_PORTS,
             "connections": int(pr["connections"]), "flows": int(pr["flows"]),
             "policy": _policy(pr["policy"]),
             "first_seen": pr["first_seen"], "last_seen": pr["last_seen"]}
            for (peer_key, port, proto), pr in pairs
        ]
    return out


def profile_shapes(ep: dict, directions: tuple, medians: dict) -> tuple[list, dict]:
    """Which of scanner, fan_in_server, admin_reach, high_volume, single_peer apply.

    Evidence is returned next to the names so a report can quote the numbers
    the test used rather than re-deriving them.
    """
    shapes, evidence = [], {}
    src = ep["as_source"] if "as_source" in directions else None
    dst = ep["as_destination"] if "as_destination" in directions else None

    if src and len(src["pairs"]) >= SCANNER_MIN_PAIRS:
        median = statistics.median(p["connections"] for p in src["pairs"].values())
        known = sum(src["policy"].get(k, 0) for k in POLICY_DECISIONS)
        denied = src["policy"].get("blocked", 0) + src["policy"].get("potentially_blocked", 0)
        share = (denied / known) if known else None
        if median <= SCANNER_MAX_MEDIAN and (share is None or share >= SCANNER_BLOCKED_SHARE):
            shapes.append("scanner")
            evidence["scanner"] = {"peer_port_pairs": len(src["pairs"]),
                                   "median_connections_per_pair": median,
                                   "denied_share": None if share is None else round(share, 2)}

    if dst:
        apps = {a for a in dst["apps"] if a != "unlabelled"}
        if len(apps) >= FAN_IN_MIN_APPS and len(dst["ports"]) <= FAN_IN_MAX_PORTS:
            shapes.append("fan_in_server")
            evidence["fan_in_server"] = {"peer_apps": len(apps), "ports": len(dst["ports"])}

    if src:
        admin = sorted((f"{port}/{_proto(proto)}" for (port, proto) in src["ports"]
                        if (port, proto) in ADMIN_PORTS))
        if admin:
            shapes.append("admin_reach")
            allowed = sum(int(p["policy"].get("allowed", 0)) for (port, proto), p in src["ports"].items()
                          if (port, proto) in ADMIN_PORTS)
            evidence["admin_reach"] = {"admin_ports": admin, "allowed_connections": allowed}

    for name, side in (("as_source", src), ("as_destination", dst)):
        median = medians.get(name)
        if side and median and side["connections"] >= HIGH_VOLUME_MULTIPLE * median:
            if "high_volume" not in shapes:
                shapes.append("high_volume")
            evidence.setdefault("high_volume", {})[name] = {
                "connections": int(side["connections"]), "median": median,
                "multiple": round(side["connections"] / median, 1)}

    peers = set()
    for side in (src, dst):
        if side:
            peers |= set(side["peers"])
    if len(peers) == 1:
        shapes.append("single_peer")
        evidence["single_peer"] = {"peer": next(iter(peers))}
    return shapes, evidence


def _direction_medians(endpoints: list, directions: tuple) -> dict:
    """Median connections per direction over all unknown endpoints active there.

    The rule needs at least HIGH_VOLUME_MIN_ENDPOINTS endpoints: with fewer, the
    median is one or two hosts and every busy one would be an outlier.
    """
    medians = {}
    for name in directions:
        values = [ep[name]["connections"] for ep in endpoints if ep[name]["connections"] > 0]
        if len(values) >= HIGH_VOLUME_MIN_ENDPOINTS:
            medians[name] = statistics.median(values)
    return medians


def render_endpoint(ep: dict, directions: tuple, inventory: dict, ip_lists: list,
                    medians: dict, full_pairs: bool = False) -> dict:
    addr = _addr(ep["ip"])
    klass = address_class(ep["ip"], inventory["managed_prefixes"])
    out = {
        "ip": ep["ip"],
        "fqdn": ep["fqdns"].most_common(1)[0][0] if ep["fqdns"] else None,
        "address_class": klass,
        "noise": klass in NOISE_CLASSES,
        "ip_lists": [],
        "likely_provider": None,
        "provider_confidence": None,
        "neighbourhood": None,
        "connections": 0,
        "peer_workloads": 0,
        "peers_enforced": 0,
    }
    if addr is not None:
        names = set(covering_ip_lists(addr, ip_lists))
        default_names = {l["name"] for l in ip_lists if l["default"]}
        names |= (ep["flow_ip_lists"] - default_names)
        out["ip_lists"] = sorted(n for n in names if n)
        prefix = _prefix(addr)
        managed = inventory["managed_prefixes"].get(prefix, 0)
        if managed:
            out["neighbourhood"] = {"prefix": prefix, "managed_workloads": managed}
        if klass == "public":
            out["likely_provider"], out["provider_confidence"] = classify_destination(ep["ip"])

    peers = {}
    for name in directions:
        side = ep[name]
        if side["flows"]:
            out[name] = _render_side(side, full_pairs)
            out["connections"] += int(side["connections"])
            peers.update(side["peers"])
    out["peer_workloads"] = len(peers)
    out["peers_enforced"] = sum(1 for p in peers.values() if p["enforcement_mode"] == "full")
    out["profile"], out["profile_evidence"] = profile_shapes(ep, directions, medians)
    return out


# ---------------------------------------------------------------------------
# Timeline for one endpoint
# ---------------------------------------------------------------------------

def endpoint_timeline(df: pd.DataFrame, start: str, end: str) -> dict:
    """Bucketed flows for one endpoint: 1h buckets up to two days, else 1d.

    Reuses the timeline tool's bucketing and spike rule, including its two
    caveats: a requested bucket finer than the data, and a worst bucket on the
    window edge where earlier aggregates pile up.
    """
    s_dt, e_dt = datetime.fromisoformat(start), datetime.fromisoformat(end)
    s_dt = s_dt if s_dt.tzinfo else s_dt.replace(tzinfo=timezone.utc)
    e_dt = e_dt if e_dt.tzinfo else e_dt.replace(tzinfo=timezone.utc)
    bucket = "1h" if (e_dt - s_dt) <= timedelta(days=2) else "1d"
    step = TIMELINE_BUCKETS[bucket]
    first_bucket = int(s_dt.timestamp()) // step * step
    count = (int(e_dt.timestamp()) // step * step - first_bucket) // step + 1

    series, spanning, unbucketed, outside, median_span = _bucket_series(
        df, first_bucket, step, count, "policy_decision")
    effective = _effective_bucket(median_span)
    too_fine = TIMELINE_BUCKETS[effective] > step
    payload = {
        "bucket": bucket,
        "effective_bucket": effective,
        "series": series,
        "rows_spanning_buckets": spanning,
        "spikes": _spikes(series),
    }
    if unbucketed or outside:
        payload["rows_not_bucketed"] = {"no_timestamp": unbucketed, "outside_window": outside}
    if spanning:
        payload["resolution_note"] = (
            f"{spanning} row(s) span more than one {bucket} bucket; Explorer aggregates "
            f"a persistent connection, and older data per day, into one row counted "
            f"where it began. Median row span {median_span / 3600:.1f}h, so the data "
            f"supports {effective} buckets.")
    worst = payload["spikes"]["worst"]
    if too_fine:
        payload["spikes"]["caveat"] = (
            f"Unreliable at {bucket}: most rows are aggregates wider than the bucket, "
            f"so their starts read as spikes. Read at {effective}.")
    elif worst and spanning and worst["bucket_start"] == series[0]["bucket_start"]:
        payload["spikes"]["caveat"] = (
            "The worst bucket is the first of the window, where aggregates that began "
            "earlier pile up. Widen the window by one bucket before calling it a spike.")
    return payload


# ---------------------------------------------------------------------------
# Handler
# ---------------------------------------------------------------------------

_DIRECTIONS = {"inbound": ("as_source",), "outbound": ("as_destination",),
               "both": ("as_source", "as_destination")}


def _pull(pce, start, end, arguments, max_results, *, sources=None, destinations=None):
    name = arguments.get("query_name", "mcp-unknown-endpoints")
    query = TrafficQuery.build(
        start_date=start, end_date=end,
        include_sources=_normalise_filter(sources),
        include_destinations=_normalise_filter(destinations),
        exclude_sources=[], exclude_destinations=[],
        include_services=arguments.get("include_services") or [],
        exclude_services=[],
        policy_decisions=arguments.get("policy_decisions") or list(POLICY_DECISIONS),
        # Unknown endpoints usually sit inside some IP list; excluding
        # workloads that match one would hide exactly the flows wanted.
        exclude_workloads_from_ip_list_query=False,
        max_results=max_results, query_name=name,
    )
    return fetch_flows_raw(pce, query, name)


def handle_find_unknown_endpoints(ctx, arguments: dict) -> list:
    """Endpoints in traffic that are neither managed nor unmanaged workloads."""
    logger.debug("FIND UNKNOWN ENDPOINTS CALLED: %s", ScrubbedArgs(arguments))
    arguments = dict(arguments or {})
    try:
        direction = str(arguments.get("direction") or "both")
        if direction not in _DIRECTIONS:
            return _text({"error": f"direction must be one of {', '.join(_DIRECTIONS)}, got {direction!r}"})
        directions = _DIRECTIONS[direction]
        min_connections = int(arguments.get("min_connections", 1))
        top_n = int(arguments.get("top_n", 50))
        include_noise = bool(arguments.get("include_noise", False))
        target = arguments.get("ip")
        target_addr = _addr(target) if target else None
        if target and target_addr is None:
            return _text({"error": f"ip {target!r} is not an IP address"})
        target = str(target_addr) if target_addr else None

        lookback = int(arguments.get("lookback_days", 7))
        start = to_query_start(arguments.get("start_date") or
                               (datetime.now() - timedelta(days=lookback)).strftime("%Y-%m-%d"))
        end = to_query_end(arguments.get("end_date") or datetime.now().strftime("%Y-%m-%d"))
        check_window(start, end)
        max_results = min(int(arguments.get("max_results", MCP_QUERY_MAX_RESULTS)),
                          MCP_QUERY_MAX_RESULTS)

        pce = ctx.pce
        inventory = load_inventory(pce, int(arguments.get("max_workloads", DEFAULT_WORKLOADS)))
        ip_lists, lists_truncated = load_ip_lists(pce, int(arguments.get("max_ip_lists", DEFAULT_IP_LISTS)))
        default_lists = sorted(l["name"] for l in ip_lists if l["default"] and l["name"])

        if target and target in inventory["known"]:
            w = inventory["known"][target]
            return _text({
                "window": {"start": start, "end": end},
                "ip": target, "known": True,
                "workload": {k: w[k] for k in ("href", "hostname", "managed", "enforcement_mode", "app", "env")},
                "message": (f"{target} is an interface address of workload "
                            f"{w['hostname'] or w['href']} ({'managed' if w['managed'] else 'unmanaged'}); "
                            f"it is not unknown. No Explorer query was run."),
                "totals": {"inventory_workloads": inventory["count"],
                           "inventory_truncated": inventory["truncated"]},
            })

        # One Explorer pull. With `ip`, filter server-side so the profile is
        # built from that address's flows rather than from whatever slice of
        # the estate fits under the cap; `both` needs one pull per side since
        # include_sources and include_destinations are ANDed.
        pulls = []
        if target:
            ip_filter = [{"ip_address": target}]
            if "as_source" in directions:
                pulls.append(_pull(pce, start, end, arguments, max_results, sources=ip_filter))
            if "as_destination" in directions:
                pulls.append(_pull(pce, start, end, arguments, max_results, destinations=ip_filter))
        else:
            pulls.append(_pull(pce, start, end, arguments, max_results))
        raw = [flow for pull in pulls for flow in pull]
        queries = len(pulls)
        flows_truncated = any(len(pull) >= max_results for pull in pulls)

        df = raw_flows_to_dataframe(pce, raw)
        endpoints, counts = aggregate_endpoints(df, inventory)
        if target:
            endpoints = {ip: ep for ip, ep in endpoints.items() if ip == target}

        active = [ep for ep in endpoints.values()
                  if sum(ep[d]["connections"] for d in directions) >= max(min_connections, 1)
                  or (target and any(ep[d]["flows"] for d in directions))]
        noise = [ep for ep in active
                 if address_class(ep["ip"], inventory["managed_prefixes"]) in NOISE_CLASSES]
        noise_ips = {ep["ip"] for ep in noise}
        unknown = [ep for ep in active if ep["ip"] not in noise_ips]
        medians = _direction_medians(unknown, directions)

        rendered = [render_endpoint(ep, directions, inventory, ip_lists, medians, full_pairs=bool(target))
                    for ep in unknown]
        rendered.sort(key=lambda e: (-e["connections"], e["ip"]))
        noise_rendered = []
        if include_noise or target:
            noise_rendered = [render_endpoint(ep, directions, inventory, ip_lists, {}, full_pairs=bool(target))
                              for ep in noise]
            noise_rendered.sort(key=lambda e: (-e["connections"], e["ip"]))

        payload = {
            "window": {"start": start, "end": end},
            "direction": direction,
            "totals": {
                "unknown_endpoints": len(rendered),
                "returned": min(len(rendered), top_n),
                "unknown_connections": sum(e["connections"] for e in rendered),
                "noise_endpoints": len(noise),
                "noise_connections": sum(sum(ep[d]["connections"] for d in directions) for ep in noise),
                "unlabelled_workloads_seen": counts["unlabelled_workloads_seen"],
                "known_by_inventory_only": counts["known_by_inventory_only"],
                "rows_between_unknowns": counts["rows_between_unknowns"],
                "pce_flows": len(raw),
                "pce_queries": queries,
                "flows_truncated": flows_truncated,
                "inventory_workloads": inventory["count"],
                "inventory_truncated": inventory["truncated"],
                "ip_lists": len(ip_lists),
                "ip_lists_truncated": lists_truncated,
                "default_ip_lists": default_lists,
            },
            "profiles": {
                "scanner": f">= {SCANNER_MIN_PAIRS} peer x port pairs, median <= {SCANNER_MAX_MEDIAN} connections per pair, >= {int(SCANNER_BLOCKED_SHARE * 100)}% blocked or potentially_blocked",
                "fan_in_server": f">= {FAN_IN_MIN_APPS} peer apps on <= {FAN_IN_MAX_PORTS} ports",
                "admin_reach": "source reaching an admin port on a workload",
                "high_volume": f">= {HIGH_VOLUME_MULTIPLE}x the median connections over unknown endpoints in that direction (needs >= {HIGH_VOLUME_MIN_ENDPOINTS})",
                "single_peer": "exactly one peer workload",
            },
            "endpoints": rendered[:top_n],
        }
        if include_noise:
            payload["noise"] = noise_rendered[:top_n]
        if target:
            payload["ip"] = target
            hit = (rendered or noise_rendered)
            payload["endpoints"] = hit[:1]
            if hit:
                mask = (df["src_ip"] == target) | (df["dst_ip"] == target) if not df.empty else None
                payload["timeline"] = endpoint_timeline(df[mask] if mask is not None else df, start, end)
            else:
                payload["message"] = (f"No flows with {target} on an unknown side in the window. "
                                      f"Either it did not talk, or Explorer attached a workload to it.")
        payload["coverage_note"] = _coverage_note(payload["totals"], max_results)
        payload["note"] = (
            "Unknown = no workload attached by Explorer AND not an interface address of any "
            "inventoried workload. IP-list membership does not make an endpoint known; the "
            "default 0.0.0.0/0 list is never coverage. Noise (link-local, multicast, broadcast, "
            "loopback) is counted but listed only with include_noise.")
        return _text(payload)

    except Exception as e:
        error_msg = f"Failed to find unknown endpoints: {describe_error(e)}"
        logger.error(error_msg, exc_info=True)
        return _text({"error": error_msg})


def _coverage_note(totals: dict, max_results: int) -> str:
    parts = []
    if totals["flows_truncated"]:
        parts.append(f"Hit the {max_results}-flow cap, so endpoints and counts are lower bounds; "
                     f"narrow the window or raise min_connections.")
    if totals["inventory_truncated"]:
        parts.append(f"Inventory truncated at {totals['inventory_workloads']} workloads, so an "
                     f"endpoint listed here may be a workload in the unseen part (possibly known).")
    if totals["ip_lists_truncated"]:
        parts.append(f"IP lists truncated at {totals['ip_lists']}; ip_lists coverage may be incomplete.")
    if totals["rows_between_unknowns"]:
        parts.append(f"{totals['rows_between_unknowns']} flow row(s) had no workload on either side "
                     f"and were not profiled.")
    if not parts:
        return (f"Complete: {totals['pce_flows']} flows under the {max_results} cap, "
                f"inventory of {totals['inventory_workloads']} workloads and "
                f"{totals['ip_lists']} IP lists read in full.")
    return " ".join(parts)


def _text(payload: dict) -> list:
    return [types.TextContent(type="text", text=json.dumps(payload, default=str))]
