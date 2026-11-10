"""Traffic fingerprints: a snapshot of who talks to whom on which service,
and the drift between two of them.

A fingerprint is the set of (source identity, destination identity, service)
keys seen in one window for one scope (the org, an environment or an app),
each with the set of policy decisions it was seen with, plus per-app shape
metrics derived from those keys (peers in and out, external destinations,
services, blocked share). Identities are apps (`shop (prod)`) or, off the
estate, the most stable name available: an FQDN, else the provider an
address attributes to, else an IP-list name, hostname or address.

The rules come from illumio-tui's traffic compare (#77-80) and snapshot
compare (#85), which this format is meant to stay compatible with:

- Keys are matched on identity, never on counts. Explorer returns lifetime
  counters on records that overlap the window, so a count says nothing about
  what happened inside it.
- `first_detected` is not part of a key: a long-lived flow comes back as a
  fresh record every day and would read as "new" forever.
- A truncated side is recorded and named: it inflates "new" (a baseline cut
  short) or "gone" (a recent window cut short).
- A compare across PCEs, orgs, scopes or identity labels is refused, not
  fudged. A compare across unequal window lengths is allowed and warned.

Pure: pandas in, dicts out. The tool in `tools/fingerprint.py` runs the
queries. The file format is versioned (`fingerprint_version`) so a baseline
a client kept from an earlier release is recognised or refused by number.
"""
from __future__ import annotations

import collections
import datetime
import logging

logger = logging.getLogger("illumio_mcp.fingerprint")

FINGERPRINT_VERSION = 1

NA = "-"
DEFAULT_IDENTITY_LABELS = ("app", "env")
KEY_COLUMNS = ["src", "dst", "service", "decisions"]
CHANGED_COLUMNS = ["src", "dst", "service", "was", "now"]

# One letter per decision, in a fixed order, so a key's decision set is a
# short string that sorts and compares: "AP" is allowed + potentially blocked.
_DECISION_CODES = {"allowed": "A", "potentially_blocked": "P", "blocked": "B"}
_DECISION_ORDER = "APBU"
_BLOCKING = {"P", "B"}

_PROTO_NAMES = {1: "icmp", 6: "tcp", 17: "udp", 58: "icmpv6"}


def classify_destination(ip):
    """Provider attribution for an address, resolved at call time.

    The attribution table lives in `tools.traffic`, which imports this
    package's tool modules; importing it here at load time would make the
    import order matter. Tests replace this name to pin an attribution.
    """
    from .tools.traffic import classify_destination as attribute
    return attribute(ip)


def _present(value) -> bool:
    if value is None or value == NA or value == "":
        return False
    return not (isinstance(value, float) and value != value)


def _label_values(row, prefix: str, identity_labels) -> dict:
    return {key: str(row.get(f"{prefix}_{key}")) for key in identity_labels
            if _present(row.get(f"{prefix}_{key}"))}


def _identity(row, prefix: str, identity_labels) -> tuple[str, str, str | None]:
    """One side of a flow -> (name, kind, provider).

    kind is `app` (the identity labels are set), `external` (no workload, or
    an address the PCE does not manage) or `unlabelled` (a managed workload
    without the identity labels). Off the estate the name is chosen for
    stability across windows: an FQDN, then the provider a published range
    attributes the address to, then an IP-list name, hostname or address.
    An IP-list name is context, not identity -- ranked first it folded every
    external destination into one bucket called "internet".
    """
    parts = []
    for key in identity_labels:
        value = row.get(f"{prefix}_{key}")
        if _present(value):
            parts.append(str(value))
    if parts:
        name = f"{parts[0]} ({', '.join(parts[1:])})" if len(parts) > 1 else parts[0]
        return name, "app", None
    fqdn = row.get(f"{prefix}_fqdn")
    if _present(fqdn):
        return str(fqdn), "external", None
    ip = row.get(f"{prefix}_ip")
    hostname = row.get(f"{prefix}_hostname")
    if _present(hostname):
        # A managed workload the identity labels do not cover: its own
        # identity, so two legacy hosts are two peers, not one "unlabelled".
        return f"unlabelled:{hostname}", "unlabelled", None
    if _present(ip):
        provider, _confidence = classify_destination(str(ip))
        if provider:
            return str(provider), "external", str(provider)
    ip_list = row.get(f"{prefix}_ip_lists")
    if _present(ip):
        return str(ip), "external", None
    if _present(ip_list):
        return str(ip_list), "external", None
    return "unknown", "external", None


def _service(row) -> str:
    proto = row.get("proto")
    port = row.get("port")
    try:
        proto_i = int(proto)
        proto_s = _PROTO_NAMES.get(proto_i, str(proto_i))
    except (TypeError, ValueError):
        proto_s = str(proto) if _present(proto) else "?"
    try:
        port_s = str(int(port))
    except (TypeError, ValueError):
        port_s = "*"
    return f"{proto_s}/{port_s}"


def _decision_code(value) -> str:
    return _DECISION_CODES.get(str(value), "U") if _present(value) else "U"


def _codes(codes: set) -> str:
    return "".join(c for c in _DECISION_ORDER if c in codes)


def _window_days(window: dict) -> float | None:
    try:
        start = _parse(window["start"])
        end = _parse(window["end"])
    except (KeyError, TypeError, ValueError):
        return None
    return round((end - start).total_seconds() / 86400, 1)


def _parse(value) -> datetime.datetime:
    text = str(value).strip()
    if text.isdigit():
        return datetime.datetime.fromtimestamp(int(text), datetime.timezone.utc)
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    parsed = datetime.datetime.fromisoformat(text)
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=datetime.timezone.utc)


def _now() -> str:
    return datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


# ---------------------------------------------------------------------------
# build
# ---------------------------------------------------------------------------

def build_fingerprint(df, *, pce: dict, scope: dict, window: dict, coverage: dict,
                      identity_labels=DEFAULT_IDENTITY_LABELS, filters: dict | None = None) -> dict:
    """The fingerprint of `df` (a `raw_flows_to_dataframe` frame).

    `pce` is {host, org_id}; `scope` is {kind: org|env|app, app?, env?};
    `window` is {start, end}; `coverage` is what the fetch reported
    (pce_flows, truncated, truncated_at, raw_observations, note). `filters`
    are any extra query filters, recorded so a compare can see they match.
    """
    identity_labels = tuple(identity_labels)
    keys: dict[tuple, set] = collections.defaultdict(set)
    records: dict[tuple, int] = collections.Counter()
    kinds: dict[str, str] = {}
    providers: dict[str, str] = {}
    values: dict[str, dict] = {}

    rows = df.to_dict("records") if len(df) else []
    for row in rows:
        src, src_kind, src_provider = _identity(row, "src", identity_labels)
        dst, dst_kind, dst_provider = _identity(row, "dst", identity_labels)
        kinds[src], kinds[dst] = src_kind, dst_kind
        if src_kind == "app":
            values.setdefault(src, _label_values(row, "src", identity_labels))
        if dst_kind == "app":
            values.setdefault(dst, _label_values(row, "dst", identity_labels))
        if src_provider:
            providers[src] = src_provider
        if dst_provider:
            providers[dst] = dst_provider
        key = (src, dst, _service(row))
        keys[key].add(_decision_code(row.get("policy_decision")))
        records[key] += 1

    apps = _app_metrics(keys, records, kinds, providers)
    # In an env or app scope the query only returned flows touching the
    # scope, so a remote app's metrics describe its side of that traffic,
    # not the app. Say which is which.
    wanted = {k: str(scope[k]) for k in ("app", "env") if scope.get(k)}
    for name, metrics in apps.items():
        metrics["in_scope"] = all(values.get(name, {}).get(k) == v for k, v in wanted.items())
    total_records = sum(records.values())
    blocking_records = sum(n for k, n in records.items() if keys[k] & _BLOCKING)
    external_dsts = {dst for (_s, dst, _v) in keys if kinds.get(dst) == "external"}
    external_srcs = {src for (src, _d, _v) in keys if kinds.get(src) == "external"}

    return {
        "fingerprint_version": FINGERPRINT_VERSION,
        "generated_at": _now(),
        "pce": {"host": pce.get("host"), "org_id": pce.get("org_id")},
        "scope": {"kind": scope.get("kind", "org"), "app": scope.get("app"),
                  "env": scope.get("env"), "identity_labels": list(identity_labels)},
        "basis": {"window": {"start": window.get("start"), "end": window.get("end")},
                  "window_days": _window_days(window),
                  "filters": dict(filters or {})},
        "coverage": dict(coverage),
        "totals": {"keys": len(keys), "apps": len(apps),
                   "apps_in_scope": sum(1 for a in apps.values() if a["in_scope"]),
                   "external_destinations": len(external_dsts),
                   "external_sources": len(external_srcs),
                   "blocked_share": _share(blocking_records, total_records)},
        "apps": apps,
        "key_columns": list(KEY_COLUMNS),
        "keys": [[s, d, v, _codes(keys[(s, d, v)])] for (s, d, v) in sorted(keys)],
        "keys_omitted": False,
    }


def _share(part: int, whole: int) -> float:
    return round(part / whole, 4) if whole else 0.0


def _app_metrics(keys, records, kinds, providers) -> dict:
    """Per-app shape, from the keys alone."""
    apps = {name for name, kind in kinds.items() if kind == "app"}
    out = {}
    for app in sorted(apps):
        peers_in, peers_out, services, ext_dst, ext_src, provs = set(), set(), set(), set(), set(), set()
        n_records = n_blocking = n_keys = 0
        for (src, dst, service), decisions in keys.items():
            if app not in (src, dst):
                continue
            n_keys += 1
            n_records += records[(src, dst, service)]
            if decisions & _BLOCKING:
                n_blocking += records[(src, dst, service)]
            services.add(service)
            if src == app and dst != app:
                peers_out.add(dst)
                if kinds.get(dst) == "external":
                    ext_dst.add(dst)
                if dst in providers:
                    provs.add(providers[dst])
            if dst == app and src != app:
                peers_in.add(src)
                if kinds.get(src) == "external":
                    ext_src.add(src)
                if src in providers:
                    provs.add(providers[src])
        out[app] = {
            "keys": n_keys,
            "peers_in": len(peers_in),
            "peers_out": len(peers_out),
            "external_destinations": len(ext_dst),
            "external_sources": len(ext_src),
            "services": len(services),
            "records": n_records,
            "blocked_share": _share(n_blocking, n_records),
            "providers": sorted(provs),
        }
    return out


# ---------------------------------------------------------------------------
# compare
# ---------------------------------------------------------------------------

def check_basis(current: dict, baseline) -> tuple[list[str], list[str]]:
    """(problems, warnings): problems refuse the compare, warnings qualify it."""
    problems: list[str] = []
    warnings: list[str] = []
    if not isinstance(baseline, dict) or not baseline:
        return ["baseline is not a fingerprint (expected the `fingerprint` object "
                "returned by an earlier get-traffic-fingerprint call)"], warnings
    version = baseline.get("fingerprint_version")
    if version != FINGERPRINT_VERSION:
        problems.append(f"baseline fingerprint_version {version!r} is not "
                        f"{FINGERPRINT_VERSION}; this server cannot read it")
        return problems, warnings
    if baseline.get("pce") != current.get("pce"):
        problems.append(f"baseline is of another pce/org: {baseline.get('pce')} "
                        f"vs {current.get('pce')}")
    b_scope, c_scope = baseline.get("scope") or {}, current.get("scope") or {}
    for field in ("kind", "app", "env"):
        if b_scope.get(field) != c_scope.get(field):
            problems.append(f"baseline scope {field} differs: {b_scope.get(field)!r} "
                            f"vs {c_scope.get(field)!r}")
    if b_scope.get("identity_labels") != c_scope.get("identity_labels"):
        problems.append(f"baseline identity_labels differ: {b_scope.get('identity_labels')} "
                        f"vs {c_scope.get('identity_labels')}")
    if baseline.get("keys_omitted") or not isinstance(baseline.get("keys"), list):
        problems.append("baseline carries no keys (it was too large to return "
                        "whole); use baseline_days for an in-call compare or a "
                        "narrower scope")
    b_filters = (baseline.get("basis") or {}).get("filters") or {}
    c_filters = (current.get("basis") or {}).get("filters") or {}
    if b_filters != c_filters:
        problems.append(f"baseline query filters differ: {b_filters} vs {c_filters}")
    if problems:
        return problems, warnings

    b_days = (baseline.get("basis") or {}).get("window_days")
    c_days = (current.get("basis") or {}).get("window_days")
    if b_days and c_days and abs(b_days - c_days) > 0.1 * max(b_days, c_days):
        longer = "baseline" if b_days > c_days else "recent"
        inflated = "gone" if longer == "baseline" else "new"
        warnings.append(f"window lengths differ: recent {c_days:g} days vs baseline "
                        f"{b_days:g} days; the longer ({longer}) side sees more keys, "
                        f"so `{inflated}` over-reports")
    if (baseline.get("coverage") or {}).get("truncated"):
        warnings.append("the baseline was truncated at its row cap, so keys it missed "
                        "read as `new` now; treat `new` as an upper bound")
    if (current.get("coverage") or {}).get("truncated"):
        warnings.append("the recent window was truncated at its row cap, so keys it "
                        "missed read as `gone`; treat `gone` as an upper bound")
    return problems, warnings


def compare_fingerprints(current: dict, baseline, *, max_list: int = 200) -> dict:
    """`current` against `baseline`: new, changed, gone and same keys, the
    drift per app, and what came and went.

    drift = (new + changed + gone) / baseline keys, so 0 is "nothing moved"
    and 1 means as many differences as the baseline had keys. Per app the
    denominator is the app's own baseline keys (1 for an app the baseline
    did not have, so an app that appeared scores its new keys).
    """
    problems, warnings = check_basis(current, baseline)
    out = {
        "basis": {"comparable": not problems, "problems": problems, "warnings": warnings},
    }
    if problems:
        return out
    out["baseline"] = {
        "generated_at": baseline.get("generated_at"),
        "window": (baseline.get("basis") or {}).get("window"),
        "window_days": (baseline.get("basis") or {}).get("window_days"),
        "coverage": baseline.get("coverage"),
    }

    now = {tuple(k[:3]): k[3] for k in current.get("keys") or []}
    then = {tuple(k[:3]): k[3] for k in baseline["keys"]}
    new = sorted(k for k in now if k not in then)
    gone = sorted(k for k in then if k not in now)
    changed = sorted(k for k in now if k in then and now[k] != then[k])
    same = len(now) - len(new) - len(changed)

    out["counts"] = {"new": len(new), "changed": len(changed), "gone": len(gone), "same": same}
    out["drift"] = round((len(new) + len(changed) + len(gone)) / max(len(then), 1), 4)
    out["new"] = [[*k, now[k]] for k in new[:max_list]]
    out["changed_columns"] = list(CHANGED_COLUMNS)
    out["changed"] = [[*k, then[k], now[k]] for k in changed[:max_list]]
    out["gone"] = [[*k, then[k]] for k in gone[:max_list]]
    out["lists_capped_at"] = max_list
    out["by_app"] = _app_drift(current, baseline, now, then, new, changed, gone)

    b_providers = {p for a in (baseline.get("apps") or {}).values() for p in a.get("providers", [])}
    c_providers = {p for a in (current.get("apps") or {}).values() for p in a.get("providers", [])}
    out["new_providers"] = sorted(c_providers - b_providers)
    out["gone_providers"] = sorted(b_providers - c_providers)
    return out


def _app_drift(current, baseline, now, then, new, changed, gone) -> dict:
    c_apps = current.get("apps") or {}
    b_apps = baseline.get("apps") or {}
    external_now = _external_names(current)
    out = {}
    for app in sorted(set(c_apps) | set(b_apps)):
        def mine(keys):
            return [k for k in keys if app in (k[0], k[1])]
        a_new, a_changed, a_gone = mine(new), mine(changed), mine(gone)
        peers_then = {_peer(k, app) for k in then if app in (k[0], k[1])} - {app}
        peers_now = {_peer(k, app) for k in now if app in (k[0], k[1])} - {app}
        new_peers = sorted(peers_now - peers_then)
        base_keys = b_apps.get(app, {}).get("keys", 0)
        out[app] = {
            "new": len(a_new), "changed": len(a_changed), "gone": len(a_gone),
            "drift": round((len(a_new) + len(a_changed) + len(a_gone)) / max(base_keys, 1), 4),
            "new_peers": new_peers,
            "gone_peers": sorted(peers_then - peers_now),
            "new_external": [p for p in new_peers if p in external_now],
            "in_baseline": app in b_apps,
            "in_recent": app in c_apps,
        }
    return out


def _peer(key, app):
    src, dst, _service = key
    return dst if src == app else src


def _external_names(print_: dict) -> set:
    """The external identities a fingerprint's keys name: anything that is
    not one of its apps and not an unlabelled workload."""
    apps = set(print_.get("apps") or {})
    names = set()
    for k in print_.get("keys") or []:
        for name in k[:2]:
            if name not in apps and not str(name).startswith("unlabelled:"):
                names.add(name)
    return names
