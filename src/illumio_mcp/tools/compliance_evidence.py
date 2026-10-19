"""collect-compliance-evidence: per-test segmentation evidence for a label-pair
scope, read from ACTIVE policy and observed traffic. Issue #54.

`compliance-check` is a first look: keyword-routed heuristics on draft policy
that end in a percentage. An auditor cannot use a percentage. What they need,
per requirement, is the rule applied, the measured values and the rows the
verdict rests on. This tool runs the tests the illumio-compliance-evidence
skill defines (its references/tests.md, T1 to T14) server-side, once per
app/env pair, and returns PASS / FAIL / EXCEPTION / NOT_TESTED with evidence.
The mapping of tests to PCI, DORA or NIS2 requirement ids stays in the skill's
matrices and the illumio://compliance/* resources; the tests are framework
independent.

Rules that keep the verdicts honest:

- A capped pull (the Explorer returned exactly `max_results` rows, or the
  workload list hit its ceiling) never yields PASS. A violation visible in a
  capped result is FAIL; a clean capped result is EXCEPTION "capped".
- An unknown scope label is an error, not a silently wider query.
- Nothing here writes. No ringfence, no isolation, no provisioning.
"""
from __future__ import annotations

import ipaddress
import json
import logging
import re
from datetime import datetime, timedelta, timezone

import pandas as pd
import mcp.types as types
from illumio import TrafficQuery

from ..label_refs import encode_label_filter, unresolved_label_error
from ..log_scrub import ScrubbedArgs
from ..errors import describe_error
from .constants import MCP_BUG_MAX_RESULTS, MCP_QUERY_MAX_RESULTS
from .rulesets import POLICY_VERSIONS, _PolicyNames, _render_rule, _render_scope_entry, _rule_names_all, _PROTO_NAMES
from .traffic import (
    NA, fetch_flows_raw, raw_flows_to_dataframe, to_query_start, to_query_end,
    check_window, _bucket_series, _spikes, _effective_bucket, TIMELINE_BUCKETS,
)
from .workloads import _ven_fields

logger = logging.getLogger('illumio_mcp')


# Worst-of order. A row of several clauses, a test of several pairs and the
# pack as a whole all take the first of these that any part reached.
RESULT_ORDER = ("FAIL", "EXCEPTION", "NOT_TESTED", "PASS")

# Ports a reviewer must see even when they are approved: cleartext protocols.
CLEARTEXT_PORTS = {21, 23, 69, 80, 110, 143, 389}

HEARTBEAT_MAX_AGE = timedelta(hours=24)
HEALTHY_SYNC_STATES = {"synced", "applied"}

# Event types that evidence a policy or enforcement change (T11 / T14).
POLICY_EVENT_RE = re.compile(r"provision|sec_policy|rule|enforcement", re.IGNORECASE)

# Every test the catalogue defines, with the rule in words. The three that
# are not run here say why in `not_run`.
TESTS = {
    "T1":  ("Scope inventory", "pair",
            "every pair has at least one workload carrying both labels"),
    "T2":  ("Enforcement", "pair",
            "enforcement_mode equals full for 100% of managed workloads; a selective "
            "row needs a justification the caller supplies to become EXCEPTION"),
    "T3":  ("VEN health", "pair",
            "every managed workload has ven_status active, a heartbeat within 24h of "
            "collection, policy_sync_state synced or applied and no health errors"),
    "T4":  ("Unmanaged workloads in scope", "pair",
            "zero unmanaged workloads carry the scope labels; each one listed needs a "
            "justification the caller supplies to become EXCEPTION"),
    "T5":  ("Providing rules are described", "pair",
            "every enabled allow rule that provides into the pair has a non-empty "
            "description"),
    "T6":  ("No broad consumer into the scope", "pair",
            "no providing rule admits all workloads estate-wide (unscoped_consumers "
            "or an unscoped ruleset) or an IP list covering 0.0.0.0/0 or ::/0"),
    "T7":  ("Admitted services versus the approved list", "pair",
            "no all-services rule into the pair; every service object expands to "
            "ports; every admitted port/proto is approved for direction in"),
    "T8":  ("Inbound boundary flows", "pair",
            "every allowed crossing into the pair is approved for direction in and "
            "comes from a workload or a named IP list a rule uses; zero potentially "
            "blocked flows into the pair"),
    "T9":  ("Outbound boundary flows", "pair",
            "every allowed crossing out of the pair is approved for direction out; "
            "public destinations are inside a named IP list a rule uses"),
    "T11": ("Change control", "scope-wide",
            "no pending draft change touches a ruleset the pair's policy comes from"),
    "T14": ("Logging", "scope-wide",
            "the PCE holds at least one event and at least one flow for the pair "
            "inside the window"),
}
RUNNABLE = tuple(TESTS)

NOT_RUN = {
    "T10": "needs the unknown-endpoint scan (illumio-unknown-endpoints skill) over the T1 addresses",
    "T12": "isolation drill is an attestation; the capability is visible in T5's deny rules",
    "T13": "review cadence is an attestation; T11's event rows are the supporting evidence",
}

# Tests that cannot be computed without the data an earlier step collects.
NEEDS_INVENTORY = {"T1", "T2", "T3", "T4"}
NEEDS_POLICY = {"T5", "T6", "T7", "T8", "T9", "T11"}
NEEDS_INBOUND = {"T8", "T14"}
NEEDS_OUTBOUND = {"T9"}


def worst(results) -> str:
    """The worst result in RESULT_ORDER; PASS for an empty set."""
    found = set(results)
    for r in RESULT_ORDER:
        if r in found:
            return r
    return "PASS"


def _proto_name(value) -> str:
    if value is None:
        return NA
    if isinstance(value, str):
        text = value.strip().lower()
        return text or NA
    return str(_PROTO_NAMES.get(int(value), value))


def _strip_version(href: str | None) -> str:
    """/orgs/1/sec_policy/active/rule_sets/5 and .../draft/... are one object."""
    return re.sub(r"/sec_policy/(active|draft)/", "/sec_policy/", href or "")


def _is_public(ip) -> bool:
    try:
        return ipaddress.ip_address(str(ip)).is_global
    except ValueError:
        return False


def _covers_everything(text: str) -> bool:
    return "0.0.0.0/0" in text or "::/0" in text


def _range_is_default(ip_range) -> bool:
    """An IP list range that spans the whole address space."""
    get = (lambda k: ip_range.get(k)) if isinstance(ip_range, dict) else (lambda k: getattr(ip_range, k, None))
    from_ip, to_ip = str(get("from_ip") or ""), str(get("to_ip") or "")
    if get("exclusion"):
        return False
    if _covers_everything(from_ip):
        return True
    if from_ip in ("0.0.0.0", "::") and to_ip in ("255.255.255.255", "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff"):
        return True
    return False


def _actor_text(actors) -> str:
    parts = []
    for a in actors or []:
        if a.get("all_workloads"):
            parts.append("all_workloads")
        elif a.get("label"):
            parts.append(f"{a['label'].get('key')}={a['label'].get('value')}")
        else:
            kind = next(iter(a), "?")
            name = (a.get(kind) or {}).get("name") if isinstance(a.get(kind), dict) else None
            parts.append(f"{kind}:{name or (a.get(kind) or {}).get('href', '?')}")
    return ", ".join(parts) or "-"


def _parse_ts(value):
    if not value:
        return None
    text = str(value).strip().replace("Z", "+00:00")
    try:
        ts = datetime.fromisoformat(text)
    except ValueError:
        return None
    return ts if ts.tzinfo else ts.replace(tzinfo=timezone.utc)


def _actor_from_created_by(created_by) -> str | None:
    """`created_by` is a dict on the SDK object and dict-text in get-events;
    the username is what an auditor wants."""
    if created_by is None:
        return None
    if isinstance(created_by, dict):
        for k in ("user", "agent", "system", "api_key"):
            inner = created_by.get(k)
            if isinstance(inner, dict):
                return inner.get("username") or inner.get("hostname") or inner.get("name") or inner.get("href")
        return created_by.get("username") or json.dumps(created_by, default=str)
    text = str(created_by)
    m = re.search(r"'(?:username|hostname|name)':\s*'([^']*)'", text)
    return m.group(1) if m else text


class _Pair:
    def __init__(self, app, env, app_href, env_href):
        self.app, self.env = app, env
        self.app_href, self.env_href = app_href, env_href
        self.key = f"{app}/{env}"
        self.hrefs = [app_href, env_href]
        self.workloads: list[dict] = []
        self.inventory_capped = False
        self.rulesets: list[dict] = []          # rendered, scoped or naming the pair
        self.providing: list[tuple[dict, dict]] = []   # (ruleset, rule)
        self.ip_list_names: set[str] = set()   # named IP lists any of the pair's rules use
        self.inbound_pce_flows = 0

    @property
    def empty(self) -> bool:
        return not self.workloads


class _Collector:
    def __init__(self, pce, pversion: str, max_results: int, max_rows: int):
        self.pce, self.pversion = pce, pversion
        self.max_results, self.max_rows = max_results, max_rows
        self.queries = 0
        self.label_map: dict[str, dict] = {}
        self._rulesets = None
        self._deny: dict[str, list] = {}
        self._ip_lists = None
        self._services = None
        self._names = None

    # ---- PCE reads, every one counted ------------------------------------

    def labels(self) -> dict:
        self.queries += 1
        self.label_map = {l.href: {"key": l.key, "value": l.value}
                          for l in self.pce.labels.get(params={"max_results": 10000})}
        return self.label_map

    def workloads(self, pair: _Pair) -> tuple[list, dict]:
        self.queries += 1
        params = {"include": "labels", "max_results": 10000,
                  "labels": encode_label_filter(pair.hrefs)}
        wl = self.pce.workloads.get(params=params)
        rows = []
        for w in wl:
            rows.append({
                "href": w.href, "name": w.name, "hostname": w.hostname,
                "ip_addresses": ", ".join(i.address for i in (w.interfaces or [])
                                          if getattr(i, "address", None)) or None,
                "managed": bool(getattr(w, "agent", None) or getattr(w, "ven", None)),
                "enforcement_mode": w.enforcement_mode,
                "visibility_level": getattr(w, "visibility_level", None),
                "online": getattr(w, "online", None),
                **_ven_fields(w),
            })
        pair.inventory_capped = len(wl) >= 10000
        evidence = {"tool": "get-workloads",
                    "arguments": {"labels": [f"app={pair.app}", f"env={pair.env}"],
                                  "detail_level": "compact", "max_results": 10000},
                    "returned": len(rows), "capped": pair.inventory_capped}
        return rows, evidence

    def names(self) -> _PolicyNames:
        """href -> name for the objects rules reference. Seeded from the pulls
        this tool makes anyway (labels, IP lists, services), so rendering a
        rule never costs a second read of the same list."""
        if self._names is None:
            self._names = _PolicyNames(self.pce, self.pversion)
            self._names._cache["label"] = self.label_map
            self._names._cache["ip_list"] = {h: v["name"] for h, v in self.ip_lists().items()}
            self._names._cache["service"] = {h: v["name"] for h, v in self.services().items()}
        return self._names

    def rulesets(self) -> list[dict]:
        """Every ruleset of the policy version, once, as raw dicts."""
        if self._rulesets is None:
            self.queries += 1
            raw = self.pce.rule_sets.get_all(policy_version=self.pversion)
            self._rulesets = [r.to_json() if hasattr(r, "to_json") else dict(r) for r in raw]
        return self._rulesets

    def deny_rules(self, href: str) -> list:
        if href not in self._deny:
            self.queries += 1
            try:
                self._deny[href] = self.pce.get(f"{href}/deny_rules").json() or []
            except Exception as e:
                logger.debug("Could not fetch deny_rules for %s: %s", href, e)
                self._deny[href] = []
        return self._deny[href]

    def ip_lists(self) -> dict:
        """href -> {name, default: bool} for the policy version the rules come
        from (get-iplists reads draft only; here the ranges match the rules)."""
        if self._ip_lists is None:
            self.queries += 1
            out = {}
            for ipl in self.pce.ip_lists.get(policy_version=self.pversion, params={"max_results": 10000}):
                ranges = getattr(ipl, "ip_ranges", None) or []
                out[ipl.href] = {
                    "name": ipl.name,
                    "default": _covers_everything(str(ipl.name or "")) or any(_range_is_default(r) for r in ranges),
                }
            self._ip_lists = out
        return self._ip_lists

    def services(self) -> dict:
        """href -> {name, service_ports}, so service objects expand to ports."""
        if self._services is None:
            self.queries += 1
            out = {}
            try:
                for s in self.pce.services.get(policy_version=self.pversion, params={"max_results": 10000}):
                    d = s.to_json() if hasattr(s, "to_json") else dict(s)
                    out[d.get("href")] = {
                        "name": d.get("name"),
                        "service_ports": d.get("service_ports") or [],
                        "windows_services": d.get("windows_services") or [],
                    }
            except Exception as e:
                logger.warning("Could not fetch services to expand service objects: %s", e)
            self._services = out
        return self._services

    def flows(self, name: str, *, include_sources=None, include_destinations=None,
              policy_decisions, start: str, end: str) -> tuple[pd.DataFrame, dict]:
        self.queries += 1
        query = TrafficQuery.build(
            start_date=start, end_date=end,
            include_sources=[include_sources] if include_sources else [[]],
            include_destinations=[include_destinations] if include_destinations else [[]],
            policy_decisions=list(policy_decisions),
            max_results=self.max_results, query_name=name)
        raw = fetch_flows_raw(self.pce, query, name)
        df = raw_flows_to_dataframe(self.pce, raw, label_map=self.label_map)
        evidence = {"tool": "get-traffic-flows", "query_name": name,
                    "arguments": {"start_date": start, "end_date": end,
                                  "policy_decisions": list(policy_decisions),
                                  "max_results": self.max_results},
                    "returned": len(raw), "capped": len(raw) >= self.max_results}
        return df, evidence

    def pending(self) -> list:
        self.queries += 1
        body = self.pce.get("/sec_policy/pending").json()
        items = []
        if isinstance(body, list):
            items = [i for i in body if isinstance(i, dict)]
        elif isinstance(body, dict):
            for kind, entries in body.items():
                if isinstance(entries, list):
                    items += [{"type": kind, **i} for i in entries if isinstance(i, dict)]
        return items

    def events(self, start: str, end: str) -> list[dict]:
        self.queries += 1
        evs = self.pce.events.get(params={"timestamp[gte]": start, "timestamp[lte]": end,
                                          "max_results": 500})
        rows = []
        for e in evs:
            rows.append({"timestamp": str(getattr(e, "timestamp", None)),
                         "event_type": getattr(e, "event_type", None),
                         "actor": _actor_from_created_by(getattr(e, "created_by", None)),
                         "status": getattr(e, "status", None),
                         "severity": getattr(e, "severity", None)})
        return rows


# ---------------------------------------------------------------------------
# Argument handling
# ---------------------------------------------------------------------------

def _error(payload: dict) -> list:
    return [types.TextContent(type="text", text=json.dumps(payload, indent=2, default=str))]


def _parse_scope(scope) -> list[tuple[str, str]] | str:
    if not isinstance(scope, list) or not scope:
        return "scope must be a non-empty list of {app, env} pairs"
    pairs = []
    for i, entry in enumerate(scope):
        if not isinstance(entry, dict) or not entry.get("app") or not entry.get("env"):
            return f"scope[{i}] must be an object with non-empty app and env"
        pairs.append((str(entry["app"]).strip(), str(entry["env"]).strip()))
    return pairs


def _parse_approved(items) -> list[dict] | str:
    out = []
    for i, item in enumerate(items or []):
        if not isinstance(item, dict):
            return f"approved_services[{i}] must be an object"
        try:
            port = int(item["port"])
        except (KeyError, TypeError, ValueError):
            return f"approved_services[{i}].port must be an integer"
        proto = _proto_name(item.get("proto", "tcp"))
        direction = str(item.get("direction") or "in").lower()
        if direction not in ("in", "out"):
            return f"approved_services[{i}].direction must be 'in' or 'out'"
        out.append({"port": port, "proto": proto, "direction": direction,
                    "justification": item.get("justification")})
    return out


def _window(arguments: dict) -> tuple[str, str, int] | str:
    today = datetime.now(timezone.utc).date()
    if arguments.get("start_date") or arguments.get("end_date"):
        if not (arguments.get("start_date") and arguments.get("end_date")):
            return "start_date and end_date must be given together (or use lookback_days)"
        start, end = str(arguments["start_date"])[:10], str(arguments["end_date"])[:10]
    else:
        days = int(arguments.get("lookback_days") or 30)
        if days < 1:
            return "lookback_days must be at least 1"
        end = today.isoformat()
        start = (today - timedelta(days=days)).isoformat()
    try:
        s, e = datetime.fromisoformat(start).date(), datetime.fromisoformat(end).date()
    except ValueError:
        return "start_date and end_date must be YYYY-MM-DD"
    if e < s:
        return f"end_date {end} is before start_date {start}"
    return start, end, (e - s).days


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

class _Approved:
    def __init__(self, items: list[dict] | None):
        self.given = items is not None
        self.index = {(i["port"], i["proto"], i["direction"]) for i in (items or [])}

    def ok(self, port, to_port, proto, direction) -> bool | None:
        """True/False against the list; None when no list was given."""
        if not self.given:
            return None
        try:
            lo, hi = int(port), int(to_port if to_port is not None else port)
        except (TypeError, ValueError):
            return False
        proto = _proto_name(proto)
        return all((p, proto, direction) in self.index for p in range(lo, hi + 1))


def _cap(result: str, capped: bool) -> str:
    """A clean verdict on a capped pull is EXCEPTION, never PASS."""
    return "EXCEPTION" if capped and result == "PASS" else result


def _rows(rows: list, max_rows: int) -> dict:
    out = {"rows": rows[:max_rows]}
    if len(rows) > max_rows:
        out["rows_total"] = len(rows)
        out["rows_truncated"] = True
    return out


def test_inventory(pair: _Pair, evidence: dict, max_rows: int) -> dict:
    n, managed = len(pair.workloads), sum(1 for w in pair.workloads if w["managed"])
    result = "FAIL" if n == 0 else _cap("PASS", pair.inventory_capped)
    measured = (f"{n} workloads, {managed} managed" if n else
                "no workload carries both labels; the scope labels are not in use")
    if pair.inventory_capped:
        measured += "; inventory hit the 10000-row ceiling and is partial"
    return {"result": result, "measured": measured, **_rows(pair.workloads, max_rows), "evidence": [evidence]}


def test_enforcement(pair: _Pair, evidence: dict, max_rows: int) -> dict:
    managed = [w for w in pair.workloads if w["managed"]]
    bad = [{"workload": w["name"] or w["hostname"], "href": w["href"],
            "mode": w["enforcement_mode"], "justification": None}
           for w in managed if w["enforcement_mode"] != "full"]
    full = len(managed) - len(bad)
    modes = {}
    for w in managed:
        modes[w["enforcement_mode"] or "unknown"] = modes.get(w["enforcement_mode"] or "unknown", 0) + 1
    return {"result": _cap("FAIL" if bad else "PASS", pair.inventory_capped),
            "measured": f"{full} of {len(managed)} managed workloads in full enforcement; modes {modes}",
            **_rows(bad, max_rows), "evidence": [evidence]}


def test_ven_health(pair: _Pair, evidence: dict, now: datetime, max_rows: int) -> dict:
    bad = []
    for w in pair.workloads:
        if not w["managed"]:
            continue
        name = w["name"] or w["hostname"]
        if w.get("ven_status") != "active":
            bad.append({"workload": name, "field": "ven_status", "value": w.get("ven_status")})
        hb = _parse_ts(w.get("last_heartbeat_on"))
        if hb is None or now - hb > HEARTBEAT_MAX_AGE:
            bad.append({"workload": name, "field": "last_heartbeat_on", "value": w.get("last_heartbeat_on")})
        if (w.get("policy_sync_state") or "").lower() not in HEALTHY_SYNC_STATES:
            bad.append({"workload": name, "field": "policy_sync_state", "value": w.get("policy_sync_state")})
        if w.get("health_errors"):
            bad.append({"workload": name, "field": "health_errors",
                        "value": w.get("health_error_types") or w.get("health_errors")})
    managed = sum(1 for w in pair.workloads if w["managed"])
    failing = len({b["workload"] for b in bad})
    return {"result": _cap("FAIL" if bad else "PASS", pair.inventory_capped),
            "measured": f"{managed - failing} of {managed} managed workloads healthy at {now.isoformat()}",
            **_rows(bad, max_rows), "evidence": [evidence]}


def test_unmanaged(pair: _Pair, evidence: dict, max_rows: int) -> dict:
    rows = [{"workload": w["name"] or w["hostname"], "href": w["href"],
             "ip_addresses": w["ip_addresses"], "justification": None}
            for w in pair.workloads if not w["managed"]]
    return {"result": _cap("FAIL" if rows else "PASS", pair.inventory_capped),
            "measured": f"{len(rows)} unmanaged workloads carry the scope labels",
            **_rows(rows, max_rows), "evidence": [evidence]}


def _scoped_to(rs: dict, pair: _Pair) -> bool:
    """A scope entry naming both of the pair's labels."""
    for scope in rs.get("scopes") or []:
        hrefs = {e.get("href") for e in scope if isinstance(e, dict)}
        if set(pair.hrefs) <= hrefs:
            return True
    return False


def _unscoped(rs: dict) -> bool:
    scopes = rs.get("scopes") or []
    return not scopes or all(not s for s in scopes)


def collect_policy(c: _Collector, pair: _Pair) -> dict:
    """The pair's rulesets: scoped to it, or holding a rule that names it.
    Union by href, deny rules included, providing rules picked out."""
    names = c.names()
    chosen = []
    for raw in c.rulesets():
        rules = [_render_rule(r, "allow", names) for r in raw.get("rules") or []]
        scoped = _scoped_to({"scopes": [[_render_scope_entry(a, names) for a in s]
                                        for s in raw.get("scopes") or []]}, pair)
        naming = [r for r in rules if _rule_names_all(r, pair.hrefs, "any")]
        if not scoped and not naming:
            continue
        for dr in c.deny_rules(raw["href"]):
            rules.append(_render_rule(dr, "override_deny" if dr.get("override") else "deny", names))
        rs = {"href": raw.get("href"), "name": raw.get("name"), "enabled": raw.get("enabled"),
              "description": raw.get("description"),
              "scopes": [[_render_scope_entry(a, names) for a in s] for s in raw.get("scopes") or []],
              "scoped_to_pair": scoped, "unscoped": _unscoped(raw),
              "matched_by": "scope" if scoped else "actor",
              "rules": rules}
        chosen.append(rs)
    pair.rulesets = chosen

    providing = []
    for rs in chosen:
        if rs["enabled"] is False:
            continue
        for rule in rs["rules"]:
            for actor in rule["consumers"] + rule["providers"]:
                if actor.get("ip_list") and actor["ip_list"].get("name"):
                    pair.ip_list_names.add(actor["ip_list"]["name"])
            if rule["rule_type"] != "allow" or rule.get("enabled") is False:
                continue
            provider_names_pair = _rule_names_all(rule, pair.hrefs, "provider")
            inside_scope = rs["scoped_to_pair"] and any(
                a.get("all_workloads") or a.get("label") or a.get("label_group") for a in rule["providers"])
            if provider_names_pair or inside_scope:
                providing.append((rs, rule))
    pair.providing = providing
    return {"tool": "get-rulesets",
            "arguments": {"pversion": c.pversion, "labels": [f"app={pair.app}", f"env={pair.env}"],
                          "actor_labels": [f"app={pair.app}", f"env={pair.env}"], "actor_side": "any"},
            "note": "one estate-wide pull of the policy version, filtered server-side: scope names "
                    "both labels, or a rule names both on one side; union by href",
            "rulesets": len(chosen), "providing_rules": len(providing), "capped": False}


def test_descriptions(pair: _Pair, evidence: dict, max_rows: int) -> dict:
    rows = [{"ruleset": rs["name"], "ruleset_href": rs["href"], "rule": rule["href"],
             "consumers": _actor_text(rule["consumers"]), "providers": _actor_text(rule["providers"])}
            for rs, rule in pair.providing if not (rule.get("description") or "").strip()]
    return {"result": "FAIL" if rows else "PASS",
            "measured": f"{len(pair.providing) - len(rows)} of {len(pair.providing)} providing rules described; "
                        f"{len(pair.rulesets)} rulesets in the pair's policy",
            **_rows(rows, max_rows), "evidence": [evidence]}


def test_broad_consumers(c: _Collector, pair: _Pair, evidence: dict, max_rows: int) -> dict:
    ip_lists = c.ip_lists()
    rows = []
    for rs, rule in pair.providing:
        for actor in rule["consumers"]:
            why = None
            if actor.get("all_workloads"):
                if rule.get("unscoped_consumers"):
                    why = "all workloads with unscoped_consumers: any managed workload in the estate"
                elif rs["unscoped"]:
                    why = "all workloads in an unscoped ruleset: any managed workload in the estate"
            elif actor.get("ip_list"):
                name = actor["ip_list"].get("name") or ""
                info = ip_lists.get(actor["ip_list"].get("href"))
                if _covers_everything(name) or (info and info["default"]):
                    why = f"IP list {name!r} covers 0.0.0.0/0 or ::/0 ({c.pversion} ranges)"
            if why:
                rows.append({"ruleset": rs["name"], "rule": rule["href"],
                             "consumer": _actor_text([actor]), "why": why})
    return {"result": "FAIL" if rows else "PASS",
            "measured": f"{len(rows)} broad consumers across {len(pair.providing)} providing rules",
            **_rows(rows, max_rows),
            "evidence": [evidence, {"tool": "get-iplists", "arguments": {"pversion": c.pversion},
                                    "returned": len(ip_lists), "capped": False}]}


def test_admitted_services(c: _Collector, pair: _Pair, approved: _Approved, evidence: dict,
                           max_rows: int) -> dict:
    admitted, all_services, unexpanded = [], [], []
    services = None
    for rs, rule in pair.providing:
        if not rule["ingress_services"]:
            all_services.append({"ruleset": rs["name"], "rule": rule["href"],
                                 "consumers": _actor_text(rule["consumers"])})
            continue
        for svc in rule["ingress_services"]:
            if svc.get("service"):
                services = services if services is not None else c.services()
                info = services.get(svc["service"].get("href"))
                ports = (info or {}).get("service_ports") or []
                if not ports:
                    unexpanded.append({"ruleset": rs["name"], "rule": rule["href"],
                                       "service": svc["service"].get("name"),
                                       "why": "no port entries (process-qualified or empty)"
                                              if info else "service object not found in this policy version"})
                    continue
                for p in ports:
                    admitted.append({"ruleset": rs["name"], "rule": rule["href"],
                                     "port": p.get("port"), "to_port": p.get("to_port"),
                                     "proto": _proto_name(p.get("proto")),
                                     "service": svc["service"].get("name")})
            elif svc.get("port") is not None:
                admitted.append({"ruleset": rs["name"], "rule": rule["href"], "port": svc["port"],
                                 "to_port": svc.get("to_port"), "proto": _proto_name(svc.get("proto")),
                                 "service": None})
            else:
                unexpanded.append({"ruleset": rs["name"], "rule": rule["href"],
                                   "service": json.dumps(svc, default=str), "why": "no port"})
    unapproved = 0
    for row in admitted:
        row["approved"] = approved.ok(row["port"], row["to_port"], row["proto"], "in")
        hi = row["to_port"] if row["to_port"] is not None else row["port"]
        try:
            row["cleartext"] = sorted(p for p in CLEARTEXT_PORTS if int(row["port"]) <= p <= int(hi))
        except (TypeError, ValueError):
            row["cleartext"] = []
        if row["approved"] is False:
            unapproved += 1
    clauses = {"no_all_services_rule": "FAIL" if all_services else "PASS",
               "every_service_object_expanded": "FAIL" if unexpanded else "PASS",
               "every_port_approved": ("NOT_TESTED" if not approved.given else
                                       "FAIL" if unapproved else "PASS")}
    return {"result": worst(clauses.values()), "clauses": clauses,
            "measured": f"{len(admitted)} admitted port entries, {unapproved} unapproved, "
                        f"{len(all_services)} all-services rules, {len(unexpanded)} unexpanded"
                        + ("" if approved.given else "; no approved list, admitted set is the candidate list"),
            **_rows(admitted, max_rows), "all_services_rules": all_services, "unexpanded": unexpanded,
            "evidence": [evidence]}


def _drop_intra_scope(df: pd.DataFrame, prefix: str, pairs: set) -> tuple[pd.DataFrame, int]:
    if df.empty or f"{prefix}_app" not in df.columns or f"{prefix}_env" not in df.columns:
        return df, 0
    intra = df.apply(lambda r: (r.get(f"{prefix}_app"), r.get(f"{prefix}_env")) in pairs, axis=1)
    return df[~intra], int(intra.sum())


def _grouped(df: pd.DataFrame, cols: list[str]) -> list[dict]:
    """Sum connections over the named columns, keeping rows with blanks."""
    if df.empty:
        return []
    present = [c for c in cols if c in df.columns]
    frame = df.copy()
    for col in cols:
        if col not in frame.columns:
            frame[col] = NA
    frame = frame.fillna({c: NA for c in cols})
    frame["num_connections"] = pd.to_numeric(frame.get("num_connections", 0), errors="coerce").fillna(0)
    g = frame.groupby(cols, dropna=False)["num_connections"].sum().reset_index()
    g = g.sort_values("num_connections", ascending=False)
    out = []
    for rec in g.to_dict("records"):
        rec = {k: (None if v == NA else v) for k, v in rec.items()}
        rec["connections"] = int(rec.pop("num_connections"))
        out.append(rec)
    return out


def _timeline(blocked: pd.DataFrame, pot: pd.DataFrame, start: str, end: str) -> dict:
    frames = [f for f in (blocked, pot) if not f.empty]
    df = pd.concat(frames, ignore_index=True) if frames else pd.DataFrame()
    step = TIMELINE_BUCKETS["1d"]
    s = datetime.fromisoformat(to_query_start(start).replace("Z", "+00:00"))
    e = datetime.fromisoformat(to_query_end(end).replace("Z", "+00:00"))
    first = int(s.timestamp()) // step * step
    count = (int(e.timestamp()) // step * step - first) // step + 1
    series, spanning, _, _, median_span = _bucket_series(df, first, step, count, "policy_decision")
    effective = _effective_bucket(median_span)
    spikes = _spikes(series)
    caveat = None
    if TIMELINE_BUCKETS[effective] > step:
        caveat = "rows are aggregates wider than one day; bucket starts read as spikes"
    elif spikes["worst"] and spanning and spikes["worst"]["bucket_start"] == series[0]["bucket_start"]:
        caveat = "worst bucket is the first of the window, where earlier aggregates pile up"
    return {"bucket": "1d", "effective_bucket": effective,
            "series": [{"bucket_start": b["bucket_start"], "flows": b["flows"], "connections": b["connections"],
                        "blocked": b["by_policy_decision"].get("blocked", 0),
                        "potentially_blocked": b["by_policy_decision"].get("potentially_blocked", 0)}
                       for b in series],
            "rows_spanning_buckets": spanning, "worst_spike": spikes["worst"], "spike_rule": spikes["rule"],
            "caveat": caveat}


def test_inbound(c: _Collector, pair: _Pair, pairs: set, approved: _Approved, start: str, end: str,
                 max_rows: int) -> dict:
    dest = [{"label": {"href": h}} for h in pair.hrefs]
    qs, qe = to_query_start(start), to_query_end(end)
    allowed, ev_a = c.flows(f"compliance-evidence:T8:{pair.key}:allowed", include_destinations=dest,
                            policy_decisions=["allowed"], start=qs, end=qe)
    pot, ev_p = c.flows(f"compliance-evidence:T8:{pair.key}:potentially_blocked", include_destinations=dest,
                        policy_decisions=["potentially_blocked"], start=qs, end=qe)
    blocked, ev_b = c.flows(f"compliance-evidence:T8:{pair.key}:blocked", include_destinations=dest,
                            policy_decisions=["blocked"], start=qs, end=qe)
    pair.inbound_pce_flows = ev_a["returned"] + ev_p["returned"] + ev_b["returned"]
    capped = ev_a["capped"] or ev_p["capped"]

    crossings_df, intra = _drop_intra_scope(allowed, "src", pairs)
    rows = _grouped(crossings_df, ["src_app", "src_env", "src_ip", "src_hostname", "src_ip_lists", "port", "proto"])
    unapproved = not_workload = 0
    for r in rows:
        r["proto"] = _proto_name(r["proto"])
        r["source"] = (f"{r['src_app']} ({r['src_env']})" if r["src_app"] else r["src_hostname"] or r["src_ip"])
        r["approved"] = approved.ok(r["port"], None, r["proto"], "in")
        findings = []
        if r["approved"] is False:
            unapproved += 1
            findings.append("not in approved list")
        in_named_list = bool(r["src_ip_lists"]) and bool(
            set(x.strip() for x in str(r["src_ip_lists"]).split(",")) & pair.ip_list_names)
        if not r["src_hostname"] and not in_named_list:
            not_workload += 1
            findings.append("source is not a workload and not inside a named IP list a rule uses")
        if _is_public(r["src_ip"]) and not in_named_list:
            findings.append("public source address")
        r["findings"] = findings
    pot_rows = _grouped(pot, ["src_app", "src_env", "src_ip", "src_hostname", "port", "proto"])
    for r in pot_rows:
        r["proto"] = _proto_name(r["proto"])
    clauses = {
        "every_crossing_approved": ("NOT_TESTED" if not approved.given else "FAIL" if unapproved else "PASS"),
        "every_source_is_a_workload_or_named_ip_list":
            "FAIL" if any("named IP list" in f or "public" in f for r in rows for f in r["findings"]) else "PASS",
        "zero_potentially_blocked": "FAIL" if pot_rows else "PASS",
    }
    result = _cap(worst(clauses.values()), capped)
    blocked_conns = int(pd.to_numeric(blocked.get("num_connections", pd.Series(dtype=float)),
                                      errors="coerce").fillna(0).sum()) if not blocked.empty else 0
    return {"result": result, "clauses": clauses,
            "measured": f"{len(rows)} allowed crossings ({intra} intra-scope rows dropped), {unapproved} unapproved, "
                        f"{not_workload} from non-workload sources; {len(pot_rows)} potentially blocked; "
                        f"{len(blocked)} blocked rows, {blocked_conns} blocked connections"
                        + ("; capped: counts are lower bounds" if capped else ""),
            **_rows(rows, max_rows),
            "potentially_blocked": pot_rows[:max_rows],
            "blocked": {"rows": len(blocked), "connections": blocked_conns, "capped": ev_b["capped"]},
            "timeline": _timeline(blocked, pot, start, end),
            "evidence": [ev_a, ev_p, ev_b]}


def test_outbound(c: _Collector, pair: _Pair, pairs: set, approved: _Approved, start: str, end: str,
                  max_rows: int) -> dict:
    src = [{"label": {"href": h}} for h in pair.hrefs]
    allowed, ev = c.flows(f"compliance-evidence:T9:{pair.key}:allowed", include_sources=src,
                          policy_decisions=["allowed"], start=to_query_start(start), end=to_query_end(end))
    crossings_df, intra = _drop_intra_scope(allowed, "dst", pairs)
    rows = _grouped(crossings_df, ["dst_app", "dst_env", "dst_ip", "dst_hostname", "dst_fqdn", "dst_ip_lists",
                                  "port", "proto"])
    unapproved = public_unlisted = 0
    for r in rows:
        r["proto"] = _proto_name(r["proto"])
        r["destination"] = (f"{r['dst_app']} ({r['dst_env']})" if r["dst_app"]
                            else r["dst_hostname"] or r["dst_fqdn"] or r["dst_ip"])
        r["outside_estate"] = not r["dst_hostname"]
        r["public"] = _is_public(r["dst_ip"])
        r["in_named_ip_list"] = bool(r["dst_ip_lists"]) and bool(
            set(x.strip() for x in str(r["dst_ip_lists"]).split(",")) & pair.ip_list_names)
        r["approved"] = approved.ok(r["port"], None, r["proto"], "out")
        findings = []
        if r["approved"] is False:
            unapproved += 1
            findings.append("not in approved list")
        if r["public"] and not r["in_named_ip_list"]:
            public_unlisted += 1
            findings.append("public destination not inside a named IP list a rule uses")
        r["findings"] = findings
    rows.sort(key=lambda r: (not r["public"], -r["connections"]))
    clauses = {"every_destination_approved": ("NOT_TESTED" if not approved.given else
                                              "FAIL" if unapproved else "PASS"),
               "public_destinations_in_named_ip_list": "FAIL" if public_unlisted else "PASS"}
    return {"result": _cap(worst(clauses.values()), ev["capped"]), "clauses": clauses,
            "measured": f"{len(rows)} allowed crossings out ({intra} intra-scope rows dropped), "
                        f"{unapproved} unapproved, {public_unlisted} public destinations outside any named IP list"
                        + ("; capped: counts are lower bounds" if ev["capped"] else ""),
            **_rows(rows, max_rows), "evidence": [ev]}


def test_change_control(pending: list, pair: _Pair, max_rows: int) -> dict:
    mine = {_strip_version(rs["href"]) for rs in pair.rulesets}
    rows = []
    for item in pending:
        href = item.get("href", "")
        if "/rule_sets/" in href and _strip_version(href) in mine:
            rows.append({"href": href, "name": item.get("name"), "change_type": item.get("change_type")})
    return {"result": "EXCEPTION" if rows else "PASS",
            "measured": (f"{len(rows)} pending draft changes touch the pair's {len(pair.rulesets)} rulesets "
                         f"({len(pending)} pending in total)" if pending else "draft and active are in sync"),
            **_rows(rows, max_rows),
            "evidence": [{"tool": "compare-draft-active", "arguments": {"resource_type": "rule_sets"},
                          "returned": len(pending), "capped": False}]}


def test_logging(events: list, pair: _Pair, ran_inbound: bool, max_rows: int) -> dict:
    policy_rows = [e for e in events if e.get("event_type") and POLICY_EVENT_RE.search(e["event_type"])]
    if not ran_inbound:
        result, flows_text = "NOT_TESTED", "inbound flows not collected (T8 not requested)"
    else:
        result = "PASS" if events and pair.inbound_pce_flows > 0 else "FAIL"
        flows_text = f"{pair.inbound_pce_flows} flows into the pair"
    return {"result": result,
            "measured": f"{len(events)} events in the window ({len(policy_rows)} policy or enforcement related); "
                        f"{flows_text}",
            **_rows(policy_rows, max_rows),
            "evidence": [{"tool": "get-events", "arguments": {"max_results": 500}, "returned": len(events),
                          "capped": len(events) >= 500}]}


# ---------------------------------------------------------------------------
# Handler
# ---------------------------------------------------------------------------

def handle_collect_compliance_evidence(ctx, arguments: dict) -> list:
    logger.debug("COLLECT COMPLIANCE EVIDENCE CALLED: %s", ScrubbedArgs(arguments))
    arguments = dict(arguments or {})
    try:
        pce = ctx.pce

        pairs_in = _parse_scope(arguments.get("scope"))
        if isinstance(pairs_in, str):
            return _error({"error": "invalid_scope", "message": pairs_in})

        pversion = str(arguments.get("pversion") or "active").lower()
        if pversion not in POLICY_VERSIONS:
            return _error({"error": f"pversion must be 'draft' or 'active', got {pversion!r}"})

        win = _window(arguments)
        if isinstance(win, str):
            return _error({"error": "invalid_window", "message": win})
        start, end, days = win
        check_window(to_query_start(start), to_query_end(end))

        approved_in = arguments.get("approved_services")
        approved_list = _parse_approved(approved_in) if approved_in is not None else None
        if isinstance(approved_list, str):
            return _error({"error": "invalid_approved_services", "message": approved_list})
        approved = _Approved(approved_list)

        requested = arguments.get("tests")
        if requested:
            requested = [str(t).upper() for t in requested]
            unknown = [t for t in requested if t not in RUNNABLE]
            if unknown:
                return _error({"error": "unknown_tests", "unknown": unknown, "runnable": list(RUNNABLE),
                               "not_run": NOT_RUN})
        else:
            requested = list(RUNNABLE)
        wanted = set(requested)

        max_results = min(int(arguments.get("max_results") or MCP_BUG_MAX_RESULTS), MCP_QUERY_MAX_RESULTS)
        max_rows = int(arguments.get("max_rows") or 200)

        c = _Collector(pce, pversion, max_results, max_rows)
        label_map = c.labels()
        index = {(v["key"], v["value"]): h for h, v in label_map.items()}
        pairs, unresolved = [], []
        for app, env in pairs_in:
            app_href, env_href = index.get(("app", app)), index.get(("env", env))
            if not app_href:
                unresolved.append(f"app={app}")
            if not env_href:
                unresolved.append(f"env={env}")
            if app_href and env_href:
                pairs.append(_Pair(app, env, app_href, env_href))
        if unresolved:
            err = unresolved_label_error(sorted(set(unresolved)), pce, keys=("app", "env"))
            err["error"] = "unresolved_scope_labels"
            err["message"] = ("These scope labels do not exist in the PCE, so nothing was collected. "
                              "An unknown label would otherwise widen the scope to the whole estate.")
            return _error(err)
        pair_keys = {(p.app, p.env) for p in pairs}
        now = datetime.now(timezone.utc)

        results: dict[str, dict] = {t: {} for t in requested}

        # Inventory: always, since every later test is NOT_TESTED for an empty pair.
        for p in pairs:
            p.workloads, ev = c.workloads(p)
            if "T1" in wanted:
                results["T1"][p.key] = test_inventory(p, ev, max_rows)
            if "T2" in wanted:
                results["T2"][p.key] = test_enforcement(p, ev, max_rows)
            if "T3" in wanted:
                results["T3"][p.key] = test_ven_health(p, ev, now, max_rows)
            if "T4" in wanted:
                results["T4"][p.key] = test_unmanaged(p, ev, max_rows)

        def skip(test_id: str, p: _Pair):
            results[test_id][p.key] = {"result": "NOT_TESTED",
                                       "measured": "no workloads in scope (T1 failed for this pair)",
                                       "rows": [], "evidence": []}

        live = [p for p in pairs if not p.empty]
        for p in pairs:
            for t in ("T2", "T3", "T4"):
                if t in wanted and p.empty:
                    skip(t, p)

        if wanted & NEEDS_POLICY:
            for p in live:
                ev = collect_policy(c, p)
                if "T5" in wanted:
                    results["T5"][p.key] = test_descriptions(p, ev, max_rows)
                if "T6" in wanted:
                    results["T6"][p.key] = test_broad_consumers(c, p, ev, max_rows)
                if "T7" in wanted:
                    results["T7"][p.key] = test_admitted_services(c, p, approved, ev, max_rows)
            for p in pairs:
                if p.empty:
                    for t in ("T5", "T6", "T7"):
                        if t in wanted:
                            skip(t, p)

        if wanted & NEEDS_INBOUND:
            for p in live:
                r = test_inbound(c, p, pair_keys, approved, start, end, max_rows)
                if "T8" in wanted:
                    results["T8"][p.key] = r
            for p in pairs:
                if p.empty and "T8" in wanted:
                    skip("T8", p)

        if wanted & NEEDS_OUTBOUND:
            for p in live:
                results["T9"][p.key] = test_outbound(c, p, pair_keys, approved, start, end, max_rows)
            for p in pairs:
                if p.empty:
                    skip("T9", p)

        if "T11" in wanted:
            pending = c.pending()
            for p in live:
                results["T11"][p.key] = test_change_control(pending, p, max_rows)
            for p in pairs:
                if p.empty:
                    skip("T11", p)

        if "T14" in wanted:
            events = c.events(to_query_start(start), to_query_end(end))
            for p in live:
                results["T14"][p.key] = test_logging(events, p, "T8" in wanted, max_rows)
            for p in pairs:
                if p.empty:
                    skip("T14", p)

        tests = []
        for t in requested:
            name, kind, rule = TESTS[t]
            per_pair = results[t]
            tests.append({"id": t, "name": name, "scope": kind, "rule": rule,
                          "result": worst(v["result"] for v in per_pair.values()),
                          "per_pair": per_pair})

        payload = {
            "policy_version": pversion,
            "collected_at": now.isoformat(),
            "window": {"start": start, "end": end, "days": days},
            "scope": {"pairs": [{"app": p.app, "env": p.env, "app_href": p.app_href, "env_href": p.env_href,
                                 "workloads": len(p.workloads),
                                 "managed": sum(1 for w in p.workloads if w["managed"])} for p in pairs]},
            "inputs": {"approved_services": approved_list, "tests": requested,
                       "max_results": max_results, "max_rows": max_rows},
            "overall": worst(t["result"] for t in tests),
            "queries": c.queries,
            "tests": tests,
            "not_run": NOT_RUN,
            "notes": [
                "Results are PASS, FAIL, EXCEPTION (capped pull or pending change) or NOT_TESTED (missing "
                "input or empty pair); worst-of in that order. No score.",
                "IP list ranges and service objects are read from the same policy version as the rules.",
                "T8/T9 drop rows whose other end is a scope pair (intra-scope); Explorer excludes cannot "
                "express 'not (app AND env)'.",
                "Framework requirement mapping is not done here; see the illumio://compliance/* resources "
                "and the illumio-compliance-evidence skill matrices.",
            ],
        }
        return [types.TextContent(type="text", text=json.dumps(payload, indent=2, default=str))]

    except Exception as e:
        error_msg = f"Failed to collect compliance evidence: {describe_error(e)}"
        logger.error(error_msg, exc_info=True)
        return _error({"error": error_msg})
