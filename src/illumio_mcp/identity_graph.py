"""Identity graph from traffic flows: who acted, where, on what, and when.

Illumio records a `user_name` on a flow -- the account the communicating process
ran as. That turns flow data into an identity question: what can this account
reach, from how many places, and over what period. For segmentation that is the
least-privilege question, and it is not answerable from workload labels alone.

Two kinds of identity show up, and they want different readings:

  service accounts   root, www-data, NT AUTHORITY\\SYSTEM, mysql, tomcat.
                     Appear on MANY workloads by design -- that is what a daemon
                     does -- so host spread is not suspicious, but the set of
                     destinations they can reach is the blast radius if one is
                     compromised.
  interactive users  agarcia, bjones. Normally one workload each, a handful of
                     destinations. Spread here is the interesting signal.

Identity resolution comes first
-------------------------------

The same person arrives under more than one spelling. Measured on a live PCE:
`CRYSTAL\\agarcia` and `agarcia` are one human recorded twice, so every
interactive user was double-counted -- 26 "identities" that are really 13
people. Same shape as a process path appearing once per user profile.

So the domain qualifier is stripped for identity, and kept as an attribute: you
still want to know an account was seen both domain-joined and local, because
that difference is itself worth looking at.

What this does NOT claim
------------------------

An account observed on many workloads is reported as exactly that -- observed on
many workloads. Whether that is lateral movement or a backup agent doing its job
is context this data cannot supply, so the output never uses the phrase.
"""
from __future__ import annotations

import collections
import datetime
import logging
import re

logger = logging.getLogger(__name__)

NA = "-"
ONE_DAY = datetime.timedelta(days=1)

# Accounts that are service identities by construction, not by behaviour.
_SERVICE_EXACT = {
    "root", "www-data", "daemon", "nobody", "systemd-network", "systemd-resolve",
    "mysql", "postgres", "mssql", "oracle", "mongodb", "redis", "elasticsearch",
    "tomcat", "jboss", "nginx", "apache", "httpd", "bind", "named", "postfix",
    "sendmail", "syslog", "rsyslog", "ntp", "chrony", "nagios", "zabbix",
    "splunk", "openldap", "krb5kdc", "modbus", "sshd", "ftp", "mail", "news",
}
_SERVICE_PREFIXES = ("nt authority\\", "nt service\\", "iis apppool\\", "window manager\\")
_SERVICE_SUFFIXES = ("$",)          # machine accounts: HOSTNAME$


def split_identity(raw: str) -> tuple[str, str | None]:
    """`DOMAIN\\user` or `user@realm` -> (account, qualifier).

    The qualifier is preserved rather than discarded: an account seen both as
    CRYSTAL\\agarcia and plain agarcia is one identity used two ways, and that
    distinction is worth reporting even though it must not split the identity.
    """
    if raw is None:
        return "", None
    text = str(raw).strip()
    if not text:
        return "", None
    if "\\" in text:
        domain, _, account = text.rpartition("\\")
        return account.strip(), domain.strip() or None
    if "@" in text and not text.startswith("@"):
        account, _, realm = text.partition("@")
        return account.strip(), realm.strip() or None
    return text, None


def classify_identity(account: str, qualifier: str | None) -> tuple[str, str]:
    """(class, why). Class is 'service' or 'interactive'.

    The reason is returned so the caller can disagree with it. A heuristic that
    cannot explain itself is one nobody can correct.
    """
    low = (account or "").strip().lower()
    full = f"{qualifier}\\{account}".lower() if qualifier else low

    if not low:
        return "unknown", "no account name on the flow"
    if any(full.startswith(p) for p in _SERVICE_PREFIXES):
        return "service", f"well-known service principal prefix in {full!r}"
    if any(low.endswith(s) for s in _SERVICE_SUFFIXES):
        return "service", "machine account (trailing $)"
    if low in _SERVICE_EXACT:
        return "service", f"{low!r} is a conventional daemon account"
    if re.fullmatch(r"(svc|sa|srv|sys)[-_.].*", low):
        return "service", "svc/sa/srv naming convention"
    return "interactive", "no service-account pattern matched"


class Identity:
    """One resolved identity and everything observed about it."""

    __slots__ = ("account", "qualifiers", "klass", "why", "workloads",
                 "destinations", "apps", "external", "ports", "processes",
                 "connections", "rows", "first_seen", "last_seen", "active_days",
                 "new_flow_days", "decisions")

    def __init__(self, account: str):
        self.account = account
        self.qualifiers: set[str] = set()
        self.klass = "unknown"
        self.why = ""
        self.workloads: set[str] = set()
        self.destinations: collections.Counter = collections.Counter()
        # Apps and external addresses are different questions. Counted
        # together, 40 internet IPs read as "reaches 43 destinations" and the
        # wide-reach signal fired for 10 of 11 interactive users.
        self.apps: set[str] = set()
        self.external: set[str] = set()
        self.ports: collections.Counter = collections.Counter()
        self.processes: collections.Counter = collections.Counter()
        self.connections = 0
        self.rows = 0
        self.first_seen = None
        self.last_seen = None
        self.active_days: set = set()
        self.new_flow_days: set = set()
        self.decisions: collections.Counter = collections.Counter()

    def as_dict(self, top: int = 10, window_days_bounds=None) -> dict:
        out = {
            "identity": self.account,
            "class": self.klass,
            "classified_because": self.why,
            "observed_on_workloads": len(self.workloads),
            "distinct_apps": len(self.apps),
            "external_destinations": len(self.external),
            "distinct_destinations": len(self.destinations),
            "connections": self.connections,
            "flow_rows": self.rows,
            "destinations": [{"to": d, "connections": c}
                             for d, c in self.destinations.most_common(top)],
            "ports": [f"{p}" for p, _ in self.ports.most_common(top)],
            "processes": [p for p, _ in self.processes.most_common(top)],
            "policy_decisions": dict(self.decisions),
        }
        if len(self.qualifiers) > 1 or (self.qualifiers and None not in self.qualifiers):
            out["seen_as"] = sorted(
                (f"{q}\\{self.account}" if q else self.account) for q in self.qualifiers
            )
        if self.first_seen and self.last_seen:
            out["first_seen"] = self.first_seen.isoformat()
            out["last_seen"] = self.last_seen.isoformat()
            out["active_days"] = len(self.active_days)
            # The lower bound. active_days counts every day a row covers, so
            # one row of 2 connections spanning 30 days reads 30 of 30; the
            # distinct days on which rows BEGAN cannot be inflated that way.
            out["days_with_new_flows"] = len(self.new_flow_days)
            # Calendar days, like active_days, so the two are comparable:
            # 14 Sep 08:00 to 9 Oct 06:00 is 26 days, not 24.9 rounded down.
            # Clipped to the query window: Explorer returns any aggregate
            # overlapping it, so a one-day query can carry a six-day row.
            lo, hi = self.first_seen.date(), self.last_seen.date()
            if window_days_bounds:
                lo, hi = max(lo, window_days_bounds[0]), min(hi, window_days_bounds[1])
            span = max((hi - lo).days + 1, 1)
            out["window_days"] = span
            # A gap between active days and window days is the interesting bit:
            # 2 active days inside a 30-day window is a different story from 28.
            out["activity_density"] = round(min(len(self.active_days), span) / span, 2)
        return out


def _present(value) -> bool:
    """A real value: not None, not the "-" sentinel, not "", not a pandas NaN.

    NaN is truthy and != "-", so the naive `value and value != NA` test let it
    through. That is how every unmanaged destination rendered as "nan (nan)"
    and collapsed into one bucket -- for one user the fourth-largest
    destination, 538,992 connections across 22, 3389, 443 and 445.
    """
    if value is None or value == NA or value == "":
        return False
    return not (isinstance(value, float) and value != value)


def _endpoint(row, attribute=None) -> tuple[str, bool]:
    """Destination name and whether it is an app -> (name, is_app).

    Apps are app+env. Anything else is external: FQDN, else the provider when
    `attribute(ip)` names one (seven Anthropic addresses are one destination,
    not seven; eighteen CloudFront edges are one CDN, and the bucket's name
    already says it cannot see the SaaS behind it), else hostname or IP. An
    IP-list name is context,
    not identity -- ranked above the address it turned every external
    destination into one bucket called "internet" -- so it goes in parentheses.
    """
    app = row.get("dst_app")
    if _present(app):
        env = row.get("dst_env")
        return (f"{app} ({env})" if _present(env) else str(app)), True
    ip_list = row.get("dst_ip_lists")
    suffix = f" ({ip_list})" if _present(ip_list) else ""
    fqdn = row.get("dst_fqdn")
    if _present(fqdn):
        return f"{fqdn}{suffix}", False
    ip = row.get("dst_ip")
    if attribute is not None and _present(ip):
        provider, _confidence = attribute(str(ip))
        if provider:
            return f"{provider}{suffix}", False
    for value in (row.get("dst_hostname"), ip):
        if _present(value):
            return f"{value}{suffix}", False
    return (str(ip_list) if _present(ip_list) else "unknown"), False


def build_identity_graph(df, *, include_service_accounts: bool = True,
                         identity_filter=None, top: int = 10,
                         attribute=None, window=None) -> dict:
    """Aggregate a flow frame into identities, their reach, and their timeline.

    Rows with no `user_name` are counted and reported rather than dropped: the
    PCE only records an account when the VEN could attribute the flow to one, so
    "how much of this estate has no identity data" is itself an answer.

    `attribute(ip) -> (provider, confidence)` groups external addresses by
    provider. `window=(start, end)` is the query window the caller asked for:
    the timeline is measured inside it, and data outside it is disclosed.
    """
    import pandas as pd

    win_lo = win_hi = None
    if window and window[0] and window[1]:
        win_lo = pd.Timestamp(window[0]).tz_convert("UTC") if pd.Timestamp(window[0]).tzinfo \
            else pd.Timestamp(window[0]).tz_localize("UTC")
        win_hi = pd.Timestamp(window[1]).tz_convert("UTC") if pd.Timestamp(window[1]).tzinfo \
            else pd.Timestamp(window[1]).tz_localize("UTC")
    day_bounds = (win_lo.date(), win_hi.date()) if win_lo is not None else None

    wanted = None
    if identity_filter:
        if isinstance(identity_filter, str):
            identity_filter = [identity_filter]
        wanted = {split_identity(x)[0].lower() for x in identity_filter}

    identities: dict[str, Identity] = {}
    edges: dict[tuple, dict] = {}
    rows_total = len(df)
    rows_without_identity = 0

    first = pd.to_datetime(df.get("first_detected"), errors="coerce", utc=True) \
        if "first_detected" in df.columns else None
    last = pd.to_datetime(df.get("last_detected"), errors="coerce", utc=True) \
        if "last_detected" in df.columns else None

    for pos, (_, row) in enumerate(df.iterrows()):
        raw = row.get("user_name")
        if not raw or raw == NA or (isinstance(raw, float) and pd.isna(raw)):
            rows_without_identity += 1
            continue

        account, qualifier = split_identity(raw)
        if not account:
            rows_without_identity += 1
            continue
        klass, why = classify_identity(account, qualifier)
        if klass == "service" and not include_service_accounts:
            continue
        if wanted is not None and account.lower() not in wanted:
            continue

        ident = identities.get(account)
        if ident is None:
            ident = identities[account] = Identity(account)
            ident.klass, ident.why = klass, why
        ident.qualifiers.add(qualifier)

        src = row.get("src_hostname")
        if not _present(src):
            src = row.get("src_ip") if _present(row.get("src_ip")) else "unknown"
        dst, is_app = _endpoint(row, attribute)
        conns = int(row.get("num_connections") or 0)

        ident.workloads.add(str(src))
        ident.destinations[dst] += conns
        (ident.apps if is_app else ident.external).add(dst)
        ident.connections += conns
        ident.rows += 1
        port, proto = row.get("port"), row.get("proto")
        if _present(port):
            ident.ports[f"{port}/{proto}" if _present(proto) else str(port)] += conns
        proc = row.get("process_name")
        if _present(proc):
            ident.processes[str(proc).rsplit("\\", 1)[-1].rsplit("/", 1)[-1]] += conns
        decision = row.get("policy_decision")
        if _present(decision):
            ident.decisions[str(decision)] += 1

        seen_from = first.iloc[pos] if first is not None and pos < len(first) else None
        seen_to = last.iloc[pos] if last is not None and pos < len(last) else None
        if seen_from is not None and pd.notna(seen_from):
            ident.first_seen = (seen_from if ident.first_seen is None
                                else min(ident.first_seen, seen_from))
            # Explorer aggregates a persistent connection into ONE row spanning
            # first_detected..last_detected, so a daemon live for 26 days is one
            # row, not 26. Count every day the row covers, not the day it began:
            # counting the start alone made nagios "active on only 1 of 26 days".
            stop = seen_to.date() if (seen_to is not None and pd.notna(seen_to)
                                      and seen_to >= seen_from) else seen_from.date()
            day = seen_from.date()
            ident.new_flow_days.add(day)
            if day_bounds:
                day, stop = max(day, day_bounds[0]), min(stop, day_bounds[1])
            while day <= stop:
                ident.active_days.add(day)
                day += ONE_DAY
        if seen_to is not None and pd.notna(seen_to):
            ident.last_seen = seen_to if ident.last_seen is None else max(ident.last_seen, seen_to)

        key = (account, str(src), dst)
        edge = edges.get(key)
        if edge is None:
            edges[key] = {"identity": account, "from": str(src), "to": dst,
                          "connections": conns, "ports": {str(port)}}
        else:
            edge["connections"] += conns
            edge["ports"].add(str(port))

    ranked = sorted(identities.values(), key=lambda i: -i.connections)
    data_span = _data_span(first, last, win_lo, win_hi)
    return {
        **({"data_span": data_span} if data_span else {}),
        "totals": {
            "flow_rows": rows_total,
            "rows_with_identity": rows_total - rows_without_identity,
            "rows_without_identity": rows_without_identity,
            "identities": len(identities),
            "interactive": sum(1 for i in ranked if i.klass == "interactive"),
            "service": sum(1 for i in ranked if i.klass == "service"),
            "edges": len(edges),
        },
        "identities": [i.as_dict(top=top, window_days_bounds=day_bounds) for i in ranked],
        "edges": [{**e, "ports": sorted(e["ports"])} for e in
                  sorted(edges.values(), key=lambda e: -e["connections"])],
    }


def _data_span(first, last, win_lo, win_hi) -> dict | None:
    """Where the returned rows actually sit in time, against the query window.

    Explorer keeps older flows in multi-day aggregates and returns any that
    overlap the window, so a one-day query for 27 Sep came back with rows
    starting 22 Sep and 1.67M connections -- labelled as 27 Sep. The label was
    the lie; the data is what it is, and the caller needs to know which.
    """
    if first is None or last is None or win_lo is None:
        return None
    earliest, latest = first.min(), last.max()
    if not (earliest == earliest and latest == latest):      # all NaT
        return None
    before, after = bool(earliest < win_lo), bool(latest > win_hi)
    span = {"earliest": earliest.isoformat(), "latest": latest.isoformat(),
            "extends_before_window": before, "extends_after_window": after}
    if before or after:
        span["note"] = (
            "Rows extend outside the requested window: Explorer stores older "
            "flows as multi-day aggregates and returns any that overlap it. "
            "Connection counts on those rows cover the whole aggregate, not just "
            "the window; active_days and window_days are clipped to the window."
        )
    return span


def reach_findings(graph: dict, *, workload_threshold: int = 10,
                   destination_threshold: int = 10) -> list[dict]:
    """Identities worth a human look, ordered by how UNEXPECTED they are.

    Ranking matters more than detection here. Thresholds alone put `root on 235
    workloads` at the top, which is a daemon doing its job, and bury the finding
    that actually needs a person: one interactive account operating from two
    devices. So each signal carries an interest level, and expected service
    spread is reported as informational rather than as a finding.

    Measured example of the signal this surfaces: `CRYSTAL\\agarcia` on
    win-endpoint-1 and `agarcia` on mac-endpoint-1 are one human on a Windows
    and a Mac endpoint -- invisible until the two spellings are resolved to one
    identity.

    Nothing here is a verdict. A backup agent on 200 workloads is correct; an
    interactive account on 200 is a question. The output says what was observed
    and why it was surfaced, and leaves the judgement.
    """
    INTEREST = {"review": 0, "note": 1, "expected": 2}
    out = []
    for item in graph.get("identities", []):
        signals = []

        if item["class"] == "interactive" and item["observed_on_workloads"] > 1:
            signals.append(("review",
                f"interactive account active from {item['observed_on_workloads']} "
                f"workloads; one person on several devices, or a shared credential"))

        blocked = (item.get("policy_decisions") or {}).get("blocked")
        if blocked:
            signals.append(("review",
                f"{blocked} flow(s) from this identity are already blocked by policy"))

        # Apps, not addresses: 40 internet IPs are not 40 places to reach into
        # the estate, and counted as such this fired for 10 of 11 users.
        apps = item.get("distinct_apps", item["distinct_destinations"])
        if item["class"] == "interactive" and apps >= destination_threshold:
            signals.append(("note",
                f"interactive account reaches {apps} distinct apps -- wide for a "
                f"single user"))

        density = item.get("activity_density")
        if density is not None and density <= 0.2 and item["connections"] > 0:
            signals.append(("note",
                f"active on only {item.get('active_days')} of "
                f"{item.get('window_days')} days -- intermittent, not steady-state"))

        if item["class"] == "service" and item["observed_on_workloads"] >= workload_threshold:
            signals.append(("expected",
                f"service account on {item['observed_on_workloads']} workloads reaching "
                f"{item['distinct_destinations']} destinations -- normal for a daemon, but "
                f"this is the blast radius if the account is compromised"))

        if not signals:
            continue
        level = min(signals, key=lambda s: INTEREST[s[0]])[0]
        out.append({
            "identity": item["identity"],
            "class": item["class"],
            "interest": level,
            "why_surfaced": [text for _lvl, text in
                             sorted(signals, key=lambda s: INTEREST[s[0]])],
            "observed_on_workloads": item["observed_on_workloads"],
            "distinct_apps": item.get("distinct_apps"),
            "external_destinations": item.get("external_destinations"),
            "distinct_destinations": item["distinct_destinations"],
            "connections": item["connections"],
        })

    # review first, then note, then expected; within a level, widest reach first
    out.sort(key=lambda f: (INTEREST[f["interest"]], -f["observed_on_workloads"]))
    return out
