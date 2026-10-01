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
import logging
import re

logger = logging.getLogger(__name__)

NA = "-"

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
                 "destinations", "ports", "processes", "connections", "rows",
                 "first_seen", "last_seen", "active_days", "decisions")

    def __init__(self, account: str):
        self.account = account
        self.qualifiers: set[str] = set()
        self.klass = "unknown"
        self.why = ""
        self.workloads: set[str] = set()
        self.destinations: collections.Counter = collections.Counter()
        self.ports: collections.Counter = collections.Counter()
        self.processes: collections.Counter = collections.Counter()
        self.connections = 0
        self.rows = 0
        self.first_seen = None
        self.last_seen = None
        self.active_days: set = set()
        self.decisions: collections.Counter = collections.Counter()

    def as_dict(self, top: int = 10) -> dict:
        out = {
            "identity": self.account,
            "class": self.klass,
            "classified_because": self.why,
            "observed_on_workloads": len(self.workloads),
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
            span = (self.last_seen - self.first_seen).days + 1
            out["window_days"] = span
            # A gap between active days and window days is the interesting bit:
            # 2 active days inside a 30-day window is a different story from 28.
            out["activity_density"] = round(len(self.active_days) / max(span, 1), 2)
        return out


def _endpoint(row) -> str:
    """Destination as app+env where known, else FQDN, IP list, hostname, IP."""
    app = row.get("dst_app")
    if app and app != NA:
        env = row.get("dst_env")
        return f"{app} ({env})" if env and env != NA else str(app)
    for col in ("dst_fqdn", "dst_ip_lists", "dst_hostname", "dst_ip"):
        value = row.get(col)
        if value and value != NA:
            return str(value)
    return "unknown"


def build_identity_graph(df, *, include_service_accounts: bool = True,
                         identity_filter=None, top: int = 10) -> dict:
    """Aggregate a flow frame into identities, their reach, and their timeline.

    Rows with no `user_name` are counted and reported rather than dropped: the
    PCE only records an account when the VEN could attribute the flow to one, so
    "how much of this estate has no identity data" is itself an answer.
    """
    import pandas as pd

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
        if not src or src == NA:
            src = row.get("src_ip") or "unknown"
        dst = _endpoint(row)
        conns = int(row.get("num_connections") or 0)

        ident.workloads.add(str(src))
        ident.destinations[dst] += conns
        ident.connections += conns
        ident.rows += 1
        port, proto = row.get("port"), row.get("proto")
        if port not in (None, NA):
            ident.ports[f"{port}/{proto}" if proto not in (None, NA) else str(port)] += conns
        proc = row.get("process_name")
        if proc and proc != NA:
            ident.processes[str(proc).rsplit("\\", 1)[-1].rsplit("/", 1)[-1]] += conns
        decision = row.get("policy_decision")
        if decision and decision != NA:
            ident.decisions[str(decision)] += 1

        if first is not None and pos < len(first):
            ts = first.iloc[pos]
            if pd.notna(ts):
                ident.first_seen = ts if ident.first_seen is None else min(ident.first_seen, ts)
                ident.active_days.add(ts.date())
        if last is not None and pos < len(last):
            ts = last.iloc[pos]
            if pd.notna(ts):
                ident.last_seen = ts if ident.last_seen is None else max(ident.last_seen, ts)

        key = (account, str(src), dst)
        edge = edges.get(key)
        if edge is None:
            edges[key] = {"identity": account, "from": str(src), "to": dst,
                          "connections": conns, "ports": {str(port)}}
        else:
            edge["connections"] += conns
            edge["ports"].add(str(port))

    ranked = sorted(identities.values(), key=lambda i: -i.connections)
    return {
        "totals": {
            "flow_rows": rows_total,
            "rows_with_identity": rows_total - rows_without_identity,
            "rows_without_identity": rows_without_identity,
            "identities": len(identities),
            "interactive": sum(1 for i in ranked if i.klass == "interactive"),
            "service": sum(1 for i in ranked if i.klass == "service"),
            "edges": len(edges),
        },
        "identities": [i.as_dict(top=top) for i in ranked],
        "edges": [{**e, "ports": sorted(e["ports"])} for e in
                  sorted(edges.values(), key=lambda e: -e["connections"])],
    }


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

        if item["class"] == "interactive" and item["distinct_destinations"] >= destination_threshold:
            signals.append(("note",
                f"interactive account reaches {item['distinct_destinations']} distinct "
                f"destinations -- wide for a single user"))

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
            "distinct_destinations": item["distinct_destinations"],
            "connections": item["connections"],
        })

    # review first, then note, then expected; within a level, widest reach first
    out.sort(key=lambda f: (INTEREST[f["interest"]], -f["observed_on_workloads"]))
    return out
