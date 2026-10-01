"""Identity graph: resolution, classification, traversal and time.

Flow data carries the account a communicating process ran as, which turns it
into a least-privilege question: what can this account reach, from how many
places, over what period. The hard part is not aggregation -- it is getting the
identity right before aggregating.
"""
import pandas as pd
import pytest

from illumio_mcp.identity_graph import (
    split_identity, classify_identity, build_identity_graph, reach_findings, NA,
)
from illumio_mcp.tools import TOOL_REGISTRY


# ----- identity resolution: the same person must not be two identities -----

@pytest.mark.parametrize("raw,account,qualifier", [
    ("CRYSTAL\\agarcia", "agarcia", "CRYSTAL"),
    ("agarcia", "agarcia", None),
    ("NT AUTHORITY\\SYSTEM", "SYSTEM", "NT AUTHORITY"),
    ("user@corp.local", "user", "corp.local"),
    ("  spaced  ", "spaced", None),
])
def test_split_identity(raw, account, qualifier):
    assert split_identity(raw) == (account, qualifier)


def test_domain_and_bare_forms_resolve_to_one_identity():
    """Measured on a live PCE: CRYSTAL\\agarcia is on a domain-joined Windows
    host and plain `agarcia` is the same human on a Mac. Unresolved, every
    interactive user was counted twice -- 26 identities that were 13 people."""
    assert split_identity("CRYSTAL\\agarcia")[0] == split_identity("agarcia")[0]


@pytest.mark.parametrize("raw", [None, "", "   "])
def test_empty_identity_is_not_invented(raw):
    assert split_identity(raw)[0] == ""


# ----- classification: service spread is normal, user spread is not -----

@pytest.mark.parametrize("account,qualifier", [
    ("SYSTEM", "NT AUTHORITY"), ("root", None), ("mysql", None), ("www-data", None),
    ("WS01$", None), ("svc-backup", None), ("sa_report", None),
])
def test_service_accounts_are_recognised(account, qualifier):
    klass, why = classify_identity(account, qualifier)
    assert klass == "service", f"{account} classified {klass}: {why}"
    assert why, "a heuristic that cannot explain itself cannot be corrected"


@pytest.mark.parametrize("account", ["agarcia", "bjones", "dwilliams"])
def test_interactive_accounts_are_recognised(account):
    assert classify_identity(account, "CRYSTAL")[0] == "interactive"


def test_classification_always_gives_a_reason():
    for account, qual in (("root", None), ("agarcia", "CRYSTAL"), ("", None)):
        assert classify_identity(account, qual)[1]


# ----- the graph -----

def _frame(rows):
    base = {"src_hostname": "h1", "src_ip": "10.0.0.1", "dst_app": "payment",
            "dst_env": "Production", "dst_hostname": NA, "dst_fqdn": NA,
            "dst_ip_lists": NA, "dst_ip": "10.1.0.1", "port": 443, "proto": 6,
            "policy_decision": "allowed", "num_connections": 10,
            "process_name": NA, "user_name": NA,
            "first_detected": "2026-09-01T00:00:00Z",
            "last_detected": "2026-09-01T01:00:00Z"}
    return pd.DataFrame([{**base, **r} for r in rows])


def test_two_spellings_become_one_identity_with_both_workloads():
    g = build_identity_graph(_frame([
        {"user_name": "CRYSTAL\\agarcia", "src_hostname": "win-1"},
        {"user_name": "agarcia", "src_hostname": "mac-1"},
    ]))
    assert g["totals"]["identities"] == 1
    ident = g["identities"][0]
    assert ident["identity"] == "agarcia"
    assert ident["observed_on_workloads"] == 2
    assert set(ident["seen_as"]) == {"CRYSTAL\\agarcia", "agarcia"}


def test_rows_without_an_identity_are_counted_not_dropped():
    """The PCE records an account only when the VEN could attribute the flow, so
    'how much of this estate has no identity data' is itself the answer."""
    g = build_identity_graph(_frame([
        {"user_name": "root"}, {"user_name": NA}, {"user_name": None},
    ]))
    assert g["totals"]["rows_with_identity"] == 1
    assert g["totals"]["rows_without_identity"] == 2


def test_service_accounts_can_be_excluded():
    rows = [{"user_name": "root"}, {"user_name": "agarcia"}]
    assert build_identity_graph(_frame(rows))["totals"]["identities"] == 2
    only_people = build_identity_graph(_frame(rows), include_service_accounts=False)
    assert [i["identity"] for i in only_people["identities"]] == ["agarcia"]


def test_identity_filter_accepts_either_spelling():
    rows = [{"user_name": "CRYSTAL\\agarcia"}, {"user_name": "root"}]
    for probe in ("agarcia", "CRYSTAL\\agarcia"):
        g = build_identity_graph(_frame(rows), identity_filter=probe)
        assert [i["identity"] for i in g["identities"]] == ["agarcia"], probe


def test_destination_prefers_app_identity_over_raw_address():
    g = build_identity_graph(_frame([{"user_name": "agarcia"}]))
    assert g["identities"][0]["destinations"][0]["to"] == "payment (Production)"


def test_process_paths_are_reduced_to_basenames():
    g = build_identity_graph(_frame([
        {"user_name": "agarcia",
         "process_name": r"C:\Users\agarcia\AppData\Local\Chrome\chrome.exe"},
    ]))
    assert g["identities"][0]["processes"] == ["chrome.exe"]


def test_connections_and_edges_aggregate():
    g = build_identity_graph(_frame([
        {"user_name": "agarcia", "num_connections": 5},
        {"user_name": "agarcia", "num_connections": 7},
    ]))
    assert g["identities"][0]["connections"] == 12
    assert g["totals"]["edges"] == 1, "same identity/src/dst is one edge"


# ----- the time axis -----

def test_activity_window_and_density():
    g = build_identity_graph(_frame([
        {"user_name": "agarcia", "first_detected": "2026-09-01T00:00:00Z",
         "last_detected": "2026-09-01T01:00:00Z"},
        {"user_name": "agarcia", "first_detected": "2026-09-10T00:00:00Z",
         "last_detected": "2026-09-10T01:00:00Z"},
    ]))
    ident = g["identities"][0]
    assert ident["active_days"] == 2
    assert ident["window_days"] == 10
    # 2 active days inside a 10-day window is a different story from 10
    assert ident["activity_density"] == 0.2


def test_missing_timestamps_do_not_break_the_graph():
    df = _frame([{"user_name": "agarcia"}])
    df = df.drop(columns=["first_detected", "last_detected"])
    g = build_identity_graph(df)
    assert g["identities"][0]["identity"] == "agarcia"
    assert "active_days" not in g["identities"][0]


# ----- findings: ranked by how unexpected, not by raw size -----

def test_interactive_on_several_workloads_outranks_daemon_spread():
    """Thresholds alone put `root on 235 workloads` first, which is a daemon
    doing its job, and bury the finding that needs a person."""
    rows = [{"user_name": "root", "src_hostname": f"srv-{i}"} for i in range(40)]
    rows += [{"user_name": "CRYSTAL\\agarcia", "src_hostname": "win-1"},
             {"user_name": "agarcia", "src_hostname": "mac-1"}]
    findings = reach_findings(build_identity_graph(_frame(rows)))
    assert findings[0]["identity"] == "agarcia"
    assert findings[0]["interest"] == "review"
    assert any(f["identity"] == "root" and f["interest"] == "expected" for f in findings)


def test_blocked_flows_are_surfaced_for_review():
    g = build_identity_graph(_frame([
        {"user_name": "agarcia", "policy_decision": "blocked"},
    ]))
    f = reach_findings(g)[0]
    assert f["interest"] == "review"
    assert any("blocked" in r for r in f["why_surfaced"])


def test_quiet_single_host_user_raises_nothing():
    """No finding is the correct output for ordinary behaviour."""
    assert reach_findings(build_identity_graph(_frame([{"user_name": "agarcia"}]))) == []


def test_findings_state_observations_not_verdicts():
    """A backup agent on 200 workloads is correct; an interactive account on 200
    is a question. The wording must not decide which."""
    rows = [{"user_name": "root", "src_hostname": f"s{i}"} for i in range(30)]
    text = " ".join(r for f in reach_findings(build_identity_graph(_frame(rows)))
                    for r in f["why_surfaced"]).lower()
    for loaded in ("lateral movement", "compromised account", "attacker", "malicious"):
        assert loaded not in text, f"finding language asserts {loaded!r}"


# ----- registration -----

def test_tool_is_registered_read_only():
    spec = TOOL_REGISTRY["build-identity-graph"]
    assert spec.mutating is False
    assert spec.requires_pce is True


def test_tool_is_advertised_with_the_resolution_caveat():
    import asyncio
    from illumio_mcp.server import handle_list_tools
    tool = next(t for t in asyncio.run(handle_list_tools())
                if t.name == "build-identity-graph")
    assert "identity" in tool.description.lower()
    assert "DOMAIN" in tool.description or "domain" in tool.description.lower()
    assert "include_service_accounts" in tool.inputSchema["properties"]
