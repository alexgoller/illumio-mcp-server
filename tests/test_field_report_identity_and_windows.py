"""Four defects reported from a Claude session driving the server against a
live PCE. Each test reproduces one without a PCE.

1. Unlabelled destinations rendered as "nan (nan)" in the identity graph, so
   everything external or unmanaged collapsed into one bucket.
2. active_days counted the first_detected date of each row, so a flow live
   from 14 Sep to 9 Oct was "active on only 1 of 26 days" and the
   intermittent finding fired for every long-lived daemon.
3. discover-process-egress built its per-process and per-provider rollups from
   the `limit` findings it returned, not from everything it found.
4. Window dates were never validated: "not-a-date" reached the PCE as
   "not-a-dateT00:00:00Z", and a reversed window read as "no flows".
"""
import json

import pandas as pd
import pytest
from illumio import TrafficQuery

from illumio_mcp.context import ToolContext
from illumio_mcp.identity_graph import NA, build_identity_graph, reach_findings
from illumio_mcp.tools import traffic
from illumio_mcp.tools.traffic import (fetch_flows_raw, to_query_end,
                                       to_query_start)

from test_traffic_tools import LABELS, FakePCE, _flow


def _frame(rows):
    base = {"src_hostname": "h1", "src_ip": "10.0.0.1", "dst_app": "payment",
            "dst_env": "Production", "dst_hostname": NA, "dst_fqdn": NA,
            "dst_ip_lists": NA, "dst_ip": "10.1.0.1", "port": 443, "proto": 6,
            "policy_decision": "allowed", "num_connections": 10,
            "process_name": NA, "user_name": "agarcia",
            "first_detected": "2026-09-01T00:00:00Z",
            "last_detected": "2026-09-01T01:00:00Z"}
    return pd.DataFrame([{**base, **r} for r in rows])


# --- 1. nan (nan) -----------------------------------------------------------

def test_unlabelled_destinations_keep_their_address():
    """raw_flows_to_dataframe leaves dst_app/dst_env as float NaN for an
    unmanaged destination. NaN is truthy and != the "-" sentinel, so the
    endpoint formatter printed it. Reported: 538,992 connections for one user
    on 22, 3389, 443 and 445 all filed under "nan (nan)"."""
    nan = float("nan")
    g = build_identity_graph(_frame([
        {"dst_app": nan, "dst_env": nan, "dst_ip": "203.0.113.5"},
        {"dst_app": nan, "dst_env": nan, "dst_ip": "203.0.113.6"},
    ]))
    ident = g["identities"][0]
    names = {d["to"] for d in ident["destinations"]}
    assert "nan (nan)" not in names and not any("nan" in n for n in names)
    assert names == {"203.0.113.5", "203.0.113.6"}, "two hosts must stay two destinations"
    assert ident["distinct_destinations"] == 2


def test_ip_list_name_does_not_swallow_distinct_external_hosts():
    """With the nan gone, the same traffic landed in one bucket named
    "internet" -- the IP list, ranked above the address. Context, not identity."""
    nan = float("nan")
    g = build_identity_graph(_frame([
        {"dst_app": nan, "dst_env": nan, "dst_ip": "203.0.113.5", "dst_ip_lists": "internet"},
        {"dst_app": nan, "dst_env": nan, "dst_ip": "203.0.113.6", "dst_ip_lists": "internet"},
        {"dst_app": nan, "dst_env": nan, "dst_ip": "203.0.113.7",
         "dst_fqdn": "api.example.com", "dst_ip_lists": "internet"},
    ]))
    names = {d["to"] for d in g["identities"][0]["destinations"]}
    assert names == {"203.0.113.5 (internet)", "203.0.113.6 (internet)",
                     "api.example.com (internet)"}


def test_labelled_app_with_unlabelled_env_does_not_print_nan():
    g = build_identity_graph(_frame([{"dst_env": float("nan")}]))
    assert g["identities"][0]["destinations"][0]["to"] == "payment"


# --- 2. active_days ---------------------------------------------------------

def test_long_lived_flow_is_active_on_every_day_it_covers():
    """Explorer aggregates a persistent connection into ONE row spanning
    first_detected..last_detected. Reported: nagios, 11M connections, 14 Sep
    to 9 Oct, "active on only 1 of 26 days"."""
    g = build_identity_graph(_frame([
        {"user_name": "nagios", "num_connections": 11_000_000,
         "first_detected": "2026-09-14T08:00:00Z",
         "last_detected": "2026-10-09T06:00:00Z"},
    ]))
    ident = g["identities"][0]
    assert ident["window_days"] == 26
    assert ident["active_days"] == 26
    assert ident["activity_density"] == 1.0
    texts = [t for f in reach_findings(g) for t in f["why_surfaced"]]
    assert not any("intermittent" in t for t in texts)


def test_separate_short_rows_still_count_as_separate_days():
    """The existing semantics for genuinely intermittent use are unchanged."""
    g = build_identity_graph(_frame([
        {"first_detected": "2026-09-01T00:00:00Z", "last_detected": "2026-09-01T01:00:00Z"},
        {"first_detected": "2026-09-10T00:00:00Z", "last_detected": "2026-09-10T01:00:00Z"},
    ]))
    ident = g["identities"][0]
    assert (ident["active_days"], ident["window_days"]) == (2, 10)


# --- 3. rollups cover every finding ----------------------------------------

def test_egress_rollups_cover_everything_found_not_just_what_was_returned(monkeypatch):
    """Reported with limit=40: 11 distinct processes and anthropic:[Claude.exe],
    while a filtered query showed the Mac Claude process hitting the same
    Anthropic IPs. The rollups were computed inside the head(limit) loop."""
    flows = [
        _flow(dst={"ip": "10.9.9.1"}, num_connections=100,
              service={"port": 443, "proto": 6, "process_name": "chrome.exe"}),
        _flow(dst={"ip": "10.9.9.2"}, num_connections=50,
              service={"port": 443, "proto": 6, "process_name": "slack.exe"}),
        # Lowest volume, so outside limit=1 -- but Anthropic-bound.
        _flow(dst={"ip": "160.79.104.10"}, num_connections=1,
              service={"port": 443, "proto": 6, "process_name": "Claude"}),
    ]
    monkeypatch.setattr(traffic, "fetch_flows_raw", lambda *a, **k: flows)
    ctx = ToolContext(pce=FakePCE(LABELS), is_stdio=True)
    out = json.loads(traffic.handle_discover_process_egress(ctx, {"limit": 1})[0].text)

    assert out["totals"]["returned"] == 1 and out["totals"]["findings_truncated"]
    assert out["totals"]["distinct_processes"] == 3
    assert {p["process"] for p in out["processes"]} == {"chrome.exe", "slack.exe", "Claude"}
    anthropic = [p for p in out["providers"] if p["provider"] == "anthropic"]
    assert anthropic and anthropic[0]["processes"] == ["Claude"]


# --- 4. window validation ---------------------------------------------------

@pytest.mark.parametrize("bad", ["not-a-date", "2026-13-45", "2026-09-31", "yesterday", ""])
def test_malformed_dates_are_rejected_before_the_pce_sees_them(bad):
    with pytest.raises(ValueError, match=rf"start_date {bad!r}"):
        to_query_start(bad)
    with pytest.raises(ValueError, match="end_date"):
        to_query_end(bad)


@pytest.mark.parametrize("ok", ["2026-08-15T06:30:00Z", "2026-08-15T06:30:00+02:00",
                                "2026-08-15T06:30:00", 1700000000, 1700000000.5])
def test_timestamps_and_epochs_the_sdk_accepts_still_pass(ok):
    assert to_query_start(ok) == str(ok)


def test_reversed_window_is_rejected_with_a_hint():
    """Reported: start after end returned "no flows in window" with no hint.
    FakePCE has no .post, so the failure must come from the window check."""
    q = TrafficQuery.build(start_date=to_query_start("2026-10-09"),
                           end_date=to_query_end("2026-10-01"),
                           max_results=10, query_name="reversed")
    with pytest.raises(ValueError, match="start_date .* is after end_date"):
        fetch_flows_raw(FakePCE(), q, "reversed")


def test_same_day_window_is_fine():
    q = TrafficQuery.build(start_date=to_query_start("2026-10-01"),
                           end_date=to_query_end("2026-10-01"),
                           max_results=10, query_name="same-day")
    with pytest.raises(AttributeError):      # reached .post on the FakePCE
        fetch_flows_raw(FakePCE(), q, "same-day")
