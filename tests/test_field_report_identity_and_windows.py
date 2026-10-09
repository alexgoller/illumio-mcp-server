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


# ===========================================================================
# Second report, after 0.9.1 split the external bucket into real addresses.
# ===========================================================================

# --- 5. "wide for a single user" fired for 10 of 11 interactive users -------

def _external(ip, **over):
    nan = float("nan")
    return {"dst_app": nan, "dst_env": nan, "dst_ip": ip, "dst_ip_lists": "internet", **over}


def test_external_addresses_are_not_counted_as_apps():
    """Reported: distinct_destinations went from 8-12 per user to 119-126
    against a threshold of 10, so the signal fired for everyone. Apps and
    external addresses are different questions; count them apart."""
    rows = [{"dst_app": f"app{i}", "dst_env": "Production"} for i in range(3)]
    rows += [_external(f"203.0.113.{i}") for i in range(1, 41)]
    g = build_identity_graph(_frame(rows))
    ident = g["identities"][0]
    assert ident["distinct_apps"] == 3
    assert ident["external_destinations"] == 40
    assert ident["distinct_destinations"] == 43      # unchanged meaning: the union
    texts = [t for f in reach_findings(g) for t in f["why_surfaced"]]
    assert not any("wide for a single user" in t for t in texts)


def test_wide_reach_still_fires_on_apps():
    rows = [{"dst_app": f"app{i}", "dst_env": "Production"} for i in range(12)]
    g = build_identity_graph(_frame(rows))
    texts = [t for f in reach_findings(g) for t in f["why_surfaced"]]
    assert any("12 distinct apps" in t and "wide for a single user" in t for t in texts)


def test_attributable_external_addresses_group_by_provider():
    """agarcia: 226 of 241 edges were single internet IPs. Seven of them were
    Anthropic's; one destination, not seven. CDN edges group too: eighteen
    CloudFront addresses are one place, and the bucket name says what it is."""
    def attribute(ip):
        return {"160.79.105.10": ("anthropic", "likely"),
                "160.79.105.100": ("anthropic", "likely"),
                "104.18.3.205": ("cloudflare-fronted", "ambiguous")}.get(ip, (None, None))
    g = build_identity_graph(_frame([
        _external("160.79.105.10", num_connections=5),
        _external("160.79.105.100", num_connections=7),
        _external("104.18.3.205"),
        _external("198.51.100.9"),
    ]), attribute=attribute)
    ident = g["identities"][0]
    by_name = {d["to"]: d["connections"] for d in ident["destinations"]}
    assert by_name["anthropic (internet)"] == 12
    assert "cloudflare-fronted (internet)" in by_name and "198.51.100.9 (internet)" in by_name
    assert ident["external_destinations"] == 3
    assert sum(1 for e in g["edges"] if e["to"] == "anthropic (internet)") == 1


# --- 6. a narrow window returned data from outside it ----------------------

def test_aggregates_overlapping_the_window_are_clipped_and_disclosed():
    """Reported: a one-day query for 27 Sep came back with first_seen 22 Sep,
    window_days 6 and 1.67M connections, labelled as 27 Sep only. Explorer
    stores older flows in multi-day aggregates and returns any that overlap.
    The window the caller asked for is the one the timeline is measured in."""
    g = build_identity_graph(_frame([
        {"first_detected": "2026-09-22T10:00:00Z", "last_detected": "2026-09-27T09:00:00Z",
         "num_connections": 1_670_000},
    ]), window=("2026-09-27T00:00:00Z", "2026-09-27T23:59:59Z"))
    ident = g["identities"][0]
    assert ident["first_seen"].startswith("2026-09-22")      # the data fact, kept
    assert (ident["active_days"], ident["window_days"]) == (1, 1)
    span = g["data_span"]
    assert span["earliest"].startswith("2026-09-22") and span["extends_before_window"]
    assert not span["extends_after_window"]
    assert "aggregate" in span["note"]


def test_data_inside_the_window_carries_no_disclosure():
    g = build_identity_graph(_frame([{}]), window=("2026-09-01T00:00:00Z", "2026-09-01T23:59:59Z"))
    assert "data_span" not in g or not g["data_span"].get("extends_before_window")


def test_window_handler_passes_the_window_through(monkeypatch):
    from illumio_mcp.tools import identity as identity_tool
    captured = {}
    def fake_build(df, **kw):
        captured.update(kw)
        return {"totals": {"rows_with_identity": 0}, "identities": [], "edges": [],
                "data_span": {"earliest": "2026-09-22T10:00:00+00:00",
                              "latest": "2026-09-27T09:00:00+00:00",
                              "extends_before_window": True, "extends_after_window": False,
                              "note": "aggregate"}}
    monkeypatch.setattr(identity_tool, "fetch_flows_raw", lambda *a, **k: [])
    monkeypatch.setattr(identity_tool, "raw_flows_to_dataframe", lambda *a, **k: pd.DataFrame())
    monkeypatch.setattr(identity_tool, "build_identity_graph", fake_build)
    out = json.loads(identity_tool.handle_build_identity_graph(
        ToolContext(pce=FakePCE(), is_stdio=True),
        {"start_date": "2026-09-27", "end_date": "2026-09-27"})[0].text)
    assert captured["window"] == ("2026-09-27T00:00:00Z", "2026-09-27T23:59:59Z")
    assert out["window"]["start"] == "2026-09-27" and out["window"]["data_span"]["extends_before_window"]


# --- 7. activity_density is an upper bound ----------------------------------

def test_days_with_new_flows_is_reported_as_the_lower_bound():
    """Reported: one row with 2 connections spanning 30 days reads 30 of 30.
    True, and inherent in aggregated data. Report the other bound too."""
    g = build_identity_graph(_frame([
        {"first_detected": "2026-09-01T00:00:00Z", "last_detected": "2026-09-30T00:00:00Z",
         "num_connections": 2},
    ]))
    ident = g["identities"][0]
    assert ident["active_days"] == 30
    assert ident["days_with_new_flows"] == 1
