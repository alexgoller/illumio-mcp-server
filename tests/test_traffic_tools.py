"""Unit tests for traffic flow parsing and summarisation. No PCE required.

Each test pins one of four defects reported from a live demo PCE, where
get-traffic-flows returned `total_pce_flows: 500, total_rows: 0`.
"""
import pandas as pd
import pytest

from illumio_mcp.tools.traffic import (
    NA,
    _normalise_filter,
    _resolve_filter_block,
    raw_flows_to_dataframe,
    summarize_traffic_structured,
)


class FakeLabel:
    def __init__(self, href, key, value):
        self.href, self.key, self.value = href, key, value


class FakeLabels:
    def __init__(self, labels): self._labels = labels
    def get(self, params=None):
        key = (params or {}).get("key")
        return [l for l in self._labels if key is None or l.key == key]


class FakePCE:
    def __init__(self, labels=()): self.labels = FakeLabels(list(labels))


LABELS = [FakeLabel("/orgs/1/labels/1", "app", "vdi"),
          FakeLabel("/orgs/1/labels/2", "env", "production")]


def _flow(**over):
    flow = {
        "src": {"ip": "10.0.0.1", "workload": {"hostname": "web01", "labels": [
            {"href": "/orgs/1/labels/1"}]}},
        "dst": {"ip": "10.0.0.2", "workload": {"hostname": "db01"}},
        "service": {"port": 443, "proto": 6, "process_name": "httpd", "user_name": "root"},
        "policy_decision": "allowed",
        "flow_direction": "outbound",
        "num_connections": 5,
    }
    flow.update(over)
    return flow


# --- finding 2: rows silently discarded -----------------------------------

def test_endpoint_flows_without_a_workload_survive():
    """Regression: a destination with no workload has a NaN hostname, and
    pandas' groupby drops any row with a NaN group key -- which deleted every
    outbound flow. 500 flows in, 0 rows out."""
    flows = [_flow(dst={"ip": "1.2.3.4"}),                      # no workload at all
             _flow(dst={"ip": "5.6.7.8", "ip_lists": [{"name": "internet"}]})]
    df = raw_flows_to_dataframe(FakePCE(LABELS), flows)
    assert len(df) == 2

    summary = summarize_traffic_structured(df)
    assert summary["totals"]["rows"] == 2

    # Assert on the GROUPED output, not on totals. totals is computed from the
    # frame before grouping, so it stays correct even when grouping throws
    # every row away -- which is precisely how the original bug hid.
    reached = {e["dst_label"] for e in summary["external_destinations"]}
    assert reached == {"1.2.3.4", "internet"}, reached
    assert sum(e["connections"] for e in summary["external_destinations"]) == 10


def test_grouping_keeps_rows_with_missing_keys():
    """The sentinel, not NaN, is what makes grouping safe."""
    df = raw_flows_to_dataframe(FakePCE(LABELS), [_flow(dst={"ip": "1.2.3.4"})])
    filled = df.fillna(NA)
    grouped = filled.groupby(["dst_hostname", "dst_ip"], dropna=False).size()
    assert grouped.sum() == 1


# --- finding 3: process and identity detail --------------------------------

def test_process_user_and_fqdn_are_preserved():
    """The SDK's typed TrafficNode drops dst.fqdn entirely, so the raw payload
    is parsed instead. Without process_name the demo cannot show which binary
    is talking."""
    flows = [_flow(dst={"ip": "1.2.3.4", "fqdn": "api.anthropic.com"},
                   service={"port": 443, "proto": 6,
                            "process_name": "claude.exe", "user_name": "alex"})]
    df = raw_flows_to_dataframe(FakePCE(LABELS), flows)
    row = df.iloc[0]
    assert row["process_name"] == "claude.exe"
    assert row["user_name"] == "alex"
    assert row["dst_fqdn"] == "api.anthropic.com"


def test_summary_groups_by_process_and_names_the_destination():
    flows = [_flow(dst={"ip": "1.2.3.4", "fqdn": "api.anthropic.com"},
                   service={"port": 443, "proto": 6, "process_name": "claude.exe"},
                   num_connections=7)]
    summary = summarize_traffic_structured(raw_flows_to_dataframe(FakePCE(LABELS), flows))
    proc = summary["by_process"][0]
    assert proc["process"] == "claude.exe"
    assert proc["destinations"][0]["to"] == "api.anthropic.com"
    assert proc["destinations"][0]["proto"] == "tcp"      # not 6
    assert proc["destinations"][0]["port"] == 443


def test_empty_process_name_is_not_its_own_group():
    """The PCE sends "" as often as it omits the field; treating those
    differently put a nameless entry at the top of the ranking."""
    flows = [_flow(service={"port": 1, "proto": 6, "process_name": ""}),
             _flow(service={"port": 2, "proto": 6, "process_name": None})]
    summary = summarize_traffic_structured(raw_flows_to_dataframe(FakePCE(LABELS), flows))
    assert summary["by_process"] == []
    assert summary["totals"]["distinct_processes"] == 0


def test_external_destinations_are_called_out():
    flows = [_flow(dst={"ip": "1.2.3.4", "fqdn": "api.anthropic.com"}, num_connections=3),
             _flow()]  # internal, has a workload
    summary = summarize_traffic_structured(raw_flows_to_dataframe(FakePCE(LABELS), flows))
    assert any(e["dst_label"] == "api.anthropic.com"
               for e in summary["external_destinations"])


def test_blocked_traffic_is_called_out():
    flows = [_flow(policy_decision="blocked", num_connections=9)]
    summary = summarize_traffic_structured(raw_flows_to_dataframe(FakePCE(LABELS), flows))
    assert summary["blocked"][0]["connections"] == 9


# --- finding 1: label shorthand -------------------------------------------

def test_label_shorthand_resolves_to_href():
    lookup = {"app=vdi": "/orgs/1/labels/1"}
    unresolved = []
    assert _resolve_filter_block(["app=vdi"], lookup, unresolved) == \
        [{"label": {"href": "/orgs/1/labels/1"}}]
    assert unresolved == []


def test_unknown_label_is_reported_not_silently_forwarded():
    unresolved = []
    _resolve_filter_block(["app=nope"], {"app=vdi": "/x"}, unresolved)
    assert unresolved == ["app=nope"]


@pytest.mark.parametrize("value", ["/orgs/1/labels/1", "10.0.0.1", "api.anthropic.com"])
def test_non_label_filters_pass_through_untouched(value):
    assert _resolve_filter_block([value], {}, []) == [value]


# --- finding 4: unfiltered query ------------------------------------------

def test_empty_filter_becomes_match_all():
    """Explorer wants [[]] for "anything"; [] produces an invalid query."""
    assert _normalise_filter(None) == [[]]
    assert _normalise_filter([]) == [[]]


def test_flat_filter_list_is_wrapped_into_one_block():
    assert _normalise_filter(["app=vdi"]) == [["app=vdi"]]


def test_already_nested_filter_is_left_alone():
    assert _normalise_filter([["app=vdi"]]) == [["app=vdi"]]


def test_empty_dataframe_summarises_without_crashing():
    summary = summarize_traffic_structured(pd.DataFrame())
    assert summary["totals"]["rows"] == 0


# ---------------------------------------------------------------------------
# group_by dimensions and process-egress discovery
# ---------------------------------------------------------------------------

from illumio_mcp.tools.traffic import (          # noqa: E402
    GROUP_DIMENSIONS,
    TIME_AGGREGATES,
    group_flows,
    resolve_group_by,
    _is_external,
)


def _frame(*flows):
    return raw_flows_to_dataframe(FakePCE(LABELS), list(flows))


def test_group_by_collapses_to_the_requested_dimensions():
    df = _frame(_flow(dst={"ip": "1.1.1.1", "fqdn": "a.example"}),
                _flow(dst={"ip": "2.2.2.2", "fqdn": "a.example"}))
    grouped, cols, unknown = group_flows(df, ["process", "fqdn"])
    assert unknown == []
    assert "process_name" in cols and "dst_fqdn" in cols
    assert "dst_ip" not in cols           # collapsed away
    assert len(grouped) == 1              # both rows share process + fqdn
    assert grouped.iloc[0]["num_connections"] == 10


def test_unknown_dimension_is_reported_not_ignored():
    """Silently grouping by something else answers a different question."""
    _, _, unknown = group_flows(_frame(_flow()), ["proces"])
    assert unknown == ["proces"]


def test_raw_column_name_works_as_an_escape_hatch():
    _, cols, unknown = group_flows(_frame(_flow()), ["policy_decision"])
    assert unknown == [] and "policy_decision" in cols


def test_timestamps_survive_grouping():
    """Regression: first/last_detected were collected by the parser and then
    dropped by the groupby -- neither a key nor an aggregate. Exactly how
    process_name used to vanish."""
    a = _flow(timestamp_range={"first_detected": "2026-01-01T00:00:00Z",
                               "last_detected": "2026-01-02T00:00:00Z"})
    b = _flow(timestamp_range={"first_detected": "2026-01-03T00:00:00Z",
                               "last_detected": "2026-01-04T00:00:00Z"})
    grouped, _, _ = group_flows(_frame(a, b), ["process"])
    assert set(TIME_AGGREGATES) <= set(grouped.columns)
    assert grouped.iloc[0]["first_detected"] == "2026-01-01T00:00:00Z"   # min
    assert grouped.iloc[0]["last_detected"] == "2026-01-04T00:00:00Z"    # max


def test_every_declared_dimension_is_usable():
    df = _frame(_flow(dst={"ip": "1.1.1.1", "fqdn": "a.example"}))
    for name in GROUP_DIMENSIONS:
        _, _, unknown = group_flows(df, [name])
        assert unknown == [], f"{name} declared but unusable"


def test_external_is_absence_of_a_managed_destination():
    """Egress is defined by no managed destination workload, not by RFC1918."""
    assert _is_external({"dst_hostname": None})
    assert _is_external({"dst_hostname": NA})
    assert not _is_external({"dst_hostname": "db01"})


def test_bytes_are_summed_when_present():
    df = _frame(_flow(dst_bi=100, dst_bo=50), _flow(dst_bi=1, dst_bo=2))
    grouped, _, _ = group_flows(df, ["process"])
    assert grouped.iloc[0]["bytes_in"] == 101
    assert grouped.iloc[0]["bytes_out"] == 52
