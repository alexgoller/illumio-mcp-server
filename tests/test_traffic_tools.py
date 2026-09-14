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
    """Resolves to a bare HREF string.

    This test previously asserted a {"label": {"href": ...}} dict, which is what
    the code produced and what the SDK silently refuses to coerce. The test
    passed while the feature was broken -- it encoded my assumption about the
    SDK rather than the SDK's actual contract.
    """
    lookup = {"app=vdi": "/orgs/1/labels/1"}
    unresolved = []
    assert _resolve_filter_block(["app=vdi"], lookup, unresolved) == ["/orgs/1/labels/1"]
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


def test_flat_filter_list_is_left_flat_for_the_sdk():
    """Previously asserted [["app=vdi"]]. Wrapping is the SDK's job, and doing
    it ourselves is exactly what made TrafficQuery.build reject the filter."""
    assert _normalise_filter(["app=vdi"]) == ["app=vdi"]


def test_already_nested_filter_is_flattened():
    """Legacy callers pass [[...]]; flatten it so the SDK can coerce the string."""
    assert _normalise_filter([["app=vdi"]]) == ["app=vdi"]


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


# ---------------------------------------------------------------------------
# Filter shaping. The SDK's _parse_traffic_filters coerces STRINGS and wraps
# each into its own AND-block; anything non-str it passes through untouched,
# which then fails validation with "Invalid value for include". So our job is
# to hand it flat strings, not to pre-wrap.
# ---------------------------------------------------------------------------

HREF = "/orgs/1/labels/74"
ENV_HREF = "/orgs/1/labels/126"


def test_label_shorthand_becomes_a_bare_href_string():
    """Not a {'label': {'href': ...}} dict: the SDK skips coercion on non-str."""
    unresolved = []
    assert _resolve_filter_block(["app=vdi"], {"app=vdi": HREF}, unresolved) == [HREF]
    assert unresolved == []


def test_bare_href_passes_through_as_a_string():
    """Regression: a raw HREF used to reach TrafficQuery.build nested one level
    deep, raising AttributeError('Invalid value for include')."""
    assert _normalise_filter([HREF]) == [HREF]


def test_nested_filter_is_flattened_for_the_sdk():
    """Callers (and our own older code) pass [[href]]; flatten rather than reject."""
    assert _normalise_filter([[HREF]]) == [HREF]


def test_two_labels_stay_flat_so_the_sdk_ands_them():
    """['app','env'] becomes [[app],[env]] inside the SDK -- an AND. Verified
    on a live PCE: this returns flows, [[app, env]] returns none."""
    assert _normalise_filter([HREF, ENV_HREF]) == [HREF, ENV_HREF]


def test_empty_filter_is_the_one_case_we_wrap():
    """[] yields no flows at all; [[]] means match anything."""
    assert _normalise_filter(None) == [[]]
    assert _normalise_filter([]) == [[]]


def test_a_single_string_is_accepted():
    assert _normalise_filter(HREF) == [HREF]


# ---------------------------------------------------------------------------
# Which host runs the process. process_name comes from whichever VEN reported
# the flow, so direction decides the side. Verified on a live PCE:
# chrome.exe/mstsc.exe/putty.exe are outbound, httpd/sshd are inbound.
# ---------------------------------------------------------------------------

def test_inbound_process_is_attributed_to_the_destination():
    """httpd reported on an inbound flow runs on the web server, not on the
    endpoint that connected to it. Getting this backwards puts a server daemon
    on someone's laptop."""
    flows = [_flow(service={"port": 443, "proto": 6, "process_name": "httpd"},
                   flow_direction="inbound")]
    summary = summarize_traffic_structured(raw_flows_to_dataframe(FakePCE(LABELS), flows))
    assert summary["by_process"][0]["destinations"][0]["process_runs_on"] == "destination"


def test_outbound_process_is_attributed_to_the_source():
    flows = [_flow(service={"port": 443, "proto": 6, "process_name": "chrome.exe"},
                   flow_direction="outbound")]
    summary = summarize_traffic_structured(raw_flows_to_dataframe(FakePCE(LABELS), flows))
    assert summary["by_process"][0]["destinations"][0]["process_runs_on"] == "source"


def test_direction_splits_the_same_process_name():
    """httpd inbound and httpd outbound are different facts and must not merge."""
    flows = [_flow(service={"port": 443, "proto": 6, "process_name": "httpd"},
                   flow_direction="inbound", dst={"ip": "1.1.1.1"}),
             _flow(service={"port": 443, "proto": 6, "process_name": "httpd"},
                   flow_direction="outbound", dst={"ip": "1.1.1.1"})]
    summary = summarize_traffic_structured(raw_flows_to_dataframe(FakePCE(LABELS), flows))
    sides = {d["process_runs_on"] for d in summary["by_process"][0]["destinations"]}
    assert sides == {"source", "destination"}


# ---------------------------------------------------------------------------
# Contract tests: does the SDK actually ACCEPT what we produce?
#
# Everything above asserts the shape our helpers return, which is what my own
# assumption said was right -- and three of those tests passed while the
# feature was broken, because they encoded the assumption rather than the
# contract. TrafficQuery.build validates its input without any network, so the
# contract is cheap to test directly. These are the tests that would have
# caught it.
# ---------------------------------------------------------------------------

import pytest as _pytest
from illumio import TrafficQuery                      # noqa: E402

LABEL_HREF = "/orgs/1/labels/74"
ENV_LABEL_HREF = "/orgs/1/labels/126"


def _build(sources=None, destinations=None):
    return TrafficQuery.build(
        start_date="2026-01-01", end_date="2026-01-02",
        include_sources=_normalise_filter(sources),
        include_destinations=_normalise_filter(destinations),
        exclude_sources=[], exclude_destinations=[],
        include_services=[], exclude_services=[], policy_decisions=[],
        max_results=10, query_name="contract-test",
    )


def test_sdk_accepts_a_resolved_label_shorthand():
    """app=vdi -> href -> TrafficQuery.build must not raise.

    The old code produced {"label": {"href": ...}}; the SDK passes non-str
    through uncoerced and then rejects it with
    AttributeError: Invalid value for include.
    """
    resolved = _resolve_filter_block(["app=vdi"], {"app=vdi": LABEL_HREF}, [])
    query = _build(sources=resolved)
    assert query.sources.include == [[{"label": {"href": LABEL_HREF}}]]


def test_sdk_accepts_a_bare_href():
    assert _build(sources=[LABEL_HREF]).sources.include == [[{"label": {"href": LABEL_HREF}}]]


def test_sdk_accepts_a_legacy_nested_href():
    assert _build(sources=[[LABEL_HREF]]).sources.include == [[{"label": {"href": LABEL_HREF}}]]


def test_two_labels_become_two_and_blocks_in_the_sdk():
    """Two AND-blocks, not one block with two labels. On a live PCE the former
    returns flows and the latter returns none."""
    assert _build(sources=[LABEL_HREF, ENV_LABEL_HREF]).sources.include == [
        [{"label": {"href": LABEL_HREF}}],
        [{"label": {"href": ENV_LABEL_HREF}}],
    ]


def test_sdk_accepts_an_omitted_filter_as_match_all():
    assert _build(sources=None).sources.include == [[]]


def test_sdk_accepts_an_ip_address():
    assert _build(sources=["10.0.0.1"]).sources.include == [[{"ip_address": "10.0.0.1"}]]


def test_pre_wrapped_dict_is_what_the_sdk_rejects():
    """Pins the failure mode itself, so nobody reintroduces the dict form
    thinking it is equivalent."""
    with _pytest.raises(Exception):
        TrafficQuery.build(
            start_date="2026-01-01", end_date="2026-01-02",
            include_sources=[[LABEL_HREF]],          # nested raw string
            include_destinations=[[]], exclude_sources=[], exclude_destinations=[],
            include_services=[], exclude_services=[], policy_decisions=[],
            max_results=10, query_name="must-raise",
        )


# ---------------------------------------------------------------------------
# discover-process-egress: only source-side processes, and never a bare zero
# ---------------------------------------------------------------------------

def test_egress_ignores_inbound_flows():
    """An inbound flow names the listener on the destination. Counting it as
    egress puts a web server's httpd on the endpoint that called it."""
    from illumio_mcp.tools.traffic import _is_external
    df = raw_flows_to_dataframe(FakePCE(LABELS), [
        _flow(dst={"ip": "1.2.3.4"}, flow_direction="inbound",
              service={"port": 443, "proto": 6, "process_name": "httpd"}),
        _flow(dst={"ip": "5.6.7.8"}, flow_direction="outbound",
              service={"port": 443, "proto": 6, "process_name": "claude.exe"}),
    ])
    outbound = df[df["flow_direction"] != "inbound"]
    external = outbound[outbound.apply(_is_external, axis=1)]
    assert set(external["process_name"]) == {"claude.exe"}


def test_egress_excludes_managed_destinations():
    """A destination with a workload is internal, however exotic its IP."""
    from illumio_mcp.tools.traffic import _is_external
    df = raw_flows_to_dataframe(FakePCE(LABELS), [
        _flow(dst={"ip": "8.8.8.8", "workload": {"hostname": "db01"}}),
        _flow(dst={"ip": "8.8.4.4"}),
    ])
    assert int(df.apply(_is_external, axis=1).sum()) == 1


# ---------------------------------------------------------------------------
# Ringfence remote-app extraction
# ---------------------------------------------------------------------------

def test_ringfence_grouping_keeps_unlabelled_sources():
    """src_app/src_env are null for every unlabelled source. pandas drops those
    rows by default, which is how a ringfence reported zero remote apps while
    the summary showed hundreds of thousands of connections."""
    import pandas as _pd
    from illumio_mcp.tools.ringfence import _group_keeping_blanks
    frame = _pd.DataFrame([
        {"src_app": "vdi", "src_env": "prod", "port": 443, "proto": 6, "num_connections": 5},
        {"src_app": None, "src_env": None, "port": 443, "proto": 6, "num_connections": 7},
    ])
    grouped = _group_keeping_blanks(frame, ["src_app", "src_env", "port", "proto"])
    assert len(grouped) == 2
    assert grouped["num_connections"].sum() == 12


def test_ringfence_does_not_combine_app_and_env_into_one_block():
    """[[app, env]] returns no flows on a live PCE; [[app], [env]] returns 278.
    A source guard, because the difference only shows against a real PCE."""
    import pathlib
    for name in ("ringfence.py", "policy.py"):
        src = (pathlib.Path("src/illumio_mcp/tools") / name).read_text()
        assert "[[app_filter, env_filter]]" not in src, f"{name} rebuilt the broken filter"
