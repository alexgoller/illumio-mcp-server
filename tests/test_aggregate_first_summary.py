"""Aggregate-first traffic summary: pull wide, aggregate, spend the budget.

One constant used to answer two unrelated questions -- how many rows to ASK the
PCE for, and how many to hand BACK. Because it was 500 for both, every tool that
aggregates flows into a summary computed that summary from the first 500 rows
the PCE happened to return. Measured on demo100: a 30-day whole-estate window is
7,967 Explorer rows, so the summary described 6% of the window, and not a
representative 6%.

Aggregation is what makes the wide query affordable: the same window collapses
to a few hundred tuples at ~89 bytes each, against ~2 KB for a raw row.
"""
import inspect
import json

import pandas as pd
import pytest

from illumio_mcp.tools.constants import (
    MCP_BUG_MAX_RESULTS, MCP_QUERY_MAX_RESULTS, MCP_MAX_RESPONSE_BYTES,
)
from illumio_mcp.tools import traffic
from illumio_mcp.tools.traffic import (
    summarize_traffic_structured, _fit_summary_to_budget, _app_identity,
    GROUP_DIMENSIONS, NA,
)


def _frame(n=400):
    """Synthetic flows across several apps, ports and decisions."""
    rows = []
    for i in range(n):
        rows.append({
            'src_app': f"app{i % 12}", 'src_env': "Production",
            'dst_app': f"app{(i + 5) % 12}", 'dst_env': "Production",
            'src_hostname': f"host-src-{i}", 'dst_hostname': f"host-dst-{i}",
            'src_fqdn': NA, 'dst_fqdn': NA,
            'src_ip_lists': NA, 'dst_ip_lists': NA,
            'src_ip': f"10.0.0.{i % 250}", 'dst_ip': f"10.1.0.{i % 250}",
            'port': 400 + (i % 40), 'proto': 6,
            'policy_decision': ["allowed", "blocked", "potentially_blocked"][i % 3],
            'num_connections': 1000 - i,
            'process_name': f"proc{i % 9}.exe",
            'flow_direction': "outbound",
            'user_name': NA, 'matched_rules': NA, 'windows_service_name': NA,
        })
    return pd.DataFrame(rows)


# ----- step 1: the two caps are genuinely separate -----

def test_query_cap_is_far_larger_than_the_response_cap():
    assert MCP_QUERY_MAX_RESULTS > MCP_BUG_MAX_RESULTS * 100, (
        "the query cap exists so aggregating tools can see the whole window"
    )


@pytest.mark.parametrize("handler_name", [
    "handle_get_traffic_flows_summary",
    "handle_find_unmanaged_traffic",
    "handle_discover_process_egress",
])
def test_aggregating_tools_do_not_clamp_the_query_to_the_response_cap(handler_name):
    src = inspect.getsource(getattr(traffic, handler_name))
    assert "max_results=MCP_BUG_MAX_RESULTS" not in src
    assert "max_results = MCP_BUG_MAX_RESULTS" not in src


def test_raw_row_tool_is_still_capped():
    """get-traffic-flows returns raw rows, so the response cap IS its query cap.
    Raising it here would blow the context window, not widen the answer."""
    src = inspect.getsource(traffic.handle_get_traffic_flows)
    assert "MCP_BUG_MAX_RESULTS" in src


def test_policy_tools_pull_wide():
    from illumio_mcp.tools import policy
    src = inspect.getsource(policy)
    assert "MCP_BUG_MAX_RESULTS" not in src, (
        "enforcement readiness and coverage aggregate before responding"
    )


# ----- section_totals: completeness must be stated, not inferred -----

def test_section_totals_reports_the_full_count_not_the_shown_count():
    summary = summarize_traffic_structured(_frame(), limit=5)
    totals = summary["section_totals"]
    assert totals["app_to_app"] > len(summary["app_to_app"]) == 5, (
        "a trimmed section that looks complete is the bug this prevents"
    )


def test_section_totals_survive_the_budget_fitter():
    df = _frame()
    base = summarize_traffic_structured(df, limit=2000)
    fitted, _ = _fit_summary_to_budget(df, dict(base), 20_000)
    assert fitted["section_totals"]["app_to_app"] == base["section_totals"]["app_to_app"]


def test_complete_answer_is_not_marked_truncated():
    df = _frame(30)
    summary = summarize_traffic_structured(df, limit=2000)
    fitted, _ = _fit_summary_to_budget(df, dict(summary), MCP_MAX_RESPONSE_BYTES)
    assert "truncated_sections" not in fitted


# ----- the budget fitter -----

@pytest.mark.parametrize("budget", [MCP_MAX_RESPONSE_BYTES, 200_000, 50_000, 20_000])
def test_fitter_always_produces_a_payload_within_budget(budget):
    df = _frame()
    base = summarize_traffic_structured(df, limit=2000)
    _, payload = _fit_summary_to_budget(df, dict(base), budget)
    assert len(payload) <= budget, f"{len(payload)} exceeds {budget}"


def _rows_shown(summary):
    return sum(len(v) for k, v in summary.items()
               if isinstance(v, list) and k != "truncated_sections")


def test_fitter_prefers_the_widest_limit_that_fits():
    """A generous budget must not be spent as though it were a small one -- the
    previous behaviour cut every section to 5 regardless of how much room there
    was. Compared across all sections, since which one binds depends on the
    data."""
    df = _frame()
    base = summarize_traffic_structured(df, limit=2000)
    wide, _ = _fit_summary_to_budget(df, dict(base), MCP_MAX_RESPONSE_BYTES)
    narrow, _ = _fit_summary_to_budget(df, dict(base), 20_000)
    assert _rows_shown(wide) > _rows_shown(narrow)


def test_trimming_names_exactly_the_sections_it_trimmed():
    """Every named section must really be short, and every short section must be
    named -- a section quietly trimmed without being listed is the failure."""
    df = _frame()
    base = summarize_traffic_structured(df, limit=2000)
    fitted, _ = _fit_summary_to_budget(df, dict(base), 20_000)

    named = set(fitted["truncated_sections"])
    assert named, "something must have been trimmed at a 20KB budget"
    actually_short = {
        key for key, total in fitted["section_totals"].items()
        if len(fitted.get(key, [])) < total
    }
    assert named == actually_short, (
        f"reported {named} but actually short: {actually_short}"
    )
    assert "section_totals" in fitted["truncation_note"]


def test_fitter_preserves_window_and_totals():
    df = _frame()
    base = summarize_traffic_structured(df, limit=2000)
    base["window"] = {"start": "x", "end": "y"}
    fitted, _ = _fit_summary_to_budget(df, base, 20_000)
    assert fitted["window"] == {"start": "x", "end": "y"}
    assert "totals" in fitted


# ----- app_to_app must be app-level, not workload-level -----

def test_app_to_app_groups_on_apps_not_hostnames():
    """It is documented as "the coarse app-to-app view" but grouped on
    _endpoint_label, which prefers hostname -- so on demo100 it produced 1,394
    host pairs where the app+env view is a few hundred."""
    summary = summarize_traffic_structured(_frame(), limit=2000)
    froms = {row["from"] for row in summary["app_to_app"]}
    assert all("host-src-" not in f for f in froms), f"hostnames leaked in: {froms}"
    assert any("(" in f for f in froms), "expected 'app (env)' identities"


def test_app_to_app_is_bounded_by_app_count_not_flow_count():
    few = summarize_traffic_structured(_frame(100), limit=2000)["section_totals"]["app_to_app"]
    many = summarize_traffic_structured(_frame(400), limit=2000)["section_totals"]["app_to_app"]
    assert many <= 12 * 12 * 3, "app pairs should be bounded by apps x decisions"
    assert many >= few


@pytest.mark.parametrize("row,expected", [
    ({'src_app': 'ordering', 'src_env': 'Production'}, "ordering (Production)"),
    ({'src_app': 'ordering', 'src_env': NA}, "ordering"),
    ({'src_app': NA, 'src_fqdn': 'api.example.com'}, "external:api.example.com"),
    ({'src_app': NA, 'src_fqdn': NA, 'src_ip_lists': 'Any'}, "external:Any"),
    ({'src_app': NA, 'src_fqdn': NA, 'src_ip_lists': NA}, "unlabelled"),
])
def test_app_identity_fallbacks(row, expected):
    assert _app_identity(row, 'src') == expected


def test_app_identity_does_not_clobber_the_group_by_columns():
    """src_app/dst_app are the `source_app`/`destination_app` group_by keys.
    Writing a formatted 'app (env)' string into them would silently change what
    group_by returns."""
    assert GROUP_DIMENSIONS["source_app"] == ["src_app", "src_env"]
    df = _frame(20)
    summarize_traffic_structured(df, limit=10)
    assert set(df['src_app']) == {f"app{i}" for i in range(12)}, (
        "raw src_app was overwritten by the display identity"
    )


# ----- detail_level: analysis is always complete, display is not -----

def test_standard_shows_less_than_full():
    df = _frame()
    base = summarize_traffic_structured(df, limit=2000)
    std, std_payload = _fit_summary_to_budget(
        df, dict(base), MCP_MAX_RESPONSE_BYTES, detail_level="standard")
    full, full_payload = _fit_summary_to_budget(
        df, dict(base), MCP_MAX_RESPONSE_BYTES, detail_level="full")
    assert len(std_payload) < len(full_payload)


def test_both_detail_levels_report_identical_totals():
    """The whole point: trimming the DISPLAY must not change the arithmetic.
    A smaller response that also reported smaller numbers would be a lie."""
    df = _frame()
    base = summarize_traffic_structured(df, limit=2000)
    std, _ = _fit_summary_to_budget(df, dict(base), MCP_MAX_RESPONSE_BYTES, detail_level="standard")
    full, _ = _fit_summary_to_budget(df, dict(base), MCP_MAX_RESPONSE_BYTES, detail_level="full")
    assert std["section_totals"] == full["section_totals"]
    assert std["totals"] == full["totals"]


def test_standard_is_the_default_for_an_unknown_level():
    df = _frame()
    base = summarize_traffic_structured(df, limit=2000)
    default, _ = _fit_summary_to_budget(df, dict(base), MCP_MAX_RESPONSE_BYTES)
    named, _ = _fit_summary_to_budget(df, dict(base), MCP_MAX_RESPONSE_BYTES, detail_level="standard")
    bogus, _ = _fit_summary_to_budget(df, dict(base), MCP_MAX_RESPONSE_BYTES, detail_level="nonsense")
    assert len(default["app_to_app"]) == len(named["app_to_app"]) == len(bogus["app_to_app"])


def test_standard_caps_sections_at_the_standard_ceiling():
    df = _frame(1200)
    base = summarize_traffic_structured(df, limit=2000)
    std, _ = _fit_summary_to_budget(df, dict(base), MCP_MAX_RESPONSE_BYTES, detail_level="standard")
    for key, shown in ((k, len(v)) for k, v in std.items()
                       if isinstance(v, list) and k != "truncated_sections"):
        assert shown <= 100, f"{key} showed {shown} rows at detail_level=standard"


def test_trimmed_standard_says_the_analysis_was_complete():
    """Otherwise a trimmed section reads as a truncated query, which is exactly
    the confusion this whole change set out to remove."""
    df = _frame(1200)
    base = summarize_traffic_structured(df, limit=2000)
    std, _ = _fit_summary_to_budget(df, dict(base), MCP_MAX_RESPONSE_BYTES, detail_level="standard")
    if std.get("truncated_sections"):
        note = std["truncation_note"]
        assert "whole window" in note
        assert "detail_level='full'" in note


def test_detail_level_is_advertised_with_both_options():
    import asyncio
    from illumio_mcp.server import handle_list_tools
    tools = {t.name: t for t in asyncio.run(handle_list_tools())}
    prop = tools["get-traffic-flows-summary"].inputSchema["properties"]["detail_level"]
    assert set(prop["enum"]) == {"standard", "full"}
    assert "whole window" in prop["description"].lower()


# ----- label dimensions are per-PCE, not a fixed app/env assumption -----

def _labelled_frame():
    """A frame carrying label keys beyond app/env, as a real PCE does.
    demo100 defines 15 dimensions: bu, compliance, risk, os, type and more."""
    rows = []
    for i in range(60):
        rows.append({
            'src_app': f"app{i % 6}", 'src_env': "Production",
            'src_bu': f"bu{i % 3}", 'src_compliance': "PCI-DSS" if i % 2 else NA,
            'src_DFIRBubble': f"z{i % 2}",
            'dst_app': f"app{(i + 2) % 6}", 'dst_env': "Production",
            'dst_bu': f"bu{(i + 1) % 3}", 'dst_compliance': NA,
            'dst_DFIRBubble': f"z{(i + 1) % 2}",
            'src_hostname': f"h{i}", 'dst_hostname': f"d{i}",
            'src_fqdn': NA, 'dst_fqdn': NA, 'src_ip_lists': NA, 'dst_ip_lists': NA,
            'src_ip': f"10.0.0.{i}", 'dst_ip': f"10.1.0.{i}",
            'port': 443, 'proto': 6, 'policy_decision': "allowed",
            'num_connections': 100 - i, 'process_name': "p.exe",
            'flow_direction': "outbound", 'user_name': NA,
            'matched_rules': NA, 'windows_service_name': NA,
        })
    return pd.DataFrame(rows)


@pytest.mark.parametrize("labels,expected_top", [
    (("app", "env"), "app0 (Production)"),
    (("bu",), "bu0"),
    (("compliance", "env"), "PCI-DSS (Production)"),
])
def test_identity_labels_change_the_axis_not_the_machinery(labels, expected_top):
    summary = summarize_traffic_structured(
        _labelled_frame(), limit=100, identity_labels=labels)
    froms = {row["from"] for row in summary["app_to_app"]}
    assert expected_top in froms, f"{labels} produced {sorted(froms)[:4]}"


def test_default_identity_is_still_app_env():
    from illumio_mcp.tools.traffic import DEFAULT_IDENTITY_LABELS
    assert DEFAULT_IDENTITY_LABELS == ("app", "env")


def test_endpoints_without_the_chosen_label_do_not_vanish():
    """Grouping by a SPARSE label -- compliance, which only some workloads carry
    -- must not silently drop the rest. They appear as `unlabelled` on whichever
    side lacks the label, rather than being dropped from the estate."""
    summary = summarize_traffic_structured(
        _labelled_frame(), limit=100, identity_labels=("compliance",))
    endpoints = {row["from"] for row in summary["app_to_app"]}
    endpoints |= {row["to"] for row in summary["app_to_app"]}
    assert "unlabelled" in endpoints, (
        f"endpoints lacking the label disappeared: {sorted(endpoints)}"
    )
    assert "PCI-DSS" in endpoints, "labelled endpoints missing"


def test_self_pairs_are_excluded_on_any_axis():
    """app_to_app is between-identity traffic, so X -> X is filtered. On a
    sparse label that means unlabelled -> unlabelled traffic is not shown here;
    it is still counted in `totals`."""
    summary = summarize_traffic_structured(
        _labelled_frame(), limit=100, identity_labels=("compliance",))
    assert all(row["from"] != row["to"] for row in summary["app_to_app"])


# ----- group_by reaches every label dimension -----

@pytest.mark.parametrize("name,expected", [
    ("source_bu", "src_bu"),
    ("destination_bu", "dst_bu"),
    ("dest_compliance", "dst_compliance"),
    ("src_bu", "src_bu"),
    ("source_app", "src_app"),
])
def test_group_by_resolves_any_label_dimension(name, expected):
    from illumio_mcp.tools.traffic import resolve_group_by
    cols, unknown = resolve_group_by(_labelled_frame(), [name])
    assert not unknown, f"{name} was rejected"
    assert expected in cols


def test_group_by_is_case_insensitive_for_label_keys():
    """Label keys preserve case (DFIRBubble) but nobody types them that way.
    Lowercasing the lookup used to make the column unreachable."""
    from illumio_mcp.tools.traffic import resolve_group_by
    cols, unknown = resolve_group_by(_labelled_frame(), ["source_dfirbubble"])
    assert not unknown
    assert "src_DFIRBubble" in cols


def test_unknown_dimension_is_still_reported():
    from illumio_mcp.tools.traffic import resolve_group_by
    _, unknown = resolve_group_by(_labelled_frame(), ["source_nonexistent"])
    assert unknown == ["source_nonexistent"]


def test_available_dimensions_lists_the_labels_this_pce_has():
    from illumio_mcp.tools.traffic import available_dimensions
    dims = available_dimensions(_labelled_frame())
    assert "bu" in dims["labels"] and "compliance" in dims["labels"]
    assert "ip" not in dims["labels"], "fixed endpoint columns are not labels"
    assert "source_<label>" in dims["usage"]


def test_identity_labels_survive_the_budget_fitter():
    """It is a list, and an earlier fitter treated every list as a display
    section -- which dropped it from the response entirely."""
    df = _labelled_frame()
    base = summarize_traffic_structured(df, limit=2000, identity_labels=("bu",))
    base["identity_labels"] = ["bu"]
    fitted, _ = _fit_summary_to_budget(df, base, MCP_MAX_RESPONSE_BYTES,
                                       identity_labels=("bu",))
    assert fitted["identity_labels"] == ["bu"]
