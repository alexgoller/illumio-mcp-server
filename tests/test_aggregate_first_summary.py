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
