"""get-traffic-fingerprint: a snapshot of an org's, environment's or app's
traffic shape, and the drift against an earlier one.

The queries and the response fit live here; the format and the compare are
in `illumio_mcp.fingerprint`. Read-only: one Explorer query for the window,
a second for the window before it when `baseline_days` is given.
"""
import json
import logging
from datetime import datetime, timedelta, timezone

import mcp.types as types
from illumio import TrafficQuery

from .. import fingerprint as fp
from ..errors import describe_error
from ..log_scrub import ScrubbedArgs
from .constants import MCP_MAX_RESPONSE_BYTES, MCP_QUERY_MAX_RESULTS
from .traffic import (
    _normalise_filter, _resolve_label_filters, _unresolved_error,
    check_window, fetch_flows_raw, raw_flows_to_dataframe,
    to_query_end, to_query_start,
)

logger = logging.getLogger("illumio_mcp.tools.fingerprint")

DEFAULT_LOOKBACK_DAYS = 7
MAX_BASELINE_DAYS = 365
LIST_CAPS = (200, 50, 0)


def _error(message: str, **extra) -> list:
    return [types.TextContent(type="text", text=json.dumps({"error": message, **extra}))]


def _scope(arguments: dict) -> tuple[dict, list[str]]:
    """The scope and the label shorthand that narrows the query to it."""
    raw = arguments.get("scope") or {}
    if not isinstance(raw, dict):
        raise ValueError("scope must be an object: {app, env}, {env} or omitted for the org")
    app = raw.get("app") or None
    env = raw.get("env") or None
    kind = "app" if app else "env" if env else "org"
    labels = [f"app={app}"] if app else []
    if env:
        labels.append(f"env={env}")
    return {"kind": kind, "app": app, "env": env}, labels


def _query(pce, start: str, end: str, labels: list[str], arguments: dict,
           max_results: int, name: str) -> tuple[TrafficQuery | None, dict | None]:
    """One Explorer query over [start, end] narrowed to the scope's labels on
    either side (`or`), or the error that stops it."""
    filters = {"include_sources": list(labels), "include_destinations": list(labels)}
    problems = _resolve_label_filters(pce, filters)
    # The same shorthand is resolved on both sides; name it once.
    problems.unresolved = list(dict.fromkeys(problems.unresolved))
    problem = _unresolved_error(problems, pce)
    if problem:
        return None, problem
    query = TrafficQuery.build(
        start_date=start, end_date=end,
        include_sources=_normalise_filter(filters["include_sources"]),
        include_destinations=_normalise_filter(filters["include_destinations"]),
        policy_decisions=arguments.get("policy_decisions", []),
        exclude_workloads_from_ip_list_query=arguments.get(
            "exclude_workloads_from_ip_list_query", True),
        max_results=max_results,
        query_name=name,
    )
    if labels:
        # The app on either side: its inbound and its outbound in one answer.
        query.sources_destinations_query_op = "or"
    return query, None


def _fetch(pce, query, name: str, max_results: int) -> tuple:
    """The frame for one query and what the PCE said about its completeness."""
    meta: dict = {}
    flows = fetch_flows_raw(pce, query, name, meta=meta)
    truncated = len(flows) >= max_results
    coverage = {"pce_flows": len(flows), "truncated": truncated, "truncated_at": max_results}
    if isinstance(meta.get("raw_observations"), int):
        coverage["raw_observations"] = meta["raw_observations"]
    if truncated:
        coverage["note"] = (f"Hit the {max_results}-row cap, so this is a partial view: "
                            f"keys the PCE did not return are missing. Narrow the scope "
                            f"or the window, or raise max_results.")
    return raw_flows_to_dataframe(pce, flows), coverage


def _fit(body: dict) -> str:
    """The response within the budget: whole, else without the key list, else
    with the compare lists cut. The metrics and counts always survive."""
    payload = json.dumps(body)
    if len(payload) <= MCP_MAX_RESPONSE_BYTES:
        return payload
    print_ = body["fingerprint"]
    print_["keys"] = []
    print_["keys_omitted"] = True
    print_["keys_note"] = (
        f"The {print_['totals']['keys']} keys were left out: the fingerprint exceeded "
        f"the {MCP_MAX_RESPONSE_BYTES // 1000} KB response budget. This fingerprint "
        f"cannot serve as a `baseline` later; use baseline_days for an in-call compare, "
        f"or a narrower scope (an env or an app) for one that can.")
    payload = json.dumps(body)
    compare = body.get("compare")
    for cap in LIST_CAPS:
        if len(payload) <= MCP_MAX_RESPONSE_BYTES or not compare or "new" not in compare:
            break
        for section in ("new", "changed", "gone"):
            compare[section] = compare[section][:cap]
        compare["lists_capped_at"] = cap
        payload = json.dumps(body)
    return payload


def handle_get_traffic_fingerprint(ctx, arguments: dict) -> list:
    logger.debug("GET TRAFFIC FINGERPRINT CALLED: %s", ScrubbedArgs(arguments))
    arguments = dict(arguments or {})
    try:
        pce = ctx.pce
        scope, labels = _scope(arguments)
        identity_labels = tuple(arguments.get("identity_labels") or fp.DEFAULT_IDENTITY_LABELS)

        baseline = arguments.get("baseline")
        baseline_days = arguments.get("baseline_days")
        if baseline is not None and baseline_days is not None:
            return _error("give either baseline (a fingerprint returned earlier) or "
                          "baseline_days (query the window before this one), not both")
        if baseline_days is not None:
            baseline_days = int(baseline_days)
            if not 1 <= baseline_days <= MAX_BASELINE_DAYS:
                return _error(f"baseline_days must be 1..{MAX_BASELINE_DAYS}, got {baseline_days}")

        # The default window is exactly lookback_days long and ends now, so
        # baseline_days=lookback_days is a like-for-like compare. Calendar-day
        # defaults (midnight to 23:59:59) would make "7 days" 8 days long and
        # every default compare warn about unequal windows.
        lookback = int(arguments.get("lookback_days", DEFAULT_LOOKBACK_DAYS))
        if lookback < 1:
            return _error(f"lookback_days must be at least 1, got {lookback}")
        now = datetime.now(timezone.utc).replace(microsecond=0)
        end = (to_query_end(arguments["end_date"]) if arguments.get("end_date")
               else now.strftime("%Y-%m-%dT%H:%M:%SZ"))
        start = (to_query_start(arguments["start_date"]) if arguments.get("start_date")
                 else (fp._parse(end) - timedelta(days=lookback)).strftime("%Y-%m-%dT%H:%M:%SZ"))
        check_window(start, end)
        max_results = min(int(arguments.get("max_results", MCP_QUERY_MAX_RESULTS)),
                          MCP_QUERY_MAX_RESULTS)
        filters = {k: arguments[k] for k in ("policy_decisions",) if arguments.get(k)}

        query, problem = _query(pce, start, end, labels, arguments, max_results,
                                "mcp-traffic-fingerprint")
        if problem:
            return [types.TextContent(type="text", text=json.dumps(problem))]

        pce_id = {"host": f"{pce._hostname}:{pce._port}", "org_id": pce.org_id}
        window = {"start": start, "end": end}
        df, coverage = _fetch(pce, query, "mcp-traffic-fingerprint", max_results)
        current = fp.build_fingerprint(df, pce=pce_id, scope=scope, window=window,
                                       coverage=coverage, identity_labels=identity_labels,
                                       filters=filters)
        body = {"fingerprint": current}

        if baseline_days is not None:
            b_end = fp._parse(start)
            b_start = b_end - timedelta(days=baseline_days)
            b_window = {"start": b_start.strftime("%Y-%m-%dT%H:%M:%SZ"),
                        "end": b_end.strftime("%Y-%m-%dT%H:%M:%SZ")}
            b_query, problem = _query(pce, b_window["start"], b_window["end"], labels,
                                      arguments, max_results, "mcp-traffic-fingerprint-baseline")
            if problem:
                return [types.TextContent(type="text", text=json.dumps(problem))]
            b_df, b_coverage = _fetch(pce, b_query, "mcp-traffic-fingerprint-baseline",
                                      max_results)
            baseline = fp.build_fingerprint(b_df, pce=pce_id, scope=scope, window=b_window,
                                            coverage=b_coverage,
                                            identity_labels=identity_labels, filters=filters)
        if baseline is not None:
            body["compare"] = fp.compare_fingerprints(current, baseline)

        return [types.TextContent(type="text", text=_fit(body))]
    except ValueError as e:
        return _error(str(e))
    except Exception as e:
        error_msg = f"Failed in PCE operation: {describe_error(e)}"
        logger.error(error_msg, exc_info=True)
        return _error(error_msg)
