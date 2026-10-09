"""Identity-centric view of traffic: who acted, from where, on what, when."""
import json
import logging
from datetime import datetime, timedelta

import mcp.types as types

from ..errors import describe_error
from ..identity_graph import build_identity_graph, reach_findings
from ..log_scrub import ScrubbedArgs
from .constants import MCP_MAX_RESPONSE_BYTES, MCP_QUERY_MAX_RESULTS
from .traffic import (classify_destination, fetch_flows_raw, raw_flows_to_dataframe,
                      to_query_start, to_query_end, _resolve_label_filters,
                      _unresolved_error, _normalise_filter)

logger = logging.getLogger('illumio_mcp')

# Edges are the largest part of the payload -- a month of a mid-size estate is
# ~2,500 -- so they are opt-in and capped. The identity rollup answers most
# questions without them.
MAX_EDGES = 400


def handle_build_identity_graph(ctx, arguments: dict) -> list:
    """Aggregate flows by the account the communicating process ran as."""
    logger.debug("BUILD IDENTITY GRAPH: %s", ScrubbedArgs(arguments))
    arguments = arguments or {}
    try:
        pce = ctx.pce
        lookback = int(arguments.get('lookback_days', 30))
        start = arguments.get('start_date') or (
            datetime.now() - timedelta(days=lookback)).strftime('%Y-%m-%d')
        end = arguments.get('end_date') or datetime.now().strftime('%Y-%m-%d')

        unresolved = _resolve_label_filters(pce, arguments)
        problem = _unresolved_error(unresolved, pce)
        if problem:
            return [types.TextContent(type="text", text=json.dumps(problem))]

        window = (to_query_start(start), to_query_end(end))
        from illumio.explorer import TrafficQuery
        query = TrafficQuery.build(
            start_date=window[0],
            end_date=window[1],
            include_sources=_normalise_filter(arguments.get('include_sources')),
            include_destinations=_normalise_filter(arguments.get('include_destinations')),
            policy_decisions=arguments.get('policy_decisions', []),
            # Aggregated before responding, so pull the whole window.
            max_results=MCP_QUERY_MAX_RESULTS,
            query_name='identity-graph',
        )
        df = raw_flows_to_dataframe(pce, fetch_flows_raw(pce, query, 'identity-graph'))

        graph = build_identity_graph(
            df,
            include_service_accounts=arguments.get('include_service_accounts', True),
            identity_filter=arguments.get('identity'),
            top=int(arguments.get('top', 10)),
            attribute=classify_destination,
            window=window,
        )
        payload = {
            "window": {"start": start, "end": end,
                       **({"data_span": graph["data_span"]} if graph.get("data_span") else {})},
            "metrics_note": (
                "activity_density is an upper bound: active_days counts every day "
                "a flow row covers, and Explorer aggregates a persistent connection "
                "into one row. days_with_new_flows is the matching lower bound."
            ),
            "totals": graph["totals"],
            "findings": reach_findings(graph),
            "identities": graph["identities"],
        }
        if not payload["totals"]["rows_with_identity"]:
            payload["note"] = (
                "No flow in this window carried a user_name. The PCE records one "
                "only when the VEN could attribute the flow to an account, so "
                "this is a visibility gap, not an absence of activity."
            )
        if arguments.get('include_edges'):
            edges = graph["edges"]
            payload["edges"] = edges[:MAX_EDGES]
            if len(edges) > MAX_EDGES:
                payload["edges_truncated"] = {
                    "shown": MAX_EDGES, "total": len(edges),
                    "note": ("Edges are ranked by connections. Filter with "
                             "`identity` to see one account's full traversal."),
                }

        text = json.dumps(payload, default=str, indent=2)
        if len(text) > MCP_MAX_RESPONSE_BYTES:
            payload.pop("edges", None)
            payload["identities"] = payload["identities"][:25]
            payload["response_trimmed"] = (
                "Identities trimmed to the 25 busiest and edges dropped to fit the "
                "response limit. `totals` still describes the whole window."
            )
            text = json.dumps(payload, default=str, indent=2)
        return [types.TextContent(type="text", text=text)]

    except Exception as e:
        logger.error("identity graph failed: %s", e, exc_info=True)
        return [types.TextContent(type="text", text=json.dumps(
            {"error": f"Failed to build identity graph: {describe_error(e)}"}))]
