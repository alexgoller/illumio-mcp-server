import json
import logging
from datetime import datetime, timedelta
import pandas as pd
import mcp.types as types
from illumio import TrafficQuery
from illumio.explorer.trafficanalysis import TrafficQueryFilter
from illumio.util.jsonutils import Reference
from ..pce import run_sync
from .constants import MCP_BUG_MAX_RESULTS, MCP_MAX_RESPONSE_BYTES
from ..log_scrub import ScrubbedArgs

logger = logging.getLogger('illumio_mcp')


def _build_split_response(df, total_pce_flows, total_grouped_rows):
    """Build a compact MCP response using split format (columns + data arrays).

    Split format avoids repeating column names per row — ~60-70% smaller than
    orient='records' for typical traffic data.  Includes metadata so the LLM
    knows whether results were truncated and how much data exists.
    """
    df = df.sort_values('num_connections', ascending=False).reset_index(drop=True)

    def _serialize(frame):
        # NaN → null: astype(object) prevents pandas from coercing None back to NaN
        clean = frame.astype(object).where(frame.notna(), None)
        return json.dumps({
            "total_pce_flows": total_pce_flows,
            "total_rows": total_grouped_rows,
            "returned_rows": len(frame),
            "truncated": len(frame) < total_grouped_rows,
            "columns": frame.columns.tolist(),
            "data": clean.values.tolist(),
        }, default=str)

    payload = _serialize(df)
    if len(payload) <= MCP_MAX_RESPONSE_BYTES:
        return payload

    # Binary search for the largest row count that fits
    lo, hi = 1, len(df)
    best = df.head(1)
    while lo <= hi:
        mid = (lo + hi) // 2
        candidate = df.head(mid)
        size = len(_serialize(candidate))
        if size <= MCP_MAX_RESPONSE_BYTES:
            best = candidate
            lo = mid + 1
        else:
            hi = mid - 1

    logger.warning(f"Truncated response from {len(df)} to {len(best)} rows to fit MCP limit ({MCP_MAX_RESPONSE_BYTES} bytes)")
    return _serialize(best)


def to_dataframe(pce, flows):

    label_href_map = {}
    value_href_map = {}
    for l in pce.labels.get(params={'max_results': 10000}):
        label_href_map[l.href] = {"key": l.key, "value": l.value}
        value_href_map["{}={}".format(l.key, l.value)] = l.href

    if not flows:
        logger.warning("Warning: Empty flows list received.")
        return pd.DataFrame()

    series_array = []
    for flow in flows:
        try:
            f = {
                'src_ip': flow.src.ip,
                'src_hostname': flow.src.workload.name if flow.src.workload is not None else None,
                'dst_ip': flow.dst.ip,
                'dst_hostname': flow.dst.workload.name if flow.dst.workload is not None else None,
                'proto': flow.service.proto,
                'port': flow.service.port,
                'process_name': flow.service.process_name,
                'service_name': flow.service.service_name,
                'policy_decision': flow.policy_decision,
                'flow_direction': flow.flow_direction,
                'num_connections': flow.num_connections,
                'first_detected': flow.timestamp_range.first_detected,
                'last_detected': flow.timestamp_range.last_detected,
            }

            # Add IP list names for src and dst
            if flow.src.ip_lists:
                ip_list_names = [ipl.name for ipl in flow.src.ip_lists if hasattr(ipl, 'name') and ipl.name]
                f['src_ip_lists'] = ', '.join(ip_list_names) if ip_list_names else None
            else:
                f['src_ip_lists'] = None

            if flow.dst.ip_lists:
                ip_list_names = [ipl.name for ipl in flow.dst.ip_lists if hasattr(ipl, 'name') and ipl.name]
                f['dst_ip_lists'] = ', '.join(ip_list_names) if ip_list_names else None
            else:
                f['dst_ip_lists'] = None

            # Add src and dst labels from workloads
            if flow.src.workload:
                for l in flow.src.workload.labels:
                    if l.href in label_href_map:
                        key = label_href_map[l.href]['key']
                        value = label_href_map[l.href]['value']
                        f[f'src_{key}'] = value

            if flow.dst.workload:
                for l in flow.dst.workload.labels:
                    if l.href in label_href_map:
                        key = label_href_map[l.href]['key']
                        value = label_href_map[l.href]['value']
                        f[f'dst_{key}'] = value

            series_array.append(f)
        except AttributeError as e:
            logger.debug(f"Error processing flow: {e}")
            logger.debug(f"Flow object: {flow}")

    df = pd.DataFrame(series_array)
    return df


def summarize_traffic(df):
    logger.debug(f"Summarizing traffic with dataframe: {df}")

    # Define all possible group columns, including IP list columns and policy decision
    potential_columns = [
        'src_app', 'src_env', 'src_ip_lists',
        'dst_app', 'dst_env', 'dst_ip_lists',
        'proto', 'port', 'policy_decision'
    ]

    # Filter to only use columns that exist in the DataFrame
    group_columns = [col for col in potential_columns if col in df.columns]

    if not group_columns:
        logger.warning("No grouping columns found in DataFrame")
        return "No traffic data available for summarization"

    if df.empty:
        logger.warning("Empty DataFrame received")
        return "No traffic data available for summarization"

    # Fill NaN in IP list columns so groupby works properly
    for col in ['src_ip_lists', 'dst_ip_lists']:
        if col in df.columns:
            df[col] = df[col].fillna('')

    logger.debug(f"Using group columns: {group_columns}")
    logger.debug(f"DataFrame shape before grouping: {df.shape}")
    logger.debug(f"DataFrame columns: {df.columns.tolist()}")
    logger.debug(f"First few rows of DataFrame:\n{df.head()}")

    # Group by available columns
    summary = df.groupby(group_columns)['num_connections'].sum().reset_index()

    logger.debug(f"Summary shape after grouping: {summary.shape}")
    logger.debug(f"Summary columns: {summary.columns.tolist()}")
    logger.debug(f"First few rows of summary:\n{summary.head()}")

    # Sort by number of connections in descending order
    summary = summary.sort_values('num_connections', ascending=False)

    # Convert to a more readable format
    summary_list = []
    for _, row in summary.iterrows():
        # Build source info: prefer app/env labels, fall back to IP list name
        src_info = []
        if 'src_app' in row and row['src_app']:
            src_info.append(row['src_app'])
        if 'src_env' in row and row['src_env']:
            src_info.append(f"({row['src_env']})")
        if not src_info and 'src_ip_lists' in row and row['src_ip_lists']:
            src_info.append(f"[IPList: {row['src_ip_lists']}]")
        src_str = " ".join(src_info) if src_info else "Unknown Source"

        # Build destination info: prefer app/env labels, fall back to IP list name
        dst_info = []
        if 'dst_app' in row and row['dst_app']:
            dst_info.append(row['dst_app'])
        if 'dst_env' in row and row['dst_env']:
            dst_info.append(f"({row['dst_env']})")
        if not dst_info and 'dst_ip_lists' in row and row['dst_ip_lists']:
            dst_info.append(f"[IPList: {row['dst_ip_lists']}]")
        dst_str = " ".join(dst_info) if dst_info else "Unknown Destination"

        if src_str != dst_str:
            port_info = f"port {row['port']}" if 'port' in row else "unknown port"
            proto_info = f"proto {row['proto']}" if 'proto' in row else ""
            policy = row.get('policy_decision', '') if 'policy_decision' in row.index else ''
            policy_str = f" [{policy}]" if policy else ""
            summary_list.append(
                f"From {src_str} to {dst_str} on {port_info} {proto_info}: {row['num_connections']} connections{policy_str}"
            )

    if not summary_list:
        return "No traffic patterns to summarize"

    return "\n".join(summary_list)


def handle_get_traffic_flows(ctx, arguments: dict) -> list:
    logger.debug("=" * 80)
    logger.debug("GET TRAFFIC FLOWS CALLED")
    logger.debug("Arguments received: %s", ScrubbedArgs(arguments))

    # assume a default start date of 1 day ago and end date of now
    if 'start_date' not in arguments:
        arguments['start_date'] = (datetime.now() - timedelta(days=1)).strftime('%Y-%m-%d')
    if 'end_date' not in arguments:
        arguments['end_date'] = datetime.now().strftime('%Y-%m-%d')

    if not arguments or 'start_date' not in arguments or 'end_date' not in arguments:
        error_msg = "Missing required arguments: 'start_date' and 'end_date' are required"
        logger.error(error_msg)
        return [types.TextContent(
            type="text",
            text=json.dumps({"error": error_msg})
        )]

    logger.debug(f"Start Date: {arguments.get('start_date')}")
    logger.debug(f"End Date: {arguments.get('end_date')}")
    logger.debug(f"Include Sources: {arguments.get('include_sources', [])}")
    logger.debug(f"Exclude Sources: {arguments.get('exclude_sources', [])}")
    logger.debug(f"Include Destinations: {arguments.get('include_destinations', [])}")
    logger.debug(f"Exclude Destinations: {arguments.get('exclude_destinations', [])}")
    logger.debug(f"Include Services: {arguments.get('include_services', [])}")
    logger.debug(f"Exclude Services: {arguments.get('exclude_services', [])}")
    logger.debug(f"Policy Decisions: {arguments.get('policy_decisions', [])}")
    logger.debug(f"Exclude Workloads from IP List: {arguments.get('exclude_workloads_from_ip_list_query', True)}")
    logger.debug(f"Max Results: {arguments.get('max_results', 900)}")
    logger.debug(f"Query Name: {arguments.get('query_name')}")
    logger.debug("=" * 80)

    try:
        pce = ctx.pce

        logger.debug(f"Due to a condition in MCP, max results is set to {MCP_BUG_MAX_RESULTS}")
        arguments['max_results'] = MCP_BUG_MAX_RESULTS

        traffic_query = TrafficQuery.build(
            start_date=arguments['start_date'],
            end_date=arguments['end_date'],
            include_sources=arguments.get('include_sources', [[]]),
            exclude_sources=arguments.get('exclude_sources', []),
            include_destinations=arguments.get('include_destinations', [[]]),
            exclude_destinations=arguments.get('exclude_destinations', []),
            include_services=arguments.get('include_services', []),
            exclude_services=arguments.get('exclude_services', []),
            policy_decisions=arguments.get('policy_decisions', []),
            exclude_workloads_from_ip_list_query=arguments.get('exclude_workloads_from_ip_list_query', True),
            max_results=arguments.get('max_results', 10000),
            query_name=arguments.get('query_name', 'mcp-traffic-query')
        )

        # Use async query with Accept: application/json header
        # PCE 25.x returns CSV by default on download endpoint
        all_traffic = pce.get_traffic_flows_async(
            query_name=arguments.get('query_name', 'mcp-traffic-query'),
            traffic_query=traffic_query,
            headers={'Accept': 'application/json'}
        )

        df = to_dataframe(pce, all_traffic)

        if df.empty:
            return [types.TextContent(
                type="text",
                text=json.dumps({"message": "No traffic flows found for the given query parameters",
                                 "start_date": arguments['start_date'],
                                 "end_date": arguments['end_date']})
            )]

        # Group by columns that exist, always including IP list names
        group_cols = ['src_ip', 'dst_ip', 'proto', 'port', 'policy_decision']
        for col in ['src_ip_lists', 'dst_ip_lists', 'src_hostname', 'dst_hostname']:
            if col in df.columns:
                group_cols.append(col)
        group_cols = [c for c in group_cols if c in df.columns]
        df = df.groupby(group_cols).agg({'num_connections': 'sum'}).reset_index()

        total_grouped_rows = len(df)
        payload = _build_split_response(df, total_pce_flows=len(all_traffic), total_grouped_rows=total_grouped_rows)
        del df

        return [types.TextContent(
            type="text",
            text=payload
        )]
    except Exception as e:
        error_msg = f"Failed in PCE operation: {str(e)}"
        logger.error(error_msg, exc_info=True)
        return [types.TextContent(
            type="text",
            text=json.dumps({"error": error_msg})
        )]


def handle_get_traffic_flows_summary(ctx, arguments: dict) -> list:
    logger.debug("=" * 80)
    logger.debug("GET TRAFFIC FLOWS SUMMARY CALLED")
    logger.debug("Arguments received: %s", ScrubbedArgs(arguments))
    logger.debug(f"Start Date: {arguments.get('start_date')}")
    logger.debug(f"End Date: {arguments.get('end_date')}")
    logger.debug(f"Include Sources: {arguments.get('include_sources', [])}")
    logger.debug(f"Exclude Sources: {arguments.get('exclude_sources', [])}")
    logger.debug(f"Include Destinations: {arguments.get('include_destinations', [])}")
    logger.debug(f"Exclude Destinations: {arguments.get('exclude_destinations', [])}")
    logger.debug(f"Include Services: {arguments.get('include_services', [])}")
    logger.debug(f"Exclude Services: {arguments.get('exclude_services', [])}")
    logger.debug(f"Policy Decisions: {arguments.get('policy_decisions', [])}")
    logger.debug(f"Exclude Workloads from IP List: {arguments.get('exclude_workloads_from_ip_list_query', True)}")
    logger.debug(f"Max Results: {arguments.get('max_results', 10000)}")
    logger.debug(f"Query Name: {arguments.get('query_name')}")
    logger.debug("=" * 80)

    try:
        pce = ctx.pce

        logger.debug(f"Due to a condition in MCP, max results is set to {MCP_BUG_MAX_RESULTS}")
        max_results = int(arguments.get('max_results', 10000))
        if max_results > MCP_BUG_MAX_RESULTS:
            logger.debug(f"Setting max results to {MCP_BUG_MAX_RESULTS} from original value {max_results}")
            max_results = MCP_BUG_MAX_RESULTS
        arguments['max_results'] = max_results

        query = TrafficQuery.build(
            start_date=arguments['start_date'],
            end_date=arguments['end_date'],
            include_sources=arguments.get('include_sources', [[]]),
            exclude_sources=arguments.get('exclude_sources', []),
            include_destinations=arguments.get('include_destinations', [[]]),
            exclude_destinations=arguments.get('exclude_destinations', []),
            include_services=arguments.get('include_services', []),
            exclude_services=arguments.get('exclude_services', []),
            policy_decisions=arguments.get('policy_decisions', []),
            exclude_workloads_from_ip_list_query=arguments.get('exclude_workloads_from_ip_list_query', True),
            max_results=arguments.get('max_results', 10000),
            query_name=arguments.get('query_name', 'mcp-traffic-summary')
        )

        # Use async query with Accept: application/json header
        # PCE 25.x returns CSV by default on download endpoint
        all_traffic = pce.get_traffic_flows_async(
            query_name=arguments.get('query_name', 'mcp-traffic-summary'),
            traffic_query=query,
            headers={'Accept': 'application/json'}
        )

        df = to_dataframe(pce, all_traffic)
        summary = summarize_traffic(df)

        summary_lines = ""
        # Ensure the summary is a list of strings
        if isinstance(summary, list):
            # join list to be one string separated by newlines
            summary_lines = "\n".join(summary)
        else:
            summary_lines = str(summary)

        logger.debug(f"Summary data type: {type(summary_lines)}")
        logger.debug(f"Summary size: {len(summary_lines)}")

        return [types.TextContent(
            type="text",
            text=summary_lines
        )]
    except Exception as e:
        error_msg = f"Failed in PCE operation: {str(e)}"
        logger.error(error_msg, exc_info=True)
        return [types.TextContent(
            type="text",
            text=json.dumps({"error": error_msg})
        )]


def handle_find_unmanaged_traffic(ctx, arguments: dict) -> list:
    logger.debug("=" * 80)
    logger.debug("FIND UNMANAGED TRAFFIC CALLED")
    logger.debug("Arguments received: %s", ScrubbedArgs(arguments))
    logger.debug("=" * 80)

    try:
        pce = ctx.pce

        lookback_days = arguments.get("lookback_days", 30)
        direction = arguments.get("direction", "both")
        min_connections = arguments.get("min_connections", 1)
        top_n = arguments.get("top_n", 50)

        start_date = (datetime.now() - timedelta(days=lookback_days)).strftime('%Y-%m-%d')
        end_date = datetime.now().strftime('%Y-%m-%d')

        traffic_query = TrafficQuery.build(
            start_date=start_date,
            end_date=end_date,
            policy_decisions=["allowed", "potentially_blocked", "blocked"],
            max_results=MCP_BUG_MAX_RESULTS,
            query_name='unmanaged-traffic'
        )

        flows = pce.get_traffic_flows_async(query_name='unmanaged-traffic', traffic_query=traffic_query)
        df = to_dataframe(pce, flows)

        if df.empty:
            return [types.TextContent(type="text", text=json.dumps({
                "message": "No traffic flows found", "lookback_days": lookback_days
            }, indent=2))]

        results = {"unmanaged_sources": [], "unmanaged_destinations": []}

        # Find traffic from unmanaged sources (no src_app label) to managed destinations
        if direction in ("inbound", "both"):
            if 'src_app' in df.columns and 'dst_app' in df.columns:
                unmanaged_src = df[df['src_app'].isna() & df['dst_app'].notna()].copy()
                if not unmanaged_src.empty:
                    group_cols = ['src_ip']
                    if 'dst_app' in unmanaged_src.columns:
                        group_cols.append('dst_app')
                    if 'dst_env' in unmanaged_src.columns:
                        group_cols.append('dst_env')
                    if 'port' in unmanaged_src.columns:
                        group_cols.append('port')
                    if 'proto' in unmanaged_src.columns:
                        group_cols.append('proto')

                    grouped = unmanaged_src.groupby(group_cols)['num_connections'].sum().reset_index()
                    grouped = grouped[grouped['num_connections'] >= min_connections]
                    grouped = grouped.sort_values('num_connections', ascending=False).head(top_n)

                    for _, row in grouped.iterrows():
                        entry = {
                            "src_ip": row.get('src_ip', ''),
                            "dst_app": row.get('dst_app', ''),
                            "dst_env": row.get('dst_env', ''),
                            "port": int(row['port']) if 'port' in row and pd.notna(row['port']) else None,
                            "proto": int(row['proto']) if 'proto' in row and pd.notna(row['proto']) else None,
                            "connections": int(row['num_connections'])
                        }
                        results["unmanaged_sources"].append(entry)

        # Find traffic to unmanaged destinations (no dst_app label) from managed sources
        if direction in ("outbound", "both"):
            if 'src_app' in df.columns and 'dst_app' in df.columns:
                unmanaged_dst = df[df['dst_app'].isna() & df['src_app'].notna()].copy()
                if not unmanaged_dst.empty:
                    group_cols = ['dst_ip']
                    if 'src_app' in unmanaged_dst.columns:
                        group_cols.append('src_app')
                    if 'src_env' in unmanaged_dst.columns:
                        group_cols.append('src_env')
                    if 'port' in unmanaged_dst.columns:
                        group_cols.append('port')
                    if 'proto' in unmanaged_dst.columns:
                        group_cols.append('proto')

                    grouped = unmanaged_dst.groupby(group_cols)['num_connections'].sum().reset_index()
                    grouped = grouped[grouped['num_connections'] >= min_connections]
                    grouped = grouped.sort_values('num_connections', ascending=False).head(top_n)

                    for _, row in grouped.iterrows():
                        entry = {
                            "dst_ip": row.get('dst_ip', ''),
                            "src_app": row.get('src_app', ''),
                            "src_env": row.get('src_env', ''),
                            "port": int(row['port']) if 'port' in row and pd.notna(row['port']) else None,
                            "proto": int(row['proto']) if 'proto' in row and pd.notna(row['proto']) else None,
                            "connections": int(row['num_connections'])
                        }
                        results["unmanaged_destinations"].append(entry)

        result = {
            "lookback_days": lookback_days,
            "direction_filter": direction,
            "min_connections": min_connections,
            "unmanaged_source_count": len(results["unmanaged_sources"]),
            "unmanaged_destination_count": len(results["unmanaged_destinations"]),
            "unmanaged_sources": results["unmanaged_sources"],
            "unmanaged_destinations": results["unmanaged_destinations"],
            "recommendation": (
                "Unmanaged traffic represents policy blind spots. Consider: "
                "1) Creating IP lists for known external services, "
                "2) Deploying VEN agents on unmanaged workloads, "
                "3) Adding rules for legitimate unmanaged traffic sources."
            )
        }

        return [types.TextContent(type="text", text=json.dumps(result, indent=2))]

    except Exception as e:
        error_msg = f"Failed to find unmanaged traffic: {str(e)}"
        logger.error(error_msg, exc_info=True)
        return [types.TextContent(type="text", text=json.dumps({"error": error_msg}, indent=2))]
