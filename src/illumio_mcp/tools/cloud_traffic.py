import json
import logging
import pandas as pd
import mcp.types as types
from ..cloud_client import CloudTrafficClient
from .constants import MCP_MAX_RESPONSE_BYTES

logger = logging.getLogger('illumio_mcp')

_NOT_CONFIGURED = json.dumps({
    "error": "Cloud Traffic API not configured. Set CLOUD_TRAFFIC_API_KEY, CLOUD_TRAFFIC_API_SECRET, and CLOUD_API_HOST."
})


def _truncate_split(df, metadata, max_bytes=MCP_MAX_RESPONSE_BYTES):
    """Serialize DataFrame as split-format JSON, truncating to fit max_bytes."""
    def _serialize(frame, trunc):
        clean = frame.astype(object).where(frame.notna(), None)
        envelope = {**metadata, "returned": len(frame), "truncated": trunc,
                    "columns": frame.columns.tolist(), "data": clean.values.tolist()}
        return json.dumps(envelope, default=str)

    payload = _serialize(df, False)
    if len(payload) <= max_bytes:
        return payload

    lo, hi = 1, len(df)
    best = df.head(1)
    while lo <= hi:
        mid = (lo + hi) // 2
        if len(_serialize(df.head(mid), True)) <= max_bytes:
            best = df.head(mid)
            lo = mid + 1
        else:
            hi = mid - 1

    logger.warning(f"Truncated cloud traffic flows from {len(df)} to {len(best)} rows")
    return _serialize(best, True)


def _flow_to_row(flow):
    """Flatten a unified traffic flow into a flat dict for DataFrame."""
    src = flow.get("src", {})
    dst = flow.get("dst", {})
    service = flow.get("service", {})

    row = {
        "src_ip": src.get("ip"),
        "dst_ip": dst.get("ip"),
        "proto": service.get("proto"),
        "port": service.get("port"),
        "policy_decision": flow.get("policy_decision"),
        "boundary_decision": flow.get("boundary_decision"),
        "num_connections": flow.get("num_connections", 0),
        "flow_direction": flow.get("flow_direction"),
    }

    # Source identity: workload or cloud_resource
    src_wl = src.get("workload")
    src_cr = src.get("cloud_resource")
    if src_wl:
        row["src_name"] = src_wl.get("name") or src_wl.get("hostname")
        row["src_type"] = "workload"
    elif src_cr:
        row["src_name"] = src_cr.get("resource_uuid")
        row["src_type"] = f"cloud:{src_cr.get('type', '')}"

    # Destination identity
    dst_wl = dst.get("workload")
    dst_cr = dst.get("cloud_resource")
    if dst_wl:
        row["dst_name"] = dst_wl.get("name") or dst_wl.get("hostname")
        row["dst_type"] = "workload"
    elif dst_cr:
        row["dst_name"] = dst_cr.get("resource_uuid")
        row["dst_type"] = f"cloud:{dst_cr.get('type', '')}"

    # FQDN
    if src.get("fqdn_name"):
        row["src_fqdn"] = src["fqdn_name"]
    if dst.get("fqdn_name"):
        row["dst_fqdn"] = dst["fqdn_name"]

    # Timestamps
    ts = flow.get("timestamp_range", {})
    row["first_detected"] = ts.get("first_detected")
    row["last_detected"] = ts.get("last_detected")

    return row


def handle_cloud_get_traffic_queries(arguments: dict) -> list:
    logger.debug("=" * 80)
    logger.debug("CLOUD GET TRAFFIC QUERIES CALLED")
    logger.debug("=" * 80)

    if not CloudTrafficClient.is_configured():
        return [types.TextContent(type="text", text=_NOT_CONFIGURED)]

    try:
        client = CloudTrafficClient.get_instance()
        resp = client.get_queries()

        queries = resp.get("info", [])
        result = {
            "total_queries": len(queries),
            "queries": [{
                "query_id": q.get("query_id"),
                "status": q.get("status"),
                "query_name": q.get("query_parameters", {}).get("query_name"),
                "matches_count": q.get("matches_count"),
                "flows_count": q.get("flows_count"),
                "created_at": q.get("created_at"),
                "updated_at": q.get("updated_at"),
                "download_url": q.get("result"),
            } for q in queries]
        }

        return [types.TextContent(type="text", text=json.dumps(result, indent=2))]

    except Exception as e:
        error_msg = f"Failed in Cloud Traffic API: {str(e)}"
        logger.error(error_msg, exc_info=True)
        return [types.TextContent(type="text", text=json.dumps({"error": error_msg}))]


def handle_cloud_create_traffic_query(arguments: dict) -> list:
    logger.debug("=" * 80)
    logger.debug("CLOUD CREATE TRAFFIC QUERY CALLED")
    logger.debug(f"Arguments received: {json.dumps(arguments, indent=2)}")
    logger.debug("=" * 80)

    if not CloudTrafficClient.is_configured():
        return [types.TextContent(type="text", text=_NOT_CONFIGURED)]

    try:
        client = CloudTrafficClient.get_instance()

        # Build query body from arguments
        body = {
            "query_name": arguments.get("query_name", "mcp-cloud-traffic-query"),
            "start_date": arguments["start_date"],
            "end_date": arguments["end_date"],
            "max_results": arguments.get("max_results", 10000),
        }

        # Sources/destinations filters
        for key in ["sources", "destinations"]:
            if arguments.get(key):
                body[key] = arguments[key]
            else:
                body[key] = {"include": []}

        # Services filter
        if arguments.get("services"):
            body["services"] = arguments["services"]

        # Policy/boundary decisions
        if arguments.get("policy_decisions"):
            body["policy_decisions"] = arguments["policy_decisions"]
        if arguments.get("boundary_decisions"):
            body["boundary_decisions"] = arguments["boundary_decisions"]

        # Data sources
        if arguments.get("data_sources"):
            body["data_sources"] = arguments["data_sources"]

        # Optional flags
        if "sources_destinations_query_op" in arguments:
            body["sources_destinations_query_op"] = arguments["sources_destinations_query_op"]
        if "exclude_workloads_from_ip_list_query" in arguments:
            body["exclude_workloads_from_ip_list_query"] = arguments["exclude_workloads_from_ip_list_query"]
        if "aggregate_lows_across_days" in arguments:
            body["aggregate_lows_across_days"] = arguments["aggregate_lows_across_days"]

        resp = client.create_query(body)

        # Response contains the query info
        queries = resp.get("info", [])
        if queries:
            q = queries[0]
            result = {
                "message": "Traffic query created",
                "query_id": q.get("query_id"),
                "status": q.get("status"),
                "download_url": q.get("result"),
            }
        else:
            result = {"message": "Traffic query submitted", "response": resp}

        return [types.TextContent(type="text", text=json.dumps(result, indent=2))]

    except Exception as e:
        error_msg = f"Failed in Cloud Traffic API: {str(e)}"
        logger.error(error_msg, exc_info=True)
        return [types.TextContent(type="text", text=json.dumps({"error": error_msg}))]


def handle_cloud_get_traffic_flows(arguments: dict) -> list:
    logger.debug("=" * 80)
    logger.debug("CLOUD GET TRAFFIC FLOWS CALLED")
    logger.debug(f"Arguments received: {json.dumps(arguments, indent=2)}")
    logger.debug("=" * 80)

    if not CloudTrafficClient.is_configured():
        return [types.TextContent(type="text", text=_NOT_CONFIGURED)]

    try:
        client = CloudTrafficClient.get_instance()

        query_id = arguments["query_id"]
        offset = arguments.get("offset", 0)
        limit = arguments.get("limit", 5000)

        resp = client.download_flows(query_id, offset=offset, limit=limit)
        flows = resp.get("flows", [])

        if not flows:
            return [types.TextContent(type="text", text=json.dumps({
                "message": "No traffic flows returned. The query may still be running — check status with cloud-get-traffic-queries.",
                "query_id": query_id, "offset": offset, "limit": limit
            }))]

        # Flatten flows to DataFrame
        rows = [_flow_to_row(f) for f in flows]
        df = pd.DataFrame(rows)

        # Group to reduce volume
        group_cols = [c for c in ["src_ip", "dst_ip", "proto", "port", "policy_decision",
                                   "boundary_decision", "src_name", "dst_name", "src_type", "dst_type"]
                      if c in df.columns]
        if group_cols and "num_connections" in df.columns:
            df = df.groupby(group_cols, dropna=False).agg({"num_connections": "sum"}).reset_index()
            df = df.sort_values("num_connections", ascending=False).reset_index(drop=True)

        metadata = {"query_id": query_id, "total_flows": len(flows), "total_grouped_rows": len(df)}
        payload = _truncate_split(df, metadata)

        return [types.TextContent(type="text", text=payload)]

    except Exception as e:
        error_msg = f"Failed in Cloud Traffic API: {str(e)}"
        logger.error(error_msg, exc_info=True)
        return [types.TextContent(type="text", text=json.dumps({"error": error_msg}))]
