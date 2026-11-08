"""Unified traffic (FQS) async queries: list, create, download."""
import json
import logging

import mcp.types as types
import pandas as pd

from ..cloud_client import get_cloud_traffic_client
from ..errors import describe_error
from ..log_scrub import ScrubbedArgs
from .workloads import _truncate_split

logger = logging.getLogger('illumio_mcp')


def _row(flow: dict) -> dict:
    src, dst, svc = flow.get("src") or {}, flow.get("dst") or {}, flow.get("service") or {}
    row = {"src_ip": src.get("ip"), "dst_ip": dst.get("ip"), "proto": svc.get("proto"), "port": svc.get("port"),
           "policy_decision": flow.get("policy_decision"), "boundary_decision": flow.get("boundary_decision"),
           "num_connections": flow.get("num_connections", 0), "flow_direction": flow.get("flow_direction")}
    for side, ep in (("src", src), ("dst", dst)):
        wl, cr = ep.get("workload"), ep.get("cloud_resource")
        if wl:
            row[f"{side}_name"], row[f"{side}_type"] = wl.get("name") or wl.get("hostname"), "workload"
        elif cr:
            row[f"{side}_name"], row[f"{side}_type"] = cr.get("resource_uuid"), f"cloud:{cr.get('type', '')}"
        if ep.get("fqdn_name"):
            row[f"{side}_fqdn"] = ep["fqdn_name"]
    ts = flow.get("timestamp_range") or {}
    row["first_detected"], row["last_detected"] = ts.get("first_detected"), ts.get("last_detected")
    return row


def _query_summary(q: dict) -> dict:
    return {"query_id": q.get("query_id"), "status": q.get("status"),
            "query_name": (q.get("query_parameters") or {}).get("query_name"),
            "matches_count": q.get("matches_count"), "flows_count": q.get("flows_count"),
            "created_at": q.get("created_at"), "updated_at": q.get("updated_at"), "download_url": q.get("result")}


def _error(e: Exception) -> list:
    msg = f"Failed in Cloud traffic API: {describe_error(e)}"
    logger.error(msg, exc_info=True)
    return [types.TextContent(type="text", text=json.dumps({"error": msg}))]


def handle_cloud_get_traffic_queries(ctx, arguments: dict) -> list:
    logger.debug("CLOUD GET TRAFFIC QUERIES")
    try:
        queries = get_cloud_traffic_client().get_queries().get("info") or []
        return [types.TextContent(type="text", text=json.dumps(
            {"total_queries": len(queries), "queries": [_query_summary(q) for q in queries]}, indent=2))]
    except Exception as e:
        return _error(e)


def handle_cloud_create_traffic_query(ctx, arguments: dict) -> list:
    logger.debug("CLOUD CREATE TRAFFIC QUERY: %s", ScrubbedArgs(arguments))
    arguments = arguments or {}
    try:
        body = {"query_name": arguments.get("query_name", "mcp-cloud-traffic-query"),
                "start_date": arguments["start_date"], "end_date": arguments["end_date"],
                "max_results": int(arguments.get("max_results", 10000)),
                "sources": arguments.get("sources") or {"include": []},
                "destinations": arguments.get("destinations") or {"include": []}}
        for key in ("services", "policy_decisions", "boundary_decisions", "data_sources"):
            if arguments.get(key):
                body[key] = arguments[key]
        for key in ("sources_destinations_query_op", "exclude_workloads_from_ip_list_query", "aggregate_lows_across_days"):
            if key in arguments:
                body[key] = arguments[key]
        resp = get_cloud_traffic_client().create_query(body)
        queries = resp.get("info") or []
        out = ({"message": "Traffic query created", **_query_summary(queries[0])} if queries
               else {"message": "Traffic query submitted", "response": resp})
        return [types.TextContent(type="text", text=json.dumps(out, indent=2))]
    except KeyError as e:
        return [types.TextContent(type="text", text=json.dumps({"error": f"missing required argument {e}"}))]
    except Exception as e:
        return _error(e)


def handle_cloud_get_traffic_flows(ctx, arguments: dict) -> list:
    logger.debug("CLOUD GET TRAFFIC FLOWS: %s", ScrubbedArgs(arguments))
    arguments = arguments or {}
    try:
        query_id = arguments["query_id"]
        offset, limit = int(arguments.get("offset", 0)), int(arguments.get("limit", 5000))
        flows = get_cloud_traffic_client().download_flows(query_id, offset=offset, limit=limit).get("flows") or []
        if not flows:
            return [types.TextContent(type="text", text=json.dumps({
                "message": "No traffic flows returned; the query may still be running (cloud-get-traffic-queries shows status)",
                "query_id": query_id, "offset": offset, "limit": limit}))]
        df = pd.DataFrame([_row(f) for f in flows])
        keys = [c for c in ("src_ip", "dst_ip", "proto", "port", "policy_decision", "boundary_decision",
                            "src_name", "dst_name", "src_type", "dst_type") if c in df.columns]
        if keys and "num_connections" in df.columns:
            df = (df.groupby(keys, dropna=False)["num_connections"].sum().reset_index()
                    .sort_values("num_connections", ascending=False).reset_index(drop=True))
        meta = {"query_id": query_id, "total_flows": len(flows), "total_grouped_rows": int(len(df))}
        return [types.TextContent(type="text", text=_truncate_split(df, meta))]
    except KeyError as e:
        return [types.TextContent(type="text", text=json.dumps({"error": f"missing required argument {e}"}))]
    except Exception as e:
        return _error(e)
