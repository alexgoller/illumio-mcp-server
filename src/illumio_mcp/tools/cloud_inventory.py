import json
import logging
import pandas as pd
import mcp.types as types
from ..cloud_client import CloudPlatformClient
from .constants import MCP_MAX_RESPONSE_BYTES

logger = logging.getLogger('illumio_mcp')


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

    logger.warning(f"Truncated cloud resources from {len(df)} to {len(best)} rows")
    return _serialize(best, True)


def _truncate_records(records, metadata, max_bytes=MCP_MAX_RESPONSE_BYTES):
    """Serialize list of dicts as JSON, truncating to fit max_bytes."""
    def _serialize(recs, trunc):
        envelope = {**metadata, "returned": len(recs), "truncated": trunc, "resources": recs}
        return json.dumps(envelope, default=str)

    payload = _serialize(records, False)
    if len(payload) <= max_bytes:
        return payload

    lo, hi = 1, len(records)
    best = records[:1]
    while lo <= hi:
        mid = (lo + hi) // 2
        if len(_serialize(records[:mid], True)) <= max_bytes:
            best = records[:mid]
            lo = mid + 1
        else:
            hi = mid - 1

    logger.warning(f"Truncated cloud resources from {len(records)} to {len(best)} records")
    return _serialize(best, True)


def handle_cloud_get_resources(arguments: dict) -> list:
    logger.debug("=" * 80)
    logger.debug("CLOUD GET RESOURCES CALLED")
    logger.debug(f"Arguments received: {json.dumps(arguments, indent=2)}")
    logger.debug("=" * 80)

    if not CloudPlatformClient.is_configured():
        return [types.TextContent(type="text", text=json.dumps({
            "error": "Cloud Platform API not configured. Set CLOUD_API_HOST, CLOUD_API_KEY, CLOUD_API_SECRET, CLOUD_TENANT_ID."
        }))]

    try:
        client = CloudPlatformClient.get_instance()
        detail_level = arguments.get("detail_level", "compact")
        max_results = arguments.get("max_results", 500)

        # Build request body from arguments
        body = {}
        for key in ["account_ids", "categories", "clouds", "csp_ids", "illumio_regions",
                     "ip_addresses", "label_ids", "object_types", "regions", "resource_ids",
                     "resource_names", "states", "subcategories"]:
            if arguments.get(key):
                body[key] = arguments[key]

        if arguments.get("labels"):
            body["labels"] = arguments["labels"]
        if arguments.get("tags"):
            body["tags"] = arguments["tags"]
        if "include_enforcement_status" in arguments:
            body["include_enforcement_status"] = arguments["include_enforcement_status"]
        if "json_view" in arguments:
            body["json_view"] = arguments["json_view"]
        if "exclude_references" in arguments:
            body["exclude_references"] = arguments["exclude_references"]

        body["with_total_count"] = True
        body["max_results"] = min(max_results, 500)  # API page size cap

        # Auto-paginate
        all_items = []
        total_size = None
        while len(all_items) < max_results:
            resp = client.post_inventory(body)
            items = resp.get("items", [])
            all_items.extend(items)

            if total_size is None:
                total_size = resp.get("total_size", len(items))

            next_token = resp.get("next_page_token")
            if not next_token or not items:
                break
            body["page_token"] = next_token
            body["max_results"] = min(max_results - len(all_items), 500)

        all_items = all_items[:max_results]
        logger.debug(f"Retrieved {len(all_items)} cloud resources (total available: {total_size})")

        if not all_items:
            return [types.TextContent(type="text", text=json.dumps({
                "message": "No cloud resources found matching the query",
                "total": 0, "returned": 0, "truncated": False
            }))]

        metadata = {"total_available": total_size or len(all_items), "total_fetched": len(all_items)}

        if detail_level == "full":
            payload = _truncate_records(all_items, metadata)
        else:
            # Compact: flatten to DataFrame
            rows = []
            for item in all_items:
                row = {
                    "id": item.get("id"),
                    "name": item.get("name"),
                    "csp_id": item.get("csp_id"),
                    "cloud": item.get("cloud"),
                    "object_type": item.get("object_type"),
                    "category": item.get("category"),
                    "subcategory": item.get("subcategory"),
                    "region": item.get("region"),
                    "illumio_region": item.get("illumio_region"),
                    "account_id": item.get("account_id"),
                    "account_name": item.get("account_name", item.get("owner_account", {}).get("name") if isinstance(item.get("owner_account"), dict) else None),
                }
                # Flatten labels
                for lbl in item.get("labels", []):
                    if isinstance(lbl, dict) and "key" in lbl and "value" in lbl:
                        row[lbl["key"]] = lbl["value"]
                # Flatten IPs
                ips = item.get("ips")
                if ips and isinstance(ips, dict):
                    addrs = ips.get("addresses") or ips.get("private") or []
                    if isinstance(addrs, list):
                        row["ip_addresses"] = ", ".join(str(a) for a in addrs[:5])
                elif ips and isinstance(ips, list):
                    row["ip_addresses"] = ", ".join(str(a) for a in ips[:5])
                rows.append(row)

            df = pd.DataFrame(rows)
            payload = _truncate_split(df, metadata)

        return [types.TextContent(type="text", text=payload)]

    except Exception as e:
        error_msg = f"Failed in Cloud Inventory API: {str(e)}"
        logger.error(error_msg, exc_info=True)
        return [types.TextContent(type="text", text=json.dumps({"error": error_msg}))]
