"""cloud-get-resources: the Illumio Cloud inventory, filtered and paginated."""
import json
import logging

import mcp.types as types
import pandas as pd

from ..cloud_client import get_cloud_platform_client
from ..errors import describe_error
from ..log_scrub import ScrubbedArgs
from .workloads import _truncate_records, _truncate_split

logger = logging.getLogger('illumio_mcp')

FILTER_KEYS = ("account_ids", "categories", "clouds", "csp_ids", "illumio_regions", "ip_addresses",
               "label_ids", "object_types", "regions", "resource_ids", "resource_names", "states",
               "subcategories", "labels", "tags")
PAGE = 500


def _flatten(item: dict) -> dict:
    owner = item.get("owner_account") if isinstance(item.get("owner_account"), dict) else {}
    row = {k: item.get(k) for k in ("id", "name", "csp_id", "cloud", "object_type", "category",
                                     "subcategory", "region", "illumio_region", "account_id")}
    row["account_name"] = item.get("account_name") or owner.get("name")
    for lbl in item.get("labels") or []:
        if isinstance(lbl, dict) and "key" in lbl and "value" in lbl:
            row[lbl["key"]] = lbl["value"]
    ips = item.get("ips")
    addrs = (ips.get("addresses") or ips.get("private") or []) if isinstance(ips, dict) else (ips or [])
    if isinstance(addrs, list) and addrs:
        row["ip_addresses"] = ", ".join(str(a) for a in addrs[:5])
    return row


def handle_cloud_get_resources(ctx, arguments: dict) -> list:
    logger.debug("CLOUD GET RESOURCES: %s", ScrubbedArgs(arguments))
    arguments = arguments or {}
    try:
        client = get_cloud_platform_client()
        detail_level = arguments.get("detail_level", "compact")
        max_results = int(arguments.get("max_results", PAGE))
        body = {k: arguments[k] for k in FILTER_KEYS if arguments.get(k)}
        for flag in ("include_enforcement_status", "json_view", "exclude_references"):
            if flag in arguments:
                body[flag] = arguments[flag]
        body["with_total_count"] = True
        body["max_results"] = min(max_results, PAGE)

        items, total = [], None
        while len(items) < max_results:
            resp = client.post_inventory(body)
            page = resp.get("items") or []
            items.extend(page)
            if total is None:
                total = resp.get("total_size", len(page))
            token = resp.get("next_page_token")
            if not token or not page:
                break
            body["page_token"] = token
            body["max_results"] = min(max_results - len(items), PAGE)
        items = items[:max_results]
        if not items:
            return [types.TextContent(type="text", text=json.dumps({
                "message": "No cloud resources matched", "total": 0, "returned": 0, "truncated": False}))]
        meta = {"total_available": total if total is not None else len(items), "total_fetched": len(items)}
        if detail_level == "full":
            return [types.TextContent(type="text", text=_truncate_records(items, meta))]
        return [types.TextContent(type="text", text=_truncate_split(pd.DataFrame([_flatten(i) for i in items]), meta))]
    except Exception as e:
        msg = f"Failed in Cloud inventory API: {describe_error(e)}"
        logger.error(msg, exc_info=True)
        return [types.TextContent(type="text", text=json.dumps({"error": msg}))]
