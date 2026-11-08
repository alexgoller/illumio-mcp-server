"""cloud-assign-labels / cloud-remove-labels on Illumio Cloud resources."""
import json
import logging

import mcp.types as types

from ..cloud_client import get_cloud_platform_client
from ..errors import describe_error
from ..log_scrub import ScrubbedArgs

logger = logging.getLogger('illumio_mcp')


def _apply(arguments: dict, verb: str) -> list:
    arguments = arguments or {}
    try:
        assignments = arguments.get("assignments") or []
        if not assignments:
            return [types.TextContent(type="text", text=json.dumps({
                "error": "No assignments provided. Expected [{csp_id, labels: [{key, value}]}]"}))]
        payload = []
        for a in assignments:
            labels = [{"key": l["key"], "value": l["value"]} for l in a.get("labels") or []
                      if isinstance(l, dict) and "key" in l and "value" in l]
            if a.get("csp_id") and labels:
                payload.append({"csp_id": a["csp_id"], verb: labels})
        if not payload:
            return [types.TextContent(type="text", text=json.dumps({
                "error": "Every assignment needs a csp_id and at least one {key, value} label"}))]
        resp = get_cloud_platform_client().post_label_assignments({"label_assignments": payload})
        failed = resp.get("failed_resources") or []
        out = {"action": verb, "submitted": len(payload), "failed": len(failed), "succeeded": len(payload) - len(failed)}
        if failed:
            out["failed_resources"] = failed
        return [types.TextContent(type="text", text=json.dumps(out, indent=2))]
    except Exception as e:
        msg = f"Failed in Cloud labeling API: {describe_error(e)}"
        logger.error(msg, exc_info=True)
        return [types.TextContent(type="text", text=json.dumps({"error": msg}))]


def handle_cloud_assign_labels(ctx, arguments: dict) -> list:
    logger.debug("CLOUD ASSIGN LABELS: %s", ScrubbedArgs(arguments))
    return _apply(arguments, "add")


def handle_cloud_remove_labels(ctx, arguments: dict) -> list:
    logger.debug("CLOUD REMOVE LABELS: %s", ScrubbedArgs(arguments))
    return _apply(arguments, "remove")
