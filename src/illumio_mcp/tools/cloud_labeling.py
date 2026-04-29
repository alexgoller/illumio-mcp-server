import json
import logging
import mcp.types as types
from ..cloud_client import CloudPlatformClient

logger = logging.getLogger('illumio_mcp')

_NOT_CONFIGURED = json.dumps({
    "error": "Cloud Platform API not configured. Set CLOUD_API_HOST, CLOUD_API_KEY, CLOUD_API_SECRET, CLOUD_TENANT_ID."
})


def handle_cloud_assign_labels(arguments: dict) -> list:
    logger.debug("=" * 80)
    logger.debug("CLOUD ASSIGN LABELS CALLED")
    logger.debug(f"Arguments received: {json.dumps(arguments, indent=2)}")
    logger.debug("=" * 80)

    if not CloudPlatformClient.is_configured():
        return [types.TextContent(type="text", text=_NOT_CONFIGURED)]

    try:
        client = CloudPlatformClient.get_instance()
        assignments = arguments.get("assignments", [])

        if not assignments:
            return [types.TextContent(type="text", text=json.dumps({"error": "No assignments provided. Expected list of {csp_id, labels: [{key, value}]}"}))]

        # Build API request body
        label_assignments = []
        for a in assignments:
            csp_id = a.get("csp_id")
            labels = a.get("labels", [])
            if not csp_id or not labels:
                continue
            label_assignments.append({
                "csp_id": csp_id,
                "add": [{"key": l["key"], "value": l["value"]} for l in labels if "key" in l and "value" in l],
            })

        resp = client.post_label_assignments({"label_assignments": label_assignments})

        failed = resp.get("failed_resources", [])
        result = {
            "submitted": len(label_assignments),
            "failed": len(failed),
            "succeeded": len(label_assignments) - len(failed),
        }
        if failed:
            result["failed_resources"] = failed

        return [types.TextContent(type="text", text=json.dumps(result, indent=2))]

    except Exception as e:
        error_msg = f"Failed in Cloud Labeling API: {str(e)}"
        logger.error(error_msg, exc_info=True)
        return [types.TextContent(type="text", text=json.dumps({"error": error_msg}))]


def handle_cloud_remove_labels(arguments: dict) -> list:
    logger.debug("=" * 80)
    logger.debug("CLOUD REMOVE LABELS CALLED")
    logger.debug(f"Arguments received: {json.dumps(arguments, indent=2)}")
    logger.debug("=" * 80)

    if not CloudPlatformClient.is_configured():
        return [types.TextContent(type="text", text=_NOT_CONFIGURED)]

    try:
        client = CloudPlatformClient.get_instance()
        assignments = arguments.get("assignments", [])

        if not assignments:
            return [types.TextContent(type="text", text=json.dumps({"error": "No assignments provided. Expected list of {csp_id, labels: [{key, value}]}"}))]

        label_assignments = []
        for a in assignments:
            csp_id = a.get("csp_id")
            labels = a.get("labels", [])
            if not csp_id or not labels:
                continue
            label_assignments.append({
                "csp_id": csp_id,
                "remove": [{"key": l["key"], "value": l["value"]} for l in labels if "key" in l and "value" in l],
            })

        resp = client.post_label_assignments({"label_assignments": label_assignments})

        failed = resp.get("failed_resources", [])
        result = {
            "submitted": len(label_assignments),
            "failed": len(failed),
            "succeeded": len(label_assignments) - len(failed),
        }
        if failed:
            result["failed_resources"] = failed

        return [types.TextContent(type="text", text=json.dumps(result, indent=2))]

    except Exception as e:
        error_msg = f"Failed in Cloud Labeling API: {str(e)}"
        logger.error(error_msg, exc_info=True)
        return [types.TextContent(type="text", text=json.dumps({"error": error_msg}))]
