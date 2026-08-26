import json
import logging
import pandas as pd
import mcp.types as types
from illumio import Label, Workload, Interface
from .constants import MCP_MAX_RESPONSE_BYTES
from ..log_scrub import scrub_arguments_for_log

logger = logging.getLogger('illumio_mcp')


def _build_label_map(pce):
    """Build {href: {key, value}} lookup from all PCE labels."""
    label_map = {}
    for l in pce.labels.get(params={'max_results': 10000}):
        label_map[l.href] = {"key": l.key, "value": l.value}
    return label_map


def _truncate_split(df, metadata, max_bytes=MCP_MAX_RESPONSE_BYTES):
    """Serialize DataFrame as split-format JSON, truncating to fit max_bytes.

    Returns JSON string with metadata + columns + data arrays.
    """
    total = len(df)

    def _serialize(frame, trunc):
        clean = frame.astype(object).where(frame.notna(), None)
        envelope = {**metadata, "returned": len(frame), "truncated": trunc, "columns": frame.columns.tolist(), "data": clean.values.tolist()}
        return json.dumps(envelope, default=str)

    payload = _serialize(df, False)
    if len(payload) <= max_bytes:
        return payload

    # Binary search for largest row count that fits
    lo, hi = 1, total
    best = df.head(1)
    while lo <= hi:
        mid = (lo + hi) // 2
        candidate = df.head(mid)
        if len(_serialize(candidate, True)) <= max_bytes:
            best = candidate
            lo = mid + 1
        else:
            hi = mid - 1

    logger.warning(f"Truncated workloads from {total} to {len(best)} rows to fit MCP limit")
    return _serialize(best, True)


def _truncate_records(records, metadata, max_bytes=MCP_MAX_RESPONSE_BYTES):
    """Serialize a list of dicts as JSON records, truncating to fit max_bytes."""
    def _serialize(recs, trunc):
        envelope = {**metadata, "returned": len(recs), "truncated": trunc, "workloads": recs}
        return json.dumps(envelope, default=str)

    payload = _serialize(records, False)
    if len(payload) <= max_bytes:
        return payload

    # Binary search for largest count that fits
    lo, hi = 1, len(records)
    best = records[:1]
    while lo <= hi:
        mid = (lo + hi) // 2
        candidate = records[:mid]
        if len(_serialize(candidate, True)) <= max_bytes:
            best = candidate
            lo = mid + 1
        else:
            hi = mid - 1

    logger.warning(f"Truncated workloads from {len(records)} to {len(best)} records to fit MCP limit")
    return _serialize(best, True)


def _format_compact(workloads, label_map):
    """Compact split-format: key fields + dynamic label columns."""
    rows = []
    for w in workloads:
        row = {
            "href": w.href,
            "name": w.name,
            "hostname": w.hostname,
            "ip_addresses": ", ".join(
                intf.address for intf in (w.interfaces or [])
                if hasattr(intf, 'address') and intf.address
            ) or None,
            "os_type": w.os_type,
            "online": w.online,
            "managed": bool(w.agent or w.ven),
            "enforcement_mode": w.enforcement_mode,
            "visibility_level": w.visibility_level,
        }
        if w.labels:
            for l in w.labels:
                info = label_map.get(l.href)
                if info:
                    row[info["key"]] = info["value"]
        rows.append(row)

    if not rows:
        return json.dumps({"total": 0, "returned": 0, "truncated": False,
                           "message": "No workloads found"})

    df = pd.DataFrame(rows)
    return _truncate_split(df, {"total": len(rows)})


def _format_full(workloads, label_map):
    """Full detail: complete to_json() with resolved labels."""
    records = []
    for w in workloads:
        d = w.to_json()
        # Resolve label hrefs to key/value
        if "labels" in d and isinstance(d["labels"], list):
            resolved = []
            for lbl in d["labels"]:
                href = lbl.get("href") if isinstance(lbl, dict) else getattr(lbl, 'href', None)
                if href and href in label_map:
                    resolved.append({"href": href, **label_map[href]})
                elif href:
                    resolved.append({"href": href})
            d["labels"] = resolved
        d["managed"] = bool(w.agent or w.ven)
        records.append(d)

    if not records:
        return json.dumps({"total": 0, "returned": 0, "truncated": False,
                           "message": "No workloads found"})

    return _truncate_records(records, {"total": len(records)})


def _format_labels_only(workloads, label_map):
    """Minimal split-format: identity + labels only. Maximum breadth."""
    rows = []
    for w in workloads:
        row = {"href": w.href, "name": w.name, "hostname": w.hostname}
        if w.labels:
            for l in w.labels:
                info = label_map.get(l.href)
                if info:
                    row[info["key"]] = info["value"]
        rows.append(row)

    if not rows:
        return json.dumps({"total": 0, "returned": 0, "truncated": False,
                           "message": "No workloads found"})

    df = pd.DataFrame(rows)
    return _truncate_split(df, {"total": len(rows)})


def handle_get_workloads(ctx, arguments: dict) -> list:
    logger.debug("=" * 80)
    logger.debug("GET WORKLOADS CALLED")
    logger.debug(f"Arguments received: {json.dumps(scrub_arguments_for_log(arguments), indent=2)}")
    logger.debug("=" * 80)

    try:
        pce = ctx.pce
        detail_level = arguments.get('detail_level', 'compact')

        params = {"include": "labels", "max_results": arguments.get('max_results', 10000)}
        for param in ['name', 'hostname', 'ip_address', 'description', 'labels', 'enforcement_mode']:
            if arguments.get(param):
                params[param] = arguments[param]
        if 'managed' in arguments:
            params['managed'] = arguments['managed']
        if 'online' in arguments:
            params['online'] = arguments['online']

        workloads = pce.workloads.get(params=params)
        logger.debug(f"Retrieved {len(workloads)} workloads, detail_level={detail_level}")

        label_map = _build_label_map(pce)

        if detail_level == 'full':
            payload = _format_full(workloads, label_map)
        elif detail_level == 'labels_only':
            payload = _format_labels_only(workloads, label_map)
        else:
            payload = _format_compact(workloads, label_map)

        return [types.TextContent(type="text", text=payload)]
    except Exception as e:
        error_msg = f"Failed in PCE operation: {str(e)}"
        logger.error(error_msg, exc_info=True)
        return [types.TextContent(type="text", text=json.dumps({"error": error_msg}))]


def handle_create_workload(ctx, arguments: dict) -> list:
    logger.debug(f"Creating workload with name: {arguments['name']} and ip_addresses: {arguments['ip_addresses']}")
    logger.debug(f"Labels: {arguments['labels']}")
    try:
        pce = ctx.pce

        interfaces = []
        prefix = "eth"
        if_count = 0
        for ip in arguments['ip_addresses']:
            intf = Interface(name=f"{prefix}{if_count}", address=ip)
            interfaces.append(intf)
            if_count += 1

        workload_labels = []

        for label in arguments['labels']:
            logger.debug(f"Label: {label}")
            # check if label already exists
            label_resp = pce.labels.get(params={"key": label['key'], "value": label['value']})
            if label_resp:
                logger.debug(f"Label already exists: {label_resp}")
                workload_label = label_resp[0]  # Get the first matching label
            else:
                logger.debug(f"Label does not exist, creating: {label}")
                new_label = Label(key=label['key'], value=label['value'])
                workload_label = pce.labels.create(new_label)

            workload_labels.append(workload_label)

        logger.debug(f"Labels: {workload_labels}")

        workload = Workload(
            name=arguments['name'],
            interfaces=interfaces,
            labels=workload_labels,
            hostname=arguments['name']  # Adding hostname which might be required
        )
        status = pce.workloads.create(workload)
        logger.debug(f"Workload creation status: {status}")
        return [types.TextContent(
            type="text",
            text=f"Workload created with status: {status}, workload: {workload}"
        )]
    except Exception as e:
        error_msg = f"Failed in PCE operation: {str(e)}"
        logger.error(error_msg, exc_info=True)
        return [types.TextContent(
            type="text",
            text=f"Error: {error_msg}"
        )]


def handle_update_workload(ctx, arguments: dict) -> list:
    logger.debug(f"UPDATE WORKLOAD CALLED with arguments: {json.dumps(scrub_arguments_for_log(arguments), indent=2)}")
    try:
        pce = ctx.pce

        # Find the workload by href or name
        workload_obj = None
        if arguments.get("href"):
            workload_obj = pce.workloads.get_by_reference(arguments["href"])
        elif arguments.get("name"):
            workloads = pce.workloads.get(params={"name": arguments["name"]})
            if workloads:
                workload_obj = workloads[0]

        if not workload_obj:
            return [types.TextContent(type="text", text=json.dumps({"error": "Workload not found"}))]

        # Build update payload via raw API for flexibility
        update_data = {}
        if "new_name" in arguments:
            update_data["name"] = arguments["new_name"]
        if "description" in arguments:
            update_data["description"] = arguments["description"]
        if "hostname" in arguments:
            update_data["hostname"] = arguments["hostname"]
        if "enforcement_mode" in arguments:
            update_data["enforcement_mode"] = arguments["enforcement_mode"]

        # Handle IP addresses -> interfaces
        if arguments.get("ip_addresses"):
            interfaces = []
            for i, ip in enumerate(arguments["ip_addresses"]):
                interfaces.append({"name": f"eth{i}", "address": ip})
            update_data["interfaces"] = interfaces

        # Handle labels
        if "labels" in arguments:
            workload_labels = []
            for label_spec in arguments["labels"]:
                label_resp = pce.labels.get(params={"key": label_spec["key"], "value": label_spec["value"]})
                if label_resp:
                    workload_labels.append({"href": label_resp[0].href})
                else:
                    new_label = Label(key=label_spec["key"], value=label_spec["value"])
                    created = pce.labels.create(new_label)
                    workload_labels.append({"href": created.href})
            update_data["labels"] = workload_labels

        if not update_data:
            return [types.TextContent(type="text", text=json.dumps({"error": "No update fields provided"}))]

        pce.put(workload_obj.href, json=update_data)

        return [types.TextContent(
            type="text",
            text=json.dumps({"message": f"Successfully updated workload {workload_obj.href}", "updated_fields": list(update_data.keys())}, indent=2)
        )]
    except Exception as e:
        error_msg = f"Failed in PCE operation: {str(e)}"
        logger.error(error_msg, exc_info=True)
        return [types.TextContent(type="text", text=json.dumps({"error": error_msg}))]


def handle_delete_workload(ctx, arguments: dict) -> list:
    logger.debug(f"DELETE WORKLOAD CALLED with arguments: {json.dumps(scrub_arguments_for_log(arguments), indent=2)}")
    try:
        pce = ctx.pce

        workload_obj = None
        if arguments.get("href"):
            workload_obj = pce.workloads.get_by_reference(arguments["href"])
        elif arguments.get("name"):
            workloads = pce.workloads.get(params={"name": arguments["name"]})
            if workloads:
                workload_obj = workloads[0]

        if workload_obj:
            pce.workloads.delete(workload_obj)
            return [types.TextContent(
                type="text",
                text=json.dumps({"message": f"Workload deleted successfully: {workload_obj.href}"})
            )]
        else:
            return [types.TextContent(type="text", text=json.dumps({"error": "Workload not found"}))]
    except Exception as e:
        error_msg = f"Failed in PCE operation: {str(e)}"
        logger.error(error_msg, exc_info=True)
        return [types.TextContent(type="text", text=json.dumps({"error": error_msg}))]
