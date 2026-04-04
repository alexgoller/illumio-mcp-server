import json
import logging
import mcp.types as types
from illumio import Label, Workload, Interface
from ..pce import get_pce

logger = logging.getLogger('illumio_mcp')


def handle_get_workloads(arguments: dict) -> list:
    logger.debug("=" * 80)
    logger.debug("GET WORKLOADS CALLED")
    logger.debug(f"Arguments received: {json.dumps(arguments, indent=2)}")
    logger.debug("=" * 80)

    logger.debug("Initializing PCE connection")
    try:
        pce = get_pce()

        params = {"include": "labels", "max_results": arguments.get('max_results', 10000)}
        for param in ['name', 'hostname', 'ip_address', 'description', 'labels', 'enforcement_mode']:
            if arguments.get(param):
                params[param] = arguments[param]
        if 'managed' in arguments:
            params['managed'] = arguments['managed']
        if 'online' in arguments:
            params['online'] = arguments['online']

        workloads = pce.workloads.get(params=params)
        logger.debug(f"Successfully retrieved {len(workloads)} workloads")
        return [types.TextContent(
            type="text",
            text=f"Workloads: {workloads}"
        )]
    except Exception as e:
        error_msg = f"Failed in PCE operation: {str(e)}"
        logger.error(error_msg, exc_info=True)
        return [types.TextContent(
            type="text",
            text=f"Error: {error_msg}"
        )]


def handle_create_workload(arguments: dict) -> list:
    logger.debug(f"Creating workload with name: {arguments['name']} and ip_addresses: {arguments['ip_addresses']}")
    logger.debug(f"Labels: {arguments['labels']}")
    try:
        pce = get_pce()

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


def handle_update_workload(arguments: dict) -> list:
    logger.debug(f"UPDATE WORKLOAD CALLED with arguments: {json.dumps(arguments, indent=2)}")
    try:
        pce = get_pce()

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


def handle_delete_workload(arguments: dict) -> list:
    logger.debug(f"DELETE WORKLOAD CALLED with arguments: {json.dumps(arguments, indent=2)}")
    try:
        pce = get_pce()

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
