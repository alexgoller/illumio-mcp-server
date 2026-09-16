import json
import logging

import mcp.types as types

from ..log_scrub import ScrubbedArgs
from ..service_refs import ServiceRefError, normalise_windows_services

logger = logging.getLogger('illumio_mcp')


def handle_get_services(ctx, arguments: dict) -> list:
    logger.debug("=" * 80)
    logger.debug("GET SERVICES CALLED")
    logger.debug("Arguments received: %s", ScrubbedArgs(arguments))
    logger.debug("=" * 80)

    try:
        logger.debug("Initializing PCE connection...")
        pce = ctx.pce

        params = {}
        for param in ['name', 'description', 'port', 'proto', 'process_name', 'max_results']:
            if arguments.get(param):
                params[param] = arguments[param]

        # The PCE has no server-side filter for a process inside
        # windows_egress_services, so it is applied below, after the fetch.
        egress_process_filter = (arguments.get('egress_process_name') or '').strip().lower()

        logger.debug(f"Querying services with params: {json.dumps(params, indent=2)}")
        services = pce.services.get(params=params)
        logger.debug(f"Found {len(services)} services")

        # Convert services to serializable format
        service_data = []
        for service in services:
            logger.debug(f"Processing service: {service.name} ({service.href})")
            service_dict = {
                'href': service.href,
                'name': service.name,
                'description': service.description if hasattr(service, 'description') else None,
                'process_name': service.process_name if hasattr(service, 'process_name') else None,
                'service_ports': []
            }

            # Add service ports - check both possible attribute names
            ports = []
            if hasattr(service, 'service_ports'):
                ports = service.service_ports or []  # Handle None case
            elif hasattr(service, 'ports'):
                ports = service.ports or []  # Handle None case

            logger.debug(f"Processing {len(ports)} ports for service {service.name}")
            for port in ports:
                try:
                    port_dict = {
                        'port': port.port,
                        'proto': port.proto
                    }
                    # Only add to_port if it exists and is different from port
                    if hasattr(port, 'to_port') and port.to_port is not None:
                        port_dict['to_port'] = port.to_port
                    service_dict['service_ports'].append(port_dict)
                    logger.debug(f"Added port {port.port}/{port.proto} to service {service.name}")
                except AttributeError as e:
                    logger.warning(f"Error processing port {port} for service {service.name}: {e}")
                    continue

            # Windows qualifiers, ingress and egress alike. Egress was already
            # in the PCE model and the SDK but was never surfaced, so a service
            # created with a process qualifier read back looking empty.
            for field in ('windows_services', 'windows_egress_services'):
                entries = getattr(service, field, None)
                if not entries:
                    continue
                ws_list = []
                for ws in entries:
                    ws_dict = {}
                    for attr in ('service_name', 'process_name', 'port', 'proto', 'to_port'):
                        value = getattr(ws, attr, None)
                        if value not in (None, ''):
                            ws_dict[attr] = value
                    ws_list.append(ws_dict)
                service_dict[field] = ws_list

            if egress_process_filter:
                haystack = [str(e.get('process_name', '')).lower()
                            for e in service_dict.get('windows_egress_services', [])]
                if not any(egress_process_filter in name for name in haystack):
                    continue

            service_data.append(service_dict)
            logger.debug(f"Completed processing service: {service.name}")

        logger.debug(f"Successfully processed {len(service_data)} services")
        return [types.TextContent(
            type="text",
            text=json.dumps({
                "services": service_data,
                "total_count": len(service_data)
            }, indent=2)
        )]

    except Exception as e:
        error_msg = f"Failed to get services: {str(e)}"
        logger.error(error_msg, exc_info=True)
        return [types.TextContent(
            type="text",
            text=json.dumps({"error": error_msg})
        )]


def handle_create_service(ctx, arguments: dict) -> list:
    logger.debug("CREATE SERVICE CALLED with arguments: %s", ScrubbedArgs(arguments))
    try:
        pce = ctx.pce

        payload = {"name": arguments["name"]}

        # Any one of the three qualifier lists makes a valid service, so
        # service_ports is no longer required -- a process-only egress service
        # has no ports at all. The PCE rejects a service with none of them, but
        # only after a round trip and without naming the omission.
        service_ports = arguments.get("service_ports") or []
        windows_services = normalise_windows_services(
            arguments.get("windows_services"), "windows_services")
        windows_egress = normalise_windows_services(
            arguments.get("windows_egress_services"), "windows_egress_services")

        if not (service_ports or windows_services or windows_egress):
            return [types.TextContent(type="text", text=json.dumps({
                "error": "empty_service",
                "message": ("A service needs at least one of service_ports, "
                            "windows_services or windows_egress_services."),
            }, indent=2))]

        # The three lists are MUTUALLY EXCLUSIVE. A service carries an OS type
        # -- editing one into the other answers "cannot change OS type of
        # service" -- and on create the PCE keeps one list, silently NULLs the
        # others, and still returns 201. A caller asking for "chrome.exe on 443"
        # got back a service with no ports and no warning that half the request
        # had been discarded. Refusing here is the whole point: a wrong object
        # that reports success is worse than a rejected call.
        supplied = [name for name, value in (
            ("service_ports", service_ports),
            ("windows_services", windows_services),
            ("windows_egress_services", windows_egress)) if value]
        if len(supplied) > 1:
            return [types.TextContent(type="text", text=json.dumps({
                "error": "conflicting_service_definition",
                "supplied": supplied,
                "message": (
                    f"A service object can carry only one of {supplied}. The PCE "
                    f"would keep one and silently discard the rest. Split this "
                    f"into separate service objects, or pick the one that "
                    f"expresses what you mean."
                ),
                "guidance": {
                    "port only": "service_ports",
                    "process on the PROVIDER side, with a port":
                        "windows_services (accepts port + process_name together)",
                    "process on the CONSUMER side":
                        ("windows_egress_services (process_name/service_name only "
                         "-- the PCE does not accept a port here, so this matches "
                         "that process on ANY port)"),
                },
            }, indent=2))]

        if service_ports:
            payload["service_ports"] = service_ports
        if windows_services:
            payload["windows_services"] = windows_services
        if windows_egress:
            payload["windows_egress_services"] = windows_egress
        if arguments.get("description"):
            payload["description"] = arguments["description"]

        resp = pce.post("/sec_policy/draft/services", json=payload)
        result = resp.json()

        # Verify the PCE stored what was asked for. It accepts and discards
        # quietly in more places than the exclusivity check above covers, and a
        # response echoing the request would hide that.
        response = {"message": "Successfully created service", "service": result}
        discarded = [field for field in
                     ("service_ports", "windows_services", "windows_egress_services")
                     if payload.get(field) and not result.get(field)]
        if discarded:
            response["message"] = "Service created, but the PCE discarded part of it"
            response["discarded_fields"] = discarded
            response["warning"] = (
                f"The PCE stored the service without {discarded}. What was written "
                f"is NOT what was requested -- inspect `service` before relying on it."
            )
        if windows_egress:
            response["note"] = (
                "windows_egress_services matches on the CONSUMER side and needs a "
                "Windows VEN there. Non-Windows consumers ignore the process "
                "qualifier and match on port alone, which widens the rule."
            )
        return [types.TextContent(type="text", text=json.dumps(response, indent=2))]
    except ServiceRefError as e:
        return [types.TextContent(type="text", text=json.dumps(
            {"error": "invalid_service_definition", "message": str(e)}, indent=2))]
    except Exception as e:
        error_msg = f"Failed to create service: {str(e)}"
        logger.error(error_msg, exc_info=True)
        return [types.TextContent(type="text", text=json.dumps({"error": error_msg}, indent=2))]


def handle_update_service(ctx, arguments: dict) -> list:
    logger.debug("UPDATE SERVICE CALLED with arguments: %s", ScrubbedArgs(arguments))
    try:
        pce = ctx.pce

        # Find service by href or name
        service_href = None
        if arguments.get("href"):
            service_href = arguments["href"]
        elif arguments.get("name"):
            services = pce.services.get(params={"name": arguments["name"]})
            if services:
                service_href = services[0].href
            else:
                return [types.TextContent(type="text", text=json.dumps({"error": f"Service '{arguments['name']}' not found"}))]

        if not service_href:
            return [types.TextContent(type="text", text=json.dumps({"error": "Must provide either 'href' or 'name'"}))]

        if '/active/' in service_href:
            service_href = service_href.replace('/active/', '/draft/')

        update_data = {}
        if "new_name" in arguments:
            update_data["name"] = arguments["new_name"]
        if "description" in arguments:
            update_data["description"] = arguments["description"]
        if "service_ports" in arguments:
            update_data["service_ports"] = arguments["service_ports"]
        for field in ("windows_services", "windows_egress_services"):
            if field in arguments:
                update_data[field] = normalise_windows_services(arguments[field], field)

        if not update_data:
            return [types.TextContent(type="text", text=json.dumps({"error": "No update fields provided"}))]

        pce.put(service_href, json=update_data)

        return [types.TextContent(
            type="text",
            text=json.dumps({"message": f"Successfully updated service {service_href}", "updated_fields": list(update_data.keys())}, indent=2)
        )]
    except ServiceRefError as e:
        return [types.TextContent(type="text", text=json.dumps(
            {"error": "invalid_service_definition", "message": str(e)}, indent=2))]
    except Exception as e:
        error_msg = f"Failed to update service: {str(e)}"
        logger.error(error_msg, exc_info=True)
        return [types.TextContent(type="text", text=json.dumps({"error": error_msg}, indent=2))]


def handle_delete_service(ctx, arguments: dict) -> list:
    logger.debug("DELETE SERVICE CALLED with arguments: %s", ScrubbedArgs(arguments))
    try:
        pce = ctx.pce

        service_href = None
        if arguments.get("href"):
            service_href = arguments["href"]
        elif arguments.get("name"):
            services = pce.services.get(params={"name": arguments["name"]})
            if services:
                service_href = services[0].href
            else:
                return [types.TextContent(type="text", text=json.dumps({"error": f"Service '{arguments['name']}' not found"}))]

        if not service_href:
            return [types.TextContent(type="text", text=json.dumps({"error": "Must provide either 'href' or 'name'"}))]

        if '/active/' in service_href:
            service_href = service_href.replace('/active/', '/draft/')

        pce.delete(service_href)

        return [types.TextContent(
            type="text",
            text=json.dumps({"message": f"Successfully deleted service {service_href}"}, indent=2)
        )]
    except Exception as e:
        error_msg = f"Failed to delete service: {str(e)}"
        logger.error(error_msg, exc_info=True)
        return [types.TextContent(type="text", text=json.dumps({"error": error_msg}, indent=2))]
