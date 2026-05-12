import json
import logging
import mcp.types as types

logger = logging.getLogger('illumio_mcp')


def handle_get_services(ctx, arguments: dict) -> list:
    logger.debug("=" * 80)
    logger.debug("GET SERVICES CALLED")
    logger.debug(f"Arguments received: {json.dumps(arguments, indent=2)}")
    logger.debug("=" * 80)

    try:
        logger.debug("Initializing PCE connection...")
        pce = ctx.pce

        params = {}
        for param in ['name', 'description', 'port', 'proto', 'process_name', 'max_results']:
            if arguments.get(param):
                params[param] = arguments[param]

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

            # Add windows services if present
            if hasattr(service, 'windows_services') and service.windows_services:
                logger.debug(f"Found windows_services for {service.name}")
                ws_list = []
                for ws in service.windows_services:
                    ws_dict = {}
                    if hasattr(ws, 'service_name') and ws.service_name:
                        ws_dict['service_name'] = ws.service_name
                    if hasattr(ws, 'process_name') and ws.process_name:
                        ws_dict['process_name'] = ws.process_name
                    if hasattr(ws, 'port') and ws.port is not None:
                        ws_dict['port'] = ws.port
                    if hasattr(ws, 'proto') and ws.proto:
                        ws_dict['proto'] = ws.proto
                    if hasattr(ws, 'to_port') and ws.to_port is not None:
                        ws_dict['to_port'] = ws.to_port
                    ws_list.append(ws_dict)
                service_dict['windows_services'] = ws_list

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
    logger.debug(f"CREATE SERVICE CALLED with arguments: {json.dumps(arguments, indent=2)}")
    try:
        pce = ctx.pce

        payload = {
            "name": arguments["name"],
            "service_ports": arguments["service_ports"],
        }
        if arguments.get("description"):
            payload["description"] = arguments["description"]

        resp = pce.post("/sec_policy/draft/services", json=payload)
        result = resp.json()

        return [types.TextContent(
            type="text",
            text=json.dumps({"message": "Successfully created service", "service": result}, indent=2)
        )]
    except Exception as e:
        error_msg = f"Failed to create service: {str(e)}"
        logger.error(error_msg, exc_info=True)
        return [types.TextContent(type="text", text=json.dumps({"error": error_msg}, indent=2))]


def handle_update_service(ctx, arguments: dict) -> list:
    logger.debug(f"UPDATE SERVICE CALLED with arguments: {json.dumps(arguments, indent=2)}")
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

        if not update_data:
            return [types.TextContent(type="text", text=json.dumps({"error": "No update fields provided"}))]

        pce.put(service_href, json=update_data)

        return [types.TextContent(
            type="text",
            text=json.dumps({"message": f"Successfully updated service {service_href}", "updated_fields": list(update_data.keys())}, indent=2)
        )]
    except Exception as e:
        error_msg = f"Failed to update service: {str(e)}"
        logger.error(error_msg, exc_info=True)
        return [types.TextContent(type="text", text=json.dumps({"error": error_msg}, indent=2))]


def handle_delete_service(ctx, arguments: dict) -> list:
    logger.debug(f"DELETE SERVICE CALLED with arguments: {json.dumps(arguments, indent=2)}")
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
