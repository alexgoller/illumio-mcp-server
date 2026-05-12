import json
import logging
import mcp.types as types

logger = logging.getLogger('illumio_mcp')


def handle_get_iplists(ctx, arguments: dict) -> list:
    logger.debug(f"GET IP LISTS CALLED with arguments: {json.dumps(arguments, indent=2)}")
    try:
        pce = ctx.pce

        params = {"max_results": arguments.get("max_results", 10000)}
        for param in ['name', 'description', 'fqdn', 'ip_address']:
            if arguments.get(param):
                params[param] = arguments[param]

        ip_lists = pce.ip_lists.get(params=params)

        iplist_data = []
        for iplist in ip_lists:
            iplist_dict = {
                'href': iplist.href,
                'name': iplist.name,
                'description': iplist.description,
                'ip_ranges': [str(ip_range) for ip_range in iplist.ip_ranges] if iplist.ip_ranges else [],
                'fqdns': [str(fqdn) for fqdn in iplist.fqdns] if hasattr(iplist, 'fqdns') and iplist.fqdns else [],
                'created_at': str(iplist.created_at) if hasattr(iplist, 'created_at') else None,
                'updated_at': str(iplist.updated_at) if hasattr(iplist, 'updated_at') else None,
            }
            iplist_data.append(iplist_dict)

        return [types.TextContent(
            type="text",
            text=json.dumps({"ip_lists": iplist_data, "total_count": len(iplist_data)}, indent=2)
        )]
    except Exception as e:
        error_msg = f"Failed to get IP lists: {str(e)}"
        logger.error(error_msg, exc_info=True)
        return [types.TextContent(type="text", text=json.dumps({"error": error_msg}))]


def handle_create_iplist(ctx, arguments: dict) -> list:
    logger.debug("=" * 80)
    logger.debug("CREATE IP LIST CALLED")
    logger.debug(f"Arguments received: {json.dumps(arguments, indent=2)}")
    logger.debug("=" * 80)

    try:
        logger.debug("Initializing PCE connection...")
        pce = ctx.pce

        # Check if IP List already exists
        logger.debug(f"Checking if IP List '{arguments['name']}' already exists...")
        existing_iplists = pce.ip_lists.get(params={"name": arguments["name"]})
        if existing_iplists:
            error_msg = f"IP List with name '{arguments['name']}' already exists"
            logger.error(error_msg)
            return [types.TextContent(
                type="text",
                text=json.dumps({
                    "error": error_msg,
                    "existing_iplist": {
                        "href": existing_iplists[0].href,
                        "name": existing_iplists[0].name
                    }
                }, indent=2)
            )]

        # Create IP ranges
        ip_ranges = []
        for range_def in arguments["ip_ranges"]:
            ip_range = {
                "from_ip": range_def["from_ip"],
                "exclusion": range_def.get("exclusion", False)
            }

            # Add optional fields if present
            if "to_ip" in range_def:
                ip_range["to_ip"] = range_def["to_ip"]
            if "description" in range_def:
                ip_range["description"] = range_def["description"]

            ip_ranges.append(ip_range)

        # Create the IP List object
        iplist_data = {
            "name": arguments["name"],
            "ip_ranges": ip_ranges
        }

        # Add optional fields if present
        if "description" in arguments:
            iplist_data["description"] = arguments["description"]
        if "fqdn" in arguments:
            iplist_data["fqdn"] = arguments["fqdn"]

        logger.debug(f"Creating IP List with data: {json.dumps(iplist_data, indent=2)}")
        iplist = pce.ip_lists.create(iplist_data)

        # Format response
        response_data = {
            "href": iplist.href,
            "name": iplist.name,
            "description": getattr(iplist, "description", None),
            "ip_ranges": [
                {
                    "from_ip": r.from_ip,
                    "to_ip": getattr(r, "to_ip", None),
                    "description": getattr(r, "description", None),
                    "exclusion": getattr(r, "exclusion", False)
                } for r in iplist.ip_ranges
            ],
            "fqdn": getattr(iplist, "fqdn", None)
        }

        return [types.TextContent(
            type="text",
            text=json.dumps(response_data, indent=2)
        )]

    except Exception as e:
        error_msg = f"Failed to create IP List: {str(e)}"
        logger.error(error_msg, exc_info=True)
        return [types.TextContent(
            type="text",
            text=json.dumps({"error": error_msg}, indent=2)
        )]


def handle_update_iplist(ctx, arguments: dict) -> list:
    logger.debug("=" * 80)
    logger.debug("UPDATE IP LIST CALLED")
    logger.debug(f"Arguments received: {json.dumps(arguments, indent=2)}")
    logger.debug("=" * 80)

    try:
        logger.debug("Initializing PCE connection...")
        pce = ctx.pce

        # Find the IP List
        iplist = None
        if "href" in arguments:
            logger.debug(f"Looking up IP List by href: {arguments['href']}")
            try:
                iplist = pce.ip_lists.get_by_reference(arguments['href'])
            except Exception as e:
                logger.error(f"Failed to find IP List by href: {str(e)}")
                return [types.TextContent(
                    type="text",
                    text=json.dumps({"error": f"IP List not found: {str(e)}"}, indent=2)
                )]
        else:
            logger.debug(f"Looking up IP List by name: {arguments['name']}")
            iplists = pce.ip_lists.get(params={"name": arguments["name"]})
            if iplists:
                iplist = iplists[0]
            else:
                return [types.TextContent(
                    type="text",
                    text=json.dumps({"error": f"IP List with name '{arguments['name']}' not found"}, indent=2)
                )]

        logger.debug(f"Found IP List: {iplist.href}, {iplist.name}")

        # Prepare update data
        update_data = {}
        if "description" in arguments:
            update_data["description"] = arguments["description"]
        if "fqdn" in arguments:
            update_data["fqdn"] = arguments["fqdn"]
        if "ip_ranges" in arguments:
            ip_ranges = []
            for range_def in arguments["ip_ranges"]:
                ip_range = {
                    "from_ip": range_def["from_ip"],
                    "exclusion": range_def.get("exclusion", False)
                }
                if "to_ip" in range_def:
                    ip_range["to_ip"] = range_def["to_ip"]
                if "description" in range_def:
                    ip_range["description"] = range_def["description"]
                ip_ranges.append(ip_range)
            update_data["ip_ranges"] = ip_ranges

        logger.debug(f"Updating IP List with data: {json.dumps(update_data, indent=2)}")

        # Update the IP List
        pce.ip_lists.update(iplist.href, update_data)

        # Fetch the updated IP List to get the current state
        updated_iplist = pce.ip_lists.get_by_reference(iplist.href)

        # Format response
        response_data = {
            "href": updated_iplist.href,
            "name": updated_iplist.name,
            "description": getattr(updated_iplist, "description", None),
            "ip_ranges": []
        }

        # Safely add IP ranges if they exist
        if hasattr(updated_iplist, 'ip_ranges') and updated_iplist.ip_ranges:
            for r in updated_iplist.ip_ranges:
                range_data = {"from_ip": r.from_ip}
                if hasattr(r, "to_ip"):
                    range_data["to_ip"] = r.to_ip
                if hasattr(r, "description"):
                    range_data["description"] = r.description
                if hasattr(r, "exclusion"):
                    range_data["exclusion"] = r.exclusion
                response_data["ip_ranges"].append(range_data)

        # Add FQDN if it exists
        if hasattr(updated_iplist, "fqdn"):
            response_data["fqdn"] = updated_iplist.fqdn

        return [types.TextContent(
            type="text",
            text=json.dumps(response_data, indent=2)
        )]

    except Exception as e:
        error_msg = f"Failed to update IP List: {str(e)}"
        logger.error(error_msg, exc_info=True)
        return [types.TextContent(
            type="text",
            text=json.dumps({"error": error_msg}, indent=2)
        )]


def handle_delete_iplist(ctx, arguments: dict) -> list:
    logger.debug("=" * 80)
    logger.debug("DELETE IP LIST CALLED")
    logger.debug(f"Arguments received: {json.dumps(arguments, indent=2)}")
    logger.debug("=" * 80)

    try:
        logger.debug("Initializing PCE connection...")
        pce = ctx.pce

        # Find the IP List
        iplist = None
        if "href" in arguments:
            logger.debug(f"Looking up IP List by href: {arguments['href']}")
            try:
                iplist = pce.ip_lists.get_by_reference(arguments['href'])
            except Exception as e:
                logger.error(f"Failed to find IP List by href: {str(e)}")
                return [types.TextContent(
                    type="text",
                    text=json.dumps({"error": f"IP List not found: {str(e)}"}, indent=2)
                )]
        else:
            logger.debug(f"Looking up IP List by name: {arguments['name']}")
            iplists = pce.ip_lists.get(params={"name": arguments["name"]})
            if iplists:
                iplist = iplists[0]
            else:
                return [types.TextContent(
                    type="text",
                    text=json.dumps({"error": f"IP List with name '{arguments['name']}' not found"}, indent=2)
                )]

        # Delete the IP List
        logger.debug(f"Deleting IP List: {iplist.href}")
        pce.ip_lists.delete(iplist.href)

        return [types.TextContent(
            type="text",
            text=json.dumps({
                "message": f"Successfully deleted IP List: {iplist.name}",
                "href": iplist.href
            }, indent=2)
        )]

    except Exception as e:
        error_msg = f"Failed to delete IP List: {str(e)}"
        logger.error(error_msg, exc_info=True)
        return [types.TextContent(
            type="text",
            text=json.dumps({"error": error_msg}, indent=2)
        )]
