import json
import logging
from ipaddress import ip_address, ip_network
import mcp.types as types
from ..log_scrub import ScrubbedArgs
from ..errors import describe_error

logger = logging.getLogger('illumio_mcp')


POLICY_VERSIONS = ("draft", "active")
_DEFAULT_NETS = {ip_network("0.0.0.0/0"), ip_network("::/0")}


def _range_dict(r) -> dict:
    """One IPRange as plain data. The SDK repr was the previous shape, and a
    caller who wants to know whether an address is covered had to regex
    `from_ip=` out of it."""
    return {
        "from_ip": getattr(r, "from_ip", None),
        "to_ip": getattr(r, "to_ip", None),
        "exclusion": bool(getattr(r, "exclusion", False)),
        "description": getattr(r, "description", None),
    }


def _fqdn_dict(f) -> dict:
    return {"fqdn": getattr(f, "fqdn", None), "description": getattr(f, "description", None)}


def _range_contains(addr, rng: dict) -> bool:
    """`from_ip` is a CIDR, a single address, or -- when `to_ip` is set -- the
    start of an inclusive span. A range the PCE accepted but ipaddress does
    not parse, or one of the other IP version, does not contain anything."""
    try:
        if rng.get("to_ip"):
            lo, hi = ip_address(rng["from_ip"]), ip_address(rng["to_ip"])
            return lo.version == addr.version and lo <= addr <= hi
        net = ip_network(rng["from_ip"], strict=False)
        return net.version == addr.version and addr in net
    except (ValueError, TypeError):
        return False


def _matched_range(addr, ranges: list[dict]) -> dict | None:
    """The inclusion range that covers `addr`, or None when no range does or
    an exclusion range carves it back out. Exclusions win regardless of
    order, which is how the PCE evaluates them."""
    if any(r["exclusion"] and _range_contains(addr, r) for r in ranges):
        return None
    return next((r for r in ranges if not r["exclusion"] and _range_contains(addr, r)), None)


def _is_default(ranges: list[dict]) -> bool:
    """True for a list carrying 0.0.0.0/0 or ::/0 as an inclusion -- the
    built-in "Any" list, which covers every address and so says nothing
    about whether an address is "in an IP list"."""
    for r in ranges:
        if r["exclusion"] or r.get("to_ip"):
            continue
        try:
            if ip_network(r["from_ip"], strict=False) in _DEFAULT_NETS:
                return True
        except (ValueError, TypeError):
            continue
    return False


def handle_get_iplists(ctx, arguments: dict) -> list:
    logger.debug("GET IP LISTS CALLED with arguments: %s", ScrubbedArgs(arguments))
    try:
        pce = ctx.pce

        pversion = str(arguments.get('pversion') or 'draft').lower()
        if pversion not in POLICY_VERSIONS:
            return [types.TextContent(type="text", text=json.dumps({
                "error": f"pversion must be 'draft' or 'active', got {pversion!r}"}))]

        # Exact containment, evaluated here. The PCE's `ip_address` filter is
        # a substring match on the range text: it matches 10.20.30.4 against
        # 10.20.30.40/32 and never matches an address inside a CIDR.
        contains = None
        if arguments.get('contains_ip'):
            try:
                contains = ip_address(str(arguments['contains_ip']).strip())
            except ValueError:
                return [types.TextContent(type="text", text=json.dumps({
                    "error": f"contains_ip must be a single IPv4 or IPv6 address, "
                             f"got {arguments['contains_ip']!r}"}))]

        params = {"max_results": arguments.get("max_results", 10000)}
        for param in ['name', 'description', 'fqdn', 'ip_address']:
            if arguments.get(param):
                params[param] = arguments[param]

        ip_lists = pce.ip_lists.get(policy_version=pversion, params=params)

        iplist_data = []
        for iplist in ip_lists:
            ranges = [_range_dict(r) for r in (getattr(iplist, 'ip_ranges', None) or [])]
            matched = None
            if contains is not None:
                matched = _matched_range(contains, ranges)
                if matched is None:
                    continue
            iplist_dict = {
                'href': iplist.href,
                'name': iplist.name,
                'description': iplist.description,
                'is_default': _is_default(ranges),
                'ip_ranges': ranges,
                'fqdns': [_fqdn_dict(f) for f in (getattr(iplist, 'fqdns', None) or [])],
                'created_at': str(iplist.created_at) if hasattr(iplist, 'created_at') else None,
                'updated_at': str(iplist.updated_at) if hasattr(iplist, 'updated_at') else None,
            }
            if matched is not None:
                iplist_dict['matched_range'] = matched
            iplist_data.append(iplist_dict)

        payload = {
            "policy_version": pversion,
            "ip_lists": iplist_data,
            "total_count": len(iplist_data),
        }
        if contains is not None:
            payload["contains_ip"] = str(contains)
        return [types.TextContent(type="text", text=json.dumps(payload, indent=2))]
    except Exception as e:
        error_msg = f"Failed to get IP lists: {describe_error(e)}"
        logger.error(error_msg, exc_info=True)
        return [types.TextContent(type="text", text=json.dumps({"error": error_msg}))]


def handle_create_iplist(ctx, arguments: dict) -> list:
    logger.debug("=" * 80)
    logger.debug("CREATE IP LIST CALLED")
    logger.debug("Arguments received: %s", ScrubbedArgs(arguments))
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
        error_msg = f"Failed to create IP List: {describe_error(e)}"
        logger.error(error_msg, exc_info=True)
        return [types.TextContent(
            type="text",
            text=json.dumps({"error": error_msg}, indent=2)
        )]


def handle_update_iplist(ctx, arguments: dict) -> list:
    logger.debug("=" * 80)
    logger.debug("UPDATE IP LIST CALLED")
    logger.debug("Arguments received: %s", ScrubbedArgs(arguments))
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
                logger.error(f"Failed to find IP List by href: {describe_error(e)}")
                return [types.TextContent(
                    type="text",
                    text=json.dumps({"error": f"IP List not found: {describe_error(e)}"}, indent=2)
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
        error_msg = f"Failed to update IP List: {describe_error(e)}"
        logger.error(error_msg, exc_info=True)
        return [types.TextContent(
            type="text",
            text=json.dumps({"error": error_msg}, indent=2)
        )]


def handle_delete_iplist(ctx, arguments: dict) -> list:
    logger.debug("=" * 80)
    logger.debug("DELETE IP LIST CALLED")
    logger.debug("Arguments received: %s", ScrubbedArgs(arguments))
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
                logger.error(f"Failed to find IP List by href: {describe_error(e)}")
                return [types.TextContent(
                    type="text",
                    text=json.dumps({"error": f"IP List not found: {describe_error(e)}"}, indent=2)
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
        error_msg = f"Failed to delete IP List: {describe_error(e)}"
        logger.error(error_msg, exc_info=True)
        return [types.TextContent(
            type="text",
            text=json.dumps({"error": error_msg}, indent=2)
        )]
