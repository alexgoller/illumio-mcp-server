"""Update and delete individual allow rules (`sec_rules`) inside a ruleset.

create-ruleset could create allow rules but nothing could change one afterwards,
so refining a rule -- swapping a placeholder 443/tcp for a process-qualified
service, say -- meant deleting the whole ruleset and rebuilding it, losing any
other rules in it. These mirror update-deny-rule / delete-deny-rule so the two
rule families behave the same way.
"""
import json
import logging

import mcp.types as types

from ..log_scrub import ScrubbedArgs
from ..service_refs import (
    resolve_ingress_services, consumer_os_warning,
    reject_egress_service_in_ingress, ServiceRefError,
)
from .deny_rules import actor_reference

logger = logging.getLogger('illumio_mcp')


def _label_value_map(pce) -> dict:
    return {f"{l.key}={l.value}": l.href
            for l in pce.labels.get(params={'max_results': 10000})}


def _build_actors(pce, refs, side, value_href_map):
    """Returns (actors, error). Resolution is all-or-nothing."""
    actors = []
    for ref in refs:
        actor, problem = actor_reference(ref, pce, value_href_map, side)
        if problem:
            return None, problem
        actors.append(actor)
    return actors, None


def handle_update_sec_rule(ctx, arguments: dict) -> list:
    """Update an allow rule in place. Only supplied fields change."""
    logger.debug("UPDATE SEC RULE CALLED with arguments: %s", ScrubbedArgs(arguments))
    try:
        pce = ctx.pce
        href = arguments["href"]
        if "/sec_rules/" not in href:
            return [types.TextContent(type="text", text=json.dumps({
                "error": "invalid_href",
                "message": (f"{href} is not a sec_rule href. Expected "
                            ".../rule_sets/<id>/sec_rules/<id>. For deny rules "
                            "use update-deny-rule."),
            }, indent=2))]

        update_data = {}
        resolved_display = None

        if arguments.get("ingress_services"):
            try:
                payload, resolved_display = resolve_ingress_services(
                    pce, arguments["ingress_services"])
            except ServiceRefError as e:
                return [types.TextContent(type="text", text=json.dumps({
                    "error": "invalid_ingress_services", "message": str(e)}, indent=2))]
            misplaced = reject_egress_service_in_ingress(pce, payload)
            if misplaced:
                return [types.TextContent(type="text", text=json.dumps({
                    "error": "egress_service_in_ingress", "message": misplaced}, indent=2))]
            update_data["ingress_services"] = payload

        if arguments.get("egress_services"):
            # Consumer-side process qualifier. Separate from ingress_services,
            # which stays the provider-side port.
            try:
                egress_payload, egress_display = resolve_ingress_services(
                    pce, arguments["egress_services"])
            except ServiceRefError as e:
                return [types.TextContent(type="text", text=json.dumps({
                    "error": "invalid_egress_services", "message": str(e)}, indent=2))]
            update_data["egress_services"] = egress_payload

        if arguments.get("providers") or arguments.get("consumers"):
            value_href_map = _label_value_map(pce)
            for side, key in (("provider", "providers"), ("consumer", "consumers")):
                if arguments.get(key):
                    actors, problem = _build_actors(pce, arguments[key], side, value_href_map)
                    if problem:
                        return [types.TextContent(type="text", text=json.dumps({
                            "error": "invalid_actor", "message": problem}, indent=2))]
                    update_data[key] = actors

        for field in ("enabled", "description", "unscoped_consumers"):
            if field in arguments:
                update_data[field] = arguments[field]

        if not update_data:
            return [types.TextContent(type="text", text=json.dumps({
                "error": "no_update_fields",
                "message": ("Supply at least one of ingress_services, providers, "
                            "consumers, enabled, description, unscoped_consumers."),
            }, indent=2))]

        pce.put(href, json=update_data)

        # The PUT returns 204, so re-fetch to report what the PCE actually stored
        # rather than echoing the request back as though it were confirmation.
        stored = None
        try:
            resp = pce.get(href)
            resp.raise_for_status()
            stored = resp.json()
        except Exception as e:
            logger.debug("could not re-read %s after update: %s", href, e)

        response = {
            "message": f"Successfully updated rule {href}",
            "updated_fields": sorted(update_data),
        }
        if arguments.get("egress_services"):
            response["egress_services_resolved"] = egress_display
        if resolved_display:
            response["ingress_services_resolved"] = resolved_display
            # Consumers may have been supplied in this call or already be on the
            # rule; use whichever we know about.
            consumers = arguments.get("consumers")
            if not consumers and stored:
                consumers = [f"{c.get('label', {}).get('href')}"
                             for c in stored.get("consumers", []) if c.get("label")]
            warning = consumer_os_warning(
                pce, update_data.get("egress_services") or update_data["ingress_services"],
                consumers)
            if warning:
                response["policy_widening_warning"] = warning
        if stored is not None:
            response["rule"] = stored
        return [types.TextContent(type="text", text=json.dumps(response, indent=2))]

    except Exception as e:
        error_msg = f"Failed to update rule: {str(e)}"
        logger.error(error_msg, exc_info=True)
        return [types.TextContent(type="text", text=json.dumps({"error": error_msg}, indent=2))]


def handle_delete_sec_rule(ctx, arguments: dict) -> list:
    """Delete a single allow rule, leaving the rest of the ruleset intact."""
    logger.debug("DELETE SEC RULE CALLED with arguments: %s", ScrubbedArgs(arguments))
    try:
        pce = ctx.pce
        href = arguments["href"]
        if "/sec_rules/" not in href:
            return [types.TextContent(type="text", text=json.dumps({
                "error": "invalid_href",
                "message": (f"{href} is not a sec_rule href. For deny rules use "
                            "delete-deny-rule."),
            }, indent=2))]

        pce.delete(href)
        return [types.TextContent(type="text", text=json.dumps({
            "message": f"Successfully deleted rule {href}",
            "note": "Draft policy changed. Provision to make it active.",
        }, indent=2))]
    except Exception as e:
        error_msg = f"Failed to delete rule: {str(e)}"
        logger.error(error_msg, exc_info=True)
        return [types.TextContent(type="text", text=json.dumps({"error": error_msg}, indent=2))]
