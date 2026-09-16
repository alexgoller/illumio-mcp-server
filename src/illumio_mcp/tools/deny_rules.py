import json
import logging
import mcp.types as types
from ..log_scrub import ScrubbedArgs
from ..service_refs import (
    resolve_ingress_services, windows_qualified_services, ServiceRefError,
)

logger = logging.getLogger('illumio_mcp')


def actor_reference(ref, pce, value_href_map, side: str):
    """Turn one provider/consumer reference into a PCE actor object.

    Accepts "ams", "iplist:<name>", "key=value" label shorthand, or a bare
    HREF. The HREF branch dispatches on the path segment: previously ANY
    unrecognised string was assumed to be a label, so an IP-list HREF became
    {"label": {"href": ...}} and the PCE answered

        406 invalid_uri: Invalid URI: {{"href"=>"/orgs/.../ip_lists/..."}}

    Returns (actor, error_message). Exactly one is None.
    """
    if not isinstance(ref, str):
        return None, f"{side} reference must be a string, got {type(ref).__name__}: {ref!r}"
    if ref == "ams":
        return {"actors": "ams"}, None
    if ref.startswith("iplist:"):
        name = ref.split(":", 1)[1]
        matches = pce.ip_lists.get(params={"name": name})
        if not matches:
            return None, f"IP list not found: {name}"
        return {"ip_list": {"href": matches[0].href}}, None
    if ref in value_href_map:
        return {"label": {"href": value_href_map[ref]}}, None
    if ref.startswith("/orgs/"):
        for segment, key in (("/ip_lists/", "ip_list"),
                             ("/labels/", "label"),
                             ("/label_groups/", "label_group"),
                             ("/workloads/", "workload"),
                             ("/virtual_services/", "virtual_service"),
                             ("/virtual_servers/", "virtual_server")):
            if segment in ref:
                return {key: {"href": ref}}, None
        return None, (f"Unrecognised {side} HREF: {ref}. Expected one of "
                      "ip_lists, labels, label_groups, workloads, virtual_services, "
                      "virtual_servers.")
    return None, (f"Unrecognised {side} reference: {ref!r}. Use 'ams', "
                  "'iplist:<name>', 'key=value', or an HREF.")



def handle_create_deny_rule(ctx, arguments: dict) -> list:
    logger.debug("=" * 80)
    logger.debug("CREATE DENY RULE CALLED")
    logger.debug("Arguments received: %s", ScrubbedArgs(arguments))
    logger.debug("=" * 80)

    try:
        pce = ctx.pce

        # Build label maps
        label_href_map = {}
        value_href_map = {}
        for l in pce.labels.get(params={'max_results': 10000}):
            label_href_map[l.href] = {"key": l.key, "value": l.value}
            value_href_map["{}={}".format(l.key, l.value)] = l.href

        # Find the ruleset
        ruleset_href = None
        if arguments.get("ruleset_href"):
            ruleset_href = arguments["ruleset_href"]
            # Ensure it's a draft href
            if '/active/' in ruleset_href:
                ruleset_href = ruleset_href.replace('/active/', '/draft/')
        elif arguments.get("ruleset_name"):
            rulesets = pce.rule_sets.get(params={"name": arguments["ruleset_name"]})
            if not rulesets:
                return [types.TextContent(
                    type="text",
                    text=json.dumps({"error": f"Ruleset '{arguments['ruleset_name']}' not found"}, indent=2)
                )]
            ruleset_href = rulesets[0].href
            if '/active/' in ruleset_href:
                ruleset_href = ruleset_href.replace('/active/', '/draft/')
        else:
            return [types.TextContent(
                type="text",
                text=json.dumps({"error": "Must provide either 'ruleset_href' or 'ruleset_name'"}, indent=2)
            )]

        is_override = arguments.get("override_deny", False)
        rule_type = "override_deny" if is_override else "deny"

        # Guardrail: warn about override deny usage
        override_warning = None
        if is_override:
            override_warning = (
                "IMPORTANT: You are creating an OVERRIDE DENY rule. This is the highest priority deny "
                "in Illumio — it blocks traffic even when allow rules exist, overriding everything. "
                "Override deny means 'this traffic must not happen under any circumstances.' "
                "Use cases: emergency isolation of compromised systems, hard compliance blocks "
                "(e.g., PCI zones that must never reach the internet), or any scenario where "
                "no allow rule should ever override the block. "
                "Do NOT use override deny for normal segmentation or ringfencing — use regular deny rules instead. "
                "Rule processing order: Essential > Override Deny > Allow > Deny > Default."
            )
            logger.warning(f"Override deny rule being created: {override_warning}")

        # Build providers
        providers = []
        for ref in arguments["providers"]:
            actor, problem = actor_reference(ref, pce, value_href_map, "provider")
            if problem:
                return [types.TextContent(type="text",
                        text=json.dumps({"error": problem}))]
            providers.append(actor)

        # Build consumers
        consumers = []
        for ref in arguments["consumers"]:
            actor, problem = actor_reference(ref, pce, value_href_map, "consumer")
            if problem:
                return [types.TextContent(type="text",
                        text=json.dumps({"error": problem}))]
            consumers.append(actor)

        # Resolve ingress services. Inline ports, service hrefs and service
        # names all land here; anything unresolvable raises before the POST.
        try:
            ingress_services, resolved_display = resolve_ingress_services(
                pce, arguments.get("ingress_services"))
        except ServiceRefError as e:
            return [types.TextContent(type="text", text=json.dumps({
                "error": "invalid_ingress_services", "message": str(e)}, indent=2))]

        process_qualified = windows_qualified_services(pce, ingress_services)
        if process_qualified:
            return [types.TextContent(type="text", text=json.dumps({
                "error": "process_qualified_deny_unsupported",
                "services": process_qualified,
                "message": (
                    "Deny rules cannot use a service with Windows process or "
                    "service qualifiers -- the PCE matches the deny without "
                    "process context, so it would silently apply to the ports "
                    "alone. Write the process-qualified rule as an ALLOW above a "
                    "broad deny instead; allow rules are evaluated first."
                ),
            }, indent=2))]

        # Build the rule payload
        rule_payload = {
            "enabled": True,
            "providers": providers,
            "consumers": consumers,
            "ingress_services": ingress_services,
            "unscoped_consumers": arguments.get("unscoped_consumers", False),
            "override": rule_type == "override_deny"
        }

        endpoint = f"{ruleset_href}/deny_rules"

        logger.debug(f"Creating {rule_type} rule at endpoint: {endpoint}")
        logger.debug("Rule payload: %s", ScrubbedArgs(rule_payload))

        resp = pce.post(endpoint, json=rule_payload)
        result = resp.json()

        response = {
            "message": f"Successfully created {rule_type} rule",
            "rule": result,
            # Echo what was actually written, with names alongside hrefs -- an
            # href on its own is unreadable, and this is what lets a caller see
            # that "All Services" is what landed.
            "ingress_services_resolved": resolved_display,
        }
        if override_warning:
            response["override_deny_warning"] = override_warning

        return [types.TextContent(
            type="text",
            text=json.dumps(response, indent=2)
        )]

    except Exception as e:
            error_msg = f"Failed to create deny rule: {str(e)}"
            logger.error(error_msg, exc_info=True)
            return [types.TextContent(
                type="text",
                text=json.dumps({"error": error_msg}, indent=2)
            )]

def handle_update_deny_rule(ctx, arguments: dict) -> list:
    logger.debug("UPDATE DENY RULE CALLED with arguments: %s", ScrubbedArgs(arguments))

    try:
        pce = ctx.pce

        href = arguments["href"]
        if '/active/' in href:
            href = href.replace('/active/', '/draft/')

        update_data = {}
        if "enabled" in arguments:
            update_data["enabled"] = arguments["enabled"]

        # Build label maps if providers/consumers use key=value
        if arguments.get("providers") or arguments.get("consumers"):
            label_href_map = {}
            value_href_map = {}
            for l in pce.labels.get(params={'max_results': 10000}):
                label_href_map[l.href] = {"key": l.key, "value": l.value}
                value_href_map[f"{l.key}={l.value}"] = l.href

        if arguments.get("providers"):
            raw_providers = []
            for p in arguments["providers"]:
                if p == "ams":
                    raw_providers.append({"actors": "ams"})
                elif p.startswith("iplist:"):
                    ip_lists = pce.ip_lists.get(params={"name": p.split(":", 1)[1]})
                    if ip_lists:
                        raw_providers.append({"ip_list": {"href": ip_lists[0].href}})
                elif p in value_href_map:
                    raw_providers.append({"label": {"href": value_href_map[p]}})
                else:
                    raw_providers.append({"label": {"href": p}})
            update_data["providers"] = raw_providers

        if arguments.get("consumers"):
            raw_consumers = []
            for c in arguments["consumers"]:
                if c == "ams":
                    raw_consumers.append({"actors": "ams"})
                elif c.startswith("iplist:"):
                    ip_lists = pce.ip_lists.get(params={"name": c.split(":", 1)[1]})
                    if ip_lists:
                        raw_consumers.append({"ip_list": {"href": ip_lists[0].href}})
                elif c in value_href_map:
                    raw_consumers.append({"label": {"href": value_href_map[c]}})
                else:
                    raw_consumers.append({"label": {"href": c}})
            update_data["consumers"] = raw_consumers

        resolved_display = None
        if arguments.get("ingress_services"):
            try:
                raw_services, resolved_display = resolve_ingress_services(
                    pce, arguments["ingress_services"])
            except ServiceRefError as e:
                return [types.TextContent(type="text", text=json.dumps({
                    "error": "invalid_ingress_services", "message": str(e)}, indent=2))]
            process_qualified = windows_qualified_services(pce, raw_services)
            if process_qualified:
                return [types.TextContent(type="text", text=json.dumps({
                    "error": "process_qualified_deny_unsupported",
                    "services": process_qualified,
                    "message": ("Deny rules cannot use process-qualified services. "
                                "Use a qualified allow above a broad deny."),
                }, indent=2))]
            update_data["ingress_services"] = raw_services

        if not update_data:
            return [types.TextContent(type="text", text=json.dumps({"error": "No update fields provided"}))]

        pce.put(href, json=update_data)

        return [types.TextContent(
            type="text",
            text=json.dumps({"message": f"Successfully updated deny rule {href}",
                             "updated_fields": list(update_data.keys()),
                             **({"ingress_services_resolved": resolved_display}
                                if resolved_display else {})}, indent=2)
        )]
    except Exception as e:
            error_msg = f"Failed to update deny rule: {str(e)}"
            logger.error(error_msg, exc_info=True)
            return [types.TextContent(type="text", text=json.dumps({"error": error_msg}, indent=2))]


def handle_delete_deny_rule(ctx, arguments: dict) -> list:
    logger.debug("DELETE DENY RULE CALLED with arguments: %s", ScrubbedArgs(arguments))

    try:
        pce = ctx.pce

        href = arguments["href"]
        if '/active/' in href:
            href = href.replace('/active/', '/draft/')

        pce.delete(href)

        return [types.TextContent(
            type="text",
            text=json.dumps({"message": f"Successfully deleted deny rule {href}"}, indent=2)
        )]
    except Exception as e:
            error_msg = f"Failed to delete deny rule: {str(e)}"
            logger.error(error_msg, exc_info=True)
            return [types.TextContent(type="text", text=json.dumps({"error": error_msg}, indent=2))]


# Shared with sec_rules.py, which needs the same provider/consumer handling.
# Public alias kept because the name was private when only this module used it.
_actor_reference = actor_reference
