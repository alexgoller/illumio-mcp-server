import json
import logging
import mcp.types as types
from ..pce import get_pce

logger = logging.getLogger('illumio_mcp')


def handle_create_deny_rule(arguments: dict) -> list:
    logger.debug("=" * 80)
    logger.debug("CREATE DENY RULE CALLED")
    logger.debug(f"Arguments received: {json.dumps(arguments, indent=2)}")
    logger.debug("=" * 80)

    try:
        pce = get_pce()

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
        for provider in arguments["providers"]:
            if provider == "ams":
                providers.append({"actors": "ams"})
            elif provider.startswith("iplist:"):
                ip_list_name = provider.split(":", 1)[1]
                ip_lists = pce.ip_lists.get(params={"name": ip_list_name})
                if ip_lists:
                    providers.append({"ip_list": {"href": ip_lists[0].href}})
                else:
                    return [types.TextContent(
                        type="text",
                        text=json.dumps({"error": f"IP list not found: {ip_list_name}"})
                    )]
            elif provider in value_href_map:
                providers.append({"label": {"href": value_href_map[provider]}})
            else:
                providers.append({"label": {"href": provider}})

        # Build consumers
        consumers = []
        for consumer in arguments["consumers"]:
            if consumer == "ams":
                consumers.append({"actors": "ams"})
            elif consumer.startswith("iplist:"):
                ip_list_name = consumer.split(":", 1)[1]
                ip_lists = pce.ip_lists.get(params={"name": ip_list_name})
                if ip_lists:
                    consumers.append({"ip_list": {"href": ip_lists[0].href}})
                else:
                    return [types.TextContent(
                        type="text",
                        text=json.dumps({"error": f"IP list not found: {ip_list_name}"})
                    )]
            elif consumer in value_href_map:
                consumers.append({"label": {"href": value_href_map[consumer]}})
            else:
                consumers.append({"label": {"href": consumer}})

        # Build ingress services
        proto_map = {"tcp": 6, "udp": 17, "icmp": 1}
        ingress_services = []
        for svc in arguments["ingress_services"]:
            proto_val = svc["proto"]
            if isinstance(proto_val, str):
                proto_val = proto_map.get(proto_val.lower(), proto_val)
            ingress_services.append({"port": svc["port"], "proto": proto_val})

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
        logger.debug(f"Rule payload: {json.dumps(rule_payload, indent=2)}")

        resp = pce.post(endpoint, json=rule_payload)
        result = resp.json()

        response = {
            "message": f"Successfully created {rule_type} rule",
            "rule": result
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

def handle_update_deny_rule(arguments: dict) -> list:
    logger.debug(f"UPDATE DENY RULE CALLED with arguments: {json.dumps(arguments, indent=2)}")

    try:
        pce = get_pce()

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

        if arguments.get("ingress_services"):
            proto_map = {"tcp": 6, "udp": 17, "icmp": 1}
            raw_services = []
            for svc in arguments["ingress_services"]:
                proto_val = svc["proto"]
                if isinstance(proto_val, str):
                    proto_val = proto_map.get(proto_val.lower(), proto_val)
                raw_services.append({"port": svc["port"], "proto": proto_val})
            update_data["ingress_services"] = raw_services

        if not update_data:
            return [types.TextContent(type="text", text=json.dumps({"error": "No update fields provided"}))]

        pce.put(href, json=update_data)

        return [types.TextContent(
            type="text",
            text=json.dumps({"message": f"Successfully updated deny rule {href}", "updated_fields": list(update_data.keys())}, indent=2)
        )]
    except Exception as e:
            error_msg = f"Failed to update deny rule: {str(e)}"
            logger.error(error_msg, exc_info=True)
            return [types.TextContent(type="text", text=json.dumps({"error": error_msg}, indent=2))]


def handle_delete_deny_rule(arguments: dict) -> list:
    logger.debug(f"DELETE DENY RULE CALLED with arguments: {json.dumps(arguments, indent=2)}")

    try:
        pce = get_pce()

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
