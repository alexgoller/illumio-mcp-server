import json
import logging
import mcp.types as types
from illumio import RuleSet, LabelSet, Rule, AMS, ServicePort
from ..log_scrub import scrub_arguments_for_log

logger = logging.getLogger('illumio_mcp')


def handle_get_rulesets(ctx, arguments: dict) -> list:
    logger.debug(f"GET RULESETS CALLED with arguments: {json.dumps(scrub_arguments_for_log(arguments), indent=2)}")
    try:
        pce = ctx.pce

        params = {}
        for param in ['name', 'description', 'labels']:
            if arguments.get(param):
                params[param] = arguments[param]
        if 'enabled' in arguments and arguments['enabled'] is not None:
            params['enabled'] = arguments['enabled']
        if arguments.get('max_results'):
            params['max_results'] = arguments['max_results']

        rulesets = pce.rule_sets.get(params=params) if params else pce.rule_sets.get_all()

        # Convert rulesets to serializable format
        ruleset_data = []
        for ruleset in rulesets:
            rules = []
            for rule in ruleset.rules:
                rule_dict = {
                    'rule_type': 'allow',
                    'enabled': rule.enabled,
                    'description': rule.description,
                    'resolve_labels_as': str(rule.resolve_labels_as) if rule.resolve_labels_as else None,
                    'consumers': [str(consumer) for consumer in rule.consumers] if rule.consumers else [],
                    'providers': [str(provider) for provider in rule.providers] if rule.providers else [],
                    'ingress_services': [str(service) for service in rule.ingress_services] if rule.ingress_services else []
                }
                rules.append(rule_dict)

            # Fetch deny rules via raw API (override flag distinguishes override deny rules)
            try:
                resp = pce.get(f"{ruleset.href}/deny_rules")
                deny_rules = resp.json()
                if deny_rules:
                    for dr in deny_rules:
                        is_override = dr.get('override', False)
                        rule_dict = {
                            'rule_type': 'override_deny' if is_override else 'deny',
                            'href': dr.get('href'),
                            'enabled': dr.get('enabled'),
                            'description': dr.get('description'),
                            'consumers': [str(c) for c in dr.get('consumers', [])],
                            'providers': [str(p) for p in dr.get('providers', [])],
                            'ingress_services': [str(s) for s in dr.get('ingress_services', [])]
                        }
                        rules.append(rule_dict)
            except Exception as de:
                logger.debug(f"Could not fetch deny_rules for {ruleset.href}: {de}")

            ruleset_dict = {
                'href': ruleset.href,
                'name': ruleset.name,
                'enabled': ruleset.enabled,
                'description': ruleset.description,
                'scopes': [str(scope) for scope in ruleset.scopes] if ruleset.scopes else [],
                'rules': rules
            }
            ruleset_data.append(ruleset_dict)

        return [types.TextContent(
            type="text",
            text=json.dumps({
                "rulesets": ruleset_data,
                "total_count": len(ruleset_data)
            }, indent=2)
        )]

    except Exception as e:
        error_msg = f"Failed to get rulesets: {str(e)}"
        logger.error(error_msg, exc_info=True)
        return [types.TextContent(
            type="text",
            text=json.dumps({"error": error_msg})
        )]


def handle_create_ruleset(ctx, arguments: dict) -> list:
    logger.debug("=" * 80)
    logger.debug("CREATE RULESET CALLED")
    logger.debug(f"Arguments received: {json.dumps(scrub_arguments_for_log(arguments), indent=2)}")
    logger.debug("=" * 80)

    try:
        logger.debug("Initializing PCE connection...")
        pce = ctx.pce

        # populate the label maps
        label_href_map = {}
        value_href_map = {}
        for l in pce.labels.get(params={'max_results': 10000}):
            label_href_map[l.href] = {"key": l.key, "value": l.value}
            value_href_map["{}={}".format(l.key, l.value)] = l.href

        # Check if ruleset already exists
        logger.debug(f"Checking if ruleset '{arguments['name']}' already exists...")
        existing_rulesets = pce.rule_sets.get(params={"name": arguments["name"]})
        if existing_rulesets:
            error_msg = f"Ruleset with name '{arguments['name']}' already exists"
            logger.error(error_msg)
            return [types.TextContent(
                type="text",
                text=json.dumps({
                    "error": error_msg,
                    "existing_ruleset": {
                        "href": existing_rulesets[0].href,
                        "name": existing_rulesets[0].name
                    }
                }, indent=2)
            )]

        # Create the ruleset
        logger.debug(f"Instantiating ruleset object: {arguments['name']}")
        ruleset = RuleSet(
            name=arguments["name"],
            description=arguments.get("description", "")
        )

        # Handle scopes
        label_sets = []
        if arguments.get("scopes"):
            logger.debug(f"Processing scopes: {json.dumps(scrub_arguments_for_log(arguments).get('scopes'), indent=2)}")

            for scope in arguments["scopes"]:
                label_set = LabelSet(labels=[])
                for label in scope:
                    logger.debug(f"Processing label: {label}")
                    if isinstance(label, dict) and "href" in label:
                        # Handle direct href references
                        logger.debug(f"Found label with href: {label['href']}")
                        append_label = pce.labels.get_by_reference(label["href"])
                        logger.debug(f"Appending label: {append_label}")
                        label_set.labels.append(append_label)
                    elif isinstance(label, str):
                        # Handle string references (either href or label value)
                        if label in value_href_map:
                            logger.debug(f"Found label value: {value_href_map[label]}")
                            append_label = pce.labels.get_by_reference(value_href_map[label])
                        else:
                            logger.debug(f"Assuming direct href: {label}")
                            append_label = pce.labels.get_by_reference(label)
                        logger.debug(f"Appending label: {append_label}")
                        label_set.labels.append(append_label)
                    else:
                        logger.warning(f"Unexpected label format: {label}")
                        continue

                label_sets.append(label_set)
                logger.debug(f"Label set: {label_set}")
        else:
            # If no scopes provided, create a default scope with all workloads
            logger.debug("No scopes provided, creating default scope with all workloads")
            label_sets = [LabelSet(labels=[])]

        logger.debug(f"Final ruleset scopes count: {len(label_sets)}")
        ruleset.scopes = label_sets

        # Create the ruleset in PCE
        logger.debug("Creating ruleset in PCE...")
        logger.debug(f"Ruleset object scopes: {[str(ls.labels) for ls in ruleset.scopes]}")
        ruleset = pce.rule_sets.create(ruleset)
        logger.debug(f"Ruleset created with href: {ruleset.href}")

        # Create rules if provided
        created_rules = []
        if arguments.get("rules"):
            logger.debug(f"Processing rules: {json.dumps(scrub_arguments_for_log(arguments).get('rules'), indent=2)}")

            for rule_def in arguments["rules"]:
                logger.debug(f"Processing rule: {json.dumps(rule_def, indent=2)}")

                # Process providers
                providers = []
                for provider in rule_def["providers"]:
                    if provider == "ams":
                        providers.append(AMS)
                    elif provider.startswith("iplist:"):
                        # Extract IP list name and look it up
                        ip_list_name = provider.split(":", 1)[1]
                        logger.debug(f"Looking up IP list: {ip_list_name}")
                        ip_lists = pce.ip_lists.get(params={"name": ip_list_name})
                        if ip_lists:
                            providers.append(ip_lists[0])
                        else:
                            logger.error(f"IP list not found: {ip_list_name}")
                            return [types.TextContent(
                                type="text",
                                text=json.dumps({"error": f"IP list not found: {ip_list_name}"})
                            )]
                    elif provider in value_href_map:
                        providers.append(pce.labels.get_by_reference(value_href_map[provider]))
                    else:
                        providers.append(pce.labels.get_by_reference(provider))

                # Process consumers
                consumers = []
                for consumer in rule_def["consumers"]:
                    if consumer == "ams":
                        consumers.append(AMS)
                    elif consumer.startswith("iplist:"):
                        # Extract IP list name and look it up
                        ip_list_name = consumer.split(":", 1)[1]
                        logger.debug(f"Looking up IP list: {ip_list_name}")
                        ip_lists = pce.ip_lists.get(params={"name": ip_list_name})
                        if ip_lists:
                            consumers.append(ip_lists[0])
                        else:
                            logger.error(f"IP list not found: {ip_list_name}")
                            return [types.TextContent(
                                type="text",
                                text=json.dumps({"error": f"IP list not found: {ip_list_name}"})
                            )]
                    elif consumer in value_href_map:
                        consumers.append(pce.labels.get_by_reference(value_href_map[consumer]))
                    else:
                        consumers.append(pce.labels.get_by_reference(consumer))

                # Create ingress services
                ingress_services = []
                for svc in rule_def["ingress_services"]:
                    service_port = ServicePort(
                        port=svc["port"],
                        proto=svc["proto"]
                    )
                    ingress_services.append(service_port)

                # Determine rule type
                rule_type = rule_def.get("rule_type", "allow")

                if rule_type in ("deny", "override_deny"):
                    # Deny/override deny rules use raw API since SDK doesn't support rule_type
                    proto_map = {"tcp": 6, "udp": 17, "icmp": 1}
                    raw_providers = []
                    for p in providers:
                        if p == AMS:
                            raw_providers.append({"actors": "ams"})
                        elif hasattr(p, 'href') and hasattr(p, 'key'):
                            raw_providers.append({"label": {"href": p.href}})
                        elif hasattr(p, 'href'):
                            raw_providers.append({"ip_list": {"href": p.href}})
                    raw_consumers = []
                    for c in consumers:
                        if c == AMS:
                            raw_consumers.append({"actors": "ams"})
                        elif hasattr(c, 'href') and hasattr(c, 'key'):
                            raw_consumers.append({"label": {"href": c.href}})
                        elif hasattr(c, 'href'):
                            raw_consumers.append({"ip_list": {"href": c.href}})
                    raw_services = []
                    for svc in ingress_services:
                        proto_val = svc.proto
                        if isinstance(proto_val, str):
                            proto_val = proto_map.get(proto_val.lower(), proto_val)
                        raw_services.append({"port": svc.port, "proto": proto_val})

                    rule_payload = {
                        "enabled": True,
                        "providers": raw_providers,
                        "consumers": raw_consumers,
                        "ingress_services": raw_services,
                        "unscoped_consumers": rule_def.get("unscoped_consumers", False),
                        "override": rule_type == "override_deny"
                    }

                    endpoint = f"{ruleset.href}/deny_rules"

                    logger.debug(f"Creating {rule_type} rule at: {endpoint}")
                    resp = pce.post(endpoint, json=rule_payload)
                    result = resp.json()
                    created_rules.append({
                        "href": result.get("href", ""),
                        "rule_type": rule_type,
                        "providers": [str(p) for p in providers],
                        "consumers": [str(c) for c in consumers],
                        "services": [f"{s.port}/{s.proto}" for s in ingress_services],
                        "unscoped_consumers": rule_def.get("unscoped_consumers", False)
                    })
                else:
                    # Standard allow rule using SDK
                    rule = Rule.build(
                        providers=providers,
                        consumers=consumers,
                        ingress_services=ingress_services,
                        unscoped_consumers=rule_def.get("unscoped_consumers", False)
                    )

                    created_rule = pce.rules.create(rule, parent=ruleset)
                    created_rules.append({
                        "href": created_rule.href,
                        "rule_type": "allow",
                        "providers": [str(p) for p in providers],
                        "consumers": [str(c) for c in consumers],
                        "services": [f"{s.port}/{s.proto}" for s in ingress_services],
                        "unscoped_consumers": rule_def.get("unscoped_consumers", False)
                    })

        # Update the response to include rules
        return [types.TextContent(
            type="text",
            text=json.dumps({
                "ruleset": {
                    "href": ruleset.href,
                    "name": ruleset.name,
                    "description": ruleset.description,
                    "rules": created_rules
                }
            }, indent=2)
        )]

    except Exception as e:
        error_msg = f"Failed to create ruleset: {str(e)}"
        logger.error(error_msg, exc_info=True)
        return [types.TextContent(
            type="text",
            text=json.dumps({"error": error_msg})
        )]


def handle_update_ruleset(ctx, arguments: dict) -> list:
    logger.debug("=" * 80)
    logger.debug("UPDATE RULESET CALLED")
    logger.debug(f"Arguments received: {json.dumps(scrub_arguments_for_log(arguments), indent=2)}")
    logger.debug("=" * 80)

    try:
        logger.debug("Initializing PCE connection...")
        pce = ctx.pce

        # Find the ruleset
        ruleset = None
        if "href" in arguments:
            logger.debug(f"Looking up ruleset by href: {arguments['href']}")
            try:
                ruleset = pce.rule_sets.get_by_reference(arguments['href'])
            except Exception as e:
                logger.error(f"Failed to find ruleset by href: {str(e)}")
                return [types.TextContent(
                    type="text",
                    text=json.dumps({"error": f"Ruleset not found: {str(e)}"}, indent=2)
                )]
        else:
            logger.debug(f"Looking up ruleset by name: {arguments['name']}")
            rulesets = pce.rule_sets.get(params={"name": arguments["name"]})
            if rulesets:
                ruleset = rulesets[0]
            else:
                return [types.TextContent(
                    type="text",
                    text=json.dumps({"error": f"Ruleset with name '{arguments['name']}' not found"}, indent=2)
                )]

        # Prepare update data
        update_data = {}
        if "description" in arguments:
            update_data["description"] = arguments["description"]
        if "enabled" in arguments:
            update_data["enabled"] = arguments["enabled"]

        # Handle scopes if provided
        if "scopes" in arguments:
            logger.debug(f"Processing scopes: {json.dumps(scrub_arguments_for_log(arguments).get('scopes'), indent=2)}")
            label_sets = []

            for scope in arguments["scopes"]:
                label_set = LabelSet(labels=[])
                for label in scope:
                    logger.debug(f"Processing label: {label}")
                    if isinstance(label, dict) and "href" in label:
                        # Handle direct href references
                        logger.debug(f"Found label with href: {label['href']}")
                        append_label = pce.labels.get_by_reference(label["href"])
                        logger.debug(f"Appending label: {append_label}")
                        label_set.labels.append(append_label)
                    elif isinstance(label, str):
                        # Handle string references (either href or label value)
                        if "=" in label:  # key=value format
                            key, value = label.split("=", 1)
                            labels = pce.labels.get(params={"key": key, "value": value})
                            if labels:
                                append_label = labels[0]
                                logger.debug(f"Appending label: {append_label}")
                                label_set.labels.append(append_label)
                        else:  # direct href
                            append_label = pce.labels.get_by_reference(label)
                            logger.debug(f"Appending label: {append_label}")
                            label_set.labels.append(append_label)

                label_sets.append(label_set)
                logger.debug(f"Label set: {label_set}")

            update_data["scopes"] = label_sets

        # Update the ruleset
        logger.debug(f"Updating ruleset with data: {update_data}")
        pce.rule_sets.update(ruleset.href, update_data)

        # Re-fetch the ruleset to get updated state
        updated_ruleset = pce.rule_sets.get_by_reference(ruleset.href)

        # Format response
        response_data = {
            "href": updated_ruleset.href,
            "name": updated_ruleset.name,
            "description": getattr(updated_ruleset, "description", None),
            "enabled": getattr(updated_ruleset, "enabled", None),
            "scopes": []
        }

        # Add scopes if they exist
        if hasattr(updated_ruleset, "scopes"):
            for scope in updated_ruleset.scopes:
                scope_labels = []
                for label in scope.labels:
                    scope_labels.append({
                        "href": label.href,
                        "key": label.key,
                        "value": label.value
                    })
                response_data["scopes"].append(scope_labels)

        return [types.TextContent(
            type="text",
            text=json.dumps(response_data, indent=2)
        )]

    except Exception as e:
        error_msg = f"Failed to update ruleset: {str(e)}"
        logger.error(error_msg, exc_info=True)
        return [types.TextContent(
            type="text",
            text=json.dumps({"error": error_msg}, indent=2)
        )]


def handle_delete_ruleset(ctx, arguments: dict) -> list:
    logger.debug("=" * 80)
    logger.debug("DELETE RULESET CALLED")
    logger.debug(f"Arguments received: {json.dumps(scrub_arguments_for_log(arguments), indent=2)}")
    logger.debug("=" * 80)

    try:
        logger.debug("Initializing PCE connection...")
        pce = ctx.pce

        # Find the ruleset
        ruleset = None
        if "href" in arguments:
            logger.debug(f"Looking up ruleset by href: {arguments['href']}")
            try:
                ruleset = pce.rule_sets.get_by_reference(arguments['href'])
            except Exception as e:
                logger.error(f"Failed to find ruleset by href: {str(e)}")
                return [types.TextContent(
                    type="text",
                    text=json.dumps({"error": f"Ruleset not found: {str(e)}"}, indent=2)
                )]
        else:
            logger.debug(f"Looking up ruleset by name: {arguments['name']}")
            rulesets = pce.rule_sets.get(params={"name": arguments["name"]})
            if rulesets:
                ruleset = rulesets[0]
            else:
                return [types.TextContent(
                    type="text",
                    text=json.dumps({"error": f"Ruleset with name '{arguments['name']}' not found"}, indent=2)
                )]

        # Delete the ruleset
        logger.debug(f"Deleting ruleset: {ruleset.href}")
        pce.rule_sets.delete(ruleset.href)

        return [types.TextContent(
            type="text",
            text=json.dumps({
                "message": f"Successfully deleted ruleset: {ruleset.name}",
                "href": ruleset.href
            }, indent=2)
        )]

    except Exception as e:
        error_msg = f"Failed to delete ruleset: {str(e)}"
        logger.error(error_msg, exc_info=True)
        return [types.TextContent(
            type="text",
            text=json.dumps({"error": error_msg}, indent=2)
        )]


def handle_provision_policy(ctx, arguments: dict) -> list:
    logger.debug("=" * 80)
    logger.debug("PROVISION POLICY CALLED")
    logger.debug(f"Arguments received: {json.dumps(scrub_arguments_for_log(arguments), indent=2)}")
    logger.debug("=" * 80)

    try:
        pce = ctx.pce

        change_description = arguments.get("change_description", "Provisioned via MCP")
        hrefs = arguments.get("hrefs")

        if hrefs:
            # Provision specific items using the SDK's PolicyChangeset
            # which correctly maps hrefs to typed keys (rule_sets, ip_lists, etc.)
            provision_hrefs = hrefs
        else:
            # Get all pending changes first
            resp = pce.get("/sec_policy/pending")
            pending = resp.json()

            if not pending:
                return [types.TextContent(type="text", text=json.dumps({
                    "message": "No pending draft changes to provision",
                    "status": "no_changes"
                }, indent=2))]

            # /sec_policy/pending returns a list of objects with 'href' keys,
            # or a dict with resource type keys containing lists of objects
            pending_hrefs = []
            if isinstance(pending, list):
                for item in pending:
                    if isinstance(item, dict) and 'href' in item:
                        pending_hrefs.append(item['href'])
            elif isinstance(pending, dict):
                # Response may be keyed by resource type: rule_sets, ip_lists, etc.
                for resource_type, items in pending.items():
                    if isinstance(items, list):
                        for item in items:
                            if isinstance(item, dict) and 'href' in item:
                                pending_hrefs.append(item['href'])

            if not pending_hrefs:
                return [types.TextContent(type="text", text=json.dumps({
                    "message": "No pending draft changes to provision",
                    "status": "no_changes"
                }, indent=2))]

            provision_hrefs = pending_hrefs

        # Use the SDK's provision_policy_changes method which correctly
        # builds a PolicyChangeset (mapping hrefs to rule_sets, ip_lists, etc.)
        policy_version = pce.provision_policy_changes(
            change_description=change_description,
            hrefs=provision_hrefs
        )

        return [types.TextContent(type="text", text=json.dumps({
            "message": "Policy provisioned successfully",
            "change_description": change_description,
            "version": policy_version.version,
            "workloads_affected": policy_version.workloads_affected,
            "href": policy_version.href
        }, indent=2))]

    except Exception as e:
        error_msg = f"Failed to provision policy: {str(e)}"
        logger.error(error_msg, exc_info=True)
        return [types.TextContent(type="text", text=json.dumps({"error": error_msg}, indent=2))]
