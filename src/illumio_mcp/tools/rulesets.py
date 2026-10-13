import json
import logging
import mcp.types as types
from illumio import RuleSet, LabelSet, Rule, AMS, ServicePort
from ..log_scrub import ScrubbedArgs
from ..errors import describe_error
from ..label_refs import resolve_label_refs, encode_label_filter
from ..service_refs import (
    resolve_ingress_services, windows_qualified_services, consumer_os_warning,
    reject_egress_service_in_ingress, ServiceRefError,
)

logger = logging.getLogger('illumio_mcp')


POLICY_VERSIONS = ("draft", "active")
ACTOR_SIDES = ("consumer", "provider", "any")
_PROTO_NAMES = {1: "icmp", 6: "tcp", 17: "udp", 58: "icmpv6"}


class _PolicyNames:
    """href -> name lookups for the objects rules reference, fetched lazily and
    once. A ruleset listing names labels on every rule, IP lists on some and
    label groups on few, so each kind is fetched only when first seen."""

    def __init__(self, pce, policy_version: str):
        self.pce, self.pversion = pce, policy_version
        self._cache: dict[str, dict] = {}

    def label(self, href: str) -> dict:
        if "label" not in self._cache:
            self._cache["label"] = {
                l.href: {"key": l.key, "value": l.value}
                for l in self.pce.labels.get(params={"max_results": 10000})}
        info = self._cache["label"].get(href) or {}
        return {"key": info.get("key"), "value": info.get("value"), "href": href}

    def name(self, kind: str, href: str) -> dict:
        if kind not in self._cache:
            api = {"ip_list": "ip_lists", "label_group": "label_groups",
                   "service": "services"}.get(kind)
            objs = []
            if api is not None:
                try:
                    objs = getattr(self.pce, api).get(
                        policy_version=self.pversion, params={"max_results": 10000})
                except Exception as exc:                     # names are a nicety
                    logger.debug("could not list %s for names: %s", api, exc)
            self._cache[kind] = {o.href: getattr(o, "name", None) for o in objs}
        return {"name": self._cache[kind].get(href), "href": href}


def _ref_href(ref) -> str | None:
    if isinstance(ref, dict):
        return ref.get("href")
    return getattr(ref, "href", None) or (str(ref) if ref else None)


def _render_actor(actor, names: _PolicyNames) -> dict:
    """One consumer/provider/scope entry as plain data.

    The PCE's shape is {"label": {"href"}} | {"ip_list": {"href"}} |
    {"actors": "ams"} | ... -- the href is the identity, the name is what a
    reader needs, so both are returned.
    """
    if not isinstance(actor, dict):
        actor = actor.to_json() if hasattr(actor, "to_json") else {"raw": str(actor)}
    if actor.get("actors") == "ams":
        return {"all_workloads": True}
    for kind in ("label", "label_group", "ip_list", "workload",
                 "virtual_service", "virtual_server"):
        if actor.get(kind):
            href = _ref_href(actor[kind])
            if kind == "label":
                return {"label": names.label(href)}
            if kind in ("ip_list", "label_group"):
                return {kind: names.name(kind, href)}
            return {kind: {"href": href}}
    return {"raw": actor}


def _render_scope_entry(entry, names: _PolicyNames) -> dict:
    """A scope is a list of labels; show each as {key, value, href}."""
    rendered = _render_actor(entry, names)
    if "label" in rendered:
        return rendered["label"]
    if "label_group" in rendered:
        return {"label_group": rendered["label_group"]}
    return rendered


def _render_service(svc, names: _PolicyNames) -> dict:
    if not isinstance(svc, dict):
        svc = svc.to_json() if hasattr(svc, "to_json") else {"raw": str(svc)}
    if svc.get("href"):
        return {"service": names.name("service", svc["href"])}
    out: dict = {}
    if svc.get("port") is not None:
        out["port"] = svc["port"]
    if svc.get("to_port") is not None:
        out["to_port"] = svc["to_port"]
    proto = svc.get("proto")
    if proto is not None:
        out["proto"] = _PROTO_NAMES.get(proto, proto)
    for key in ("icmp_type", "icmp_code", "process_name", "windows_service_name",
                "service_name", "user_name"):
        if svc.get(key) is not None:
            out[key] = svc[key]
    return out or {"raw": svc}


def _render_rule(rule: dict, rule_type: str, names: _PolicyNames) -> dict:
    out = {
        "rule_type": rule_type,
        "href": rule.get("href"),
        "enabled": rule.get("enabled"),
        "description": rule.get("description"),
        "consumers": [_render_actor(a, names) for a in rule.get("consumers") or []],
        "providers": [_render_actor(a, names) for a in rule.get("providers") or []],
        "ingress_services": [_render_service(x, names) for x in rule.get("ingress_services") or []],
    }
    if rule_type == "allow":
        out["resolve_labels_as"] = rule.get("resolve_labels_as")
        if rule.get("unscoped_consumers"):
            out["unscoped_consumers"] = True
    return out


def _rule_names_all(rule: dict, hrefs: list[str], side: str) -> bool:
    """True when ONE side of the rule references every label in hrefs."""
    sides = ("consumers", "providers") if side == "any" else (side + "s",)
    for key in sides:
        present = {(a.get("label") or {}).get("href") for a in rule.get(key) or []
                   if isinstance(a, dict)}
        if all(h in present for h in hrefs):
            return True
    return False


def handle_get_rulesets(ctx, arguments: dict) -> list:
    logger.debug("GET RULESETS CALLED with arguments: %s", ScrubbedArgs(arguments))
    try:
        pce = ctx.pce

        pversion = str(arguments.get('pversion') or 'draft').lower()
        if pversion not in POLICY_VERSIONS:
            return [types.TextContent(type="text", text=json.dumps({
                "error": f"pversion must be 'draft' or 'active', got {pversion!r}"}))]

        params = {}
        for param in ['name', 'description']:
            if arguments.get(param):
                params[param] = arguments[param]
        if 'enabled' in arguments and arguments['enabled'] is not None:
            params['enabled'] = arguments['enabled']
        if arguments.get('max_results'):
            params['max_results'] = arguments['max_results']

        # Scope filter. key=value and HREFs resolve like get-workloads; a
        # string that already looks like the PCE's JSON encoding passes
        # through, so callers who built '[["/orgs/1/labels/5"]]' by hand keep
        # working. Raw pass-through of anything else was the 406 invalid_uri.
        labels = arguments.get('labels')
        if labels:
            if isinstance(labels, str) and labels.lstrip().startswith('['):
                params['labels'] = labels
            else:
                hrefs, unknown = resolve_label_refs(pce, labels)
                if unknown:
                    return [types.TextContent(type="text", text=json.dumps({
                        "error": "unresolved_label_filter",
                        "unresolved": unknown,
                        "message": "Use key=value with an existing label, or a label HREF.",
                    }))]
                params['labels'] = encode_label_filter(hrefs)

        # Actor filter: rules that NAME these labels as consumer or provider,
        # in any ruleset. The PCE has no server-side form of this, so it is a
        # client-side pass over the fetched rulesets -- still one call for the
        # caller instead of a fetch-everything-and-regex-the-hrefs.
        actor_hrefs, actor_side = None, 'any'
        if arguments.get('actor_labels'):
            actor_side = str(arguments.get('actor_side') or 'any').lower()
            if actor_side not in ACTOR_SIDES:
                return [types.TextContent(type="text", text=json.dumps({
                    "error": f"actor_side must be one of {', '.join(ACTOR_SIDES)}"}))]
            actor_hrefs, unknown = resolve_label_refs(pce, arguments['actor_labels'])
            if unknown:
                return [types.TextContent(type="text", text=json.dumps({
                    "error": "unresolved_actor_labels", "unresolved": unknown,
                    "message": "Use key=value with an existing label, or a label HREF.",
                }))]

        if params:
            rulesets = pce.rule_sets.get(policy_version=pversion, params=params)
        else:
            rulesets = pce.rule_sets.get_all(policy_version=pversion)

        names = _PolicyNames(pce, pversion)
        ruleset_data, rules_matched = [], 0
        for ruleset in rulesets:
            rs = ruleset.to_json() if hasattr(ruleset, "to_json") else dict(ruleset)
            rules = [_render_rule(r, 'allow', names) for r in rs.get('rules') or []]

            # Deny rules live on an undocumented endpoint, one call per ruleset.
            try:
                for dr in pce.get(f"{rs['href']}/deny_rules").json() or []:
                    rules.append(_render_rule(
                        dr, 'override_deny' if dr.get('override') else 'deny', names))
            except Exception as de:
                logger.debug(f"Could not fetch deny_rules for {rs.get('href')}: {de}")

            if actor_hrefs is not None:
                rules = [r for r in rules if _rule_names_all(r, actor_hrefs, actor_side)]
                rules_matched += len(rules)
                if not rules:
                    continue

            ruleset_data.append({
                'href': rs.get('href'),
                'name': rs.get('name'),
                'enabled': rs.get('enabled'),
                'description': rs.get('description'),
                'scopes': [[_render_scope_entry(a, names) for a in scope]
                           for scope in rs.get('scopes') or []],
                'rules': rules,
            })

        payload = {
            "policy_version": pversion,
            "rulesets": ruleset_data,
            "total_count": len(ruleset_data),
        }
        if actor_hrefs is not None:
            payload["actor_filter"] = {
                "labels": list(arguments['actor_labels']) if not isinstance(arguments['actor_labels'], str)
                          else [arguments['actor_labels']],
                "side": actor_side, "rules_matched": rules_matched}
        return [types.TextContent(type="text", text=json.dumps(payload, indent=2))]

    except Exception as e:
        error_msg = f"Failed to get rulesets: {describe_error(e)}"
        logger.error(error_msg, exc_info=True)
        return [types.TextContent(
            type="text",
            text=json.dumps({"error": error_msg})
        )]


def handle_create_ruleset(ctx, arguments: dict) -> list:
    logger.debug("=" * 80)
    logger.debug("CREATE RULESET CALLED")
    logger.debug("Arguments received: %s", ScrubbedArgs(arguments))
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
            logger.debug("Processing scopes: %s", ScrubbedArgs(arguments, 'scopes'))

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
                    elif isinstance(label, dict) and "key" in label and "value" in label:
                        # {"key": "app", "value": "vdi"} -- the form the schema's
                        # "array of label values" invites. This previously fell
                        # through to the catch-all, was skipped with only a log
                        # line, and produced an EMPTY scope: the ruleset was
                        # created unscoped and nothing told the caller.
                        key, value = label["key"], label["value"]
                        href = value_href_map.get(f"{key}={value}")
                        if not href:
                            return [types.TextContent(type="text", text=json.dumps({
                                "error": "label_not_found",
                                "message": f"No label {key}={value} exists in the PCE",
                            }))]
                        label_set.labels.append(pce.labels.get_by_reference(href))
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
                        # Never skip silently: a dropped scope label creates the
                        # ruleset WIDER than asked for, which is the dangerous
                        # direction for a policy object.
                        return [types.TextContent(type="text", text=json.dumps({
                            "error": "invalid_scope_label",
                            "message": ("Scope labels must be {'key':..., 'value':...}, "
                                        "{'href':...}, 'key=value', or a label HREF"),
                            "received": repr(label),
                        }))]

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
            logger.debug("Processing rules: %s", ScrubbedArgs(arguments, 'rules'))

            for rule_index, rule_def in enumerate(arguments["rules"]):
                logger.debug("Processing rule: %s", ScrubbedArgs(rule_def))

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

                # Resolve ingress services: inline ports, service hrefs and
                # service names alike. Resolution happens before anything is
                # written, so a bad reference cannot leave a half-built ruleset.
                try:
                    svc_payload, svc_display = resolve_ingress_services(
                        pce, rule_def.get("ingress_services"))
                except ServiceRefError as e:
                    return [types.TextContent(type="text", text=json.dumps({
                        "error": "invalid_ingress_services",
                        "rule_index": rule_index,
                        "message": str(e),
                        "note": ("Ruleset and any earlier rules were created; this "
                                 "rule was not."),
                    }, indent=2))]

                misplaced = reject_egress_service_in_ingress(pce, svc_payload)
                if misplaced:
                    return [types.TextContent(type="text", text=json.dumps({
                        "error": "egress_service_in_ingress",
                        "rule_index": rule_index,
                        "message": misplaced,
                    }, indent=2))]

                # Consumer-side process qualifier, if any. The SDK's Rule has no
                # egress_services field, so it is applied to the created rule
                # rather than passed to Rule.build.
                egress_payload, egress_display = [], []
                if rule_def.get("egress_services"):
                    try:
                        egress_payload, egress_display = resolve_ingress_services(
                            pce, rule_def["egress_services"])
                    except ServiceRefError as e:
                        return [types.TextContent(type="text", text=json.dumps({
                            "error": "invalid_egress_services",
                            "rule_index": rule_index,
                            "message": str(e),
                        }, indent=2))]

                # ServicePort for inline entries so the SDK serialises them as
                # before; href entries stay dicts, which Rule.build accepts.
                ingress_services = [
                    ServicePort(**item) if "port" in item else dict(item)
                    for item in svc_payload
                ]

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
                    raw_services = svc_payload

                    process_qualified = windows_qualified_services(pce, raw_services)
                    if process_qualified:
                        return [types.TextContent(type="text", text=json.dumps({
                            "error": "process_qualified_deny_unsupported",
                            "rule_index": rule_index,
                            "services": process_qualified,
                            "message": ("Deny rules cannot use process-qualified "
                                        "services. Use a qualified allow above a "
                                        "broad deny."),
                        }, indent=2))]

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
                        "services": svc_display,
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

                    if egress_payload:
                        rule_href = created_rule.href
                        if '/active/' in rule_href:
                            rule_href = rule_href.replace('/active/', '/draft/')
                        pce.put(rule_href, json={"egress_services": egress_payload})

                    entry = {
                        "href": created_rule.href,
                        "rule_type": "allow",
                        "providers": [str(p) for p in providers],
                        "consumers": [str(c) for c in consumers],
                        "services": svc_display,
                        "unscoped_consumers": rule_def.get("unscoped_consumers", False)
                    }
                    if egress_display:
                        entry["egress_services"] = egress_display
                    warning = consumer_os_warning(
                        pce, egress_payload or svc_payload, rule_def.get("consumers"))
                    if warning:
                        entry["policy_widening_warning"] = warning
                    created_rules.append(entry)

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
        error_msg = f"Failed to create ruleset: {describe_error(e)}"
        logger.error(error_msg, exc_info=True)
        return [types.TextContent(
            type="text",
            text=json.dumps({"error": error_msg})
        )]


def handle_update_ruleset(ctx, arguments: dict) -> list:
    logger.debug("=" * 80)
    logger.debug("UPDATE RULESET CALLED")
    logger.debug("Arguments received: %s", ScrubbedArgs(arguments))
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
                logger.error(f"Failed to find ruleset by href: {describe_error(e)}")
                return [types.TextContent(
                    type="text",
                    text=json.dumps({"error": f"Ruleset not found: {describe_error(e)}"}, indent=2)
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
            logger.debug("Processing scopes: %s", ScrubbedArgs(arguments, 'scopes'))
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
                    elif isinstance(label, dict) and "key" in label and "value" in label:
                        # {"key": "app", "value": "vdi"} -- the form the schema's
                        # "array of label values" invites. This previously fell
                        # through to the catch-all, was skipped with only a log
                        # line, and produced an EMPTY scope: the ruleset was
                        # created unscoped and nothing told the caller.
                        key, value = label["key"], label["value"]
                        href = value_href_map.get(f"{key}={value}")
                        if not href:
                            return [types.TextContent(type="text", text=json.dumps({
                                "error": "label_not_found",
                                "message": f"No label {key}={value} exists in the PCE",
                            }))]
                        label_set.labels.append(pce.labels.get_by_reference(href))
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
        error_msg = f"Failed to update ruleset: {describe_error(e)}"
        logger.error(error_msg, exc_info=True)
        return [types.TextContent(
            type="text",
            text=json.dumps({"error": error_msg}, indent=2)
        )]


def handle_delete_ruleset(ctx, arguments: dict) -> list:
    logger.debug("=" * 80)
    logger.debug("DELETE RULESET CALLED")
    logger.debug("Arguments received: %s", ScrubbedArgs(arguments))
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
                logger.error(f"Failed to find ruleset by href: {describe_error(e)}")
                return [types.TextContent(
                    type="text",
                    text=json.dumps({"error": f"Ruleset not found: {describe_error(e)}"}, indent=2)
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
        error_msg = f"Failed to delete ruleset: {describe_error(e)}"
        logger.error(error_msg, exc_info=True)
        return [types.TextContent(
            type="text",
            text=json.dumps({"error": error_msg}, indent=2)
        )]


def handle_provision_policy(ctx, arguments: dict) -> list:
    logger.debug("=" * 80)
    logger.debug("PROVISION POLICY CALLED")
    logger.debug("Arguments received: %s", ScrubbedArgs(arguments))
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
        error_msg = f"Failed to provision policy: {describe_error(e)}"
        logger.error(error_msg, exc_info=True)
        return [types.TextContent(type="text", text=json.dumps({"error": error_msg}, indent=2))]
