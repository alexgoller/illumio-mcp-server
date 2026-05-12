import json
import logging
from datetime import datetime, timedelta
from collections import defaultdict, deque
import mcp.types as types
from illumio import TrafficQuery, RuleSet, LabelSet, Rule, AMS, ServicePort
from illumio.explorer.trafficanalysis import TrafficQueryFilter
from illumio.util.jsonutils import Reference
from .traffic import to_dataframe
from .constants import MCP_BUG_MAX_RESULTS

logger = logging.getLogger('illumio_mcp')


def handle_create_ringfence(ctx, arguments: dict) -> list:
    logger.debug("=" * 80)
    logger.debug("CREATE RINGFENCE CALLED")
    logger.debug(f"Arguments received: {json.dumps(arguments, indent=2)}")
    logger.debug("=" * 80)

    try:
        pce = ctx.pce

        app_name = arguments["app_name"]
        env_name = arguments["env_name"]
        lookback_days = arguments.get("lookback_days", 30)
        dry_run = arguments.get("dry_run", False)
        selective = arguments.get("selective", False)
        deny_consumer = arguments.get("deny_consumer", "any")
        skip_allowed = arguments.get("skip_allowed", False)
        rs_name = arguments.get("ruleset_name", f"RF-{app_name}-{env_name}")

        # Step 1: Find app and env labels
        app_labels = pce.labels.get(params={"key": "app", "value": app_name})
        if not app_labels:
            return [types.TextContent(type="text", text=json.dumps({"error": f"App label '{app_name}' not found"}))]
        app_label = app_labels[0]

        env_labels = pce.labels.get(params={"key": "env", "value": env_name})
        if not env_labels:
            return [types.TextContent(type="text", text=json.dumps({"error": f"Env label '{env_name}' not found"}))]
        env_label = env_labels[0]

        logger.debug(f"Found labels: app={app_label.href}, env={env_label.href}")

        # Build label maps for resolving traffic flow labels
        label_href_map = {}
        for l in pce.labels.get(params={'max_results': 10000}):
            label_href_map[l.href] = {"key": l.key, "value": l.value}

        # Step 2: Find "All Services" service object and "Any (0.0.0.0/0)" IP list
        all_services = pce.services.get(params={"name": "All Services"})
        all_services_href = None
        if all_services:
            all_services_href = all_services[0].href
            logger.debug(f"Found All Services: {all_services_href}")
        else:
            logger.warning("'All Services' service object not found, will use port -1 fallback")

        any_iplist_href = None
        if deny_consumer in ("any", "ams_and_any"):
            any_iplists = pce.ip_lists.get(params={"name": "Any (0.0.0.0/0 and ::/0)"})
            if any_iplists:
                any_iplist_href = any_iplists[0].href
                logger.debug(f"Found Any IP list: {any_iplist_href}")
            else:
                # Try alternate name
                any_iplists = pce.ip_lists.get(params={"name": "Any (0.0.0.0/0)"})
                if any_iplists:
                    any_iplist_href = any_iplists[0].href
                    logger.debug(f"Found Any IP list (alt name): {any_iplist_href}")
                else:
                    logger.warning("'Any' IP list not found, falling back to deny_consumer='ams'")
                    deny_consumer = "ams"

        # Step 3: Query traffic flows for this app+env (as destination = inbound)
        start_date = (datetime.now() - timedelta(days=lookback_days)).strftime('%Y-%m-%d')
        end_date = datetime.now().strftime('%Y-%m-%d')

        # Build TrafficQueryFilter objects for the app+env labels
        app_filter = TrafficQueryFilter(label=Reference(href=app_label.href))
        env_filter = TrafficQueryFilter(label=Reference(href=env_label.href))

        traffic_query = TrafficQuery.build(
            start_date=start_date,
            end_date=end_date,
            include_sources=[[]],
            exclude_sources=[],
            include_destinations=[[app_filter, env_filter]],
            exclude_destinations=[],
            include_services=[],
            exclude_services=[],
            policy_decisions=[],
            exclude_workloads_from_ip_list_query=True,
            max_results=MCP_BUG_MAX_RESULTS,
            query_name='ringfence-inbound'
        )

        logger.debug("Querying inbound traffic flows...")
        inbound_flows = pce.get_traffic_flows_async(
            query_name='ringfence-inbound',
            traffic_query=traffic_query
        )

        # Step 4: Also query outbound traffic (this app as source)
        traffic_query_out = TrafficQuery.build(
            start_date=start_date,
            end_date=end_date,
            include_sources=[[app_filter, env_filter]],
            exclude_sources=[],
            include_destinations=[[]],
            exclude_destinations=[],
            include_services=[],
            exclude_services=[],
            policy_decisions=[],
            exclude_workloads_from_ip_list_query=True,
            max_results=MCP_BUG_MAX_RESULTS,
            query_name='ringfence-outbound'
        )

        logger.debug("Querying outbound traffic flows...")
        outbound_flows = pce.get_traffic_flows_async(
            query_name='ringfence-outbound',
            traffic_query=traffic_query_out
        )

        # Step 5: Convert flows to dataframes and group by app+env
        inbound_df = to_dataframe(pce, inbound_flows)
        outbound_df = to_dataframe(pce, outbound_flows)

        remote_apps_inbound = {}  # key: (app_value, env_value) -> list of {port, proto, connections}
        remote_apps_outbound = {}
        remote_apps_policy = {}  # key: (app_value, env_value) -> set of policy_decisions

        if not inbound_df.empty:
            # Group inbound by source app+env to find unique remote apps connecting in
            src_group_cols = []
            if 'src_app' in inbound_df.columns:
                src_group_cols.append('src_app')
            if 'src_env' in inbound_df.columns:
                src_group_cols.append('src_env')
            if src_group_cols and 'port' in inbound_df.columns and 'proto' in inbound_df.columns:
                group_cols = src_group_cols + ['port', 'proto']
                if 'policy_decision' in inbound_df.columns:
                    group_cols.append('policy_decision')
                group_cols = [c for c in group_cols if c in inbound_df.columns]
                inbound_grouped = inbound_df.groupby(group_cols)['num_connections'].sum().reset_index()
                for _, row in inbound_grouped.iterrows():
                    src_app_val = row.get('src_app')
                    src_env_val = row.get('src_env')
                    if not src_app_val or not src_env_val:
                        continue
                    if src_app_val == app_name and src_env_val == env_name:
                        continue  # Skip intra-app traffic
                    key = (src_app_val, src_env_val)
                    if key not in remote_apps_inbound:
                        remote_apps_inbound[key] = []
                    if key not in remote_apps_policy:
                        remote_apps_policy[key] = set()
                    policy = row.get('policy_decision', 'unknown')
                    remote_apps_policy[key].add(policy)
                    remote_apps_inbound[key].append({
                        "port": int(row['port']) if 'port' in row else None,
                        "proto": int(row['proto']) if 'proto' in row else None,
                        "connections": int(row['num_connections']),
                        "policy_decision": policy
                    })

        if not outbound_df.empty:
            dst_group_cols = []
            if 'dst_app' in outbound_df.columns:
                dst_group_cols.append('dst_app')
            if 'dst_env' in outbound_df.columns:
                dst_group_cols.append('dst_env')
            if dst_group_cols and 'port' in outbound_df.columns and 'proto' in outbound_df.columns:
                group_cols = dst_group_cols + ['port', 'proto']
                group_cols = [c for c in group_cols if c in outbound_df.columns]
                outbound_grouped = outbound_df.groupby(group_cols)['num_connections'].sum().reset_index()
                for _, row in outbound_grouped.iterrows():
                    dst_app_val = row.get('dst_app')
                    dst_env_val = row.get('dst_env')
                    if not dst_app_val or not dst_env_val:
                        continue
                    if dst_app_val == app_name and dst_env_val == env_name:
                        continue
                    key = (dst_app_val, dst_env_val)
                    if key not in remote_apps_outbound:
                        remote_apps_outbound[key] = []
                    remote_apps_outbound[key].append({
                        "port": int(row['port']) if 'port' in row else None,
                        "proto": int(row['proto']) if 'proto' in row else None,
                        "connections": int(row['num_connections'])
                    })

        logger.debug(f"Discovered {len(remote_apps_inbound)} inbound remote apps, {len(remote_apps_outbound)} outbound remote apps")

        # Classify each remote app's policy coverage
        # "already_allowed" = all flows are policy_decision=allowed
        # "newly_allowed" = at least one flow is potentially_blocked or blocked
        remote_apps_coverage = {}
        for key, decisions in remote_apps_policy.items():
            if decisions <= {'allowed'}:
                remote_apps_coverage[key] = "already_allowed"
            else:
                remote_apps_coverage[key] = "newly_allowed"

        already_allowed_count = sum(1 for v in remote_apps_coverage.values() if v == "already_allowed")
        newly_allowed_count = sum(1 for v in remote_apps_coverage.values() if v == "newly_allowed")

        # If skip_allowed, remove already-allowed remote apps
        skipped_already_allowed = []
        if skip_allowed:
            for key in list(remote_apps_inbound.keys()):
                if remote_apps_coverage.get(key) == "already_allowed":
                    logger.debug(f"Skipping already-allowed remote app: app={key[0]}, env={key[1]}")
                    skipped_already_allowed.append({"app": key[0], "env": key[1]})
                    del remote_apps_inbound[key]

        # Step 6: Build the result summary
        summary = {
            "app": app_name,
            "env": env_name,
            "app_label_href": app_label.href,
            "env_label_href": env_label.href,
            "lookback_days": lookback_days,
            "skip_allowed": skip_allowed,
            "policy_coverage": {
                "already_allowed": already_allowed_count,
                "newly_allowed": newly_allowed_count,
                "total_remote_apps": already_allowed_count + newly_allowed_count,
                "description": (
                    f"{already_allowed_count} remote apps already covered by existing policy, "
                    f"{newly_allowed_count} need new rules"
                )
            },
            "inbound_remote_apps": [
                {
                    "app": k[0], "env": k[1],
                    "coverage": remote_apps_coverage.get(k, "unknown"),
                    "observed_ports": v
                }
                for k, v in sorted(remote_apps_inbound.items())
            ],
            "outbound_remote_apps": [
                {"app": k[0], "env": k[1], "observed_ports": v}
                for k, v in sorted(remote_apps_outbound.items())
            ],
        }
        if skipped_already_allowed:
            summary["skipped_already_allowed"] = skipped_already_allowed

        summary["selective"] = selective
        if selective:
            summary["deny_consumer"] = deny_consumer

        if dry_run:
            summary["dry_run"] = True
            if selective:
                consumer_explain = {
                    "any": "Any (0.0.0.0/0) as consumer - deny rule only written to destination workloads (safest)",
                    "ams": "All Workloads as consumer - deny rule pushed to every managed source workload",
                    "ams_and_any": "All Workloads + Any (0.0.0.0/0) - maximum coverage for managed and unmanaged sources"
                }
                summary["message"] = (f"Dry run - no changes made. Selective mode with deny_consumer='{deny_consumer}': "
                    f"{consumer_explain.get(deny_consumer, '')}. "
                    "Will create allow rules for known remote apps plus a deny rule blocking all other inbound. "
                    "Rule order: allow > deny > default(allow-all). Review and run again with dry_run=false.")
            else:
                summary["message"] = "Dry run - no changes made. Review the discovered traffic and run again with dry_run=false to create the ringfence."
            return [types.TextContent(type="text", text=json.dumps(summary, indent=2))]

        # Step 7: Check if ruleset already exists - merge if so
        existing = pce.rule_sets.get(params={"name": rs_name})
        has_intra_scope = False
        has_deny_all_inbound = False
        existing_remote_keys = set()

        if existing:
            ruleset = existing[0]
            logger.debug(f"Merging into existing ruleset: {ruleset.href}")
            summary["merged"] = True

            # Scan existing allow rules for duplicates
            # SDK returns Actor objects: Actor(actors='ams') or Actor(label=Reference(href='...'))
            def is_ams_actor(actor):
                return hasattr(actor, 'actors') and actor.actors == 'ams'

            def get_label_href(actor):
                if hasattr(actor, 'label') and actor.label and hasattr(actor.label, 'href'):
                    return actor.label.href
                return None

            for rule in ruleset.rules:
                rule_app = None
                rule_env = None
                is_ams_consumers = False
                is_ams_providers = False
                is_unscoped = getattr(rule, 'unscoped_consumers', False)

                if rule.consumers:
                    for c in rule.consumers:
                        if is_ams_actor(c):
                            is_ams_consumers = True
                        else:
                            href = get_label_href(c)
                            if href:
                                info = label_href_map.get(href, {})
                                if info.get("key") == "app":
                                    rule_app = info.get("value")
                                elif info.get("key") == "env":
                                    rule_env = info.get("value")

                if rule.providers:
                    for p in rule.providers:
                        if is_ams_actor(p):
                            is_ams_providers = True

                # Detect intra-scope rule: AMS->AMS, not unscoped
                if is_ams_consumers and is_ams_providers and not is_unscoped:
                    has_intra_scope = True

                # Detect extra-scope rule by consumer app+env
                if rule_app and rule_env:
                    existing_remote_keys.add((rule_app, rule_env))

            # Scan existing deny rules
            try:
                rs_href = ruleset.href
                if '/active/' in rs_href:
                    rs_href = rs_href.replace('/active/', '/draft/')
                resp = pce.get(f"{rs_href}/deny_rules")
                existing_deny_rules = resp.json()
                for dr in existing_deny_rules:
                    if not dr.get('override', False):
                        # Regular deny rule - check if it's a deny-all-inbound
                        # Consumer could be AMS, Any IP list, or both
                        is_unscoped = dr.get('unscoped_consumers', False)
                        consumers_ams = any(c.get('actors') == 'ams' for c in dr.get('consumers', []))
                        consumers_iplist = any(c.get('ip_list') for c in dr.get('consumers', []))
                        providers_ams = any(p.get('actors') == 'ams' for p in dr.get('providers', []))
                        if is_unscoped and (consumers_ams or consumers_iplist) and providers_ams:
                            has_deny_all_inbound = True
            except Exception as de:
                logger.debug(f"Could not fetch deny_rules for merge check: {de}")

            summary["has_deny_all_inbound"] = has_deny_all_inbound

            # Remove already-covered remote apps from inbound list
            skipped = []
            for key in list(remote_apps_inbound.keys()):
                if key in existing_remote_keys:
                    logger.debug(f"Skipping already-covered remote app: app={key[0]}, env={key[1]}")
                    skipped.append({"app": key[0], "env": key[1]})
                    del remote_apps_inbound[key]
            if skipped:
                summary["skipped_existing_rules"] = skipped
        else:
            # Step 8: Create the ruleset scoped to [app, env]
            ruleset = RuleSet(name=rs_name, description=f"Ringfence for {app_name} ({env_name})")
            scope_labels = LabelSet(labels=[app_label, env_label])
            ruleset.scopes = [scope_labels]
            ruleset = pce.rule_sets.create(ruleset)
            logger.debug(f"Created ruleset: {ruleset.href}")
            summary["merged"] = False

        created_rules = []

        # Step 9: Create intra-scope rule if it doesn't already exist
        if not has_intra_scope:
            if all_services_href:
                intra_services = [{"href": all_services_href}]
            else:
                intra_services = [ServicePort(port=-1, proto=6), ServicePort(port=-1, proto=17)]

            intra_rule = Rule.build(
                providers=[AMS],
                consumers=[AMS],
                ingress_services=intra_services,
                unscoped_consumers=False
            )
            created_intra = pce.rules.create(intra_rule, parent=ruleset)
            created_rules.append({
                "type": "intra-scope",
                "href": created_intra.href,
                "description": "All workloads within app can communicate on All Services",
                "consumers": "All Workloads (in scope)",
                "providers": "All Workloads (in scope)",
                "services": "All Services"
            })

        # Step 10: For selective mode, create a deny rule blocking all inbound traffic
        if selective and not summary.get("has_deny_all_inbound", False):
            if all_services_href:
                deny_services = [{"href": all_services_href}]
            else:
                deny_services = [{"port": -1, "proto": 6}, {"port": -1, "proto": 17}]

            # Build consumers based on deny_consumer flavor
            if deny_consumer == "any":
                deny_consumers = [{"ip_list": {"href": any_iplist_href}}]
                consumer_desc = "Any (0.0.0.0/0) - deny written to destination only"
            elif deny_consumer == "ams":
                deny_consumers = [{"actors": "ams"}]
                consumer_desc = "All Workloads - deny pushed to all managed source workloads"
            elif deny_consumer == "ams_and_any":
                deny_consumers = [{"actors": "ams"}, {"ip_list": {"href": any_iplist_href}}]
                consumer_desc = "All Workloads + Any (0.0.0.0/0) - maximum coverage"
            else:
                deny_consumers = [{"ip_list": {"href": any_iplist_href}}]
                consumer_desc = "Any (0.0.0.0/0)"

            deny_payload = {
                "enabled": True,
                "providers": [{"actors": "ams"}],
                "consumers": deny_consumers,
                "ingress_services": deny_services,
                "unscoped_consumers": True,
                "override": False
            }

            ruleset_href = ruleset.href
            if '/active/' in ruleset_href:
                ruleset_href = ruleset_href.replace('/active/', '/draft/')

            resp = pce.post(f"{ruleset_href}/deny_rules", json=deny_payload)
            deny_result = resp.json()
            created_rules.append({
                "type": "deny (block all inbound)",
                "href": deny_result.get("href", ""),
                "description": f"Deny all inbound traffic to {app_name} ({env_name}) - selective enforcement",
                "consumers": consumer_desc,
                "deny_consumer_mode": deny_consumer,
                "providers": "All Workloads (in scope)",
                "services": "All Services"
            })
            logger.debug(f"Created deny rule for selective enforcement: {deny_result.get('href')}")

        # Step 11: Create extra-scope allow rules for each inbound remote app
        # In both standard and selective mode, known remote apps get allow rules.
        # Rule processing order: override_deny > allow > deny > default.
        # In selective mode the deny rule (step 10) catches unknown inbound,
        # but allow rules for known apps are processed first (step 3 in rule order).
        for (remote_app, remote_env), ports in sorted(remote_apps_inbound.items()):
            remote_app_labels = pce.labels.get(params={"key": "app", "value": remote_app})
            remote_env_labels = pce.labels.get(params={"key": "env", "value": remote_env})

            if not remote_app_labels or not remote_env_labels:
                logger.warning(f"Could not find labels for remote app={remote_app}, env={remote_env}, skipping")
                continue

            consumers = [remote_app_labels[0], remote_env_labels[0]]

            if all_services_href:
                extra_services = [{"href": all_services_href}]
            else:
                extra_services = [ServicePort(port=-1, proto=6), ServicePort(port=-1, proto=17)]

            extra_rule = Rule.build(
                providers=[AMS],
                consumers=consumers,
                ingress_services=extra_services,
                unscoped_consumers=True
            )
            coverage = remote_apps_coverage.get((remote_app, remote_env), "unknown")
            created_extra = pce.rules.create(extra_rule, parent=ruleset)
            created_rules.append({
                "type": "extra-scope allow (inbound)",
                "href": created_extra.href,
                "description": f"Allow {remote_app} ({remote_env}) -> {app_name} ({env_name})",
                "consumers": f"app={remote_app}, env={remote_env}",
                "providers": "All Workloads (in scope)",
                "services": "All Services",
                "coverage": coverage,
                "observed_ports": ports
            })

        # Build summary message
        extra_rules = [r for r in created_rules if r["type"] == "extra-scope allow (inbound)"]
        already_count = sum(1 for r in extra_rules if r.get("coverage") == "already_allowed")
        newly_count = sum(1 for r in extra_rules if r.get("coverage") == "newly_allowed")
        coverage_note = ""
        if already_count > 0 or newly_count > 0:
            coverage_note = (f" Policy coverage: {already_count} rules for already-allowed traffic "
                f"(documentation), {newly_count} rules for newly-allowed traffic (filling gaps).")

        if selective:
            deny_count = sum(1 for r in created_rules if r["type"].startswith("deny"))
            allow_count = sum(1 for r in created_rules if "allow" in r["type"])
            summary["enforcement_mode"] = "selective"
            summary["message"] = (f"Selective ringfence created with {len(created_rules)} rules: "
                f"{allow_count} allow (intra-scope + known remote apps), "
                f"{deny_count} deny-all-inbound. "
                f"In selective mode: allows are processed before deny, so known apps pass through "
                f"and everything else is blocked by the deny rule.{coverage_note}")
        else:
            summary["message"] = (f"Ringfence created with {len(created_rules)} rules "
                f"({1} intra-scope + {len(created_rules) - 1} extra-scope inbound).{coverage_note}")

        summary["ruleset"] = {
            "href": ruleset.href,
            "name": rs_name,
            "rules": created_rules
        }

        return [types.TextContent(type="text", text=json.dumps(summary, indent=2))]

    except Exception as e:
        error_msg = f"Failed to create ringfence: {str(e)}"
        logger.error(error_msg, exc_info=True)
        return [types.TextContent(type="text", text=json.dumps({"error": error_msg}, indent=2))]


def handle_ringfence_batch(ctx, arguments: dict) -> list:
    logger.debug("=" * 80)
    logger.debug("RINGFENCE BATCH CALLED")
    logger.debug(f"Arguments received: {json.dumps(arguments, indent=2)}")
    logger.debug("=" * 80)

    try:
        apps = arguments["apps"]
        auto_order = arguments.get("auto_order", False)
        dry_run = arguments.get("dry_run", False)
        lookback_days = arguments.get("lookback_days", 30)

        if auto_order:
            # Use infrastructure identification to order apps
            infra_result = handle_identify_infrastructure_services(ctx, {
                "lookback_days": lookback_days,
                "top_n": 1000
            })
            # Parse the result to build an ordering map
            try:
                infra_data = json.loads(infra_result[0].text)
                score_map = {}
                for r in infra_data.get("results", []):
                    score_map[(r["app"], r["env"])] = r["infrastructure_score"]
            except (json.JSONDecodeError, KeyError, IndexError):
                score_map = {}

            # Sort apps: infrastructure (higher score) first
            apps.sort(key=lambda a: score_map.get((a["app_name"], a["env_name"]), 0), reverse=True)

        results = []
        for app in apps:
            rf_args = {
                "app_name": app["app_name"],
                "env_name": app["env_name"],
                "lookback_days": lookback_days,
                "dry_run": dry_run,
                "selective": app.get("selective", False)
            }

            try:
                rf_result = handle_create_ringfence(ctx, rf_args)
                result_data = json.loads(rf_result[0].text)
                results.append({
                    "app": app["app_name"],
                    "env": app["env_name"],
                    "status": "success",
                    "result": result_data
                })
            except Exception as app_err:
                results.append({
                    "app": app["app_name"],
                    "env": app["env_name"],
                    "status": "error",
                    "error": str(app_err)
                })

        success_count = sum(1 for r in results if r["status"] == "success")
        error_count = sum(1 for r in results if r["status"] == "error")

        output = {
            "summary": {
                "total_apps": len(apps),
                "successful": success_count,
                "errors": error_count,
                "dry_run": dry_run,
                "auto_ordered": auto_order
            },
            "results": results
        }

        return [types.TextContent(type="text", text=json.dumps(output, indent=2))]

    except Exception as e:
        error_msg = f"Failed batch ringfence: {str(e)}"
        logger.error(error_msg, exc_info=True)
        return [types.TextContent(type="text", text=json.dumps({"error": error_msg}, indent=2))]


def handle_identify_infrastructure_services(ctx, arguments: dict) -> list:
    logger.debug("=" * 80)
    logger.debug("IDENTIFY INFRASTRUCTURE SERVICES CALLED")
    logger.debug(f"Arguments received: {json.dumps(arguments, indent=2)}")
    logger.debug("=" * 80)

    try:
        pce = ctx.pce

        lookback_days = arguments.get("lookback_days", 90)
        min_connections = arguments.get("min_connections", 1)
        top_n = arguments.get("top_n", 20)

        # Query all traffic
        end = datetime.now()
        start = end - timedelta(days=lookback_days)

        traffic_query = TrafficQuery.build(
            start_date=start.strftime("%Y-%m-%d"),
            end_date=end.strftime("%Y-%m-%d"),
            policy_decisions=["allowed", "potentially_blocked", "blocked"],
            max_results=100000
        )

        flows = pce.get_traffic_flows_async(
            query_name='infra-identification',
            traffic_query=traffic_query
        )
        logger.debug(f"Got {len(flows)} flows for infrastructure analysis")

        if not flows:
            return [types.TextContent(type="text", text=json.dumps({
                "message": "No traffic flows found in the specified time range",
                "lookback_days": lookback_days
            }, indent=2))]

        df = to_dataframe(pce, flows)

        if df.empty or 'src_app' not in df.columns or 'dst_app' not in df.columns:
            return [types.TextContent(type="text", text=json.dumps({
                "message": "Traffic data has no labeled app flows to analyze",
                "total_flows": len(flows)
            }, indent=2))]

        # Build app-to-app edge list (only flows where both sides have app+env labels)
        edge_cols = ['src_app', 'src_env', 'dst_app', 'dst_env', 'num_connections']
        edges_df = df[edge_cols].dropna().copy()
        edges_df['src'] = edges_df['src_app'] + '|' + edges_df['src_env']
        edges_df['dst'] = edges_df['dst_app'] + '|' + edges_df['dst_env']

        # Remove self-loops (intra-app traffic)
        edges_df = edges_df[edges_df['src'] != edges_df['dst']]

        # Aggregate edges
        edge_agg = edges_df.groupby(['src', 'dst'])['num_connections'].sum().reset_index()

        # Apply min_connections filter
        edge_agg = edge_agg[edge_agg['num_connections'] >= min_connections]

        all_nodes = sorted(set(edge_agg['src']) | set(edge_agg['dst']))
        num_nodes = len(all_nodes)

        if num_nodes == 0:
            return [types.TextContent(type="text", text=json.dumps({
                "message": "No app-to-app edges found after filtering",
                "total_flows": len(flows),
                "min_connections": min_connections
            }, indent=2))]

        # Compute degree metrics
        in_degree = {}
        out_degree = {}
        in_conn = {}
        out_conn = {}
        in_neighbors = {}
        out_neighbors = {}

        for node in all_nodes:
            ie = edge_agg[edge_agg['dst'] == node]
            oe = edge_agg[edge_agg['src'] == node]
            in_degree[node] = len(ie)
            out_degree[node] = len(oe)
            in_conn[node] = int(ie['num_connections'].sum())
            out_conn[node] = int(oe['num_connections'].sum())
            in_neighbors[node] = sorted(ie['src'].tolist())
            out_neighbors[node] = sorted(oe['dst'].tolist())

        # Betweenness centrality (Brandes algorithm on undirected graph)
        adj = defaultdict(set)
        for _, row in edge_agg.iterrows():
            adj[row['src']].add(row['dst'])
            adj[row['dst']].add(row['src'])

        betweenness = {v: 0.0 for v in all_nodes}
        for s in all_nodes:
            S = []
            P = {v: [] for v in all_nodes}
            sigma = {v: 0 for v in all_nodes}
            sigma[s] = 1
            d = {v: -1 for v in all_nodes}
            d[s] = 0
            Q = deque([s])
            while Q:
                v = Q.popleft()
                S.append(v)
                for w in adj[v]:
                    if d[w] < 0:
                        Q.append(w)
                        d[w] = d[v] + 1
                    if d[w] == d[v] + 1:
                        sigma[w] += sigma[v]
                        P[w].append(v)
            delta = {v: 0.0 for v in all_nodes}
            while S:
                w = S.pop()
                for v in P[w]:
                    delta[v] += (sigma[v] / sigma[w]) * (1 + delta[w])
                if w != s:
                    betweenness[w] += delta[w]

        # Normalize betweenness
        if num_nodes > 2:
            norm = 1.0 / ((num_nodes - 1) * (num_nodes - 2))
            betweenness = {k: v * norm for k, v in betweenness.items()}

        # Count unmanaged sources connecting to each app
        unmanaged_df = df[df['src_app'].isna() & df['dst_app'].notna()].copy()
        unmanaged_in = {}
        if not unmanaged_df.empty:
            unmanaged_df['dst'] = unmanaged_df['dst_app'] + '|' + unmanaged_df['dst_env']
            unmanaged_in = unmanaged_df.groupby('dst')['src_ip'].nunique().to_dict()

        # Compute dual-pattern infrastructure score.
        # Two types of infra: providers (high in-degree) and consumers (high out-degree).
        # Compute both pattern scores, take the max, then apply dampening + env penalty.
        max_in = max(in_degree.values()) if in_degree else 1
        max_out = max(out_degree.values()) if out_degree else 1
        max_between = max(betweenness.values()) if betweenness else 1
        max_conn = max(in_conn[n] + out_conn[n] for n in all_nodes) if all_nodes else 1

        results = []
        for node in all_nodes:
            total_deg = in_degree[node] + out_degree[node]
            consumer_ratio = in_degree[node] / total_deg if total_deg > 0 else 0
            producer_ratio = 1.0 - consumer_ratio
            total_connections = in_conn[node] + out_conn[node]

            in_deg_score = (in_degree[node] / max_in) * 100 if max_in > 0 else 0
            out_deg_score = (out_degree[node] / max_out) * 100 if max_out > 0 else 0
            between_score = (betweenness[node] / max_between) * 100 if max_between > 0 else 0
            conn_score = (total_connections / max_conn) * 100 if max_conn > 0 else 0

            # Provider pattern: consumed by many apps (AD, DNS, shared DB)
            provider_score = (
                (in_deg_score * 0.40) + (consumer_ratio * 100 * 0.30) +
                (between_score * 0.25) + (conn_score * 0.05)
            )

            # Consumer pattern: connects out to many apps (monitoring, backup)
            consumer_score = (
                (out_deg_score * 0.40) + (producer_ratio * 100 * 0.30) +
                (between_score * 0.25) + (conn_score * 0.05)
            )

            infra_score = max(provider_score, consumer_score)
            dominant_pattern = "provider" if provider_score >= consumer_score else "consumer"

            # Mixed-traffic dampening: apps with both inbound AND outbound
            # connections are likely business apps, not infrastructure.
            # Only applies when min(in, out) > 0.
            mixed_degree = min(in_degree[node], out_degree[node])
            if mixed_degree > 0:
                infra_score *= 1.0 / (1 + mixed_degree * 0.3)

            # Environment penalty: infrastructure services live in prod.
            # Non-production environments get a 50% score reduction.
            app, env = node.split('|', 1)
            env_lower = env.lower()
            is_prod = env_lower in ('prod', 'production')
            if not is_prod:
                infra_score *= 0.5

            infra_score = round(infra_score, 1)

            if infra_score >= 75:
                tier = "Core Infrastructure"
            elif infra_score >= 50:
                tier = "Shared Service"
            else:
                tier = "Standard Application"

            results.append({
                "app": app,
                "env": env,
                "is_production": is_prod,
                "infrastructure_score": infra_score,
                "tier": tier,
                "dominant_pattern": dominant_pattern,
                "in_degree": in_degree[node],
                "out_degree": out_degree[node],
                "betweenness_centrality": round(betweenness[node], 4),
                "consumer_ratio": round(consumer_ratio, 2),
                "inbound_connections": in_conn[node],
                "outbound_connections": out_conn[node],
                "total_connections": total_connections,
                "unmanaged_sources": unmanaged_in.get(node, 0),
                "consumed_by": in_neighbors[node],
                "consumes": out_neighbors[node],
            })

        # Sort by score descending
        results.sort(key=lambda x: x["infrastructure_score"], reverse=True)

        # Trim to top_n
        results = results[:top_n]

        # Build tier summary
        core_count = sum(1 for r in results if r["tier"] == "Core Infrastructure")
        shared_count = sum(1 for r in results if r["tier"] == "Shared Service")
        standard_count = sum(1 for r in results if r["tier"] == "Standard Application")

        output = {
            "summary": {
                "total_flows_analyzed": len(flows),
                "lookback_days": lookback_days,
                "unique_apps": num_nodes,
                "unique_app_to_app_edges": len(edge_agg),
                "min_connections_filter": min_connections,
                "tier_counts": {
                    "core_infrastructure": core_count,
                    "shared_service": shared_count,
                    "standard_application": standard_count
                },
                "scoring_methodology": (
                    "Dual-pattern scoring recognizes two types of infrastructure: "
                    "PROVIDER (AD, DNS, shared DB — consumed by many apps, high in-degree) and "
                    "CONSUMER (monitoring, backup — connects out to many apps, high out-degree). "
                    "Provider score = 40% in-degree + 30% consumer ratio + 25% betweenness + 5% volume. "
                    "Consumer score = 40% out-degree + 30% producer ratio + 25% betweenness + 5% volume. "
                    "Final score = max(provider, consumer). "
                    "Mixed-traffic dampening: score *= 1/(1 + min(in,out) * 0.3) — "
                    "apps with both significant in AND out connections are business apps, not infra. "
                    "Non-production environments receive a 50% score penalty. "
                    "Core Infrastructure >= 75, Shared Service >= 50, Standard Application < 50."
                ),
                "recommendation": (
                    "Start segmentation with Core Infrastructure and Shared Services — "
                    "these are consumed by many apps and must be explicitly allowed in ringfence policies. "
                    "Policy them first to avoid breaking dependent applications."
                )
            },
            "results": results
        }

        return [types.TextContent(type="text", text=json.dumps(output, indent=2))]

    except Exception as e:
        error_msg = f"Failed to identify infrastructure services: {str(e)}"
        logger.error(error_msg, exc_info=True)
        return [types.TextContent(type="text", text=json.dumps({"error": error_msg}, indent=2))]


def handle_detect_lateral_movement_paths(ctx, arguments: dict) -> list:
    logger.debug("=" * 80)
    logger.debug("DETECT LATERAL MOVEMENT PATHS CALLED")
    logger.debug(f"Arguments received: {json.dumps(arguments, indent=2)}")
    logger.debug("=" * 80)

    try:
        pce = ctx.pce

        lookback_days = arguments.get("lookback_days", 30)
        max_hops = arguments.get("max_hops", 4)
        start_app = arguments.get("app_name")
        start_env = arguments.get("env_name")

        start_date = (datetime.now() - timedelta(days=lookback_days)).strftime('%Y-%m-%d')
        end_date = datetime.now().strftime('%Y-%m-%d')

        traffic_query = TrafficQuery.build(
            start_date=start_date,
            end_date=end_date,
            policy_decisions=["allowed", "potentially_blocked", "blocked"],
            max_results=100000,
            query_name='lateral-movement'
        )

        flows = pce.get_traffic_flows_async(query_name='lateral-movement', traffic_query=traffic_query)
        df = to_dataframe(pce, flows)

        if df.empty or 'src_app' not in df.columns or 'dst_app' not in df.columns:
            return [types.TextContent(type="text", text=json.dumps({
                "message": "No labeled traffic flows found for lateral movement analysis",
                "lookback_days": lookback_days
            }, indent=2))]

        # Build directed graph
        edges_df = df[['src_app', 'src_env', 'dst_app', 'dst_env', 'num_connections']].dropna().copy()
        edges_df['src'] = edges_df['src_app'] + '|' + edges_df['src_env']
        edges_df['dst'] = edges_df['dst_app'] + '|' + edges_df['dst_env']
        edges_df = edges_df[edges_df['src'] != edges_df['dst']]

        edge_agg = edges_df.groupby(['src', 'dst'])['num_connections'].sum().reset_index()

        # Build adjacency list (directed)
        adj = defaultdict(set)
        for _, row in edge_agg.iterrows():
            adj[row['src']].add(row['dst'])

        all_nodes = sorted(set(edge_agg['src']) | set(edge_agg['dst']))

        # Find bridge nodes (articulation points in undirected version)
        # These are nodes whose removal disconnects the graph
        undirected_adj = defaultdict(set)
        for _, row in edge_agg.iterrows():
            undirected_adj[row['src']].add(row['dst'])
            undirected_adj[row['dst']].add(row['src'])

        # Tarjan's bridge-finding algorithm
        visited = set()
        disc = {}
        low = {}
        parent = {}
        bridges = []
        articulation_points = set()
        timer = [0]

        def dfs_ap(u):
            children = 0
            visited.add(u)
            disc[u] = low[u] = timer[0]
            timer[0] += 1

            for v in undirected_adj[u]:
                if v not in visited:
                    children += 1
                    parent[v] = u
                    dfs_ap(v)
                    low[u] = min(low[u], low[v])

                    # u is an articulation point if:
                    if parent.get(u) is None and children > 1:
                        articulation_points.add(u)
                    if parent.get(u) is not None and low[v] >= disc[u]:
                        articulation_points.add(u)
                elif v != parent.get(u):
                    low[u] = min(low[u], disc[v])

        for node in all_nodes:
            if node not in visited:
                parent[node] = None
                dfs_ap(node)

        # BFS to find reachable paths from starting node(s)
        paths_from_start = []
        if start_app:
            start_node = f"{start_app}|{start_env}" if start_env else None
            if not start_node:
                # Find all envs for this app
                start_nodes = [n for n in all_nodes if n.startswith(f"{start_app}|")]
            else:
                start_nodes = [start_node] if start_node in adj else []

            for sn in start_nodes:
                # BFS up to max_hops
                queue = deque([(sn, [sn])])
                seen = {sn}
                while queue:
                    current, path = queue.popleft()
                    if len(path) > max_hops + 1:
                        continue
                    for neighbor in adj.get(current, []):
                        if neighbor not in seen:
                            new_path = path + [neighbor]
                            paths_from_start.append(new_path)
                            seen.add(neighbor)
                            queue.append((neighbor, new_path))

        # Compute reach (how many nodes each node can reach)
        reach = {}
        for node in all_nodes:
            visited_bfs = set()
            queue = deque([node])
            visited_bfs.add(node)
            while queue:
                current = queue.popleft()
                for neighbor in adj.get(current, []):
                    if neighbor not in visited_bfs:
                        visited_bfs.add(neighbor)
                        queue.append(neighbor)
            reach[node] = len(visited_bfs) - 1  # exclude self

        # High-risk nodes: articulation points sorted by reach
        high_risk_nodes = []
        for node in sorted(articulation_points, key=lambda n: reach.get(n, 0), reverse=True):
            app, env = node.split('|', 1)
            high_risk_nodes.append({
                "app": app,
                "env": env,
                "is_articulation_point": True,
                "reachable_apps": reach.get(node, 0),
                "direct_connections_out": len(adj.get(node, [])),
                "direct_connections_in": sum(1 for n in all_nodes if node in adj.get(n, set()))
            })

        # Top reach nodes (even if not articulation points)
        top_reach = []
        for node in sorted(all_nodes, key=lambda n: reach.get(n, 0), reverse=True)[:20]:
            app, env = node.split('|', 1)
            top_reach.append({
                "app": app,
                "env": env,
                "reachable_apps": reach.get(node, 0),
                "is_bridge_node": node in articulation_points
            })

        result = {
            "lookback_days": lookback_days,
            "total_apps": len(all_nodes),
            "total_edges": len(edge_agg),
            "articulation_points": len(articulation_points),
            "high_risk_bridge_nodes": high_risk_nodes[:10],
            "top_reachable_nodes": top_reach,
        }

        if start_app:
            result["paths_from"] = start_app + (f"|{start_env}" if start_env else "")
            result["max_hops"] = max_hops
            result["paths"] = [
                {"path": p, "hops": len(p) - 1}
                for p in sorted(paths_from_start, key=lambda x: len(x), reverse=True)[:50]
            ]

        result["recommendation"] = (
            "Bridge nodes (articulation points) are critical lateral movement risks — "
            "if compromised, they provide access to otherwise disconnected app groups. "
            "Prioritize ringfencing these apps and applying strict segmentation policies. "
            "Apps with high reachability should have minimal necessary connectivity."
        )

        return [types.TextContent(type="text", text=json.dumps(result, indent=2))]

    except Exception as e:
        error_msg = f"Failed to detect lateral movement paths: {str(e)}"
        logger.error(error_msg, exc_info=True)
        return [types.TextContent(type="text", text=json.dumps({"error": error_msg}, indent=2))]
