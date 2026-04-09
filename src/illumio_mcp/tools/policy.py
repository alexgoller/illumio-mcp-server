import json
import logging
from datetime import datetime, timedelta
import pandas as pd
import mcp.types as types
from illumio import TrafficQuery
from illumio.explorer.trafficanalysis import TrafficQueryFilter
from illumio.util.jsonutils import Reference
from ..pce import get_pce
from .traffic import to_dataframe
from .constants import MCP_BUG_MAX_RESULTS

logger = logging.getLogger('illumio_mcp')


def handle_compliance_check(arguments: dict) -> list:
    logger.debug("=" * 80)
    logger.debug("COMPLIANCE CHECK CALLED")
    logger.debug(f"Arguments received: {json.dumps(arguments, indent=2)}")
    logger.debug("=" * 80)

    try:
        pce = get_pce()

        framework = arguments.get("framework", "general")
        app_name = arguments.get("app_name")
        env_name = arguments.get("env_name")
        lookback_days = arguments.get("lookback_days", 30)

        # Define compliance checks per framework
        framework_checks = {
            "pci-dss": {
                "name": "PCI-DSS",
                "checks": [
                    {"id": "PCI-1.3", "name": "Restrict inbound traffic to CDE", "description": "Inbound traffic to cardholder data environment must be explicitly allowed"},
                    {"id": "PCI-1.4", "name": "Restrict outbound traffic from CDE", "description": "Outbound traffic from CDE must be explicitly authorized"},
                    {"id": "PCI-2.1", "name": "No default passwords", "description": "Change vendor-supplied defaults (check for common admin ports)"},
                    {"id": "PCI-6.1", "name": "Segment CDE from non-CDE", "description": "CDE must be segmented from non-CDE networks"},
                    {"id": "PCI-7.1", "name": "Restrict access by business need", "description": "Limit access to system components to only those required"},
                ],
                "high_risk_ports": [3389, 22, 23, 445, 1433, 3306, 5432, 1521],
            },
            "nist": {
                "name": "NIST 800-53",
                "checks": [
                    {"id": "AC-4", "name": "Information flow enforcement", "description": "Enforce approved authorizations for controlling information flow"},
                    {"id": "SC-7", "name": "Boundary protection", "description": "Monitor and control communications at external boundaries and key internal boundaries"},
                    {"id": "CM-7", "name": "Least functionality", "description": "Configure to provide only essential capabilities — no unnecessary ports or services"},
                    {"id": "SI-4", "name": "System monitoring", "description": "Monitor for unauthorized network connections and traffic"},
                ],
                "high_risk_ports": [3389, 22, 23, 445, 135, 139, 1433, 3306, 5432],
            },
            "cis": {
                "name": "CIS Controls",
                "checks": [
                    {"id": "CIS-9", "name": "Network access control", "description": "Manage network access control and micro-segmentation"},
                    {"id": "CIS-12", "name": "Network infrastructure management", "description": "Establish network segmentation with security boundaries"},
                    {"id": "CIS-13", "name": "Network monitoring and defense", "description": "Operate processes to detect network-based threats"},
                ],
                "high_risk_ports": [3389, 22, 23, 445, 135, 139, 21, 69],
            },
            "dora": {
                "name": "DORA (Digital Operational Resilience Act)",
                "checks": [
                    {"id": "DORA-9.2", "name": "Network access restriction", "description": "Implement policies to restrict network access (Article 9.2)"},
                    {"id": "DORA-9.3", "name": "Immediate isolation capability", "description": "Design network to allow immediate severing/isolation of affected systems (Article 9.3)"},
                    {"id": "DORA-8.1", "name": "ICT asset identification", "description": "Identify and document all ICT-supported business functions and assets (Article 8.1)"},
                    {"id": "DORA-10.1", "name": "Anomaly detection", "description": "Detect anomalous activities and ICT incidents (Article 10.1)"},
                    {"id": "DORA-25.1", "name": "Resilience testing", "description": "Perform vulnerability and network security assessments (Article 25.1)"},
                ],
                "high_risk_ports": [3389, 22, 23, 445, 135, 139, 1433, 3306, 5432, 1521, 27017, 6379],
            },
            "iso-27001": {
                "name": "ISO 27001:2022",
                "checks": [
                    {"id": "A.8.22", "name": "Network segregation", "description": "Groups of information services, users, and systems shall be segregated"},
                    {"id": "A.8.20", "name": "Networks security", "description": "Secure networks including mechanisms for filtering traffic"},
                    {"id": "A.5.9", "name": "Asset inventory", "description": "Maintain inventory of information and associated assets"},
                    {"id": "A.8.26", "name": "Application security requirements", "description": "Security requirements identified when developing/acquiring applications"},
                ],
                "high_risk_ports": [3389, 22, 23, 445, 135, 139, 1433, 3306, 5432, 21],
            },
            "swift-csp": {
                "name": "SWIFT Customer Security Programme",
                "checks": [
                    {"id": "SWIFT-1.1", "name": "SWIFT environment protection", "description": "Protect SWIFT infrastructure from general IT environment"},
                    {"id": "SWIFT-1.4", "name": "Internet access restriction", "description": "SWIFT-connected systems must not have direct internet access"},
                    {"id": "SWIFT-2.1", "name": "Internal data flow security", "description": "Ensure confidentiality and integrity of data flows between SWIFT components"},
                    {"id": "SWIFT-5.1", "name": "Logical access control", "description": "Enforce least-privilege access to SWIFT systems"},
                    {"id": "SWIFT-6.4", "name": "Logging and monitoring", "description": "Record and monitor security events in the SWIFT secure zone"},
                ],
                "high_risk_ports": [3389, 22, 23, 445, 135, 139, 21, 80, 1433, 3306, 5432],
            },
            "hipaa": {
                "name": "HIPAA Security Rule",
                "checks": [
                    {"id": "HIPAA-164.312(a)", "name": "Access control", "description": "Implement technical policies to allow access only to authorized persons/software"},
                    {"id": "HIPAA-164.312(b)", "name": "Audit controls", "description": "Implement mechanisms to record and examine activity in systems containing ePHI"},
                    {"id": "HIPAA-164.312(e)", "name": "Transmission security", "description": "Guard against unauthorized access to ePHI during transmission"},
                    {"id": "HIPAA-164.308(a)(1)", "name": "Security management process", "description": "Prevent, detect, contain, and correct security violations"},
                ],
                "high_risk_ports": [3389, 22, 23, 445, 135, 139, 1433, 3306, 5432, 1521, 21, 80],
            },
            "general": {
                "name": "General Security Best Practices",
                "checks": [
                    {"id": "SEG-1", "name": "Application segmentation", "description": "Apps should have ringfence policies limiting lateral movement"},
                    {"id": "SEG-2", "name": "Enforcement mode", "description": "Workloads should not be in idle or visibility_only mode in production"},
                    {"id": "SEG-3", "name": "High-risk port exposure", "description": "Sensitive ports (RDP, SSH, DB) should have explicit allow rules only"},
                    {"id": "SEG-4", "name": "Policy coverage", "description": "Traffic should be covered by explicit policy, not relying on default actions"},
                ],
                "high_risk_ports": [3389, 22, 23, 445, 135, 139, 1433, 3306, 5432, 1521, 27017, 6379, 9200],
            },
        }

        fw = framework_checks.get(framework, framework_checks["general"])
        high_risk_ports = fw["high_risk_ports"]

        # Get workloads
        params = {"include": "labels", "max_results": 10000}
        filter_labels = []
        if app_name:
            app_labels = pce.labels.get(params={"key": "app", "value": app_name})
            if app_labels:
                filter_labels.append(app_labels[0].href)
        if env_name:
            env_labels = pce.labels.get(params={"key": "env", "value": env_name})
            if env_labels:
                filter_labels.append(env_labels[0].href)
        if filter_labels:
            params["labels"] = json.dumps(filter_labels)

        workloads = pce.workloads.get(params=params)

        # Build label map
        label_href_map = {}
        for l in pce.labels.get(params={'max_results': 10000}):
            label_href_map[l.href] = {"key": l.key, "value": l.value}

        # Analyze enforcement modes
        enforcement_modes = {}
        idle_workloads = []
        vis_only_workloads = []
        for w in workloads:
            mode = getattr(w, 'enforcement_mode', 'unknown') or 'unknown'
            enforcement_modes[mode] = enforcement_modes.get(mode, 0) + 1
            if mode == 'idle':
                idle_workloads.append(w.name or w.hostname or w.href)
            elif mode == 'visibility_only':
                vis_only_workloads.append(w.name or w.hostname or w.href)

        # Query traffic
        start_date = (datetime.now() - timedelta(days=lookback_days)).strftime('%Y-%m-%d')
        end_date = datetime.now().strftime('%Y-%m-%d')

        query_kwargs = {
            "start_date": start_date,
            "end_date": end_date,
            "policy_decisions": ["allowed", "potentially_blocked", "blocked"],
            "max_results": MCP_BUG_MAX_RESULTS,
            "query_name": "compliance-check"
        }

        if app_name and filter_labels:
            filters = [TrafficQueryFilter(label=Reference(href=h)) for h in filter_labels]
            query_kwargs["include_destinations"] = [filters]
            query_kwargs["include_sources"] = [[]]
        else:
            pass  # Query all traffic

        traffic_query = TrafficQuery.build(**query_kwargs)
        flows = pce.get_traffic_flows_async(query_name='compliance-check', traffic_query=traffic_query)
        df = to_dataframe(flows)

        # Run compliance checks
        findings = []
        passed = 0
        failed = 0
        warnings = 0

        for check in fw["checks"]:
            finding = {"id": check["id"], "name": check["name"], "description": check["description"]}

            if "segmentation" in check["name"].lower() or "ringfence" in check["name"].lower() or check["id"] in ("SEG-1", "PCI-6.1", "CIS-9", "CIS-12"):
                # Check if ringfence exists
                if app_name:
                    rulesets = pce.rule_sets.get(params={"name": f"RF-{app_name}"})
                    if rulesets:
                        finding["status"] = "PASS"
                        finding["detail"] = f"Ringfence ruleset found for {app_name}"
                        passed += 1
                    else:
                        finding["status"] = "FAIL"
                        finding["detail"] = f"No ringfence ruleset found for {app_name} — run create-ringfence"
                        failed += 1
                else:
                    # Check total rulesets
                    all_rulesets = pce.rule_sets.get(params={"max_results": 1000})
                    rf_count = sum(1 for rs in all_rulesets if rs.name and rs.name.startswith("RF-"))
                    finding["status"] = "INFO"
                    finding["detail"] = f"{rf_count} ringfence rulesets found out of {len(all_rulesets)} total rulesets"
                    warnings += 1

            elif "enforcement" in check["name"].lower() or check["id"] == "SEG-2":
                if idle_workloads:
                    finding["status"] = "FAIL"
                    finding["detail"] = f"{len(idle_workloads)} workloads in idle mode: {idle_workloads[:5]}"
                    failed += 1
                elif vis_only_workloads and env_name and env_name.lower() in ('production', 'prod'):
                    finding["status"] = "WARNING"
                    finding["detail"] = f"{len(vis_only_workloads)} production workloads in visibility_only mode"
                    warnings += 1
                else:
                    finding["status"] = "PASS"
                    finding["detail"] = f"All {len(workloads)} workloads have appropriate enforcement modes"
                    passed += 1

            elif "high-risk" in check["name"].lower() or "port" in check["name"].lower() or check["id"] in ("SEG-3", "PCI-2.1"):
                if not df.empty and 'port' in df.columns:
                    exposed_high_risk = df[df['port'].isin(high_risk_ports)]
                    if not exposed_high_risk.empty:
                        uncovered = exposed_high_risk[exposed_high_risk.get('policy_decision', pd.Series()) != 'allowed'] if 'policy_decision' in exposed_high_risk.columns else pd.DataFrame()
                        ports_found = sorted(exposed_high_risk['port'].unique().tolist())
                        if not uncovered.empty:
                            finding["status"] = "FAIL"
                            finding["detail"] = f"High-risk ports with uncovered traffic: {ports_found}"
                            failed += 1
                        else:
                            finding["status"] = "PASS"
                            finding["detail"] = f"High-risk ports {ports_found} are all covered by policy"
                            passed += 1
                    else:
                        finding["status"] = "PASS"
                        finding["detail"] = "No high-risk port traffic detected"
                        passed += 1
                else:
                    finding["status"] = "INFO"
                    finding["detail"] = "No traffic data available for port analysis"
                    warnings += 1

            elif "coverage" in check["name"].lower() or "flow" in check["name"].lower() or check["id"] in ("SEG-4", "AC-4", "SC-7"):
                if not df.empty and 'policy_decision' in df.columns:
                    total = len(df)
                    allowed = len(df[df['policy_decision'] == 'allowed'])
                    coverage_pct = round(allowed / total * 100, 1) if total > 0 else 0
                    if coverage_pct >= 90:
                        finding["status"] = "PASS"
                        finding["detail"] = f"{coverage_pct}% of traffic covered by policy ({allowed}/{total} flows)"
                        passed += 1
                    elif coverage_pct >= 50:
                        finding["status"] = "WARNING"
                        finding["detail"] = f"Only {coverage_pct}% of traffic covered ({allowed}/{total} flows)"
                        warnings += 1
                    else:
                        finding["status"] = "FAIL"
                        finding["detail"] = f"Only {coverage_pct}% of traffic covered ({allowed}/{total} flows) — significant policy gaps"
                        failed += 1
                else:
                    finding["status"] = "INFO"
                    finding["detail"] = "No traffic data available for coverage analysis"
                    warnings += 1

            else:
                # Default: check traffic patterns
                if not df.empty and 'policy_decision' in df.columns:
                    blocked = len(df[df['policy_decision'] == 'blocked'])
                    pot_blocked = len(df[df['policy_decision'] == 'potentially_blocked'])
                    if blocked > 0:
                        finding["status"] = "WARNING"
                        finding["detail"] = f"{blocked} blocked and {pot_blocked} potentially blocked flows detected"
                        warnings += 1
                    else:
                        finding["status"] = "PASS"
                        finding["detail"] = "No blocked traffic detected"
                        passed += 1
                else:
                    finding["status"] = "INFO"
                    finding["detail"] = "No traffic data for analysis"
                    warnings += 1

            findings.append(finding)

        total_checks = passed + failed + warnings
        compliance_score = round(passed / total_checks * 100, 1) if total_checks > 0 else 0

        # Map framework key to resource URI for detailed guidance
        framework_resource_map = {
            "pci-dss": "illumio://compliance/pci-dss",
            "dora": "illumio://compliance/dora",
            "nist": "illumio://compliance/nist-800-53",
            "iso-27001": "illumio://compliance/iso-27001",
            "swift-csp": "illumio://compliance/swift-csp",
            "hipaa": "illumio://compliance/hipaa",
            "cis": "illumio://compliance/cis-controls",
            "general": "illumio://compliance/segmentation-methodology",
        }

        result = {
            "framework": fw["name"],
            "resource_uri": framework_resource_map.get(framework, "illumio://compliance/segmentation-methodology"),
            "resource_hint": f"Read the resource at {framework_resource_map.get(framework, 'illumio://compliance/segmentation-methodology')} for detailed {fw['name']} guidance and remediation steps",
            "scope": {
                "app": app_name or "all",
                "env": env_name or "all",
                "lookback_days": lookback_days
            },
            "compliance_score": compliance_score,
            "summary": {
                "total_checks": total_checks,
                "passed": passed,
                "failed": failed,
                "warnings": warnings
            },
            "workloads_analyzed": len(workloads),
            "enforcement_modes": enforcement_modes,
            "findings": findings,
            "recommendation": (
                "Compliant — maintain current policies" if compliance_score >= 90
                else "Mostly compliant — address failed checks" if compliance_score >= 70
                else "Significant gaps — prioritize failed findings" if compliance_score >= 40
                else "Major compliance gaps — immediate remediation needed"
            )
        }

        return [types.TextContent(type="text", text=json.dumps(result, indent=2))]

    except Exception as e:
        error_msg = f"Failed to run compliance check: {str(e)}"
        logger.error(error_msg, exc_info=True)
        return [types.TextContent(type="text", text=json.dumps({"error": error_msg}, indent=2))]


def handle_enforcement_readiness(arguments: dict) -> list:
    logger.debug("=" * 80)
    logger.debug("ENFORCEMENT READINESS CALLED")
    logger.debug(f"Arguments received: {json.dumps(arguments, indent=2)}")
    logger.debug("=" * 80)

    try:
        pce = get_pce()

        app_name = arguments["app_name"]
        env_name = arguments["env_name"]
        lookback_days = arguments.get("lookback_days", 30)

        # Find labels
        app_labels = pce.labels.get(params={"key": "app", "value": app_name})
        if not app_labels:
            return [types.TextContent(type="text", text=json.dumps({"error": f"App label '{app_name}' not found"}))]
        app_label = app_labels[0]

        env_labels = pce.labels.get(params={"key": "env", "value": env_name})
        if not env_labels:
            return [types.TextContent(type="text", text=json.dumps({"error": f"Env label '{env_name}' not found"}))]
        env_label = env_labels[0]

        # Get workloads for this app+env
        workloads = pce.workloads.get(params={
            "labels": json.dumps([app_label.href, env_label.href]),
            "max_results": 10000,
            "include": "labels"
        })

        # Analyze enforcement modes
        enforcement_modes = {}
        for w in workloads:
            mode = getattr(w, 'enforcement_mode', 'unknown') or 'unknown'
            enforcement_modes[mode] = enforcement_modes.get(mode, 0) + 1

        # Query traffic flows
        start_date = (datetime.now() - timedelta(days=lookback_days)).strftime('%Y-%m-%d')
        end_date = datetime.now().strftime('%Y-%m-%d')

        app_filter = TrafficQueryFilter(label=Reference(href=app_label.href))
        env_filter = TrafficQueryFilter(label=Reference(href=env_label.href))

        # Inbound traffic
        traffic_query = TrafficQuery.build(
            start_date=start_date,
            end_date=end_date,
            include_sources=[[]],
            include_destinations=[[app_filter, env_filter]],
            policy_decisions=["allowed", "potentially_blocked", "blocked"],
            max_results=MCP_BUG_MAX_RESULTS,
            query_name='readiness-inbound'
        )
        inbound_flows = pce.get_traffic_flows_async(query_name='readiness-inbound', traffic_query=traffic_query)

        # Outbound traffic
        traffic_query_out = TrafficQuery.build(
            start_date=start_date,
            end_date=end_date,
            include_sources=[[app_filter, env_filter]],
            include_destinations=[[]],
            policy_decisions=["allowed", "potentially_blocked", "blocked"],
            max_results=MCP_BUG_MAX_RESULTS,
            query_name='readiness-outbound'
        )
        outbound_flows = pce.get_traffic_flows_async(query_name='readiness-outbound', traffic_query=traffic_query_out)

        inbound_df = to_dataframe(inbound_flows)
        outbound_df = to_dataframe(outbound_flows)

        # Analyze policy decisions
        policy_stats = {"allowed": 0, "potentially_blocked": 0, "blocked": 0, "unknown": 0}
        total_flows = 0

        for df in [inbound_df, outbound_df]:
            if not df.empty and 'policy_decision' in df.columns:
                for decision, count in df['policy_decision'].value_counts().items():
                    policy_stats[decision] = policy_stats.get(decision, 0) + count
                    total_flows += count

        # Identify unique remote apps and their coverage
        remote_apps_covered = set()
        remote_apps_uncovered = set()

        if not inbound_df.empty and 'src_app' in inbound_df.columns and 'src_env' in inbound_df.columns:
            for _, row in inbound_df.iterrows():
                if pd.notna(row.get('src_app')) and pd.notna(row.get('src_env')):
                    key = (row['src_app'], row['src_env'])
                    if key == (app_name, env_name):
                        continue
                    if row.get('policy_decision') == 'allowed':
                        remote_apps_covered.add(key)
                    else:
                        remote_apps_uncovered.add(key)

        # Check for existing rulesets
        rulesets = pce.rule_sets.get(params={"name": f"RF-{app_name}-{env_name}"})
        has_ringfence = len(rulesets) > 0

        # Calculate readiness score (0-100)
        readiness_score = 0
        recommendations = []

        # Factor 1: Policy coverage (40 points)
        if total_flows > 0:
            coverage_ratio = policy_stats.get("allowed", 0) / total_flows
            readiness_score += coverage_ratio * 40
            if coverage_ratio < 0.5:
                recommendations.append("Less than 50% of traffic is covered by policy — create rules for observed traffic patterns")
            elif coverage_ratio < 0.9:
                recommendations.append("Some traffic is not yet covered — review potentially_blocked flows and add rules")
        else:
            recommendations.append("No traffic flows found — verify workloads are online and sending data")

        # Factor 2: Ringfence exists (20 points)
        if has_ringfence:
            readiness_score += 20
        else:
            recommendations.append("No ringfence ruleset found — run create-ringfence to create app-level segmentation")

        # Factor 3: Enforcement mode (20 points)
        if enforcement_modes.get('full', 0) == len(workloads) and len(workloads) > 0:
            readiness_score += 20
        elif enforcement_modes.get('selective', 0) > 0:
            readiness_score += 10
            recommendations.append("Some workloads in selective mode — consider moving to full enforcement after validation")
        elif enforcement_modes.get('visibility_only', 0) > 0:
            readiness_score += 5
            recommendations.append("Workloads in visibility_only — move to selective or full enforcement when policies are ready")
        else:
            recommendations.append("No enforcement configured — start with visibility_only, then selective, then full")

        # Factor 4: No blocked traffic (10 points)
        if policy_stats.get("blocked", 0) == 0:
            readiness_score += 10
        else:
            recommendations.append(f"{policy_stats['blocked']} flows are currently blocked — investigate if these are intentional or need new rules")

        # Factor 5: All remote apps covered (10 points)
        uncovered_only = remote_apps_uncovered - remote_apps_covered
        if not uncovered_only:
            readiness_score += 10
        else:
            recommendations.append(f"{len(uncovered_only)} remote apps have uncovered traffic — review and create allow rules")

        readiness_score = round(readiness_score, 1)

        if readiness_score >= 80:
            readiness_level = "Ready for enforcement"
        elif readiness_score >= 50:
            readiness_level = "Partially ready — address recommendations"
        else:
            readiness_level = "Not ready — significant policy gaps"

        result = {
            "app": app_name,
            "env": env_name,
            "readiness_score": readiness_score,
            "readiness_level": readiness_level,
            "workloads": {
                "total": len(workloads),
                "enforcement_modes": enforcement_modes
            },
            "traffic_analysis": {
                "lookback_days": lookback_days,
                "total_flows": total_flows,
                "policy_decisions": policy_stats,
                "coverage_percentage": round((policy_stats.get("allowed", 0) / total_flows * 100) if total_flows > 0 else 0, 1)
            },
            "remote_apps": {
                "covered": [{"app": a, "env": e} for a, e in sorted(remote_apps_covered)],
                "uncovered": [{"app": a, "env": e} for a, e in sorted(uncovered_only)],
            },
            "has_ringfence": has_ringfence,
            "recommendations": recommendations
        }

        return [types.TextContent(type="text", text=json.dumps(result, indent=2))]

    except Exception as e:
        error_msg = f"Failed to assess enforcement readiness: {str(e)}"
        logger.error(error_msg, exc_info=True)
        return [types.TextContent(type="text", text=json.dumps({"error": error_msg}, indent=2))]


def handle_get_policy_coverage_report(arguments: dict) -> list:
    logger.debug("=" * 80)
    logger.debug("GET POLICY COVERAGE REPORT CALLED")
    logger.debug(f"Arguments received: {json.dumps(arguments, indent=2)}")
    logger.debug("=" * 80)

    try:
        pce = get_pce()

        app_name = arguments["app_name"]
        env_name = arguments["env_name"]
        lookback_days = arguments.get("lookback_days", 30)

        app_labels = pce.labels.get(params={"key": "app", "value": app_name})
        if not app_labels:
            return [types.TextContent(type="text", text=json.dumps({"error": f"App label '{app_name}' not found"}))]
        app_label = app_labels[0]

        env_labels = pce.labels.get(params={"key": "env", "value": env_name})
        if not env_labels:
            return [types.TextContent(type="text", text=json.dumps({"error": f"Env label '{env_name}' not found"}))]
        env_label = env_labels[0]

        start_date = (datetime.now() - timedelta(days=lookback_days)).strftime('%Y-%m-%d')
        end_date = datetime.now().strftime('%Y-%m-%d')

        app_filter = TrafficQueryFilter(label=Reference(href=app_label.href))
        env_filter = TrafficQueryFilter(label=Reference(href=env_label.href))

        # Query inbound traffic with all policy decisions
        traffic_query = TrafficQuery.build(
            start_date=start_date,
            end_date=end_date,
            include_sources=[[]],
            include_destinations=[[app_filter, env_filter]],
            policy_decisions=["allowed", "potentially_blocked", "blocked"],
            max_results=MCP_BUG_MAX_RESULTS,
            query_name='coverage-inbound'
        )
        inbound_flows = pce.get_traffic_flows_async(query_name='coverage-inbound', traffic_query=traffic_query)

        # Query outbound
        traffic_query_out = TrafficQuery.build(
            start_date=start_date,
            end_date=end_date,
            include_sources=[[app_filter, env_filter]],
            include_destinations=[[]],
            policy_decisions=["allowed", "potentially_blocked", "blocked"],
            max_results=MCP_BUG_MAX_RESULTS,
            query_name='coverage-outbound'
        )
        outbound_flows = pce.get_traffic_flows_async(query_name='coverage-outbound', traffic_query=traffic_query_out)

        inbound_df = to_dataframe(inbound_flows)
        outbound_df = to_dataframe(outbound_flows)

        # Analyze by policy decision
        def analyze_coverage(df, direction):
            if df.empty:
                return {"total_flows": 0, "by_decision": {}, "uncovered_services": [], "uncovered_apps": []}

            total = len(df)
            by_decision = {}
            if 'policy_decision' in df.columns:
                by_decision = df['policy_decision'].value_counts().to_dict()
                by_decision = {k: int(v) for k, v in by_decision.items()}

            # Find uncovered (potentially_blocked or blocked) services
            uncovered_services = []
            uncovered_apps = []
            if 'policy_decision' in df.columns:
                uncovered = df[df['policy_decision'].isin(['potentially_blocked', 'blocked'])]
                if not uncovered.empty:
                    # Group by port/proto
                    if 'port' in uncovered.columns and 'proto' in uncovered.columns:
                        svc_group = uncovered.groupby(['port', 'proto'])['num_connections'].sum().reset_index()
                        for _, row in svc_group.iterrows():
                            uncovered_services.append({
                                "port": int(row['port']),
                                "proto": int(row['proto']),
                                "connections": int(row['num_connections'])
                            })
                    # Group by remote app
                    remote_col = 'src_app' if direction == 'inbound' else 'dst_app'
                    remote_env_col = 'src_env' if direction == 'inbound' else 'dst_env'
                    if remote_col in uncovered.columns and remote_env_col in uncovered.columns:
                        app_group = uncovered.groupby([remote_col, remote_env_col])['num_connections'].sum().reset_index()
                        for _, row in app_group.iterrows():
                            if pd.notna(row[remote_col]) and pd.notna(row[remote_env_col]):
                                uncovered_apps.append({
                                    "app": row[remote_col],
                                    "env": row[remote_env_col],
                                    "connections": int(row['num_connections'])
                                })

            covered = by_decision.get('allowed', 0)
            return {
                "total_flows": total,
                "by_decision": by_decision,
                "coverage_percentage": round(covered / total * 100, 1) if total > 0 else 0,
                "uncovered_services": sorted(uncovered_services, key=lambda x: x['connections'], reverse=True),
                "uncovered_apps": sorted(uncovered_apps, key=lambda x: x['connections'], reverse=True)
            }

        inbound_coverage = analyze_coverage(inbound_df, 'inbound')
        outbound_coverage = analyze_coverage(outbound_df, 'outbound')

        total_flows = inbound_coverage["total_flows"] + outbound_coverage["total_flows"]
        total_allowed = inbound_coverage["by_decision"].get("allowed", 0) + outbound_coverage["by_decision"].get("allowed", 0)
        overall_coverage = round(total_allowed / total_flows * 100, 1) if total_flows > 0 else 0

        result = {
            "app": app_name,
            "env": env_name,
            "lookback_days": lookback_days,
            "overall_coverage_percentage": overall_coverage,
            "total_flows": total_flows,
            "total_allowed": total_allowed,
            "inbound": inbound_coverage,
            "outbound": outbound_coverage,
            "recommendation": (
                "Full coverage — ready for enforcement" if overall_coverage >= 95
                else "High coverage — review remaining gaps before enforcement" if overall_coverage >= 80
                else "Moderate coverage — create rules for uncovered traffic" if overall_coverage >= 50
                else "Low coverage — significant policy gaps exist, start with ringfencing"
            )
        }

        return [types.TextContent(type="text", text=json.dumps(result, indent=2))]

    except Exception as e:
        error_msg = f"Failed to generate policy coverage report: {str(e)}"
        logger.error(error_msg, exc_info=True)
        return [types.TextContent(type="text", text=json.dumps({"error": error_msg}, indent=2))]


def handle_compare_draft_active(arguments: dict) -> list:
    logger.debug("=" * 80)
    logger.debug("COMPARE DRAFT ACTIVE CALLED")
    logger.debug(f"Arguments received: {json.dumps(arguments, indent=2)}")
    logger.debug("=" * 80)

    try:
        pce = get_pce()

        resource_type = arguments.get("resource_type", "all")

        # Get pending changes which show what differs between draft and active
        resp = pce.get("/sec_policy/pending")
        pending = resp.json()

        if not pending:
            return [types.TextContent(type="text", text=json.dumps({
                "message": "No differences between draft and active policy",
                "status": "in_sync"
            }, indent=2))]

        changes = {
            "created": [],
            "updated": [],
            "deleted": []
        }

        for item in pending:
            if not isinstance(item, dict):
                continue

            href = item.get('href', '')
            change_type = item.get('change_type', 'unknown')
            item_type = 'unknown'

            if '/rule_sets/' in href:
                item_type = 'rule_sets'
            elif '/ip_lists/' in href:
                item_type = 'ip_lists'
            elif '/services/' in href:
                item_type = 'services'
            elif '/labels/' in href:
                item_type = 'labels'

            if resource_type != "all" and item_type != resource_type:
                continue

            change_info = {
                "href": href,
                "type": item_type,
                "name": item.get('name', ''),
            }

            if change_type == 'create':
                changes["created"].append(change_info)
            elif change_type == 'update':
                changes["updated"].append(change_info)
            elif change_type == 'delete':
                changes["deleted"].append(change_info)
            else:
                changes.setdefault("other", []).append({**change_info, "change_type": change_type})

        summary = {
            "total_pending_changes": len(pending),
            "filter": resource_type,
            "created_count": len(changes["created"]),
            "updated_count": len(changes["updated"]),
            "deleted_count": len(changes["deleted"]),
            "changes": changes
        }

        return [types.TextContent(type="text", text=json.dumps(summary, indent=2))]

    except Exception as e:
        error_msg = f"Failed to compare draft vs active: {str(e)}"
        logger.error(error_msg, exc_info=True)
        return [types.TextContent(type="text", text=json.dumps({"error": error_msg}, indent=2))]


def handle_get_workload_enforcement_status(arguments: dict) -> list:
    logger.debug("=" * 80)
    logger.debug("GET WORKLOAD ENFORCEMENT STATUS CALLED")
    logger.debug(f"Arguments received: {json.dumps(arguments, indent=2)}")
    logger.debug("=" * 80)

    try:
        pce = get_pce()

        params = {"include": "labels", "max_results": 10000}

        # Build label filter if app/env specified
        filter_labels = []
        if arguments.get("app_name"):
            app_labels = pce.labels.get(params={"key": "app", "value": arguments["app_name"]})
            if app_labels:
                filter_labels.append(app_labels[0].href)
        if arguments.get("env_name"):
            env_labels = pce.labels.get(params={"key": "env", "value": arguments["env_name"]})
            if env_labels:
                filter_labels.append(env_labels[0].href)
        if filter_labels:
            params["labels"] = json.dumps(filter_labels)

        workloads = pce.workloads.get(params=params)

        # Build label href map for resolution
        label_href_map = {}
        for l in pce.labels.get(params={'max_results': 10000}):
            label_href_map[l.href] = {"key": l.key, "value": l.value}

        # Group by app+env
        app_env_groups = {}
        for w in workloads:
            app_val = None
            env_val = None
            if hasattr(w, 'labels') and w.labels:
                for l in w.labels:
                    info = label_href_map.get(l.href, {})
                    if info.get("key") == "app":
                        app_val = info.get("value")
                    elif info.get("key") == "env":
                        env_val = info.get("value")

            key = f"{app_val or 'unlabeled'}|{env_val or 'unlabeled'}"
            if key not in app_env_groups:
                app_env_groups[key] = {"app": app_val, "env": env_val, "modes": {}, "workloads": []}

            mode = getattr(w, 'enforcement_mode', 'unknown') or 'unknown'
            app_env_groups[key]["modes"][mode] = app_env_groups[key]["modes"].get(mode, 0) + 1
            app_env_groups[key]["workloads"].append({
                "name": w.name or w.hostname or "unnamed",
                "href": w.href,
                "enforcement_mode": mode,
                "online": getattr(w, 'online', None)
            })

        # Identify mixed enforcement states
        mixed_apps = []
        for key, group in app_env_groups.items():
            if len(group["modes"]) > 1:
                mixed_apps.append({
                    "app": group["app"],
                    "env": group["env"],
                    "modes": group["modes"]
                })

        # Global mode summary
        global_modes = {}
        for w in workloads:
            mode = getattr(w, 'enforcement_mode', 'unknown') or 'unknown'
            global_modes[mode] = global_modes.get(mode, 0) + 1

        # Format app groups (without individual workload details to keep output manageable)
        app_summaries = []
        for key, group in sorted(app_env_groups.items()):
            app_summaries.append({
                "app": group["app"],
                "env": group["env"],
                "workload_count": sum(group["modes"].values()),
                "enforcement_modes": group["modes"],
                "is_mixed": len(group["modes"]) > 1
            })

        result = {
            "total_workloads": len(workloads),
            "global_enforcement_modes": global_modes,
            "app_groups": app_summaries,
            "mixed_enforcement_apps": mixed_apps,
            "mixed_count": len(mixed_apps)
        }

        return [types.TextContent(type="text", text=json.dumps(result, indent=2))]

    except Exception as e:
        error_msg = f"Failed to get enforcement status: {str(e)}"
        logger.error(error_msg, exc_info=True)
        return [types.TextContent(type="text", text=json.dumps({"error": error_msg}, indent=2))]
