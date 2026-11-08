"""Tool definitions for the Illumio Cloud Platform feature.

Kept out of server.py's main list on purpose: they are advertised only when
features.feature_enabled("cloud") is true, by the same predicate that admits
their ToolSpecs to the visible registry.
"""
import mcp.types as types

_LABEL = {"type": "object", "properties": {"key": {"type": "string"}, "value": {"type": "string"}}, "required": ["key", "value"]}
_ASSIGNMENTS = {
    "type": "array",
    "items": {"type": "object", "properties": {
        "csp_id": {"type": "string", "description": "Cloud service provider ID of the resource"},
        "labels": {"type": "array", "items": _LABEL}}, "required": ["csp_id", "labels"]},
}


def cloud_tool_definitions() -> list[types.Tool]:
    return [
        types.Tool(
            name="cloud-get-resources",
            description="List and filter cloud resources from the Illumio Cloud inventory (AWS, Azure, GCP, OCI). compact: one row per resource with labels flattened to columns; full: the complete resource JSON. Paginates server-side up to max_results.",
            inputSchema={"type": "object", "properties": {
                "clouds": {"type": "array", "items": {"type": "string"}, "description": "aws, azure, gcp, oci"},
                "regions": {"type": "array", "items": {"type": "string"}, "description": "CSP regions, e.g. us-west-1"},
                "illumio_regions": {"type": "array", "items": {"type": "string"}},
                "account_ids": {"type": "array", "items": {"type": "string"}, "description": "Onboarded account IDs"},
                "object_types": {"type": "array", "items": {"type": "string"}, "description": "CSP object types, e.g. AWS::EC2::Instance"},
                "categories": {"type": "array", "items": {"type": "string"}},
                "subcategories": {"type": "array", "items": {"type": "string"}},
                "labels": {"type": "array", "items": _LABEL, "description": "Illumio labels the resource carries"},
                "ip_addresses": {"type": "array", "items": {"type": "string"}},
                "resource_names": {"type": "array", "items": {"type": "string"}},
                "resource_ids": {"type": "array", "items": {"type": "string"}, "description": "Illumio resource IDs"},
                "csp_ids": {"type": "array", "items": {"type": "string"}},
                "states": {"type": "array", "items": {"type": "string"}},
                "tags": {"type": "object", "description": "CSP tags as a key-value map"},
                "include_enforcement_status": {"type": "boolean"},
                "json_view": {"type": "boolean", "description": "Include the raw CSP JSON per resource"},
                "max_results": {"type": "integer", "description": "Default 500"},
                "detail_level": {"type": "string", "enum": ["compact", "full"], "default": "compact"},
            }},
        ),
        types.Tool(
            name="cloud-assign-labels",
            description="Assign Illumio labels to cloud resources identified by csp_id. An env label requires an app label; one value per label type per resource.",
            inputSchema={"type": "object", "properties": {"assignments": _ASSIGNMENTS}, "required": ["assignments"]},
        ),
        types.Tool(
            name="cloud-remove-labels",
            description="Remove Illumio labels from cloud resources identified by csp_id. System labels cannot be removed.",
            inputSchema={"type": "object", "properties": {"assignments": _ASSIGNMENTS}, "required": ["assignments"]},
        ),
        types.Tool(
            name="cloud-get-traffic-queries",
            description="List the unified-traffic async queries: query_id, status (running/completed), match counts, download URL. Run before cloud-get-traffic-flows.",
            inputSchema={"type": "object", "properties": {}},
        ),
        types.Tool(
            name="cloud-create-traffic-query",
            description="Create an async unified-traffic flow query (cloud and workload flows together). Asynchronous: poll cloud-get-traffic-queries, then download with cloud-get-traffic-flows.",
            inputSchema={"type": "object", "properties": {
                "start_date": {"type": "string", "description": "ISO 8601, e.g. 2026-08-01T00:00:00Z"},
                "end_date": {"type": "string", "description": "ISO 8601"},
                "query_name": {"type": "string"},
                "sources": {"type": "object", "description": "{include: [[{label: {href}}]], exclude: [...]}"},
                "destinations": {"type": "object", "description": "Same shape as sources"},
                "services": {"type": "object", "description": "{include: [{port, to_port, proto}], exclude: [...]}"},
                "policy_decisions": {"type": "array", "items": {"type": "string"}, "description": "allowed, blocked, potentially_blocked, unknown"},
                "boundary_decisions": {"type": "array", "items": {"type": "string"}},
                "data_sources": {"type": "object", "description": "{include: ['server'], exclude: [...]}"},
                "max_results": {"type": "integer", "description": "Default 10000"},
                "sources_destinations_query_op": {"type": "string", "enum": ["and", "or"]},
                "exclude_workloads_from_ip_list_query": {"type": "boolean"},
                "aggregate_lows_across_days": {"type": "boolean"},
            }, "required": ["start_date", "end_date"]},
        ),
        types.Tool(
            name="cloud-get-traffic-flows",
            description="Download a completed unified-traffic query's flows, grouped by endpoint pair, port, protocol and decision, with cloud resources and workloads named.",
            inputSchema={"type": "object", "properties": {
                "query_id": {"type": "string"},
                "offset": {"type": "integer", "description": "Default 0"},
                "limit": {"type": "integer", "description": "Default 5000"},
            }, "required": ["query_id"]},
        ),
    ]
