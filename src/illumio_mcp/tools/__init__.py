"""Tool registry. Maps MCP tool names to ToolSpec (handler + authz metadata).

Add a new tool by:
  1. Implementing `def handle_X(ctx, arguments) -> list:` in the right module.
  2. Adding a ToolSpec entry below with explicit `roles=`. Default-deny: a tool
     with no roles will fail at import time.
"""
from typing import Callable

from ..registry import ToolSpec, READER, OPERATOR, ADMIN, ALL_ROLES

from .workloads import (
    handle_get_workloads,
    handle_create_workload,
    handle_update_workload,
    handle_delete_workload,
)
from .labels import (
    handle_get_labels,
    handle_create_label,
    handle_update_label,
    handle_delete_label,
)
from .services import (
    handle_get_services,
    handle_create_service,
    handle_update_service,
    handle_delete_service,
)
from .iplists import (
    handle_get_iplists,
    handle_create_iplist,
    handle_update_iplist,
    handle_delete_iplist,
)
from .rulesets import (
    handle_get_rulesets,
    handle_create_ruleset,
    handle_update_ruleset,
    handle_delete_ruleset,
    handle_provision_policy,
)
from .deny_rules import (
    handle_create_deny_rule,
    handle_update_deny_rule,
    handle_delete_deny_rule,
)
from .traffic import (
    handle_get_traffic_flows,
    handle_get_traffic_flows_summary,
    handle_find_unmanaged_traffic,
)
from .policy import (
    handle_compliance_check,
    handle_enforcement_readiness,
    handle_get_policy_coverage_report,
    handle_compare_draft_active,
    handle_get_workload_enforcement_status,
)
from .ringfence import (
    handle_create_ringfence,
    handle_ringfence_batch,
    handle_identify_infrastructure_services,
    handle_detect_lateral_movement_paths,
)
from .containers import (
    handle_get_container_clusters,
    handle_get_container_workload_profiles,
    handle_update_container_workload_profile,
    handle_get_kubernetes_workloads,
)
from .infra import (
    handle_check_pce_connection,
    handle_get_events,
    handle_get_pairing_profiles,
)
from .credentials import (
    handle_register_pce_credentials,
    handle_delete_pce_credentials,
    handle_check_pce_credentials_status,
)


_OP_ADMIN = frozenset({OPERATOR, ADMIN})
_ADMIN_ONLY = frozenset({ADMIN})


TOOL_REGISTRY: dict[str, ToolSpec] = {
    # Workloads
    "get-workloads":              ToolSpec(handle_get_workloads,            roles=ALL_ROLES),
    "create-workload":            ToolSpec(handle_create_workload,          roles=_OP_ADMIN, mutating=True),
    "update-workload":            ToolSpec(handle_update_workload,          roles=_OP_ADMIN, mutating=True),
    "delete-workload":            ToolSpec(handle_delete_workload,          roles=_OP_ADMIN, mutating=True),
    # Labels
    "get-labels":                 ToolSpec(handle_get_labels,               roles=ALL_ROLES),
    "create-label":               ToolSpec(handle_create_label,             roles=_OP_ADMIN, mutating=True),
    "update-label":               ToolSpec(handle_update_label,             roles=_OP_ADMIN, mutating=True),
    "delete-label":               ToolSpec(handle_delete_label,             roles=_OP_ADMIN, mutating=True),
    # Services
    "get-services":               ToolSpec(handle_get_services,             roles=ALL_ROLES),
    "create-service":             ToolSpec(handle_create_service,           roles=_OP_ADMIN, mutating=True),
    "update-service":             ToolSpec(handle_update_service,           roles=_OP_ADMIN, mutating=True),
    "delete-service":             ToolSpec(handle_delete_service,           roles=_OP_ADMIN, mutating=True),
    # IP Lists
    "get-iplists":                ToolSpec(handle_get_iplists,              roles=ALL_ROLES),
    "create-iplist":              ToolSpec(handle_create_iplist,            roles=_OP_ADMIN, mutating=True),
    "update-iplist":              ToolSpec(handle_update_iplist,            roles=_OP_ADMIN, mutating=True),
    "delete-iplist":              ToolSpec(handle_delete_iplist,            roles=_OP_ADMIN, mutating=True),
    # Rulesets + provisioning
    "get-rulesets":               ToolSpec(handle_get_rulesets,             roles=ALL_ROLES),
    "create-ruleset":             ToolSpec(handle_create_ruleset,           roles=_OP_ADMIN, mutating=True),
    "update-ruleset":             ToolSpec(handle_update_ruleset,           roles=_OP_ADMIN, mutating=True),
    "delete-ruleset":             ToolSpec(handle_delete_ruleset,           roles=_OP_ADMIN, mutating=True),
    "provision-policy":           ToolSpec(handle_provision_policy,         roles=_ADMIN_ONLY, mutating=True, requires_confirm=True),
    # Deny Rules
    "create-deny-rule":           ToolSpec(handle_create_deny_rule,         roles=_OP_ADMIN, mutating=True),
    "update-deny-rule":           ToolSpec(handle_update_deny_rule,         roles=_OP_ADMIN, mutating=True),
    "delete-deny-rule":           ToolSpec(handle_delete_deny_rule,         roles=_OP_ADMIN, mutating=True),
    # Traffic
    "get-traffic-flows":          ToolSpec(handle_get_traffic_flows,        roles=ALL_ROLES),
    "get-traffic-flows-summary":  ToolSpec(handle_get_traffic_flows_summary,roles=ALL_ROLES),
    "find-unmanaged-traffic":     ToolSpec(handle_find_unmanaged_traffic,   roles=ALL_ROLES, unscopable=True),
    # Policy reports (PCE-wide; not safely scopable)
    "compliance-check":           ToolSpec(handle_compliance_check,         roles=ALL_ROLES, unscopable=True),
    "enforcement-readiness":      ToolSpec(handle_enforcement_readiness,    roles=ALL_ROLES, unscopable=True),
    "get-policy-coverage-report": ToolSpec(handle_get_policy_coverage_report,roles=ALL_ROLES, unscopable=True),
    "compare-draft-active":       ToolSpec(handle_compare_draft_active,     roles=ALL_ROLES, unscopable=True),
    "get-workload-enforcement-status": ToolSpec(handle_get_workload_enforcement_status, roles=ALL_ROLES),
    # Ringfence
    "create-ringfence":           ToolSpec(handle_create_ringfence,         roles=_OP_ADMIN, mutating=True),
    "ringfence-batch":            ToolSpec(handle_ringfence_batch,          roles=_ADMIN_ONLY, mutating=True, requires_confirm=True),
    "identify-infrastructure-services": ToolSpec(handle_identify_infrastructure_services, roles=ALL_ROLES, unscopable=True),
    "detect-lateral-movement-paths":    ToolSpec(handle_detect_lateral_movement_paths,    roles=ALL_ROLES, unscopable=True),
    # Containers
    "get-container-clusters":     ToolSpec(handle_get_container_clusters,   roles=ALL_ROLES),
    "get-container-workload-profiles": ToolSpec(handle_get_container_workload_profiles, roles=ALL_ROLES),
    "update-container-workload-profile": ToolSpec(handle_update_container_workload_profile, roles=_OP_ADMIN, mutating=True),
    "get-kubernetes-workloads":   ToolSpec(handle_get_kubernetes_workloads, roles=ALL_ROLES),
    # Infrastructure
    "check-pce-connection":       ToolSpec(handle_check_pce_connection,     roles=ALL_ROLES),
    "get-events":                 ToolSpec(handle_get_events,               roles=ALL_ROLES),
    "get-pairing-profiles":       ToolSpec(handle_get_pairing_profiles,     roles=ALL_ROLES),
    # Credentials (HTTP mode only; do NOT need ctx.pce). They mutate
    # per-user keystore state (not PCE state) — `mutating=True` is honest
    # about that and keeps the destructive-name guard happy.
    "register-pce-credentials":   ToolSpec(handle_register_pce_credentials,    roles=ALL_ROLES, requires_pce=False, mutating=True),
    "delete-pce-credentials":     ToolSpec(handle_delete_pce_credentials,      roles=ALL_ROLES, requires_pce=False, mutating=True),
    "check-pce-credentials-status": ToolSpec(handle_check_pce_credentials_status, roles=ALL_ROLES, requires_pce=False),
}


# Back-compat: derived map of name → callable. Some external code (and the
# previous server.py) referenced TOOL_HANDLERS directly. After Task 16 this is
# no longer used internally; kept as a derived export to avoid breaking any
# downstream importers.
TOOL_HANDLERS: dict[str, Callable] = {name: spec.handler for name, spec in TOOL_REGISTRY.items()}
