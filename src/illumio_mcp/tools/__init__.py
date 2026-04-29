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
from .cloud_inventory import (
    handle_cloud_get_resources,
)
from .cloud_labeling import (
    handle_cloud_assign_labels,
    handle_cloud_remove_labels,
)
from .cloud_traffic import (
    handle_cloud_get_traffic_queries,
    handle_cloud_create_traffic_query,
    handle_cloud_get_traffic_flows,
)

TOOL_HANDLERS = {
    # Workloads
    "get-workloads": handle_get_workloads,
    "create-workload": handle_create_workload,
    "update-workload": handle_update_workload,
    "delete-workload": handle_delete_workload,
    # Labels
    "get-labels": handle_get_labels,
    "create-label": handle_create_label,
    "update-label": handle_update_label,
    "delete-label": handle_delete_label,
    # Services
    "get-services": handle_get_services,
    "create-service": handle_create_service,
    "update-service": handle_update_service,
    "delete-service": handle_delete_service,
    # IP Lists
    "get-iplists": handle_get_iplists,
    "create-iplist": handle_create_iplist,
    "update-iplist": handle_update_iplist,
    "delete-iplist": handle_delete_iplist,
    # Rulesets
    "get-rulesets": handle_get_rulesets,
    "create-ruleset": handle_create_ruleset,
    "update-ruleset": handle_update_ruleset,
    "delete-ruleset": handle_delete_ruleset,
    "provision-policy": handle_provision_policy,
    # Deny Rules
    "create-deny-rule": handle_create_deny_rule,
    "update-deny-rule": handle_update_deny_rule,
    "delete-deny-rule": handle_delete_deny_rule,
    # Traffic
    "get-traffic-flows": handle_get_traffic_flows,
    "get-traffic-flows-summary": handle_get_traffic_flows_summary,
    "find-unmanaged-traffic": handle_find_unmanaged_traffic,
    # Policy
    "compliance-check": handle_compliance_check,
    "enforcement-readiness": handle_enforcement_readiness,
    "get-policy-coverage-report": handle_get_policy_coverage_report,
    "compare-draft-active": handle_compare_draft_active,
    "get-workload-enforcement-status": handle_get_workload_enforcement_status,
    # Ringfence
    "create-ringfence": handle_create_ringfence,
    "ringfence-batch": handle_ringfence_batch,
    "identify-infrastructure-services": handle_identify_infrastructure_services,
    "detect-lateral-movement-paths": handle_detect_lateral_movement_paths,
    # Containers
    "get-container-clusters": handle_get_container_clusters,
    "get-container-workload-profiles": handle_get_container_workload_profiles,
    "update-container-workload-profile": handle_update_container_workload_profile,
    "get-kubernetes-workloads": handle_get_kubernetes_workloads,
    # Infrastructure
    "check-pce-connection": handle_check_pce_connection,
    "get-events": handle_get_events,
    "get-pairing-profiles": handle_get_pairing_profiles,
    # Cloud Platform
    "cloud-get-resources": handle_cloud_get_resources,
    "cloud-assign-labels": handle_cloud_assign_labels,
    "cloud-remove-labels": handle_cloud_remove_labels,
    "cloud-get-traffic-queries": handle_cloud_get_traffic_queries,
    "cloud-create-traffic-query": handle_cloud_create_traffic_query,
    "cloud-get-traffic-flows": handle_cloud_get_traffic_flows,
}
