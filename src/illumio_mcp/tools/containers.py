import json
import logging
import mcp.types as types
from ..pce import get_pce, PCE_ORG_ID

logger = logging.getLogger('illumio_mcp')


def handle_get_container_workload_profiles(arguments: dict) -> list:
    logger.debug("=" * 80)
    logger.debug("GET CONTAINER WORKLOAD PROFILES CALLED")
    logger.debug(f"Arguments received: {json.dumps(arguments, indent=2)}")
    logger.debug("=" * 80)

    try:
        pce = get_pce()

        cluster_href = arguments.get("cluster_href")

        if not cluster_href:
            # List all container clusters first
            resp = pce.get("/orgs/{}/container_clusters".format(PCE_ORG_ID))
            clusters = resp.json()
            if not clusters:
                return [types.TextContent(type="text", text=json.dumps({"message": "No container clusters found", "clusters": []}, indent=2))]
            # Use first cluster if only one, otherwise return list
            if len(clusters) == 1:
                cluster_href = clusters[0]["href"]
            else:
                result = [{"href": c["href"], "name": c.get("name"), "online": c.get("online")} for c in clusters]
                return [types.TextContent(type="text", text=json.dumps({
                    "message": f"Found {len(clusters)} clusters. Specify cluster_href to get profiles.",
                    "clusters": result
                }, indent=2))]

        resp = pce.get("{}/container_workload_profiles".format(cluster_href))
        profiles = resp.json()

        # Apply filters
        ns_filter = arguments.get("namespace")
        managed_filter = arguments.get("managed")
        if ns_filter:
            profiles = [p for p in profiles if p.get("namespace") == ns_filter]
        if managed_filter is not None:
            profiles = [p for p in profiles if p.get("managed") == managed_filter]

        result = []
        for p in profiles:
            labels = [{"href": l.get("href"), "key": l.get("key"), "value": l.get("value")} for l in p.get("assign_labels", [])]
            result.append({
                "href": p.get("href"),
                "name": p.get("name"),
                "namespace": p.get("namespace"),
                "managed": p.get("managed"),
                "enforcement_mode": p.get("enforcement_mode"),
                "assign_labels": labels,
            })

        return [types.TextContent(type="text", text=json.dumps({
            "profiles": result,
            "total_count": len(result)
        }, indent=2))]
    except Exception as e:
            error_msg = f"Failed to get container workload profiles: {str(e)}"
            logger.error(error_msg, exc_info=True)
            return [types.TextContent(type="text", text=json.dumps({"error": error_msg}, indent=2))]


def handle_update_container_workload_profile(arguments: dict) -> list:
    logger.debug("=" * 80)
    logger.debug("UPDATE CONTAINER WORKLOAD PROFILE CALLED")
    logger.debug(f"Arguments received: {json.dumps(arguments, indent=2)}")
    logger.debug("=" * 80)

    try:
        pce = get_pce()

        profile_href = arguments["profile_href"]
        payload = {}
        if "managed" in arguments:
            payload["managed"] = arguments["managed"]
        if "enforcement_mode" in arguments:
            payload["enforcement_mode"] = arguments["enforcement_mode"]
        if "assign_labels" in arguments:
            payload["assign_labels"] = arguments["assign_labels"]

        resp = pce.put(profile_href, json=payload)

        return [types.TextContent(type="text", text=json.dumps({
            "message": f"Successfully updated container workload profile",
            "href": profile_href,
            "updated_fields": list(payload.keys())
        }, indent=2))]
    except Exception as e:
            error_msg = f"Failed to update container workload profile: {str(e)}"
            logger.error(error_msg, exc_info=True)
            return [types.TextContent(type="text", text=json.dumps({"error": error_msg}, indent=2))]


def handle_get_kubernetes_workloads(arguments: dict) -> list:
    logger.debug("=" * 80)
    logger.debug("GET KUBERNETES WORKLOADS CALLED")
    logger.debug(f"Arguments received: {json.dumps(arguments, indent=2)}")
    logger.debug("=" * 80)

    try:
        pce = get_pce()

        params = {"max_results": arguments.get("max_results", 500)}
        if arguments.get("namespace"):
            params["namespace"] = arguments["namespace"]

        resp = pce.get("/orgs/{}/kubernetes_workloads".format(PCE_ORG_ID), params=params)
        workloads = resp.json()

        # Filter by cluster if specified
        cluster_href = arguments.get("cluster_href")
        if cluster_href:
            workloads = [w for w in workloads if w.get("container_cluster", {}).get("href") == cluster_href]

        result = []
        for w in workloads:
            labels = [{"key": l.get("key"), "value": l.get("value")} for l in w.get("labels", [])]
            result.append({
                "href": w.get("href"),
                "name": w.get("name"),
                "kind": w.get("kind"),
                "namespace": w.get("namespace"),
                "labels": labels,
                "enforcement_mode": w.get("enforcement_mode"),
                "security_policy_sync_state": w.get("security_policy_sync_state"),
                "cluster": w.get("container_cluster", {}).get("name"),
            })

        return [types.TextContent(type="text", text=json.dumps({
            "kubernetes_workloads": result,
            "total_count": len(result)
        }, indent=2))]
    
    except Exception as e:
            error_msg = f"Failed to get kubernetes workloads: {str(e)}"
            logger.error(error_msg, exc_info=True)
            return [types.TextContent(type="text", text=json.dumps({"error": error_msg}, indent=2))]


def handle_get_container_clusters(arguments: dict) -> list:
    logger.debug("=" * 80)
    logger.debug("GET CONTAINER CLUSTERS CALLED")
    logger.debug(f"Arguments received: {json.dumps(arguments, indent=2)}")
    logger.debug("=" * 80)

    try:
        pce = get_pce()

        params = {"max_results": arguments.get("max_results", 50)}
        if arguments.get("name"):
            params["name"] = arguments["name"]

        resp = pce.get("/orgs/{}/container_clusters".format(PCE_ORG_ID), params=params)
        clusters = resp.json()

        result = []
        for c in clusters:
            nodes = c.get("nodes", [])
            result.append({
                "href": c.get("href"),
                "name": c.get("name"),
                "online": c.get("online"),
                "clas_mode": c.get("clas_mode"),
                "cluster_mode": c.get("cluster_mode"),
                "kubelink_version": c.get("kubelink_version"),
                "container_runtime": c.get("container_runtime"),
                "node_count": len(nodes),
                "nodes": [{"name": n.get("name")} for n in nodes],
            })

        return [types.TextContent(type="text", text=json.dumps({
            "container_clusters": result,
            "total_count": len(result)
        }, indent=2))]
    except Exception as e:
            error_msg = f"Failed to get container clusters: {str(e)}"
            logger.error(error_msg, exc_info=True)
            return [types.TextContent(type="text", text=json.dumps({"error": error_msg}, indent=2))]
