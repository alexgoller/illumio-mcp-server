import json
import logging
import time
import mcp.types as types
from ..pce import PCE_ORG_ID
from ..log_scrub import ScrubbedArgs
from ..errors import describe_error

logger = logging.getLogger('illumio_mcp')


def handle_check_pce_connection(ctx, arguments: dict) -> list:
    """Is the PCE answering, and how fast. The diagnostic tool, so it reports
    what it saw and how long it waited rather than just failing."""
    logger.debug("Initializing PCE connection")
    pce = ctx.pce
    started = time.monotonic()
    try:
        # One GET first, no org, so a dead PCE is reported after a single
        # bounded request instead of after the SDK's two-call check.
        response = pce.get('/health', include_org=False)
        health_ms = (time.monotonic() - started) * 1000
        status = pce.check_connection()
        return [types.TextContent(type="text", text=json.dumps({
            "status": "ok",
            "pce": f"{pce._hostname}:{pce._port}",
            "org_id": pce.org_id,
            "health_http_status": response.status_code,
            "health_round_trip_ms": round(health_ms),
            "total_seconds": round(time.monotonic() - started, 2),
            "connection_check": bool(status),
        }))]
    except Exception as e:
        waited = time.monotonic() - started
        error_msg = (f"PCE did not answer GET /health on {pce._hostname}:{pce._port} "
                     f"after {waited:.1f} seconds: {describe_error(e)}")
        logger.error(error_msg, exc_info=True)
        return [types.TextContent(type="text", text=json.dumps({
            "status": "unreachable",
            "error": error_msg,
            "hint": ("A 5xx here is the PCE or its front end, not this server; a "
                     "timeout is the network or a PCE that accepts connections but "
                     "does not respond. Retries and timeouts are bounded by "
                     "MCP_PCE_RETRIES / MCP_PCE_REQUEST_TIMEOUT."),
        }))]


# Event-type strings behind the get-events `kind` filter.
#
# Illumio names events <object>.<verb>. "verified" = returned by GET /events on
# demo100 (26.30, 2026-10-19) when asked for that event_type. "expected" = the
# name in Illumio's events guide, NOT seen on that PCE: either nothing of the
# kind happened inside its 30-day event retention (no provisioning, pairing or
# enforcement edit of a single workload in the window) or, for user.* on a
# SaaS PCE, the login is recorded by the platform rather than the org. Treat
# an empty result for an expected string as "unconfirmed", not "none". Each
# kind is queried one type at a time (the PCE takes a single event_type per
# request) and merged newest-first.
EVENT_KINDS = {
    # provisioning, rulesets, rules, IP lists, services
    "policy": [
        "sec_policy.create",            # expected: policy provisioned (draft -> active)
        "sec_policy.restore",           # expected: an earlier version re-provisioned
        "rule_set.create", "rule_set.update", "rule_set.delete",            # verified
        "sec_rule.create", "sec_rule.delete",                               # verified
        "sec_rule.update",                                                  # expected
        "deny_rule.create", "deny_rule.update", "deny_rule.delete",         # verified
        "ip_list.create", "ip_list.update", "ip_list.delete",               # verified
        "service.create", "service.update", "service.delete",               # verified
    ],
    # enforcement mode changes arrive as workload updates whose
    # resource_changes[].changes names enforcement_mode; see _is_enforcement_change
    "enforcement": [
        "workloads.bulk_update",        # verified: changes = {enforcement_mode: {before, after}}
        "workload.update",              # expected: single workload edited
    ],
    # pairing, unpairing, tampering
    "ven": [
        "agent.activate",               # expected: VEN paired
        "agent.deactivate",             # expected: VEN unpaired / deactivated
        "agent.tampering",              # expected: firewall tampered with
        "agent.clone_detected",         # expected
        "agent.suspend", "agent.unsuspend",                                  # expected
        "workloads.unpair",             # expected: bulk unpair from the UI/API
    ],
    # user login/logout and API-key use
    "auth": [
        "user.login", "user.logout",                                         # expected: UI
        "user.sign_in", "user.sign_out",                                     # expected
        "user.authenticate",            # expected: API key / SAML
        "request.authorization_failed", # verified: 403 on an API request
    ],
}

# Seen on a live PCE (demo100, 26.30, 2026-10-19), so a caller can tell a
# documented name from a confirmed one. Not a complete list of what the PCE
# emits; label.* and workload.create/delete were there too and are not a kind.
VERIFIED_EVENT_TYPES = {
    "rule_set.create", "rule_set.update", "rule_set.delete",
    "sec_rule.create", "sec_rule.delete",
    "deny_rule.create", "deny_rule.update", "deny_rule.delete",
    "ip_list.create", "ip_list.update", "ip_list.delete",
    "service.create", "service.update", "service.delete",
    "workloads.bulk_update",
    "request.authorization_failed",
    "label.create", "label.update", "label.delete",
    "workload.create", "workload.delete",
    "system_task.inactive_ven_cleanup",
    "system_task.expire_service_account_api_keys",     # SDK docstring
    "soft_limit_exceeded", "hard_limit_exceeded",      # 0.12.0, get-pce-capacity
}


def render_created_by(raw) -> dict | None:
    """{"user": {"href", "username"}} | {"agent": {"href", "hostname"}} |
    {"system": {}} -> {type, username, href}. The PCE's shape keys the actor
    by its kind; a reader wants the kind as a value, not as the only key."""
    if not isinstance(raw, dict) or not raw:
        return None
    kind, body = next(iter(raw.items()))
    if not isinstance(body, dict):
        body = {}
    return {
        "type": kind,
        "username": body.get("username") or body.get("hostname") or body.get("name"),
        "href": body.get("href"),
    }


def _render_resource_change(rc: dict) -> dict:
    """{resource: {rule_set: {href, name}}, change_type, changes} ->
    {resource_type, href, name, change_type, changes}."""
    resource = rc.get("resource") if isinstance(rc.get("resource"), dict) else {}
    rtype, body = (next(iter(resource.items())) if resource else (None, {}))
    if not isinstance(body, dict):
        body = {}
    out = {
        "resource_type": rtype,
        "href": body.get("href"),
        "name": body.get("name") or body.get("hostname") or body.get("username"),
        "change_type": rc.get("change_type"),
    }
    if rc.get("changes") is not None:
        out["changes"] = rc["changes"]
    return out


def _is_enforcement_change(event: dict) -> bool:
    """A workload update is an enforcement-mode change when a resource change
    says so. If the PCE gave no parseable `changes`, keep the event -- better
    an extra workload.update in an audit than a dropped mode flip."""
    changes = [rc.get("changes") for rc in event.get("resource_changes") or []
               if isinstance(rc, dict)]
    parseable = [c for c in changes if isinstance(c, dict)]
    if not parseable:
        return True
    return any("enforcement_mode" in json.dumps(c) for c in parseable)


def render_event(ev: dict) -> dict:
    out = {
        "href": ev.get("href"),
        "event_type": ev.get("event_type"),
        "timestamp": ev.get("timestamp"),
        "severity": ev.get("severity"),
        "status": ev.get("status"),
        "created_by": render_created_by(ev.get("created_by")),
        "info": ev.get("info"),
        "pce_fqdn": ev.get("pce_fqdn"),
    }
    rcs = [_render_resource_change(rc) for rc in ev.get("resource_changes") or []
           if isinstance(rc, dict)]
    if rcs:
        out["resource_changes"] = rcs
    notes = [{"notification_type": n.get("notification_type"), "info": n.get("info")}
             for n in ev.get("notifications") or [] if isinstance(n, dict)]
    if notes:
        out["notifications"] = notes
    action = ev.get("action")
    if isinstance(action, dict):
        out["action"] = {k: action.get(k) for k in
                         ("api_endpoint", "api_method", "src_ip", "http_status_code", "task_name")
                         if action.get(k) is not None}
    return out


def handle_get_events(ctx, arguments: dict) -> list:
    logger.debug("=" * 80)
    logger.debug("GET EVENTS CALLED")
    logger.debug("Arguments received: %s", ScrubbedArgs(arguments))
    logger.debug("=" * 80)

    try:
        pce = ctx.pce

        base = {}
        for param in ['severity', 'status', 'max_results', 'created_by']:
            if arguments.get(param):
                base[param] = arguments[param]
        if arguments.get('timestamp_gte'):
            base['timestamp[gte]'] = arguments['timestamp_gte']
        if arguments.get('timestamp_lte'):
            base['timestamp[lte]'] = arguments['timestamp_lte']
        max_results = int(arguments.get('max_results') or 100)
        base.setdefault('max_results', max_results)

        # event_type: string or list (OR). kind: a named list. Both together
        # are ORed. The PCE filters on ONE event_type per request, so each
        # type is its own request and the results are merged newest-first.
        requested = arguments.get('event_type')
        if isinstance(requested, str):
            requested = [requested]
        event_types = list(requested or [])
        kind = arguments.get('kind')
        if kind:
            if kind not in EVENT_KINDS:
                return [types.TextContent(type="text", text=json.dumps({
                    "error": f"kind must be one of {', '.join(EVENT_KINDS)}, got {kind!r}",
                }))]
            event_types += [t for t in EVENT_KINDS[kind] if t not in event_types]

        # Raw JSON, not the SDK dataclass: Event drops nothing, but
        # NotificationEvent/ResourceEvent re-validate severity and change_type
        # and a value this build does not know raises for the whole page.
        queries = [dict(base, event_type=t) for t in event_types] or [dict(base)]
        seen, events = set(), []
        for params in queries:
            page = pce.get("/events", include_org=True, params=params).json() or []
            for ev in page:
                if not isinstance(ev, dict) or ev.get("href") in seen:
                    continue
                seen.add(ev.get("href"))
                events.append(ev)

        if kind == "enforcement":
            events = [e for e in events if _is_enforcement_change(e)]

        events.sort(key=lambda e: e.get("timestamp") or "", reverse=True)
        truncated = len(events) > max_results
        events = events[:max_results]

        payload = {
            "events": [render_event(e) for e in events],
            "total_count": len(events),
            "event_types_queried": event_types,
            "event_types_unverified": [t for t in event_types if t not in VERIFIED_EVENT_TYPES],
            "truncated": truncated,
        }
        if kind:
            payload["kind"] = kind
        return [types.TextContent(type="text", text=json.dumps(payload, indent=2))]

    except Exception as e:
        error_msg = f"Failed to get events: {describe_error(e)}"
        logger.error(error_msg, exc_info=True)
        return [types.TextContent(
            type="text",
            text=json.dumps({"error": error_msg})
        )]


def handle_get_pairing_profiles(ctx, arguments: dict) -> list:
    logger.debug("=" * 80)
    logger.debug("GET PAIRING PROFILES CALLED")
    logger.debug("Arguments received: %s", ScrubbedArgs(arguments))
    logger.debug("=" * 80)

    try:
        pce = ctx.pce

        params = {"max_results": arguments.get("max_results", 50)}
        if arguments.get("name"):
            params["name"] = arguments["name"]

        resp = pce.get("/orgs/{}/pairing_profiles".format(PCE_ORG_ID), params=params)
        profiles = resp.json()

        result = []
        for p in profiles:
            labels = [{"href": l.get("href"), "key": l.get("key"), "value": l.get("value")} for l in p.get("labels", [])]
            result.append({
                "href": p.get("href"),
                "name": p.get("name"),
                "enforcement_mode": p.get("enforcement_mode"),
                "enforcement_mode_lock": p.get("enforcement_mode_lock"),
                "enabled": p.get("enabled"),
                "labels": labels,
            })

        return [types.TextContent(type="text", text=json.dumps({
            "pairing_profiles": result,
            "total_count": len(result)
        }, indent=2))]

    except Exception as e:
        error_msg = f"Failed to get pairing profiles: {describe_error(e)}"
        logger.error(error_msg, exc_info=True)
        return [types.TextContent(type="text", text=json.dumps({"error": error_msg}, indent=2))]
