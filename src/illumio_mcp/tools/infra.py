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


def handle_get_events(ctx, arguments: dict) -> list:
    logger.debug("=" * 80)
    logger.debug("GET EVENTS CALLED")
    logger.debug("Arguments received: %s", ScrubbedArgs(arguments))
    logger.debug("=" * 80)

    try:
        pce = ctx.pce

        params = {}
        for param in ['event_type', 'severity', 'status', 'max_results', 'created_by']:
            if arguments.get(param):
                params[param] = arguments[param]
        if arguments.get('timestamp_gte'):
            params['timestamp[gte]'] = arguments['timestamp_gte']
        if arguments.get('timestamp_lte'):
            params['timestamp[lte]'] = arguments['timestamp_lte']

        events = pce.events.get(params=params)

        # Convert events to serializable format
        event_data = []
        for event in events:
            event_dict = {
                'href': event.href,
                'event_type': event.event_type,
                'timestamp': str(event.timestamp) if hasattr(event, 'timestamp') else None,
                'severity': event.severity if hasattr(event, 'severity') else None,
                'status': event.status if hasattr(event, 'status') else None,
                'created_by': str(event.created_by) if hasattr(event, 'created_by') else None,
                'notification_type': event.notification_type if hasattr(event, 'notification_type') else None,
                'info': event.info if hasattr(event, 'info') else None,
                'pce_fqdn': event.pce_fqdn if hasattr(event, 'pce_fqdn') else None
            }
            event_data.append(event_dict)

        return [types.TextContent(
            type="text",
            text=json.dumps({
                "events": event_data,
                "total_count": len(event_data)
            }, indent=2)
        )]

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
