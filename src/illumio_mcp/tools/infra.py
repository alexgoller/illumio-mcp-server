import json
import logging
import mcp.types as types
from ..pce import get_pce, PCE_ORG_ID

logger = logging.getLogger('illumio_mcp')


def handle_check_pce_connection(arguments: dict) -> list:
    logger.debug("Initializing PCE connection")
    try:
        pce = get_pce()
        connection_status = pce.check_connection()
        return [types.TextContent(
            type="text",
            text=f"PCE connection successful: {connection_status}"
        )]
    except Exception as e:
        error_msg = f"Failed in PCE operation: {str(e)}"
        logger.error(error_msg, exc_info=True)
        return [types.TextContent(
            type="text",
            text=f"Error: {error_msg}"
        )]


def handle_get_events(arguments: dict) -> list:
    logger.debug("=" * 80)
    logger.debug("GET EVENTS CALLED")
    logger.debug(f"Arguments received: {json.dumps(arguments, indent=2)}")
    logger.debug("=" * 80)

    try:
        pce = get_pce()

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
        error_msg = f"Failed to get events: {str(e)}"
        logger.error(error_msg, exc_info=True)
        return [types.TextContent(
            type="text",
            text=json.dumps({"error": error_msg})
        )]


def handle_get_pairing_profiles(arguments: dict) -> list:
    logger.debug("=" * 80)
    logger.debug("GET PAIRING PROFILES CALLED")
    logger.debug(f"Arguments received: {json.dumps(arguments, indent=2)}")
    logger.debug("=" * 80)

    try:
        pce = get_pce()

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
        error_msg = f"Failed to get pairing profiles: {str(e)}"
        logger.error(error_msg, exc_info=True)
        return [types.TextContent(type="text", text=json.dumps({"error": error_msg}, indent=2))]
