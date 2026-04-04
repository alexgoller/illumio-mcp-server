import json
import logging
import mcp.types as types
from illumio import Label
from ..pce import get_pce

logger = logging.getLogger('illumio_mcp')


def handle_get_labels(arguments: dict) -> list:
    logger.debug("Initializing PCE connection")
    try:
        pce = get_pce()

        params = {}
        if arguments.get('key'):
            params['key'] = arguments['key']
        if arguments.get('value'):
            params['value'] = arguments['value']
        if arguments.get('max_results'):
            params['max_results'] = arguments['max_results']
        if arguments.get('include_deleted'):
            params['include_deleted'] = arguments['include_deleted']
        if arguments.get('usage'):
            params['usage'] = arguments['usage']

        resp = pce.get('/labels', params=params)
        labels = resp.json()
        return [types.TextContent(
            type="text",
            text=f"Labels: {labels}"
        )]
    except Exception as e:
        error_msg = f"Failed in PCE operation: {str(e)}"
        logger.error(error_msg, exc_info=True)
        return [types.TextContent(
            type="text",
            text=f"Error: {error_msg}"
        )]


def handle_create_label(arguments: dict) -> list:
    logger.debug(f"Creating label with key: {arguments['key']} and value: {arguments['value']}")
    try:
        pce = get_pce()
        label = Label(key=arguments['key'], value=arguments['value'])
        label = pce.labels.create(label)
        logger.debug(f"Label created with status: {label}")
        return [types.TextContent(
            type="text",
            text=f"Label created with status: {label}"
        )]
    except Exception as e:
        error_msg = f"Failed in PCE operation: {str(e)}"
        logger.error(error_msg, exc_info=True)
        return [types.TextContent(
            type="text",
            text=f"Error: {error_msg}"
        )]


def handle_update_label(arguments: dict) -> list:
    logger.debug("Initializing PCE connection")
    try:
        pce = get_pce()

        href = arguments.get("href")
        key = arguments.get("key")
        value = arguments.get("value")
        new_value = arguments.get("new_value")

        # First, find the label
        label = None
        if href:
            logger.debug(f"Looking up label by href: {href}")
            try:
                label = pce.labels.get_by_reference(href)
                logger.debug(f"Found label by href: {label}")
            except Exception as e:
                logger.error(f"Failed to find label by href {href}: {str(e)}")
                return [types.TextContent(
                    type="text",
                    text=f"Error: Label with href {href} not found"
                )]
        else:
            logger.debug(f"Looking up label by key={key}, value={value}")
            labels = pce.labels.get(params={"key": key, "value": value})
            if labels and len(labels) > 0:
                label = labels[0]  # Get the first matching label
                logger.debug(f"Found label by key-value: {label}")
            else:
                logger.error(f"No label found with key={key}, value={value}")
                return [types.TextContent(
                    type="text",
                    text=f"Error: No label found with key={key}, value={value}"
                )]

        if label:
            logger.debug(f"Updating label {label.href} with new_value={new_value}")
            # Prepare the update payload - only include the new value
            update_data = {
                "value": new_value
            }

            # Update the label
            updated_label = pce.labels.update(label.href, update_data)
            logger.debug(f"Label updated successfully: {updated_label}")

            return [types.TextContent(
                type="text",
                text=f"Successfully updated label: {updated_label}"
            )]
        else:
            error_msg = "Failed to find label to update"
            logger.error(error_msg)
            return [types.TextContent(
                type="text",
                text=f"Error: {error_msg}"
            )]

    except Exception as e:
        error_msg = f"Failed to update label: {str(e)}"
        logger.error(error_msg, exc_info=True)
        return [types.TextContent(
            type="text",
            text=f"Error: {error_msg}"
        )]


def handle_delete_label(arguments: dict) -> list:
    logger.debug(f"Deleting label with key: {arguments['key']} and value: {arguments['value']}")
    try:
        pce = get_pce()
        label = pce.labels.get(params={"key": arguments['key'], "value": arguments['value']})
        if label:
            pce.labels.delete(label[0])
            return [types.TextContent(
                type="text",
                text=f"Label deleted with status: {label}"
            )]
        else:
            return [types.TextContent(
                type="text",
                text=f"Label not found"
            )]
    except Exception as e:
        error_msg = f"Failed in PCE operation: {str(e)}"
        logger.error(error_msg, exc_info=True)
        return [types.TextContent(
            type="text",
            text=f"Error: {error_msg}"
        )]
