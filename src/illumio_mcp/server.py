import asyncio
import os
import json
import logging
from mcp.server.models import InitializationOptions
import mcp.types as types
from mcp.server import NotificationOptions, Server
from pydantic import AnyUrl, BaseModel
import mcp.server.stdio
import dotenv
import sys
from datetime import datetime, timedelta
from illumio import *
import pandas as pd
from json import JSONEncoder
from pathlib import Path

def setup_logging():
    """Configure logging based on environment"""
    logger = logging.getLogger('illumio_mcp')
    logger.setLevel(logging.DEBUG)
    
    # Create formatter
    formatter = logging.Formatter(
        '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    
    # Determine log path based on environment
    if os.environ.get('DOCKER_CONTAINER'):
        log_path = Path('/var/log/illumio-mcp/illumio-mcp.log')
    else:
        # Use home directory for local logging
        log_path = './illumio-mcp.log'
    
    file_handler = logging.FileHandler(str(log_path))
    file_handler.setFormatter(formatter)
    file_handler.setLevel(logging.DEBUG)
    logger.addHandler(file_handler)
    
    # Prevent logs from propagating to root logger
    logger.propagate = False
    
    return logger

# Initialize logging
logger = setup_logging()
logger.debug("Loading environment variables")

dotenv.load_dotenv()

PCE_HOST = os.getenv("PCE_HOST")
PCE_PORT = os.getenv("PCE_PORT")
PCE_ORG_ID = os.getenv("PCE_ORG_ID")
API_KEY = os.getenv("API_KEY")
API_SECRET = os.getenv("API_SECRET")

MCP_BUG_MAX_RESULTS = 500

# Store notes as a simple key-value dict to demonstrate state management
notes: dict[str, str] = {}

server = Server("illumio-mcp")
logging.debug("Server initialized")

@server.list_prompts()
async def handle_list_prompts() -> list[types.Prompt]:
    """
    List available prompts.
        Each prompt can have optional arguments to customize its behavior.
    """
    return [
        types.Prompt(
            name="summarize-notes",
            description="Creates a summary of all notes",
            arguments=[
                types.PromptArgument(
                    name="style",
                    description="Style of the summary (brief/detailed)",
                    required=False,
                )
            ],
        ),
        types.Prompt(
            name="ringfence-application",
            description="Ringfence an application by deploying rulesets to limit the inbound and outbound traffic",
            arguments=[
                types.PromptArgument(
                    name="application_name",
                    description="Name of the application to ringfence",
                    required=True,
                ),
                types.PromptArgument(
                    name="application_environment",
                    description="Environment of the application to ringfence",
                    required=True,
                )
            ],
        ),
        types.Prompt(
            name="analyze-application-traffic",
            description="Analyze the traffic flows for an application and environment",
            arguments=[
                types.PromptArgument(
                    name="application_name",
                    description="Name of the application to analyze",
                    required=True,
                ),
                types.PromptArgument(
                    name="application_environment",
                    description="Environment of the application to analyze",
                    required=True,
                )
            ]
        )
    ]

@server.get_prompt()
async def handle_get_prompt(
    name: str, arguments: dict[str, str] | None
) -> types.GetPromptResult:
    """
    Generate a prompt by combining arguments with server state.
    The prompt includes all current notes and can be customized via arguments.
    """
    if name == "ringfence-application":
        return types.GetPromptResult(
            description="Ringfence an application by deploying rulesets to limit the inbound and outbound traffic",
        messages=[
                types.PromptMessage(
                    role="user",
                    content=types.TextContent(
                        type="text",
                        text=f"""
Ringfence the application {arguments['application_name']} in the environment {arguments['application_environment']}.
Always reference labels as hrefs like /orgs/1/labels/57 or similar.
Consumers means the source of the traffic, providers means the destination of the traffic.

1. First, get all the labels to have them available for later use.
2. Retrieve all the traffic flows inside the application and environment. 
   Only fetch potentially blocked or blocked traffic.Analyze the connections.
3. Then retrieve all the traffic flows inbound to the application and environment.
4. Inside the app, please be sure to have rules for each role or app tier to connect to the other tiers. 
5. Prefer the traffic summary over the traffic flow tool.

Always use traffic flows to find out what other applications and environemnts need to connect into {arguments['application_name']}, 
and then deploy rulesets to limit the inbound traffic to those applications and environments. 
For traffic that is required to connect outbound from {arguments['application_name']}, deploy rulesets to limit the 
outbound traffic to those applications and environments. If a consumer is coming from the same app and env, please use 
all workloads for the rules inside the scope (intra-scope). If it comes from the outside, please use app, env and if possible role

If a remote app is connected as destination, a new ruleset needs to be created that has the name of the remote app and env,
all incoming connections need to be added as extra-scope rules in that ruleset.
Always use hrefs for labels and workloads.
The logic in illumio is the following:

If a scope exists. Rules define connections within the scope if unscoped consumers is not set to true. Unscoped consumers define inbound traffic from things outside the scope. The unscoped consumer is a set of labels being the source of inbound traffic. Provider is the destination. For the provider a value of AMS (short for all workloads) means that a connection is allowed for all workloads inside the scope. So for example if the source is role=monitoring, app=nagios, env=prod, then the rule for the app=ordering, env=prod application would be:

  consumer: role=monitoring,app=nagios,env=prod 
  provider: role=All workloads
  service: 5666/tcp

  If a rule is setting unscoped consumers to "false", this means that the rule is intra scope. Repeating any label that is in the scope does not make sense for this. Instead use role or whatever specific label to characterize the thing in the scope.

e.g. for the loadbalancer to connect to the web-tier in ordering, prod the rule is:

scope: app=ordering, env=prod
consumers: role=loadbalancer
providers: role=web
service: 8080/tcp
unscoped consumers: false

This is a intra-scope rule allowing the role=loadbalancer,app=ordering,env=prod workloads to connect to the role=web,app=ordering,env=prod workloads on port 8080/tcp. 

For traffic that goes from the {arguments['application_name']} app to the outside, please create a ruleset with the name {arguments['application_name']}-outbound and make it scopeless.
Add all the outbound traffic to that ruleset using roles, applications and environments as labels.
                        """
                    )
                )
            ]
        )
    elif name == "analyze-application-traffic":
        return types.GetPromptResult(
            description="Analyze the traffic flows for an application and environment",
            messages=[
                types.PromptMessage(
                    role="user",
                    content=types.TextContent(
                        type="text",
                        text=f"""
                            Please provide the traffic flows for {arguments['application_name']} in the environment {arguments['application_environment']}.
                            Order by inbound and outbound traffic and app/env/role tupels.
                            Find other label types that are of interest and show them. Display your results in a react component. Show protocol, port and try to
                            understand the traffic flows (e.g. 5666/tcp likely could be nagios).
                            Categorize traffic into infrastructure and application traffic.
                            Find out if the application is internet facing or not.
                            Show illumio role labels, as well as application and environment labels in the output.
                        """
                    )
                )
            ]
        )

    else:
        raise ValueError(f"Unknown prompt: {name}")

@server.list_tools()
async def handle_list_tools() -> list[types.Tool]:
    """
    List available tools.
    Each tool specifies its arguments using JSON Schema validation.
    """
    return [
        types.Tool(
            name="add-note",
            description="Add a new note",
            inputSchema={
                "type": "object",
                "properties": {
                    "name": {"type": "string"},
                    "content": {"type": "string"},
                },
                "required": ["name", "content"],
            },
        ),
        types.Tool(
            name="get-workloads",
            description="Get workloads from the PCE",
            inputSchema={
                "type": "object",
                "properties": {
                    "name": {"type": "string"},
                },
                "required": ["name"],
            },
        ),
        types.Tool(
            name="update-workload",
            description="Update a workload in the PCE",
            inputSchema={
                "type": "object",
                "properties": {
                    "name": {"type": "string"},
                    "ip_addresses": {"type": "array", "items": {"type": "string"}},
                    "labels": {"type": "array", "items": 
                               {"key": {"type": "string"}, "value": {"type": "string"}}
                    },
                },
                "required": ["name", "ip_addresses"],
            }
        ),
        types.Tool(
            name="get-labels",
            description="Get all labels from PCE",
            mimeType="application/json",
            inputSchema={
                "type": "object",
                "properties": {
                    "name": {"type": "string"},
                },
                "required": [],
            }
        ),
        types.Tool(
            name="create-workload",
            description="Create a Illumio Core unmanaged workload in the PCE",
            inputSchema={
                "type": "object",
                "properties": {
                    "name": {"type": "string"},
                    "ip_addresses": {"type": "array", "items": {"type": "string"}},
                    "labels": {"type": "array", "items": 
                               {"key": {"type": "string"}, "value": {"type": "string"}}
                    },
                },
                "required": ["name", "ip_addresses"],
            }
        ),
        types.Tool(
            name="create-label",
            description="Create a label of a specific type and the value in the PCE",
            inputSchema={
                "type": "object",
                "properties": {
                    "key": {"type": "string"},
                    "value": {"type": "string"},
                },
                "required": ["key", "value"]
            }
        ),
        types.Tool(
            name="delete-label",
            description="Delete a label in the PCE",
            inputSchema={
                "type": "object",
                "properties": {
                    "key": {"type": "string"},
                    "value": {"type": "string"},
                },
                "required": ["key", "value"]
            }
        ),
        types.Tool(
            name="delete-workload",
            description="Delete a workload from the PCE",
            inputSchema={
                "type": "object",
                "properties": {"name": {"type": "string"}},
                "required": ["name"]
            }
        ),
        types.Tool(
            name="get-traffic-flows",
            description="Get traffic flows from the PCE with comprehensive filtering options",
            inputSchema={
                "type": "object",
                "properties": {
                    "start_date": {"type": "string", "description": "Starting datetime (YYYY-MM-DD or timestamp)"},
                    "end_date": {"type": "string", "description": "Ending datetime (YYYY-MM-DD or timestamp)"},
                    "include_sources": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": "Sources to include (label/IP list/workload HREFs, FQDNs, IPs)"
                    },
                    "exclude_sources": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": "Sources to exclude (label/IP list/workload HREFs, FQDNs, IPs)"
                    },
                    "include_destinations": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": "Destinations to include (label/IP list/workload HREFs, FQDNs, IPs)"
                    },
                    "exclude_destinations": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": "Destinations to exclude (label/IP list/workload HREFs, FQDNs, IPs)"
                    },
                    "include_services": {
                        "type": "array",
                        "items": {
                            "type": "object",
                            "properties": {
                                "port": {"type": "integer"},
                                "proto": {"type": "string"}
                            }
                        }
                    },
                    "exclude_services": {
                        "type": "array",
                        "items": {
                            "type": "object",
                            "properties": {
                                "port": {"type": "integer"},
                                "proto": {"type": "string"}
                            }
                        }
                    },
                    "policy_decisions": {
                        "type": "array",
                        "items": {
                            "type": "string",
                            "enum": ["allowed", "blocked", "potentially_blocked", "unknown"]
                        }
                    },
                    "exclude_workloads_from_ip_list_query": {"type": "boolean"},
                    "max_results": {"type": "integer"},
                    "query_name": {"type": "string"}
                },
                "required": ["start_date", "end_date"]
            }
        ),
        types.Tool(
            name="get-traffic-flows-summary",
            description="Get traffic flows from the PCE in a summarized text format, this is a text format that is not a dataframe, it also is not json, the form is: 'From <source> to <destination> on <port> <proto>: <number of connections>'",
            inputSchema={
                "type": "object",
                "properties": {
                    "start_date": {"type": "string", "description": "Starting datetime (YYYY-MM-DD or timestamp)"},
                    "end_date": {"type": "string", "description": "Ending datetime (YYYY-MM-DD or timestamp)"},
                    "include_sources": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": "Sources to include (label/IP list/workload HREFs, FQDNs, IPs). Best case these are hrefs like /orgs/1/labels/57 or similar. Other way is app=env as an example (label key and value)"
                    },
                    "exclude_sources": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": "Sources to exclude (label/IP list/workload HREFs, FQDNs, IPs). Best case these are hrefs like /orgs/1/labels/57 or similar. Other way is app=env as an example (label key and value)"
                    },
                    "include_destinations": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": "Destinations to include (label/IP list/workload HREFs, FQDNs, IPs). Best case these are hrefs like /orgs/1/labels/57 or similar. Other way is app=env as an example (label key and value)"
                    },
                    "exclude_destinations": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": "Destinations to exclude (label/IP list/workload HREFs, FQDNs, IPs). Best case these are hrefs like /orgs/1/labels/57 or similar. Other way is app=env as an example (label key and value)"
                    },
                    "include_services": {
                        "type": "array",
                        "items": {
                            "type": "object",
                            "properties": {
                                "port": {"type": "integer"},
                                "proto": {"type": "string"}
                            }
                        }
                    },
                    "exclude_services": {
                        "type": "array",
                        "items": {
                            "type": "object",
                            "properties": {
                                "port": {"type": "integer"},
                                "proto": {"type": "string"}
                            }
                        }
                    },
                    "policy_decisions": {
                        "type": "array",
                        "items": {
                            "type": "string",
                            "enum": ["allowed", "potentially_blocked", "blocked", "unknown"]
                        }
                    },
                    "exclude_workloads_from_ip_list_query": {"type": "boolean"},
                    "max_results": {"type": "integer"},
                    "query_name": {"type": "string"}
                },
                "required": ["start_date", "end_date"]
            }
        ),
        types.Tool(
            name="check-pce-connection",
            description="Are my credentials and the connection to the PCE working?",
            inputSchema={
                "type": "object",
                "properties": {}
            }
        ),
        types.Tool(
            name="get-rulesets",
            description="Get rulesets from the PCE",
            inputSchema={
                "type": "object",
                "properties": {
                    "name": {
                        "type": "string",
                        "description": "Filter rulesets by name (optional)"
                    },
                    "enabled": {
                        "type": "boolean",
                        "description": "Filter by enabled/disabled status (optional)"
                    }
                }
            }
        ),
        # add a delete-ruleset tool, either by href or name
        types.Tool(
            name="delete-ruleset",
            description="Delete a ruleset from the PCE",
            inputSchema={
                "type": "object",
                "properties": {
                    "href": {"type": "string"},
                    "name": {"type": "string"}
                },
                "oneOf": [
                    {"required": ["href"]},
                    {"required": ["name"]}
                ]
            }
        ),
        types.Tool(
            name="get-iplists",
            description="Get IP lists from the PCE",
            inputSchema={
                "type": "object",
                "properties": {
                    "name": {
                        "type": "string",
                        "description": "Filter IP lists by name (optional)"
                    },
                    "description": {
                        "type": "string",
                        "description": "Filter by description (optional)"
                    },
                    "ip_ranges": {
                        "type": "array",
                        "items": {
                            "type": "string"
                        },
                        "description": "Filter by IP ranges (optional)"
                    }
                }
            }
        ),
        types.Tool(
            name="get-events",
            description="Get events from the PCE",
            inputSchema={
                "type": "object",
                "properties": {
                    "event_type": {
                        "type": "string",
                        "description": "Filter by event type (e.g., 'system_task.expire_service_account_api_keys')"
                    },
                    "severity": {
                        "type": "string",
                        "enum": ["emerg", "alert", "crit", "err", "warning", "notice", "info", "debug"],
                        "description": "Filter by event severity"
                    },
                    "status": {
                        "type": "string",
                        "enum": ["success", "failure"],
                        "description": "Filter by event status"
                    },
                    "max_results": {
                        "type": "integer",
                        "description": "Maximum number of events to return",
                        "default": 100
                    }
                }
            }
        ),
        types.Tool(
            name="create-ruleset",
            description="Create a ruleset in the PCE with support for ring-fencing patterns",
            inputSchema={
                "type": "object",
                "properties": {
                    "name": {"type": "string", "description": "Name of the ruleset (e.g., 'RS-ELK'). Must be unique in the PCE."},
                    "description": {"type": "string", "description": "Description of the ruleset (optional)"},
                    "scopes": {
                        "type": "array",
                        "items": {
                            "type": "array",
                            "items": {"type": "string"}
                        },
                        "description": "List of label combinations that define scopes. Each scope is an array of label values. This need to be label references like /orgs/1/labels/57 or similar. Get the label href from the get-labels tool."
                    },
                    "rules": {
                        "type": "array",
                        "items": {
                            "type": "object",
                            "properties": {
                                "providers": {
                                    "type": "array",
                                    "items": {"type": "string"},
                                    "description": "Array of provider labels, 'ams' for all workloads, or IP list references (e.g., 'iplist:Any (0.0.0.0/0)')"
                                },
                                "consumers": {
                                    "type": "array",
                                    "items": {"type": "string"},
                                    "description": "Array of consumer labels, 'ams' for all workloads, or IP list references (e.g., 'iplist:Any (0.0.0.0/0)')"
                                },
                                "ingress_services": {
                                    "type": "array",
                                    "items": {
                                        "type": "object",
                                        "properties": {
                                            "port": {"type": "integer"},
                                            "proto": {"type": "string"}
                                        },
                                        "required": ["port", "proto"]
                                    }
                                },
                                "unscoped_consumers": {
                                    "type": "boolean",
                                    "description": "Whether to allow unscoped consumers (extra-scope rule)",
                                    "default": False
                                }
                            },
                            "required": ["providers", "consumers", "ingress_services"]
                        }
                    }
                },
                "required": ["name", "scopes"]
            }
        ),
        types.Tool(
            name="get-services",
            description="Get services from the PCE with optional filtering",
            inputSchema={
                "type": "object",
                "properties": {
                    "name": {
                        "type": "string",
                        "description": "Filter services by name"
                    },
                    "description": {
                        "type": "string",
                        "description": "Filter services by description"
                    },
                    "port": {
                        "type": "integer",
                        "description": "Filter services by port number"
                    },
                    "proto": {
                        "type": "string",
                        "description": "Filter services by protocol (e.g., tcp, udp)"
                    },
                    "process_name": {
                        "type": "string",
                        "description": "Filter services by process name"
                    }
                }
            }
        ),
        types.Tool(
            name="update-label",
            description="Update an existing label in the PCE",
            inputSchema={
                "type": "object",
                "properties": {
                    "href": {
                        "type": "string",
                        "description": "Label href (e.g., /orgs/1/labels/42). Either href or both key and value must be provided to identify the label."
                    },
                    "key": {
                        "type": "string",
                        "description": "Label type (e.g., role, app, env, loc)"
                    },
                    "value": {
                        "type": "string",
                        "description": "Current value of the label"
                    },
                    "new_value": {
                        "type": "string",
                        "description": "New value for the label"
                    }
                },
                "oneOf": [
                    {"required": ["href", "key", "new_value"]},
                    {"required": ["key", "value", "new_value"]}
                ]
            }
        ),
        types.Tool(
            name="create-iplist",
            description="Create a new IP List in the PCE",
            inputSchema={
                "type": "object",
                "properties": {
                    "name": {
                        "type": "string",
                        "description": "Name of the IP List"
                    },
                    "description": {
                        "type": "string",
                        "description": "Description of the IP List"
                    },
                    "ip_ranges": {
                        "type": "array",
                        "description": "List of IP ranges to include",
                        "items": {
                            "type": "object",
                            "properties": {
                                "from_ip": {
                                    "type": "string",
                                    "description": "Starting IP address (IPv4 or IPv6)"
                                },
                                "to_ip": {
                                    "type": "string",
                                    "description": "Ending IP address (optional, for ranges)"
                                },
                                "description": {
                                    "type": "string",
                                    "description": "Description of this IP range (optional)"
                                },
                                "exclusion": {
                                    "type": "boolean",
                                    "description": "Whether this is an exclusion range",
                                    "default": False
                                }
                            },
                            "required": ["from_ip"]
                        }
                    },
                    "fqdn": {
                        "type": "string",
                        "description": "Fully Qualified Domain Name (optional)"
                    }
                },
                "required": ["name", "ip_ranges"]
            }
        ),
        types.Tool(
            name="update-iplist",
            description="Update an existing IP List in the PCE",
            inputSchema={
                "type": "object",
                "properties": {
                    "href": {
                        "type": "string",
                        "description": "Href of the IP List to update"
                    },
                    "name": {
                        "type": "string",
                        "description": "Name of the IP List to update (alternative to href)"
                    },
                    "description": {
                        "type": "string",
                        "description": "New description for the IP List (optional)"
                    },
                    "ip_ranges": {
                        "type": "array",
                        "description": "New list of IP ranges",
                        "items": {
                            "type": "object",
                            "properties": {
                                "from_ip": {
                                    "type": "string",
                                    "description": "Starting IP address (IPv4 or IPv6)"
                                },
                                "to_ip": {
                                    "type": "string",
                                    "description": "Ending IP address (optional, for ranges)"
                                },
                                "description": {
                                    "type": "string",
                                    "description": "Description of this IP range (optional)"
                                },
                                "exclusion": {
                                    "type": "boolean",
                                    "description": "Whether this is an exclusion range",
                                    "default": False
                                }
                            },
                            "required": ["from_ip"]
                        }
                    },
                    "fqdn": {
                        "type": "string",
                        "description": "New Fully Qualified Domain Name (optional)"
                    }
                },
                "oneOf": [
                    {"required": ["href"]},
                    {"required": ["name"]}
                ]
            }
        ),
        types.Tool(
            name="delete-iplist",
            description="Delete an IP List from the PCE",
            inputSchema={
                "type": "object",
                "properties": {
                    "href": {
                        "type": "string",
                        "description": "Href of the IP List to delete"
                    },
                    "name": {
                        "type": "string",
                        "description": "Name of the IP List to delete (alternative to href)"
                    }
                },
                "oneOf": [
                    {"required": ["href"]},
                    {"required": ["name"]}
                ]
            }
        ),
        types.Tool(
            name="update-ruleset",
            description="Update an existing ruleset in the PCE",
            inputSchema={
                "type": "object",
                "properties": {
                    "href": {
                        "type": "string",
                        "description": "Href of the ruleset to update"
                    },
                    "name": {
                        "type": "string",
                        "description": "Name of the ruleset to update (alternative to href)"
                    },
                    "description": {
                        "type": "string",
                        "description": "New description for the ruleset"
                    },
                    "enabled": {
                        "type": "boolean",
                        "description": "Whether the ruleset is enabled"
                    },
                    "scopes": {
                        "type": "array",
                        "description": "New scopes for the ruleset",
                        "items": {
                            "type": "array",
                            "items": {
                                "oneOf": [
                                    {
                                        "type": "string",
                                        "description": "Label href or key=value string"
                                    },
                                    {
                                        "type": "object",
                                        "properties": {
                                            "href": {
                                                "type": "string",
                                                "description": "Label href"
                                            }
                                        },
                                        "required": ["href"]
                                    }
                                ]
                            }
                        }
                    }
                },
                "oneOf": [
                    {"required": ["href"]},
                    {"required": ["name"]}
                ]
            }
        ),
        types.Tool(
            name="delete-ruleset",
            description="Delete a ruleset from the PCE",
            inputSchema={
                "type": "object",
                "properties": {
                    "href": {
                        "type": "string",
                        "description": "Href of the ruleset to delete"
                    },
                    "name": {
                        "type": "string",
                        "description": "Name of the ruleset to delete (alternative to href)"
                    }
                },
                "oneOf": [
                    {"required": ["href"]},
                    {"required": ["name"]}
                ]
            }
        ),
    ]

@server.call_tool()
async def handle_call_tool(
    name: str, arguments: dict | None
) -> list[types.TextContent | types.ImageContent | types.EmbeddedResource]:
    logger.debug(f"Handling tool call: {name} with arguments: {arguments}")
    
    if name == "get-workloads":
        # harmonize the logging
        logger.debug("=" * 80)  
        logger.debug("GET WORKLOADS CALLED")
        logger.debug(f"Arguments received: {json.dumps(arguments, indent=2)}")
        logger.debug("=" * 80)

        logger.debug("Initializing PCE connection")
        try:
            logger.debug(f"PCE connection details - Host: {PCE_HOST}, Port: {PCE_PORT}, Org: {PCE_ORG_ID}")
            pce = PolicyComputeEngine(PCE_HOST, port=PCE_PORT, org_id=PCE_ORG_ID)
            pce.set_credentials(API_KEY, API_SECRET)
            logger.debug("Credentials set")
            connection_status = pce.check_connection()
            logger.debug(f"PCE connection status: {connection_status}")
            
            logger.debug("Fetching workloads from PCE")
            workloads = pce.workloads.get(params={"include": "labels", "max_results": 10000})
            logger.debug(f"Successfully retrieved {len(workloads)} workloads")
            return [types.TextContent(
                type="text",
                text=f"Workloads: {workloads}"
            )]
        except Exception as e:
            error_msg = f"Failed in PCE operation: {str(e)}"
            logger.error(error_msg, exc_info=True)
            return [types.TextContent(
                type="text",
                text=f"Error: {error_msg}"
            )]
    elif name == "check-pce-connection":
        logger.debug("Initializing PCE connection")
        try:
            pce = PolicyComputeEngine(PCE_HOST, port=PCE_PORT, org_id=PCE_ORG_ID)
            pce.set_credentials(API_KEY, API_SECRET)
            return [types.TextContent(
                type="text",
                text=f"PCE connection successful"
            )]
        except Exception as e:
            error_msg = f"Failed in PCE operation: {str(e)}"
            logger.error(error_msg, exc_info=True)
            return [types.TextContent(
                type="text",
                text=f"Error: {error_msg}"
            )]
    elif name == "create-label":
        logger.debug(f"Creating label with key: {arguments['key']} and value: {arguments['value']}")
        try:
            pce = PolicyComputeEngine(PCE_HOST, port=PCE_PORT, org_id=PCE_ORG_ID)
            pce.set_credentials(API_KEY, API_SECRET)
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
    elif name == "delete-label":
        logger.debug(f"Deleting label with key: {arguments['key']} and value: {arguments['value']}")
        try:
            pce = PolicyComputeEngine(PCE_HOST, port=PCE_PORT, org_id=PCE_ORG_ID)
            pce.set_credentials(API_KEY, API_SECRET)
            label = pce.labels.get(params = { "key": arguments['key'], "value": arguments['value'] })
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
    elif name == "get-labels":
        logger.debug("Initializing PCE connection")
        try:
            pce = PolicyComputeEngine(PCE_HOST, port=PCE_PORT, org_id=PCE_ORG_ID)
            pce.set_credentials(API_KEY, API_SECRET)
            resp = pce.get('/labels')
            labels = resp.json()
            return [types.TextContent(
                type="text",
                text= f"Labels: {labels}"
            )]
        except Exception as e:
            error_msg = f"Failed in PCE operation: {str(e)}"
            logger.error(error_msg, exc_info=True)
            return [types.TextContent(
                type="json",
                text=f"Error: {error_msg}"
            )]
    elif name == "create-workload":
        logger.debug(f"Creating workload with name: {arguments['name']} and ip_addresses: {arguments['ip_addresses']}")
        logger.debug(f"Labels: {arguments['labels']}")
        try:
            pce = PolicyComputeEngine(PCE_HOST, port=PCE_PORT, org_id=PCE_ORG_ID)
            pce.set_credentials(API_KEY, API_SECRET)

            interfaces = []
            prefix = "eth"
            if_count = 0
            for ip in arguments['ip_addresses']:
                intf = Interface(name = f"{prefix}{if_count}", address = ip)
                interfaces.append(intf)
                if_count += 1

            workload_labels = []

            for label in arguments['labels']:
                logger.debug(f"Label: {label}")
                # check if label already exists
                label_resp = pce.labels.get(params = { "key": label['key'], "value": label['value'] })
                if label_resp:
                    logger.debug(f"Label already exists: {label_resp}")
                    workload_label = label_resp[0]  # Get the first matching label
                else:
                    logger.debug(f"Label does not exist, creating: {label}")
                    new_label = Label(key=label['key'], value=label['value'])
                    workload_label = pce.labels.create(new_label)

                workload_labels.append(workload_label)

            logger.debug(f"Labels: {workload_labels}")

            workload = Workload(
                name=arguments['name'], 
                interfaces=interfaces, 
                labels=workload_labels,
                hostname=arguments['name']  # Adding hostname which might be required
            )
            status = pce.workloads.create(workload)
            logger.debug(f"Workload creation status: {status}")
            return [types.TextContent(
                type="text",
                text=f"Workload created with status: {status}, workload: {workload}"
            )]
        except Exception as e:
            error_msg = f"Failed in PCE operation: {str(e)}"
            logger.error(error_msg, exc_info=True)
            return [types.TextContent(
                type="text",
                text=f"Error: {error_msg}"
            )]
    elif name == "update-workload":
        logger.debug(f"Updating workload with name: {arguments['name']} and ip_addresses: {arguments['ip_addresses']}")
        logger.debug(f"Labels: {arguments['labels']}")
        try:
            pce = PolicyComputeEngine(PCE_HOST, port=PCE_PORT, org_id=PCE_ORG_ID)
            pce.set_credentials(API_KEY, API_SECRET)

            workload = pce.workloads.get(params = { "name": arguments['name'] })
            if workload:
                logger.debug(f"Workload found: {workload}")
                interfaces = []
                prefix = "eth"
                if_count = 0
                for ip in arguments['ip_addresses']:
                    intf = Interface(name = f"{prefix}{if_count}", address = ip)
                    interfaces.append(intf)
                    if_count += 1

                workload_labels = []

                for label in arguments['labels']:
                    logger.debug(f"Label: {label}")
                    # check if label already exists
                    label_resp = pce.labels.get(params = { "key": label['key'], "value": label['value'] })
                    if label_resp:
                        logger.debug(f"Label already exists: {label_resp}")
                        workload_label = label_resp[0]  # Get the first matching label
                    else:
                        logger.debug(f"Label does not exist, creating: {label}")
                        new_label = Label(key=label['key'], value=label['value'])
                        workload_label = pce.labels.create(new_label)

                    workload_labels.append(workload_label)

                logger.debug(f"Labels: {workload_labels}")
                if workload_labels:
                    workload = pce.workloads.update(workload[0], labels=workload_labels)
                    logger.debug(f"Workload update status: {workload}")
                    return [types.TextContent(
                    type="text",
                    text=f"Workload updated with status: {workload}"
                )]

                elif interfaces:
                    workload = pce.workloads.update(workload[0], interfaces=interfaces)
                    logger.debug(f"Workload update status: {workload}")
                    return [types.TextContent(
                    type="text",
                    text=f"Workload updated with status: {workload}"
                )]
                elif interfaces and workload_labels:
                    workload = pce.workloads.update(workload[0], interfaces=interfaces, labels=workload_labels)
                    logger.debug(f"Workload update status: {workload}")
                    return [types.TextContent(
                    type="text",
                    text=f"Workload updated with status: {workload}"
                )]
            else:
                logger.debug(f"Workload not found")
                return [types.TextContent(
                    type="text",
                    text=f"Workload not found"
                )]
        except Exception as e:
            error_msg = f"Failed in PCE operation: {str(e)}"
            logger.error(error_msg, exc_info=True)
            return [types.TextContent(
                type="text",
                text=f"Error: {error_msg}"
            )]
    elif name == "delete-workload":
        logger.debug(f"Deleting workload with name: {arguments['name']}")
        try:
            pce = PolicyComputeEngine(PCE_HOST, port=PCE_PORT, org_id=PCE_ORG_ID)
            pce.set_credentials(API_KEY, API_SECRET)
            workload = pce.workloads.get(params = { "name": arguments['name'] })
            if workload:
                pce.workloads.delete(workload[0])
                return [types.TextContent(
                    type="text",
                    text=f"Workload deleted with status: {status}"
                )]
            else:
                return [types.TextContent(
                    type="text",
                    text=f"Workload not found"
                )]
        except Exception as e:
            error_msg = f"Failed in PCE operation: {str(e)}"
            logger.error(error_msg, exc_info=True)
            return [types.TextContent(
                type="text",
                text=f"Error: {error_msg}"
            )]
    elif name == "get-traffic-flows":
        logger.debug("=" * 80)
        logger.debug("GET TRAFFIC FLOWS CALLED")
        logger.debug(f"Arguments received: {json.dumps(arguments, indent=2)}")
        
        # assume a default start date of 1 day ago and end date of now
        if 'start_date' not in arguments:
            arguments['start_date'] = (datetime.now() - timedelta(days=1)).strftime('%Y-%m-%d')
        if 'end_date' not in arguments:
            arguments['end_date'] = datetime.now().strftime('%Y-%m-%d')

        if not arguments or 'start_date' not in arguments or 'end_date' not in arguments:
            error_msg = "Missing required arguments: 'start_date' and 'end_date' are required"
            logger.error(error_msg)
            return [types.TextContent(
                type="text",
                text=json.dumps({"error": error_msg})
            )]

        logger.debug(f"Start Date: {arguments.get('start_date')}")
        logger.debug(f"End Date: {arguments.get('end_date')}")
        logger.debug(f"Include Sources: {arguments.get('include_sources', [])}")
        logger.debug(f"Exclude Sources: {arguments.get('exclude_sources', [])}")
        logger.debug(f"Include Destinations: {arguments.get('include_destinations', [])}")
        logger.debug(f"Exclude Destinations: {arguments.get('exclude_destinations', [])}")
        logger.debug(f"Include Services: {arguments.get('include_services', [])}")
        logger.debug(f"Exclude Services: {arguments.get('exclude_services', [])}")
        logger.debug(f"Policy Decisions: {arguments.get('policy_decisions', [])}")
        logger.debug(f"Exclude Workloads from IP List: {arguments.get('exclude_workloads_from_ip_list_query', True)}")
        logger.debug(f"Max Results: {arguments.get('max_results', 900)}")
        logger.debug(f"Query Name: {arguments.get('query_name')}")
        logger.debug("=" * 80)

        try:
            pce = PolicyComputeEngine(PCE_HOST, port=PCE_PORT, org_id=PCE_ORG_ID)
            pce.set_credentials(API_KEY, API_SECRET)

            logger.debug(f"Due to a condition in MCP, max results is set to {MCP_BUG_MAX_RESULTS}")
            # TODO: fix this in the future...
            arguments['max_results'] = MCP_BUG_MAX_RESULTS

            traffic_query = TrafficQuery.build(
                start_date=arguments['start_date'],
                end_date=arguments['end_date'],
                include_sources=arguments.get('include_sources', [[]]),
                exclude_sources=arguments.get('exclude_sources', []),
                include_destinations=arguments.get('include_destinations', [[]]),
                exclude_destinations=arguments.get('exclude_destinations', []),
                include_services=arguments.get('include_services', []),
                exclude_services=arguments.get('exclude_services', []),
                policy_decisions=arguments.get('policy_decisions', []),
                exclude_workloads_from_ip_list_query=arguments.get('exclude_workloads_from_ip_list_query', True),
                max_results=arguments.get('max_results', 10000),
                query_name=arguments.get('query_name', 'mcp-traffic-query')
            )

            all_traffic = pce.get_traffic_flows_async(
                query_name=arguments.get('query_name', 'mcp-traffic-query'),
                traffic_query=traffic_query
            )
            
            # Convert the traffic flows to a serializable format
            traffic_data = []
            for flow in all_traffic:
                try:
                    flow_dict = {
                        'src_ip': str(flow.src.ip) if flow.src and hasattr(flow.src, 'ip') else None,
                        'dst_ip': str(flow.dst.ip) if flow.dst and hasattr(flow.dst, 'ip') else None,
                        'proto': str(flow.service.proto) if flow.service and hasattr(flow.service, 'proto') else None,
                        'port': int(flow.service.port) if flow.service and hasattr(flow.service, 'port') else None,
                        'policy_decision': str(flow.policy_decision) if hasattr(flow, 'policy_decision') else None,
                        'num_connections': int(flow.num_connections) if hasattr(flow, 'num_connections') else 0
                    }
                    # Add workload information if available
                    if hasattr(flow.src, 'workload') and flow.src.workload:
                        flow_dict['src_workload'] = str(flow.src.workload.name)
                    if hasattr(flow.dst, 'workload') and flow.dst.workload:
                        flow_dict['dst_workload'] = str(flow.dst.workload.name)
                    
                    traffic_data.append(flow_dict)
                except Exception as e:
                    logger.error(f"Error processing flow: {e}")
                    continue

            df = to_dataframe(all_traffic)

            # group dataframe by src_ip, dst_ip, proto, port, policy_decision tuples, aggregate num_connections
            df = df.groupby(['src_ip', 'dst_ip', 'proto', 'port', 'policy_decision']).agg({'num_connections': 'sum'}).reset_index()

            # limit dataframe json output to less than 1048576
            MAX_ROWS = 1000
            if len(df) > MAX_ROWS:
                logger.warning(f"Truncating results from {len(df)} to {MAX_ROWS} entries")
                df = df.nlargest(MAX_ROWS, 'num_connections')

            response_size = len(df.to_json(orient="records"))

            if response_size > 1048576:
                logger.warning(f"Response size exceeds 1MB limit. Truncating to {MAX_ROWS} entries")
                step_down = 0.9
                while response_size > 1048576 or step_down == 0:
                    rows = int(MAX_ROWS * step_down)
                    step_down = step_down - 0.1
                    df = df.nlargest(rows, 'num_connections')
                    response_size = len(df.to_json(orient="records"))
                    logger.debug(f"Response size: {response_size} Step down: {step_down}")

            # trying this in case GC doesn't work
            df_json = df.to_json(orient="records")
            del df

            # return dataframe df in json format
            return [types.TextContent(
                type="text",
                text= df_json
            )]
        except Exception as e:
            error_msg = f"Failed in PCE operation: {str(e)}"
            logger.error(error_msg, exc_info=True)
            return [types.TextContent(
                type="text",
                text=json.dumps({"error": error_msg})
            )]
    elif name == "get-traffic-flows-summary":
        logger.debug("=" * 80)
        logger.debug("GET TRAFFIC FLOWS SUMMARY CALLED")
        logger.debug(f"Arguments received: {json.dumps(arguments, indent=2)}")
        logger.debug(f"Start Date: {arguments.get('start_date')}")
        logger.debug(f"End Date: {arguments.get('end_date')}")
        logger.debug(f"Include Sources: {arguments.get('include_sources', [])}")
        logger.debug(f"Exclude Sources: {arguments.get('exclude_sources', [])}")
        logger.debug(f"Include Destinations: {arguments.get('include_destinations', [])}")
        logger.debug(f"Exclude Destinations: {arguments.get('exclude_destinations', [])}")
        logger.debug(f"Include Services: {arguments.get('include_services', [])}")
        logger.debug(f"Exclude Services: {arguments.get('exclude_services', [])}")
        logger.debug(f"Policy Decisions: {arguments.get('policy_decisions', [])}")
        logger.debug(f"Exclude Workloads from IP List: {arguments.get('exclude_workloads_from_ip_list_query', True)}")
        logger.debug(f"Max Results: {arguments.get('max_results', 10000)}")
        logger.debug(f"Query Name: {arguments.get('query_name')}")
        logger.debug("=" * 80)

        try:
            pce = PolicyComputeEngine(PCE_HOST, port=PCE_PORT, org_id=PCE_ORG_ID)
            pce.set_credentials(API_KEY, API_SECRET)

            logger.debug(f"Due to a condition in MCP, max results is set to {MCP_BUG_MAX_RESULTS}")
            # TODO: fix this in the future...
            if 'max_results' in arguments and arguments.get('max_results') > MCP_BUG_MAX_RESULTS:
                logger.debug(f"Setting max results to {MCP_BUG_MAX_RESULTS} from original value {arguments.get('max_results')}")
                arguments['max_results'] = MCP_BUG_MAX_RESULTS

            query = TrafficQuery.build(
                start_date=arguments['start_date'],
                end_date=arguments['end_date'],
                include_sources=arguments.get('include_sources', [[]]),
                exclude_sources=arguments.get('exclude_sources', []),
                include_destinations=arguments.get('include_destinations', [[]]),
                exclude_destinations=arguments.get('exclude_destinations', []),
                include_services=arguments.get('include_services', []),
                exclude_services=arguments.get('exclude_services', []),
                policy_decisions=arguments.get('policy_decisions', []),
                exclude_workloads_from_ip_list_query=arguments.get('exclude_workloads_from_ip_list_query', True),
                max_results=arguments.get('max_results', 10000),
                query_name=arguments.get('query_name', 'mcp-traffic-summary')
            )

            all_traffic = pce.get_traffic_flows_async(
                query_name=arguments.get('query_name', 'mcp-traffic-summary'),
                traffic_query=query
            )

            df = to_dataframe(all_traffic)
            summary = summarize_traffic(df)
            
            summary_lines = ""
            # Ensure the summary is a list of strings
            if isinstance(summary, list):
                # join list to be one string separated by newlines
                summary_lines = "\n".join(summary)
            else:
                summary_lines = str(summary)

            logger.debug(f"Summary data type: {type(summary_lines)}")
            logger.debug(f"Summary size: {len(summary_lines)}")

            return [types.TextContent(
                type="text",
                text=summary_lines
            )]
        except Exception as e:
            error_msg = f"Failed in PCE operation: {str(e)}"
            logger.error(error_msg, exc_info=True)
            return [types.TextContent(
                type="text",
                text=json.dumps({"error": error_msg})
            )]
    elif name == "get-rulesets":
        logger.debug("=" * 80)
        logger.debug("GET RULESETS CALLED")
        logger.debug(f"Arguments received: {json.dumps(arguments, indent=2)}")
        logger.debug(f"Name filter: {arguments.get('name')}")
        logger.debug(f"Enabled filter: {arguments.get('enabled')}")
        logger.debug("=" * 80)

        try:
            pce = PolicyComputeEngine(PCE_HOST, port=PCE_PORT, org_id=PCE_ORG_ID)
            pce.set_credentials(API_KEY, API_SECRET)

            # Prepare filter parameters
            params = {}
            if arguments.get('name'):
                params['name'] = arguments['name']
            if arguments.get('enabled') is not None:
                params['enabled'] = arguments['enabled']

            rulesets = pce.rule_sets.get_all()
            
            # Convert rulesets to serializable format
            ruleset_data = []
            for ruleset in rulesets:
                rules = []
                for rule in ruleset.rules:
                    rule_dict = {
                        'enabled': rule.enabled,
                        'description': rule.description,
                        'resolve_labels_as': str(rule.resolve_labels_as) if rule.resolve_labels_as else None,
                        'consumers': [str(consumer) for consumer in rule.consumers] if rule.consumers else [],
                        'providers': [str(provider) for provider in rule.providers] if rule.providers else [],
                        'ingress_services': [str(service) for service in rule.ingress_services] if rule.ingress_services else []
                    }
                    rules.append(rule_dict)

                ruleset_dict = {
                    'href': ruleset.href,
                    'name': ruleset.name,
                    'enabled': ruleset.enabled,
                    'description': ruleset.description,
                    'scopes': [str(scope) for scope in ruleset.scopes] if ruleset.scopes else [],
                    'rules': rules
                }
                ruleset_data.append(ruleset_dict)

            return [types.TextContent(
                type="text",
                text=json.dumps({
                    "rulesets": ruleset_data,
                    "total_count": len(ruleset_data)
                }, indent=2)
            )]

        except Exception as e:
            error_msg = f"Failed to get rulesets: {str(e)}"
            logger.error(error_msg, exc_info=True)
            return [types.TextContent(
                type="text",
                text=json.dumps({"error": error_msg})
            )]
    elif name == "get-iplists":
        logger.debug("=" * 80)
        logger.debug("GET IP LISTS CALLED")
        logger.debug(f"Arguments received: {json.dumps(arguments, indent=2)}")
        logger.debug(f"Name filter: {arguments.get('name')}")
        logger.debug(f"Description filter: {arguments.get('description')}")
        logger.debug(f"IP ranges filter: {arguments.get('ip_ranges', [])}")
        logger.debug("=" * 80)

        try:
            pce = PolicyComputeEngine(PCE_HOST, port=PCE_PORT, org_id=PCE_ORG_ID)
            pce.set_credentials(API_KEY, API_SECRET)

            # Prepare filter parameters
            params = {}
            if arguments.get('name'):
                params['name'] = arguments['name']
            if arguments.get('description'):
                params['description'] = arguments['description']

            params['max_results'] = 10000

            ip_lists = pce.ip_lists.get(params=params)
            
            # Convert IP lists to serializable format
            iplist_data = []
            for iplist in ip_lists:
                iplist_dict = {
                    'href': iplist.href,
                    'name': iplist.name,
                    'description': iplist.description,
                    'ip_ranges': [str(ip_range) for ip_range in iplist.ip_ranges] if iplist.ip_ranges else [],
                    'fqdns': iplist.fqdns if hasattr(iplist, 'fqdns') else [],
                    'created_at': str(iplist.created_at) if hasattr(iplist, 'created_at') else None,
                    'updated_at': str(iplist.updated_at) if hasattr(iplist, 'updated_at') else None,
                    'deleted_at': str(iplist.deleted_at) if hasattr(iplist, 'deleted_at') else None,
                    'created_by': str(iplist.created_by) if hasattr(iplist, 'created_by') else None,
                    'updated_by': str(iplist.updated_by) if hasattr(iplist, 'updated_by') else None,
                    'deleted_by': str(iplist.deleted_by) if hasattr(iplist, 'deleted_by') else None
                }
                
                # Apply IP ranges filter if provided
                if arguments.get('ip_ranges'):
                    if any(ip_range in iplist_dict['ip_ranges'] for ip_range in arguments['ip_ranges']):
                        iplist_data.append(iplist_dict)
                else:
                    iplist_data.append(iplist_dict)

            logger.debug(f"Found {len(iplist_data)} IP lists")

            return [types.TextContent(
                type="text",
                text=json.dumps({
                    "ip_lists": iplist_data,
                    "total_count": len(iplist_data)
                }, indent=2)
            )]

        except Exception as e:
            error_msg = f"Failed to get IP lists: {str(e)}"
            logger.error(error_msg, exc_info=True)
            return [types.TextContent(
                type="text",
                text=json.dumps({"error": error_msg})
            )]
    elif name == "get-events":
        logger.debug("=" * 80)
        logger.debug("GET EVENTS CALLED")
        logger.debug(f"Arguments received: {json.dumps(arguments, indent=2)}")
        logger.debug("=" * 80)

        try:
            pce = PolicyComputeEngine(PCE_HOST, port=PCE_PORT, org_id=PCE_ORG_ID)
            pce.set_credentials(API_KEY, API_SECRET)

            # Prepare filter parameters
            params = {}
            if arguments.get('event_type'):
                params['event_type'] = arguments['event_type']
            if arguments.get('severity'):
                params['severity'] = arguments['severity']
            if arguments.get('status'):
                params['status'] = arguments['status']
            if arguments.get('max_results'):
                params['max_results'] = arguments['max_results']

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
    elif name == "create-ruleset":
        logger.debug("=" * 80)
        logger.debug("CREATE RULESET CALLED")
        logger.debug(f"Arguments received: {json.dumps(arguments, indent=2)}")
        logger.debug("=" * 80)

        try:
            logger.debug("Initializing PCE connection...")
            pce = PolicyComputeEngine(PCE_HOST, port=PCE_PORT, org_id=PCE_ORG_ID)
            pce.set_credentials(API_KEY, API_SECRET)
            
            # populate the label maps
            label_href_map = {}
            value_href_map = {}
            for l in pce.labels.get(params={'max_results': 10000}):
                label_href_map[l.href] = {"key": l.key, "value": l.value}
                value_href_map["{}={}".format(l.key, l.value)] = l.href

            # Check if ruleset already exists
            logger.debug(f"Checking if ruleset '{arguments['name']}' already exists...")
            existing_rulesets = pce.rule_sets.get(params={"name": arguments["name"]})
            if existing_rulesets:
                error_msg = f"Ruleset with name '{arguments['name']}' already exists"
                logger.error(error_msg)
                return [types.TextContent(
                    type="text",
                    text=json.dumps({
                        "error": error_msg,
                        "existing_ruleset": {
                            "href": existing_rulesets[0].href,
                            "name": existing_rulesets[0].name
                        }
                    }, indent=2)
                )]

            # Create the ruleset
            logger.debug(f"Instantiating ruleset object: {arguments['name']}")
            ruleset = RuleSet(
                name=arguments["name"],
                description=arguments.get("description", "")
            )

            # Handle scopes
            label_sets = []
            if arguments.get("scopes"):
                logger.debug(f"Processing scopes: {json.dumps(arguments['scopes'], indent=2)}")
                
                for scope in arguments["scopes"]:
                    label_set = LabelSet(labels=[])
                    for label in scope:
                        logger.debug(f"Processing label: {label}")
                        if isinstance(label, dict) and "href" in label:
                            # Handle direct href references
                            logger.debug(f"Found label with href: {label['href']}")
                            append_label = pce.labels.get_by_reference(label["href"])
                            logger.debug(f"Appending label: {append_label}")
                            label_set.labels.append(append_label)
                        elif isinstance(label, str):
                            # Handle string references (either href or label value)
                            if label in value_href_map:
                                logger.debug(f"Found label value: {value_href_map[label]}")
                                append_label = pce.labels.get_by_reference(value_href_map[label])
                            else:
                                logger.debug(f"Assuming direct href: {label}")
                                append_label = pce.labels.get_by_reference(label)
                            logger.debug(f"Appending label: {append_label}")
                            label_set.labels.append(append_label)
                        else:
                            logger.warning(f"Unexpected label format: {label}")
                            continue
                            
                    label_sets.append(label_set)
                    logger.debug(f"Label set: {label_set}")
            else:
                # If no scopes provided, create a default scope with all workloads
                logger.debug("No scopes provided, creating default scope with all workloads")
                label_sets = [LabelSet(labels=[])]

            logger.debug(f"Final ruleset scopes count: {len(label_sets)}")
            ruleset.scopes = label_sets

            # Create the ruleset in PCE
            logger.debug("Creating ruleset in PCE...")
            logger.debug(f"Ruleset object scopes: {[str(ls.labels) for ls in ruleset.scopes]}")
            ruleset = pce.rule_sets.create(ruleset)
            logger.debug(f"Ruleset created with href: {ruleset.href}")

            # Create rules if provided
            created_rules = []
            if arguments.get("rules"):
                logger.debug(f"Processing rules: {json.dumps(arguments['rules'], indent=2)}")
                
                for rule_def in arguments["rules"]:
                    logger.debug(f"Processing rule: {json.dumps(rule_def, indent=2)}")
                    
                    # Process providers
                    providers = []
                    for provider in rule_def["providers"]:
                        if provider == "ams":
                            providers.append(AMS)
                        elif provider.startswith("iplist:"):
                            # Extract IP list name and look it up
                            ip_list_name = provider.split(":", 1)[1]
                            logger.debug(f"Looking up IP list: {ip_list_name}")
                            ip_lists = pce.ip_lists.get(params={"name": ip_list_name})
                            if ip_lists:
                                providers.append(ip_lists[0])
                            else:
                                logger.error(f"IP list not found: {ip_list_name}")
                                return [types.TextContent(
                                    type="text",
                                    text=json.dumps({"error": f"IP list not found: {ip_list_name}"})
                                )]
                        elif provider in value_href_map:
                            providers.append(pce.labels.get_by_reference(value_href_map[provider]))
                        else:
                            providers.append(pce.labels.get_by_reference(provider))
                    
                    # Process consumers
                    consumers = []
                    for consumer in rule_def["consumers"]:
                        if consumer == "ams":
                            consumers.append(AMS)
                        elif consumer.startswith("iplist:"):
                            # Extract IP list name and look it up
                            ip_list_name = consumer.split(":", 1)[1]
                            logger.debug(f"Looking up IP list: {ip_list_name}")
                            ip_lists = pce.ip_lists.get(params={"name": ip_list_name})
                            if ip_lists:
                                consumers.append(ip_lists[0])
                            else:
                                logger.error(f"IP list not found: {ip_list_name}")
                                return [types.TextContent(
                                    type="text",
                                    text=json.dumps({"error": f"IP list not found: {ip_list_name}"})
                                )]
                        elif consumer in value_href_map:
                            consumers.append(pce.labels.get_by_reference(value_href_map[consumer]))
                        else:
                            consumers.append(pce.labels.get_by_reference(consumer))
                    
                    # Create ingress services
                    ingress_services = []
                    for svc in rule_def["ingress_services"]:
                        service_port = ServicePort(
                            port=svc["port"],
                            proto=svc["proto"]
                        )
                        ingress_services.append(service_port)
                    
                    # Build and create the rule
                    rule = Rule.build(
                        providers=providers,
                        consumers=consumers,
                        ingress_services=ingress_services,
                        unscoped_consumers=rule_def.get("unscoped_consumers", False)
                    )
                    
                    created_rule = pce.rules.create(rule, parent=ruleset)
                    created_rules.append({
                        "href": created_rule.href,
                        "providers": [str(p) for p in providers],
                        "consumers": [str(c) for c in consumers],
                        "services": [f"{s.port}/{s.proto}" for s in ingress_services],
                        "unscoped_consumers": rule_def.get("unscoped_consumers", False)
                    })
            
            # Update the response to include rules
            return [types.TextContent(
                type="text",
                text=json.dumps({
                    "ruleset": {
                        "href": ruleset.href,
                        "name": ruleset.name,
                        "description": ruleset.description,
                        "rules": created_rules
                    }
                }, indent=2)
            )]

        except Exception as e:
            error_msg = f"Failed to create ruleset: {str(e)}"
            logger.error(error_msg, exc_info=True)
            return [types.TextContent(
                type="text",
                text=json.dumps({"error": error_msg})
            )]
    elif name == "delete-ruleset":
        logger.debug("=" * 80)
        logger.debug("DELETE RULESET CALLED")
        logger.debug(f"Arguments received: {json.dumps(arguments, indent=2)}")
        logger.debug("=" * 80)

        # add implementation here for delete-ruleset
        try:
            pce = PolicyComputeEngine(PCE_HOST, port=PCE_PORT, org_id=PCE_ORG_ID)
            pce.set_credentials(API_KEY, API_SECRET)
            # check if href or name is provided, for href, delete, for name, get and delete 
            if "href" in arguments:
                pce.rule_sets.delete(arguments["href"])
            elif "name" in arguments:
                rulesets = pce.rule_sets.get(params={"name": arguments["name"]})
                if rulesets:
                    pce.rule_sets.delete(rulesets[0].href)
                    return [types.TextContent(type="text", text=json.dumps({"success": "Ruleset deleted successfully"}))]
                else:
                    return [types.TextContent(type="text", text=json.dumps({"error": "Ruleset not found"}))]
            else:
                return [types.TextContent(type="text", text=json.dumps({"error": "Either href or name must be provided"}))]
        except Exception as e:
            error_msg = f"Failed to delete ruleset: {str(e)}"
            logger.error(error_msg, exc_info=True)
            return [types.TextContent(type="text", text=json.dumps({"error": error_msg}))]
    elif name == "get-services":
        logger.debug("=" * 80)
        logger.debug("GET SERVICES CALLED")
        logger.debug(f"Arguments received: {json.dumps(arguments, indent=2)}")
        logger.debug("=" * 80)

        try:
            logger.debug("Initializing PCE connection...")
            pce = PolicyComputeEngine(PCE_HOST, port=PCE_PORT, org_id=PCE_ORG_ID)
            pce.set_credentials(API_KEY, API_SECRET)

            # Prepare filter parameters
            params = {}
            if arguments.get('name'):
                params['name'] = arguments['name']
            if arguments.get('description'):
                params['description'] = arguments['description']
            if arguments.get('port'):
                params['port'] = arguments['port']
            if arguments.get('proto'):
                params['proto'] = arguments['proto']
            if arguments.get('process_name'):
                params['process_name'] = arguments['process_name']
            
            logger.debug(f"Querying services with params: {json.dumps(params, indent=2)}")
            services = pce.services.get(params=params)
            logger.debug(f"Found {len(services)} services")
            
            # Convert services to serializable format
            service_data = []
            for service in services:
                logger.debug(f"Processing service: {service.name} ({service.href})")
                service_dict = {
                    'href': service.href,
                    'name': service.name,
                    'description': service.description if hasattr(service, 'description') else None,
                    'process_name': service.process_name if hasattr(service, 'process_name') else None,
                    'service_ports': []
                }
                
                # Add service ports - check both possible attribute names
                ports = []
                if hasattr(service, 'service_ports'):
                    # logger.debug(f"Found service_ports attribute for {service.name}")
                    ports = service.service_ports or []  # Handle None case
                elif hasattr(service, 'ports'):
                    # logger.debug(f"Found ports attribute for {service.name}")
                    ports = service.ports or []  # Handle None case
                
                logger.debug(f"Processing {len(ports)} ports for service {service.name}")
                for port in ports:
                    try:
                        port_dict = {
                            'port': port.port,
                            'proto': port.proto
                        }
                        # Only add to_port if it exists and is different from port
                        if hasattr(port, 'to_port') and port.to_port is not None:
                            port_dict['to_port'] = port.to_port
                        service_dict['service_ports'].append(port_dict)
                        logger.debug(f"Added port {port.port}/{port.proto} to service {service.name}")
                    except AttributeError as e:
                        logger.warning(f"Error processing port {port} for service {service.name}: {e}")
                        continue

                # Add windows services if present
                if hasattr(service, 'windows_services'):
                    logger.debug(f"Found windows_services for {service.name}")
                    service_dict['windows_services'] = service.windows_services

                service_data.append(service_dict)
                logger.debug(f"Completed processing service: {service.name}")

            logger.debug(f"Service data: {json.dumps(service_data, indent=2)}")
            logger.debug(f"Successfully processed {len(service_data)} services")
            return [types.TextContent(
                type="text",
                text=json.dumps({
                    "services": service_data,
                    "total_count": len(service_data)
                }, indent=2)
            )]

        except Exception as e:
            error_msg = f"Failed to get services: {str(e)}"
            logger.error(error_msg, exc_info=True)
            return [types.TextContent(
                type="text",
                text=json.dumps({"error": error_msg})
            )]
    elif name == "update-label":
        logger.debug("Initializing PCE connection")
        try:
            pce = PolicyComputeEngine(PCE_HOST, port=PCE_PORT, org_id=PCE_ORG_ID)
            pce.set_credentials(API_KEY, API_SECRET)
            
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
    elif name == "create-iplist":
        logger.debug("=" * 80)
        logger.debug("CREATE IP LIST CALLED")
        logger.debug(f"Arguments received: {json.dumps(arguments, indent=2)}")
        logger.debug("=" * 80)

        try:
            logger.debug("Initializing PCE connection...")
            pce = PolicyComputeEngine(PCE_HOST, port=PCE_PORT, org_id=PCE_ORG_ID)
            pce.set_credentials(API_KEY, API_SECRET)

            # Check if IP List already exists
            logger.debug(f"Checking if IP List '{arguments['name']}' already exists...")
            existing_iplists = pce.ip_lists.get(params={"name": arguments["name"]})
            if existing_iplists:
                error_msg = f"IP List with name '{arguments['name']}' already exists"
                logger.error(error_msg)
                return [types.TextContent(
                    type="text",
                    text=json.dumps({
                        "error": error_msg,
                        "existing_iplist": {
                            "href": existing_iplists[0].href,
                            "name": existing_iplists[0].name
                        }
                    }, indent=2)
                )]

            # Create IP ranges
            ip_ranges = []
            for range_def in arguments["ip_ranges"]:
                ip_range = {
                    "from_ip": range_def["from_ip"],
                    "exclusion": range_def.get("exclusion", False)
                }
                
                # Add optional fields if present
                if "to_ip" in range_def:
                    ip_range["to_ip"] = range_def["to_ip"]
                if "description" in range_def:
                    ip_range["description"] = range_def["description"]
                
                ip_ranges.append(ip_range)

            # Create the IP List object
            iplist_data = {
                "name": arguments["name"],
                "ip_ranges": ip_ranges
            }

            # Add optional fields if present
            if "description" in arguments:
                iplist_data["description"] = arguments["description"]
            if "fqdn" in arguments:
                iplist_data["fqdn"] = arguments["fqdn"]

            logger.debug(f"Creating IP List with data: {json.dumps(iplist_data, indent=2)}")
            iplist = pce.ip_lists.create(iplist_data)
            
            # Format response
            response_data = {
                "href": iplist.href,
                "name": iplist.name,
                "description": getattr(iplist, "description", None),
                "ip_ranges": [
                    {
                        "from_ip": r.from_ip,
                        "to_ip": getattr(r, "to_ip", None),
                        "description": getattr(r, "description", None),
                        "exclusion": getattr(r, "exclusion", False)
                    } for r in iplist.ip_ranges
                ],
                "fqdn": getattr(iplist, "fqdn", None)
            }

            return [types.TextContent(
                type="text",
                text=json.dumps(response_data, indent=2)
            )]

        except Exception as e:
            error_msg = f"Failed to create IP List: {str(e)}"
            logger.error(error_msg, exc_info=True)
            return [types.TextContent(
                type="text",
                text=json.dumps({"error": error_msg}, indent=2)
            )]
    elif name == "update-iplist":
        logger.debug("=" * 80)
        logger.debug("UPDATE IP LIST CALLED")
        logger.debug(f"Arguments received: {json.dumps(arguments, indent=2)}")
        logger.debug("=" * 80)

        try:
            logger.debug("Initializing PCE connection...")
            pce = PolicyComputeEngine(PCE_HOST, port=PCE_PORT, org_id=PCE_ORG_ID)
            pce.set_credentials(API_KEY, API_SECRET)

            # Find the IP List
            iplist = None
            if "href" in arguments:
                logger.debug(f"Looking up IP List by href: {arguments['href']}")
                try:
                    iplist = pce.ip_lists.get_by_reference(arguments['href'])
                except Exception as e:
                    logger.error(f"Failed to find IP List by href: {str(e)}")
                    return [types.TextContent(
                        type="text",
                        text=json.dumps({"error": f"IP List not found: {str(e)}"}, indent=2)
                    )]
            else:
                logger.debug(f"Looking up IP List by name: {arguments['name']}")
                iplists = pce.ip_lists.get(params={"name": arguments["name"]})
                if iplists:
                    iplist = iplists[0]
                else:
                    return [types.TextContent(
                        type="text",
                        text=json.dumps({"error": f"IP List with name '{arguments['name']}' not found"}, indent=2)
                    )]

            logger.debug(f"Found IP List: {iplist.href}, {iplist.name}")

            # Prepare update data
            update_data = {}
            if "description" in arguments:
                update_data["description"] = arguments["description"]
            if "fqdn" in arguments:
                update_data["fqdn"] = arguments["fqdn"]
            if "ip_ranges" in arguments:
                ip_ranges = []
                for range_def in arguments["ip_ranges"]:
                    ip_range = {
                        "from_ip": range_def["from_ip"],
                        "exclusion": range_def.get("exclusion", False)
                    }
                    if "to_ip" in range_def:
                        ip_range["to_ip"] = range_def["to_ip"]
                    if "description" in range_def:
                        ip_range["description"] = range_def["description"]
                    ip_ranges.append(ip_range)
                update_data["ip_ranges"] = ip_ranges

            logger.debug(f"Updating IP List with data: {json.dumps(update_data, indent=2)}")
            
            # Update the IP List
            pce.ip_lists.update(iplist.href, update_data)
            
            # Fetch the updated IP List to get the current state
            updated_iplist = pce.ip_lists.get_by_reference(iplist.href)
            
            # Format response
            response_data = {
                "href": updated_iplist.href,
                "name": updated_iplist.name,
                "description": getattr(updated_iplist, "description", None),
                "ip_ranges": []
            }
            
            # Safely add IP ranges if they exist
            if hasattr(updated_iplist, 'ip_ranges') and updated_iplist.ip_ranges:
                for r in updated_iplist.ip_ranges:
                    range_data = {"from_ip": r.from_ip}
                    if hasattr(r, "to_ip"):
                        range_data["to_ip"] = r.to_ip
                    if hasattr(r, "description"):
                        range_data["description"] = r.description
                    if hasattr(r, "exclusion"):
                        range_data["exclusion"] = r.exclusion
                    response_data["ip_ranges"].append(range_data)
            
            # Add FQDN if it exists
            if hasattr(updated_iplist, "fqdn"):
                response_data["fqdn"] = updated_iplist.fqdn

            return [types.TextContent(
                type="text",
                text=json.dumps(response_data, indent=2)
            )]

        except Exception as e:
            error_msg = f"Failed to update IP List: {str(e)}"
            logger.error(error_msg, exc_info=True)
            return [types.TextContent(
                type="text",
                text=json.dumps({"error": error_msg}, indent=2)
            )]
    elif name == "delete-iplist":
        logger.debug("=" * 80)
        logger.debug("DELETE IP LIST CALLED")
        logger.debug(f"Arguments received: {json.dumps(arguments, indent=2)}")
        logger.debug("=" * 80)

        try:
            logger.debug("Initializing PCE connection...")
            pce = PolicyComputeEngine(PCE_HOST, port=PCE_PORT, org_id=PCE_ORG_ID)
            pce.set_credentials(API_KEY, API_SECRET)

            # Find the IP List
            iplist = None
            if "href" in arguments:
                logger.debug(f"Looking up IP List by href: {arguments['href']}")
                try:
                    iplist = pce.ip_lists.get_by_reference(arguments['href'])
                except Exception as e:
                    logger.error(f"Failed to find IP List by href: {str(e)}")
                    return [types.TextContent(
                        type="text",
                        text=json.dumps({"error": f"IP List not found: {str(e)}"}, indent=2)
                    )]
            else:
                logger.debug(f"Looking up IP List by name: {arguments['name']}")
                iplists = pce.ip_lists.get(params={"name": arguments["name"]})
                if iplists:
                    iplist = iplists[0]
                else:
                    return [types.TextContent(
                        type="text",
                        text=json.dumps({"error": f"IP List with name '{arguments['name']}' not found"}, indent=2)
                    )]

            # Delete the IP List
            logger.debug(f"Deleting IP List: {iplist.href}")
            pce.ip_lists.delete(iplist.href)

            return [types.TextContent(
                type="text",
                text=json.dumps({
                    "message": f"Successfully deleted IP List: {iplist.name}",
                    "href": iplist.href
                }, indent=2)
            )]

        except Exception as e:
            error_msg = f"Failed to delete IP List: {str(e)}"
            logger.error(error_msg, exc_info=True)
            return [types.TextContent(
                type="text",
                text=json.dumps({"error": error_msg}, indent=2)
            )]
    elif name == "update-ruleset":
        logger.debug("=" * 80)
        logger.debug("UPDATE RULESET CALLED")
        logger.debug(f"Arguments received: {json.dumps(arguments, indent=2)}")
        logger.debug("=" * 80)

        try:
            logger.debug("Initializing PCE connection...")
            pce = PolicyComputeEngine(PCE_HOST, port=PCE_PORT, org_id=PCE_ORG_ID)
            pce.set_credentials(API_KEY, API_SECRET)

            # Find the ruleset
            ruleset = None
            if "href" in arguments:
                logger.debug(f"Looking up ruleset by href: {arguments['href']}")
                try:
                    ruleset = pce.rule_sets.get_by_reference(arguments['href'])
                except Exception as e:
                    logger.error(f"Failed to find ruleset by href: {str(e)}")
                    return [types.TextContent(
                        type="text",
                        text=json.dumps({"error": f"Ruleset not found: {str(e)}"}, indent=2)
                    )]
            else:
                logger.debug(f"Looking up ruleset by name: {arguments['name']}")
                rulesets = pce.rule_sets.get(params={"name": arguments["name"]})
                if rulesets:
                    ruleset = rulesets[0]
                else:
                    return [types.TextContent(
                        type="text",
                        text=json.dumps({"error": f"Ruleset with name '{arguments['name']}' not found"}, indent=2)
                    )]

            # Prepare update data
            update_data = {}
            if "description" in arguments:
                update_data["description"] = arguments["description"]
            if "enabled" in arguments:
                update_data["enabled"] = arguments["enabled"]

            # Handle scopes if provided
            if "scopes" in arguments:
                logger.debug(f"Processing scopes: {json.dumps(arguments['scopes'], indent=2)}")
                label_sets = []
                
                for scope in arguments["scopes"]:
                    label_set = LabelSet(labels=[])
                    for label in scope:
                        logger.debug(f"Processing label: {label}")
                        if isinstance(label, dict) and "href" in label:
                            # Handle direct href references
                            logger.debug(f"Found label with href: {label['href']}")
                            append_label = pce.labels.get_by_reference(label["href"])
                            logger.debug(f"Appending label: {append_label}")
                            label_set.labels.append(append_label)
                        elif isinstance(label, str):
                            # Handle string references (either href or label value)
                            if "=" in label:  # key=value format
                                key, value = label.split("=", 1)
                                labels = pce.labels.get(params={"key": key, "value": value})
                                if labels:
                                    append_label = labels[0]
                                    logger.debug(f"Appending label: {append_label}")
                                    label_set.labels.append(append_label)
                            else:  # direct href
                                append_label = pce.labels.get_by_reference(label)
                                logger.debug(f"Appending label: {append_label}")
                                label_set.labels.append(append_label)
                    
                    label_sets.append(label_set)
                    logger.debug(f"Label set: {label_set}")
                
                update_data["scopes"] = label_sets

            # Update the ruleset
            logger.debug(f"Updating ruleset with data: {update_data}")
            updated_ruleset = pce.rule_sets.update(ruleset.href, update_data)
            
            # Format response
            response_data = {
                "href": updated_ruleset.href,
                "name": updated_ruleset.name,
                "description": getattr(updated_ruleset, "description", None),
                "enabled": getattr(updated_ruleset, "enabled", None),
                "scopes": []
            }

            # Add scopes if they exist
            if hasattr(updated_ruleset, "scopes"):
                for scope in updated_ruleset.scopes:
                    scope_labels = []
                    for label in scope.labels:
                        scope_labels.append({
                            "href": label.href,
                            "key": label.key,
                            "value": label.value
                        })
                    response_data["scopes"].append(scope_labels)

            return [types.TextContent(
                type="text",
                text=json.dumps(response_data, indent=2)
            )]

        except Exception as e:
            error_msg = f"Failed to update ruleset: {str(e)}"
            logger.error(error_msg, exc_info=True)
            return [types.TextContent(
                type="text",
                text=json.dumps({"error": error_msg}, indent=2)
            )]

    elif name == "delete-ruleset":
        logger.debug("=" * 80)
        logger.debug("DELETE RULESET CALLED")
        logger.debug(f"Arguments received: {json.dumps(arguments, indent=2)}")
        logger.debug("=" * 80)

        try:
            logger.debug("Initializing PCE connection...")
            pce = PolicyComputeEngine(PCE_HOST, port=PCE_PORT, org_id=PCE_ORG_ID)
            pce.set_credentials(API_KEY, API_SECRET)

            # Find the ruleset
            ruleset = None
            if "href" in arguments:
                logger.debug(f"Looking up ruleset by href: {arguments['href']}")
                try:
                    ruleset = pce.rule_sets.get_by_reference(arguments['href'])
                except Exception as e:
                    logger.error(f"Failed to find ruleset by href: {str(e)}")
                    return [types.TextContent(
                        type="text",
                        text=json.dumps({"error": f"Ruleset not found: {str(e)}"}, indent=2)
                    )]
            else:
                logger.debug(f"Looking up ruleset by name: {arguments['name']}")
                rulesets = pce.rule_sets.get(params={"name": arguments["name"]})
                if rulesets:
                    ruleset = rulesets[0]
                else:
                    return [types.TextContent(
                        type="text",
                        text=json.dumps({"error": f"Ruleset with name '{arguments['name']}' not found"}, indent=2)
                    )]

            # Delete the ruleset
            logger.debug(f"Deleting ruleset: {ruleset.href}")
            pce.rule_sets.delete(ruleset.href)

            return [types.TextContent(
                type="text",
                text=json.dumps({
                    "message": f"Successfully deleted ruleset: {ruleset.name}",
                    "href": ruleset.href
                }, indent=2)
            )]

        except Exception as e:
            error_msg = f"Failed to delete ruleset: {str(e)}"
            logger.error(error_msg, exc_info=True)
            return [types.TextContent(
                type="text",
                text=json.dumps({"error": error_msg}, indent=2)
            )]

def to_dataframe(flows):
    pce = PolicyComputeEngine(PCE_HOST, port=PCE_PORT, org_id=PCE_ORG_ID)
    pce.set_credentials(API_KEY, API_SECRET)

    label_href_map = {}
    value_href_map = {}
    for l in pce.labels.get(params={'max_results': 10000}):
        label_href_map[l.href] = {"key": l.key, "value": l.value}
        value_href_map["{}={}".format(l.key, l.value)] = l.href

    if not flows:
        logger.warning("Warning: Empty flows list received.")
        return pd.DataFrame()

    series_array = []
    for flow in flows:
        try:
            f = {
                'src_ip': flow.src.ip,
                    'src_hostname': flow.src.workload.name if flow.src.workload is not None else None,
                    'dst_ip': flow.dst.ip,
                    'dst_hostname': flow.dst.workload.name if flow.dst.workload is not None else None,
                    'proto': flow.service.proto,
                    'port': flow.service.port,
                    'process_name': flow.service.process_name,
                    'service_name': flow.service.service_name,
                    'policy_decision': flow.policy_decision,
                    'flow_direction': flow.flow_direction,
                    'num_connections': flow.num_connections,
                    'first_detected': flow.timestamp_range.first_detected,
                    'last_detected': flow.timestamp_range.last_detected,
            }

            # Add src and dst app and env labels
            if flow.src.workload:
                for l in flow.src.workload.labels:
                    if l.href in label_href_map:
                        key = label_href_map[l.href]['key']
                        value = label_href_map[l.href]['value']
                        f[f'src_{key}'] = value

            if flow.dst.workload:
                for l in flow.dst.workload.labels:
                    if l.href in label_href_map:
                        key = label_href_map[l.href]['key']
                        value = label_href_map[l.href]['value']
                        f[f'dst_{key}'] = value

                series_array.append(f)
        except AttributeError as e:
            logger.debug(f"Error processing flow: {e}")
            logger.debug(f"Flow object: {flow}")

    df = pd.DataFrame(series_array)
    return df
  
def summarize_traffic(df):
    logger.debug(f"Summarizing traffic with dataframe: {df}")
    
    # Define all possible group columns
    potential_columns = ['src_app', 'src_env', 'dst_app', 'dst_env', 'proto', 'port']
    
    # Filter to only use columns that exist in the DataFrame
    group_columns = [col for col in potential_columns if col in df.columns]
    
    if not group_columns:
        logger.warning("No grouping columns found in DataFrame")
        return "No traffic data available for summarization"

    if df.empty:
        logger.warning("Empty DataFrame received")
        return "No traffic data available for summarization"

    logger.debug(f"Using group columns: {group_columns}")
    logger.debug(f"DataFrame shape before grouping: {df.shape}")
    logger.debug(f"DataFrame columns: {df.columns.tolist()}")
    logger.debug(f"First few rows of DataFrame:\n{df.head()}")

    # Group by available columns
    summary = df.groupby(group_columns)['num_connections'].sum().reset_index()
        
    logger.debug(f"Summary shape after grouping: {summary.shape}")
    logger.debug(f"Summary columns: {summary.columns.tolist()}")
    logger.debug(f"First few rows of summary:\n{summary.head()}")

    # Sort by number of connections in descending order
    summary = summary.sort_values('num_connections', ascending=False)

    # Convert to a more readable format
    summary_list = []
    for _, row in summary.iterrows():
        # Build source and destination info based on available columns
        src_info = []
        if 'src_app' in row:
            src_info.append(row['src_app'])
        if 'src_env' in row:
            src_info.append(f"({row['src_env']})")
        src_str = " ".join(src_info) if src_info else "Unknown Source"

        dst_info = []
        if 'dst_app' in row:
            dst_info.append(row['dst_app'])
        if 'dst_env' in row:
            dst_info.append(f"({row['dst_env']})")
        dst_str = " ".join(dst_info) if dst_info else "Unknown Destination"

        if src_str != dst_str:
            port_info = f"port {row['port']}" if 'port' in row else "unknown port"
            proto_info = f"proto {row['proto']}" if 'proto' in row else ""
            summary_list.append(
                f"From {src_str} to {dst_str} on {port_info} {proto_info}: {row['num_connections']} connections"
            )
    
    if not summary_list:
        return "No traffic patterns to summarize"
        
    return "\n".join(summary_list)

async def main():
    # Run the server using stdin/stdout streams
    logger.debug("Starting server")
    async with mcp.server.stdio.stdio_server() as (read_stream, write_stream):
        await server.run(
            read_stream,
            write_stream,
            InitializationOptions(
                server_name="illumio-mcp",
                server_version="0.1.0",
                capabilities=server.get_capabilities(
                    notification_options=NotificationOptions(),
                    experimental_capabilities={},
                ),
            ),
        )

class ServicePortEncoder(JSONEncoder):
    def default(self, obj):
        if isinstance(obj, ServicePort):
            return {
                'port': obj.port,
                'protocol': obj.protocol
            }
        return super().default(obj)