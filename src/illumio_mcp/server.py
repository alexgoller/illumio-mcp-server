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
from illumio.util.jsonutils import Reference
from illumio.explorer.trafficanalysis import TrafficQueryFilter
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
            name="get-workloads",
            description="Get workloads from the PCE with optional filtering",
            inputSchema={
                "type": "object",
                "properties": {
                    "name": {"type": "string", "description": "Filter by workload name (supports partial matches)"},
                    "hostname": {"type": "string", "description": "Filter by hostname (supports partial matches)"},
                    "ip_address": {"type": "string", "description": "Filter by IP address (supports partial matches)"},
                    "description": {"type": "string", "description": "Filter by description (supports partial matches)"},
                    "managed": {"type": "boolean", "description": "Filter managed (true) or unmanaged (false) workloads"},
                    "online": {"type": "boolean", "description": "Filter online (true) or offline (false) workloads"},
                    "enforcement_mode": {
                        "type": "string",
                        "enum": ["visibility_only", "full", "idle", "selective"],
                        "description": "Filter by enforcement mode"
                    },
                    "labels": {"type": "string", "description": "JSON-encoded list of label URIs to filter by"},
                    "max_results": {"type": "integer", "description": "Maximum number of workloads to return (default 10000)"},
                },
            },
        ),
        types.Tool(
            name="update-workload",
            description="Update a workload in the PCE. Identify by href (preferred) or name. Provide only fields you want to change.",
            inputSchema={
                "type": "object",
                "properties": {
                    "href": {"type": "string", "description": "Workload href (e.g., /orgs/1/workloads/xxxx). Preferred identifier."},
                    "name": {"type": "string", "description": "Workload name to find (alternative to href). If updating, this finds the workload."},
                    "new_name": {"type": "string", "description": "New name for the workload"},
                    "description": {"type": "string", "description": "New description for the workload"},
                    "hostname": {"type": "string", "description": "New hostname for the workload"},
                    "enforcement_mode": {
                        "type": "string",
                        "enum": ["visibility_only", "full", "idle", "selective"],
                        "description": "Enforcement mode to set"
                    },
                    "ip_addresses": {"type": "array", "items": {"type": "string"}, "description": "New IP addresses (replaces existing interfaces)"},
                    "labels": {
                        "type": "array",
                        "items": {"type": "object", "properties": {"key": {"type": "string"}, "value": {"type": "string"}}},
                        "description": "Labels to assign (replaces existing labels). Each item has 'key' and 'value'."
                    },
                },
            }
        ),
        types.Tool(
            name="get-labels",
            description="Get labels from the PCE with optional filtering",
            inputSchema={
                "type": "object",
                "properties": {
                    "key": {"type": "string", "description": "Filter by label key/type (e.g., 'role', 'app', 'env', 'loc')"},
                    "value": {"type": "string", "description": "Filter by label value (supports partial matches)"},
                    "max_results": {"type": "integer", "description": "Maximum number of labels to return"},
                    "include_deleted": {"type": "boolean", "description": "Include deleted labels"},
                    "usage": {"type": "boolean", "description": "Include label usage flags"},
                },
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
                               {"type": "object", "properties": {"key": {"type": "string"}, "value": {"type": "string"}}}
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
            description="Delete a workload from the PCE. Identify by href (preferred) or name.",
            inputSchema={
                "type": "object",
                "properties": {
                    "href": {"type": "string", "description": "Workload href (e.g., /orgs/1/workloads/xxxx)"},
                    "name": {"type": "string", "description": "Workload name (alternative to href)"},
                },
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
            description="Get rulesets from the PCE with optional filtering",
            inputSchema={
                "type": "object",
                "properties": {
                    "name": {"type": "string", "description": "Filter rulesets by name (supports partial matches)"},
                    "description": {"type": "string", "description": "Filter rulesets by description (supports partial matches)"},
                    "enabled": {"type": "boolean", "description": "Filter by enabled/disabled status"},
                    "labels": {"type": "string", "description": "JSON-encoded list of label URIs to filter by scope"},
                    "max_results": {"type": "integer", "description": "Maximum number of rulesets to return"},
                }
            }
        ),
        types.Tool(
            name="get-iplists",
            description="Get IP lists from the PCE with optional filtering",
            inputSchema={
                "type": "object",
                "properties": {
                    "name": {"type": "string", "description": "Filter IP lists by name (supports partial matches)"},
                    "description": {"type": "string", "description": "Filter by description (supports partial matches)"},
                    "fqdn": {"type": "string", "description": "Filter by FQDN (supports partial matches)"},
                    "ip_address": {"type": "string", "description": "Filter by IP address (supports partial matches)"},
                    "max_results": {"type": "integer", "description": "Maximum number of IP lists to return"},
                }
            }
        ),
        types.Tool(
            name="get-events",
            description="Get events from the PCE with optional filtering",
            inputSchema={
                "type": "object",
                "properties": {
                    "event_type": {"type": "string", "description": "Filter by event type (e.g., 'system_task.expire_service_account_api_keys')"},
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
                    "created_by": {"type": "string", "description": "Filter by creator (user, agent, or system)"},
                    "timestamp_gte": {"type": "string", "description": "Earliest event timestamp (RFC 3339 format)"},
                    "timestamp_lte": {"type": "string", "description": "Latest event timestamp (RFC 3339 format)"},
                    "max_results": {"type": "integer", "description": "Maximum number of events to return", "default": 100},
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
                                },
                                "rule_type": {
                                    "type": "string",
                                    "enum": ["allow", "deny", "override_deny"],
                                    "description": "Type of rule: 'allow' (default), 'deny' to block traffic, or 'override_deny' to override a deny rule",
                                    "default": "allow"
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
            name="create-deny-rule",
            description="Create a deny rule in an existing ruleset. Deny rules block specific traffic. They are created inside rulesets just like allow rules but with rule_type 'deny'. Override deny rules allow traffic that would otherwise be denied by a deny rule.",
            inputSchema={
                "type": "object",
                "properties": {
                    "ruleset_href": {
                        "type": "string",
                        "description": "Href of the ruleset to add the deny rule to (e.g., /orgs/1/sec_policy/draft/rule_sets/123)"
                    },
                    "ruleset_name": {
                        "type": "string",
                        "description": "Name of the ruleset to add the deny rule to (alternative to ruleset_href)"
                    },
                    "providers": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": "Array of provider (destination) references: 'ams' for all workloads, label hrefs, key=value pairs, or 'iplist:<name>'"
                    },
                    "consumers": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": "Array of consumer (source) references: 'ams' for all workloads, label hrefs, key=value pairs, or 'iplist:<name>'"
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
                        },
                        "description": "Services to deny (e.g., [{'port': 3389, 'proto': 'tcp'}])"
                    },
                    "override_deny": {
                        "type": "boolean",
                        "description": "If true, creates an override deny rule (allows traffic that would be denied). If false (default), creates a deny rule.",
                        "default": False
                    },
                    "unscoped_consumers": {
                        "type": "boolean",
                        "description": "Whether to allow unscoped consumers (extra-scope rule)",
                        "default": False
                    }
                },
                "required": ["providers", "consumers", "ingress_services"]
            }
        ),
        types.Tool(
            name="get-services",
            description="Get services from the PCE with optional filtering",
            inputSchema={
                "type": "object",
                "properties": {
                    "name": {"type": "string", "description": "Filter services by name (supports partial matches)"},
                    "description": {"type": "string", "description": "Filter services by description (supports partial matches)"},
                    "port": {"type": "integer", "description": "Filter services by port number"},
                    "proto": {"type": "string", "description": "Filter services by protocol (e.g., tcp, udp)"},
                    "process_name": {"type": "string", "description": "Filter services by process name"},
                    "max_results": {"type": "integer", "description": "Maximum number of services to return"},
                }
            }
        ),
        types.Tool(
            name="create-service",
            description="Create a new service definition in the PCE",
            inputSchema={
                "type": "object",
                "properties": {
                    "name": {"type": "string", "description": "Name of the service"},
                    "description": {"type": "string", "description": "Description of the service"},
                    "service_ports": {
                        "type": "array",
                        "items": {
                            "type": "object",
                            "properties": {
                                "port": {"type": "integer", "description": "Port number (-1 for all ports)"},
                                "to_port": {"type": "integer", "description": "End port for a port range (optional)"},
                                "proto": {"type": "integer", "description": "Protocol number (6=TCP, 17=UDP, 1=ICMP)"}
                            },
                            "required": ["proto"]
                        },
                        "description": "Array of port/protocol definitions"
                    },
                },
                "required": ["name", "service_ports"]
            }
        ),
        types.Tool(
            name="update-service",
            description="Update an existing service in the PCE. Identify by href (preferred) or name.",
            inputSchema={
                "type": "object",
                "properties": {
                    "href": {"type": "string", "description": "Service href (e.g., /orgs/1/sec_policy/draft/services/123)"},
                    "name": {"type": "string", "description": "Service name to find (alternative to href)"},
                    "new_name": {"type": "string", "description": "New name for the service"},
                    "description": {"type": "string", "description": "New description"},
                    "service_ports": {
                        "type": "array",
                        "items": {
                            "type": "object",
                            "properties": {
                                "port": {"type": "integer"},
                                "to_port": {"type": "integer"},
                                "proto": {"type": "integer"}
                            },
                            "required": ["proto"]
                        },
                        "description": "New port/protocol definitions (replaces existing)"
                    },
                },
            }
        ),
        types.Tool(
            name="delete-service",
            description="Delete a service from the PCE. Identify by href (preferred) or name.",
            inputSchema={
                "type": "object",
                "properties": {
                    "href": {"type": "string", "description": "Service href (e.g., /orgs/1/sec_policy/draft/services/123)"},
                    "name": {"type": "string", "description": "Service name (alternative to href)"},
                },
            }
        ),
        types.Tool(
            name="update-deny-rule",
            description="Update an existing deny rule in a ruleset. Identify the rule by its href.",
            inputSchema={
                "type": "object",
                "properties": {
                    "href": {"type": "string", "description": "Deny rule href (e.g., /orgs/1/sec_policy/draft/rule_sets/123/deny_rules/456)"},
                    "enabled": {"type": "boolean", "description": "Enable or disable the deny rule"},
                    "providers": {
                        "type": "array", "items": {"type": "string"},
                        "description": "Updated provider references: 'ams', label hrefs, key=value pairs, or 'iplist:<name>'"
                    },
                    "consumers": {
                        "type": "array", "items": {"type": "string"},
                        "description": "Updated consumer references: 'ams', label hrefs, key=value pairs, or 'iplist:<name>'"
                    },
                    "ingress_services": {
                        "type": "array",
                        "items": {
                            "type": "object",
                            "properties": {"port": {"type": "integer"}, "proto": {"type": "string"}},
                            "required": ["port", "proto"]
                        },
                        "description": "Updated services"
                    },
                },
                "required": ["href"]
            }
        ),
        types.Tool(
            name="delete-deny-rule",
            description="Delete a deny rule from a ruleset by its href",
            inputSchema={
                "type": "object",
                "properties": {
                    "href": {"type": "string", "description": "Deny rule href (e.g., /orgs/1/sec_policy/draft/rule_sets/123/deny_rules/456)"},
                },
                "required": ["href"]
            }
        ),
        types.Tool(
            name="update-label",
            description="Update an existing label in the PCE. Provide either: 1) href + new_value (optionally with key), or 2) key + value + new_value to identify and update the label.",
            inputSchema={
                "type": "object",
                "properties": {
                    "href": {
                        "type": "string",
                        "description": "Label href (e.g., /orgs/1/labels/42). Use this to directly identify the label."
                    },
                    "key": {
                        "type": "string",
                        "description": "Label type (e.g., role, app, env, loc). Required when using value to identify label, or when using href."
                    },
                    "value": {
                        "type": "string",
                        "description": "Current value of the label. Used with key to identify the label when href is not provided."
                    },
                    "new_value": {
                        "type": "string",
                        "description": "New value for the label. Always required."
                    }
                }
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
            description="Update an existing IP List in the PCE. Provide either 'href' or 'name' (but not both) to identify the IP List.",
            inputSchema={
                "type": "object",
                "properties": {
                    "href": {
                        "type": "string",
                        "description": "Href of the IP List to update (e.g., /orgs/1/sec_policy/draft/ip_lists/123)"
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
                }
            }
        ),
        types.Tool(
            name="delete-iplist",
            description="Delete an IP List from the PCE. Provide either 'href' or 'name' (but not both) to identify the IP List.",
            inputSchema={
                "type": "object",
                "properties": {
                    "href": {
                        "type": "string",
                        "description": "Href of the IP List to delete (e.g., /orgs/1/sec_policy/draft/ip_lists/123)"
                    },
                    "name": {
                        "type": "string",
                        "description": "Name of the IP List to delete (alternative to href)"
                    }
                }
            }
        ),
        types.Tool(
            name="update-ruleset",
            description="Update an existing ruleset in the PCE. Provide either 'href' or 'name' (but not both) to identify the ruleset.",
            inputSchema={
                "type": "object",
                "properties": {
                    "href": {
                        "type": "string",
                        "description": "Href of the ruleset to update (e.g., /orgs/1/sec_policy/active/rule_sets/123)"
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
                        "description": "New scopes for the ruleset. Each scope is an array of label identifiers (either href strings like '/orgs/1/labels/42', or key=value strings like 'role=web', or objects with href property).",
                        "items": {
                            "type": "array",
                            "items": {
                                "description": "Label identifier - can be a string (href or key=value) or an object with href property"
                            }
                        }
                    }
                }
            }
        ),
        types.Tool(
            name="delete-ruleset",
            description="Delete a ruleset from the PCE by its href",
            inputSchema={
                "type": "object",
                "properties": {
                    "href": {
                        "type": "string",
                        "description": "Href of the ruleset to delete (e.g., /orgs/1/sec_policy/draft/rule_sets/123)"
                    }
                },
                "required": ["href"]
            }
        ),
        types.Tool(
            name="create-ringfence",
            description="""Create a ringfencing policy for an application. This analyzes traffic flows to discover
which other apps communicate with this app, then creates a ruleset with:
1) An intra-scope rule allowing all workloads within the app to communicate on All Services
2) Extra-scope rules for each remote app+env discovered in traffic, allowing them in on All Services
The result is a coarse-grained segmentation that controls which apps can talk to each other,
reducing risk without requiring per-port policies.""",
            inputSchema={
                "type": "object",
                "properties": {
                    "app_name": {
                        "type": "string",
                        "description": "Application label value (e.g., 'CRM', 'Ordering', 'ELK')"
                    },
                    "env_name": {
                        "type": "string",
                        "description": "Environment label value (e.g., 'Production', 'Staging', 'Development')"
                    },
                    "lookback_days": {
                        "type": "integer",
                        "description": "Number of days to look back for traffic flows (default: 30)",
                        "default": 30
                    },
                    "ruleset_name": {
                        "type": "string",
                        "description": "Custom name for the ringfence ruleset (default: 'RF-<app_name>-<env_name>')"
                    },
                    "dry_run": {
                        "type": "boolean",
                        "description": "If true, analyze traffic and report what would be created without actually creating anything (default: false)",
                        "default": False
                    },
                    "selective": {
                        "type": "boolean",
                        "description": "If true, adds a deny rule blocking all inbound traffic to the app. "
                            "In selective enforcement mode the default action is allow-all, so without "
                            "this deny rule the ringfence has no teeth. Allow rules for known remote apps "
                            "are processed before the deny rule (rule order: override_deny > allow > deny > default), "
                            "so known apps pass through and everything else hits the deny. "
                            "This gets you to enforcement faster than full enforcement mode.",
                        "default": False
                    }
                },
                "required": ["app_name", "env_name"]
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
            pce = PolicyComputeEngine(PCE_HOST, port=PCE_PORT, org_id=PCE_ORG_ID)
            pce.set_credentials(API_KEY, API_SECRET)

            params = {"include": "labels", "max_results": arguments.get('max_results', 10000)}
            for param in ['name', 'hostname', 'ip_address', 'description', 'labels', 'enforcement_mode']:
                if arguments.get(param):
                    params[param] = arguments[param]
            if 'managed' in arguments:
                params['managed'] = arguments['managed']
            if 'online' in arguments:
                params['online'] = arguments['online']

            workloads = pce.workloads.get(params=params)
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
        logger.debug(f"UPDATE WORKLOAD CALLED with arguments: {json.dumps(arguments, indent=2)}")
        try:
            pce = PolicyComputeEngine(PCE_HOST, port=PCE_PORT, org_id=PCE_ORG_ID)
            pce.set_credentials(API_KEY, API_SECRET)

            # Find the workload by href or name
            workload_obj = None
            if arguments.get("href"):
                workload_obj = pce.workloads.get_by_reference(arguments["href"])
            elif arguments.get("name"):
                workloads = pce.workloads.get(params={"name": arguments["name"]})
                if workloads:
                    workload_obj = workloads[0]

            if not workload_obj:
                return [types.TextContent(type="text", text=json.dumps({"error": "Workload not found"}))]

            # Build update payload via raw API for flexibility
            update_data = {}
            if "new_name" in arguments:
                update_data["name"] = arguments["new_name"]
            if "description" in arguments:
                update_data["description"] = arguments["description"]
            if "hostname" in arguments:
                update_data["hostname"] = arguments["hostname"]
            if "enforcement_mode" in arguments:
                update_data["enforcement_mode"] = arguments["enforcement_mode"]

            # Handle IP addresses -> interfaces
            if arguments.get("ip_addresses"):
                interfaces = []
                for i, ip in enumerate(arguments["ip_addresses"]):
                    interfaces.append({"name": f"eth{i}", "address": ip})
                update_data["interfaces"] = interfaces

            # Handle labels
            if "labels" in arguments:
                workload_labels = []
                for label_spec in arguments["labels"]:
                    label_resp = pce.labels.get(params={"key": label_spec["key"], "value": label_spec["value"]})
                    if label_resp:
                        workload_labels.append({"href": label_resp[0].href})
                    else:
                        new_label = Label(key=label_spec["key"], value=label_spec["value"])
                        created = pce.labels.create(new_label)
                        workload_labels.append({"href": created.href})
                update_data["labels"] = workload_labels

            if not update_data:
                return [types.TextContent(type="text", text=json.dumps({"error": "No update fields provided"}))]

            pce.put(workload_obj.href, json=update_data)

            return [types.TextContent(
                type="text",
                text=json.dumps({"message": f"Successfully updated workload {workload_obj.href}", "updated_fields": list(update_data.keys())}, indent=2)
            )]
        except Exception as e:
            error_msg = f"Failed in PCE operation: {str(e)}"
            logger.error(error_msg, exc_info=True)
            return [types.TextContent(type="text", text=json.dumps({"error": error_msg}))]
    elif name == "delete-workload":
        logger.debug(f"DELETE WORKLOAD CALLED with arguments: {json.dumps(arguments, indent=2)}")
        try:
            pce = PolicyComputeEngine(PCE_HOST, port=PCE_PORT, org_id=PCE_ORG_ID)
            pce.set_credentials(API_KEY, API_SECRET)

            workload_obj = None
            if arguments.get("href"):
                workload_obj = pce.workloads.get_by_reference(arguments["href"])
            elif arguments.get("name"):
                workloads = pce.workloads.get(params={"name": arguments["name"]})
                if workloads:
                    workload_obj = workloads[0]

            if workload_obj:
                pce.workloads.delete(workload_obj)
                return [types.TextContent(
                    type="text",
                    text=json.dumps({"message": f"Workload deleted successfully: {workload_obj.href}"})
                )]
            else:
                return [types.TextContent(type="text", text=json.dumps({"error": "Workload not found"}))]
        except Exception as e:
            error_msg = f"Failed in PCE operation: {str(e)}"
            logger.error(error_msg, exc_info=True)
            return [types.TextContent(type="text", text=json.dumps({"error": error_msg}))]
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
            
            df = to_dataframe(all_traffic)

            # Group by columns that exist, always including IP list names
            group_cols = ['src_ip', 'dst_ip', 'proto', 'port', 'policy_decision']
            for col in ['src_ip_lists', 'dst_ip_lists', 'src_hostname', 'dst_hostname']:
                if col in df.columns:
                    group_cols.append(col)
            group_cols = [c for c in group_cols if c in df.columns]
            df = df.groupby(group_cols).agg({'num_connections': 'sum'}).reset_index()

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
        logger.debug(f"GET RULESETS CALLED with arguments: {json.dumps(arguments, indent=2)}")
        try:
            pce = PolicyComputeEngine(PCE_HOST, port=PCE_PORT, org_id=PCE_ORG_ID)
            pce.set_credentials(API_KEY, API_SECRET)

            params = {}
            for param in ['name', 'description', 'labels']:
                if arguments.get(param):
                    params[param] = arguments[param]
            if 'enabled' in arguments and arguments['enabled'] is not None:
                params['enabled'] = arguments['enabled']
            if arguments.get('max_results'):
                params['max_results'] = arguments['max_results']

            rulesets = pce.rule_sets.get(params=params) if params else pce.rule_sets.get_all()
            
            # Convert rulesets to serializable format
            ruleset_data = []
            for ruleset in rulesets:
                rules = []
                for rule in ruleset.rules:
                    rule_dict = {
                        'rule_type': 'allow',
                        'enabled': rule.enabled,
                        'description': rule.description,
                        'resolve_labels_as': str(rule.resolve_labels_as) if rule.resolve_labels_as else None,
                        'consumers': [str(consumer) for consumer in rule.consumers] if rule.consumers else [],
                        'providers': [str(provider) for provider in rule.providers] if rule.providers else [],
                        'ingress_services': [str(service) for service in rule.ingress_services] if rule.ingress_services else []
                    }
                    rules.append(rule_dict)

                # Fetch deny rules via raw API (override flag distinguishes override deny rules)
                try:
                    resp = pce.get(f"{ruleset.href}/deny_rules")
                    deny_rules = resp.json()
                    if deny_rules:
                        for dr in deny_rules:
                            is_override = dr.get('override', False)
                            rule_dict = {
                                'rule_type': 'override_deny' if is_override else 'deny',
                                'href': dr.get('href'),
                                'enabled': dr.get('enabled'),
                                'description': dr.get('description'),
                                'consumers': [str(c) for c in dr.get('consumers', [])],
                                'providers': [str(p) for p in dr.get('providers', [])],
                                'ingress_services': [str(s) for s in dr.get('ingress_services', [])]
                            }
                            rules.append(rule_dict)
                except Exception as de:
                    logger.debug(f"Could not fetch deny_rules for {ruleset.href}: {de}")

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
        logger.debug(f"GET IP LISTS CALLED with arguments: {json.dumps(arguments, indent=2)}")
        try:
            pce = PolicyComputeEngine(PCE_HOST, port=PCE_PORT, org_id=PCE_ORG_ID)
            pce.set_credentials(API_KEY, API_SECRET)

            params = {"max_results": arguments.get("max_results", 10000)}
            for param in ['name', 'description', 'fqdn', 'ip_address']:
                if arguments.get(param):
                    params[param] = arguments[param]

            ip_lists = pce.ip_lists.get(params=params)

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
                }
                iplist_data.append(iplist_dict)

            return [types.TextContent(
                type="text",
                text=json.dumps({"ip_lists": iplist_data, "total_count": len(iplist_data)}, indent=2)
            )]
        except Exception as e:
            error_msg = f"Failed to get IP lists: {str(e)}"
            logger.error(error_msg, exc_info=True)
            return [types.TextContent(type="text", text=json.dumps({"error": error_msg}))]
    elif name == "get-events":
        logger.debug("=" * 80)
        logger.debug("GET EVENTS CALLED")
        logger.debug(f"Arguments received: {json.dumps(arguments, indent=2)}")
        logger.debug("=" * 80)

        try:
            pce = PolicyComputeEngine(PCE_HOST, port=PCE_PORT, org_id=PCE_ORG_ID)
            pce.set_credentials(API_KEY, API_SECRET)

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
                    
                    # Determine rule type
                    rule_type = rule_def.get("rule_type", "allow")

                    if rule_type in ("deny", "override_deny"):
                        # Deny/override deny rules use raw API since SDK doesn't support rule_type
                        proto_map = {"tcp": 6, "udp": 17, "icmp": 1}
                        raw_providers = []
                        for p in providers:
                            if p == AMS:
                                raw_providers.append({"actors": "ams"})
                            elif hasattr(p, 'href') and hasattr(p, 'key'):
                                raw_providers.append({"label": {"href": p.href}})
                            elif hasattr(p, 'href'):
                                raw_providers.append({"ip_list": {"href": p.href}})
                        raw_consumers = []
                        for c in consumers:
                            if c == AMS:
                                raw_consumers.append({"actors": "ams"})
                            elif hasattr(c, 'href') and hasattr(c, 'key'):
                                raw_consumers.append({"label": {"href": c.href}})
                            elif hasattr(c, 'href'):
                                raw_consumers.append({"ip_list": {"href": c.href}})
                        raw_services = []
                        for svc in ingress_services:
                            proto_val = svc.proto
                            if isinstance(proto_val, str):
                                proto_val = proto_map.get(proto_val.lower(), proto_val)
                            raw_services.append({"port": svc.port, "proto": proto_val})

                        rule_payload = {
                            "enabled": True,
                            "providers": raw_providers,
                            "consumers": raw_consumers,
                            "ingress_services": raw_services,
                            "unscoped_consumers": rule_def.get("unscoped_consumers", False),
                            "override": rule_type == "override_deny"
                        }

                        endpoint = f"{ruleset.href}/deny_rules"

                        logger.debug(f"Creating {rule_type} rule at: {endpoint}")
                        resp = pce.post(endpoint, json=rule_payload)
                        result = resp.json()
                        created_rules.append({
                            "href": result.get("href", ""),
                            "rule_type": rule_type,
                            "providers": [str(p) for p in providers],
                            "consumers": [str(c) for c in consumers],
                            "services": [f"{s.port}/{s.proto}" for s in ingress_services],
                            "unscoped_consumers": rule_def.get("unscoped_consumers", False)
                        })
                    else:
                        # Standard allow rule using SDK
                        rule = Rule.build(
                            providers=providers,
                            consumers=consumers,
                            ingress_services=ingress_services,
                            unscoped_consumers=rule_def.get("unscoped_consumers", False)
                        )

                        created_rule = pce.rules.create(rule, parent=ruleset)
                        created_rules.append({
                            "href": created_rule.href,
                            "rule_type": "allow",
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
    elif name == "get-services":
        logger.debug("=" * 80)
        logger.debug("GET SERVICES CALLED")
        logger.debug(f"Arguments received: {json.dumps(arguments, indent=2)}")
        logger.debug("=" * 80)

        try:
            logger.debug("Initializing PCE connection...")
            pce = PolicyComputeEngine(PCE_HOST, port=PCE_PORT, org_id=PCE_ORG_ID)
            pce.set_credentials(API_KEY, API_SECRET)

            params = {}
            for param in ['name', 'description', 'port', 'proto', 'process_name', 'max_results']:
                if arguments.get(param):
                    params[param] = arguments[param]
            
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
            pce.rule_sets.update(ruleset.href, update_data)

            # Re-fetch the ruleset to get updated state
            updated_ruleset = pce.rule_sets.get_by_reference(ruleset.href)

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

    elif name == "create-deny-rule":
        logger.debug("=" * 80)
        logger.debug("CREATE DENY RULE CALLED")
        logger.debug(f"Arguments received: {json.dumps(arguments, indent=2)}")
        logger.debug("=" * 80)

        try:
            pce = PolicyComputeEngine(PCE_HOST, port=PCE_PORT, org_id=PCE_ORG_ID)
            pce.set_credentials(API_KEY, API_SECRET)

            # Build label maps
            label_href_map = {}
            value_href_map = {}
            for l in pce.labels.get(params={'max_results': 10000}):
                label_href_map[l.href] = {"key": l.key, "value": l.value}
                value_href_map["{}={}".format(l.key, l.value)] = l.href

            # Find the ruleset
            ruleset_href = None
            if arguments.get("ruleset_href"):
                ruleset_href = arguments["ruleset_href"]
                # Ensure it's a draft href
                if '/active/' in ruleset_href:
                    ruleset_href = ruleset_href.replace('/active/', '/draft/')
            elif arguments.get("ruleset_name"):
                rulesets = pce.rule_sets.get(params={"name": arguments["ruleset_name"]})
                if not rulesets:
                    return [types.TextContent(
                        type="text",
                        text=json.dumps({"error": f"Ruleset '{arguments['ruleset_name']}' not found"}, indent=2)
                    )]
                ruleset_href = rulesets[0].href
                if '/active/' in ruleset_href:
                    ruleset_href = ruleset_href.replace('/active/', '/draft/')
            else:
                return [types.TextContent(
                    type="text",
                    text=json.dumps({"error": "Must provide either 'ruleset_href' or 'ruleset_name'"}, indent=2)
                )]

            is_override = arguments.get("override_deny", False)
            rule_type = "override_deny" if is_override else "deny"

            # Build providers
            providers = []
            for provider in arguments["providers"]:
                if provider == "ams":
                    providers.append({"actors": "ams"})
                elif provider.startswith("iplist:"):
                    ip_list_name = provider.split(":", 1)[1]
                    ip_lists = pce.ip_lists.get(params={"name": ip_list_name})
                    if ip_lists:
                        providers.append({"ip_list": {"href": ip_lists[0].href}})
                    else:
                        return [types.TextContent(
                            type="text",
                            text=json.dumps({"error": f"IP list not found: {ip_list_name}"})
                        )]
                elif provider in value_href_map:
                    providers.append({"label": {"href": value_href_map[provider]}})
                else:
                    providers.append({"label": {"href": provider}})

            # Build consumers
            consumers = []
            for consumer in arguments["consumers"]:
                if consumer == "ams":
                    consumers.append({"actors": "ams"})
                elif consumer.startswith("iplist:"):
                    ip_list_name = consumer.split(":", 1)[1]
                    ip_lists = pce.ip_lists.get(params={"name": ip_list_name})
                    if ip_lists:
                        consumers.append({"ip_list": {"href": ip_lists[0].href}})
                    else:
                        return [types.TextContent(
                            type="text",
                            text=json.dumps({"error": f"IP list not found: {ip_list_name}"})
                        )]
                elif consumer in value_href_map:
                    consumers.append({"label": {"href": value_href_map[consumer]}})
                else:
                    consumers.append({"label": {"href": consumer}})

            # Build ingress services
            proto_map = {"tcp": 6, "udp": 17, "icmp": 1}
            ingress_services = []
            for svc in arguments["ingress_services"]:
                proto_val = svc["proto"]
                if isinstance(proto_val, str):
                    proto_val = proto_map.get(proto_val.lower(), proto_val)
                ingress_services.append({"port": svc["port"], "proto": proto_val})

            # Build the rule payload
            rule_payload = {
                "enabled": True,
                "providers": providers,
                "consumers": consumers,
                "ingress_services": ingress_services,
                "unscoped_consumers": arguments.get("unscoped_consumers", False),
                "override": rule_type == "override_deny"
            }

            endpoint = f"{ruleset_href}/deny_rules"

            logger.debug(f"Creating {rule_type} rule at endpoint: {endpoint}")
            logger.debug(f"Rule payload: {json.dumps(rule_payload, indent=2)}")

            resp = pce.post(endpoint, json=rule_payload)
            result = resp.json()

            return [types.TextContent(
                type="text",
                text=json.dumps({
                    "message": f"Successfully created {rule_type} rule",
                    "rule": result
                }, indent=2)
            )]

        except Exception as e:
            error_msg = f"Failed to create deny rule: {str(e)}"
            logger.error(error_msg, exc_info=True)
            return [types.TextContent(
                type="text",
                text=json.dumps({"error": error_msg}, indent=2)
            )]

    elif name == "update-deny-rule":
        logger.debug(f"UPDATE DENY RULE CALLED with arguments: {json.dumps(arguments, indent=2)}")
        try:
            pce = PolicyComputeEngine(PCE_HOST, port=PCE_PORT, org_id=PCE_ORG_ID)
            pce.set_credentials(API_KEY, API_SECRET)

            href = arguments["href"]
            if '/active/' in href:
                href = href.replace('/active/', '/draft/')

            update_data = {}
            if "enabled" in arguments:
                update_data["enabled"] = arguments["enabled"]

            # Build label maps if providers/consumers use key=value
            if arguments.get("providers") or arguments.get("consumers"):
                label_href_map = {}
                value_href_map = {}
                for l in pce.labels.get(params={'max_results': 10000}):
                    label_href_map[l.href] = {"key": l.key, "value": l.value}
                    value_href_map[f"{l.key}={l.value}"] = l.href

            if arguments.get("providers"):
                raw_providers = []
                for p in arguments["providers"]:
                    if p == "ams":
                        raw_providers.append({"actors": "ams"})
                    elif p.startswith("iplist:"):
                        ip_lists = pce.ip_lists.get(params={"name": p.split(":", 1)[1]})
                        if ip_lists:
                            raw_providers.append({"ip_list": {"href": ip_lists[0].href}})
                    elif p in value_href_map:
                        raw_providers.append({"label": {"href": value_href_map[p]}})
                    else:
                        raw_providers.append({"label": {"href": p}})
                update_data["providers"] = raw_providers

            if arguments.get("consumers"):
                raw_consumers = []
                for c in arguments["consumers"]:
                    if c == "ams":
                        raw_consumers.append({"actors": "ams"})
                    elif c.startswith("iplist:"):
                        ip_lists = pce.ip_lists.get(params={"name": c.split(":", 1)[1]})
                        if ip_lists:
                            raw_consumers.append({"ip_list": {"href": ip_lists[0].href}})
                    elif c in value_href_map:
                        raw_consumers.append({"label": {"href": value_href_map[c]}})
                    else:
                        raw_consumers.append({"label": {"href": c}})
                update_data["consumers"] = raw_consumers

            if arguments.get("ingress_services"):
                proto_map = {"tcp": 6, "udp": 17, "icmp": 1}
                raw_services = []
                for svc in arguments["ingress_services"]:
                    proto_val = svc["proto"]
                    if isinstance(proto_val, str):
                        proto_val = proto_map.get(proto_val.lower(), proto_val)
                    raw_services.append({"port": svc["port"], "proto": proto_val})
                update_data["ingress_services"] = raw_services

            if not update_data:
                return [types.TextContent(type="text", text=json.dumps({"error": "No update fields provided"}))]

            pce.put(href, json=update_data)

            return [types.TextContent(
                type="text",
                text=json.dumps({"message": f"Successfully updated deny rule {href}", "updated_fields": list(update_data.keys())}, indent=2)
            )]
        except Exception as e:
            error_msg = f"Failed to update deny rule: {str(e)}"
            logger.error(error_msg, exc_info=True)
            return [types.TextContent(type="text", text=json.dumps({"error": error_msg}, indent=2))]

    elif name == "delete-deny-rule":
        logger.debug(f"DELETE DENY RULE CALLED with arguments: {json.dumps(arguments, indent=2)}")
        try:
            pce = PolicyComputeEngine(PCE_HOST, port=PCE_PORT, org_id=PCE_ORG_ID)
            pce.set_credentials(API_KEY, API_SECRET)

            href = arguments["href"]
            if '/active/' in href:
                href = href.replace('/active/', '/draft/')

            pce.delete(href)

            return [types.TextContent(
                type="text",
                text=json.dumps({"message": f"Successfully deleted deny rule {href}"}, indent=2)
            )]
        except Exception as e:
            error_msg = f"Failed to delete deny rule: {str(e)}"
            logger.error(error_msg, exc_info=True)
            return [types.TextContent(type="text", text=json.dumps({"error": error_msg}, indent=2))]

    elif name == "create-ringfence":
        logger.debug("=" * 80)
        logger.debug("CREATE RINGFENCE CALLED")
        logger.debug(f"Arguments received: {json.dumps(arguments, indent=2)}")
        logger.debug("=" * 80)

        try:
            pce = PolicyComputeEngine(PCE_HOST, port=PCE_PORT, org_id=PCE_ORG_ID)
            pce.set_credentials(API_KEY, API_SECRET)

            app_name = arguments["app_name"]
            env_name = arguments["env_name"]
            lookback_days = arguments.get("lookback_days", 30)
            dry_run = arguments.get("dry_run", False)
            selective = arguments.get("selective", False)
            rs_name = arguments.get("ruleset_name", f"RF-{app_name}-{env_name}")

            # Step 1: Find app and env labels
            app_labels = pce.labels.get(params={"key": "app", "value": app_name})
            if not app_labels:
                return [types.TextContent(type="text", text=json.dumps({"error": f"App label '{app_name}' not found"}))]
            app_label = app_labels[0]

            env_labels = pce.labels.get(params={"key": "env", "value": env_name})
            if not env_labels:
                return [types.TextContent(type="text", text=json.dumps({"error": f"Env label '{env_name}' not found"}))]
            env_label = env_labels[0]

            logger.debug(f"Found labels: app={app_label.href}, env={env_label.href}")

            # Build label maps for resolving traffic flow labels
            label_href_map = {}
            for l in pce.labels.get(params={'max_results': 10000}):
                label_href_map[l.href] = {"key": l.key, "value": l.value}

            # Step 2: Find "All Services" service object
            all_services = pce.services.get(params={"name": "All Services"})
            all_services_href = None
            if all_services:
                all_services_href = all_services[0].href
                logger.debug(f"Found All Services: {all_services_href}")
            else:
                logger.warning("'All Services' service object not found, will use port -1 fallback")

            # Step 3: Query traffic flows for this app+env (as destination = inbound)
            start_date = (datetime.now() - timedelta(days=lookback_days)).strftime('%Y-%m-%d')
            end_date = datetime.now().strftime('%Y-%m-%d')

            # Build TrafficQueryFilter objects for the app+env labels
            app_filter = TrafficQueryFilter(label=Reference(href=app_label.href))
            env_filter = TrafficQueryFilter(label=Reference(href=env_label.href))

            traffic_query = TrafficQuery.build(
                start_date=start_date,
                end_date=end_date,
                include_sources=[[]],
                exclude_sources=[],
                include_destinations=[[app_filter, env_filter]],
                exclude_destinations=[],
                include_services=[],
                exclude_services=[],
                policy_decisions=[],
                exclude_workloads_from_ip_list_query=True,
                max_results=MCP_BUG_MAX_RESULTS,
                query_name='ringfence-inbound'
            )

            logger.debug("Querying inbound traffic flows...")
            inbound_flows = pce.get_traffic_flows_async(
                query_name='ringfence-inbound',
                traffic_query=traffic_query
            )

            # Step 4: Also query outbound traffic (this app as source)
            traffic_query_out = TrafficQuery.build(
                start_date=start_date,
                end_date=end_date,
                include_sources=[[app_filter, env_filter]],
                exclude_sources=[],
                include_destinations=[[]],
                exclude_destinations=[],
                include_services=[],
                exclude_services=[],
                policy_decisions=[],
                exclude_workloads_from_ip_list_query=True,
                max_results=MCP_BUG_MAX_RESULTS,
                query_name='ringfence-outbound'
            )

            logger.debug("Querying outbound traffic flows...")
            outbound_flows = pce.get_traffic_flows_async(
                query_name='ringfence-outbound',
                traffic_query=traffic_query_out
            )

            # Step 5: Convert flows to dataframes and group by app+env
            inbound_df = to_dataframe(inbound_flows)
            outbound_df = to_dataframe(outbound_flows)

            remote_apps_inbound = {}  # key: (app_value, env_value) -> list of {port, proto, connections}
            remote_apps_outbound = {}

            if not inbound_df.empty:
                # Group inbound by source app+env to find unique remote apps connecting in
                src_group_cols = []
                if 'src_app' in inbound_df.columns:
                    src_group_cols.append('src_app')
                if 'src_env' in inbound_df.columns:
                    src_group_cols.append('src_env')
                if src_group_cols and 'port' in inbound_df.columns and 'proto' in inbound_df.columns:
                    group_cols = src_group_cols + ['port', 'proto']
                    group_cols = [c for c in group_cols if c in inbound_df.columns]
                    inbound_grouped = inbound_df.groupby(group_cols)['num_connections'].sum().reset_index()
                    for _, row in inbound_grouped.iterrows():
                        src_app_val = row.get('src_app')
                        src_env_val = row.get('src_env')
                        if not src_app_val or not src_env_val:
                            continue
                        if src_app_val == app_name and src_env_val == env_name:
                            continue  # Skip intra-app traffic
                        key = (src_app_val, src_env_val)
                        if key not in remote_apps_inbound:
                            remote_apps_inbound[key] = []
                        remote_apps_inbound[key].append({
                            "port": int(row['port']) if 'port' in row else None,
                            "proto": int(row['proto']) if 'proto' in row else None,
                            "connections": int(row['num_connections'])
                        })

            if not outbound_df.empty:
                dst_group_cols = []
                if 'dst_app' in outbound_df.columns:
                    dst_group_cols.append('dst_app')
                if 'dst_env' in outbound_df.columns:
                    dst_group_cols.append('dst_env')
                if dst_group_cols and 'port' in outbound_df.columns and 'proto' in outbound_df.columns:
                    group_cols = dst_group_cols + ['port', 'proto']
                    group_cols = [c for c in group_cols if c in outbound_df.columns]
                    outbound_grouped = outbound_df.groupby(group_cols)['num_connections'].sum().reset_index()
                    for _, row in outbound_grouped.iterrows():
                        dst_app_val = row.get('dst_app')
                        dst_env_val = row.get('dst_env')
                        if not dst_app_val or not dst_env_val:
                            continue
                        if dst_app_val == app_name and dst_env_val == env_name:
                            continue
                        key = (dst_app_val, dst_env_val)
                        if key not in remote_apps_outbound:
                            remote_apps_outbound[key] = []
                        remote_apps_outbound[key].append({
                            "port": int(row['port']) if 'port' in row else None,
                            "proto": int(row['proto']) if 'proto' in row else None,
                            "connections": int(row['num_connections'])
                        })

            logger.debug(f"Discovered {len(remote_apps_inbound)} inbound remote apps, {len(remote_apps_outbound)} outbound remote apps")

            # Step 6: Build the result summary
            summary = {
                "app": app_name,
                "env": env_name,
                "app_label_href": app_label.href,
                "env_label_href": env_label.href,
                "lookback_days": lookback_days,
                "inbound_remote_apps": [
                    {"app": k[0], "env": k[1], "observed_ports": v}
                    for k, v in sorted(remote_apps_inbound.items())
                ],
                "outbound_remote_apps": [
                    {"app": k[0], "env": k[1], "observed_ports": v}
                    for k, v in sorted(remote_apps_outbound.items())
                ],
            }

            summary["selective"] = selective

            if dry_run:
                summary["dry_run"] = True
                if selective:
                    summary["message"] = ("Dry run - no changes made. Selective mode: will create allow rules for known remote apps "
                        "plus a deny rule blocking all other inbound traffic. Rule order: allow rules are processed before deny, "
                        "so known apps pass through. Review and run again with dry_run=false.")
                else:
                    summary["message"] = "Dry run - no changes made. Review the discovered traffic and run again with dry_run=false to create the ringfence."
                return [types.TextContent(type="text", text=json.dumps(summary, indent=2))]

            # Step 7: Check if ruleset already exists - merge if so
            existing = pce.rule_sets.get(params={"name": rs_name})
            has_intra_scope = False
            has_deny_all_inbound = False
            existing_remote_keys = set()

            if existing:
                ruleset = existing[0]
                logger.debug(f"Merging into existing ruleset: {ruleset.href}")
                summary["merged"] = True

                # Scan existing allow rules for duplicates
                for rule in ruleset.rules:
                    rule_app = None
                    rule_env = None
                    is_ams_consumers = False
                    is_ams_providers = False
                    is_unscoped = getattr(rule, 'unscoped_consumers', False)

                    if rule.consumers:
                        for c in rule.consumers:
                            if c == AMS or (hasattr(c, 'actors') and str(c) == 'ams'):
                                is_ams_consumers = True
                            elif hasattr(c, 'href'):
                                info = label_href_map.get(c.href, {})
                                if info.get("key") == "app":
                                    rule_app = info.get("value")
                                elif info.get("key") == "env":
                                    rule_env = info.get("value")

                    if rule.providers:
                        for p in rule.providers:
                            if p == AMS or (hasattr(p, 'actors') and str(p) == 'ams'):
                                is_ams_providers = True

                    # Detect intra-scope rule: AMS->AMS, not unscoped
                    if is_ams_consumers and is_ams_providers and not is_unscoped:
                        has_intra_scope = True

                    # Detect extra-scope rule by consumer app+env
                    if rule_app and rule_env:
                        existing_remote_keys.add((rule_app, rule_env))

                # Scan existing deny rules
                try:
                    rs_href = ruleset.href
                    if '/active/' in rs_href:
                        rs_href = rs_href.replace('/active/', '/draft/')
                    resp = pce.get(f"{rs_href}/deny_rules")
                    existing_deny_rules = resp.json()
                    for dr in existing_deny_rules:
                        if not dr.get('override', False):
                            # Regular deny rule - check if it's a deny-all-inbound
                            is_unscoped = dr.get('unscoped_consumers', False)
                            consumers_ams = any(c.get('actors') == 'ams' for c in dr.get('consumers', []))
                            providers_ams = any(p.get('actors') == 'ams' for p in dr.get('providers', []))
                            if is_unscoped and consumers_ams and providers_ams:
                                has_deny_all_inbound = True
                except Exception as de:
                    logger.debug(f"Could not fetch deny_rules for merge check: {de}")

                summary["has_deny_all_inbound"] = has_deny_all_inbound

                # Remove already-covered remote apps from inbound list
                skipped = []
                for key in list(remote_apps_inbound.keys()):
                    if key in existing_remote_keys:
                        logger.debug(f"Skipping already-covered remote app: app={key[0]}, env={key[1]}")
                        skipped.append({"app": key[0], "env": key[1]})
                        del remote_apps_inbound[key]
                if skipped:
                    summary["skipped_existing_rules"] = skipped
            else:
                # Step 8: Create the ruleset scoped to [app, env]
                ruleset = RuleSet(name=rs_name, description=f"Ringfence for {app_name} ({env_name})")
                scope_labels = LabelSet(labels=[app_label, env_label])
                ruleset.scopes = [scope_labels]
                ruleset = pce.rule_sets.create(ruleset)
                logger.debug(f"Created ruleset: {ruleset.href}")
                summary["merged"] = False

            created_rules = []

            # Step 9: Create intra-scope rule if it doesn't already exist
            if not has_intra_scope:
                if all_services_href:
                    intra_services = [{"href": all_services_href}]
                else:
                    intra_services = [ServicePort(port=-1, proto=6), ServicePort(port=-1, proto=17)]

                intra_rule = Rule.build(
                    providers=[AMS],
                    consumers=[AMS],
                    ingress_services=intra_services,
                    unscoped_consumers=False
                )
                created_intra = pce.rules.create(intra_rule, parent=ruleset)
                created_rules.append({
                    "type": "intra-scope",
                    "href": created_intra.href,
                    "description": "All workloads within app can communicate on All Services",
                    "consumers": "All Workloads (in scope)",
                    "providers": "All Workloads (in scope)",
                    "services": "All Services"
                })

            # Step 10: For selective mode, create a deny rule blocking all inbound traffic
            if selective and not summary.get("has_deny_all_inbound", False):
                # Build raw deny rule: all inbound to this app is denied
                if all_services_href:
                    deny_services = [{"href": all_services_href}]
                else:
                    deny_services = [{"port": -1, "proto": 6}, {"port": -1, "proto": 17}]

                deny_payload = {
                    "enabled": True,
                    "providers": [{"actors": "ams"}],
                    "consumers": [{"actors": "ams"}],
                    "ingress_services": deny_services,
                    "unscoped_consumers": True,
                    "override": False
                }

                ruleset_href = ruleset.href
                if '/active/' in ruleset_href:
                    ruleset_href = ruleset_href.replace('/active/', '/draft/')

                resp = pce.post(f"{ruleset_href}/deny_rules", json=deny_payload)
                deny_result = resp.json()
                created_rules.append({
                    "type": "deny (block all inbound)",
                    "href": deny_result.get("href", ""),
                    "description": f"Deny all inbound traffic to {app_name} ({env_name}) - selective enforcement",
                    "consumers": "All Workloads (unscoped/external)",
                    "providers": "All Workloads (in scope)",
                    "services": "All Services"
                })
                logger.debug(f"Created deny rule for selective enforcement: {deny_result.get('href')}")

            # Step 11: Create extra-scope allow rules for each inbound remote app
            # In both standard and selective mode, known remote apps get allow rules.
            # Rule processing order: override_deny > allow > deny > default.
            # In selective mode the deny rule (step 10) catches unknown inbound,
            # but allow rules for known apps are processed first (step 3 in rule order).
            for (remote_app, remote_env), ports in sorted(remote_apps_inbound.items()):
                remote_app_labels = pce.labels.get(params={"key": "app", "value": remote_app})
                remote_env_labels = pce.labels.get(params={"key": "env", "value": remote_env})

                if not remote_app_labels or not remote_env_labels:
                    logger.warning(f"Could not find labels for remote app={remote_app}, env={remote_env}, skipping")
                    continue

                consumers = [remote_app_labels[0], remote_env_labels[0]]

                if all_services_href:
                    extra_services = [{"href": all_services_href}]
                else:
                    extra_services = [ServicePort(port=-1, proto=6), ServicePort(port=-1, proto=17)]

                extra_rule = Rule.build(
                    providers=[AMS],
                    consumers=consumers,
                    ingress_services=extra_services,
                    unscoped_consumers=True
                )
                created_extra = pce.rules.create(extra_rule, parent=ruleset)
                created_rules.append({
                    "type": "extra-scope allow (inbound)",
                    "href": created_extra.href,
                    "description": f"Allow {remote_app} ({remote_env}) -> {app_name} ({env_name})",
                    "consumers": f"app={remote_app}, env={remote_env}",
                    "providers": "All Workloads (in scope)",
                    "services": "All Services",
                    "observed_ports": ports
                })

            # Build summary message
            if selective:
                deny_count = sum(1 for r in created_rules if r["type"].startswith("deny"))
                allow_count = sum(1 for r in created_rules if "allow" in r["type"])
                summary["enforcement_mode"] = "selective"
                summary["message"] = (f"Selective ringfence created with {len(created_rules)} rules: "
                    f"{allow_count} allow (intra-scope + known remote apps), "
                    f"{deny_count} deny-all-inbound. "
                    f"In selective mode: allows are processed before deny, so known apps pass through "
                    f"and everything else is blocked by the deny rule.")
            else:
                summary["message"] = f"Ringfence created with {len(created_rules)} rules ({1} intra-scope + {len(created_rules) - 1} extra-scope inbound)"

            summary["ruleset"] = {
                "href": ruleset.href,
                "name": rs_name,
                "rules": created_rules
            }

            return [types.TextContent(type="text", text=json.dumps(summary, indent=2))]

        except Exception as e:
            error_msg = f"Failed to create ringfence: {str(e)}"
            logger.error(error_msg, exc_info=True)
            return [types.TextContent(type="text", text=json.dumps({"error": error_msg}, indent=2))]

    elif name == "create-service":
        logger.debug(f"CREATE SERVICE CALLED with arguments: {json.dumps(arguments, indent=2)}")
        try:
            pce = PolicyComputeEngine(PCE_HOST, port=PCE_PORT, org_id=PCE_ORG_ID)
            pce.set_credentials(API_KEY, API_SECRET)

            payload = {
                "name": arguments["name"],
                "service_ports": arguments["service_ports"],
            }
            if arguments.get("description"):
                payload["description"] = arguments["description"]

            resp = pce.post("/sec_policy/draft/services", json=payload)
            result = resp.json()

            return [types.TextContent(
                type="text",
                text=json.dumps({"message": "Successfully created service", "service": result}, indent=2)
            )]
        except Exception as e:
            error_msg = f"Failed to create service: {str(e)}"
            logger.error(error_msg, exc_info=True)
            return [types.TextContent(type="text", text=json.dumps({"error": error_msg}, indent=2))]

    elif name == "update-service":
        logger.debug(f"UPDATE SERVICE CALLED with arguments: {json.dumps(arguments, indent=2)}")
        try:
            pce = PolicyComputeEngine(PCE_HOST, port=PCE_PORT, org_id=PCE_ORG_ID)
            pce.set_credentials(API_KEY, API_SECRET)

            # Find service by href or name
            service_href = None
            if arguments.get("href"):
                service_href = arguments["href"]
            elif arguments.get("name"):
                services = pce.services.get(params={"name": arguments["name"]})
                if services:
                    service_href = services[0].href
                else:
                    return [types.TextContent(type="text", text=json.dumps({"error": f"Service '{arguments['name']}' not found"}))]

            if not service_href:
                return [types.TextContent(type="text", text=json.dumps({"error": "Must provide either 'href' or 'name'"}))]

            if '/active/' in service_href:
                service_href = service_href.replace('/active/', '/draft/')

            update_data = {}
            if "new_name" in arguments:
                update_data["name"] = arguments["new_name"]
            if "description" in arguments:
                update_data["description"] = arguments["description"]
            if "service_ports" in arguments:
                update_data["service_ports"] = arguments["service_ports"]

            if not update_data:
                return [types.TextContent(type="text", text=json.dumps({"error": "No update fields provided"}))]

            pce.put(service_href, json=update_data)

            return [types.TextContent(
                type="text",
                text=json.dumps({"message": f"Successfully updated service {service_href}", "updated_fields": list(update_data.keys())}, indent=2)
            )]
        except Exception as e:
            error_msg = f"Failed to update service: {str(e)}"
            logger.error(error_msg, exc_info=True)
            return [types.TextContent(type="text", text=json.dumps({"error": error_msg}, indent=2))]

    elif name == "delete-service":
        logger.debug(f"DELETE SERVICE CALLED with arguments: {json.dumps(arguments, indent=2)}")
        try:
            pce = PolicyComputeEngine(PCE_HOST, port=PCE_PORT, org_id=PCE_ORG_ID)
            pce.set_credentials(API_KEY, API_SECRET)

            service_href = None
            if arguments.get("href"):
                service_href = arguments["href"]
            elif arguments.get("name"):
                services = pce.services.get(params={"name": arguments["name"]})
                if services:
                    service_href = services[0].href
                else:
                    return [types.TextContent(type="text", text=json.dumps({"error": f"Service '{arguments['name']}' not found"}))]

            if not service_href:
                return [types.TextContent(type="text", text=json.dumps({"error": "Must provide either 'href' or 'name'"}))]

            if '/active/' in service_href:
                service_href = service_href.replace('/active/', '/draft/')

            pce.delete(service_href)

            return [types.TextContent(
                type="text",
                text=json.dumps({"message": f"Successfully deleted service {service_href}"}, indent=2)
            )]
        except Exception as e:
            error_msg = f"Failed to delete service: {str(e)}"
            logger.error(error_msg, exc_info=True)
            return [types.TextContent(type="text", text=json.dumps({"error": error_msg}, indent=2))]

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

            # Add IP list names for src and dst
            if flow.src.ip_lists:
                ip_list_names = [ipl.name for ipl in flow.src.ip_lists if hasattr(ipl, 'name') and ipl.name]
                f['src_ip_lists'] = ', '.join(ip_list_names) if ip_list_names else None
            else:
                f['src_ip_lists'] = None

            if flow.dst.ip_lists:
                ip_list_names = [ipl.name for ipl in flow.dst.ip_lists if hasattr(ipl, 'name') and ipl.name]
                f['dst_ip_lists'] = ', '.join(ip_list_names) if ip_list_names else None
            else:
                f['dst_ip_lists'] = None

            # Add src and dst labels from workloads
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
    
    # Define all possible group columns, including IP list columns
    potential_columns = [
        'src_app', 'src_env', 'src_ip_lists',
        'dst_app', 'dst_env', 'dst_ip_lists',
        'proto', 'port'
    ]

    # Filter to only use columns that exist in the DataFrame
    group_columns = [col for col in potential_columns if col in df.columns]

    if not group_columns:
        logger.warning("No grouping columns found in DataFrame")
        return "No traffic data available for summarization"

    if df.empty:
        logger.warning("Empty DataFrame received")
        return "No traffic data available for summarization"

    # Fill NaN in IP list columns so groupby works properly
    for col in ['src_ip_lists', 'dst_ip_lists']:
        if col in df.columns:
            df[col] = df[col].fillna('')

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
        # Build source info: prefer app/env labels, fall back to IP list name
        src_info = []
        if 'src_app' in row and row['src_app']:
            src_info.append(row['src_app'])
        if 'src_env' in row and row['src_env']:
            src_info.append(f"({row['src_env']})")
        if not src_info and 'src_ip_lists' in row and row['src_ip_lists']:
            src_info.append(f"[IPList: {row['src_ip_lists']}]")
        src_str = " ".join(src_info) if src_info else "Unknown Source"

        # Build destination info: prefer app/env labels, fall back to IP list name
        dst_info = []
        if 'dst_app' in row and row['dst_app']:
            dst_info.append(row['dst_app'])
        if 'dst_env' in row and row['dst_env']:
            dst_info.append(f"({row['dst_env']})")
        if not dst_info and 'dst_ip_lists' in row and row['dst_ip_lists']:
            dst_info.append(f"[IPList: {row['dst_ip_lists']}]")
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