---
title: Adding a tool
layout: default
parent: Development
---

# Adding a New Tool

Five steps to add a new MCP tool. Each step is mechanical. The worked example below adds a hypothetical `get-services-by-port` tool.

---

## Step 1: Write the handler

Add a new handler function in the appropriate `tools/*.py` file. Pick the file that most closely matches the domain (`services.py` for service-related tools, `workloads.py` for workload tools, etc.).

**Signature:** `def handle_<tool_name>(ctx, arguments: dict) -> list:`

The body reads `ctx.pce` to access the PCE client. Never import `get_pce()` or anything from `transport/` or `auth/` inside a tool handler.

```python
# src/illumio_mcp/tools/services.py

def handle_get_services_by_port(ctx, arguments: dict) -> list:
    """Return services that include the specified port."""
    port = int(arguments.get("port", 0))
    if not port:
        return [types.TextContent(type="text", text=json.dumps({"error": "port is required"}))]
    pce = ctx.pce
    services = pce.services.get(params={"max_results": 500})
    matching = [
        s for s in services
        if hasattr(s, "service_ports") and any(
            getattr(sp, "port", None) == port for sp in (s.service_ports or [])
        )
    ]
    return [types.TextContent(type="text", text=json.dumps(
        [{"href": s.href, "name": s.name} for s in matching], indent=2
    ))]
```

---

## Step 2: Add the MCP Tool definition in `server.py`

Add a `types.Tool` entry in `handle_list_tools()` in `src/illumio_mcp/server.py`. This is what MCP clients see in their tool list.

```python
types.Tool(
    name="get-services-by-port",
    description="Find service definitions that include a specific port number.",
    inputSchema={
        "type": "object",
        "properties": {
            "port": {
                "type": "integer",
                "description": "TCP/UDP port number to search for.",
            },
        },
        "required": ["port"],
    },
),
```

---

## Step 3: Add a `ToolSpec` entry in `tools/__init__.py`

Import the handler at the top of `src/illumio_mcp/tools/__init__.py` and add a `ToolSpec` entry in `TOOL_REGISTRY`.

**Import:**

```python
from .services import (
    handle_get_services,
    handle_create_service,
    handle_update_service,
    handle_delete_service,
    handle_get_services_by_port,   # add this line
)
```

**Registry entry:**

```python
TOOL_REGISTRY: dict[str, ToolSpec] = {
    ...
    # Services
    "get-services":           ToolSpec(handle_get_services,          roles=ALL_ROLES),
    "create-service":         ToolSpec(handle_create_service,        roles=_OP_ADMIN, mutating=True),
    "update-service":         ToolSpec(handle_update_service,        roles=_OP_ADMIN, mutating=True),
    "delete-service":         ToolSpec(handle_delete_service,        roles=_OP_ADMIN, mutating=True),
    "get-services-by-port":   ToolSpec(handle_get_services_by_port,  roles=ALL_ROLES),  # add this
    ...
}
```

**ToolSpec field cheatsheet:**

| Field | Type | Meaning |
|---|---|---|
| `roles` | `frozenset` | Who can call this tool. Use `ALL_ROLES`, `_OP_ADMIN`, or `_ADMIN_ONLY`. Must be non-empty. |
| `mutating` | `bool` | `True` if the tool creates, updates, or deletes PCE state. Required for tools whose name starts with `create-`, `update-`, `delete-`, or `provision-`. |
| `requires_confirm` | `bool` | `True` for highly destructive tools (provision, ringfence-batch). Implies `mutating=True`. |
| `unscopable` | `bool` | `True` if the tool returns PCE-wide data that cannot be safely filtered per user scope. |
| `requires_pce` | `bool` | `False` only for credential-management tools that work before a user has a PCE key. Default `True`. |

---

## Step 4: Update the tool count in `test_tool_metadata.py`

The guard test `test_count_matches_expected` in `tests/test_tool_metadata.py` asserts the exact tool count. Bump it when you add a tool:

```python
def test_count_matches_expected():
    assert len(TOOL_REGISTRY) == 47, \  # was 46, bumped for get-services-by-port
        f"Tool count drifted to {len(TOOL_REGISTRY)}; update this test if intentional"
```

Verify:

```bash
.venv/bin/python3 -m pytest tests/test_tool_metadata.py -v
```

Expected: all 6 guard tests pass.

---

## Step 5: Add a test

Add an integration or unit test for the new tool. For tools that require a real PCE, add to the appropriate `tests/test_mcp_tools.py` test class. For tools you can test with a stub PCE, add to a fast unit test.

```python
# tests/test_mcp_tools.py (integration, requires PCE)
class TestServices:
    def test_get_services_by_port(self, client):
        result = client.call_tool("get-services-by-port", {"port": 443})
        data = json.loads(result.content[0].text)
        assert isinstance(data, list)
```

---

## What the dispatcher will enforce automatically

Once your `ToolSpec` entry is in `TOOL_REGISTRY`, the dispatcher handles the rest:

- Users without a role in `spec.roles` get `{"error": "forbidden"}`.
- Users in per-user mode without PCE credentials (if `spec.requires_pce=True`) get `{"error": "no_pce_credentials"}`.
- HTTP callers without a confirm token (if `spec.requires_confirm=True`) get `{"error": "confirm_required"}`.
- Every decision is recorded in the audit log.

You do not need to add any authz code to the handler itself.

---

## CI guards that catch common mistakes

The `tests/test_tool_metadata.py` guards will fail at CI time if:

- The tool is in `TOOL_REGISTRY` but has an empty `roles=` set (caught by `ToolSpec.__post_init__`).
- The handler's first parameter is not named `ctx` (caught by `test_handlers_have_ctx_first_argument`).
- A tool whose name starts with `create-`/`update-`/`delete-`/`provision-` does not have `mutating=True` (caught by `test_destructive_tool_names_are_marked_mutating`).
- The tool count does not match the assertion (caught by `test_count_matches_expected`).
