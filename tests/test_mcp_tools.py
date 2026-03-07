"""Integration tests for the Illumio MCP server.

These tests run against a real PCE using the MCP protocol.
Requires .env with PCE_HOST, PCE_PORT, PCE_ORG_ID, API_KEY, API_SECRET.

Run with: .venv/bin/python3 -m pytest tests/ -v
"""
import json
import pytest
from mcp import ClientSession
from mcp.client.stdio import stdio_client
from conftest import get_server_params


pytestmark = pytest.mark.asyncio


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def parse_result(result):
    """Extract text from a CallToolResult and try to parse as JSON."""
    text = result.content[0].text
    try:
        return json.loads(text)
    except (json.JSONDecodeError, TypeError):
        return text


async def run_tool(name, arguments=None):
    """Spin up MCP server, call one tool, return parsed result."""
    async with stdio_client(get_server_params()) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()
            return await session.call_tool(name, arguments or {})


def assert_no_error(data, context=""):
    """Assert that parsed result doesn't contain an error."""
    if isinstance(data, dict) and "error" in data:
        pytest.fail(f"{context}: {data['error']}")


# ---------------------------------------------------------------------------
# Tool listing
# ---------------------------------------------------------------------------

class TestToolListing:
    async def test_list_tools_returns_all_expected(self):
        async with stdio_client(get_server_params()) as (read, write):
            async with ClientSession(read, write) as session:
                await session.initialize()
                result = await session.list_tools()
                tool_names = sorted([t.name for t in result.tools])
                expected = sorted([
                    "check-pce-connection",
                    "get-workloads", "create-workload", "update-workload", "delete-workload",
                    "get-labels", "create-label", "update-label", "delete-label",
                    "get-rulesets", "create-ruleset", "update-ruleset", "delete-ruleset",
                    "create-deny-rule", "update-deny-rule", "delete-deny-rule",
                    "get-iplists", "create-iplist", "update-iplist", "delete-iplist",
                    "get-services", "create-service", "update-service", "delete-service",
                    "get-traffic-flows", "get-traffic-flows-summary",
                    "get-events",
                ])
                assert len(tool_names) == len(expected), \
                    f"Tool count mismatch: got {len(tool_names)}, expected {len(expected)}. Extra: {set(tool_names) - set(expected)}, Missing: {set(expected) - set(tool_names)}"
                for name in expected:
                    assert name in tool_names, f"Missing tool: {name}"

    async def test_tools_have_input_schemas(self):
        async with stdio_client(get_server_params()) as (read, write):
            async with ClientSession(read, write) as session:
                await session.initialize()
                result = await session.list_tools()
                for tool in result.tools:
                    assert tool.inputSchema is not None, f"{tool.name} missing inputSchema"
                    assert tool.inputSchema.get("type") == "object", \
                        f"{tool.name} schema type should be 'object'"


# ---------------------------------------------------------------------------
# Connection
# ---------------------------------------------------------------------------

class TestConnection:
    async def test_check_pce_connection(self):
        result = await run_tool("check-pce-connection")
        text = result.content[0].text
        assert "successful" in text.lower() or "True" in text


# ---------------------------------------------------------------------------
# Labels - CRUD lifecycle
# ---------------------------------------------------------------------------

class TestLabels:
    LABEL_KEY = "app"
    LABEL_VALUE = "__mcp_test_label__"

    async def test_get_labels(self):
        result = await run_tool("get-labels", {})
        text = result.content[0].text
        assert "Labels:" in text

    async def test_get_labels_with_key_filter(self):
        result = await run_tool("get-labels", {"key": "app"})
        text = result.content[0].text
        assert "Labels:" in text

    @staticmethod
    def _find_label_href(labels_text, value):
        """Find a label href by value from get-labels output.

        get-labels returns: Labels: [{'href': '/orgs/1/labels/14', 'key': 'app', 'value': 'foo', ...}, ...]
        """
        import re, ast
        # Try to parse the list from "Labels: [...]"
        match = re.match(r"Labels:\s*(\[.*\])", labels_text, re.DOTALL)
        if match:
            try:
                labels = ast.literal_eval(match.group(1))
                for label in labels:
                    if label.get("value") == value:
                        return label.get("href")
            except (ValueError, SyntaxError):
                pass
        # Fallback: regex search
        # Look for href right before/after the value
        for m in re.finditer(r"'href':\s*'(/orgs/\d+/labels/\d+)'", labels_text):
            start = max(0, m.start() - 100)
            end = min(len(labels_text), m.end() + 100)
            if f"'{value}'" in labels_text[start:end]:
                return m.group(1)
        return None

    async def test_label_lifecycle(self):
        """Create, update, and delete a label."""
        async with stdio_client(get_server_params()) as (read, write):
            async with ClientSession(read, write) as session:
                await session.initialize()

                # Clean up any leftover from previous runs (delete-label uses key+value)
                for val in [self.LABEL_VALUE, self.LABEL_VALUE + "_updated"]:
                    await session.call_tool("delete-label", {
                        "key": self.LABEL_KEY, "value": val
                    })

                # Create
                create_result = await session.call_tool("create-label", {
                    "key": self.LABEL_KEY,
                    "value": self.LABEL_VALUE,
                })
                create_text = create_result.content[0].text
                assert "error" not in create_text.lower(), \
                    f"Create label failed: {create_text}"

                # Find href of created label
                labels_result = await session.call_tool("get-labels", {})
                href = self._find_label_href(labels_result.content[0].text, self.LABEL_VALUE)
                assert href, "Could not find created label"

                # Update (changes value to _updated)
                update_result = await session.call_tool("update-label", {
                    "href": href,
                    "new_value": self.LABEL_VALUE + "_updated",
                })
                update_text = update_result.content[0].text
                assert "error" not in update_text.lower(), \
                    f"Update label failed: {update_text}"

                # Delete (value was changed to _updated)
                delete_result = await session.call_tool("delete-label", {
                    "key": self.LABEL_KEY,
                    "value": self.LABEL_VALUE + "_updated",
                })
                delete_text = delete_result.content[0].text
                assert "error" not in delete_text.lower(), \
                    f"Delete label failed: {delete_text}"


# ---------------------------------------------------------------------------
# Workloads - read + CRUD lifecycle
# ---------------------------------------------------------------------------

class TestWorkloads:
    WORKLOAD_NAME = "__mcp_test_workload__"

    async def test_get_workloads(self):
        result = await run_tool("get-workloads", {})
        text = result.content[0].text
        assert "Workloads:" in text

    async def test_get_workloads_with_name_filter(self):
        result = await run_tool("get-workloads", {"name": "nonexistent_xyz_12345"})
        text = result.content[0].text
        # Should return empty or workloads header
        assert text

    @staticmethod
    def _find_workload_href(text, name):
        """Extract workload href from get-workloads or create output."""
        import re
        for match in re.finditer(r"(/orgs/\d+/workloads/[a-f0-9-]+)", text):
            start = max(0, match.start() - 300)
            end = min(len(text), match.end() + 300)
            if name in text[start:end]:
                return match.group(1)
        # Fallback: return first match
        match = re.search(r"(/orgs/\d+/workloads/[a-f0-9-]+)", text)
        return match.group(1) if match else None

    async def test_workload_lifecycle(self):
        """Create and delete an unmanaged workload."""
        async with stdio_client(get_server_params()) as (read, write):
            async with ClientSession(read, write) as session:
                await session.initialize()

                # Clean up leftover from previous runs
                get_result = await session.call_tool("get-workloads", {"name": self.WORKLOAD_NAME})
                get_text = get_result.content[0].text
                if self.WORKLOAD_NAME in get_text:
                    href = self._find_workload_href(get_text, self.WORKLOAD_NAME)
                    if href:
                        await session.call_tool("delete-workload", {"href": href})

                # Create (requires ip_addresses array, labels is optional)
                create_result = await session.call_tool("create-workload", {
                    "name": self.WORKLOAD_NAME,
                    "ip_addresses": ["192.168.99.99"],
                    "labels": [],
                })
                create_text = create_result.content[0].text
                assert "error" not in create_text.lower(), \
                    f"Create workload failed: {create_text}"

                # Find href from create output or by listing
                href = self._find_workload_href(create_text, self.WORKLOAD_NAME)
                if not href:
                    get_result = await session.call_tool("get-workloads", {"name": self.WORKLOAD_NAME})
                    href = self._find_workload_href(get_result.content[0].text, self.WORKLOAD_NAME)

                assert href, f"Could not find workload href. Create output: {create_text}"

                # Delete
                delete_result = await session.call_tool("delete-workload", {
                    "href": href,
                })
                delete_text = delete_result.content[0].text
                assert "error" not in delete_text.lower(), \
                    f"Delete workload failed: {delete_text}"


# ---------------------------------------------------------------------------
# IP Lists - CRUD lifecycle
# ---------------------------------------------------------------------------

class TestIPLists:
    IPLIST_NAME = "__mcp_test_iplist__"

    async def test_get_iplists(self):
        result = await run_tool("get-iplists", {})
        text = result.content[0].text
        assert text

    async def test_get_iplists_with_name_filter(self):
        result = await run_tool("get-iplists", {"name": "Any (0.0.0.0/0 and ::/0)"})
        text = result.content[0].text
        assert text

    async def test_iplist_lifecycle(self):
        """Create, update, and delete an IP list."""
        async with stdio_client(get_server_params()) as (read, write):
            async with ClientSession(read, write) as session:
                await session.initialize()

                # Clean up any leftover
                existing = await session.call_tool("get-iplists", {"name": self.IPLIST_NAME})
                existing_text = existing.content[0].text
                if self.IPLIST_NAME in existing_text:
                    import re
                    match = re.search(r"(/orgs/\d+/sec_policy/draft/ip_lists/\d+)", existing_text)
                    if match:
                        await session.call_tool("delete-iplist", {"href": match.group(1)})

                # Create
                create_result = await session.call_tool("create-iplist", {
                    "name": self.IPLIST_NAME,
                    "description": "MCP integration test IP list",
                    "ip_ranges": [{"from_ip": "10.99.99.0/24"}],
                })
                create_data = parse_result(create_result)
                assert_no_error(create_data, "Create IP list")
                href = None
                if isinstance(create_data, dict):
                    href = create_data.get("href") or create_data.get("ip_list", {}).get("href")

                assert href, f"Could not get IP list href: {create_data}"

                # Update
                update_result = await session.call_tool("update-iplist", {
                    "href": href,
                    "description": "Updated by MCP test",
                    "ip_ranges": [
                        {"from_ip": "10.99.99.0/24"},
                        {"from_ip": "10.99.100.0/24"},
                    ],
                })
                update_data = parse_result(update_result)
                assert_no_error(update_data, "Update IP list")

                # Delete
                delete_result = await session.call_tool("delete-iplist", {
                    "href": href,
                })
                delete_data = parse_result(delete_result)
                assert_no_error(delete_data, "Delete IP list")


# ---------------------------------------------------------------------------
# Services
# ---------------------------------------------------------------------------

class TestServices:
    async def test_get_services(self):
        result = await run_tool("get-services", {})
        text = result.content[0].text
        assert text

    async def test_get_services_with_name_filter(self):
        result = await run_tool("get-services", {"name": "SSH"})
        text = result.content[0].text
        assert text

    async def test_get_services_with_port_filter(self):
        result = await run_tool("get-services", {"port": 443})
        text = result.content[0].text
        assert text


# ---------------------------------------------------------------------------
# Rulesets - CRUD lifecycle
# ---------------------------------------------------------------------------

class TestRulesets:
    RULESET_NAME = "__mcp_test_ruleset__"

    async def test_get_rulesets(self):
        result = await run_tool("get-rulesets", {})
        data = parse_result(result)
        assert "rulesets" in data
        assert "total_count" in data

    async def test_get_rulesets_with_name_filter(self):
        result = await run_tool("get-rulesets", {"name": "nonexistent_xyz_12345"})
        data = parse_result(result)
        assert data.get("total_count", 0) == 0

    async def test_ruleset_lifecycle(self):
        """Create a ruleset with an allow rule, update it, then delete."""
        async with stdio_client(get_server_params()) as (read, write):
            async with ClientSession(read, write) as session:
                await session.initialize()

                # Clean up leftovers
                existing = await session.call_tool(
                    "get-rulesets", {"name": self.RULESET_NAME}
                )
                existing_data = parse_result(existing)
                if existing_data.get("total_count", 0) > 0:
                    href = existing_data["rulesets"][0]["href"]
                    await session.call_tool("delete-ruleset", {"href": href})

                # Create with an allow rule
                create_result = await session.call_tool("create-ruleset", {
                    "name": self.RULESET_NAME,
                    "description": "MCP integration test ruleset",
                    "scopes": [[]],
                    "rules": [
                        {
                            "providers": ["ams"],
                            "consumers": ["ams"],
                            "ingress_services": [{"port": 443, "proto": "tcp"}],
                        }
                    ],
                })
                create_data = parse_result(create_result)
                assert_no_error(create_data, "Create ruleset")
                assert "ruleset" in create_data, f"Create failed: {create_data}"
                ruleset_href = create_data["ruleset"]["href"]

                # Verify it shows up in get-rulesets
                get_result = await session.call_tool(
                    "get-rulesets", {"name": self.RULESET_NAME}
                )
                get_data = parse_result(get_result)
                assert get_data["total_count"] == 1
                assert get_data["rulesets"][0]["name"] == self.RULESET_NAME

                # Verify the allow rule
                rules = get_data["rulesets"][0].get("rules", [])
                assert len(rules) >= 1
                assert rules[0].get("rule_type") == "allow"

                # Update description
                update_result = await session.call_tool("update-ruleset", {
                    "href": ruleset_href,
                    "description": "Updated by MCP test",
                })
                update_data = parse_result(update_result)
                assert_no_error(update_data, "Update ruleset")

                # Delete
                delete_result = await session.call_tool(
                    "delete-ruleset", {"href": ruleset_href}
                )
                delete_data = parse_result(delete_result)
                assert "Successfully deleted" in delete_data.get("message", ""), \
                    f"Delete failed: {delete_data}"


# ---------------------------------------------------------------------------
# Deny rules - full lifecycle
# ---------------------------------------------------------------------------

class TestDenyRules:
    """Test deny and override deny rules lifecycle."""

    RULESET_NAME = "__mcp_test_deny_rules__"

    async def test_deny_rule_lifecycle(self):
        async with stdio_client(get_server_params()) as (read, write):
            async with ClientSession(read, write) as session:
                await session.initialize()

                # 1. Confirm PCE is reachable
                labels_result = await session.call_tool("get-labels", {})
                labels_text = labels_result.content[0].text
                if "Error" in labels_text:
                    pytest.skip("Cannot fetch labels from PCE")

                # 2. Clean up any leftover test ruleset
                existing = await session.call_tool(
                    "get-rulesets", {"name": self.RULESET_NAME}
                )
                existing_data = parse_result(existing)
                if existing_data.get("total_count", 0) > 0:
                    href = existing_data["rulesets"][0]["href"]
                    await session.call_tool("delete-ruleset", {"href": href})

                # 3. Create ruleset with a deny rule via create-ruleset
                create_result = await session.call_tool("create-ruleset", {
                    "name": self.RULESET_NAME,
                    "description": "MCP integration test - deny rules",
                    "scopes": [[]],
                    "rules": [
                        {
                            "providers": ["ams"],
                            "consumers": ["ams"],
                            "ingress_services": [{"port": 3389, "proto": "tcp"}],
                            "rule_type": "deny",
                        }
                    ],
                })
                create_data = parse_result(create_result)
                assert "ruleset" in create_data, f"Create failed: {create_data}"
                ruleset_href = create_data["ruleset"]["href"]
                assert create_data["ruleset"]["rules"][0]["rule_type"] == "deny"

                # 4. Add an override deny rule via standalone tool
                override_result = await session.call_tool("create-deny-rule", {
                    "ruleset_href": ruleset_href,
                    "providers": ["ams"],
                    "consumers": ["ams"],
                    "ingress_services": [{"port": 3389, "proto": "tcp"}],
                    "override_deny": True,
                })
                override_data = parse_result(override_result)
                assert "rule" in override_data, f"Override deny failed: {override_data}"

                # 5. Add a plain deny rule via standalone tool
                deny_result = await session.call_tool("create-deny-rule", {
                    "ruleset_href": ruleset_href,
                    "providers": ["ams"],
                    "consumers": ["ams"],
                    "ingress_services": [{"port": 22, "proto": "tcp"}],
                })
                deny_data = parse_result(deny_result)
                assert "rule" in deny_data, f"Deny rule failed: {deny_data}"

                # 6. Verify all deny rules show up in get-rulesets
                get_result = await session.call_tool(
                    "get-rulesets", {"name": self.RULESET_NAME}
                )
                get_data = parse_result(get_result)
                assert get_data["total_count"] == 1
                rules = get_data["rulesets"][0]["rules"]
                rule_types = [r.get("rule_type") for r in rules]
                assert "deny" in rule_types, f"No deny rule found: {rules}"
                assert "override_deny" in rule_types, f"No override deny: {rules}"

                # 7. Clean up
                delete_result = await session.call_tool(
                    "delete-ruleset", {"href": ruleset_href}
                )
                delete_data = parse_result(delete_result)
                assert "Successfully deleted" in delete_data.get("message", "")

    async def test_create_deny_rule_by_ruleset_name(self):
        """Test creating a deny rule using ruleset_name instead of href."""
        async with stdio_client(get_server_params()) as (read, write):
            async with ClientSession(read, write) as session:
                await session.initialize()

                # Create a ruleset first
                create_result = await session.call_tool("create-ruleset", {
                    "name": self.RULESET_NAME,
                    "description": "Test deny by name",
                    "scopes": [[]],
                })
                create_data = parse_result(create_result)
                assert_no_error(create_data, "Create ruleset")
                ruleset_href = create_data["ruleset"]["href"]

                # Create deny rule by name
                deny_result = await session.call_tool("create-deny-rule", {
                    "ruleset_name": self.RULESET_NAME,
                    "providers": ["ams"],
                    "consumers": ["ams"],
                    "ingress_services": [{"port": 445, "proto": "tcp"}],
                })
                deny_data = parse_result(deny_result)
                assert "rule" in deny_data, f"Deny by name failed: {deny_data}"

                # Clean up
                await session.call_tool("delete-ruleset", {"href": ruleset_href})


# ---------------------------------------------------------------------------
# Ruleset with scoped labels
# ---------------------------------------------------------------------------

class TestRulesetScopes:
    RULESET_NAME = "__mcp_test_scoped_ruleset__"

    async def test_ruleset_with_label_scopes(self):
        """Create a ruleset scoped to labels using key=value syntax."""
        async with stdio_client(get_server_params()) as (read, write):
            async with ClientSession(read, write) as session:
                await session.initialize()

                # Clean up leftovers
                existing = await session.call_tool(
                    "get-rulesets", {"name": self.RULESET_NAME}
                )
                existing_data = parse_result(existing)
                if existing_data.get("total_count", 0) > 0:
                    href = existing_data["rulesets"][0]["href"]
                    await session.call_tool("delete-ruleset", {"href": href})

                # Get available labels to pick a real one
                labels_result = await session.call_tool("get-labels", {"key": "env"})
                labels_text = labels_result.content[0].text
                if "Labels:" not in labels_text:
                    pytest.skip("No env labels available")

                # Parse a label value from the listing
                import re
                match = re.search(r"env.*?value='([^']+)'", labels_text)
                if not match:
                    match = re.search(r"value='([^']+)'", labels_text)
                if not match:
                    pytest.skip("Could not parse an env label value")
                env_value = match.group(1)

                # Create scoped ruleset
                create_result = await session.call_tool("create-ruleset", {
                    "name": self.RULESET_NAME,
                    "description": "Scoped ruleset test",
                    "scopes": [[f"env={env_value}"]],
                    "rules": [
                        {
                            "providers": ["ams"],
                            "consumers": ["ams"],
                            "ingress_services": [{"port": 80, "proto": "tcp"}],
                        }
                    ],
                })
                create_data = parse_result(create_result)
                assert_no_error(create_data, "Create scoped ruleset")
                assert "ruleset" in create_data
                ruleset_href = create_data["ruleset"]["href"]

                # Verify scopes are set
                get_result = await session.call_tool(
                    "get-rulesets", {"name": self.RULESET_NAME}
                )
                get_data = parse_result(get_result)
                assert get_data["total_count"] == 1
                scopes = get_data["rulesets"][0].get("scopes", [])
                assert len(scopes) > 0
                assert len(scopes[0]) > 0, "Scope should not be empty (all)"

                # Clean up
                await session.call_tool("delete-ruleset", {"href": ruleset_href})


# ---------------------------------------------------------------------------
# Events
# ---------------------------------------------------------------------------

class TestEvents:
    async def test_get_events(self):
        result = await run_tool("get-events", {})
        text = result.content[0].text
        assert text

    async def test_get_events_with_severity(self):
        result = await run_tool("get-events", {"severity": "err"})
        text = result.content[0].text
        assert text


# ---------------------------------------------------------------------------
# Traffic flows
# ---------------------------------------------------------------------------

class TestTrafficFlows:
    async def test_traffic_flows_returns_data(self):
        from datetime import datetime, timedelta

        end = datetime.now().strftime("%Y-%m-%d")
        start = (datetime.now() - timedelta(days=7)).strftime("%Y-%m-%d")

        result = await run_tool("get-traffic-flows", {
            "start_date": start,
            "end_date": end,
            "max_results": 10,
        })
        text = result.content[0].text
        assert text

    async def test_traffic_flows_with_policy_decision(self):
        from datetime import datetime, timedelta

        end = datetime.now().strftime("%Y-%m-%d")
        start = (datetime.now() - timedelta(days=7)).strftime("%Y-%m-%d")

        result = await run_tool("get-traffic-flows", {
            "start_date": start,
            "end_date": end,
            "max_results": 10,
            "policy_decisions": ["potentially_blocked"],
        })
        text = result.content[0].text
        assert text

    async def test_traffic_summary_returns_data(self):
        from datetime import datetime, timedelta

        end = datetime.now().strftime("%Y-%m-%d")
        start = (datetime.now() - timedelta(days=7)).strftime("%Y-%m-%d")

        result = await run_tool("get-traffic-flows-summary", {
            "start_date": start,
            "end_date": end,
        })
        text = result.content[0].text
        assert text

    async def test_traffic_flows_dataframe_has_ip_columns(self):
        """Traffic flows JSON output includes standard columns."""
        from datetime import datetime, timedelta

        end = datetime.now().strftime("%Y-%m-%d")
        start = (datetime.now() - timedelta(days=7)).strftime("%Y-%m-%d")

        result = await run_tool("get-traffic-flows", {
            "start_date": start,
            "end_date": end,
            "max_results": 10,
        })
        text = result.content[0].text
        try:
            data = json.loads(text)
            if isinstance(data, list) and len(data) > 0:
                first = data[0]
                assert "src_ip" in first
                assert "dst_ip" in first
        except json.JSONDecodeError:
            pass  # Empty or non-JSON response is ok


# ---------------------------------------------------------------------------
# Error handling / edge cases
# ---------------------------------------------------------------------------

class TestErrorHandling:
    async def test_delete_nonexistent_ruleset(self):
        result = await run_tool("delete-ruleset", {
            "href": "/orgs/1/sec_policy/draft/rule_sets/999999"
        })
        data = parse_result(result)
        # Should return an error, not crash
        assert isinstance(data, (str, dict))

    async def test_delete_nonexistent_label(self):
        result = await run_tool("delete-label", {
            "key": "app", "value": "__nonexistent_label_xyz_99999__"
        })
        text = result.content[0].text
        assert text  # Should return some response, not crash

    async def test_create_deny_rule_missing_ruleset(self):
        result = await run_tool("create-deny-rule", {
            "ruleset_name": "__nonexistent_ruleset_xyz__",
            "providers": ["ams"],
            "consumers": ["ams"],
            "ingress_services": [{"port": 22, "proto": "tcp"}],
        })
        data = parse_result(result)
        assert "error" in data, "Should return error for missing ruleset"

    async def test_create_deny_rule_no_ruleset_identifier(self):
        result = await run_tool("create-deny-rule", {
            "providers": ["ams"],
            "consumers": ["ams"],
            "ingress_services": [{"port": 22, "proto": "tcp"}],
        })
        data = parse_result(result)
        assert "error" in data, "Should require ruleset_href or ruleset_name"

    async def test_delete_nonexistent_iplist(self):
        result = await run_tool("delete-iplist", {
            "href": "/orgs/1/sec_policy/draft/ip_lists/999999"
        })
        text = result.content[0].text
        assert text  # Should return some response, not crash

    async def test_delete_nonexistent_workload(self):
        result = await run_tool("delete-workload", {
            "href": "/orgs/1/workloads/00000000-0000-0000-0000-000000000000"
        })
        text = result.content[0].text
        assert text  # Should return some response, not crash

    async def test_delete_nonexistent_service(self):
        result = await run_tool("delete-service", {
            "href": "/orgs/1/sec_policy/draft/services/999999"
        })
        text = result.content[0].text
        assert text

    async def test_delete_nonexistent_deny_rule(self):
        result = await run_tool("delete-deny-rule", {
            "href": "/orgs/1/sec_policy/draft/rule_sets/999/deny_rules/999"
        })
        text = result.content[0].text
        assert text


# ---------------------------------------------------------------------------
# Services - CRUD lifecycle
# ---------------------------------------------------------------------------

class TestServicesCRUD:
    SERVICE_NAME = "__mcp_test_service__"

    async def test_service_lifecycle(self):
        """Create, update, and delete a service."""
        async with stdio_client(get_server_params()) as (read, write):
            async with ClientSession(read, write) as session:
                await session.initialize()

                # Clean up leftovers
                await session.call_tool("delete-service", {"name": self.SERVICE_NAME})
                await session.call_tool("delete-service", {"name": self.SERVICE_NAME + "_updated"})

                # Create
                create_result = await session.call_tool("create-service", {
                    "name": self.SERVICE_NAME,
                    "description": "MCP test service",
                    "service_ports": [
                        {"port": 8080, "proto": 6},
                        {"port": 8443, "proto": 6},
                    ],
                })
                create_data = parse_result(create_result)
                assert_no_error(create_data, "Create service")
                assert "service" in create_data, f"Create failed: {create_data}"
                service_href = create_data["service"]["href"]

                # Verify it shows up in get-services
                get_result = await session.call_tool(
                    "get-services", {"name": self.SERVICE_NAME}
                )
                get_data = parse_result(get_result)
                assert get_data["total_count"] >= 1

                # Update
                update_result = await session.call_tool("update-service", {
                    "href": service_href,
                    "new_name": self.SERVICE_NAME + "_updated",
                    "description": "Updated MCP test service",
                    "service_ports": [
                        {"port": 9090, "proto": 6},
                    ],
                })
                update_data = parse_result(update_result)
                assert_no_error(update_data, "Update service")

                # Delete
                delete_result = await session.call_tool("delete-service", {
                    "href": service_href,
                })
                delete_data = parse_result(delete_result)
                assert_no_error(delete_data, "Delete service")


# ---------------------------------------------------------------------------
# Deny rules - update and delete
# ---------------------------------------------------------------------------

class TestDenyRulesUD:
    """Test update and delete deny rules."""

    RULESET_NAME = "__mcp_test_deny_ud__"

    async def test_deny_rule_update_delete(self):
        async with stdio_client(get_server_params()) as (read, write):
            async with ClientSession(read, write) as session:
                await session.initialize()

                # Clean up leftovers
                existing = await session.call_tool(
                    "get-rulesets", {"name": self.RULESET_NAME}
                )
                existing_data = parse_result(existing)
                if existing_data.get("total_count", 0) > 0:
                    await session.call_tool("delete-ruleset", {
                        "href": existing_data["rulesets"][0]["href"]
                    })

                # Create ruleset
                create_result = await session.call_tool("create-ruleset", {
                    "name": self.RULESET_NAME,
                    "description": "Test deny rule update/delete",
                    "scopes": [[]],
                })
                create_data = parse_result(create_result)
                assert_no_error(create_data, "Create ruleset")
                ruleset_href = create_data["ruleset"]["href"]

                # Create a deny rule
                deny_result = await session.call_tool("create-deny-rule", {
                    "ruleset_href": ruleset_href,
                    "providers": ["ams"],
                    "consumers": ["ams"],
                    "ingress_services": [{"port": 3389, "proto": "tcp"}],
                })
                deny_data = parse_result(deny_result)
                assert "rule" in deny_data, f"Create deny failed: {deny_data}"
                deny_href = deny_data["rule"]["href"]

                # Update the deny rule (disable it)
                update_result = await session.call_tool("update-deny-rule", {
                    "href": deny_href,
                    "enabled": False,
                })
                update_data = parse_result(update_result)
                assert_no_error(update_data, "Update deny rule")

                # Delete the deny rule
                delete_result = await session.call_tool("delete-deny-rule", {
                    "href": deny_href,
                })
                delete_data = parse_result(delete_result)
                assert_no_error(delete_data, "Delete deny rule")

                # Clean up ruleset
                await session.call_tool("delete-ruleset", {"href": ruleset_href})


# ---------------------------------------------------------------------------
# Enhanced read operations
# ---------------------------------------------------------------------------

class TestEnhancedReads:
    async def test_get_labels_with_key_value_filter(self):
        """Test that get-labels filters by key and value."""
        result = await run_tool("get-labels", {"key": "role"})
        text = result.content[0].text
        assert "Labels:" in text
        # All returned labels should have key=role
        import ast, re
        match = re.match(r"Labels:\s*(\[.*\])", text, re.DOTALL)
        if match:
            try:
                labels = ast.literal_eval(match.group(1))
                for label in labels:
                    assert label.get("key") == "role", f"Expected key=role, got {label.get('key')}"
            except (ValueError, SyntaxError):
                pass  # Parse failure is ok, we tested the API call worked

    async def test_get_workloads_with_hostname_filter(self):
        result = await run_tool("get-workloads", {"hostname": "nonexistent_xyz_host"})
        text = result.content[0].text
        assert text

    async def test_get_iplists_with_fqdn_filter(self):
        result = await run_tool("get-iplists", {"fqdn": "example.com"})
        data = parse_result(result)
        assert "ip_lists" in data

    async def test_get_rulesets_with_description_filter(self):
        result = await run_tool("get-rulesets", {"description": "nonexistent_xyz"})
        data = parse_result(result)
        assert data.get("total_count", 0) == 0

    async def test_get_services_with_max_results(self):
        result = await run_tool("get-services", {"max_results": 3})
        data = parse_result(result)
        assert data.get("total_count", 0) <= 3
