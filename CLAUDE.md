# Illumio MCP Server

## Illumio Rule Processing Order

Rules in Illumio are processed in this order:

1. **Essential rules** (built-in, cannot be modified)
2. **Override Deny rules** (`override: true` on deny_rules endpoint) - deny traffic that overrides all allow rules. Used for emergency blocking scenarios.
3. **Allow rules** (normal rules in rulesets) - permit traffic
4. **Deny rules** (`override: false` on deny_rules endpoint) - block specific traffic
5. **Default action** - depends on enforcement mode:
   - **Selective mode**: default is **allow all** (only deny rules are actively enforced)
   - **Full enforcement**: default is **deny all** (only explicitly allowed traffic passes)

## Ringfencing Concepts

- Apps are identified by **app + env** label combination (unique app identity)
- Ringfence = coarse-grained segmentation controlling which apps can talk to each other on All Services
- **Standard ringfence**: intra-scope allow rule + extra-scope allow rules for known remote apps
- **Selective ringfence**: adds a **deny rule** (step 4) blocking all inbound, so in selective mode (where default=allow) the deny rule enforces the ringfence. Known remote apps get **allow rules** (step 3) which are processed before the deny rule.
- Override Deny is NOT used for ringfencing. It's for emergency scenarios where you need to block traffic that would otherwise be allowed.

## PCE API Notes

- Deny rules use `/deny_rules` endpoint on rulesets with `"override": true/false` in payload
- Deny rules API is NOT in the OpenAPI spec (undocumented)
- `pce.rule_sets.update()` returns None - must re-fetch after update
- `resolve_labels_as` must NOT be included in deny rule payloads (causes 406)
- Draft vs Active: mutations go to `/sec_policy/draft/`, reads can use either

## Project Structure

- `src/illumio_mcp/server.py` - Main MCP server with all tool definitions and handlers
- `src/illumio_mcp/__main__.py` - Entry point for `python -m illumio_mcp`
- `tests/test_mcp_tools.py` - Integration tests using MCP stdio_client
- `tests/conftest.py` - Test config
- `.env` - PCE credentials (not committed)
