# MCP transport / response-size constants shared across tools.

MCP_BUG_MAX_RESULTS = 500

# MCP tool responses land in the LLM's context window.
# Too large = wastes tokens and can exceed transport limits.
# Too small = not enough data for useful analysis.
# 800KB leaves headroom under the ~1MB practical transport limit.
MCP_MAX_RESPONSE_BYTES = 800_000
