# MCP transport / response-size constants shared across tools.

# How many rows a tool may hand BACK to the client. This is the constraint that
# genuinely exists: tool responses land in the model's context window.
MCP_BUG_MAX_RESULTS = 500

# How many rows we may ask the PCE FOR. A different question entirely, and for
# years the same 500 answered both -- so every tool that aggregates flows into a
# summary was computing that summary from the first 500 rows the PCE happened to
# return. Measured on demo100: a 30-day whole-estate window is 7,967 Explorer
# rows, so the summary was built from 6% of the window, and not a random 6%.
#
# Aggregation is what makes the wide query affordable. The same window collapses
# to 1,151 app+env x port/proto x decision tuples at 89 bytes each -- 102 KB,
# comfortably inside MCP_MAX_RESPONSE_BYTES, where the raw rows were 16.5 MB.
# So: pull wide, aggregate, then spend the response budget on tuples.
#
# Only for tools that AGGREGATE before responding. Anything returning raw rows
# must still bound itself by MCP_BUG_MAX_RESULTS.
MCP_QUERY_MAX_RESULTS = 200_000

# MCP tool responses land in the LLM's context window.
# Too large = wastes tokens and can exceed transport limits.
# Too small = not enough data for useful analysis.
# 800KB leaves headroom under the ~1MB practical transport limit.
MCP_MAX_RESPONSE_BYTES = 800_000
