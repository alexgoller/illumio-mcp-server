"""OAuth Resource Server primitives.

Each module in this package handles one auth concern:

- `config`: parses OAuth-related env vars into an OAuthConfig dataclass
- `jwt_validator`: validates JWT bearer tokens against a configured JWKS,
  returns an AuthenticatedUser
- `prm`: serves RFC 9728 Protected Resource Metadata so MCP clients can
  discover the configured Authorization Server
- `middleware`: Starlette middleware that wires the validator into the request
  pipeline and returns 401 with WWW-Authenticate on failure

Phase 3a wires these into the HTTP transport. Phase 3b/c/d will add KeyStore,
authz enforcement, and confirm tokens alongside.
"""
