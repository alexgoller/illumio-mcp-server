<!-- Not published: docs/_config.yml excludes this file. The site landing page is docs/index.md. -->

# Illumio MCP Server — Documentation

This directory contains the full operator, security, and developer documentation for the Illumio MCP Server after the Phase 1-3e rollout. For a top-level feature overview, see the [project README](../README.md).

---

## Deployment shapes

The server supports four deployment shapes. Choose the one that matches your situation:

| Shape | Command | Auth | Use when |
|---|---|---|---|
| **Stdio** | `illumio-mcp` or `python -m illumio_mcp` | None (trust the OS user) | Local power user, Claude Desktop, Cursor |
| **HTTP dev-insecure** | `MCP_DEV_INSECURE=1 illumio-mcp-http` | None | Local integration testing, MCP Inspector smoke tests |
| **HTTP per-user** | `illumio-mcp-http` | JWT + per-user PCE key | Production default; each human has their own PCE API key |
| **HTTP shared** | `MCP_PCE_MODE=shared illumio-mcp-http` | JWT + shared service account | Fast onboarding; operators rely on the MCP audit log for attribution |

---

## Operations

| Document | Description |
|---|---|
| [operations/quickstart.md](operations/quickstart.md) | Five-minute guide to get any deployment shape running |
| [operations/configuration.md](operations/configuration.md) | Every environment variable in one table, organized by feature group |
| [operations/stdio-mode.md](operations/stdio-mode.md) | Stdio deployment: Claude Desktop and Cursor config snippets |
| [operations/http-mode.md](operations/http-mode.md) | HTTP modes: per-user, shared, architecture, safety gates, health endpoints |
| [operations/oauth-providers/entra.md](operations/oauth-providers/entra.md) | Microsoft Entra ID (Azure AD) step-by-step recipe |
| [operations/oauth-providers/okta.md](operations/oauth-providers/okta.md) | Okta Custom Authorization Server recipe |
| [operations/oauth-providers/auth0.md](operations/oauth-providers/auth0.md) | Auth0 Custom API recipe |
| [operations/oauth-providers/keycloak.md](operations/oauth-providers/keycloak.md) | Keycloak realm + client recipe |
| [operations/audit-log.md](operations/audit-log.md) | Audit log schema, sample queries, retention, and SIEM shipping |
| [operations/troubleshooting.md](operations/troubleshooting.md) | Common errors and fixes |

---

## Security

| Document | Description |
|---|---|
| [security/architecture.md](security/architecture.md) | Five-layer defense diagram, crypto choices, file permissions |
| [security/threat-model.md](security/threat-model.md) | What the design protects against, what it does not, honest trade-offs |
| [security/secret-management.md](security/secret-management.md) | Generation, rotation, and storage guidance for every secret |

---

## Development

| Document | Description |
|---|---|
| [development/code-layout.md](development/code-layout.md) | Package structure and the full dispatch flow |
| [development/adding-a-tool.md](development/adding-a-tool.md) | Step-by-step recipe for adding a new MCP tool |
| [development/testing.md](development/testing.md) | How to run unit, HTTP, and integration tests locally |
