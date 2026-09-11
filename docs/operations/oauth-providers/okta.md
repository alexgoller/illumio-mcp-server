---
title: Okta
layout: default
parent: OAuth providers
grand_parent: Operations
---

# Okta — OAuth Setup

This guide sets up Okta as the Authorization Server for the MCP server. The approach uses a Custom Authorization Server (recommended over the Org AS for API access).

These steps are best-effort — verify specifics with your Okta admin, as UI paths change across Okta releases.

---

## Step 1: Create a Custom Authorization Server

1. In the Okta Admin Console, navigate to **Security** → **API** → **Authorization Servers**.
2. Click **Add Authorization Server**.
3. **Name:** `illumio-mcp`
4. **Audience:** `https://mcp.illumio.example` (this becomes `MCP_OAUTH_AUDIENCE`)
5. **Description:** `Illumio MCP Server resource`
6. Click **Save**.

Note the **Issuer URI** from the Authorization Server overview — it becomes `MCP_OAUTH_ISSUER`.

---

## Step 2: Add the `illumio-mcp.use` scope

1. In the Authorization Server, go to the **Scopes** tab.
2. Click **Add Scope**.
3. **Name:** `illumio-mcp.use`
4. **Display phrase:** `Access Illumio MCP Server`
5. **User consent:** check if you want users to explicitly grant consent.
6. Click **Create**.

---

## Step 3: Configure a groups claim

The server reads the `groups` or `roles` claim from the access token to map users to MCP roles.

1. In the Authorization Server, go to the **Claims** tab.
2. Click **Add Claim**.
3. **Name:** `groups`
4. **Include in token type:** Access Token, Always.
5. **Value type:** Groups
6. **Filter:** Matches regex `.*` (all groups), or restrict to a specific prefix like `sg-illumio.*`.
7. **Include in:** Any scope.
8. Click **Create**.

Verify with your Okta admin — the exact filter type (Starts with, Matches regex, Equals) depends on your group naming convention.

---

## Step 4: Create an OAuth Application for each MCP client

For each MCP client (Claude Desktop, Cursor, MCP Inspector):

1. Navigate to **Applications** → **Applications** → **Create App Integration**.
2. **Sign-in method:** OIDC – OpenID Connect.
3. **Application type:** Native Application (for desktop clients) or Single-Page Application (for browser-based tools like MCP Inspector).
4. **Grant type:** Authorization Code with PKCE.
5. **Sign-in redirect URIs:** Add the redirect URI for the specific client (e.g., `http://localhost` for Claude Desktop, `http://localhost:6274/oauth/callback` for MCP Inspector — verify with your IdP admin).
6. Under **Assignments**, assign users or groups.

---

## Step 5: Collect env vars

```bash
export MCP_PUBLIC_URL=https://mcp.illumio.example
# Issuer from the Authorization Server overview:
export MCP_OAUTH_ISSUER=https://<your-okta-domain>/oauth2/<auth-server-id>
# JWKS from the Authorization Server's metadata:
export MCP_OAUTH_JWKS_URL=https://<your-okta-domain>/oauth2/<auth-server-id>/v1/keys
export MCP_OAUTH_AUDIENCE=https://mcp.illumio.example
export MCP_OAUTH_REQUIRED_SCOPE=illumio-mcp.use

# Role mapping — use Okta group names (not IDs) as they appear in the groups claim
export MCP_ROLE_GROUPS_ADMIN=sg-illumio-mcp-admin
export MCP_ROLE_GROUPS_OPERATOR=sg-illumio-mcp-operator,sg-illumio-mcp-admin
export MCP_ROLE_GROUPS_READER=sg-illumio-mcp-readonly,sg-illumio-mcp-operator,sg-illumio-mcp-admin
```

---

## Troubleshooting

- **401 `iss mismatch`:** The `iss` in the token must exactly match `MCP_OAUTH_ISSUER`. For Custom AS, it includes the AS ID path segment; for the Org AS, it is just your Okta domain. Verify by decoding an access token.
- **`groups` claim missing:** The claim was not added, or the scope filter excludes the user's groups. Check the claim policy under the Authorization Server.
- Verify with your Okta admin if unsure about Application types, redirect URIs, or group filter syntax.
