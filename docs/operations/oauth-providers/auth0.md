---
title: Auth0
layout: default
parent: OAuth providers
grand_parent: Operations
---

# Auth0 — OAuth Setup

This is a briefer guide for Auth0. Verify steps with your IdP admin — Auth0's UI evolves frequently.

---

## Step 1: Create a Custom API

1. In the Auth0 Dashboard, navigate to **Applications** → **APIs** → **Create API**.
2. **Name:** `illumio-mcp`
3. **Identifier (audience):** `https://mcp.illumio.example` — this becomes `MCP_OAUTH_AUDIENCE`.
4. **Signing algorithm:** RS256.
5. Click **Create**.

---

## Step 2: Enable RBAC and add permissions

1. In the API settings, go to the **Settings** tab.
2. Enable **RBAC** and **Add Permissions in the Access Token**.
3. Go to the **Permissions** tab and add:
   - **Permission:** `illumio-mcp.use`
   - **Description:** `Access Illumio MCP Server`

---

## Step 3: Configure groups claim (verify with your IdP admin)

Auth0 does not include groups/roles in access tokens by default. The recommended approach is to use Auth0 Actions or Rules to add a custom claim:

1. Navigate to **Actions** → **Library** → **Build Custom Action** (or **Auth Pipeline** → **Rules** in the legacy interface).
2. Add a Post-Login action that reads the user's app metadata or Auth0 roles and adds them to the access token under the `groups` or `roles` key:

```javascript
// Example Auth0 Action (verify syntax with your IdP admin)
exports.onExecutePostLogin = async (event, api) => {
  const roles = event.authorization?.roles || [];
  api.accessToken.setCustomClaim('groups', roles);
};
```

The exact approach (Actions vs Rules, custom claim namespace) depends on your Auth0 plan and configuration. Verify with your IdP admin.

---

## Step 4: Create Applications for MCP clients

For each MCP client:

1. **Applications** → **Create Application**.
2. **Type:** Native (for Claude Desktop / Cursor) or Single Page Application (for MCP Inspector).
3. **Allowed Callback URLs:** Set the redirect URI for the client.
4. Under **APIs**, authorize the application to access your `illumio-mcp` API with the `illumio-mcp.use` scope.

---

## Step 5: Collect env vars

```bash
export MCP_PUBLIC_URL=https://mcp.illumio.example
export MCP_OAUTH_ISSUER=https://<your-auth0-domain>/
export MCP_OAUTH_JWKS_URL=https://<your-auth0-domain>/.well-known/jwks.json
export MCP_OAUTH_AUDIENCE=https://mcp.illumio.example
export MCP_OAUTH_REQUIRED_SCOPE=illumio-mcp.use

# Role mapping — use role/group names as they appear in the token claim you configured
export MCP_ROLE_GROUPS_ADMIN=illumio-admin
export MCP_ROLE_GROUPS_OPERATOR=illumio-operator,illumio-admin
export MCP_ROLE_GROUPS_READER=illumio-readonly,illumio-operator,illumio-admin
```

Note the trailing slash on the Auth0 issuer — this is required. Verify with your IdP admin.
