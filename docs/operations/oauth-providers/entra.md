# Microsoft Entra ID (Azure AD) — OAuth Setup

This is the most-tested IdP integration. These instructions register the MCP server as a protected resource and configure MCP clients to authenticate against your Entra tenant.

---

## Step 1: Create an App Registration for the MCP server (the resource)

This registration represents the MCP server itself — it is the OAuth resource.

1. In the [Azure Portal](https://portal.azure.com), navigate to **Azure Active Directory** → **App registrations** → **New registration**.
2. **Name:** `illumio-mcp-server` (or any meaningful name).
3. **Supported account types:** Accounts in this organizational directory only (single tenant).
4. **Redirect URI:** leave blank for now (the server registration does not need one).
5. Click **Register**.

Note the **Application (client) ID** and **Directory (tenant) ID** from the overview page.

---

## Step 2: Set the App ID URI

The App ID URI becomes `MCP_OAUTH_AUDIENCE`.

1. In the app registration, go to **Expose an API**.
2. Next to **Application ID URI**, click **Set**.
3. Accept the default (`api://<client-id>`) or set a custom URI such as `https://mcp.illumio.example`. Custom URIs must match your `MCP_PUBLIC_URL` domain.
4. Click **Save**.

---

## Step 3: Expose the `illumio-mcp.use` scope

1. Still in **Expose an API**, click **Add a scope**.
2. **Scope name:** `illumio-mcp.use`
3. **Who can consent:** Admins and users (or Admins only for enterprise policy).
4. **Admin consent display name:** `Access Illumio MCP Server`
5. **Admin consent description:** `Allows the app to call Illumio MCP tools on behalf of the user.`
6. **State:** Enabled.
7. Click **Add scope**.

---

## Step 4: Configure groups claim emission

The server maps Entra security groups to MCP roles. Entra must include the user's group memberships in the access token.

1. In the app registration, go to **Token configuration**.
2. Click **Add groups claim**.
3. Select **Security groups**.
4. Under **Access token**, check the box for **Group ID** (Entra emits object IDs, not display names — you will use object IDs in `MCP_ROLE_GROUPS_*`).
5. Click **Add**.

**Note:** If a user is a member of more than ~200 groups, Entra omits the `groups` claim and instead sets `_claim_names: {"groups": "src1"}`. For large directories, use **App roles** instead of security groups (verify with your Entra admin). The server reads either the `groups` or `roles` claim.

---

## Step 5: Pre-register MCP client apps

MCP clients (Claude Desktop, Cursor, MCP Inspector) must be registered as separate app registrations in your tenant. Open Dynamic Client Registration is typically disabled in enterprise Entra tenants.

For each client, create a new app registration:

### Claude Desktop

1. **App registration name:** `illumio-mcp-claude-desktop`
2. **Redirect URIs:** Add the platform **Mobile and desktop applications** and set URI to `http://localhost` (Claude Desktop uses a local redirect).
3. **API permissions:** Click **Add a permission** → **My APIs** → select your `illumio-mcp-server` registration → check `illumio-mcp.use` → **Add permissions**.
4. If your tenant requires admin consent, have an admin click **Grant admin consent** on the API permissions page.

### MCP Inspector

1. **App registration name:** `illumio-mcp-inspector`
2. **Redirect URIs:** Single-page application, `http://localhost:6274/oauth/callback` (MCP Inspector's default PKCE callback).
3. **API permissions:** Same as above — grant `illumio-mcp.use`.

### Cursor

Verify with your IdP admin — Cursor's redirect URI may differ by version. A common pattern is `http://localhost` with a dynamic port. Check Cursor's current MCP OAuth documentation for the exact values.

---

## Step 6: Collect env vars

```bash
# Tenant-specific JWKS endpoint
TENANT_ID=<your-tenant-id>

export MCP_PUBLIC_URL=https://mcp.illumio.example
export MCP_OAUTH_ISSUER=https://login.microsoftonline.com/${TENANT_ID}/v2.0
export MCP_OAUTH_JWKS_URL=https://login.microsoftonline.com/${TENANT_ID}/discovery/v2.0/keys
# Use the App ID URI from Step 2
export MCP_OAUTH_AUDIENCE=https://mcp.illumio.example
# Or if you kept the default: api://<client-id>
# export MCP_OAUTH_AUDIENCE=api://<application-client-id>
export MCP_OAUTH_REQUIRED_SCOPE=illumio-mcp.use

# Role mapping — use Entra group object IDs, not display names
export MCP_ROLE_GROUPS_ADMIN=<object-id-of-sg-illumio-admin>
export MCP_ROLE_GROUPS_OPERATOR=<object-id-of-sg-illumio-operator>,<object-id-of-sg-illumio-admin>
export MCP_ROLE_GROUPS_READER=<object-id-of-sg-illumio-readonly>,<object-id-of-sg-illumio-operator>,<object-id-of-sg-illumio-admin>
```

Find group object IDs in **Azure Active Directory** → **Groups** → select the group → **Object ID**.

---

## Troubleshooting

- **401 `iss mismatch`:** Ensure `MCP_OAUTH_ISSUER` exactly matches the `iss` claim in the access token. For Entra v2, the issuer is `https://login.microsoftonline.com/<tenant-id>/v2.0`. For v1, it omits `/v2.0`. Check which version your Entra is configured to issue.
- **401 `aud mismatch`:** The `aud` claim in the token must exactly match `MCP_OAUTH_AUDIENCE`. Use a JWT decoder (e.g., jwt.io) to inspect the token.
- **`forbidden_no_role`:** The user's groups are not in the token, or the group object IDs don't match what you set in `MCP_ROLE_GROUPS_*`. Decode the token and check the `groups` claim.
- **Groups claim missing entirely:** The user has too many group memberships (>200). Switch to App Roles or use a nested group approach with fewer direct groups.
