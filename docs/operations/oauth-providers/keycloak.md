# Keycloak — OAuth Setup

This is a briefer guide for self-hosted Keycloak. Verify steps with your Keycloak admin — versions vary.

---

## Step 1: Create or choose a Realm

Use an existing realm or create a new one for the MCP server:

1. In the Keycloak Admin Console, select the realm from the top-left dropdown (or create one under **Add realm**).
2. Note the realm name — it appears in all endpoint URLs.

---

## Step 2: Create a Client (the resource server)

1. Navigate to **Clients** → **Create Client**.
2. **Client type:** OpenID Connect.
3. **Client ID:** `illumio-mcp-server`.
4. Click **Next**.
5. **Client authentication:** Off (public client — the resource server does not need to authenticate to Keycloak; it only validates tokens).
6. **Authorization:** Off.
7. Click **Save**.

---

## Step 3: Configure the audience

Keycloak access tokens include the `aud` claim as the client ID by default. Set `MCP_OAUTH_AUDIENCE=illumio-mcp-server` to match.

Alternatively, add an **Audience mapper** to include a custom URI:

1. In the client, go to **Client scopes** → **illumio-mcp-server-dedicated** → **Add mapper** → **By configuration** → **Audience**.
2. **Name:** `mcp-audience`
3. **Included Custom Audience:** `https://mcp.illumio.example`
4. **Add to access token:** On.

---

## Step 4: Create a client scope for `illumio-mcp.use`

1. Navigate to **Client Scopes** → **Create client scope**.
2. **Name:** `illumio-mcp.use`
3. **Type:** Optional.
4. Click **Save**.
5. Assign this scope to the MCP client registrations (see Step 6).

---

## Step 5: Add a groups mapper

1. In the realm, go to **Client Scopes** → select a shared scope (or the dedicated scope for the MCP client) → **Mappers** → **Add mapper**.
2. **Mapper type:** Group Membership.
3. **Name:** `groups`
4. **Token Claim Name:** `groups`
5. **Full group path:** Off (emits bare group names, not `/path/to/group`).
6. **Add to access token:** On.

Verify with your Keycloak admin — the mapper configuration differs between Keycloak versions.

---

## Step 6: Register MCP client applications

For each MCP client, create a new client registration in Keycloak:

1. **Clients** → **Create Client**.
2. **Client type:** OpenID Connect.
3. **Client ID:** e.g., `illumio-mcp-claude-desktop`.
4. **Authentication:** Off (PKCE flow).
5. **Valid redirect URIs:** Set the client's redirect URI.
6. In **Client scopes**, add `illumio-mcp.use` as a default or optional scope.

---

## Step 7: Collect env vars

```bash
REALM=your-realm-name
KEYCLOAK_URL=https://keycloak.example.com

export MCP_PUBLIC_URL=https://mcp.illumio.example
export MCP_OAUTH_ISSUER=${KEYCLOAK_URL}/realms/${REALM}
export MCP_OAUTH_JWKS_URL=${KEYCLOAK_URL}/realms/${REALM}/protocol/openid-connect/certs
# Use your custom audience URI or the client ID:
export MCP_OAUTH_AUDIENCE=https://mcp.illumio.example
export MCP_OAUTH_REQUIRED_SCOPE=illumio-mcp.use

# Role mapping — group names as they appear in the groups claim
export MCP_ROLE_GROUPS_ADMIN=illumio-mcp-admin
export MCP_ROLE_GROUPS_OPERATOR=illumio-mcp-operator,illumio-mcp-admin
export MCP_ROLE_GROUPS_READER=illumio-mcp-readonly,illumio-mcp-operator,illumio-mcp-admin
```

Verify with your Keycloak admin — endpoint paths, realm-specific URLs, and group claim configuration vary across Keycloak versions and deployment types.
