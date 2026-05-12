# Quickstart

Three paths to a running server. Pick the one that matches your goal.

---

## 1. Stdio — no setup required

The default mode. The MCP client launches the server as a subprocess. No network port, no auth.

```bash
# Clone and install
git clone https://github.com/alexgoller/illumio-mcp-server.git
cd illumio-mcp-server
pip install -e .

# Create .env with your PCE credentials
cat > .env <<EOF
PCE_HOST=https://your-pce.example.com
PCE_PORT=8443
PCE_ORG_ID=1
API_KEY=your_api_key
API_SECRET=your_api_secret
EOF

# Verify it works (Ctrl-C to stop)
python -m illumio_mcp
```

Then add to Claude Desktop (`~/Library/Application Support/Claude/claude_desktop_config.json` on macOS):

```json
{
  "mcpServers": {
    "illumio-mcp": {
      "command": "uv",
      "args": ["--directory", "/path/to/illumio-mcp-server", "run", "illumio-mcp"],
      "env": {
        "PCE_HOST": "https://your-pce.example.com",
        "PCE_PORT": "8443",
        "PCE_ORG_ID": "1",
        "API_KEY": "your_api_key",
        "API_SECRET": "your_api_secret"
      }
    }
  }
}
```

See [stdio-mode.md](stdio-mode.md) for the full Cursor config and Docker variants.

---

## 2. HTTP — dev-insecure (5 minutes)

Use this for local integration testing with MCP Inspector or to verify the HTTP transport before wiring up OAuth.

**Prerequisites:** `starlette`, `uvicorn`, and `mcp>=1.8.0` (installed automatically with `pip install -e .`).

```bash
# Start the server on localhost (refuses to bind 0.0.0.0 without this flag)
MCP_DEV_INSECURE=1 illumio-mcp-http

# Verify health
curl http://127.0.0.1:8080/healthz
# {"status":"ok"}
```

Point MCP Inspector at `http://127.0.0.1:8080/mcp` (transport: Streamable HTTP). All 46 tools are available with no auth check.

The server logs a prominent warning:

```
MCP_DEV_INSECURE=1: HTTP server starting WITHOUT auth. Do not use in production.
```

Do not use this in production.

---

## 3. HTTP — production-shaped

Production requires an OAuth IdP. The fastest path to production-shaped is:

1. Set up your IdP (see [oauth-providers/entra.md](oauth-providers/entra.md) for Entra ID — the most-tested path).
2. Generate secrets:
   ```bash
   export MCP_KEK=$(python -c 'import os, base64; print(base64.b64encode(os.urandom(32)).decode())')
   export MCP_CONFIRM_HMAC_KEY=$(python -c 'import os, base64; print(base64.b64encode(os.urandom(32)).decode())')
   ```
3. Set OAuth env vars and start:
   ```bash
   export MCP_PUBLIC_URL=https://mcp.illumio.example
   export MCP_OAUTH_ISSUER=https://login.microsoftonline.com/<tenant-id>/v2.0
   export MCP_OAUTH_JWKS_URL=https://login.microsoftonline.com/<tenant-id>/discovery/v2.0/keys
   export MCP_OAUTH_AUDIENCE=https://mcp.illumio.example
   illumio-mcp-http --host 127.0.0.1 --port 8080
   ```

For the full picture — PCE mode, role mapping, audit log — see [http-mode.md](http-mode.md).
