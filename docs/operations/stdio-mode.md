# Stdio Mode

Stdio is the default transport. The MCP client launches the server as a subprocess over stdin/stdout. No network port opens, no auth is required — the OS user who launched the process is implicitly trusted.

In stdio mode:
- Roles do not apply (implicitly `admin`).
- The audit log is not written (a `NullAuditLog` is used).
- Confirm-token enforcement does not apply — mutating tools like `provision-policy` and `ringfence-batch` work without a token.
- PCE credentials come from the `PCE_*` env vars (same as [shared HTTP mode](http-mode.md)).

---

## Running directly

```bash
# With .env file (recommended)
python -m illumio_mcp

# With explicit env
PCE_HOST=https://pce.example.com PCE_PORT=8443 PCE_ORG_ID=1 \
  API_KEY=mykey API_SECRET=mysecret python -m illumio_mcp
```

The server starts, logs `Starting stdio server` to `illumio-mcp.log`, and exits cleanly when stdin closes.

---

## Claude Desktop

**macOS:** `~/Library/Application Support/Claude/claude_desktop_config.json`
**Windows:** `%APPDATA%\Claude\claude_desktop_config.json`

### Using uv (recommended)

```json
{
  "mcpServers": {
    "illumio-mcp": {
      "command": "uv",
      "args": [
        "--directory",
        "/path/to/illumio-mcp-server",
        "run",
        "illumio-mcp"
      ],
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

### Using Docker

```json
{
  "mcpServers": {
    "illumio-mcp-docker": {
      "command": "docker",
      "args": [
        "run", "-i", "--init", "--rm",
        "--env-file", "/Users/YOUR_USERNAME/.illumio-mcp.env",
        "ghcr.io/alexgoller/illumio-mcp-server:latest"
      ]
    }
  }
}
```

Where `~/.illumio-mcp.env` contains:
```
PCE_HOST=https://your-pce.example.com
PCE_PORT=8443
PCE_ORG_ID=1
API_KEY=your_api_key
API_SECRET=your_api_secret
```

---

## Cursor

In Cursor, add the server to your MCP configuration (Settings → MCP):

```json
{
  "illumio-mcp": {
    "command": "uv",
    "args": [
      "--directory",
      "/path/to/illumio-mcp-server",
      "run",
      "illumio-mcp"
    ],
    "env": {
      "PCE_HOST": "https://your-pce.example.com",
      "PCE_PORT": "8443",
      "PCE_ORG_ID": "1",
      "API_KEY": "your_api_key",
      "API_SECRET": "your_api_secret"
    }
  }
}
```

---

## TLS verification

Set `PCE_TLS_VERIFY=false` to disable TLS certificate verification for PCE instances with self-signed certificates. Do not disable TLS verification in production environments with trusted certificates.

```json
"env": {
  "PCE_TLS_VERIFY": "false",
  ...
}
```
