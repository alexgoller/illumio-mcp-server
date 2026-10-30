---
title: stdio mode
layout: default
parent: Operations
---

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

The server starts and exits cleanly when stdin closes. `Starting stdio server` is a DEBUG line, so it only
appears in `illumio-mcp.log` when `MCP_LOG_LEVEL=DEBUG`; at the default `INFO` the log stays quiet.

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

## Claude Code

Claude Code registers MCP servers from the command line; nothing is edited by hand.

```bash
claude mcp add -s user illumio-mcp \
  -e PCE_HOST=https://your-pce.example.com \
  -e PCE_PORT=443 \
  -e PCE_ORG_ID=1 \
  -e API_KEY=api_xxxxxxxxxxxxxxxx \
  -e API_SECRET=your_api_secret \
  -- uv --directory /path/to/illumio-mcp-server run illumio-mcp
```

| Flag | Meaning |
|---|---|
| `-s user` | available in every project, stored in your user config. `-s local` (default) is this project only; `-s project` writes `.mcp.json` into the repo for the team -- never with real credentials |
| `-e KEY=value` | environment for the server process; same variables as the `.env` file |
| `--` | everything after it is the server command: `uv --directory <repo> run illumio-mcp` |

`--directory` also makes the repo the server's working directory, so a `.env`
there is loaded (the `-e` flags then become optional) and `illumio-mcp.log`
is written there. Add `-e PCE_TLS_VERIFY=false` for a self-signed certificate.

Check it:

```bash
claude mcp get illumio-mcp     # Status: ✔ Connected
claude mcp list
```

Then, in a Claude Code session, ask for `check-pce-connection`; it returns the
PCE's HTTP status and round-trip time as JSON. Remove with
`claude mcp remove -s user illumio-mcp`.

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
