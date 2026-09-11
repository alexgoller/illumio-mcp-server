---
title: Getting started
layout: default
nav_order: 3
---

# Getting started
{: .no_toc }

Goes from a cloned repo to answering questions about your PCE. Assumes you have
[installed](installation) the server.

1. TOC
{:toc}

---

## 1. Supply PCE credentials

Create a `.env` in the repo root:

```bash
PCE_HOST=pce.example.com
PCE_PORT=8443
PCE_ORG_ID=1
API_KEY=api_xxxxxxxxxxxx
API_SECRET=xxxxxxxxxxxxxxxx
```

{: .caution }
> Start against a **test or demo PCE**. The tool set includes `provision-policy` and
> `ringfence-batch`, which change production segmentation.

`.env` is gitignored. For a team deployment, do not distribute credentials this way at
all — see [Central deployment](deployment/central).

## 2. Register with Claude Desktop

Add to `claude_desktop_config.json`:

**macOS** `~/Library/Application Support/Claude/claude_desktop_config.json`
**Windows** `%APPDATA%\Claude\claude_desktop_config.json`

```json
{
  "mcpServers": {
    "illumio-mcp": {
      "command": "uv",
      "args": [
        "--directory", "/absolute/path/to/illumio-mcp-server",
        "run", "illumio-mcp"
      ],
      "env": {
        "PCE_HOST": "pce.example.com",
        "PCE_PORT": "8443",
        "PCE_ORG_ID": "1",
        "API_KEY": "api_xxxxxxxxxxxx",
        "API_SECRET": "xxxxxxxxxxxxxxxx"
      }
    }
  }
}
```

Use an **absolute** path for `--directory`, and restart Claude Desktop afterwards.

{: .note }
> In stdio mode there is no authentication layer — whoever can launch the process gets
> the `admin` role. That is appropriate for a single-user laptop and nothing else.

## 3. First queries

Start read-only to confirm the wiring:

```
Check my PCE connection
  → check-pce-connection

What labels exist in the PCE?
  → get-labels

Show me the workloads in the production environment
  → get-workloads
```

Then something that shows the value:

```
Summarise traffic to the payments app in production over the last 7 days
  → get-traffic-flows-summary

Which apps look like shared infrastructure?
  → identify-infrastructure-services
```

## 4. Move toward policy

The natural progression before touching enforcement:

| Step | Tool | Question it answers |
|---|---|---|
| 1 | `get-traffic-flows-summary` | Who actually talks to this app? |
| 2 | `get-policy-coverage-report` | Which of those flows are already allowed? |
| 3 | `enforcement-readiness` | Would enforcing break anything? |
| 4 | `create-ringfence` | Write the rules (draft only) |
| 5 | `compare-draft-active` | What exactly would change? |
| 6 | `provision-policy` | Commit it — **admin + confirmation required** |

Steps 1–3 and 5 are read-only. Step 4 writes draft policy, which has no effect on traffic
until provisioned. Only step 6 changes enforcement.

## 5. Use the guided workflows

Rather than driving tools individually, the server ships multi-step prompts that
sequence them for you — ringfencing, traffic analysis and emergency isolation.

[Workflows and prompts →](workflows)

## Troubleshooting

| Symptom | Cause |
|---|---|
| Server not listed in the client | Path in `--directory` is not absolute, or client not restarted |
| `401 Unauthorized` from the PCE | API key expired or wrong org ID |
| `no_credentials` error | HTTP mode, per-user: visit `/setup` first |
| Empty log file | Expected. Default level is `INFO`; set `MCP_LOG_LEVEL=DEBUG` while diagnosing |

More in [Troubleshooting](operations/troubleshooting).
