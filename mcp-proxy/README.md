# Sqreen Core (`mcp-proxy`)

Local runtime enforcement for AI agent tool calls — MCP, OpenAI-compatible HTTP, and Cursor Integrations.

Product overview (what / why / privacy / vs guardrails): **[../README.md](../README.md)**.

## 5-minute first run

```bash
# 1. Install
curl -fsSL https://sqreen.ai/install.sh | bash

# 2. Load config (sets MCP_POLICY_PATH)
source ~/.config/mcp-proxy/env

# 3. See the aha moment — allow, then block, with an explanation
mcp-proxy demo
```

The demo uses **synthetic paths only** (`/tmp/sqreen-demo-ok.txt` and `/tmp/sqreen-demo.ssh/id_rsa`). No real secrets or destructive commands.

## Wrap MCP (Cursor / Claude Desktop)

The installer patches known IDE `mcp.json` files to run servers through Sqreen and injects `MCP_POLICY_PATH`. Restart the IDE after install.

Manual wrap:

```json
{
  "mcpServers": {
    "filesystem": {
      "command": "/Users/YOU/.local/bin/mcp-proxy",
      "args": ["--", "run", "npx", "-y", "@modelcontextprotocol/server-filesystem", "."],
      "env": {
        "MCP_POLICY_PATH": "/Users/YOU/.config/mcp-proxy/mcp-policy.yaml"
      }
    }
  }
}
```

## OpenAI-compatible agents

```bash
source ~/.config/mcp-proxy/env
mcp-proxy serve --listen 127.0.0.1:8787 --upstream https://api.openai.com
export OPENAI_BASE_URL=http://127.0.0.1:8787/v1
```

## Anthropic Messages API

```bash
mcp-proxy serve --listen 127.0.0.1:8787 --upstream https://api.anthropic.com
# Point your Anthropic SDK base URL at http://127.0.0.1:8787
```

## First policy, block, and approval

| Experience | How |
|------------|-----|
| **First policy** | `~/.config/mcp-proxy/mcp-policy.yaml` (seeded by installer) |
| **First block** | `mcp-proxy demo` or agent `read_file` on a `.ssh`-shaped path |
| **First approval** | Tool `execute_bash` is `Confirm` — high-risk actions prompt on the Runtime TTY |

Edit policy, then re-run `mcp-proxy demo` or restart the IDE MCP server.

## CLI

```text
mcp-proxy demo
mcp-proxy --help
mcp-proxy --version
mcp-proxy -- run <mcp-server> [args...]
mcp-proxy serve [--listen ADDR] [--upstream URL]
```

## Uninstall / rollback

```bash
./scripts/uninstall.sh          # remove binary; keep config
./scripts/uninstall.sh --purge  # also delete ~/.config/mcp-proxy
```

Restore IDE configs from the newest `mcp.json.bak.*` beside the live file.

## Verify (developers)

```bash
cargo test -p mcp-proxy demo::
./scripts/e2e-policy-test.sh
./scripts/test-cursor-hook.sh
./scripts/run-benchmarks.sh          # Criterion enforcement suite — see ../../docs/BENCHMARKS.md
cargo test --test adversarial_security
```
