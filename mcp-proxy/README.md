# Sqreen Core (`mcp-proxy`)

Local runtime enforcement for intercepted AI agent tool calls — MCP, OpenAI-compatible HTTP, and IDE Integrations.

Product overview (what / why / privacy / vs guardrails): **[../README.md](../README.md)**.  
Pilot path: **[../docs/QUICKSTART.md](../docs/QUICKSTART.md)**.

Binary name: **`mcp-proxy`**. Optional alias binary: **`sqreen`** (same CLI).

## 5-minute first run

```bash
# 1. Install
curl -fsSL https://sqreen.ai/install.sh | bash

# 2. Load config (sets MCP_POLICY_PATH)
source ~/.config/mcp-proxy/env

# 3. See the aha moment — allow, block, confirm/approval
mcp-proxy demo

# 4. Health
mcp-proxy status
mcp-proxy doctor
```

The demo uses **synthetic paths only** (`/tmp/sqreen-demo-ok.txt`, `/tmp/sqreen-demo.ssh/id_rsa`, benign `execute_bash`). No real secrets or destructive commands.

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

Check wraps: `mcp-proxy integrations`.

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
| **First approval** | Tool `execute_bash` is `Confirm` — local TTY or Cloud SOC when `SQREEN_APPROVAL_MODE=remote\|auto` |

Edit policy, then re-run `mcp-proxy demo` or restart the IDE MCP server. Do not disable the security baseline to clear blocks.

## CLI

```text
mcp-proxy demo
mcp-proxy status
mcp-proxy doctor
mcp-proxy integrations
mcp-proxy support-bundle [--out DIR]
mcp-proxy enroll --control-plane URL --device-token TOKEN [--device-id ID] [--org-id ORG]
mcp-proxy --help
mcp-proxy --version
mcp-proxy -- run <mcp-server> [args...]
mcp-proxy serve [--listen ADDR] [--upstream URL]

sqreen …                    # same commands (alias binary)
```

`enroll` writes `~/.config/mcp-proxy/env` (mode `0600`) and never echoes the device token.  
`support-bundle` writes a redacted diagnostics folder — inspect before sharing.

## Uninstall / rollback

```bash
./scripts/uninstall.sh          # remove binary; keep config
./scripts/uninstall.sh --purge  # also delete ~/.config/mcp-proxy
```

Restore IDE configs from the newest `mcp.json.bak.*` beside the live file.

## Verify (developers)

```bash
cargo test --lib pilot -- --nocapture
cargo test --lib demo -- --nocapture
./scripts/pilot-onboarding-smoke.sh
./scripts/e2e-policy-test.sh
./scripts/test-cursor-hook.sh
./scripts/run-benchmarks.sh          # Criterion enforcement suite — see ../../docs/BENCHMARKS.md
cargo test --test adversarial_security
```
