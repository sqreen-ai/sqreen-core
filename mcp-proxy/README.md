# Sqreen Core (`mcp-proxy`)

Local runtime enforcement for intercepted AI agent tool calls — **MCP stdio wrap** (primary), **OpenAI-compatible HTTP** (pilot limited), and optional IDE hooks (experimental / secondary).

Product overview (what / why / privacy / vs guardrails): **[../README.md](../README.md)**.  
Pilot path: **[../docs/QUICKSTART.md](../docs/QUICKSTART.md)**.  
Support matrix: **[../docs/PROVIDER_ADAPTERS.md](../docs/PROVIDER_ADAPTERS.md)**.

Binary name: **`mcp-proxy`**. Optional alias binary: **`sqreen`** (same CLI).

## 5-minute first run (Cursor + MCP)

```bash
# 1. Install (auto-wraps Cursor MCP when a supported mcp.json exists)
curl -fsSL https://sqreen.ai/install.sh | bash
source ~/.config/mcp-proxy/env
# Read post-install: Cursor integration CONFIGURED vs NOT CONFIGURED

# 2. Policy demo (not traffic proof)
mcp-proxy demo

# 3. Only if NOT CONFIGURED (also repair / re-run):
# mcp-proxy integrate cursor

# 4. Restart Cursor / reload MCP, then one real tools/call in Cursor
mcp-proxy integrations && mcp-proxy status   # VERIFIED_ACTIVE after real wrap traffic
```

`demo` uses **synthetic paths only**. It does **not** mean Cursor is protected.
`CONFIGURED` wrap ≠ `VERIFIED_ACTIVE` — real agent traffic must be observed first.
`prove` is an optional gateway self-check and does **not** mint `VERIFIED_ACTIVE`.

## Wrap MCP (Cursor / Claude Desktop)

**Day-1 primary:** installer auto-wrap when possible. Use integrate when install did not configure Cursor, or to repair:

```bash
mcp-proxy integrate cursor
```

Then restart Cursor / reload MCP. Manual shape:

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

Check wraps: `mcp-proxy integrations`. Verify active traffic: `mcp-proxy status` (after a real tools/call).

Generic MCP stdio (`mcp-proxy -- run …`) is **PRODUCTION_SUPPORTED**. Cursor Core wrap is the same engine, labeled **PILOT_SUPPORTED** for Day-1. Cursor IDE hooks are **EXPERIMENTAL / SECONDARY** and do not mint `VERIFIED_ACTIVE`.

## OpenAI-compatible agents (pilot limited)

```bash
source ~/.config/mcp-proxy/env
mcp-proxy serve --listen 127.0.0.1:8787 --upstream https://api.openai.com
export OPENAI_BASE_URL=http://127.0.0.1:8787/v1
```

**PILOT_SUPPORTED — LIMITED:** non-streaming Chat Completions only. Policy runs on **response** `tool_calls` before the client executes them — not equivalent to MCP pre-tool-call blocking. Streaming and the Responses API are unsupported.

## Anthropic Messages (experimental)

`AnthropicAdapter` exists for tests and a future Messages proxy. Pointing an Anthropic SDK at `mcp-proxy serve` does **not** enforce Messages `tool_use` today — do not advertise this as a supported HTTP path.
## First policy, block, and approval

| Experience | How |
|------------|-----|
| **First policy** | `~/.config/mcp-proxy/mcp-policy.yaml` (seeded by installer) |
| **First block** | `mcp-proxy demo` or agent `read_file` on a `.ssh`-shaped path |
| **First approval** | Tool `execute_bash` is `Confirm` — local TTY / stdin by default |

Edit policy, then re-run `mcp-proxy demo` or restart the IDE MCP server. Do not disable the security baseline to clear blocks.

## CLI

```text
mcp-proxy demo
mcp-proxy integrate cursor
mcp-proxy prove
mcp-proxy status
mcp-proxy doctor
mcp-proxy integrations
mcp-proxy support-bundle [--out DIR]
mcp-proxy --help
mcp-proxy --version
mcp-proxy -- run <mcp-server> [args...]
mcp-proxy serve [--listen ADDR] [--upstream URL]

sqreen …                    # same commands (alias binary)
```

`support-bundle` writes a redacted diagnostics folder — inspect before sharing.
Enterprise management commands (when present) are documented separately for Enterprise builds.

## Uninstall / rollback

```bash
./scripts/uninstall.sh          # remove binary; keep config
./scripts/uninstall.sh --purge  # also delete ~/.config/mcp-proxy
```

Restore IDE configs from the newest `mcp.json.bak.*` beside the live file.

## Verify (developers)

```bash
cargo test --lib adapters::framework -- --nocapture
./scripts/check-integration-claims.sh
cargo test --lib pilot -- --nocapture
cargo test --lib demo -- --nocapture
./scripts/pilot-onboarding-smoke.sh
./scripts/e2e-policy-test.sh
./scripts/test-cursor-hook.sh
./scripts/run-benchmarks.sh          # Criterion enforcement suite — see ../../docs/BENCHMARKS.md
cargo test --test adversarial_security
```
