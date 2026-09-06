# Sqreen Core — Quickstart

Local-first runtime enforcement for intercepted AI agent tool calls.
Every command matches the real CLI (`mcp-proxy`, alias `sqreen`).

## 1. Install

```bash
curl -fsSL https://sqreen.ai/install.sh | bash
source ~/.config/mcp-proxy/env   # PATH + MCP_POLICY_PATH
```

The installer **auto-wraps** supported Cursor/IDE MCP configs when it finds them.

- `Cursor integration: CONFIGURED` → skip integrate; restart Cursor next
- `Cursor integration: NOT CONFIGURED` → run step 3

`CONFIGURED` wrap ≠ `VERIFIED_ACTIVE`. Install alone does not mean traffic is protected.

## 2. Local demo (policy only)

```bash
mcp-proxy demo
```

Shows **ALLOW → DENY → optional local Confirm** on synthetic `/tmp` paths.
No Cloud, enrollment, or remote approval is required.
This proves the local policy control point — not that Cursor traffic is wrapped.

## 3. Integrate Cursor — only if NOT CONFIGURED

```bash
mcp-proxy integrate cursor
```

Wraps `~/.cursor/mcp.json` through `mcp-proxy`. Config alone is **CONFIGURED**, not verified.

## 4. Restart / reload

Restart Cursor, or Command Palette → **MCP: Restart Servers** / Reload Window.

## 5. Observe ALLOW (real wrapped traffic)

In Cursor: ask the agent to read `/tmp/sqreen-demo-ok.txt`.

Optional gateway self-check (does **not** mint `VERIFIED_ACTIVE`):

```bash
mcp-proxy prove
```

## 6. Observe DENY

Ask the agent to read:

```text
/tmp/sqreen-demo.ssh/id_rsa
```

Synthetic credential-shaped path under `/tmp` — **not** your real `~/.ssh`.
Expect a DENY with WHAT / WHY / RULE.

## 7. Local status / audit

```bash
mcp-proxy status
mcp-proxy integrations
mcp-proxy support-bundle
```

Expect after real wrap traffic:

- Policy: **LOADED**
- Runtime coverage: **VERIFIED_ACTIVE**
- Protected traffic: **VERIFIED**

Local approval defaults to the terminal (`SQREEN_APPROVAL_MODE=local`).

## 8. Developer smoke tests

```bash
cd mcp-proxy
cargo test --locked --no-default-features --lib
bash scripts/e2e-policy-test.sh
bash scripts/e2e-threat-intel-test.sh
```

## Next reading

| Doc | Purpose |
|-----|---------|
| [PRIVACY.md](PRIVACY.md) | What stays local |
| [FAILURE_MODES.md](FAILURE_MODES.md) | Broken-control behavior |
| [RELEASE_INTEGRITY.md](RELEASE_INTEGRITY.md) | Installer verification |
| [POLICY_SCHEMA.md](POLICY_SCHEMA.md) | Policy document shape |
| [../mcp-proxy/README.md](../mcp-proxy/README.md) | Full CLI notes |

Enterprise management and remote workflows are available separately.
