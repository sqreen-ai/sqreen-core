# Sqreen Core — Quickstart

Primary path for design-partner pilots. Every command below matches the real CLI (`mcp-proxy`, alias `sqreen`).

## 1. Install

```bash
curl -fsSL https://sqreen.ai/install.sh | bash
source ~/.config/mcp-proxy/env   # PATH + MCP_POLICY_PATH
```

From source:

```bash
cd mcp-proxy && cargo build --release
export PATH="$PWD/target/release:$PATH"
```

## 2. First protected action (demo)

```bash
mcp-proxy demo
# or: sqreen demo
```

Shows **allow → block → confirm/approval** on synthetic paths only (no real secrets, no shell execution).

## 3. Protect an agent

**MCP (Cursor / Claude Desktop)** — installer may wrap `mcp.json` automatically. Manual:

```bash
mcp-proxy -- run npx -y @modelcontextprotocol/server-filesystem .
```

**HTTP agents (OpenAI-compatible):**

```bash
mcp-proxy serve --listen 127.0.0.1:8787 --upstream https://api.openai.com
export OPENAI_BASE_URL=http://127.0.0.1:8787/v1
```

## 4. Status and doctor

```bash
mcp-proxy status          # ACTIVE/INACTIVE, policy, posture, cloud, integrations
mcp-proxy doctor          # PASS / WARN / FAIL with remediation
mcp-proxy integrations    # Cursor / Claude wrap, control plane, OPENAI_BASE_URL
mcp-proxy update --check  # compare to signed release channel (no auto-install)
mcp-proxy version         # or: mcp-proxy --version
```

## 5. Optional — enroll for Cloud SOC

Mint a device token in the dashboard (Agent Identities), then:

```bash
mcp-proxy enroll \
  --control-plane https://YOUR_CONTROL_PLANE \
  --device-token YOUR_TOKEN \
  --device-id YOUR_DEVICE_ID

source ~/.config/mcp-proxy/env
mcp-proxy doctor
```

The token is written to `~/.config/mcp-proxy/env` with mode `0600` and is **never printed**.

For remote approvals on Confirm / destructive-shaped actions:

```bash
export SQREEN_APPROVAL_MODE=remote   # or auto
```

## 6. Support bundle

```bash
mcp-proxy support-bundle              # writes under /tmp
mcp-proxy support-bundle --out ./out  # optional path
```

Inspect the folder before sharing — secrets are redacted as `[SET]` / `[EMPTY]`.

## Smoke test (developers)

```bash
cd mcp-proxy
./scripts/pilot-onboarding-smoke.sh
cargo test --lib pilot -- --nocapture
cargo test --lib demo -- --nocapture
```

## Next reading

| Doc | Purpose |
|-----|---------|
| [PILOT_CHECKLIST.md](PILOT_CHECKLIST.md) | Pre-pilot / Day 1 / Week 1 / exit criteria |
| [PILOT_DEPLOYMENT.md](PILOT_DEPLOYMENT.md) | Self-hosted control plane + dashboard |
| [DESIGN_PARTNER.md](DESIGN_PARTNER.md) | Recommended pilot profile |
| [PRIVACY.md](PRIVACY.md) | What stays local vs cloud |
| [REMOTE_APPROVALS.md](REMOTE_APPROVALS.md) | Remote human gate |
| [../mcp-proxy/README.md](../mcp-proxy/README.md) | Full CLI notes |
