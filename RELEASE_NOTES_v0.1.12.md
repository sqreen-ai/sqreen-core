# Sqreen Core v0.1.12 (draft)

**Theme:** Sqreen Core becomes a focused local-first open-source enforcement runtime.

## Highlights

- **Local-first by default.** Public Core builds with `--no-default-features` (`default = []`). Local MCP stdio wrap, policy evaluation, baseline/DLP, and local Confirm approvals remain the Day-1 path.
- **Open and useful without Cloud.** Install, wrap Cursor/MCP, run `demo` / `status` / `doctor`, and enforce ALLOW/DENY with the seeded local policy — no control-plane enrollment required.
- **Enterprise separately.** Cloud enrollment, remote approvals, and advanced Enterprise detectors ship in private Enterprise builds (`--features enterprise`), not in public Core release artifacts.
- **No history rewrite.** Existing tags (`v0.1.9`–`v0.1.11`) and prior public history remain. This release is a forward cut from verified main.
- **Installer unchanged in intent.** `curl -fsSL https://sqreen.ai/install.sh | bash` continues to download signed Core release assets only, with fail-closed signature verification.

## What stays the same

- Local MCP wrap (`mcp-proxy -- run …`) — production-supported
- Cursor/MCP wrap path — pilot-supported as documented
- Policy file location (`~/.config/mcp-proxy/mcp-policy.yaml`)
- Local ALLOW / DENY / Confirm behavior and mandatory baseline
- Signed release verification (Ed25519 manifest + public key)
- Fail-closed installer verification (missing/invalid signature aborts)

## What changes for some users

If you previously used a build that enabled Cloud/Enterprise commands by default:

| Area | Change |
|------|--------|
| `mcp-proxy enroll` | Not available in public open-core builds (Enterprise-only) |
| `mcp-proxy test-remote-approval` / remote approval mode | Enterprise-only |
| Cloud env (`MCP_CONTROL_PLANE_URL`, device token) | Ignored / unused for Enterprise features in public Core |
| CLI `--help` | Enterprise command block appears only on Enterprise builds |
| Package version | Reports `0.1.12` (aligned with this tag) |

Local enforcement, installer, and policy remain the supported open-core path.

## Compatibility notes

See `RELEASE_READINESS_v0.1.12.md` for the full NO CHANGE / COMPATIBLE / BREAKING / ENTERPRISE-ONLY classification.

## Upgrade

```bash
curl -fsSL https://sqreen.ai/install.sh | bash -s -- --version v0.1.12
# or: MCP_PROXY_VERSION=v0.1.12 bash install.sh
source ~/.config/mcp-proxy/env
mcp-proxy --version   # expect mcp-proxy 0.1.12
mcp-proxy status
mcp-proxy doctor
```

Existing `~/.config/mcp-proxy` policy and Cursor wrap configuration are preserved across upgrades.
