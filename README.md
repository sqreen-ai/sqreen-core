# Sqreen Core

[![MIT License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Release](https://img.shields.io/github/v/release/sdk-bens/sqreen-core)](https://github.com/sdk-bens/sqreen-core/releases)

**Open-core local-first RASP** for Model Context Protocol (MCP) tool calls — sub-millisecond policy enforcement on developer laptops.

| Package | Role |
|---------|------|
| **mcp-proxy** | Rust stdio proxy — policy, DLP, threat intel, behavioral chains, `/dev/tty` gate |
| **mcp-proxy-sdk** | Wasm policy plugin SDK |
| **install.sh** | One-line installer for macOS/Linux |

```bash
curl -fsSL https://sqreen.ai/install.sh | bash
```

Runs **fully offline** by default. Cloud policy sync and SOC fleet management are part of [Sqreen Cloud](https://sqreen.ai) (commercial).

## Quick start

```bash
# From release binary (recommended)
curl -fsSL https://sqreen.ai/install.sh | bash

# From source
git clone https://github.com/sdk-bens/sqreen-core.git
cd sqreen-core/mcp-proxy && cargo build --release
```

Wire the proxy into your MCP client config — see [mcp-proxy/README.md](mcp-proxy/README.md).

## Verify

See [docs/CLEAN_INSTALL.md](docs/CLEAN_INSTALL.md) for post-install checks.

```bash
cd mcp-proxy && cargo test
bash mcp-proxy/scripts/smoke-test-install.sh   # quick post-install check (no Cursor)
bash mcp-proxy/scripts/e2e-policy-test.sh
bash mcp-proxy/scripts/e2e-behavioral-chain-test.sh
bash mcp-proxy/scripts/e2e-threat-intel-test.sh
```

## Architecture

```
AI Agent ──► mcp-proxy (local RASP) ──► MCP tool server
                  │
                  └── optional: Sqreen Cloud policy sync
```

## Commercial (Sqreen Cloud)

- Central policy orchestration
- Threat intel distribution
- Device-token fleet enrollment
- SOC console at [console.sqreen.ai](https://console.sqreen.ai)

Contact [sdk@sqreen.ai](mailto:sdk@sqreen.ai) for enterprise/self-hosted control plane.

## Security

See [SECURITY.md](.github/SECURITY.md). Report vulnerabilities to **security@sqreen.ai** — do not open public issues for security bugs.

## License

MIT — see [LICENSE](LICENSE).

## Announcement

Read [ANNOUNCEMENT.md](ANNOUNCEMENT.md) for the open-source launch post.
