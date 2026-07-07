# Announcing Sqreen Core — MIT open source RASP for MCP

**Today we're open-sourcing the local security engine behind Sqreen.ai.**

[Sqreen Core](https://github.com/sqreen-ai/sqreen-core) is a Rust stdio proxy that sits between your AI coding agent and MCP tool servers. It inspects every JSON-RPC frame in under a millisecond — blocking sensitive file reads, masking secrets, matching IOC feeds, and enforcing behavioral chains — **fully on the developer laptop, with no cloud dependency.**

## What's in the repo

| Component | Description |
|-----------|-------------|
| **mcp-proxy** | Production RASP proxy (policy, DLP, Wasm plugins, `/dev/tty` gate) |
| **mcp-proxy-sdk** | Wasm policy plugin SDK |
| **install.sh** | One-line installer for macOS and Linux |

```bash
curl -fsSL https://sqreen.ai/install.sh | bash
```

Pre-built binaries for **v0.1.11** are on the [Releases](https://github.com/sqreen-ai/sqreen-core/releases) page.

### v0.1.11 — proxy lifecycle + Cursor hooks

- **Run mode no longer hangs** after one-shot MCP servers exit (stdin EOF or downstream stdout close).
- **Cursor project hooks** tolerate canceled/empty payloads; `failClosed` defaults to `false` so hook infrastructure glitches do not block the agent.

### v0.1.10 — threat intel hardening

IoC feed matches now **unconditionally block** the request (score 100), with no `/dev/tty` gate. A known-bad hash or domain from the threat-intel feed is treated as a hard stop, not a risk penalty.

## What's not in the repo (Sqreen Cloud)

Fleet-wide policy orchestration, threat-intel distribution, device-token enrollment, and the SOC console remain commercial. If you need centralized governance across hundreds of developer machines, see [sqreen.ai](https://sqreen.ai) for Cloud SOC.

## Why open core

AI agents run with filesystem and shell access on real developer machines. Security tooling for MCP shouldn't be a black box. We want researchers, platform teams, and the community to audit, extend, and harden the proxy — while we sell the control plane that makes it scale across an org.

## Get involved

- ⭐ Star the repo: [github.com/sqreen-ai/sqreen-core](https://github.com/sqreen-ai/sqreen-core)
- 🐛 Report bugs via GitHub Issues (security issues → security@sqreen.ai)
- 🔧 PRs welcome — see `cargo test` and e2e scripts in the README

**License:** MIT
