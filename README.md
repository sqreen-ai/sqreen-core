# Sqreen Core

Open-core **local-first RASP** for Model Context Protocol (MCP) tool calls.

- **mcp-proxy** — Rust stdio proxy (policy, DLP, threat intel, behavioral chains, `/dev/tty` gate)
- **mcp-proxy-sdk** — Wasm policy plugin SDK
- **install.sh** — one-line installer for macOS/Linux

```bash
curl -fsSL https://sqreen.ai/install.sh | bash
```

Cloud policy sync and SOC fleet management are part of [Sqreen Cloud SOC](https://sqreen.ai) (commercial). This repository runs fully offline by default.

## Verify

```bash
cd mcp-proxy && cargo test
bash mcp-proxy/scripts/e2e-policy-test.sh
bash mcp-proxy/scripts/e2e-behavioral-chain-test.sh
bash mcp-proxy/scripts/e2e-threat-intel-test.sh
```

## Security

See [SECURITY.md](.github/SECURITY.md). Report vulnerabilities to security@sqreen.ai — do not open public issues for security bugs.

## License

MIT — see [LICENSE](LICENSE).
