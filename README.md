# Sqreen Core

Open-core local-first runtime enforcement for intercepted AI agent tool calls.

- **mcp-proxy** — Rust runtime for MCP and related agent tool-call paths
- **mcp-proxy-sdk** — Wasm plugin SDK
- **sqreen-contracts** — stable public wire contracts consumed by enterprise services
- **install.sh** — one-line installer for macOS/Linux

```bash
curl -fsSL https://sqreen.ai/install.sh | bash
```

Sqreen Core runs locally and continues to enforce without a control-plane round trip.
Optional enterprise features consume the public contracts in `sqreen-contracts/`, but
local policy enforcement remains authoritative on the developer machine.

This public tree is built **without** the `enterprise` Cargo feature (no cloud client,
remote-approval engine, or advanced behavior detectors).

## Verify

```bash
cd mcp-proxy && cargo test --locked --no-default-features
bash mcp-proxy/scripts/e2e-policy-test.sh
```

Enterprise cloud/behavioral suites live in the separate enterprise product and are not
part of this public tree.

## Security

See `SECURITY.md`. Report vulnerabilities to `security@sqreen.ai` rather than opening
public security issues.

## License

See `LICENSE`.
