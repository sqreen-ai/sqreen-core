# Contributing to Sqreen Core

Thanks for helping improve local runtime security for AI agents.

## Before you start

1. Read the root [README.md](README.md) (product model + local-first defaults).
2. For edge runtime work, skim [mcp-proxy/README.md](mcp-proxy/README.md) and [docs/AGENT_EXECUTION_GATEWAY.md](docs/AGENT_EXECUTION_GATEWAY.md).
3. New agent runtimes belong in `mcp-proxy/src/adapters/` — follow [docs/PROVIDER_ADAPTERS.md](docs/PROVIDER_ADAPTERS.md). Do not add provider-specific branches to the gateway core.
4. Security-affecting changes: update [docs/FAILURE_MODES.md](docs/FAILURE_MODES.md) (and related public Core docs) in the same PR. Do not claim protections the code does not provide.

## Development setup

```bash
# Edge runtime (open-core features)
cd mcp-proxy
cargo test --locked --no-default-features
cargo run --no-default-features -- demo

# Wasm policy plugin SDK
cd ../mcp-proxy-sdk
cargo test --locked
```

Useful scripts under `mcp-proxy/scripts/`:

- `e2e-policy-test.sh`
- `e2e-http-agent-firewall.sh`
- `e2e-threat-intel-test.sh`
- `test-cursor-hook.sh`

## Pull requests

- Keep changes focused; prefer one concern per PR.
- Include tests for behavior changes in the policy / gateway / adapters.
- Do not commit secrets or production credentials.
- Prefer local-first defaults; do not add network calls that run without an
  explicit operator opt-in.
- Avoid unverified marketing claims in docs; describe what the code does.

Enterprise product development (hosted management, SOC, fleet workflows) occurs
in a separate repository and is out of scope for this Core contribution guide.

## Security issues

Do **not** open a public issue for vulnerabilities. Email **security@sqreen.ai** — see [SECURITY.md](SECURITY.md).

## Code of conduct

Be respectful. Assume good faith. Prefer clear, technical feedback over style bikeshedding.
