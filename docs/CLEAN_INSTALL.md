# Clean-install verification

Run after `curl -fsSL https://sqreen.ai/install.sh | bash` or a release binary install.

## Quick smoke test (no Cursor)

From a git clone:

```bash
bash mcp-proxy/scripts/smoke-test-install.sh
```

Or with explicit paths:

```bash
export MCP_PROXY_BIN="${HOME}/.local/bin/mcp-proxy"
export MCP_POLICY_PATH="${HOME}/.config/mcp-proxy/mcp-policy.yaml"
bash mcp-proxy/scripts/smoke-test-install.sh
```

**Checks:**

1. Binary exists and executes
2. Policy blocks `read_file` on `~/.ssh/id_rsa`
3. Proxy exits within 5s after downstream exits (no hang regression)

## Full local e2e (from clone)

```bash
cd mcp-proxy
cargo build --release
export MCP_PROXY_BIN="$PWD/target/release/mcp-proxy"
export MCP_POLICY_PATH="$PWD/mcp-policy.yaml"

bash scripts/smoke-test-install.sh
bash scripts/e2e-policy-test.sh
bash scripts/e2e-behavioral-chain-test.sh
bash scripts/e2e-threat-intel-test.sh
```

## Cursor / Claude Desktop

1. Restart the IDE after install (config is patched by `install.sh`).
2. Trigger an MCP tool call that should block (e.g. read `~/.ssh/id_rsa`).
3. Confirm the proxy returns an access-denied JSON-RPC error, not a hang.

## CI

The smoke test runs on every push in `.github/workflows/test.yml` after the release build.
