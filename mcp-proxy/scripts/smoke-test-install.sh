#!/usr/bin/env bash
# Clean-install smoke test for mcp-proxy (no Cursor required).
#
# Verifies:
#   1. Binary exists and runs
#   2. Policy blocks a sensitive path
#   3. Proxy exits promptly after downstream exits (no hang)
#
# Usage:
#   ./scripts/smoke-test-install.sh
#   MCP_PROXY_BIN=~/.local/bin/mcp-proxy ./scripts/smoke-test-install.sh
set -euo pipefail

PROXY="${MCP_PROXY_BIN:-${HOME}/.local/bin/mcp-proxy}"
POLICY="${MCP_POLICY_PATH:-${HOME}/.config/mcp-proxy/mcp-policy.yaml}"
MAX_WAIT_SECS="${SMOKE_MAX_WAIT_SECS:-5}"

if [[ ! -x "$PROXY" ]]; then
  echo "✖  mcp-proxy not found at $PROXY" >&2
  echo "    Install: curl -fsSL https://sqreen.ai/install.sh | bash" >&2
  exit 1
fi

if [[ ! -f "$POLICY" ]]; then
  echo "✖  policy not found at $POLICY" >&2
  exit 1
fi

downstream="$(mktemp)"
cat >"$downstream" <<'PY'
#!/usr/bin/env python3
import sys
for line in sys.stdin:
    sys.stdout.write(line)
    sys.stdout.flush()
    break
PY
chmod +x "$downstream"

blocked='{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"read_file","arguments":{"path":"~/.ssh/id_rsa"}}}'
output="$(mktemp)"

export MCP_POLICY_PATH="$POLICY"
export MCP_PROXY_LOG="${TMPDIR:-/tmp}/mcp-proxy-smoke.log"
unset MCP_CONTROL_PLANE_URL MCP_DEVICE_TOKEN 2>/dev/null || true

start_epoch=$(date +%s)
printf '%s\n' "$blocked" | "$PROXY" -- run python3 "$downstream" >"$output" 2>/dev/null &
proxy_pid=$!

while kill -0 "$proxy_pid" 2>/dev/null; do
  if grep -q '"id":1' "$output" 2>/dev/null; then
    break
  fi
  now=$(date +%s)
  if (( now - start_epoch >= MAX_WAIT_SECS )); then
    kill "$proxy_pid" 2>/dev/null || true
    echo "✖  proxy did not exit within ${MAX_WAIT_SECS}s (hang regression)" >&2
    exit 1
  fi
  sleep 0.1
done

wait "$proxy_pid" 2>/dev/null || true
elapsed=$(( $(date +%s) - start_epoch ))

if ! grep -qE 'access denied|blocked|error' "$output"; then
  echo "✖  expected policy block response, got:" >&2
  cat "$output" >&2
  exit 1
fi

echo "✔  policy blocked ~/.ssh read_file"
echo "✔  proxy exited in ${elapsed}s (no hang)"
rm -f "$downstream" "$output"
echo "smoke test passed"
