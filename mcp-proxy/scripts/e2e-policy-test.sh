#!/usr/bin/env bash
# Smoke-test mcp-proxy policy enforcement without Cursor.
# Sends a blocked tools/call and expects a JSON-RPC error (no passthrough).
set -euo pipefail

PROXY="${MCP_PROXY_BIN:-${HOME}/.local/bin/mcp-proxy}"
POLICY="${MCP_POLICY_PATH:-${HOME}/.config/mcp-proxy/mcp-policy.yaml}"
PASS=0

if [[ ! -x "$PROXY" ]]; then
  echo "error: mcp-proxy not found at $PROXY" >&2
  exit 1
fi

if [[ ! -f "$POLICY" ]]; then
  echo "error: policy not found at $POLICY" >&2
  exit 1
fi

# Passthrough downstream — if the frame reaches the server, the test fails.
downstream="$(mktemp)"
cat >"$downstream" <<'PY'
#!/usr/bin/env python3
import sys
for line in sys.stdin:
    sys.stdout.write(line)
    sys.stdout.flush()
PY
chmod +x "$downstream"

blocked_frame='{"jsonrpc":"2.0","id":42,"method":"tools/call","params":{"name":"read_file","arguments":{"path":"~/.ssh/id_rsa"}}}'
blocked_get_file_info='{"jsonrpc":"2.0","id":43,"method":"tools/call","params":{"name":"get_file_info","arguments":{"path":"/Users/seddik/.ssh/id_rsa"}}}'
output="$(mktemp)"

export MCP_POLICY_PATH="$POLICY"
export MCP_PROXY_LOG="${TMPDIR:-/tmp}/mcp-proxy-e2e.log"
# When set, mcp-proxy loads policy from control plane (matches Cursor mcp.json).
export MCP_CONTROL_PLANE_URL="${MCP_CONTROL_PLANE_URL:-}"
export MCP_DEVICE_TOKEN="${MCP_DEVICE_TOKEN:-dev-device-token-change-me}"

set +e
printf '%s\n' "$blocked_frame" | "$PROXY" -- run "$downstream" >"$output" 2>/dev/null &
proxy_pid=$!

for _ in $(seq 1 20); do
  if grep -q '"id":42' "$output" 2>/dev/null; then
    break
  fi
  sleep 0.1
done

kill "$proxy_pid" 2>/dev/null || true
wait "$proxy_pid" 2>/dev/null || true
set -e

if grep -q 'access denied\|blocked\|error' "$output"; then
  echo "✔  policy blocked ~/.ssh read_file (tools/call id=42)"
  PASS=1
else
  echo "✖  expected block response for read_file, got:" >&2
  cat "$output" >&2
  exit 1
fi

output_info="$(mktemp)"
set +e
printf '%s\n' "$blocked_get_file_info" | "$PROXY" -- run "$downstream" >"$output_info" 2>/dev/null &
proxy_pid=$!
for _ in $(seq 1 20); do
  if grep -q '"id":43' "$output_info" 2>/dev/null; then
    break
  fi
  sleep 0.1
done
kill "$proxy_pid" 2>/dev/null || true
wait "$proxy_pid" 2>/dev/null || true
set -e

if grep -q 'get_file_info.*blocked\|blocked.*get_file_info' "$output_info"; then
  echo "✔  policy blocked .ssh get_file_info (tools/call id=43)"
else
  echo "✖  expected block response for get_file_info, got:" >&2
  cat "$output_info" >&2
  exit 1
fi

allowed_frame='{"jsonrpc":"2.0","id":99,"method":"tools/call","params":{"name":"read_file","arguments":{"path":"/tmp"}}}'
output2="$(mktemp)"

set +e
printf '%s\n' "$allowed_frame" | "$PROXY" -- run "$downstream" >"$output2" 2>/dev/null &
proxy_pid=$!
for _ in $(seq 1 20); do
  if grep -q '"id":99' "$output2" 2>/dev/null; then
    break
  fi
  sleep 0.1
done
kill "$proxy_pid" 2>/dev/null || true
wait "$proxy_pid" 2>/dev/null || true
set -e

if grep -q '"id":99' "$output2"; then
  echo "✔  allowed /tmp read forwarded (tools/call id=99)"
else
  echo "✖  expected passthrough for allowed path, got:" >&2
  cat "$output2" >&2
  exit 1
fi

rm -f "$downstream" "$output" "$output2" "$output_info"
echo "e2e policy test passed"
