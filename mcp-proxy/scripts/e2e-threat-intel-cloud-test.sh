#!/usr/bin/env bash
# Smoke-test control-plane threat-intel sync → mcp-proxy IOC match.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
PROXY="${MCP_PROXY_BIN:-${HOME}/.local/bin/mcp-proxy}"
POLICY="${MCP_POLICY_PATH:-${ROOT}/mcp-proxy/mcp-policy.yaml}"
CP_DIR="${ROOT}/mcp-control-plane"
DB="$(mktemp)"
CP_PID=""

cleanup() {
  if [[ -n "$CP_PID" ]]; then
    kill "$CP_PID" 2>/dev/null || true
    wait "$CP_PID" 2>/dev/null || true
  fi
  rm -f "$DB" "$downstream" "$log_file" 2>/dev/null || true
}
trap cleanup EXIT

if [[ ! -x "$PROXY" ]]; then
  echo "error: mcp-proxy not found at $PROXY" >&2
  exit 1
fi

export MCP_CONTROL_PLANE_ADDR="127.0.0.1:18081"
export MCP_DB_PATH="$DB"
export MCP_DEVICE_TOKENS="dev-device-token-change-me"
export MCP_ADMIN_TOKENS="dev-admin-token-change-me"

CP_BIN="${MCP_CONTROL_PLANE_BIN:-}"
if [[ -n "$CP_BIN" && -x "$CP_BIN" ]]; then
  "$CP_BIN" &
  CP_PID=$!
else
  (cd "$CP_DIR" && go run .) &
  CP_PID=$!
fi

ready=0
for _ in $(seq 1 120); do
  if curl -sf "http://${MCP_CONTROL_PLANE_ADDR}/api/v1/threat-intel/sync" \
    -H "X-Device-Token: dev-device-token-change-me" \
    | grep -q 'evil-c2.example'; then
    ready=1
    break
  fi
  sleep 0.1
done

if [[ "$ready" -ne 1 ]]; then
  echo "error: control plane did not seed threat-intel feed" >&2
  exit 1
fi

downstream="$(mktemp)"
cat >"$downstream" <<'PY'
#!/usr/bin/env python3
import sys
for line in sys.stdin:
    sys.stdout.write(line)
    sys.stdout.flush()
PY
chmod +x "$downstream"

log_file="$(mktemp)"
export MCP_POLICY_PATH="$POLICY"
export MCP_PROXY_LOG="$log_file"
export MCP_CONTROL_PLANE_URL="http://${MCP_CONTROL_PLANE_ADDR}"
export MCP_DEVICE_TOKEN="dev-device-token-change-me"
export MCP_THREAT_INTEL_PATH="/dev/null"

set +e
printf '%s\n' \
  '{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"fetch","arguments":{"url":"https://evil-c2.example/sync-test"}}}' \
  | "$PROXY" -- run "$downstream" >/dev/null 2>&1 &
proxy_pid=$!

for _ in $(seq 1 40); do
  if [[ -f "$log_file" ]] && grep -qE 'THREAT_INTEL_IOC_MATCH|threat intel: IOC match' "$log_file" 2>/dev/null; then
    break
  fi
  sleep 0.15
done

kill "$proxy_pid" 2>/dev/null || true
wait "$proxy_pid" 2>/dev/null || true
set -e

if grep -qE 'THREAT_INTEL_IOC_MATCH|threat intel: IOC match' "$log_file"; then
  echo "✔  cloud-synced threat-intel IOC match detected"
else
  echo "✖  expected IOC match from control-plane sync" >&2
  [[ -f "$log_file" ]] && cat "$log_file" >&2 || echo "(no log file)" >&2
  exit 1
fi

echo "e2e cloud threat-intel sync test passed"
