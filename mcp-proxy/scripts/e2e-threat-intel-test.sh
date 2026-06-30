#!/usr/bin/env bash
# Smoke-test local threat-intel IOC matching on a tools/call payload.
set -euo pipefail

PROXY="${MCP_PROXY_BIN:-${HOME}/.local/bin/mcp-proxy}"
POLICY="${MCP_POLICY_PATH:-${HOME}/.config/mcp-proxy/mcp-policy.yaml}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
IOC_FILE="${MCP_THREAT_INTEL_FIXTURE:-${SCRIPT_DIR}/../test-fixtures/threat-intel-e2e.txt}"

if [[ ! -x "$PROXY" ]]; then
  echo "error: mcp-proxy not found at $PROXY" >&2
  exit 1
fi

if [[ ! -f "$POLICY" ]]; then
  echo "error: policy not found at $POLICY" >&2
  exit 1
fi

if [[ ! -f "$IOC_FILE" ]]; then
  echo "error: IOC fixture not found at $IOC_FILE" >&2
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
rm -f "$log_file"

export MCP_POLICY_PATH="$POLICY"
export MCP_PROXY_LOG="$log_file"
export MCP_THREAT_INTEL_PATH="$IOC_FILE"
export MCP_CONTROL_PLANE_URL=""

set +e
printf '%s\n' \
  '{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"fetch","arguments":{"url":"https://evil-c2.example/exfil"}}}' \
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
  echo "✔  threat-intel IOC match detected"
else
  echo "✖  expected THREAT_INTEL_IOC_MATCH or threat intel log line" >&2
  [[ -f "$log_file" ]] && cat "$log_file" >&2 || echo "(no log file)" >&2
  rm -f "$downstream" "$log_file"
  exit 1
fi

rm -f "$downstream" "$log_file"
echo "e2e threat-intel test passed"
