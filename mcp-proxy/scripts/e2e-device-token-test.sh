#!/usr/bin/env bash
# Smoke-test device token mint → edge proxy policy sync over cloud control plane.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
PROXY="${MCP_PROXY_BIN:-${HOME}/.local/bin/mcp-proxy}"
POLICY="${MCP_POLICY_PATH:-${ROOT}/mcp-proxy/mcp-policy.yaml}"
CP_DIR="${ROOT}/mcp-control-plane"
DB="$(mktemp)"
CP_BIN="$(mktemp -t sqreen-cp-e2e.XXXXXX)"
CP_PID=""
MINTED_TOKEN=""
downstream=""
log_file=""

cleanup() {
  if [[ -n "$CP_PID" ]]; then
    kill "$CP_PID" 2>/dev/null || true
    wait "$CP_PID" 2>/dev/null || true
  fi
  rm -f "$DB" "$CP_BIN" "$downstream" "$log_file" 2>/dev/null || true
}
trap cleanup EXIT

if [[ ! -x "$PROXY" ]]; then
  PROXY="${ROOT}/mcp-proxy/target/release/mcp-proxy"
fi
if [[ ! -x "$PROXY" ]]; then
  echo "error: mcp-proxy not found (set MCP_PROXY_BIN)" >&2
  exit 1
fi

echo "==> building control plane for e2e"
( cd "$CP_DIR" && go build -o "$CP_BIN" . )

export MCP_CONTROL_PLANE_ADDR="127.0.0.1:28182"
export MCP_DB_PATH="$DB"
export MCP_DEVICE_TOKENS="bootstrap-env-token"
export MCP_ADMIN_TOKENS="dev-admin-token-change-me"
export MCP_MAX_ACTIVE_DEVICE_TOKENS_PER_ORG="25"

env MCP_CONTROL_PLANE_ADDR="$MCP_CONTROL_PLANE_ADDR" \
  MCP_DB_PATH="$MCP_DB_PATH" \
  MCP_DEVICE_TOKENS="$MCP_DEVICE_TOKENS" \
  MCP_ADMIN_TOKENS="$MCP_ADMIN_TOKENS" \
  MCP_MAX_ACTIVE_DEVICE_TOKENS_PER_ORG="$MCP_MAX_ACTIVE_DEVICE_TOKENS_PER_ORG" \
  "$CP_BIN" &
CP_PID=$!

ready=0
for _ in $(seq 1 120); do
  if curl -sf "http://${MCP_CONTROL_PLANE_ADDR}/health" >/dev/null 2>&1 \
    && curl -sf "http://${MCP_CONTROL_PLANE_ADDR}/api/v1/device-tokens" \
      -H "X-Admin-Token: dev-admin-token-change-me" \
      | grep -q '"records"'; then
    ready=1
    break
  fi
  sleep 0.1
done

if [[ "$ready" -ne 1 ]]; then
  echo "✖  control plane did not become ready" >&2
  exit 1
fi

MINTED_TOKEN="$(
  curl -sf -X POST "http://${MCP_CONTROL_PLANE_ADDR}/api/v1/device-tokens" \
    -H "X-Admin-Token: dev-admin-token-change-me" \
    -H "Content-Type: application/json" \
    -d '{"org_id":"e2e-org","label":"e2e-laptop"}' \
    | python3 -c 'import json,sys; print(json.load(sys.stdin)["token"])'
)"

if [[ -z "$MINTED_TOKEN" ]]; then
  echo "✖  failed to mint device token" >&2
  exit 1
fi
echo "✔  minted device token (${MINTED_TOKEN:0:12}…)"

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
export MCP_CONTROL_PLANE_URL="http://${MCP_CONTROL_PLANE_ADDR}"
export MCP_DEVICE_TOKEN="$MINTED_TOKEN"
export MCP_THREAT_INTEL_PATH="/dev/null"

set +e
printf '%s\n' \
  '{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"read_file","arguments":{"path":"/tmp/sqreen-device-token-e2e"}}}' \
  | "$PROXY" -- run "$downstream" >/dev/null 2>&1 &
proxy_pid=$!

for _ in $(seq 1 40); do
  if [[ -f "$log_file" ]] && grep -q 'policy sync\|risk score=' "$log_file" 2>/dev/null; then
    break
  fi
  sleep 0.15
done

kill "$proxy_pid" 2>/dev/null || true
wait "$proxy_pid" 2>/dev/null || true
set -e

if grep -q 'risk score=' "$log_file"; then
  echo "✔  minted token authenticated proxy cloud sync"
else
  echo "✖  expected proxy log activity with minted token" >&2
  [[ -f "$log_file" ]] && cat "$log_file" >&2 || echo "(no log file)" >&2
  exit 1
fi

echo "e2e device token test passed"
