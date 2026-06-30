#!/usr/bin/env bash
# Verify Cursor hook denials emit telemetry to mcp-control-plane.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
HOOK="${ROOT}/.cursor/hooks/block-sensitive-paths.py"
CP_DIR="${ROOT}/mcp-control-plane"
DB="$(mktemp)"
CP_PID=""

cleanup() {
  if [[ -n "$CP_PID" ]]; then
    kill "$CP_PID" 2>/dev/null || true
    wait "$CP_PID" 2>/dev/null || true
  fi
  rm -f "$DB"
}
trap cleanup EXIT

export MCP_CONTROL_PLANE_ADDR="127.0.0.1:18080"
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
  if curl -sf "http://${MCP_CONTROL_PLANE_ADDR}/api/v1/policy/sync" \
    -H "X-Device-Token: dev-device-token-change-me" >/dev/null 2>&1; then
    ready=1
    break
  fi
  sleep 0.5
done

if [[ "$ready" -ne 1 ]]; then
  echo "✖  control plane did not become ready on ${MCP_CONTROL_PLANE_ADDR}" >&2
  exit 1
fi

export MCP_CONTROL_PLANE_URL="http://${MCP_CONTROL_PLANE_ADDR}"
export MCP_DEVICE_TOKEN="dev-device-token-change-me"

set +e
printf '%s' '{"command":"stat ~/.ssh/id_rsa","hook_event_name":"beforeShellExecution"}' \
  | python3 "$HOOK" >/dev/null 2>&1
set -e

sleep 1

stream="$(curl -sf "http://${MCP_CONTROL_PLANE_ADDR}/api/v1/telemetry/stream" \
  -H "X-Admin-Token: dev-admin-token-change-me")"

if ! printf '%s' "$stream" | grep -q 'cursor_hook:beforeShellExecution'; then
  echo "✖  expected cursor_hook telemetry in stream, got:" >&2
  echo "$stream" >&2
  exit 1
fi

if ! printf '%s' "$stream" | grep -qE 'id_rsa|\\.ssh/'; then
  echo "✖  expected sensitive-path pattern in telemetry stream" >&2
  exit 1
fi

echo "✔  hook denial emitted telemetry to control plane"
