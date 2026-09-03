#!/usr/bin/env bash
# Live local control-plane path: mint → enroll CLI → doctor → demo remote approval create → device poll.
# Human approve/deny/consume is covered by mcp-control-plane Go tests (session+CSRF).
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
PROXY_DIR="${ROOT}/mcp-proxy"
CP_DIR="${ROOT}/mcp-control-plane"
export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-${PROXY_DIR}/target}"
export PATH="${HOME:-}/.cargo/bin:${PATH}"

PROXY="${MCP_PROXY_BIN:-}"
if [[ -z "$PROXY" ]]; then
  echo "==> building mcp-proxy (release)"
  (cd "$PROXY_DIR" && cargo build -q --release --locked --bin mcp-proxy)
  PROXY="${CARGO_TARGET_DIR}/release/mcp-proxy"
fi
test -x "$PROXY" || { echo "binary missing: $PROXY" >&2; exit 1; }

TMP="$(mktemp -d /tmp/sqreen-pilot-enroll.XXXXXX)"
DB="$(mktemp "${TMP}/cp.XXXXXX.db")"
CP_BIN="$(mktemp "${TMP}/cp.XXXXXX")"
CP_PID=""
cleanup() {
  if [[ -n "${CP_PID}" ]]; then
    kill "$CP_PID" 2>/dev/null || true
    wait "$CP_PID" 2>/dev/null || true
  fi
  rm -rf "$TMP"
}
trap cleanup EXIT

echo "==> building control plane"
( cd "$CP_DIR" && go build -o "$CP_BIN" . )

export MCP_CONTROL_PLANE_ADDR="127.0.0.1:28193"
export MCP_DB_PATH="$DB"
export SQREEN_ENV=test
export SQREEN_ALLOW_INSECURE_DEV_TOKENS=1
export MCP_DEVICE_TOKENS="bootstrap-env-token"
export MCP_ADMIN_TOKENS="dev-admin-token-change-me"
export SQREEN_ENABLE_LEGACY_ADMIN_AUTH=true
export MCP_MAX_ACTIVE_DEVICE_TOKENS_PER_ORG=25
# Fail-closed signed policy bootstrap (same harness as cloud threat-intel e2e).
export SQREEN_POLICY_SIGNING_KEY_PATH="${SQREEN_POLICY_SIGNING_KEY_PATH:-$ROOT/mcp-proxy/tests/policy_integrity/fixtures/test-policy-signing.key}"
export SQREEN_POLICY_SIGNING_KEY_ID="${SQREEN_POLICY_SIGNING_KEY_ID:-sqreen-policy-ed25519-test}"
export SQREEN_POLICY_ALLOW_TEST_KEYS=1

"$CP_BIN" &
CP_PID=$!

ready=0
for _ in $(seq 1 120); do
  if curl -sf "http://${MCP_CONTROL_PLANE_ADDR}/health" >/dev/null 2>&1; then
    ready=1
    break
  fi
  sleep 0.1
done
if [[ "$ready" -ne 1 ]]; then
  echo "✖  control plane did not become ready" >&2
  exit 1
fi
echo "✔  control plane ready on ${MCP_CONTROL_PLANE_ADDR}"

MINT_JSON="$(
  curl -sf -X POST "http://${MCP_CONTROL_PLANE_ADDR}/api/v1/device-tokens" \
    -H "X-Admin-Token: ${MCP_ADMIN_TOKENS}" \
    -H "X-Org-Id: pilot-e2e" \
    -H "Content-Type: application/json" \
    -d '{"org_id":"pilot-e2e","label":"pilot-laptop"}'
)"
TOKEN="$(python3 -c 'import json,sys; print(json.load(sys.stdin)["token"])' <<<"$MINT_JSON")"
DEVICE_ID="$(python3 -c 'import json,sys; print(json.load(sys.stdin)["device_id"])' <<<"$MINT_JSON")"
if [[ -z "$TOKEN" || -z "$DEVICE_ID" ]]; then
  echo "✖  mint failed: $MINT_JSON" >&2
  exit 1
fi
echo "✔  minted device ${DEVICE_ID} (token redacted)"

export HOME="$TMP"
unset XDG_CONFIG_HOME || true
mkdir -p "$HOME/.config/mcp-proxy"
cp "$PROXY_DIR/mcp-policy.yaml" "$HOME/.config/mcp-proxy/mcp-policy.yaml"
export MCP_POLICY_PATH="$HOME/.config/mcp-proxy/mcp-policy.yaml"

echo "==> enroll"
"$PROXY" enroll \
  --control-plane "http://${MCP_CONTROL_PLANE_ADDR}" \
  --device-token "$TOKEN" \
  --device-id "$DEVICE_ID" \
  --org-id "pilot-e2e"

# shellcheck disable=SC1091
source "$HOME/.config/mcp-proxy/env"
# Ensure process env matches enroll file (doctor reads both).
export MCP_CONTROL_PLANE_URL="http://${MCP_CONTROL_PLANE_ADDR}"
export MCP_DEVICE_TOKEN="$TOKEN"
export SQREEN_DEVICE_ID="$DEVICE_ID"
export SQREEN_ORG_ID="pilot-e2e"
export SQREEN_APPROVAL_MODE=remote

# Token must never appear in status.
STATUS_OUT="$("$PROXY" status)"
if echo "$STATUS_OUT" | grep -Fq "$TOKEN"; then
  echo "✖  status leaked device token" >&2
  exit 1
fi
echo "$STATUS_OUT" | grep -q '\[SET\]'
echo "✔  enroll + status (token redacted)"

echo "==> doctor (expect PASS — cloud reachable)"
set +e
"$PROXY" doctor
DOC_EC=$?
set -e
if [[ "$DOC_EC" -ne 0 ]]; then
  echo "✖  doctor failed against live local control plane" >&2
  exit 1
fi
echo "✔  doctor PASS"

echo "==> demo remote approval create"
DEMO_OUT="$("$PROXY" demo 2>&1)"
echo "$DEMO_OUT"
if ! echo "$DEMO_OUT" | grep -q 'Approval id:'; then
  echo "✖  demo did not create a remote approval" >&2
  exit 1
fi
APPROVAL_ID="$(echo "$DEMO_OUT" | sed -n 's/.*Approval id: //p' | head -1 | tr -d '[:space:]')"
if [[ -z "$APPROVAL_ID" ]]; then
  echo "✖  could not parse approval id" >&2
  exit 1
fi

POLL="$(
  curl -sf "http://${MCP_CONTROL_PLANE_ADDR}/api/v1/device/approvals/${APPROVAL_ID}" \
    -H "X-Device-Token: ${TOKEN}"
)"
STATUS="$(python3 -c 'import json,sys; print(json.load(sys.stdin).get("status",""))' <<<"$POLL")"
if [[ "$STATUS" != "PENDING" ]]; then
  echo "✖  expected PENDING, got ${STATUS}: ${POLL}" >&2
  exit 1
fi
echo "✔  remote approval ${APPROVAL_ID} is PENDING (open SOC Approvals to decide)"
echo "✔  e2e-pilot-enroll-approval passed"
echo "   (approve/deny/consume covered by: go test ./... -run TestRemoteApprovalHappyPath)"
