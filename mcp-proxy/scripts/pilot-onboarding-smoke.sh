#!/usr/bin/env bash
# Pilot onboarding smoke — isolated HOME, no network required for core path.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-$ROOT/target}"
export PATH="${HOME:-}/.cargo/bin:$PATH"

BIN="${MCP_PROXY_BIN:-}"
if [[ -z "$BIN" ]]; then
  echo "Building mcp-proxy (debug)…"
  cargo build -q -p mcp-proxy --bin mcp-proxy
  BIN="$CARGO_TARGET_DIR/debug/mcp-proxy"
fi
test -x "$BIN" || { echo "binary missing: $BIN" >&2; exit 1; }

TMP="$(mktemp -d /tmp/sqreen-pilot-smoke.XXXXXX)"
cleanup() { rm -rf "$TMP"; }
trap cleanup EXIT

export HOME="$TMP"
unset XDG_CONFIG_HOME || true
unset MCP_CONTROL_PLANE_URL MCP_DEVICE_TOKEN SQREEN_DEVICE_ID SQREEN_ORG_ID || true
unset SQREEN_APPROVAL_MODE SQREEN_ENFORCEMENT_POSTURE OPENAI_BASE_URL || true

mkdir -p "$HOME/.config/mcp-proxy"
POLICY="$HOME/.config/mcp-proxy/mcp-policy.yaml"
cp "$ROOT/mcp-policy.yaml" "$POLICY"

export MCP_POLICY_PATH="$POLICY"

echo "==> demo"
"$BIN" demo

echo "==> status"
"$BIN" status

echo "==> doctor (expect PASS or WARN, not crash)"
set +e
"$BIN" doctor
DOC_EC=$?
set -e
# FAIL exits non-zero; for local-only smoke we allow 0 only (PASS/WARN).
# Cloud not configured → WARN, still exit 0.
if [[ "$DOC_EC" -ne 0 ]]; then
  echo "doctor exited $DOC_EC (unexpected FAIL in local smoke)" >&2
  exit 1
fi

echo "==> integrations"
"$BIN" integrations

echo "==> support-bundle"
BUNDLE_OUT="$TMP/bundle"
"$BIN" support-bundle --out "$BUNDLE_OUT"
test -f "$BUNDLE_OUT/version.txt"
test -f "$BUNDLE_OUT/doctor.txt"
test -f "$BUNDLE_OUT/env.redacted.txt"
if grep -q 'sk-live\|super-secret\|BEGIN OPENSSH' "$BUNDLE_OUT"/* 2>/dev/null; then
  echo "support-bundle appears to contain raw secrets" >&2
  exit 1
fi

echo "==> enroll (flag-based, no token echo)"
"$BIN" enroll \
  --control-plane "http://127.0.0.1:9" \
  --device-token "smoke-token-not-for-prod" \
  --device-id "smoke-device"
ENV_FILE="$HOME/.config/mcp-proxy/env"
test -f "$ENV_FILE"
# Token may be on disk; must not appear in status output.
STATUS_OUT="$("$BIN" status)"
if echo "$STATUS_OUT" | grep -q 'smoke-token-not-for-prod'; then
  echo "status leaked device token" >&2
  exit 1
fi
echo "$STATUS_OUT" | grep -q '\[SET\]'

echo "✔ pilot-onboarding-smoke passed"
