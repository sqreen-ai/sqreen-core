#!/usr/bin/env bash
# Focused Day-1 installer messaging + wrap-state tests.
# Does not download binaries; sources install.sh helpers only.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
REPO_ROOT="$(cd "$ROOT/.." && pwd)"
INSTALLER="${ROOT}/install.sh"
PASS=0
FAIL=0

assert_ok() {
  local name="$1"
  shift
  if "$@"; then
    echo "  ✔ $name"
    PASS=$((PASS + 1))
  else
    echo "  ✖ $name"
    FAIL=$((FAIL + 1))
  fi
}

assert_contains() {
  local name="$1" hay="$2" needle="$3"
  if [[ "$hay" == *"$needle"* ]]; then
    echo "  ✔ $name"
    PASS=$((PASS + 1))
  else
    echo "  ✖ $name (missing: $needle)"
    FAIL=$((FAIL + 1))
  fi
}

assert_not_contains() {
  local name="$1" hay="$2" needle="$3"
  if [[ "$hay" != *"$needle"* ]]; then
    echo "  ✔ $name"
    PASS=$((PASS + 1))
  else
    echo "  ✖ $name (unexpected: $needle)"
    FAIL=$((FAIL + 1))
  fi
}

WORKDIR="$(mktemp -d "${ROOT}/.tmp-day1-msg.XXXXXX")"
# Prefer repo-local temp so sandboxed CI can write wrap fixtures.

cleanup() { rm -rf "$WORKDIR"; }
trap cleanup EXIT

echo "== installer sync =="
assert_ok "public installer matches canonical" bash "${ROOT}/scripts/check-installer-sync.sh"

echo "== source installer helpers =="
# Minimal stubs so sourcing does not require a full install environment.
export MCP_PROXY_INSTALL_SOURCED=1
# shellcheck disable=SC1090
source "$INSTALLER"

# Provide dirs used by print_day1_next_steps / wrap helpers.
INSTALL_DIR="${WORKDIR}/bin"
CONFIG_DIR="${WORKDIR}/config"
DATA_DIR="${WORKDIR}/data"
mkdir -p "$INSTALL_DIR" "$CONFIG_DIR" "$DATA_DIR"
printf 'fake-proxy\n' >"${INSTALL_DIR}/mcp-proxy"
chmod +x "${INSTALL_DIR}/mcp-proxy"
DRY_RUN=0
SKIP_IDE=0

echo "== is_cursor_mcp_config =="
assert_ok "cursor home mcp" is_cursor_mcp_config "${WORKDIR}/.cursor/mcp.json"
assert_ok "cursor user mcp" is_cursor_mcp_config "${WORKDIR}/Cursor/User/mcp.json"
assert_fail_cursor() {
  ! is_cursor_mcp_config "${WORKDIR}/Claude/claude_desktop_config.json"
}
assert_ok "claude not cursor" assert_fail_cursor

echo "== messaging: CONFIGURED =="
OUT_CFG="$(print_day1_next_steps CONFIGURED 2>&1)"
assert_contains "configured banner" "$OUT_CFG" "Cursor integration: CONFIGURED"
assert_contains "no re-run hint" "$OUT_CFG" "do NOT re-run integrate"
assert_contains "restart next" "$OUT_CFG" "Restart Cursor"
assert_contains "status next" "$OUT_CFG" "sqreen status"
assert_contains "integrations next" "$OUT_CFG" "sqreen integrations"
assert_not_contains "no step-3 integrate" "$OUT_CFG" "3. sqreen integrate cursor"
assert_contains "repair still mentioned" "$OUT_CFG" "Repair / re-wrap later: sqreen integrate cursor"
assert_contains "configured != verified" "$OUT_CFG" "CONFIGURED wrap"
assert_not_contains "no false protected claim" "$OUT_CFG" "is protected"

echo "== messaging: NOT_CONFIGURED =="
OUT_NC="$(print_day1_next_steps NOT_CONFIGURED 2>&1)"
assert_contains "not configured banner" "$OUT_NC" "Cursor integration: NOT CONFIGURED"
assert_contains "integrate instruction" "$OUT_NC" "3. sqreen integrate cursor"
assert_not_contains "no do-not-rerun" "$OUT_NC" "do NOT re-run integrate"

echo "== messaging: SKIPPED =="
OUT_SK="$(print_day1_next_steps SKIPPED 2>&1)"
assert_contains "skipped as not configured" "$OUT_SK" "Cursor integration: NOT CONFIGURED (--skip-ide)"
assert_contains "skipped integrate" "$OUT_SK" "3. sqreen integrate cursor"

echo "== hook_ide_configs: no Cursor config =="
export HOME="${WORKDIR}/home-empty"
mkdir -p "$HOME"
# detect_platform sets OS; set explicitly for discover_ide_configs
OS="$(uname -s | tr '[:upper:]' '[:lower:]')"
case "$OS" in
  darwin) OS=darwin ;;
  *) OS=linux ;;
esac
CURSOR_MCP_STATE="NOT_CONFIGURED"
hook_ide_configs >/dev/null 2>&1 || true
assert_ok "empty home -> NOT_CONFIGURED" test "$CURSOR_MCP_STATE" = "NOT_CONFIGURED"
OUT_EMPTY="$(print_day1_next_steps "$CURSOR_MCP_STATE" 2>&1)"
assert_contains "empty home shows integrate" "$OUT_EMPTY" "3. sqreen integrate cursor"

echo "== hook_ide_configs: wrap unwrapped Cursor =="
# Use linux Cursor path (*/cursor/mcp.json) so fixtures do not create a .cursor directory.
OS=linux
export HOME="${WORKDIR}/home-wrap"
mkdir -p "${HOME}/.config/cursor"
cat >"${HOME}/.config/cursor/mcp.json" <<'JSON'
{
  "mcpServers": {
    "filesystem": {
      "command": "npx",
      "args": ["-y", "@modelcontextprotocol/server-filesystem", "."]
    }
  }
}
JSON
CURSOR_MCP_STATE="NOT_CONFIGURED"
hook_ide_configs >/dev/null 2>&1
assert_ok "wrap -> CONFIGURED" test "$CURSOR_MCP_STATE" = "CONFIGURED"
assert_ok "file contains mcp-proxy" grep -Fq 'mcp-proxy' "${HOME}/.config/cursor/mcp.json"
OUT_WRAP="$(print_day1_next_steps "$CURSOR_MCP_STATE" 2>&1)"
assert_not_contains "wrapped: no redundant integrate step" "$OUT_WRAP" "3. sqreen integrate cursor"
assert_contains "wrapped: configured banner" "$OUT_WRAP" "Cursor integration: CONFIGURED"

echo "== hook_ide_configs: already wrapped (idempotent) =="
CURSOR_MCP_STATE="NOT_CONFIGURED"
hook_ide_configs >/dev/null 2>&1
assert_ok "reinstall already wrapped -> CONFIGURED" test "$CURSOR_MCP_STATE" = "CONFIGURED"
OUT_IDEM="$(print_day1_next_steps "$CURSOR_MCP_STATE" 2>&1)"
assert_not_contains "idempotent: no redundant integrate" "$OUT_IDEM" "3. sqreen integrate cursor"

echo "== hook_ide_configs: unsupported / no mcpServers host skipped by discover =="
OS=linux
export HOME="${WORKDIR}/home-plain"
mkdir -p "${HOME}/.config/cursor"
printf '{ "note": "not an mcp host config" }\n' >"${HOME}/.config/cursor/mcp.json"
CURSOR_MCP_STATE="NOT_CONFIGURED"
hook_ide_configs >/dev/null 2>&1 || true
assert_ok "non-mcp json -> NOT_CONFIGURED" test "$CURSOR_MCP_STATE" = "NOT_CONFIGURED"
OUT_PLAIN="$(print_day1_next_steps "$CURSOR_MCP_STATE" 2>&1)"
assert_contains "unsupported shows integrate" "$OUT_PLAIN" "3. sqreen integrate cursor"

echo
echo "day1-install-messaging results: ${PASS} passed, ${FAIL} failed"
if [[ "$FAIL" -ne 0 ]]; then
  exit 1
fi
