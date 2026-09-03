#!/usr/bin/env bash
# Uninstall / rollback for Sqreen Core (mcp-proxy).
# Does not delete IDE backups automatically — lists them for restore.
set -euo pipefail

INSTALL_DIR="${MCP_PROXY_INSTALL_DIR:-${HOME}/.local/bin}"
CONFIG_DIR="${MCP_PROXY_CONFIG_DIR:-${HOME}/.config/mcp-proxy}"
DATA_DIR="${MCP_PROXY_DATA_DIR:-${HOME}/.local/share/mcp-proxy}"
PURGE=0

usage() {
  cat <<EOF
Uninstall Sqreen Core (mcp-proxy)

Usage:
  ./uninstall.sh [--purge]

  --purge   Also remove ${CONFIG_DIR} and ${DATA_DIR}
            (policy, env, logs). Default keeps config.

This script:
  1. Removes ${INSTALL_DIR}/mcp-proxy and ${INSTALL_DIR}/sqreen (alias)
  2. Lists IDE mcp.json backups (*.bak.*) so you can restore
  3. Optionally purges config/data with --purge

PATH lines in ~/.zshrc / ~/.bashrc / ~/.profile are left in place
(harmless). Remove the "Added by mcp-proxy installer" block manually if desired.
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --purge) PURGE=1; shift ;;
    -h|--help) usage; exit 0 ;;
    *) echo "Unknown option: $1" >&2; usage; exit 1 ;;
  esac
done

echo "Sqreen Core uninstall"
echo "─────────────────────"

if [[ -x "${INSTALL_DIR}/mcp-proxy" || -f "${INSTALL_DIR}/mcp-proxy" ]]; then
  rm -f "${INSTALL_DIR}/mcp-proxy"
  echo "✔  Removed ${INSTALL_DIR}/mcp-proxy"
else
  echo "·  Binary not found at ${INSTALL_DIR}/mcp-proxy"
fi

if [[ -e "${INSTALL_DIR}/sqreen" ]]; then
  rm -f "${INSTALL_DIR}/sqreen"
  echo "✔  Removed ${INSTALL_DIR}/sqreen alias"
else
  echo "·  Alias not found at ${INSTALL_DIR}/sqreen"
fi

echo
echo "IDE config backups (restore manually if needed):"
found=0
for pattern in \
  "${HOME}/.cursor/mcp.json.bak."* \
  "${HOME}/Library/Application Support/Claude/claude_desktop_config.json.bak."* \
  "${HOME}/Library/Application Support/Cursor/User/mcp.json.bak."* \
  "${HOME}/.config/Claude/claude_desktop_config.json.bak."* \
  "${HOME}/.config/cursor/mcp.json.bak."*
do
  for f in $pattern; do
    if [[ -f "$f" ]]; then
      echo "  $f"
      found=1
    fi
  done
done
if [[ "$found" -eq 0 ]]; then
  echo "  (none found)"
fi
echo "  Restore example:  cp \"/path/to/mcp.json.bak.TIMESTAMP\" \"/path/to/mcp.json\""

if [[ "$PURGE" -eq 1 ]]; then
  rm -rf "$CONFIG_DIR" "$DATA_DIR"
  echo "✔  Purged ${CONFIG_DIR} and ${DATA_DIR}"
else
  echo
  echo "Config kept at ${CONFIG_DIR} (use --purge to delete)."
fi

echo
echo "Done. Restart Cursor / Claude Desktop after restoring configs."
