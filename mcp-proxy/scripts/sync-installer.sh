#!/usr/bin/env bash
# Copy the canonical installer into a release mirror, if one exists.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
PUBLIC_ROOT="${SQREEN_PUBLIC_MIRROR_DIR:-${ROOT}/frontend/public}"

if [[ ! -d "$PUBLIC_ROOT" ]]; then
  echo "installer sync skipped: no mirror directory at $PUBLIC_ROOT"
  exit 0
fi

cp "${ROOT}/mcp-proxy/install.sh" "${PUBLIC_ROOT}/install.sh"
mkdir -p "${PUBLIC_ROOT}/releases"
cp "${ROOT}/mcp-proxy/keys/sqreen-release-ed25519.pub" \
  "${PUBLIC_ROOT}/releases/sqreen-release-ed25519.pub"
echo "synced install.sh and release public key into ${PUBLIC_ROOT}/"
