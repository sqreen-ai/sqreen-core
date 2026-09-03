#!/usr/bin/env bash
# Copy the canonical installer into the static site tree.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cp "${ROOT}/mcp-proxy/install.sh" "${ROOT}/frontend/public/install.sh"
# Also publish the release verification public key next to release assets.
mkdir -p "${ROOT}/frontend/public/releases"
cp "${ROOT}/mcp-proxy/keys/sqreen-release-ed25519.pub" \
  "${ROOT}/frontend/public/releases/sqreen-release-ed25519.pub"
echo "synced install.sh and release public key into frontend/public/"
