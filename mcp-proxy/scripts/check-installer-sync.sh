#!/usr/bin/env bash
# Fail if mcp-proxy/install.sh and frontend/public/install.sh diverge.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
CANONICAL="${ROOT}/mcp-proxy/install.sh"
PUBLIC="${ROOT}/frontend/public/install.sh"

if [[ ! -f "$CANONICAL" ]]; then
  echo "missing canonical installer: $CANONICAL" >&2
  exit 1
fi
if [[ ! -f "$PUBLIC" ]]; then
  echo "missing public installer: $PUBLIC" >&2
  exit 1
fi

if ! cmp -s "$CANONICAL" "$PUBLIC"; then
  echo "ERROR: installer drift detected." >&2
  echo "Canonical: $CANONICAL" >&2
  echo "Public:    $PUBLIC" >&2
  echo "Copy the canonical file over the public one (or re-run the sync step)." >&2
  diff -u "$CANONICAL" "$PUBLIC" | head -80 >&2 || true
  exit 1
fi

echo "installer sync ok: frontend/public/install.sh matches mcp-proxy/install.sh"
