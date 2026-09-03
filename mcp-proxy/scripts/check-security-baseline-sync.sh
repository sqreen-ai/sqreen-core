#!/usr/bin/env bash
# Fail if generated security-baseline artifacts drifted from the typed SoT.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "${ROOT}/mcp-proxy"

cargo run --quiet --bin generate-security-baseline -- --check

# Live policy YAML must match generated golden.
if ! cmp -s generated/mcp-policy.yaml mcp-policy.yaml; then
  echo "ERROR: mcp-policy.yaml drifted from generated/mcp-policy.yaml" >&2
  diff -u generated/mcp-policy.yaml mcp-policy.yaml | head -80 >&2 || true
  exit 1
fi

# Dashboard defaults must match generated golden.
DASH="${ROOT}/mcp-dashboard/lib/policy-defaults.ts"
if [[ -f "$DASH" ]] && ! cmp -s generated/policy-defaults.ts "$DASH"; then
  echo "ERROR: mcp-dashboard/lib/policy-defaults.ts drifted from generated baseline" >&2
  diff -u generated/policy-defaults.ts "$DASH" | head -80 >&2 || true
  exit 1
fi

# Cursor hook patterns must match generated golden.
HOOKS="${ROOT}/.cursor/hooks/generated_sensitive_patterns.py"
if [[ -f "$HOOKS" ]] && ! cmp -s generated/hook_patterns.py "$HOOKS"; then
  echo "ERROR: .cursor/hooks/generated_sensitive_patterns.py drifted" >&2
  diff -u generated/hook_patterns.py "$HOOKS" | head -80 >&2 || true
  exit 1
fi

# Installer seed must contain baseline markers / key content.
if ! grep -Fq 'BEGIN SECURITY_BASELINE_SEED' install.sh; then
  echo "ERROR: install.sh missing SECURITY_BASELINE_SEED markers; run generate --apply" >&2
  exit 1
fi

# Public installer must match canonical.
bash "${ROOT}/mcp-proxy/scripts/check-installer-sync.sh"

echo "security baseline sync ok"
