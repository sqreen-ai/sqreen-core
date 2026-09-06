#!/usr/bin/env bash
# Fail if public docs/marketing re-introduce overclaims that contradict
# PUBLIC_INTEGRATION_MATRIX in src/adapters/framework.rs.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$ROOT"

fail=0

# Exact phrases that previously implied Anthropic/OpenAI parity beyond production wiring.
FORBIDDEN=(
  'OpenAI-compatible & Anthropic-shaped HTTP tool loops'
  'OpenAI-compatible and Anthropic Messages API tool calls via local `serve`'
  'Anthropic Messages API tool calls via local'
  'HTTP proxy for OpenAI-compatible (and Anthropic-shaped)'
  'Wrapped MCP · OpenAI · Anthropic paths'
  'supported OpenAI / Anthropic tool traffic'
  'supported OpenAI / Anthropic / Cursor paths'
  'Wrap MCP or proxy OpenAI / Anthropic HTTP'
  'proxy OpenAI and Anthropic'
  'Point your Anthropic SDK base URL at http://127.0.0.1:8787'
  'expected VERIFIED_ACTIVE after prove'
  'Anthropic: same `serve` with `--upstream https://api.anthropic.com`'
)

# Primary claim surfaces (ignore accidental " 2.md" duplicates and vendor code comments).
SCAN_PATHS=(
  README.md
  mcp-proxy/README.md
  docs/QUICKSTART.md
  docs/PROVIDER_ADAPTERS.md
  docs/DESIGN_PARTNER.md
  docs/PILOT_CHECKLIST.md
  frontend/components/marketing
  frontend/app/products
  mcp-proxy/src/main.rs
  mcp-proxy/src/pilot/status.rs
  mcp-proxy/scripts/pilot-onboarding-smoke.sh
)

echo "==> checking integration claim phrases"

for phrase in "${FORBIDDEN[@]}"; do
  hits="$(
    grep -R --fixed-strings -n -- "${phrase}" "${SCAN_PATHS[@]}" 2>/dev/null || true
  )"
  if [[ -n "$hits" ]]; then
    echo "✖  forbidden overclaim found: ${phrase}" >&2
    echo "$hits" >&2
    fail=1
  fi
done

# Require public matrix labels to appear in PROVIDER_ADAPTERS.md
REQUIRED=(
  'PRODUCTION_SUPPORTED'
  'PILOT_SUPPORTED'
  'PILOT_SUPPORTED — LIMITED'
  'EXPERIMENTAL'
)

for label in "${REQUIRED[@]}"; do
  if ! grep -q --fixed-strings -- "$label" docs/PROVIDER_ADAPTERS.md; then
    echo "✖  docs/PROVIDER_ADAPTERS.md missing matrix label: ${label}" >&2
    fail=1
  fi
done

# Smoke must not treat prove as VERIFIED_ACTIVE mint
if grep -q 'expected VERIFIED_ACTIVE after prove' mcp-proxy/scripts/pilot-onboarding-smoke.sh; then
  echo "✖  pilot-onboarding-smoke still expects VERIFIED_ACTIVE after prove" >&2
  fail=1
fi
if ! grep -q 'prove must not mint Aggregate VERIFIED_ACTIVE' mcp-proxy/scripts/pilot-onboarding-smoke.sh; then
  echo "✖  pilot-onboarding-smoke missing prove→not VERIFIED_ACTIVE assertion" >&2
  fail=1
fi
if ! grep -q 'Aggregate:\[\[:space:\]\]+VERIFIED_ACTIVE' mcp-proxy/scripts/pilot-onboarding-smoke.sh; then
  echo "✖  pilot-onboarding-smoke should match Aggregate VERIFIED_ACTIVE precisely" >&2
  fail=1
fi
# Demo must not instruct prove → VERIFIED_ACTIVE as the traffic proof path
if grep -n 'PROVE_COMMAND' mcp-proxy/src/demo.rs | grep -q 'VERIFIED_ACTIVE'; then
  :
fi
if grep -A2 'println!("  3. {}", crate::pilot::day1::PROVE_COMMAND)' mcp-proxy/src/demo.rs 2>/dev/null | grep -q VERIFIED; then
  echo "✖  demo.rs still sequences prove before VERIFIED_ACTIVE as traffic proof" >&2
  fail=1
fi
if grep -q 'Wrap + prove next' mcp-proxy/src/demo.rs; then
  echo "✖  demo.rs still says Wrap + prove next" >&2
  fail=1
fi

if [[ "$fail" -ne 0 ]]; then
  echo "integration claim check FAILED" >&2
  exit 1
fi

echo "✔ integration claim check passed"
