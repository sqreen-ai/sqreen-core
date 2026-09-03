#!/usr/bin/env bash
# Run the mcp-proxy enforcement Criterion suite.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

echo "==> mcp-proxy enforcement benches"
echo "    docs: ../../docs/BENCHMARKS.md (monorepo) or docs/BENCHMARKS.md"
echo

cargo bench --bench enforcement "$@"

echo
echo "HTML reports: $ROOT/target/criterion/"
echo "Tip: cargo bench --bench enforcement -- --save-baseline \$(git rev-parse --short HEAD)"
