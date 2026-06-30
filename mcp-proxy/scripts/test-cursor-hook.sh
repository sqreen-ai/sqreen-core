#!/usr/bin/env bash
# Smoke-test Sqreen Cursor hooks without the IDE.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
HOOK="${1:-${ROOT}/.cursor/hooks/block-sensitive-paths.py}"

pass=0
fail=0

run_case() {
  local name="$1"
  local expect="$2"
  local payload="$3"
  set +e
  out="$(printf '%s' "$payload" | python3 "$HOOK" 2>&1)"
  code=$?
  set -e

  if [[ "$expect" == "deny" && "$code" -eq 2 && "$out" == *'"permission": "deny"'* ]]; then
    echo "✔  $name"
    pass=$((pass + 1))
  elif [[ "$expect" == "allow" && "$code" -eq 0 && "$out" == *'"permission": "allow"'* ]]; then
    echo "✔  $name"
    pass=$((pass + 1))
  else
    echo "✖  $name (expected $expect, exit=$code, out=$out)" >&2
    fail=$((fail + 1))
  fi
}

run_case "shell stat .ssh" deny '{"command":"stat ~/.ssh/id_rsa","hook_event_name":"beforeShellExecution"}'
run_case "shell ls safe" allow '{"command":"ls /tmp","hook_event_name":"beforeShellExecution"}'
run_case "read .ssh" deny '{"path":"/home/runner/.ssh/id_rsa","hook_event_name":"beforeReadFile"}'
run_case "read project file" allow '{"path":"'"$ROOT"'/README.md","hook_event_name":"beforeReadFile"}'
run_case "mcp get_file_info .ssh" deny '{"tool_input":{"path":"/home/runner/.ssh/id_rsa"},"hook_event_name":"beforeMCPExecution"}'

if [[ "$fail" -gt 0 ]]; then
  echo "hook tests failed: $fail" >&2
  exit 1
fi

echo "hook tests passed ($pass)"
