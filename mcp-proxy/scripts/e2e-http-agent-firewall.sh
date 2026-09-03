#!/usr/bin/env bash
# e2e: OpenAI-compatible agent firewall masks secrets in tool_calls.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

BIN="${MCP_PROXY_BIN:-}"
if [[ -z "$BIN" ]]; then
  source "$HOME/.cargo/env" 2>/dev/null || true
  cargo build -q
  TARGET_DIR="$(cargo metadata --format-version 1 --no-deps | python3 -c 'import json,sys; print(json.load(sys.stdin)["target_directory"])')"
  BIN="${TARGET_DIR}/debug/mcp-proxy"
fi
[[ -x "$BIN" ]] || { echo "mcp-proxy binary not found at $BIN" >&2; exit 1; }

UPSTREAM_PORT="${UPSTREAM_PORT:-18787}"
PROXY_PORT="${PROXY_PORT:-18788}"
UPSTREAM_PID=""
PROXY_PID=""

cleanup() {
  [[ -n "$PROXY_PID" ]] && kill "$PROXY_PID" 2>/dev/null || true
  [[ -n "$UPSTREAM_PID" ]] && kill "$UPSTREAM_PID" 2>/dev/null || true
}
trap cleanup EXIT

# Mock OpenAI upstream that returns a tool_call containing a fake API key.
python3 - "$UPSTREAM_PORT" <<'PY' &
import json
import sys
from http.server import BaseHTTPRequestHandler, HTTPServer

PORT = int(sys.argv[1])

class Handler(BaseHTTPRequestHandler):
    def log_message(self, fmt, *args):
        pass

    def do_POST(self):
        length = int(self.headers.get("Content-Length", "0"))
        _ = self.rfile.read(length)
        body = {
            "id": "chatcmpl-e2e",
            "object": "chat.completion",
            "choices": [{
                "index": 0,
                "message": {
                    "role": "assistant",
                    "content": None,
                    "tool_calls": [{
                        "id": "call_e2e",
                        "type": "function",
                        "function": {
                            # Benign read path so taxonomy does not DENY as credential
                            # access; secret-shaped value still must be DLP-masked.
                            "name": "read_file",
                            "arguments": json.dumps({
                                "path": "/tmp/ok.txt",
                                "note": "sk-proj-abcdefghijklmnopqrstuvwxyz012345",
                            }),
                        },
                    }],
                },
                "finish_reason": "tool_calls",
            }],
        }
        raw = json.dumps(body).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

HTTPServer(("127.0.0.1", PORT), Handler).serve_forever()
PY
UPSTREAM_PID=$!
sleep 0.4

MCP_RISK_THRESHOLD=100 \
  "$BIN" serve --listen "127.0.0.1:${PROXY_PORT}" --upstream "http://127.0.0.1:${UPSTREAM_PORT}" &
PROXY_PID=$!

for _ in $(seq 1 30); do
  if curl -fsS -o /dev/null "http://127.0.0.1:${PROXY_PORT}/v1/models" 2>/dev/null \
    || curl -sS -o /dev/null -w '' --connect-timeout 1 "http://127.0.0.1:${PROXY_PORT}/" 2>/dev/null; then
    break
  fi
  # Proxy may 502 on / until ready; just check TCP.
  if (echo >/dev/tcp/127.0.0.1/"${PROXY_PORT}") 2>/dev/null; then
    break
  fi
  sleep 0.2
done
sleep 0.3

if ! kill -0 "$PROXY_PID" 2>/dev/null; then
  echo "e2e FAIL: agent firewall process exited early" >&2
  exit 1
fi

RESP="$(curl -fsS -X POST "http://127.0.0.1:${PROXY_PORT}/v1/chat/completions" \
  -H 'Content-Type: application/json' \
  -d '{"model":"gpt-4o-mini","stream":false,"messages":[{"role":"user","content":"hi"}]}')"

echo "$RESP" | grep -q 'MASKED_SECRET_BY_PROXY'
if echo "$RESP" | grep -q 'sk-proj-abcdefghijklmnopqrstuvwxyz012345'; then
  echo "e2e FAIL: secret leaked through agent firewall" >&2
  exit 1
fi

# Streaming must be rejected.
CODE="$(curl -sS -o /tmp/mcp-proxy-stream-reject.json -w '%{http_code}' -X POST \
  "http://127.0.0.1:${PROXY_PORT}/v1/chat/completions" \
  -H 'Content-Type: application/json' \
  -d '{"model":"gpt-4o-mini","stream":true,"messages":[{"role":"user","content":"hi"}]}')"
[[ "$CODE" == "400" ]] || { echo "e2e FAIL: expected 400 for stream=true, got $CODE" >&2; exit 1; }

echo "e2e-http-agent-firewall: PASS"
