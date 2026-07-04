#!/usr/bin/env python3
"""Sqreen Cursor hook — deny Shell/Read/MCP access to sensitive local paths.

Patterns align with mcp-proxy global block_patterns (~/.ssh, .ssh/, id_rsa, …).
Reads hook JSON from stdin; prints {"permission": "allow"|"deny", ...} to stdout.
Exit 2 when denying (Cursor fail-closed compatible).

When MCP_CONTROL_PLANE_URL and MCP_DEVICE_TOKEN are set (or present in
~/.config/mcp-proxy/env), denied events POST to /api/v1/telemetry/log — same
schema as mcp-proxy — on deny only (sync, ≤3s timeout).
"""

from __future__ import annotations

import json
import os
import re
import sys
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

# Keep in sync with mcp-proxy/mcp-policy.yaml global block_patterns.
SENSITIVE_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    ("\\.ssh/", re.compile(r"\.ssh/")),
    ("~/.ssh/", re.compile(r"~/.ssh/")),
    ("id_rsa", re.compile(r"id_rsa(\.|$)")),
    ("id_ed25519", re.compile(r"id_ed25519(\.|$)")),
    (".aws/credentials", re.compile(r"\.aws/credentials")),
    (".env", re.compile(r"\.env(\.|$)")),
    ("../.. traversal", re.compile(r"\.\./\.\./")),
]

CONTROL_PLANE_URL_ENV = "MCP_CONTROL_PLANE_URL"
DEVICE_TOKEN_ENV = "MCP_DEVICE_TOKEN"
TELEMETRY_PATH = "/api/v1/telemetry/log"
HOOK_RISK_SCORE = 85


def load_mcp_env() -> None:
    """Merge install.sh env file into os.environ when keys are unset."""
    env_path = Path.home() / ".config" / "mcp-proxy" / "env"
    if not env_path.is_file():
        return

    for raw_line in env_path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("export "):
            line = line[len("export ") :]
        if "=" not in line:
            continue
        key, _, value = line.partition("=")
        key = key.strip()
        value = value.strip().strip('"').strip("'")
        if key and key not in os.environ:
            os.environ[key] = value


def collect_strings(value: Any, out: list[str]) -> None:
    if isinstance(value, str):
        out.append(value)
    elif isinstance(value, dict):
        for item in value.values():
            collect_strings(item, out)
    elif isinstance(value, list):
        for item in value:
            collect_strings(item, out)


def first_sensitive_match(text: str) -> str | None:
    for label, pattern in SENSITIVE_PATTERNS:
        if pattern.search(text):
            return label
    return None


def _post_telemetry(base_url: str, device_token: str, record: dict[str, Any]) -> None:
    url = f"{base_url.rstrip('/')}{TELEMETRY_PATH}"
    body = json.dumps(record).encode("utf-8")
    request = urllib.request.Request(
        url,
        data=body,
        method="POST",
        headers={
            "Content-Type": "application/json",
            "X-Device-Token": device_token,
        },
    )
    try:
        with urllib.request.urlopen(request, timeout=3) as response:
            response.read()
    except (urllib.error.URLError, TimeoutError, OSError):
        # Best-effort; never fail the hook on telemetry errors.
        pass


def emit_hook_telemetry(payload: dict[str, Any], pattern_label: str) -> None:
    load_mcp_env()
    base_url = os.environ.get(CONTROL_PLANE_URL_ENV, "").strip()
    device_token = os.environ.get(DEVICE_TOKEN_ENV, "").strip()
    if not base_url or not device_token:
        return

    event = str(payload.get("hook_event_name") or "cursor_hook")
    record = {
        "timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "device_id": device_token,
        "tool_name": f"cursor_hook:{event}",
        "risk_score": HOOK_RISK_SCORE,
        "pattern_matched": pattern_label,
        "user_decision": "denied",
    }
    _post_telemetry(base_url, device_token, record)


def deny(reason: str, payload: dict[str, Any] | None = None, pattern_label: str | None = None) -> None:
    if payload is not None and pattern_label is not None:
        emit_hook_telemetry(payload, pattern_label)

    message = {
        "permission": "deny",
        "user_message": f"Sqreen blocked access to a sensitive path ({reason}).",
        "agent_message": (
            "Project hooks denied this action because it targets a sensitive path "
            "(e.g. ~/.ssh). Do not retry via Shell, Read, or another MCP tool."
        ),
    }
    print(json.dumps(message))
    sys.exit(2)


def allow() -> None:
    print(json.dumps({"permission": "allow"}))
    sys.exit(0)


def main() -> None:
    raw = sys.stdin.read()
    if not raw.strip():
        allow()

    try:
        payload = json.loads(raw)
    except json.JSONDecodeError:
        # Cursor may cancel hooks or send partial payloads; don't fail-closed on that.
        allow()

    candidates: list[str] = []
    for key in ("command", "path", "filePath", "file_path", "uri"):
        if key in payload and payload[key]:
            candidates.append(str(payload[key]))

    collect_strings(payload.get("tool_input"), candidates)
    collect_strings(payload.get("arguments"), candidates)
    collect_strings(payload.get("params"), candidates)

    for text in candidates:
        if label := first_sensitive_match(text):
            deny(
                f"matched `{label}` in `{text[:160]}`",
                payload=payload,
                pattern_label=label,
            )

    allow()


if __name__ == "__main__":
    main()
