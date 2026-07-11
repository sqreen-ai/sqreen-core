#!/usr/bin/env bash
#
# Render platform-specific launch copy from launch/templates.yaml
#
# Usage:
#   ./scripts/render-launch-posts.sh v0.1.11
#   ./scripts/render-launch-posts.sh v0.1.11 --out /tmp/launch-posts
#
set -euo pipefail

VERSION="${1:?usage: render-launch-posts.sh <version> [--out DIR]}"
OUT_DIR=""
shift

while [[ $# -gt 0 ]]; do
  case "$1" in
    --out) OUT_DIR="${2:?missing value for --out}"; shift 2 ;;
    *) echo "Unknown option: $1" >&2; exit 1 ;;
  esac
done

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
TEMPLATE="${ROOT}/launch/templates.yaml"

if [[ ! -f "$TEMPLATE" ]]; then
  echo "Missing template: $TEMPLATE" >&2
  exit 1
fi

REPO="${LAUNCH_GITHUB_REPO:-sqreen-ai/sqreen-core}"
SITE_URL="${LAUNCH_SITE_URL:-https://sqreen.ai}"
INSTALL_CMD='curl -fsSL https://sqreen.ai/install.sh | bash'
REPO_URL="https://github.com/${REPO}"
RELEASE_URL="${REPO_URL}/releases/tag/${VERSION}"
DISCUSSION_URL="${REPO_URL}/discussions"

if [[ -z "$OUT_DIR" ]]; then
  OUT_DIR="${ROOT}/launch/rendered/${VERSION}"
fi
mkdir -p "$OUT_DIR"

if ! command -v python3 >/dev/null 2>&1; then
  echo "python3 is required" >&2
  exit 1
fi

python3 - "$TEMPLATE" "$OUT_DIR" "$VERSION" "$REPO_URL" "$RELEASE_URL" "$DISCUSSION_URL" "$SITE_URL" "$INSTALL_CMD" <<'PY'
import sys
from pathlib import Path

template_path, out_dir, version, repo_url, release_url, discussion_url, site_url, install_cmd = sys.argv[1:9]

raw = Path(template_path).read_text()
# Minimal YAML-ish parse: top-level keys and indented text blocks.
sections: dict[str, dict[str, str]] = {}
current_key = None
current_field = None
buf: list[str] = []

def flush():
    global buf, current_key, current_field
    if current_key and current_field is not None:
        sections.setdefault(current_key, {})[current_field] = "\n".join(buf).strip("\n")
    buf = []

for line in raw.splitlines():
    if not line.strip() or line.strip().startswith("#"):
        continue
    if not line.startswith(" ") and line.endswith(":"):
        flush()
        current_key = line[:-1].strip()
        current_field = None
        continue
    if line.startswith("  ") and ":" in line and not line.startswith("    "):
        flush()
        field, _, rest = line.strip().partition(":")
        current_field = field.strip()
        rest = rest.strip()
        if rest == "|":
            buf = []
        elif rest:
            sections.setdefault(current_key or "", {})[current_field] = rest.strip('"')
            current_field = None
        continue
    if current_field == "text" or current_field == "body":
        buf.append(line[4:] if line.startswith("    ") else line)

flush()

repl = {
    "{{version}}": version,
    "{{release_url}}": release_url,
    "{{discussion_url}}": discussion_url,
    "{{install_cmd}}": install_cmd,
    "{{repo_url}}": repo_url,
    "{{site_url}}": site_url,
}

def sub(s: str) -> str:
    for k, v in repl.items():
        s = s.replace(k, v)
    return s

out = Path(out_dir)
out.mkdir(parents=True, exist_ok=True)

def write(name: str, content: str):
    (out / name).write_text(content.rstrip() + "\n")

for platform, fields in sections.items():
    if platform == "x":
        text = sub(fields.get("text", ""))
        write("x.txt", text)
        write("x.meta.json", f'{{"max_length": {fields.get("max_length", "280")}, "chars": {len(text)}}}\n')
    elif platform == "hn":
        write("hn-title.txt", sub(fields.get("title", "")))
        write("hn-url.txt", sub(fields.get("url", repo_url)))
        write("hn-body.md", sub(fields.get("text", "")))
    elif platform == "linkedin":
        write("linkedin.txt", sub(fields.get("text", "")))
    elif platform == "bluesky":
        text = sub(fields.get("text", ""))
        write("bluesky.txt", text)
    elif platform == "github_discussion":
        write("github-discussion-title.txt", sub(fields.get("title", "")))
        write("github-discussion-category.txt", fields.get("category", "Announcements"))
        write("github-discussion-body.md", sub(fields.get("body", "")))
    elif platform == "reddit":
        write("reddit-subreddit.txt", fields.get("subreddit", ""))
        write("reddit-title.txt", sub(fields.get("title", "")))
        write("reddit-body.md", sub(fields.get("text", "")))
    elif platform == "devto":
        write("devto-title.txt", sub(fields.get("title", "")))
        write("devto-tags.txt", fields.get("tags", ""))
        write("devto-body.md", sub(fields.get("body", "")))

readme = f"""# Launch posts — {version}

Generated from launch/templates.yaml. Copy-paste or use announce-release workflow.

| File | Platform | Auto-post? |
|------|----------|------------|
| x.txt | X / Twitter | Optional (needs API secrets) |
| hn-title.txt + hn-url.txt + hn-body.md | Hacker News | Manual (Show HN) |
| linkedin.txt | LinkedIn | Manual |
| bluesky.txt | Bluesky | Yes (if BLUESKY_* secrets set) |
| github-discussion-*.md | GitHub Discussions | Yes (workflow) |
| reddit-*.txt | Reddit | Optional (needs REDDIT_* secrets) |
| devto-*.md | Dev.to | Optional (needs DEVTO_API_KEY) |

Links:
- Release: {release_url}
- Repo: {repo_url}
"""
write("README.md", readme)
print(f"Rendered launch posts → {out_dir}")
PY

echo "Done: ${OUT_DIR}"
ls -la "${OUT_DIR}"
