#!/usr/bin/env bash
#
# mcp-proxy — unified local installer
# -----------------------------------
# Downloads (or simulates downloading) a pre-built mcp-proxy binary, seeds
# ~/.config/mcp-proxy, ensures ~/.local/bin is on PATH, and wraps MCP server
# commands in supported IDE host configs with:
#
#   mcp-proxy -- run <original-command> [args...]
#
# Compatible with Bash 4+ and Zsh on macOS and Linux.
#
# Usage:
#   curl -fsSL https://sqreen.ai/install.sh | bash
#   ./install.sh [--dry-run] [--skip-ide] [--version v0.1.0]
#
if [ -z "${BASH_VERSION:-}" ]; then
  if command -v bash >/dev/null 2>&1; then
    if [ -t 0 ]; then
      exec bash "$0" "$@"
    fi
    exec bash -s -- "$@"
  fi
  printf '%s\n' "Error: bash is required. Try: curl -fsSL ... | bash" >&2
  exit 1
fi

# macOS /bin/sh is bash --posix; re-exec so bash features work under curl | sh.
if shopt -qo posix 2>/dev/null; then
  if [ -t 0 ]; then
    exec bash "$0" "$@"
  fi
  exec bash -s -- "$@"
fi

set -euo pipefail

VERSION="${MCP_PROXY_VERSION:-latest}"
DRY_RUN=0
SKIP_IDE=0
INSTALL_DIR="${MCP_PROXY_INSTALL_DIR:-${HOME}/.local/bin}"
CONFIG_DIR="${MCP_PROXY_CONFIG_DIR:-${HOME}/.config/mcp-proxy}"
DATA_DIR="${MCP_PROXY_DATA_DIR:-${HOME}/.local/share/mcp-proxy}"
GITHUB_REPO="${MCP_PROXY_GITHUB_REPO:-sdk-bens/sqreen}"
SQREEN_RELEASE_BASE="${MCP_PROXY_SQREEN_RELEASE_URL:-https://sqreen.ai/releases}"
RELEASE_BASE="${MCP_PROXY_RELEASE_URL:-https://github.com/${GITHUB_REPO}/releases}"
SOURCE_BRANCH="${MCP_PROXY_SOURCE_BRANCH:-main}"
INSTALL_SCRIPT_DIR=""
INSTALLER_REVISION="4"

if [[ -n "${BASH_SOURCE[0]:-}" && -f "${BASH_SOURCE[0]}" ]]; then
  INSTALL_SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
elif [[ -n "$0" && "$0" != "bash" && "$0" != "sh" && "$0" != "-" && -f "$0" ]]; then
  INSTALL_SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
fi

# ── ANSI styling ──────────────────────────────────────────────────────────────
if [[ -t 1 ]] && command -v tput >/dev/null 2>&1 && [[ $(tput colors 2>/dev/null || echo 0) -ge 8 ]]; then
  BOLD=$(tput bold)
  DIM=$(tput dim)
  RESET=$(tput sgr0)
  GREEN=$(tput setaf 2)
  YELLOW=$(tput setaf 3)
  BLUE=$(tput setaf 4)
  CYAN=$(tput setaf 6)
  RED=$(tput setaf 1)
else
  BOLD="" DIM="" RESET="" GREEN="" YELLOW="" BLUE="" CYAN="" RED=""
fi

info()    { printf "%s%sℹ%s  %s\n" "$BLUE" "$BOLD" "$RESET" "$*"; }
success() { printf "%s%s✔%s  %s\n" "$GREEN" "$BOLD" "$RESET" "$*"; }
warn()    { printf "%s%s⚠%s  %s\n" "$YELLOW" "$BOLD" "$RESET" "$*" >&2; }
error()   { printf "%s%s✖%s  %s\n" "$RED" "$BOLD" "$RESET" "$*" >&2; }
step()    { printf "\n%s%s▸ %s%s\n" "$CYAN" "$BOLD" "$*" "$RESET"; }
run() {
  if [[ "$DRY_RUN" -eq 1 ]]; then
    info "[dry-run] $*"
  else
    "$@"
  fi
}

usage() {
  cat <<EOF
mcp-proxy installer

Options:
  --dry-run       Print actions without modifying the system
  --skip-ide      Install binary + config only; do not patch IDE MCP configs
  --version VER   Release tag to install (default: latest)
  -h, --help      Show this help message

Environment:
  MCP_PROXY_SQREEN_RELEASE_URL  Primary release mirror (default: sqreen.ai/releases)
  MCP_PROXY_RELEASE_URL   GitHub releases fallback base
  MCP_PROXY_GITHUB_REPO   owner/repo for source fallback (default: sdk-bens/sqreen)
  MCP_PROXY_INSTALL_DIR   Binary destination (default: ~/.local/bin)
  MCP_PROXY_CONFIG_DIR    Config directory (default: ~/.config/mcp-proxy)
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --dry-run) DRY_RUN=1; shift ;;
    --skip-ide) SKIP_IDE=1; shift ;;
    --version) VERSION="${2:?missing value for --version}"; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *) error "Unknown option: $1"; usage; exit 1 ;;
  esac
done

# ── Platform detection ────────────────────────────────────────────────────────
detect_platform() {
  local raw_os raw_arch

  raw_os="$(uname -s)"
  raw_arch="$(uname -m)"

  case "$raw_os" in
    Darwin) OS="darwin" ;;
    Linux)  OS="linux" ;;
    *)
      error "Unsupported operating system: $raw_os (expected Darwin or Linux)"
      exit 1
      ;;
  esac

  case "$raw_arch" in
    arm64|aarch64) ARCH="aarch64" ;;
    x86_64|amd64)  ARCH="x86_64" ;;
    *)
      error "Unsupported CPU architecture: $raw_arch (expected arm64/aarch64 or x86_64)"
      exit 1
      ;;
  esac

  ARTIFACT_NAME="mcp-proxy-${OS}-${ARCH}"
  if [[ "$OS" == "darwin" ]]; then
    ARTIFACT_NAME="${ARTIFACT_NAME}.tar.gz"
  else
    ARTIFACT_NAME="${ARTIFACT_NAME}.tar.gz"
  fi

  success "Detected platform: ${OS}/${ARCH}"
  info "Release artifact: ${ARTIFACT_NAME}"
}

sqreen_release_download_url() {
  if [[ "$VERSION" == "latest" ]]; then
    printf '%s/latest/%s' "$SQREEN_RELEASE_BASE" "$ARTIFACT_NAME"
  else
    printf '%s/%s/%s' "$SQREEN_RELEASE_BASE" "$VERSION" "$ARTIFACT_NAME"
  fi
}

release_download_url() {
  if [[ "$VERSION" == "latest" ]]; then
    printf '%s/latest/download/%s' "$RELEASE_BASE" "$ARTIFACT_NAME"
  else
    printf '%s/download/%s/%s' "$RELEASE_BASE" "$VERSION" "$ARTIFACT_NAME"
  fi
}

mcp_proxy_source_root() {
  if [[ -n "$INSTALL_SCRIPT_DIR" && -f "${INSTALL_SCRIPT_DIR}/Cargo.toml" ]]; then
    printf '%s\n' "$INSTALL_SCRIPT_DIR"
    return 0
  fi

  return 1
}

ensure_cargo() {
  if command -v cargo >/dev/null 2>&1; then
    return 0
  fi

  if [[ -f "${HOME}/.cargo/env" ]]; then
    # shellcheck disable=SC1091
    source "${HOME}/.cargo/env"
  fi

  command -v cargo >/dev/null 2>&1
}

install_unavailable_no_cargo() {
  error "Rust (cargo) is required to build mcp-proxy from source."
  info "Install Rust:"
  info "  curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh"
  info "Then restart your shell and re-run this installer."
  exit 1
}

install_unavailable_no_source() {
  error "No prebuilt mcp-proxy release is available for ${OS}/${ARCH}."
  info "Options:"
  info "  1. Install from a local clone:"
  info "       git clone https://github.com/${GITHUB_REPO}.git"
  info "       cd sqreen/mcp-proxy && ./install.sh"
  info "  2. Build manually (requires Rust from https://rustup.rs):"
  info "       git clone https://github.com/${GITHUB_REPO}.git"
  info "       cd sqreen/mcp-proxy && cargo build --release"
  info "  3. Publish a GitHub release tagged v* with ${ARTIFACT_NAME} attached."
  exit 1
}

# ── Binary install (simulated retrieval + local fallback) ─────────────────────
sign_mcp_proxy_binary() {
  local dest="$1"

  if [[ "$OS" != "darwin" ]]; then
    return 0
  fi

  if ! command -v codesign >/dev/null 2>&1; then
    warn "codesign not found; ${dest} may be killed by macOS Gatekeeper when spawned by IDEs"
    return 0
  fi

  if codesign -s - -f "$dest" >/dev/null 2>&1; then
    info "Ad-hoc signed ${dest} for macOS IDE spawning"
  else
    warn "codesign failed for ${dest}; toggle MCP off/on may show Connection closed until signed"
  fi
}

ensure_install_dir() {
  step "Preparing install directory"
  run mkdir -p "$INSTALL_DIR"
  success "Install path ready: $INSTALL_DIR"
}

download_binary() {
  step "Retrieving mcp-proxy binary"
  local dest="${INSTALL_DIR}/mcp-proxy"
  local sqreen_url github_url url downloaded=0

  if [[ "$VERSION" == "latest" ]]; then
    sqreen_url="${SQREEN_RELEASE_BASE}/latest/${ARTIFACT_NAME}"
    github_url="${RELEASE_BASE}/latest/download/${ARTIFACT_NAME}"
  else
    sqreen_url="${SQREEN_RELEASE_BASE}/${VERSION}/${ARTIFACT_NAME}"
    github_url="${RELEASE_BASE}/download/${VERSION}/${ARTIFACT_NAME}"
  fi

  info "Downloading ${ARTIFACT_NAME} (${VERSION})…"

  if [[ "$DRY_RUN" -eq 1 ]]; then
    info "[dry-run] would download from:"
    info "  ${sqreen_url}"
    info "  ${github_url}"
    info "[dry-run] would install → ${dest}"
    return 0
  fi

  local tmp
  tmp="$(mktemp -d)"
  trap 'rm -rf "$tmp"' RETURN

  for url in "$sqreen_url" "$github_url"; do
    info "Trying ${url}"
    if curl -fsSL "$url" -o "${tmp}/${ARTIFACT_NAME}" 2>/dev/null; then
      downloaded=1
      success "Downloaded from ${url}"
      break
    fi
  done

  if [[ "$downloaded" -eq 1 ]]; then
    tar -xzf "${tmp}/${ARTIFACT_NAME}" -C "$tmp"
    if [[ -f "${tmp}/mcp-proxy" ]]; then
      install -m 0755 "${tmp}/mcp-proxy" "$dest"
    elif [[ -f "${tmp}/${ARTIFACT_NAME%.tar.gz}/mcp-proxy" ]]; then
      install -m 0755 "${tmp}/${ARTIFACT_NAME%.tar.gz}/mcp-proxy" "$dest"
    else
      warn "Archive downloaded but binary not found; trying source build fallback"
      try_build_from_source "$dest"
    fi
  else
    warn "Release download unavailable — trying source build fallback"
    try_build_from_source "$dest"
  fi

  success "Installed mcp-proxy → ${dest}"
  sign_mcp_proxy_binary "$dest"
  info "$("$dest" --version 2>/dev/null || echo 'mcp-proxy (version probe unavailable)')"
}

try_build_from_source() {
  local dest="$1"
  local root=""

  if root="$(mcp_proxy_source_root)"; then
    info "Building from local source at ${root}"
    build_mcp_proxy_at "$dest" "$root"
    return 0
  fi

  build_from_github_source "$dest"
}

build_mcp_proxy_at() {
  local dest="$1"
  local root="$2"

  if ! ensure_cargo; then
    install_unavailable_no_cargo
  fi

  info "Compiling mcp-proxy from ${root}…"
  (cd "$root" && cargo build --release --locked)
  install -m 0755 "${root}/target/release/mcp-proxy" "$dest"
  sign_mcp_proxy_binary "$dest"
}

build_from_github_source() {
  local dest="$1"
  local tmp root repo_url="https://github.com/${GITHUB_REPO}.git"
  local archive_url="https://github.com/${GITHUB_REPO}/archive/refs/heads/${SOURCE_BRANCH}.tar.gz"

  if ! ensure_cargo; then
    install_unavailable_no_cargo
  fi

  tmp="$(mktemp -d)"
  trap 'rm -rf "$tmp"' RETURN

  if command -v git >/dev/null 2>&1; then
    info "Cloning ${GITHUB_REPO} (shallow)…"
    if git clone --depth 1 --branch "$SOURCE_BRANCH" "$repo_url" "${tmp}/sqreen" 2>/dev/null; then
      root="${tmp}/sqreen/mcp-proxy"
      build_mcp_proxy_at "$dest" "$root"
      return 0
    fi
    warn "Git clone failed — trying source archive"
  fi

  info "Downloading source archive…"
  if ! curl -fsSL "$archive_url" | tar -xzf - -C "$tmp" 2>/dev/null; then
    install_unavailable_no_source
  fi

  root="${tmp}/sqreen-${SOURCE_BRANCH}/mcp-proxy"
  if [[ ! -f "${root}/Cargo.toml" ]]; then
    root="${tmp}/sqreen-main/mcp-proxy"
  fi

  if [[ ! -f "${root}/Cargo.toml" ]]; then
    install_unavailable_no_source
  fi

  build_mcp_proxy_at "$dest" "$root"
}

# ── PATH wiring ───────────────────────────────────────────────────────────────
ensure_path() {
  step "Ensuring ~/.local/bin is on PATH"

  local path_line='export PATH="$HOME/.local/bin:$PATH"'
  local updated=0

  for rc in "${HOME}/.zshrc" "${HOME}/.bashrc" "${HOME}/.profile"; do
    [[ -f "$rc" ]] || continue
    if grep -Fq '.local/bin' "$rc" 2>/dev/null; then
      info "PATH already configured in $(basename "$rc")"
    else
      run bash -c "printf '\n# Added by mcp-proxy installer\n%s\n' '$path_line' >> '$rc'"
      success "Updated $(basename "$rc")"
      updated=1
    fi
  done

  if [[ "$updated" -eq 0 ]]; then
    success "Shell PATH looks good"
  fi

  export PATH="${INSTALL_DIR}:${PATH}"
}

# ── Default config seeding ────────────────────────────────────────────────────
seed_config() {
  step "Seeding local configuration"

  run mkdir -p "$CONFIG_DIR" "$DATA_DIR"

  local policy_file="${CONFIG_DIR}/mcp-policy.yaml"
  local threat_intel_file="${CONFIG_DIR}/threat-intel.txt"
  local env_file="${CONFIG_DIR}/env"
  local readme="${CONFIG_DIR}/README.txt"

  if [[ ! -f "$policy_file" ]]; then
    if [[ "$DRY_RUN" -eq 1 ]]; then
      info "[dry-run] would create ${policy_file}"
    else
      tee "$policy_file" >/dev/null <<'YAML'
version: "1"
global:
  redact_keys:
    - OPENAI_API_KEY
    - ANTHROPIC_API_KEY
    - STRIPE_SECRET_KEY
    - AWS_SECRET_ACCESS_KEY
  risk_threshold: 70
tools:
  - name: execute_bash
    action: Confirm
    block_patterns:
      - 'rm\s+-rf\s+.*'
      - 'curl.*\|\s*sh'
  - name: read_file
    action: Allow
    block_patterns: &sensitive_paths
      - '\.\./\.\./'
      - '~/.ssh/.*'
      - '\.ssh/'
      - '~/.aws/.*'
      - '\.aws/credentials'
  - name: read_text_file
    action: Allow
    block_patterns: *sensitive_paths
  - name: read_media_file
    action: Allow
    block_patterns: *sensitive_paths
  - name: read_multiple_files
    action: Allow
    block_patterns: *sensitive_paths
  - name: get_file_info
    action: Allow
    block_patterns: *sensitive_paths
  - name: search_files
    action: Allow
    block_patterns: *sensitive_paths
YAML
      success "Created default policy → ${policy_file}"
    fi
  else
    info "Policy already exists — leaving untouched"
  fi

  if [[ ! -f "$threat_intel_file" ]]; then
    if [[ "$DRY_RUN" -eq 1 ]]; then
      info "[dry-run] would create ${threat_intel_file}"
    else
      tee "$threat_intel_file" >/dev/null <<'IOC'
# Local threat-intelligence blocklist (one domain or IP per line)
# Matched case-insensitively against MCP tool-call payloads (+50 risk, TTY gate)
#
# Examples — replace with your org feed or leave commented until needed:
# evil-c2.example
# malware-drop.biz
# 185.220.101.45
# 169.254.169.254
IOC
      success "Created default threat-intel blocklist → ${threat_intel_file}"
    fi
  else
    info "Threat-intel blocklist already exists — leaving untouched"
  fi

  if [[ ! -f "$env_file" ]]; then
    if [[ "$DRY_RUN" -eq 1 ]]; then
      info "[dry-run] would create ${env_file}"
    else
      tee "$env_file" >/dev/null <<ENV
# mcp-proxy local environment (sourced by your shell or IDE MCP config)
export PATH="${INSTALL_DIR}:\$PATH"
export MCP_POLICY_PATH="${policy_file}"
export MCP_THREAT_INTEL_PATH="${threat_intel_file}"
export MCP_PROXY_LOG="${DATA_DIR}/mcp-proxy.log"
export MCP_RISK_THRESHOLD="70"

# Cloud telemetry + policy sync (optional — leave blank to stay local-only)
export MCP_CONTROL_PLANE_URL=""
export MCP_DEVICE_TOKEN=""
ENV
      success "Created environment file → ${env_file}"
    fi
  else
    if ! grep -Fq '.local/bin' "$env_file" 2>/dev/null; then
      run bash -c "printf '\nexport PATH=\"${INSTALL_DIR}:\$PATH\"\n' >> '$env_file'"
      success "Updated environment file with install PATH → ${env_file}"
    else
      info "Environment file already exists — leaving untouched"
    fi
  fi

  if [[ "$DRY_RUN" -eq 1 ]]; then
    info "[dry-run] would write ${readme}"
  else
    tee "$readme" >/dev/null <<README
mcp-proxy local configuration
=============================

Files:
  mcp-policy.yaml     Declarative tool-call policy (YAML)
  threat-intel.txt    Local domain/IP IOC blocklist
  env                 Environment variables for the proxy

Quick start:
  source "${env_file}"
  mcp-proxy -- run npx @modelcontextprotocol/server-filesystem /tmp

Docs:
  https://github.com/sdk-bens/sqreen/tree/main/mcp-proxy
README
  fi

  success "Configuration directory ready: ${CONFIG_DIR}"
}

# ── IDE / host application hooking ───────────────────────────────────────────
# Returns candidate MCP JSON config paths, one per line.
discover_ide_configs() {
  local candidates=()

  if [[ "$OS" == "darwin" ]]; then
    candidates+=(
      "${HOME}/Library/Application Support/Claude/claude_desktop_config.json"
      "${HOME}/.cursor/mcp.json"
      "${HOME}/Library/Application Support/Cursor/User/mcp.json"
    )
  else
    candidates+=(
      "${HOME}/.config/Claude/claude_desktop_config.json"
      "${HOME}/.cursor/mcp.json"
      "${HOME}/.config/cursor/mcp.json"
    )
  fi

  local path
  for path in "${candidates[@]}"; do
    [[ -f "$path" ]] && printf '%s\n' "$path"
  done
}

is_already_wrapped() {
  local file="$1"
  grep -Fq 'mcp-proxy' "$file" 2>/dev/null
}

backup_config() {
  local file="$1"
  local backup="${file}.bak.$(date +%Y%m%d%H%M%S)"
  run cp "$file" "$backup"
  info "Backup saved → ${backup}"
}

wrap_config_with_jq() {
  local file="$1"
  local proxy_bin="$2"

  jq --arg proxy "$proxy_bin" '
    .mcpServers |= with_entries(
      .value |= (
        if (.command // "" | test("mcp-proxy")) then .
        else
          {
            command: $proxy,
            args: (["--", "run", .command] + (.args // [])),
            env: (.env // {})
          }
        end
      )
    )
  ' "$file"
}

wrap_config_with_python() {
  local file="$1"
  local proxy_bin="$2"

  python3 - "$file" "$proxy_bin" <<'PY'
import json, sys
from pathlib import Path

path, proxy = sys.argv[1], sys.argv[2]
data = json.loads(Path(path).read_text())
servers = data.get("mcpServers", {})
for name, cfg in servers.items():
    cmd = cfg.get("command", "")
    if "mcp-proxy" in cmd:
        continue
    args = cfg.get("args") or []
    env = cfg.get("env") or {}
    cfg.clear()
    cfg.update({
        "command": proxy,
        "args": ["--", "run", cmd, *args],
        "env": env,
    })
Path(path).write_text(json.dumps(data, indent=2) + "\n")
PY
}

wrap_ide_config() {
  local file="$1"
  local proxy_bin="${INSTALL_DIR}/mcp-proxy"

  if is_already_wrapped "$file"; then
    info "Already wrapped: ${file}"
    return 0
  fi

  if ! python3 -c 'import json,sys; json.load(open(sys.argv[1]))' "$file" 2>/dev/null; then
    warn "Skipping invalid JSON: ${file}"
    return 1
  fi

  backup_config "$file"

  if command -v jq >/dev/null 2>&1; then
    info "Patching with jq → ${file}"
    if [[ "$DRY_RUN" -eq 1 ]]; then
      info "[dry-run] would wrap MCP servers in ${file}"
      return 0
    fi
    wrap_config_with_jq "$file" "$proxy_bin" | run tee "$file" >/dev/null
  elif command -v python3 >/dev/null 2>&1; then
    info "Patching with python3 → ${file}"
    if [[ "$DRY_RUN" -eq 1 ]]; then
      info "[dry-run] would wrap MCP servers in ${file}"
      return 0
    fi
    run wrap_config_with_python "$file" "$proxy_bin"
  else
    warn "Neither jq nor python3 available — cannot safely patch ${file}"
    return 1
  fi

  success "Wrapped MCP servers → ${file}"
}

seed_cursor_hooks() {
  step "Seeding Cursor IDE hooks (sensitive-path blocker)"

  local hook_dir="${CONFIG_DIR}/hooks"
  local hook_script="${hook_dir}/block-sensitive-paths.py"
  local hook_source=""

  if [[ -n "$INSTALL_SCRIPT_DIR" && -f "${INSTALL_SCRIPT_DIR}/../.cursor/hooks/block-sensitive-paths.py" ]]; then
    hook_source="${INSTALL_SCRIPT_DIR}/../.cursor/hooks/block-sensitive-paths.py"
  elif [[ -n "$INSTALL_SCRIPT_DIR" && -f "${INSTALL_SCRIPT_DIR}/../../.cursor/hooks/block-sensitive-paths.py" ]]; then
    hook_source="${INSTALL_SCRIPT_DIR}/../../.cursor/hooks/block-sensitive-paths.py"
  fi

  run mkdir -p "$hook_dir"

  if [[ "$DRY_RUN" -eq 1 ]]; then
    info "[dry-run] would install Cursor hook script → ${hook_script}"
  elif [[ -n "$hook_source" ]]; then
    run cp "$hook_source" "$hook_script"
    run chmod +x "$hook_script"
    success "Installed Cursor hook script → ${hook_script}"
  elif command -v curl >/dev/null 2>&1; then
    run curl -fsSL \
      "https://raw.githubusercontent.com/${GITHUB_REPO}/${SOURCE_BRANCH}/.cursor/hooks/block-sensitive-paths.py" \
      -o "$hook_script"
    run chmod +x "$hook_script"
    success "Downloaded Cursor hook script → ${hook_script}"
  else
    warn "Could not locate block-sensitive-paths.py — skip Cursor hook seeding"
    return 0
  fi

  if command -v git >/dev/null 2>&1 && git rev-parse --is-inside-work-tree >/dev/null 2>&1; then
    local project_root
    project_root="$(git rev-parse --show-toplevel)"
    local project_cursor="${project_root}/.cursor"
    local project_hook="${project_cursor}/hooks/block-sensitive-paths.py"
    local project_hooks_json="${project_cursor}/hooks.json"

    run mkdir -p "${project_cursor}/hooks"
    if [[ "$DRY_RUN" -eq 1 ]]; then
      info "[dry-run] would copy hook into project → ${project_hook}"
    else
      run cp "$hook_script" "$project_hook"
      run chmod +x "$project_hook"
    fi

    if [[ ! -f "$project_hooks_json" ]]; then
      if [[ "$DRY_RUN" -eq 1 ]]; then
        info "[dry-run] would create ${project_hooks_json}"
      else
        tee "$project_hooks_json" >/dev/null <<'HOOKS'
{
  "version": 1,
  "hooks": {
    "beforeShellExecution": [{"command": "python3 .cursor/hooks/block-sensitive-paths.py", "failClosed": true}],
    "beforeReadFile": [{"command": "python3 .cursor/hooks/block-sensitive-paths.py", "failClosed": true}],
    "beforeTabFileRead": [{"command": "python3 .cursor/hooks/block-sensitive-paths.py", "failClosed": true}],
    "beforeMCPExecution": [{"command": "python3 .cursor/hooks/block-sensitive-paths.py", "failClosed": true}],
    "preToolUse": [{"command": "python3 .cursor/hooks/block-sensitive-paths.py", "matcher": "Shell|Read|Grep|Glob|MCP", "failClosed": true}]
  }
}
HOOKS
        success "Created project Cursor hooks → ${project_hooks_json}"
      fi
    else
      info "Project hooks.json already exists — leaving untouched"
    fi
  else
    info "Not inside a git repo — project .cursor/hooks.json not seeded (hook script at ${hook_script})"
  fi
}

hook_ide_configs() {
  step "Hooking IDE / AI host MCP configurations"

  local configs file

  configs="$(discover_ide_configs)"
  if [ -z "$configs" ]; then
    warn "No supported IDE MCP configs found on this machine"
    info "Manual wiring example:"
    printf '%s\n' \
      '  "command": "'"${INSTALL_DIR}/mcp-proxy"'",' \
      '  "args": ["--", "run", "npx", "-y", "@modelcontextprotocol/server-filesystem", "/path"]'
    return 0
  fi

  while IFS= read -r file; do
    [[ -n "$file" ]] || continue
    info "Found host config: ${file}"
    wrap_ide_config "$file" || warn "Failed to patch ${file}"
  done <<EOF
$configs
EOF
}

# ── Main ──────────────────────────────────────────────────────────────────────
main() {
  printf "\n%s%s╔══════════════════════════════════════╗%s\n" "$BOLD" "$CYAN" "$RESET"
  printf "%s%s║       mcp-proxy · local installer    ║%s\n" "$BOLD" "$CYAN" "$RESET"
  printf "%s%s╚══════════════════════════════════════╝%s\n\n" "$BOLD" "$CYAN" "$RESET"

  detect_platform
  ensure_install_dir
  download_binary
  ensure_path
  seed_config
  seed_cursor_hooks

  if [[ "$SKIP_IDE" -eq 0 ]]; then
    hook_ide_configs
  else
    info "Skipping IDE hooking (--skip-ide)"
  fi

  printf "\n"
  success "Installation complete"
  info "Binary:  ${INSTALL_DIR}/mcp-proxy"
  info "Config:  ${CONFIG_DIR}"
  info "Logs:    ${DATA_DIR}/mcp-proxy.log"
  printf "\n"
  info "Restart Claude Desktop / Cursor, or run manually:"
  printf "  source %s\n" "${CONFIG_DIR}/env"
  printf "  mcp-proxy -- run npx @modelcontextprotocol/server-filesystem \$HOME\n\n"
}

main "$@"
