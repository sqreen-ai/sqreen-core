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
FORCE=0
INSECURE_SKIP_VERIFY=0
INSTALL_DIR="${MCP_PROXY_INSTALL_DIR:-${HOME}/.local/bin}"
CONFIG_DIR="${MCP_PROXY_CONFIG_DIR:-${HOME}/.config/mcp-proxy}"
DATA_DIR="${MCP_PROXY_DATA_DIR:-${HOME}/.local/share/mcp-proxy}"
GITHUB_REPO="${MCP_PROXY_GITHUB_REPO:-sqreen-ai/sqreen}"
SQREEN_RELEASE_BASE="${MCP_PROXY_SQREEN_RELEASE_URL:-https://sqreen.ai/releases}"
RELEASE_BASE="${MCP_PROXY_RELEASE_URL:-https://github.com/${GITHUB_REPO}/releases}"
SOURCE_BRANCH="${MCP_PROXY_SOURCE_BRANCH:-main}"
INSTALL_SCRIPT_DIR=""
INSTALLER_REVISION="7"

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
  --force         Allow installing an older version than the one already present
  --insecure-skip-verify
                  DANGEROUS: skip Ed25519/SHA-256 verification (break-glass only)
  -h, --help      Show this help message

Environment:
  MCP_PROXY_SQREEN_RELEASE_URL  Primary release mirror (default: sqreen.ai/releases)
  MCP_PROXY_RELEASE_URL   GitHub releases fallback base
  MCP_PROXY_GITHUB_REPO   owner/repo for source fallback (default: sqreen-ai/sqreen)
  MCP_PROXY_INSTALL_DIR   Binary destination (default: ~/.local/bin)
  MCP_PROXY_CONFIG_DIR    Config directory (default: ~/.config/mcp-proxy)
  SQREEN_OPENSSL_BIN      OpenSSL 3 binary with Ed25519 (optional override)
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --dry-run) DRY_RUN=1; shift ;;
    --skip-ide) SKIP_IDE=1; shift ;;
    --force) FORCE=1; shift ;;
    --insecure-skip-verify) INSECURE_SKIP_VERIFY=1; shift ;;
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

# ── Release integrity (Ed25519 + SHA-256) ─────────────────────────────────────
# Trust root: Ed25519 public key embedded below (also at mcp-proxy/keys/ and
# https://sqreen.ai/releases/sqreen-release-ed25519.pub). Artifact hosts are NOT
# trusted without a signature over release-manifest.json that verifies against
# this key.

RELEASE_PUBKEY_FINGERPRINT="ddd41d35e3b6aa600575bd608cd5a6f63e0ddf04842e9e993b9062ed1d3116d9"

embedded_release_pubkey() {
  cat <<'EOF'
-----BEGIN PUBLIC KEY-----
MCowBQYDK2VwAyEANfdulWqyA9MqdXO2RU61ERujgYWSL8p7PuqUc6r8Hqw=
-----END PUBLIC KEY-----
EOF
}

validate_version_string() {
  local ver="$1"
  if [[ "$ver" == "latest" ]]; then
    return 0
  fi
  # Reject path/shell metacharacters and non-semver tags before URL interpolation.
  if [[ "$ver" =~ [/\\\$\`\;\|\&\<\>\(\)\{\}\'\"\*\?\~] ]]; then
    error "Sqreen installation aborted: invalid characters in version '${ver}'"
    exit 1
  fi
  if [[ ! "$ver" =~ ^v?[0-9]+\.[0-9]+\.[0-9]+([.-][A-Za-z0-9.-]+)?$ ]]; then
    error "Sqreen installation aborted: malformed version '${ver}' (expected vX.Y.Z or latest)"
    exit 1
  fi
}

resolve_openssl() {
  if [[ -n "${SQREEN_OPENSSL_BIN:-}" && -x "${SQREEN_OPENSSL_BIN}" ]]; then
    printf '%s\n' "${SQREEN_OPENSSL_BIN}"
    return 0
  fi
  local candidate
  for candidate in /opt/homebrew/bin/openssl /usr/local/opt/openssl@3/bin/openssl /usr/local/bin/openssl openssl; do
    if [[ -x "$candidate" ]] || command -v "$candidate" >/dev/null 2>&1; then
      local bin
      bin="$(command -v "$candidate" 2>/dev/null || printf '%s' "$candidate")"
      if "$bin" list -public-key-algorithms 2>/dev/null | grep -qi ed25519; then
        printf '%s\n' "$bin"
        return 0
      fi
      # OpenSSL 3 always has Ed25519 even if list syntax differs.
      if "$bin" version 2>/dev/null | grep -Eq 'OpenSSL 3\.'; then
        printf '%s\n' "$bin"
        return 0
      fi
    fi
  done
  return 1
}

sha256_file() {
  local path="$1"
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$path" | awk '{print $1}'
  elif command -v shasum >/dev/null 2>&1; then
    shasum -a 256 "$path" | awk '{print $1}'
  else
    error "Sqreen installation aborted: neither sha256sum nor shasum is available"
    exit 1
  fi
}

secure_curl() {
  # HTTPS-only, fail on HTTP errors, limited redirects, no auth leakage.
  curl --proto '=https' --tlsv1.2 --fail --silent --show-error \
    --location --max-redirs 3 \
    --retry 2 --retry-delay 1 \
    "$@"
}

verify_manifest_signature() {
  local manifest="$1"
  local signature="$2"
  local openssl_bin pubkey_file
  if ! openssl_bin="$(resolve_openssl)"; then
    error "Sqreen installation aborted: OpenSSL 3.x with Ed25519 is required to verify release signatures"
    info "Install OpenSSL 3 (e.g. brew install openssl@3) or set SQREEN_OPENSSL_BIN"
    exit 1
  fi
  pubkey_file="$(mktemp)"
  embedded_release_pubkey >"$pubkey_file"
  if ! "$openssl_bin" pkeyutl -verify -pubin -inkey "$pubkey_file" -rawin \
      -in "$manifest" -sigfile "$signature" >/dev/null 2>&1; then
    rm -f "$pubkey_file"
    error "Sqreen installation aborted: artifact integrity verification failed."
    info "release-manifest.json signature did not match the pinned Sqreen release key"
    info "key fingerprint (SHA-256 of DER): ${RELEASE_PUBKEY_FINGERPRINT}"
    exit 1
  fi
  rm -f "$pubkey_file"
}

manifest_artifact_sha256() {
  local manifest="$1"
  local artifact="$2"
  if command -v python3 >/dev/null 2>&1; then
    python3 - "$manifest" "$artifact" <<'PY'
import json, sys
manifest, name = sys.argv[1], sys.argv[2]
data = json.load(open(manifest, encoding="utf-8"))
art = (data.get("artifacts") or {}).get(name)
if not art or not art.get("sha256"):
    sys.exit(2)
digest = art["sha256"].strip().lower()
if len(digest) != 64 or any(c not in "0123456789abcdef" for c in digest):
    sys.exit(3)
print(digest)
PY
    return $?
  fi
  error "Sqreen installation aborted: python3 is required to parse the release manifest"
  exit 1
}

manifest_version() {
  local manifest="$1"
  python3 -c 'import json,sys; print(json.load(open(sys.argv[1], encoding="utf-8"))["version"])' "$manifest"
}

extract_mcp_proxy_from_tar() {
  # Refuse path traversal / absolute entries; only accept a top-level `mcp-proxy` member.
  local archive="$1"
  local dest_dir="$2"
  local member

  while IFS= read -r member; do
    [[ -z "$member" ]] && continue
    if [[ "$member" == *".."* || "$member" == /* || "$member" == *:\\* ]]; then
      error "Sqreen installation aborted: archive contains unsafe path '${member}'"
      exit 1
    fi
  done < <(tar -tzf "$archive")

  if tar -tzf "$archive" | grep -qx 'mcp-proxy'; then
    tar -xzf "$archive" -C "$dest_dir" mcp-proxy
  elif tar -tzf "$archive" | grep -Eq '^[^/]+/mcp-proxy$'; then
    local nested
    nested="$(tar -tzf "$archive" | grep -E '^[^/]+/mcp-proxy$' | head -1)"
    case "$nested" in
      *..*|/*) error "Sqreen installation aborted: unsafe nested archive path"; exit 1 ;;
    esac
    tar -xzf "$archive" -C "$dest_dir" "$nested"
    mv "${dest_dir}/${nested}" "${dest_dir}/mcp-proxy"
    rmdir "$(dirname "${dest_dir}/${nested}")" 2>/dev/null || true
  else
    error "Sqreen installation aborted: archive does not contain a mcp-proxy binary"
    exit 1
  fi

  if [[ ! -f "${dest_dir}/mcp-proxy" ]]; then
    error "Sqreen installation aborted: extracted binary missing"
    exit 1
  fi
}

atomic_install_binary() {
  local src="$1"
  local dest="$2"
  local dest_dir tmp_dest
  dest_dir="$(dirname "$dest")"
  mkdir -p "$dest_dir"
  tmp_dest="$(mktemp "${dest_dir}/.mcp-proxy.XXXXXX")"
  # Copy then set mode before replace so a half-written dest is never executable as final name.
  cp "$src" "$tmp_dest"
  chmod 0755 "$tmp_dest"
  mv -f "$tmp_dest" "$dest"
}

# Brand alias — same binary as mcp-proxy (hard link when possible, else symlink).
install_sqreen_alias() {
  local dest="${INSTALL_DIR}/mcp-proxy"
  local alias_path="${INSTALL_DIR}/sqreen"
  if [[ ! -x "$dest" ]]; then
    return 0
  fi
  if [[ "$DRY_RUN" -eq 1 ]]; then
    info "[dry-run] would install alias ${alias_path} → mcp-proxy"
    return 0
  fi
  rm -f "$alias_path"
  if ln "$dest" "$alias_path" 2>/dev/null; then
    success "Alias ready: ${alias_path} (hard link)"
  elif ln -s "mcp-proxy" "$alias_path" 2>/dev/null; then
    success "Alias ready: ${alias_path} → mcp-proxy"
  else
    cp "$dest" "$alias_path"
    chmod 0755 "$alias_path"
    success "Alias ready: ${alias_path} (copy)"
  fi
}

installed_proxy_version() {
  local bin="${INSTALL_DIR}/mcp-proxy"
  if [[ ! -x "$bin" ]]; then
    return 1
  fi
  local raw
  raw="$("$bin" --version 2>/dev/null || true)"
  # Expected: "mcp-proxy 0.1.9"
  python3 - "$raw" <<'PY'
import re, sys
raw = sys.argv[1]
m = re.search(r'(\d+\.\d+\.\d+(?:[.-][A-Za-z0-9.-]+)?)', raw)
if not m:
    sys.exit(1)
print(m.group(1))
PY
}

version_is_older() {
  # Return 0 if $1 < $2 (semver-ish numeric compare without build metadata).
  local a="$1" b="$2"
  python3 - "$a" "$b" <<'PY'
import sys
def parts(v):
    v = v.lstrip("v")
    core = v.split("-")[0].split("+")[0]
    return [int(x) for x in core.split(".")]
a, b = parts(sys.argv[1]), parts(sys.argv[2])
sys.exit(0 if a < b else 1)
PY
}

refuse_silent_downgrade() {
  local target="$1"
  local current
  if ! current="$(installed_proxy_version)"; then
    return 0
  fi
  local target_norm="${target#v}"
  if version_is_older "$target_norm" "$current"; then
    if [[ "$FORCE" -eq 1 ]]; then
      warn "Downgrading mcp-proxy ${current} → ${target_norm} because --force was set"
      return 0
    fi
    error "Sqreen installation aborted: refusing to downgrade ${current} → ${target_norm}"
    info "Pass --force to override, or install an explicit newer --version"
    exit 1
  fi
}

# ── Binary install ────────────────────────────────────────────────────────────
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

download_release_file() {
  local dest="$1"
  shift
  local url
  for url in "$@"; do
    case "$url" in
      https://*) ;;
      *)
        warn "Skipping non-HTTPS URL: ${url}"
        continue
        ;;
    esac
    info "Trying ${url}"
    if secure_curl -o "$dest" "$url"; then
      # Reject empty/truncated downloads.
      if [[ ! -s "$dest" ]]; then
        warn "Empty download from ${url}"
        rm -f "$dest"
        continue
      fi
      success "Downloaded from ${url}"
      return 0
    fi
    rm -f "$dest"
  done
  return 1
}

download_binary() {
  step "Retrieving mcp-proxy binary"
  local dest="${INSTALL_DIR}/mcp-proxy"
  local work

  validate_version_string "$VERSION"

  if [[ "$INSECURE_SKIP_VERIFY" -eq 1 ]]; then
    warn "DANGER: --insecure-skip-verify disables release signature and digest checks"
  fi

  if [[ "$DRY_RUN" -eq 1 ]]; then
    info "[dry-run] would download signed release-manifest.json + ${ARTIFACT_NAME}"
    info "[dry-run] would verify Ed25519 signature (key fingerprint ${RELEASE_PUBKEY_FINGERPRINT})"
    info "[dry-run] would verify SHA-256 and atomically install → ${dest}"
    return 0
  fi

  work="$(mktemp -d)"
  tmp_cleanup() { rm -rf "$work"; }
  trap tmp_cleanup EXIT

  local version_path="$VERSION"
  local manifest="${work}/release-manifest.json"
  local signature="${work}/release-manifest.json.sig"
  local archive="${work}/${ARTIFACT_NAME}"

  local manifest_urls=()
  local signature_urls=()
  local artifact_urls=()

  if [[ "$VERSION" == "latest" ]]; then
    manifest_urls+=(
      "${SQREEN_RELEASE_BASE}/latest/release-manifest.json"
      "${RELEASE_BASE}/latest/download/release-manifest.json"
    )
    signature_urls+=(
      "${SQREEN_RELEASE_BASE}/latest/release-manifest.json.sig"
      "${RELEASE_BASE}/latest/download/release-manifest.json.sig"
    )
  else
    manifest_urls+=(
      "${SQREEN_RELEASE_BASE}/${VERSION}/release-manifest.json"
      "${RELEASE_BASE}/download/${VERSION}/release-manifest.json"
    )
    signature_urls+=(
      "${SQREEN_RELEASE_BASE}/${VERSION}/release-manifest.json.sig"
      "${RELEASE_BASE}/download/${VERSION}/release-manifest.json.sig"
    )
  fi

  if ! download_release_file "$manifest" "${manifest_urls[@]}"; then
    warn "Signed release manifest unavailable — trying source build fallback (unverified release channel)"
    trap - EXIT
    tmp_cleanup
    try_build_from_source "$dest"
    success "Installed mcp-proxy from source → ${dest}"
    sign_mcp_proxy_binary "$dest"
    install_sqreen_alias
    info "$("$dest" --version 2>/dev/null || echo 'mcp-proxy (version probe unavailable)')"
    return 0
  fi

  if ! download_release_file "$signature" "${signature_urls[@]}"; then
    if [[ "$INSECURE_SKIP_VERIFY" -eq 1 ]]; then
      warn "Manifest signature missing; continuing because --insecure-skip-verify was set"
    else
      error "Sqreen installation aborted: artifact integrity verification failed."
      info "Missing release-manifest.json.sig — cannot authenticate the release"
      exit 1
    fi
  fi

  if [[ "$INSECURE_SKIP_VERIFY" -ne 1 ]]; then
    verify_manifest_signature "$manifest" "$signature"
    success "Verified release-manifest.json signature (Ed25519)"
  fi

  version_path="$(manifest_version "$manifest")"
  validate_version_string "$version_path"
  refuse_silent_downgrade "$version_path"

  local expected_sha
  if ! expected_sha="$(manifest_artifact_sha256 "$manifest" "$ARTIFACT_NAME")"; then
    error "Sqreen installation aborted: artifact integrity verification failed."
    info "Manifest has no usable SHA-256 for ${ARTIFACT_NAME}"
    exit 1
  fi

  artifact_urls=(
    "${SQREEN_RELEASE_BASE}/${version_path}/${ARTIFACT_NAME}"
    "${SQREEN_RELEASE_BASE}/latest/${ARTIFACT_NAME}"
    "${RELEASE_BASE}/download/${version_path}/${ARTIFACT_NAME}"
    "${RELEASE_BASE}/latest/download/${ARTIFACT_NAME}"
  )

  if ! download_release_file "$archive" "${artifact_urls[@]}"; then
    error "Sqreen installation aborted: could not download ${ARTIFACT_NAME} for ${version_path}"
    exit 1
  fi

  local actual_sha
  actual_sha="$(sha256_file "$archive")"
  if [[ "$actual_sha" != "$expected_sha" ]]; then
    error "Sqreen installation aborted: artifact integrity verification failed."
    info "Expected SHA-256: ${expected_sha}"
    info "Actual SHA-256:   ${actual_sha}"
    # Do not leave a failed artifact in the install path; temp dir is cleaned by trap.
    exit 1
  fi
  success "SHA-256 verified for ${ARTIFACT_NAME}"

  extract_mcp_proxy_from_tar "$archive" "$work"
  # Never execute the downloaded binary before verification (already done) and before install.
  atomic_install_binary "${work}/mcp-proxy" "$dest"

  trap - EXIT
  tmp_cleanup

  success "Installed mcp-proxy → ${dest}"
  sign_mcp_proxy_binary "$dest"
  install_sqreen_alias
  info "$("$dest" --version 2>/dev/null || echo 'mcp-proxy (version probe unavailable)')"
}

try_build_from_source() {
  local dest="$1"
  local root=""

  warn "Source builds are not covered by the signed release-manifest trust root"
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
  atomic_install_binary "${root}/target/release/mcp-proxy" "$dest"
  sign_mcp_proxy_binary "$dest"
  install_sqreen_alias
}

build_from_github_source() {
  local dest="$1"
  local tmp root repo_url="https://github.com/${GITHUB_REPO}.git"
  local archive_url="https://github.com/${GITHUB_REPO}/archive/refs/heads/${SOURCE_BRANCH}.tar.gz"

  # Guard SOURCE_BRANCH against injection into URLs / git args.
  if [[ ! "$SOURCE_BRANCH" =~ ^[A-Za-z0-9._/-]+$ ]]; then
    error "Sqreen installation aborted: invalid MCP_PROXY_SOURCE_BRANCH"
    exit 1
  fi
  if [[ ! "$GITHUB_REPO" =~ ^[A-Za-z0-9._-]+/[A-Za-z0-9._-]+$ ]]; then
    error "Sqreen installation aborted: invalid MCP_PROXY_GITHUB_REPO"
    exit 1
  fi

  if ! ensure_cargo; then
    install_unavailable_no_cargo
  fi

  tmp="$(mktemp -d)"
  cleanup_src() { rm -rf "$tmp"; }
  trap cleanup_src RETURN

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
  if ! secure_curl "$archive_url" | tar -xzf - -C "$tmp"; then
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
# BEGIN SECURITY_BASELINE_SEED
version: "baseline-2026.3"
global:
  redact_keys:
    - OPENAI_API_KEY
    - ANTHROPIC_API_KEY
    - STRIPE_SECRET_KEY
    - AWS_SECRET_ACCESS_KEY
    - AWS_SESSION_TOKEN
    - AWS_ACCESS_KEY_ID
    - GITHUB_TOKEN
    - GH_TOKEN
    - SLACK_BOT_TOKEN
    - SLACK_TOKEN
    - AUTHORIZATION
    - PASSWORD
    - PASSWD
    - SECRET
    - TOKEN
    - ACCESS_TOKEN
    - REFRESH_TOKEN
    - API_KEY
    - APIKEY
    - PRIVATE_KEY
    - CLIENT_SECRET
    - COOKIE
  risk_threshold: 70
  block_patterns: &sensitive_paths
    - '\.\./\.\./'
    - '%2e%2e'
    - '%2E%2E'
    - '%252e%252e'
    - '%252E%252E'
    - '~/.ssh/.*'
    - '\.ssh/'
    - '~/.aws/.*'
    - '\.aws/credentials'
    - '~/.gnupg/.*'
    - '/etc/shadow'
    - '/etc/passwd'
    - '\.env(\.|$)'
    - 'id_rsa(\.|$)'
    - 'id_ed25519(\.|$)'
    - '\.kube/config'
    - '\.netrc'
    - '\.pgpass'
tools:
  - name: execute_bash
    action: Confirm
    block_patterns:
      - 'rm\s+-rf\s+.*'
      - 'curl.*\|\s*sh'
      - 'wget.*\|\s*sh'
      - 'chmod\s+[0-7]{3,4}\s+.*'
      - 'sudo\s+.*'
      - 'mkfs\..*'
      - ':\(\)\{ :\|:& \};:'
  - name: run_terminal_cmd
    action: Confirm
    block_patterns:
      - 'rm\s+-rf\s+.*'
      - 'curl.*\|\s*sh'
      - 'wget.*\|\s*sh'
      - 'chmod\s+[0-7]{3,4}\s+.*'
      - 'sudo\s+.*'
      - 'mkfs\..*'
      - ':\(\)\{ :\|:& \};:'
  - name: shell
    action: Confirm
    block_patterns:
      - 'rm\s+-rf\s+.*'
      - 'curl.*\|\s*sh'
      - 'wget.*\|\s*sh'
      - 'chmod\s+[0-7]{3,4}\s+.*'
      - 'sudo\s+.*'
      - 'mkfs\..*'
      - ':\(\)\{ :\|:& \};:'
  - name: bash
    action: Confirm
    block_patterns:
      - 'rm\s+-rf\s+.*'
      - 'curl.*\|\s*sh'
      - 'wget.*\|\s*sh'
      - 'chmod\s+[0-7]{3,4}\s+.*'
      - 'sudo\s+.*'
      - 'mkfs\..*'
      - ':\(\)\{ :\|:& \};:'
  - name: sh
    action: Confirm
    block_patterns:
      - 'rm\s+-rf\s+.*'
      - 'curl.*\|\s*sh'
      - 'wget.*\|\s*sh'
      - 'chmod\s+[0-7]{3,4}\s+.*'
      - 'sudo\s+.*'
      - 'mkfs\..*'
      - ':\(\)\{ :\|:& \};:'
  - name: zsh
    action: Confirm
    block_patterns:
      - 'rm\s+-rf\s+.*'
      - 'curl.*\|\s*sh'
      - 'wget.*\|\s*sh'
      - 'chmod\s+[0-7]{3,4}\s+.*'
      - 'sudo\s+.*'
      - 'mkfs\..*'
      - ':\(\)\{ :\|:& \};:'
  - name: powershell
    action: Confirm
    block_patterns:
      - 'rm\s+-rf\s+.*'
      - 'curl.*\|\s*sh'
      - 'wget.*\|\s*sh'
      - 'chmod\s+[0-7]{3,4}\s+.*'
      - 'sudo\s+.*'
      - 'mkfs\..*'
      - ':\(\)\{ :\|:& \};:'
  - name: pwsh
    action: Confirm
    block_patterns:
      - 'rm\s+-rf\s+.*'
      - 'curl.*\|\s*sh'
      - 'wget.*\|\s*sh'
      - 'chmod\s+[0-7]{3,4}\s+.*'
      - 'sudo\s+.*'
      - 'mkfs\..*'
      - ':\(\)\{ :\|:& \};:'
  - name: cmd
    action: Confirm
    block_patterns:
      - 'rm\s+-rf\s+.*'
      - 'curl.*\|\s*sh'
      - 'wget.*\|\s*sh'
      - 'chmod\s+[0-7]{3,4}\s+.*'
      - 'sudo\s+.*'
      - 'mkfs\..*'
      - ':\(\)\{ :\|:& \};:'
  - name: run_command
    action: Confirm
    block_patterns:
      - 'rm\s+-rf\s+.*'
      - 'curl.*\|\s*sh'
      - 'wget.*\|\s*sh'
      - 'chmod\s+[0-7]{3,4}\s+.*'
      - 'sudo\s+.*'
      - 'mkfs\..*'
      - ':\(\)\{ :\|:& \};:'
  - name: terminal
    action: Confirm
    block_patterns:
      - 'rm\s+-rf\s+.*'
      - 'curl.*\|\s*sh'
      - 'wget.*\|\s*sh'
      - 'chmod\s+[0-7]{3,4}\s+.*'
      - 'sudo\s+.*'
      - 'mkfs\..*'
      - ':\(\)\{ :\|:& \};:'
  - name: read_file
    action: Allow
    block_patterns: *sensitive_paths
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
  - name: write_file
    action: Confirm
    block_patterns: *sensitive_paths
  - name: edit_file
    action: Confirm
    block_patterns: *sensitive_paths
  - name: apply_patch
    action: Confirm
    block_patterns: *sensitive_paths
  - name: create_directory
    action: Confirm
    block_patterns: *sensitive_paths
  - name: move_file
    action: Confirm
    block_patterns: *sensitive_paths
  - name: fetch
    action: Allow
    block_patterns:
      - '169\.254\.169\.254'
      - 'metadata\.google\.internal'
      - 'file://.*'
  - name: http_request
    action: Allow
    block_patterns:
      - '169\.254\.169\.254'
      - 'metadata\.google\.internal'
      - 'file://.*'
  - name: web_fetch
    action: Allow
    block_patterns:
      - '169\.254\.169\.254'
      - 'metadata\.google\.internal'
      - 'file://.*'
  - name: curl
    action: Allow
    block_patterns:
      - '169\.254\.169\.254'
      - 'metadata\.google\.internal'
      - 'file://.*'
# END SECURITY_BASELINE_SEED
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
# Secure default: missing policy DENIES. Opt into permissive local DX only consciously:
#   export SQREEN_ENFORCEMENT_POSTURE=development
export SQREEN_ENFORCEMENT_POSTURE="enforcing"

# Cloud telemetry + policy sync (optional — leave blank to stay local-only)
# Do not put long-lived secrets in world-readable files. Prefer 0600 permissions.
# Obtain MCP_DEVICE_TOKEN via admin mint (POST /api/v1/device-tokens) — never a repo default.
export MCP_CONTROL_PLANE_URL=""
export MCP_DEVICE_TOKEN=""
ENV
      chmod 0600 "$env_file" 2>/dev/null || true
      success "Created environment file → ${env_file} (mode 0600)"
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
  mcp-proxy demo
  mcp-proxy -- run npx -y @modelcontextprotocol/server-filesystem /tmp

Uninstall:
  Restore IDE mcp.json from the newest .bak.* beside it (if wrapped).
  Remove: ${INSTALL_DIR}/mcp-proxy (and optional ${INSTALL_DIR}/sqreen alias)
  Optional purge: rm -rf ${CONFIG_DIR} ${DATA_DIR}
  Remove PATH lines added to ~/.zshrc / ~/.bashrc / ~/.profile

Docs:
  https://sqreen.ai/products
  https://github.com/sqreen-ai/sqreen
README
  fi

  success "Configuration directory ready: ${CONFIG_DIR}"
}

# ── IDE / host application hooking ───────────────────────────────────────────
# True when the JSON file has an mcpServers object (not null / missing).
is_mcp_host_config() {
  local file="$1"

  if command -v python3 >/dev/null 2>&1; then
    python3 -c 'import json,sys; d=json.load(open(sys.argv[1])); sys.exit(0 if isinstance(d.get("mcpServers"), dict) else 1)' "$file" 2>/dev/null
    return $?
  fi

  if command -v jq >/dev/null 2>&1; then
    jq -e '(.mcpServers | type) == "object"' "$file" >/dev/null 2>&1
    return $?
  fi

  return 1
}

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
    if [[ -f "$path" ]] && is_mcp_host_config "$path"; then
      printf '%s\n' "$path"
    fi
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
  local policy_file="${CONFIG_DIR}/mcp-policy.yaml"
  local threat_file="${CONFIG_DIR}/threat-intel.txt"

  jq --arg proxy "$proxy_bin" --arg policy "$policy_file" --arg threat "$threat_file" '
    .mcpServers //= {}
    | .mcpServers |= with_entries(
      .value |= (
        if (.command // "" | test("mcp-proxy")) then .
        else
          {
            command: $proxy,
            args: (["--", "run", .command] + (.args // [])),
            env: (
              (.env // {})
              + {
                  MCP_POLICY_PATH: $policy,
                  MCP_THREAT_INTEL_PATH: $threat
                }
            )
          }
        end
      )
    )
  ' "$file"
}

wrap_config_with_python() {
  local file="$1"
  local proxy_bin="$2"
  local policy_file="${CONFIG_DIR}/mcp-policy.yaml"
  local threat_file="${CONFIG_DIR}/threat-intel.txt"

  python3 - "$file" "$proxy_bin" "$policy_file" "$threat_file" <<'PY'
import json, sys
from pathlib import Path

path, proxy, policy, threat = sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4]
data = json.loads(Path(path).read_text())
servers = data.get("mcpServers") or {}
for name, cfg in servers.items():
    cmd = cfg.get("command", "")
    if "mcp-proxy" in cmd:
        continue
    args = cfg.get("args") or []
    env = dict(cfg.get("env") or {})
    env.setdefault("MCP_POLICY_PATH", policy)
    env.setdefault("MCP_THREAT_INTEL_PATH", threat)
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
    local tmp
    tmp="$(mktemp)"
    if ! wrap_config_with_jq "$file" "$proxy_bin" > "$tmp"; then
      rm -f "$tmp"
      warn "Failed to patch ${file}"
      return 1
    fi
    run mv "$tmp" "$file"
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
    # Patterns module required by the hook loader.
    local patterns_src
    patterns_src="$(dirname "$hook_source")/generated_sensitive_patterns.py"
    if [[ -f "$patterns_src" ]]; then
      run cp "$patterns_src" "${hook_dir}/generated_sensitive_patterns.py"
    fi
    run chmod +x "$hook_script"
    success "Installed Cursor hook script → ${hook_script}"
  elif command -v curl >/dev/null 2>&1; then
    run secure_curl \
      "https://raw.githubusercontent.com/${GITHUB_REPO}/${SOURCE_BRANCH}/.cursor/hooks/block-sensitive-paths.py" \
      -o "$hook_script"
    run secure_curl \
      "https://raw.githubusercontent.com/${GITHUB_REPO}/${SOURCE_BRANCH}/.cursor/hooks/generated_sensitive_patterns.py" \
      -o "${hook_dir}/generated_sensitive_patterns.py" || true
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
      if [[ -f "${hook_dir}/generated_sensitive_patterns.py" ]]; then
        run cp "${hook_dir}/generated_sensitive_patterns.py" "${project_cursor}/hooks/generated_sensitive_patterns.py"
      fi
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

  while IFS= read -r file || [[ -n "${file:-}" ]]; do
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

  validate_version_string "$VERSION"
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
  info "Alias:   ${INSTALL_DIR}/sqreen  (same binary)"
  info "Config:  ${CONFIG_DIR}"
  info "Logs:    ${DATA_DIR}/mcp-proxy.log"
  printf "\n"
  info "See your first protected Agent Action (safe demo):"
  printf "  source %s\n" "${CONFIG_DIR}/env"
  printf "  mcp-proxy demo\n"
  printf "  # or: sqreen demo\n\n"
  info "Then restart Claude Desktop / Cursor, or run an MCP server:"
  printf "  mcp-proxy -- run npx -y @modelcontextprotocol/server-filesystem .\n\n"
  info "OpenAI-compatible HTTP agents:"
  printf "  mcp-proxy serve --listen 127.0.0.1:8787 --upstream https://api.openai.com\n"
  printf "  export OPENAI_BASE_URL=http://127.0.0.1:8787/v1\n\n"
  info "Anthropic Messages API (same serve process; set base URL in your SDK):\n"
  printf "  mcp-proxy serve --listen 127.0.0.1:8787 --upstream https://api.anthropic.com\n\n"
  info "Uninstall tips: ${CONFIG_DIR}/README.txt\n"
}

main "$@"
