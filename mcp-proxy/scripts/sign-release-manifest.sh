#!/usr/bin/env bash
# Build a release-manifest.json and Ed25519-sign it for Sqreen mcp-proxy releases.
#
# Usage:
#   SQREEN_RELEASE_SIGNING_KEY=/path/to/private.pem \
#     ./scripts/sign-release-manifest.sh <version> <artifacts-dir> <output-dir>
#
# Example:
#   ./scripts/sign-release-manifest.sh v0.1.10 ./artifacts ./dist
#
# Outputs in <output-dir>:
#   release-manifest.json
#   release-manifest.json.sig   (raw Ed25519 signature over the exact manifest bytes)
#
# The private key must NEVER be committed. Set via env / GitHub Actions secret.

set -euo pipefail

VERSION="${1:?usage: sign-release-manifest.sh <version> <artifacts-dir> <output-dir>}"
ARTIFACTS_DIR="${2:?}"
OUT_DIR="${3:?}"

resolve_openssl() {
  if [[ -n "${SQREEN_OPENSSL_BIN:-}" && -x "${SQREEN_OPENSSL_BIN}" ]]; then
    printf '%s\n' "${SQREEN_OPENSSL_BIN}"
    return 0
  fi
  for candidate in /opt/homebrew/bin/openssl /usr/local/bin/openssl openssl; do
    if command -v "$candidate" >/dev/null 2>&1 || [[ -x "$candidate" ]]; then
      local bin
      bin="$(command -v "$candidate" 2>/dev/null || printf '%s' "$candidate")"
      if "$bin" list -public-key-algorithms 2>/dev/null | grep -qi ed25519 \
        || "$bin" list -public-key-methods 2>/dev/null | grep -qi ed25519 \
        || "$bin" version 2>/dev/null | grep -q 'OpenSSL 3'; then
        printf '%s\n' "$bin"
        return 0
      fi
    fi
  done
  echo "error: OpenSSL 3.x with Ed25519 support is required to sign releases" >&2
  exit 1
}

sha256_file() {
  local path="$1"
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$path" | awk '{print $1}'
  else
    shasum -a 256 "$path" | awk '{print $1}'
  fi
}

OPENSSL_BIN="$(resolve_openssl)"

if [[ -z "${SQREEN_RELEASE_SIGNING_KEY:-}" ]]; then
  echo "error: SQREEN_RELEASE_SIGNING_KEY must point to the Ed25519 private key PEM" >&2
  exit 1
fi
if [[ ! -f "$SQREEN_RELEASE_SIGNING_KEY" ]]; then
  echo "error: signing key not found: $SQREEN_RELEASE_SIGNING_KEY" >&2
  exit 1
fi

# Reject shell-dangerous / non-semver tags early.
if [[ ! "$VERSION" =~ ^v?[0-9]+\.[0-9]+\.[0-9]+([.-][A-Za-z0-9.-]+)?$ ]]; then
  echo "error: invalid version string: $VERSION" >&2
  exit 1
fi

mkdir -p "$OUT_DIR"

REQUIRED=(
  mcp-proxy-darwin-aarch64.tar.gz
  mcp-proxy-darwin-x86_64.tar.gz
  mcp-proxy-linux-aarch64.tar.gz
  mcp-proxy-linux-x86_64.tar.gz
)

manifest_tmp="$(mktemp)"
trap 'rm -f "$manifest_tmp"' EXIT

{
  printf '{\n'
  printf '  "schema_version": 1,\n'
  printf '  "product": "mcp-proxy",\n'
  printf '  "version": "%s",\n' "$VERSION"
  printf '  "created_at": "%s",\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  printf '  "hash_algorithm": "sha256",\n'
  printf '  "signature_algorithm": "ed25519",\n'
  printf '  "artifacts": {\n'

  first=1
  for name in "${REQUIRED[@]}"; do
    path="${ARTIFACTS_DIR}/${name}"
    if [[ ! -f "$path" ]]; then
      echo "error: required artifact missing: $path" >&2
      exit 1
    fi
    digest="$(sha256_file "$path")"
    size="$(wc -c <"$path" | tr -d ' ')"
    if [[ "$first" -eq 0 ]]; then
      printf ',\n'
    fi
    first=0
    printf '    "%s": {\n' "$name"
    printf '      "sha256": "%s",\n' "$digest"
    printf '      "size": %s\n' "$size"
    printf '    }'
  done

  printf '\n  }\n'
  printf '}\n'
} >"$manifest_tmp"

# Canonical bytes: exact file we sign and publish (no re-serialization).
cp "$manifest_tmp" "${OUT_DIR}/release-manifest.json"

"$OPENSSL_BIN" pkeyutl -sign \
  -inkey "$SQREEN_RELEASE_SIGNING_KEY" \
  -rawin \
  -in "${OUT_DIR}/release-manifest.json" \
  -out "${OUT_DIR}/release-manifest.json.sig"

echo "signed release-manifest.json for ${VERSION}"
echo "  manifest: ${OUT_DIR}/release-manifest.json"
echo "  signature: ${OUT_DIR}/release-manifest.json.sig"
