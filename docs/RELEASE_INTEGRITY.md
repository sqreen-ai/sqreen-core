# Release integrity (mcp-proxy)

How Sqreen authenticates prebuilt `mcp-proxy` install artifacts.

## Guarantees (what is true)

1. Every published release includes a **`release-manifest.json`** listing SHA-256 digests for all supported platform archives.
2. That manifest is **Ed25519-signed**. The installer verifies the signature against a **pinned public key** embedded in `mcp-proxy/install.sh` (and checked into `mcp-proxy/keys/sqreen-release-ed25519.pub`).
3. The installer downloads the archive into a temp directory, checks SHA-256 against the signed manifest, extracts safely, then **atomically** replaces `~/.local/bin/mcp-proxy`.
4. Verification failure **fails closed** — the existing binary is not replaced; the process exits with:
   `Sqreen installation aborted: artifact integrity verification failed.`
5. HTTPS-only downloads (`curl --proto '=https'`), limited redirects, non-empty bodies required.
6. Automatic installs of `latest` refuse silent downgrades unless `--force` is set.

## What is cryptographically verified

| Object | Check |
|--------|--------|
| `release-manifest.json` | Ed25519 signature (`release-manifest.json.sig`) vs pinned public key |
| Each `.tar.gz` | SHA-256 must match the digest inside the **verified** manifest |

Checksums alone (downloaded next to the binary from the same host) are **not** treated as authenticity. Digests are only trusted after the manifest signature verifies.

## Trust root

- **Algorithm:** Ed25519 (OpenSSL 3 `pkeyutl`)
- **Public key path in repo:** `mcp-proxy/keys/sqreen-release-ed25519.pub`
- **Also published at:** `https://sqreen.ai/releases/sqreen-release-ed25519.pub` (transparency copy; **installers do not trust a downloaded key**)
- **Fingerprint (SHA-256 of DER):** `ddd41d35e3b6aa600575bd608cd5a6f63e0ddf04842e9e993b9062ed1d3116d9`
- **Private key:** GitHub Actions secret `SQREEN_RELEASE_SIGNING_KEY_B64` (base64 of the PEM). Never committed.

## Maintainer: publish a trusted release

1. Ensure `SQREEN_RELEASE_SIGNING_KEY_B64` is set on the origin repository (Settings → Secrets). Encode with:
   ```bash
   base64 < /path/to/sqreen-release-ed25519.pem | pbcopy   # macOS
   ```
2. Tag and push: `git tag vX.Y.Z && git push origin vX.Y.Z`
3. Workflow `.github/workflows/release-mcp-proxy.yml`:
   - builds all four platform artifacts (fails if any missing)
   - runs `mcp-proxy/scripts/sign-release-manifest.sh`
   - uploads tarballs + `release-manifest.json` + `.sig` to the GitHub Release
   - copies the same files into `frontend/public/releases/` for sqreen.ai
   - syncs `frontend/public/install.sh` from the canonical installer

Fork PRs and `pull_request` workflows **do not** receive the signing secret and cannot publish.

## Key rotation

1. Generate a new Ed25519 keypair (`openssl genpkey -algorithm Ed25519`).
2. Commit the new **public** key; update the embedded key + fingerprint in `install.sh`.
3. Store the new private key as `SQREEN_RELEASE_SIGNING_KEY_B64`.
4. Cut a new release. Old installers still embed the old key — ship a transitional installer that accepts either key if overlap is required, then remove the old key in a later revision.

## Break-glass

`--insecure-skip-verify` disables signature/digest enforcement. It prints a loud warning. Do not use in production fleets.

Source-build fallback (when no signed manifest is reachable) is **not** covered by the release trust root; the installer says so explicitly.

## Installer single source of truth

| Path | Role |
|------|------|
| `mcp-proxy/install.sh` | **Canonical** |
| `frontend/public/install.sh` | Deployed copy for `https://sqreen.ai/install.sh` |

`mcp-proxy/scripts/sync-installer.sh` copies canonical → public.  
`mcp-proxy/scripts/check-installer-sync.sh` fails CI if they diverge.

## Claim boundary

**True:** compromise of the *artifact hosting location alone* (tarball CDN / GitHub release assets), without the signing private key, is insufficient to cause clients that already trust the embedded public key to install attacker-modified binaries.

**Not claimed:** compromise of the host that serves `install.sh` itself to a fresh `curl | bash` user (the script and key could be swapped together). Prefer installing from a reviewed git tag, or verifying the installer script hash out-of-band, for highest assurance.
