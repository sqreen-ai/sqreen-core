# Sqreen Core v0.1.12 — Release Readiness

**Status:** RELEASE CANDIDATE (do not tag until this checklist is accepted)  
**Date:** 2026-09-06  
**Base main SHA:** `0d8617c347caa7f404145695a248c40de83d80a4`  
**Candidate branch:** `release/v0.1.12-prep`  
**Candidate commit:** `3b76351447958b4bd251e36dfbf30319888bbc94`  
**Candidate theme:** local-first open-source enforcement runtime

## Release candidate commit

Recorded after merge of `release/v0.1.12-prep` (this document is authored on that branch).  
Includes: Cargo version `0.1.12`, release notes, claims-script open-core hygiene, readiness doc.

## Core CI / local regression

| Check | Result |
|-------|--------|
| Public Core main green @ `0d8617c…` | PASS (post-PR #14) |
| `cargo test --lib --no-default-features --locked` | PASS — **369** tests |
| Supply-chain installer tests | PASS — 23 |
| Day-1 install messaging | PASS — 28 |
| Integration claim check | PASS (open-core path; Enterprise smoke optional) |
| gitleaks (local scan) | PASS — no leaks |
| Local ALLOW wrap E2E | PASS |
| Local DENY wrap E2E | PASS |
| `enroll` on open-core | PASS — clear error (`unknown command`, Enterprise separately) |

## Enterprise integration

| Check | Result |
|-------|--------|
| Enterprise PRIVATE | YES |
| Pin `SQREEN_CORE_REF` | `0d8617c347caa7f404145695a248c40de83d80a4` |
| `SQREEN_CORE_BOUNDARY_READY` | `true` |
| Integration + hooks on Enterprise main | PASS (post-PR #3) |
| Doc pin + CI dedupe | Merged PR #4 (`4122976…`) |
| Overlay + `cargo check --features enterprise` vs candidate tree | PASS |

**Note:** Keep production pin on the immutable SHA until `v0.1.12` exists; then optionally retarget pin to the tagged commit.

## Target artifacts

| Artifact | Local / CI |
|----------|------------|
| `mcp-proxy-darwin-aarch64.tar.gz` | **PASS** (built; binary-only archive; `--version` → `0.1.12`) |
| `mcp-proxy-darwin-x86_64.tar.gz` | **PASS** (cross-built; Mach-O x86_64) |
| `mcp-proxy-linux-aarch64.tar.gz` | **CI_REQUIRED** (release workflow `ubuntu-24.04-arm`) |
| `mcp-proxy-linux-x86_64.tar.gz` | **CI_REQUIRED** (release workflow `ubuntu-latest`) |

## Installer

| Check | Result |
|-------|--------|
| Downloads Core-only assets (`sqreen-ai/sqreen-core` / sqreen.ai/releases) | PASS (code audit) |
| Fail-closed signature verification | PASS (supply-chain tests) |
| Public verification key present | `mcp-proxy/keys/sqreen-release-ed25519.pub` |
| No Enterprise enrollment instructions in Core help | PASS |
| Fresh temp-HOME install (binary + policy + demo/status/doctor) | PASS |
| Upgrade v0.1.11 → candidate binary (policy + wrap survive) | PASS |
| Sync guard | Root `install.sh` ≡ `mcp-proxy/install.sh` |

## Signing audit

| Check | Result |
|-------|--------|
| Four platform artifacts required before publish | YES |
| SHA-256 digests in packaging step | YES |
| `sign-release-manifest.sh` → manifest + `.sig` | YES |
| Private key only from `SQREEN_RELEASE_SIGNING_KEY_B64` | YES |
| Missing secret fails publish | YES (explicit exit) |
| Public key in tree | YES |
| Tag-only `on: push: tags: v*` | YES |
| Default `permissions: contents: read`; publish job `contents: write` | YES |
| No Enterprise checkout / secrets in Core release workflow | YES |

## Workflow security

| Item | Notes |
|------|-------|
| Least privilege | Default read; write only on sign-and-publish |
| Secrets on PR | Release job gated to tag push on `sqreen-ai/sqreen-core` |
| Third-party Actions | `softprops/action-gh-release@v2` is **major-tag floating** — SHOULD FIX pin to full SHA |
| `actions/checkout@v5`, `upload-artifact@v5`, `download-artifact@v5`, `dtolnay/rust-toolchain@stable` | Floating majors/channels — prefer SHA pins over time |

## Compatibility changes (vs v0.1.11)

| Area | Class |
|------|-------|
| Local MCP wrap ALLOW/DENY | NO CHANGE (behavior retained) |
| Policy path `~/.config/mcp-proxy` | NO CHANGE |
| Installer signed download flow | NO CHANGE (intent) |
| `default = []` / `--no-default-features` release builds | COMPATIBLE CHANGE (explicit local-first; already on main) |
| Package/`--version` → `0.1.12` | COMPATIBLE CHANGE (Cargo was stale at 0.1.9 through prior tags) |
| `enroll` / remote approval / Cloud Enterprise CLI | ENTERPRISE-ONLY NOW |
| Help text without Enterprise block | COMPATIBLE CHANGE |
| status/doctor “Enterprise features not included” | COMPATIBLE CHANGE |

Draft public notes: `RELEASE_NOTES_v0.1.12.md`.

## Dependabot (#4–#9)

| PR | Decision |
|----|----------|
| #4 serde_json (sdk) | DEFER UNTIL AFTER v0.1.12 |
| #5 serde (sdk) | DEFER |
| #6 wasmtime 47 (CONFLICTING) | DEFER |
| #7 anyhow | DEFER |
| #8 serde_json (proxy) | DEFER |
| #9 tokio | DEFER (revisit promptly after release for security patches) |

## License / provenance

| Item | Status |
|------|--------|
| Root MIT | Present |
| `mcp-proxy` MIT OR Apache-2.0 | Present |
| Public verification keys | Intentionally public |
| `sqreen-contracts` PROVENANCE + COUNSEL_TODO | Unresolved counsel SPDX choice |
| COUNSEL_TODO blocker for v0.1.12? | **No** — contracts already in public Core tree under existing MIT intent; do not invent SPDX |

## SBOM / dependency inventory

Informal inventory: `/var/tmp` local `cargo tree` snapshot (not committed).  
Key crypto: `ed25519-dalek`, `curve25519-dalek`, `sha2`, `rustls`.  
Toolchain used locally: rustc 1.96.0 (host); release CI uses `dtolnay/rust-toolchain@stable`.

## Fly token

`FLY_API_TOKEN` remains an Enterprise control-plane **deployment** operational issue.  
**Not a blocker** for Core `v0.1.12` tag/publish.

## BLOCKERS

None identified for tagging after this candidate PR merges and Linux artifacts are produced by the tag workflow.

## SHOULD FIX (non-blocking)

1. Pin `softprops/action-gh-release` (and ideally other Actions) to full commit SHAs.
2. After tag: retarget Enterprise `SQREEN_CORE_REF` from SHA → `v0.1.12` tag or tagged commit.
3. Consider documenting that historical `v0.1.10`/`v0.1.11` binaries may report Cargo `0.1.9` (stale package version).
4. Optional formal SBOM attach on future releases.

## Exact tag process (DO NOT RUN YET)

```bash
# After release/v0.1.12-prep is merged to main:
git fetch origin main
git checkout main
git pull --ff-only origin main
# Confirm version in mcp-proxy/Cargo.toml is 0.1.12 and CI green
git tag -a v0.1.12 -m "Sqreen Core v0.1.12 — local-first open-core enforcement runtime"
git push origin v0.1.12
# Release workflow builds/signs/publishes; verify GitHub Release assets + manifest.sig
```

Do **not** force-push tags. Do **not** rewrite history.
