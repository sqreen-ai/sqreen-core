# Sqreen trust-root public keys

These files are **public verification keys** only. Private signing material never
belongs in this repository.

## Release integrity

`sqreen-release-ed25519.pub` is the trust root used by `install.sh` to verify
`release-manifest.json` (Ed25519). See [docs/RELEASE_INTEGRITY.md](../../docs/RELEASE_INTEGRITY.md).

- Fingerprint (SHA-256 of DER): `ddd41d35e3b6aa600575bd608cd5a6f63e0ddf04842e9e993b9062ed1d3116d9`
- Private release-signing material is held only in the release pipeline — never in git.

## Signed policy verification

`sqreen-policy-ed25519.pub` is the trust root Core uses to **verify** signed
policy envelopes when a signed document is presented. The compiled-in raw key
form matches this public key.

- Key id: `sqreen-policy-ed25519-1`
- Core verifies signatures, digests, and related envelope fields locally before
  activating a signed policy candidate.
- Issuance and key custody for managed policies are operated separately and are
  not part of the public Core documentation.

If verification fails, Core keeps the last verified local policy and does not
implicitly allow traffic.
