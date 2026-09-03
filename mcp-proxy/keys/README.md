# Sqreen trust-root public keys

## Release integrity

`sqreen-release-ed25519.pub` is the trust root for install.sh verification of
release-manifest.json (Ed25519). See docs/RELEASE_INTEGRITY.md.

- Fingerprint (SHA-256 of DER): ddd41d35e3b6aa600575bd608cd5a6f63e0ddf04842e9e993b9062ed1d3116d9
- Private key: GitHub secret SQREEN_RELEASE_SIGNING_KEY_B64 only — never in this repo.

## Managed policy integrity

`sqreen-policy-ed25519.pub` is the trust root for signed policy envelopes from the
control plane. The raw 32-byte form is compiled into mcp-proxy.

- Key id: sqreen-policy-ed25519-1
- Private key: SQREEN_POLICY_SIGNING_KEY or SQREEN_POLICY_SIGNING_KEY_PATH on the control plane only
- Must not reuse the release signing private key

See docs/POLICY_INTEGRITY.md.
