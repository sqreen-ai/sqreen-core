# Sqreen trust-root public keys

These files are **public verification keys** only. Private signing material never
belongs in this repository.

## Release integrity

`sqreen-release-ed25519.pub` is the trust root used by `install.sh` to verify
`release-manifest.json` (Ed25519). See [docs/RELEASE_INTEGRITY.md](../../docs/RELEASE_INTEGRITY.md).

- Fingerprint (SHA-256 of DER): `ddd41d35e3b6aa600575bd608cd5a6f63e0ddf04842e9e993b9062ed1d3116d9`
- Private release-signing material is held only in the release pipeline — never in git.

## Signed policy verification (trust set)

Core verifies managed policy envelopes against a **pinned trust set** of
`key_id → Ed25519 public key` mappings compiled into the binary. Unknown
`key_id` values fail closed. A valid signature under a different trusted key
than the envelope’s `key_id` also fails closed.

| Key id | Public file | SHA-256 of raw 32-byte pubkey | Notes |
|--------|-------------|-------------------------------|-------|
| `sqreen-policy-ed25519-1` | `sqreen-policy-ed25519.pub` | `56f37ada7590662eb5e1208708a9cfab115daed493715a7a4295f57618a775a0` | Legacy trust root (Core ≤ v0.1.12) |
| `sqreen-policy-ed25519-2` | `sqreen-policy-ed25519-2.pub` | `429c6c7b632634fcbeb321ef48b3c0e011978dff3bd55a6b9061c7943d7fd91b` | Rotation trust root (Core ≥ v0.1.13) |

During migration, fleets may keep verifying historically cached `-1` envelopes
while operators publish new envelopes under `-2`. Issuance and private-key
custody for managed policies are operated separately and are not part of the
public Core documentation.

Optional operator extras: `SQREEN_POLICY_TRUSTED_KEYS=kid:hex32,...` may add
**additional** verification keys during emergency rotation. Extra entries
**cannot** replace the pinned `-1` / `-2` roots.

If verification fails, Core keeps the last verified local policy and does not
implicitly allow traffic. Unsigned managed policy is not accepted in production.
