# Sqreen Core v0.1.13

## Highlights

- **Policy trust-root rotation support.** Core now pins a trust *set* of
  managed-policy verification keys instead of a single root.
- **Backward-compatible legacy trust.** Envelopes signed under
  `sqreen-policy-ed25519-1` continue to verify against the v0.1.12 public root
  so cached last-known-good policy remains usable after upgrade.
- **New rotation key id.** `sqreen-policy-ed25519-2` is pinned for the next
  managed-policy signing identity. Operators should emit this `key_id` only
  after edge binaries are upgraded to v0.1.13+.
- **No unsigned-policy change.** Production still rejects unsigned managed
  policy. Fail-closed behavior for unknown `key_id`, wrong-key signatures,
  digests, org binding, expiry, and anti-rollback is unchanged.
- **Open-core boundary preserved.** No Enterprise private implementation is
  included in this release.

## Upgrade notes

1. Upgrade edge `mcp-proxy` / `sqreen` to **v0.1.13**.
2. Confirm `sqreen doctor` / policy sync succeeds with existing enrollment.
3. After fleets are on v0.1.13, managed control planes should publish new
   envelopes with `key_id=sqreen-policy-ed25519-2` (signing private key custody
   remains operator-side; Core only ships public verification material).

## Security

- Verification remains: envelope `key_id` → exact pinned public key → Ed25519
  verify over the canonical signing payload.
- Signatures are never accepted merely because they verify under *some* trusted
  key; the `key_id` must match the key used.
