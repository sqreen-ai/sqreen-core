# Adversarial security tests

Integration suite: `mcp-proxy/tests/adversarial_security.rs`.

## Objective

Prove that **equivalent dangerous actions receive equivalent decisions** across provider/runtime representations (MCP, OpenAI, Anthropic, Cursor, Claude Code, generic/custom).

This is **not** a coverage chase. Each test encodes an attacker-shaped attempt or a deliberate documentation of a known gap.

## Run

```bash
cd mcp-proxy
cargo test --test adversarial_security
```

Related suites:

| Suite | Focus |
|-------|--------|
| `cross_provider_enforcement` | Same logical read/shell across adapters |
| `failure_modes` | Broken controls never plain-allow |
| `adversarial_security` | Traversal, encoding, shell chaining, approval replay, offline local-first, gaps |

## Categories covered

| Attempt | Expectation |
|---------|-------------|
| Path traversal (`../..`) | Deny |
| Percent-encoded traversal (`%2e%2e`) | Deny (adversarial policy includes encodings) |
| Nested JSON path to `secret_store/` | Deny |
| Unicode/homoglyph + `secret_store/` | Deny via store substring (homoglyph alone may not match `../`) |
| Symlink to secrets | **Known gap:** policy matches path *strings*, not `lstat` targets — documented in-test |
| Env / `printenv` / `$OPENAI_API_KEY` in shell | Stop (block or confirm→deny in harness) |
| Secret shape DLP (`sk-…`) | Masked |
| Base64-obfuscated secret | **Known gap:** DLP is not a decoder — documented |
| Malformed MCP JSON | Reject at adapter |
| Payload &gt; `MAX_PAYLOAD_BYTES` | Reject at normalize |
| Unknown tool + global pattern | Deny |
| Unknown custom runtime | Deny (same policy) |
| Approval replay / arg tamper | Reject grant |
| Optional remote sync unavailable (local-first) | Local deny still holds |
| `require_control_plane` without optional remote | Deny (never Allow) |
| Cursor `run_terminal_cmd` shell egress | Stop (regression vs bash-only policies) |

## Harness notes

- Shell/confirm paths use `DenyAllApprovalEngine` so CI never waits on `/dev/tty`. That maps Confirm → Deny; it does **not** change production defaults.
- Synthetic paths only (`secret_store/`, `/tmp/…`).
- Do **not** weaken fail-closed logic or strip block patterns to make a test pass. If a new bypass is found: add a regression that expects **Deny**, and strengthen policy/detection.

## Adding a regression

1. Reproduce the bypass as a failing `assert_blocked` / `Decision::Deny` test.
2. Fix detection or policy (strengthen only).
3. Leave the test in this file with a short comment naming the issue.
4. If the issue is deferred, add a `known_gap_*` test that documents current behavior and
   notes the limitation in the test comment (do not claim a protection the code lacks).

## Signed policy verification attacks

Covered by `mcp-proxy/src/policy/integrity_tests.rs` (offline, deterministic fixtures):

- Replay older weaker revision
- Alter DENY/Confirm to Allow (digest or signature fail)
- Swap organization_id
- Modify expiration / revision / key_id
- Corrupt signature byte
- Replace or mutate on-disk signed cache
- Unsigned bare policy sync body
- Canonicalization: signature covers sorted-key canonical JSON only

Expectation: reject candidate; keep last verified policy; no implicit ALLOW.

