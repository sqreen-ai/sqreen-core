# Security Policy

Sqreen takes the security of the **open-core edge runtime** (`mcp-proxy`) and related
public tools seriously.

## Reporting a vulnerability (responsible disclosure)

**Do not open public GitHub issues for security vulnerabilities.**

Email **security@sqreen.ai** with:

- Description of the issue and impact
- Steps to reproduce (proof-of-concept if available)
- Affected version or commit SHA
- Your contact for follow-up

We aim to:

1. **Acknowledge** within **3 business days**
2. Provide a **remediation timeline** within **14 days** for confirmed issues
3. Credit reporters who wish to be named (optional)

Please give us a reasonable window before public disclosure after we acknowledge a valid report.

## Supported versions

| Version | Supported |
|---------|-----------|
| Latest release tag | Yes |
| `main` | Best-effort |
| Older tags | Critical fixes only |

## Core security model (public)

Sqreen Core is **local-first**:

- Intercepts agent tool calls (MCP stdio and related adapters)
- Evaluates **local policy** plus a mandatory security baseline
- Can **ALLOW**, **DENY**, or require **local confirmation**
- Verifies **signed policy envelopes** when configured (verification only)
- Keeps enforcement authoritative on the developer machine without a control-plane round trip

Public docs that expand on this model:

| Doc | Contents |
|-----|----------|
| [docs/QUICKSTART.md](docs/QUICKSTART.md) | Local install → wrap → ALLOW/DENY |
| [docs/FAILURE_MODES.md](docs/FAILURE_MODES.md) | Fail-open / fail-closed / degrade-safely matrix |
| [docs/RELEASE_INTEGRITY.md](docs/RELEASE_INTEGRITY.md) | Signed release manifests and installer verification |
| [docs/ADVERSARIAL_TESTS.md](docs/ADVERSARIAL_TESTS.md) | Adversarial / cross-runtime equivalence suite |
| [docs/PRIVACY.md](docs/PRIVACY.md) | What stays local vs optional enterprise sync |
| [docs/POLICY_SCHEMA.md](docs/POLICY_SCHEMA.md) | Public policy document shape |

## Scope

**In scope (this public repository family)**

- `mcp-proxy` — local runtime, policy engine, basic DLP/risk gate, local approval
- `mcp-proxy-sdk` — Wasm policy plugin SDK
- `install.sh` — installer and local configuration seeding
- Project hooks under `.cursor/hooks/` when included

**Out of scope examples**

- Social engineering of end users
- Issues in third-party MCP servers you choose to run
- Denial-of-service against public marketing sites without customer-data impact
- Reports that require a fully compromised local OS user without an additional privilege boundary bug

Optional hosted management and remote workflows are available separately and are
**out of scope for this public Core document**.

## Safe harbor

We support good-faith security research that follows this policy. Do not access customer
data, perform destructive testing against production tenants you do not own, or spam
automated scans against production endpoints.

## Public verification

Prebuilt installer artifacts are authenticated via signed release manifests. See
[docs/RELEASE_INTEGRITY.md](docs/RELEASE_INTEGRITY.md). Public verification keys ship in
`mcp-proxy/keys/`; private signing keys never belong in this repository.
