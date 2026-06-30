# Security Policy

Sqreen.ai takes the security of **mcp-proxy** and the open-core edge tools seriously. This repository may contain only local execution assets; report issues in hosted Sqreen Cloud services separately (see below).

## Supported versions

| Version | Supported |
|---------|-----------|
| Latest release tag | Yes |
| `main` | Best-effort |
| Older tags | Critical fixes only |

## Reporting a vulnerability

**Do not open public GitHub issues for security vulnerabilities.**

Email **security@sqreen.ai** with:

- Description of the issue and impact
- Steps to reproduce (proof-of-concept if available)
- Affected version or commit SHA
- Your contact for follow-up

We aim to acknowledge reports within **3 business days** and provide a remediation timeline within **14 days** for confirmed issues.

## Scope

### In scope (this public repository)

- `mcp-proxy` — stdio proxy, policy engine, DLP, risk gate, threat intel, behavioral chains
- `mcp-proxy-sdk` — Wasm policy plugin SDK
- `install.sh` — installer and local configuration seeding
- Cursor hooks under `.cursor/hooks/` when included in this repo

### Out of scope (private Sqreen Cloud / enterprise)

- Hosted control plane (`api.sqreen.ai`)
- SOC console (`console.sqreen.ai`)
- Fly.io / Cloudflare deployment credentials and tenant data

Reports for hosted services may still be sent to **security@sqreen.ai**; we will route them appropriately.

## Safe harbor

We support good-faith security research that follows this policy. Do not access customer data, perform denial-of-service attacks, or spam automated scans against production endpoints.

## Hardcoded development tokens

Example tokens such as `dev-device-token-change-me` in tests and documentation are **intentional local dev fixtures**, not production secrets. Production deployments must rotate all tokens before going live.
