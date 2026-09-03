# Design partner program

Recommended profile for the first Sqreen Core pilots.

## Who this is for

| Dimension | Recommendation |
|-----------|----------------|
| Team size | **5–25 developers** |
| Primary runtime | **Cursor / MCP** first (HTTP `serve` optional) |
| Environment | **Non-production** agent workloads |
| Approvals | **Remote** (Cloud SOC) for destructive / Confirm-shaped actions |
| Success owner | Named engineering + security sponsor |

## Why this profile

- Small enough to wrap every laptop, large enough to see real agent behavior.
- MCP stdio wrap is the fastest path to an aha moment (`mcp-proxy demo` → IDE wrap).
- Non-prod limits blast radius while policy and approval UX are tuned.
- Remote approvals prove the human gate without relying on IDE TTYs.

## Out of scope for v1 pilots

- TPM / SPIFFE / hardware attestation
- Speculative enterprise IdP features beyond documented OIDC
- Disabling the security baseline to silence blocks
- Production secrets sprawl as the first onboarding workload

## How to start

1. [QUICKSTART.md](QUICKSTART.md) — install → demo → status/doctor  
2. [PILOT_CHECKLIST.md](PILOT_CHECKLIST.md) — day-by-day gates  
3. [PILOT_DEPLOYMENT.md](PILOT_DEPLOYMENT.md) — if self-hosting Cloud SOC  
4. [PRIVACY.md](PRIVACY.md) — share with legal / security reviewers  

## Product surface (edge)

Binary name remains **`mcp-proxy`** (brand: Sqreen Core). Optional alias: **`sqreen`**.

```bash
mcp-proxy demo | status | doctor | integrations | support-bundle | enroll | serve | -- run
```
