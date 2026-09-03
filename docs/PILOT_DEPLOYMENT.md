# Design partner — self-hosted pilot deployment

How to run Cloud SOC (control plane + dashboard) for a design-partner pilot. Edge runtime remains [QUICKSTART.md](QUICKSTART.md).

## Components

| Piece | Role |
|-------|------|
| `mcp-proxy` (edge) | Local enforcement on MCP / HTTP agent tool calls |
| `mcp-control-plane` | Device auth, policy sync, telemetry, remote approvals |
| `mcp-dashboard` | Human SOC console (OIDC session + org RBAC) |

Kubernetes is **optional** — start with a single VM / container host unless you already standardize on K8s.

## Control plane

1. Build / run `mcp-control-plane` (see that package’s README / `.env.example`).
2. Set a strong bootstrap secret store; never ship `SQREEN_ALLOW_INSECURE_DEV_TOKENS` outside local test.
3. Persist the database (SQLite path or configured DB) on durable volume.
4. Expose HTTPS to developers and the dashboard (reverse proxy / load balancer).
5. Confirm health: dashboard or `curl -fsS https://CP/health` (or `/api/v1/health` if enabled).

## Dashboard

1. Point `NEXT_PUBLIC_API_URL` at the control plane origin.
2. Configure OIDC per [HUMAN_AUTH.md](HUMAN_AUTH.md).
3. Ensure operators have org membership before inviting pilots.
4. Verify: login → Security Events → Agent Identities → Approvals.

## Keys and policy integrity

- Managed policy sync is signature-verified ([POLICY_INTEGRITY.md](POLICY_INTEGRITY.md)).
- Keep signing keys offline / in your secrets manager; rotate per your runbook.
- Do not disable the mandatory security baseline to clear false positives — overlay tighten-only.

## Edge env (per device)

After minting a device token in **Agent Identities**:

```bash
mcp-proxy enroll \
  --control-plane https://cp.example.com \
  --device-token <TOKEN> \
  --device-id <DEVICE_ID> \
  --org-id <ORG>

source ~/.config/mcp-proxy/env
# optional:
export SQREEN_APPROVAL_MODE=remote   # or auto
mcp-proxy doctor
```

`~/.config/mcp-proxy/env` should be mode `0600`. Never commit it.

## TLS notes

- Prefer HTTPS for the control plane in any shared network.
- Edge uses standard system trust; corporate MITM proxies need their CA installed on developer machines.
- Clock skew breaks TLS and approval expiry — `mcp-proxy doctor` includes a clock sanity check.

## Database / backup

- Back up the control-plane DB on a schedule (snapshots before upgrades).
- Back up policy signing material separately from the DB.
- Test restore once before the pilot starts.

## Enrollment & policy publish

1. Mint device tokens (seat-limited).
2. Developers run `enroll` + wrap MCP or `serve`.
3. Publish signed policy from the dashboard / control plane.
4. Confirm edge `status` shows ACTIVE and doctor cloud reachability PASS.

## Remote approval

1. Set `SQREEN_APPROVAL_MODE=remote` (or `auto` with cloud enrolled).
2. Trigger a Confirm-shaped action (see `mcp-proxy demo` step 3).
3. Decide in dashboard **Approvals** (APPROVE_ONCE, digest-bound).
4. Details: [REMOTE_APPROVALS.md](REMOTE_APPROVALS.md).

## Upgrade

1. Prefer signed releases only ([RELEASE_INTEGRITY.md](RELEASE_INTEGRITY.md)).
2. Upgrade control plane → dashboard → edge (or edge last if CP is backward compatible).
3. Re-run `mcp-proxy doctor` on a canary device.
4. Do **not** deploy unsigned auto-updaters that bypass release verification.

## Optional Kubernetes

If you already run K8s: deploy CP + dashboard as normal Deployments/Services with TLS ingress, persistent volume for the DB, and secrets for OIDC + signing keys. No special Sqreen operators are required for pilot scale.
