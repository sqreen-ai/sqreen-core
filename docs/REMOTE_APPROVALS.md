# Remote Approvals (Enterprise)

**Status:** foundation shipped — control plane queue + edge `RemoteApprovalEngine` + dashboard queue.  
**Related:** [THREAT_MODEL.md](./THREAT_MODEL.md) (SEC-TODO-6) · [FAILURE_MODES.md](./FAILURE_MODES.md) · [CLOUD_SOC_DOMAIN.md](./CLOUD_SOC_DOMAIN.md) · [EXECUTION_IDENTITY.md](./EXECUTION_IDENTITY.md)

## What this is

When policy / risk requires a human judgment, the edge can escalate to the **control plane** instead of (or in addition to, via mode selection) a local TTY prompt. A SOC operator approves or denies in the dashboard; the device **consumes** a single-use, digest-bound grant before execution.

Observe-only SOC table `approvals` (telemetry-derived, `GET /api/v1/soc/approvals`) remains unchanged. Live remote requests live in `approval_requests`.

## Lifecycle

```text
device create → PENDING → human APPROVE/DENY → APPROVED|DENIED
                              ↓ (APPROVED only)
                         device consume(digest) → CONSUMED
PENDING past TTL → EXPIRED
```

Statuses (exact uppercase): `PENDING`, `APPROVED`, `DENIED`, `EXPIRED`, `CANCELLED`, `CONSUMED`.

Default TTL: **10 minutes**.

Remote verdicts are **APPROVE_ONCE** only. Session / timed grants are never issued remotely.

## Fail-closed invariants

- Control plane unavailable under `SQREEN_APPROVAL_MODE=remote` → `Unavailable` / deny — **never Allow**, never fall back to TTY mid-flight.
- `auto` may select Local **only at engine selection time** when no `CloudClient` is configured.
- Consume requires matching `action_digest` (ActionBinding v2 fingerprint). Digest mismatch → reject.
- Consume is single-use; replay → reject.
- Device can only poll/consume its own requests; org isolation on every query.
- Approver identity comes from the human session (`user_id`, session public id). Body `user_id` / `org_id` are ignored for authority.

## Edge configuration

| Env | Values | Default |
|-----|--------|---------|
| `SQREEN_APPROVAL_MODE` | `local` \| `remote` \| `auto` | `local` |

Requires `MCP_CONTROL_PLANE_URL` + `MCP_DEVICE_TOKEN` for remote/auto+cloud.

Policy-rule `approval_mode` is **not** in schema yet (env-only foundation). Tracked as a follow-up.

## APIs

### Human (session + RBAC)

| Method | Path | Permission |
|--------|------|------------|
| GET | `/api/v1/approvals?status=` | `approval:read` |
| GET | `/api/v1/approvals/{id}` | `approval:read` |
| POST | `/api/v1/approvals/{id}/approve` | `approval:decide` |
| POST | `/api/v1/approvals/{id}/deny` | `approval:decide` |

Roles: OWNER / ADMIN / SECURITY_ANALYST → read+decide; VIEWER → read only.

### Device (`X-Device-Token`)

| Method | Path |
|--------|------|
| POST | `/api/v1/device/approvals` |
| GET | `/api/v1/device/approvals/{id}` |
| POST | `/api/v1/device/approvals/{id}/consume` body `{ "action_digest" }` |

## SIEM / audit

Lifecycle events emit structured `security_audit` logs and SIEM `ExportEvent` rows with `approval_outcome` / optional `approval_id`:

`approval_requested`, `approval_approved`, `approval_denied`, `approval_expired`, `approval_consumed`, `approval_replay_rejected`, `approval_digest_mismatch`, `approval_wrong_device`, `approval_wrong_org`.

## Remaining work

- Investigation timeline nodes for approval lifecycle (durable DB + SIEM already cover audit).
- Optional per-rule `approval_mode` on PolicyRule.
- Push / webhook notify to on-call (poll is foundation).
