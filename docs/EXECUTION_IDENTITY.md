# Execution identity (device-authenticated attribution)

Sqreen uses **device-authenticated execution attribution with registered agent bindings**.

This is **not** cryptographic attestation of an agent binary (no TPM / SPIFFE / workload identity in this foundation).

## Trust model

| Level | Meaning |
|-------|---------|
| **Authenticated** | Validated via a Sqreen security credential (enrolled device bearer → `device_id` + `organization_id`). |
| **Bound** | Registered agent explicitly bound to an authenticated device in the same organization. |
| **Derived** | Sqreen derived the value from trusted context (e.g. empty session placeholder). |
| **SelfAsserted** | Supplied by adapter, environment, or request **without proof**. |

**LABEL ≠ VERIFIED IDENTITY.**

`SQREEN_AGENT_ID=production-agent` is a **SelfAsserted label**, not proof that a trusted agent ran.

## Canonical principals

```text
Human (Cloud SOC):  OIDC → server session → membership → RBAC
Device (edge):      device bearer → enrollment → organization + device_id
Execution:          ExecutionPrincipal { org, device, agent claim, user claim, session claim, runtime }
```

Execution `user_id` / `session_id` are **not** Cloud SOC OIDC users / auth sessions.

## Registered agents + device bindings

1. Admin registers an agent (`POST /api/v1/registered-agents`) with optional `external_key` (label).
2. Admin binds it to an enrolled device (`POST /api/v1/registered-agents/{id}/bindings`).
3. On telemetry ingest, if the claim matches a registered agent **and** an active binding for the authenticated device exists → **Bound**.
4. Otherwise the claim remains **SelfAsserted** (legacy integrations keep working).

Disabled agents and revoked bindings never become Bound.

## Policy semantics

| Match field | Meaning |
|-------------|---------|
| `agent_id` / `agent.label` | Label match (legacy). **Allow/Redact that depend only on these require Bound/Authenticated agent trust.** |
| `agent.bound_id` / `agent.id` | Registered agent id (Bound). |
| `agent.trust` | `self_asserted` \| `bound` \| `authenticated` \| `derived` |

Self-asserted identity may **increase** restriction (Deny / Confirm / risk) but must **never grant privilege** (bypass deny, expand scope, skip approval via Allow).

## Approvals

Approval fingerprints include device id, organization id, agent trust, and bound agent id (when present). Spoofed labels on another device cannot replay a Bound agent's grant.

Remote approvals (`SQREEN_APPROVAL_MODE=remote|auto`) send the same ActionBinding digest to the control plane; consume is device-scoped and single-use. See [REMOTE_APPROVALS.md](./REMOTE_APPROVALS.md).

## Telemetry / SOC / SIEM

Events carry `agent_trust`, `agent_identity_source`, `agent_bound_id`, and parallel user/session trust fields so analysts can distinguish Bound vs Self-reported labels.

## Management API (human RBAC)

| Permission | Roles |
|------------|-------|
| `agent:read` | owner, admin, security_analyst, viewer |
| `agent:write` | owner, admin |

Device tokens cannot call these APIs.
