# Cloud SOC domain model (control plane)

This document describes the org-scoped domain model in `mcp-control-plane`, how it answers SOC questions, and the migration / isolation invariants.

## Entities

| Entity | Table | Purpose |
|--------|-------|---------|
| Organization | `organizations` | Tenant root; owns retention window |
| User | `users` | Human identity scoped to an org |
| Device | `devices` | Edge proxy / host identity |
| Agent | `agents` | Agent runtime identity (`agent_key` unique per org) |
| Agent session | `agent_sessions` | Conversation / run boundary |
| Org policy | `org_policies` | Named policy container (per org) |
| Policy version | `policy_versions` | Immutable versioned payloads + active flag |
| Action | `actions` | Canonical attempted tool action |
| Security event | `security_events` | Append-oriented SOC event stream |
| Risk finding | `risk_findings` | Durable unusual / intel findings |
| Approval | `approvals` (observe-only telemetry) + `approval_requests` (live remote queue) | Human-approval audit trail + enterprise decide/consume |
| Incident | `incidents` + `incident_events` | Grouped investigation view |

Legacy `telemetry_logs` remains for the existing dashboard stream and is dual-written with `org_id`.

## Tenant isolation

1. **Ingest:** `org_id` is taken only from the authenticated device principal (`X-Device-Token` → provisioned token org, or env token → `default`). Client JSON never sets tenant.
2. **Human SOC / admin reads:** require an authenticated **OIDC session** (HttpOnly cookie), organization **membership**, and RBAC permission. `X-Org-Id` is only a selection hint among memberships (mismatch → 403). See [HUMAN_AUTH.md](./HUMAN_AUTH.md).
3. **Queries:** Every SOC list/detail query includes `WHERE org_id = ?`. Incident detail also filters `org_id` so IDs are not globally guessable across tenants.
4. **Tests:** `tenant_isolation_test.go` covers cross-tenant agent/event/finding/stream isolation, spoofed ingest org, and incident IDOR.


## Agent inventory

Agents are **auto-discovered** from telemetry ingest — there is no manual registration API.

| Field | Source |
|-------|--------|
| agent id / name / trust | `agent_id`, `agent_label`, `agent_trust`, `agent_identity_source`, `agent_bound_id` (LABEL ≠ verified identity; see [EXECUTION_IDENTITY.md](./EXECUTION_IDENTITY.md)) |
| type / runtime | `agent_type`, `runtime` |
| model provider / model | `model_provider`, `model_name` |
| user / delegator | `user_id` / `delegator_user_id` (privacy-safe keys) |
| device | authenticated device + `device_id` |
| environment | `environment` tier (`development` / `staging` / `production` / `unknown`) |
| first / last seen | `agents.created_at` / `last_seen_at` |
| actions / blocked / approvals | denormalized counters updated on ingest |
| tools used | capped distinct tool names on the agent row |
| sensitive resources | capped privacy-safe summaries / categories |
| risk level | rolling max score + normalized level |
| matched policies | `policies_matched` from events |
| active policies | org `policy_versions` where `is_active`, else global policy version |

### APIs

- `GET /api/v1/soc/agents` — inventory list  
  Filters: `q`, `runtime`, `user`, `environment`, `risk`, `device`, `model`, `last_seen_after`, `last_seen_before`, `limit`, `offset`
- `GET /api/v1/soc/agents/{id}` — inventory detail (org-scoped; cross-tenant → 404)

### Privacy

- Prefer hashed / opaque identity keys from the edge.
- Resource summaries are truncated and home-path prefixes are stripped before persistence/API.
- Inventory queries always include `org_id` from the authenticated human tenant scope.

### Migrations

- `0004_agent_inventory.sql` — agent inventory columns + event identity columns + indexes

## Investigation timeline

Analysts can open an event, finding, or incident and retrieve a bounded IR narrative:

`session → prior actions → suspicious action → policy/risk → decision → approval → execution outcome → subsequent actions`

### Correlation

Priority: **session_id** → **trace_id** → **agent_id + time window**. Parent/child links use `parent_action_id` (stable action ids).

### APIs

- `GET /api/v1/soc/events/{id}/timeline`
- `GET /api/v1/soc/findings/{id}/timeline`
- `GET /api/v1/soc/incidents/{id}/timeline`

Query params: `before` / `after` (default 25, max 100). Response includes `timeline` narrative entries, `actions_before`, `suspicious_action`, `subsequent_actions`, `related_actions`, and truncation flags.

### Performance

Indexes: `(org_id, session_id, timestamp, id)`, `(org_id, trace_id, timestamp, id)`, `(org_id, action_id)`, `(org_id, parent_action_id)`. Queries are windowed (LIMIT) — never full-session scans.

### Privacy

Resource summaries are sanitized; decision reasons / risk factors are machine codes only — no raw secrets.

### Migration

- `0005_investigation_timeline.sql` — correlation columns + indexes

## SOC question → API / query

| Question | Endpoint | Filter / notes |
|----------|----------|----------------|
| What agents exist? | `GET /api/v1/soc/agents` | Full inventory; filters below |
| What tools are they using? | `GET /api/v1/soc/tools` (+ per-agent `tools_used`) | Aggregate on `security_events` |
| Sensitive resources accessed? | `GET /api/v1/soc/events?filter=sensitive` | Also on inventory item |
| What was blocked? | `GET /api/v1/soc/events?filter=blocked` | `blocked_actions` on inventory |
| What required approval? | `GET /api/v1/soc/approvals` (observe) · `GET /api/v1/approvals` (live remote queue) | Telemetry-derived vs durable `approval_requests` — see [REMOTE_APPROVALS.md](./REMOTE_APPROVALS.md) |
| Unusual agents? | `GET /api/v1/soc/findings` | Open risk findings |
| What happened in this incident? | `GET /api/v1/soc/incidents/{id}` | Incident + joined events |

Pagination for events uses cursor `timestamp_nanos:id` (`cursor` query param).

## Migrations

Applied after the legacy baseline schema (`migrateSchema`):

- `migrations/0002_soc_domain.sql` — full SOC tables + indexes
- `migrations/0003_telemetry_org_id.sql` — placeholder; Go applies idempotent `ALTER TABLE telemetry_logs ADD COLUMN org_id` + index
- `migrations/0004_agent_inventory.sql` — agent inventory enrichment columns + indexes
- `migrations/0005_investigation_timeline.sql` — timeline correlation columns + indexes
- `migrations/0013_remote_approvals.sql` — durable `approval_requests` for enterprise remote approvals

Versions are recorded in `schema_migrations`. Boot seeds organization `default` and ensures every `device_tokens.org_id` has an `organizations` row.

## Indexes & ingestion scale

Hot path indexes are composite leading with `org_id` then time / flag:

- `(org_id, timestamp DESC, id DESC)` on events and legacy telemetry
- Flag indexes for `blocked`, `approval_required`, `unusual`, `sensitive`
- Agent / tool / decision indexes on `actions` and `agents`

Ingestion uses WAL + `MaxOpenConns(1)` for serialized SQLite writes; dual-write keeps legacy stream compatible while enriching the domain model. Payload metadata is capped (`payload_json` ≤ 8 KiB).

## Retention

`organizations.retention_days` (default 90). `purgeExpiredEvents(db, orgID)` deletes `security_events` older than the cutoff. Call from a future scheduled job; not wired to HTTP yet.

## Auth notes

```text
Human:  OIDC → server-side session → organization membership → RBAC
Device: device bearer → enrollment → organization
```

- **Device tokens:** edge ingest + policy sync (device principal).
- **Human sessions:** SOC reads/writes, policy publish, device mint/revoke — membership + permission required.
- **Legacy `X-Admin-Token`:** DEVELOPMENT / TEST ONLY when `SQREEN_ENABLE_LEGACY_ADMIN_AUTH=true`. Production refuses this path.
- Production console never uses `NEXT_PUBLIC_ADMIN_TOKEN`.
