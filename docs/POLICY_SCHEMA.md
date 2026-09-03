# Policy schema

Sqreen policies are versioned YAML/JSON documents compiled into layered rules (`mandatory_baseline` / `organization` / `local`); priority orders matches within a layer, and cross-layer conflicts use tighten-only effect severity. Evaluation operates on normalized **AgentAction + AgentIdentity + SecurityClassification** — not provider-specific wire shapes.

## Schema versions

| `schema_version` | Meaning |
|------------------|---------|
| *(absent)* / `legacy` | Tool-centric YAML (`global`, `tools`, optional `identity_rules` / `taxonomy_rules`). Fully supported. |
| `2026.3` | Normalized `rules[]` as the primary authoring surface. Legacy sections may coexist. |

Documents are **validated at load time** (unique rule names, known match keys, valid regexes). Invalid policies fail activation.

## Top-level fields

```yaml
schema_version: "2026.3"   # optional; defaults to legacy
version: "my-bundle"       # required; exposed as engine version in audit
mode: enforce              # enforce | audit (dry-run)
global:
  redact_keys: []
  risk_threshold: 70
  block_patterns: []       # legacy global payload patterns
rules: []                  # normalized rules (2026.3)
identity_rules: []         # legacy identity predicates
taxonomy_rules: []         # legacy taxonomy predicates
tools: []                  # legacy per-tool actions + block_patterns
```

### Modes

| Mode | Behavior |
|------|----------|
| `enforce` | Matched effects block, require approval, or redact as configured. |
| `audit` | Evaluate and record what **would** happen; policy alone does not deny (except redaction and unevaluable payloads). Gateway adds `PolicyAuditOnly` reason with the simulated decision. |

Use `audit` to dry-run enterprise guardrails before enforcement.

## Normalized rules (`schema_version: "2026.3"`)

```yaml
rules:
  - name: deny-ssh-reads
    priority: 1000
    effect: deny                    # allow | deny | require_approval | redact
    description: "Human-readable audit explanation"
    tools: []                       # optional; empty = all tools
    match:                          # AND — every predicate must match
      action: read
      path_pattern: "(~|/Users/[^/]+)/\\.ssh/"
```

### Effects

| Effect | Runtime verdict |
|--------|-----------------|
| `allow` | Continue (unless a higher-priority rule wins) |
| `deny` | Block |
| `require_approval` | Escalate to approval stage |
| `redact` | Rewrite configured secret keys, then allow (legacy) |

Approval **channel** (local TTY vs remote control plane) is selected by edge env `SQREEN_APPROVAL_MODE` (`local` \| `remote` \| `auto`), not per-rule today. See [REMOTE_APPROVALS.md](./REMOTE_APPROVALS.md). Per-rule `approval_mode` is a planned schema extension.

### Match fields

Predicates are flat key/value pairs — no expression language.

**Identity**

- `agent_id` / `agent.label` — label match (legacy; Allow/Redact that depend only on these require Bound/Authenticated agent trust — see [EXECUTION_IDENTITY.md](./EXECUTION_IDENTITY.md))
- `agent.bound_id` / `agent.id` — registered agent id when Bound
- `agent.trust` — `self_asserted` | `bound` | `authenticated` | `derived`
- `agent_type`, `environment`, `workspace_id`
- `agent.anonymous` — `"true"` / `"false"`
- `labels.<key>` — e.g. `labels.team: engineering`

**Taxonomy / action**

- `action` — read, write, execute, delete, network, …
- `operation`, `runtime`, `tool_name`
- `resource.filesystem`, `resource.network`, …
- `risk.destructive`, `risk.production`, `risk.credential_access`, `risk.external_destination`, …

**Explainable risk score** (computed before policy; ordinal severity, not a probability)

- `risk.level` — `LOW` / `MEDIUM` / `HIGH` / `CRITICAL`
- `risk.level_at_least` — matches when the scored level is at least the given band
- `risk.score_at_least` — matches when the numeric score is ≥ the given integer (0–100)
- `risk.factor` — matches when a named factor fired (e.g. `secret_access`, `behavioral_anomaly`)
- `risk.factor.<kind>` — `"true"` / `"false"` for a specific factor

**Behavior**

- `path` — first extracted path argument
- `path_pattern` — regex against extracted paths (home expanded)
- `path_prefix` — path starts with prefix
- `path_not_prefix` — every extracted path is outside prefix

See `policy::DOCUMENTED_MATCH_FIELDS` in code for the authoritative list.

## Precedence (deterministic)

1. Collect **all** matching rules.
2. Sort winners by:
   - within each trust layer: `priority` descending, then effect severity
   - across layers: strongest effect wins (Deny > Confirm > Redact > Allow); lower-trust cannot weaken higher-trust
   - effect severity (`deny` > `require_approval` > `redact` > `allow`)
   - compile order ascending
   - rule `name` ascending
3. The first entry after sorting decides the verdict.
4. **Every** match is recorded in `PolicyEvaluation.matched_rules` for audit attribution.

Legacy sections compile into the same list with default priorities:

| Source | Default priority |
|--------|------------------|
| `identity_rules` | 7000 − index |
| `taxonomy_rules` | 6000 − index |
| `global.block_patterns` | 5000 |
| `tools[].block_patterns` | 4500 |
| `tools[].action: Block` | 4000 |
| `tools[].action: Confirm` | 3500 |

## Example guardrails

```yaml
schema_version: "2026.3"
version: enterprise-guardrails
mode: enforce
global:
  redact_keys: []
  block_patterns: []
rules:
  - name: deny-ssh-reads
    priority: 1000
    effect: deny
    description: Agents must not read SSH private keys
    match:
      action: read
      path_pattern: "(~|/Users/[^/]+)/\\.ssh/"

  - name: deny-secrets-external
    priority: 900
    effect: deny
    description: Secrets must not be sent to external destinations
    match:
      risk.credential_access: "true"
      risk.external_destination: "true"

  - name: approve-destructive-prod
    priority: 800
    effect: require_approval
    description: Destructive production actions require approval
    match:
      risk.destructive: "true"
      risk.production: "true"

  - name: deny-anonymous-prod
    priority: 950
    effect: deny
    description: Unknown agents may not operate in production
    match:
      agent.anonymous: "true"
      environment: production

  - name: engineering-workspace-reads
    priority: 100
    effect: allow
    match:
      labels.team: engineering
      action: read
      path_prefix: /workspaces/engineering/

  - name: engineering-outside-workspace
    priority: 500
    effect: deny
    description: Engineering agents may only read designated workspace paths
    match:
      labels.team: engineering
      action: read
      path_not_prefix: /workspaces/engineering/

  - name: confirm-credential-access
    priority: 700
    effect: require_approval
    description: Privileged credential access requires approval
    match:
      risk.credential_access: "true"
tools: []
```

## Evaluation API

- `PolicyEngine::evaluate_detailed(action)` → `PolicyEvaluation` with `matched_rules`, `winning_rule`, `explanation`, `enforced_verdict`, and `mode`.
- `PolicyEngine::evaluate_action(action)` → enforcement verdict (`Allow` in audit mode unless redact/unevaluable).
- `PolicyEngine::evaluate_tools_call(params_json)` → legacy MCP params bridge; returns `Unevaluable` when params JSON is unreadable.

Unevaluable payloads (legacy bridge, malformed canonical JSON) are **never** treated as implicit allow.

## Backwards compatibility

Existing `mcp-policy.yaml` files using `global`, `tools`, `identity_rules`, and `taxonomy_rules` continue to work unchanged. Block reason strings for legacy global/tool patterns are preserved for audit compatibility.
