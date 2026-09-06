# Agent Execution Gateway

The gateway is the single entry point for deciding whether an AI agent may perform an
action. It lives in `mcp-proxy/src/gateway/` and knows nothing about MCP, OpenAI,
Anthropic, Cursor, or Claude Code.

Provider-specific intercept → normalize → enforce → emit lives in
`mcp-proxy/src/adapters/`. See **[PROVIDER_ADAPTERS.md](./PROVIDER_ADAPTERS.md)** for how
to add a runtime without touching this pipeline.

## Pipeline

```
Agent runtime
     │
     ▼
Provider adapter ──────────────── mcp-proxy/src/adapters/
     │
     ▼
Normalized AgentAction ────────── mcp-proxy/src/action.rs
     │
     ▼
Identity + context enrichment ─── gateway/identity.rs
     │
     ▼
Policy evaluation ─────────────── gateway/policy_stage.rs   (YAML → Wasm extension)
     │
     ▼
Risk evaluation ───────────────── gateway/risk_stage.rs     (score, IOC, chains, DLP)
     │
     ▼
Approval, if required ─────────── gateway/approval.rs
     │
     ▼
ALLOW / DENY / REQUIRE_APPROVAL ─ gateway/decision.rs
     │
     ▼
Tool / API / filesystem          (the caller enforces)
     │
     ▼
Audit event ───────────────────── gateway/audit.rs
```

Each stage is a separate type with its own tests. The orchestrator in `gateway/mod.rs`
sequences them and is the only place that knows the order.

## Decision model

`gateway::evaluate` always returns an `EvaluationOutcome`. It never returns an error,
because "what does this error mean for security?" is exactly the question that gets
answered wrong under pressure. Internal failures become a reason plus whatever the failure
matrix says that failure implies.

| Field | Meaning |
|---|---|
| `decision` | `ALLOW`, `DENY`, or `REQUIRE_APPROVAL` |
| `reasons` | Every contributing factor, in stage order, each with a `stage`, a machine-readable `code`, and operator-facing `detail` |
| `matched_policies` | Rules that fired, with their source and ruleset version |
| `risk_score` | Effective score, absent when the pipeline stopped before scoring |
| `policy_version` | Version of the declarative policy that evaluated the action |
| `timestamp` | When evaluation completed |
| `latency` | Wall-clock time the pipeline spent |
| `metadata` | Free-form annotations |
| `rewritten_arguments` | Payload to forward instead of the original, when a stage redacted or masked it |

`REQUIRE_APPROVAL` is returned when the gateway determined an approval is needed and no
`ApprovalEngine` is configured to resolve it in-band. `Decision::stops_execution()` groups
it with `DENY`: **an unresolved approval is not permission to run.**

## Fail-open vs fail-closed

**[`FAILURE_MODES.md`](./FAILURE_MODES.md) is the authoritative reference.** The summary:

A subsystem that cannot do its job does not decide what its own failure means. It reports a
`SubsystemFailure`; `FailurePolicy` maps that to one of three modes; the gateway applies it
and audits it. The governing invariant is that **a broken control never produces a plain
allow** — it denies, or escalates to a human, or (for audit and optional remote-sync
failures only) proceeds while reporting the failure on the outcome.

| Mode | Effect |
|---|---|
| `FAIL_OPEN` | Record the failure; the verdict stands. For subsystems that describe rather than decide. |
| `DEGRADE_SAFELY` | Record it and escalate to an approval, rather than allowing on the strength of a control that did not run. |
| `FAIL_CLOSED` | Deny. |

Defaults: everything that inspects an action fails closed, except risk scoring and
threat-intel, which degrade safely. Audit and optional remote-sync paths fail open
(recording-only). Missing declarative policy fails **closed** under the default
`enforcing` posture (`SQREEN_ENFORCEMENT_POSTURE`); development may fail open consciously. See
[`FAILURE_MODES.md`](./FAILURE_MODES.md). Presets: `SQREEN_FAILURE_POLICY=strict|default|observe`.

Optional remote connectivity is never required to reach a verdict: local policy and local
approvals remain authoritative. `GatewayConfig::require_control_plane` is an explicit
operator demand rather than a fallback.

## Running fully locally

```rust
let gateway = GatewayBuilder::local()          // terminal approvals, stderr audit, no remote sync
    .policy_engine(Some(policy))
    .threat_intel(indicators)
    .session(session_tracker)
    .build();

let outcome = gateway.evaluate(&action).await;
```

`GatewayBuilder::local()` wires no optional remote sync and reaches the same verdicts as a
build with that path attached. `gateway.is_local_only()` reports whether any remote sync
client is attached.

## Auditing

Audit events are **signal-driven** by default: one per stage boundary that produced a
block, rewrite, mask, or approval, and none for an action that passed cleanly. This keeps
local audit volume aligned with meaningful security signals.

Set `GatewayConfig::audit_all_decisions` to also emit one event per evaluation regardless
of outcome. That yields a complete trail at the cost of one record per tool call, so it is
opt-in.

Sinks: `CloudAuditSink`, `StderrAuditSink`, `NullAuditSink`, `CompositeAuditSink` (fans
out, records everywhere even if one sink fails), plus `RecordingAuditSink` and
`FailingAuditSink` for tests.

## Adding a provider

Nothing in `gateway/` mentions a provider. A new runtime — browser driver, database proxy,
cloud SDK shim — is added by writing an adapter in `adapters/` that produces an
`AgentAction`, then calling `gateway.evaluate()`. No stage changes.

## Relationship to `guard`

`guard.rs` is now a compatibility facade. `GuardContext` is the engine bundle the existing
relays already thread through their call stacks, and `GuardContext::gateway()` turns one
into a gateway. Construction is cheap, which is what lets the stdio relay build one per
frame and pick up a hot-reloaded policy snapshot.

- `guard::evaluate_outcome` — returns the full `EvaluationOutcome`.
- `guard::evaluate_action` — projects it onto the two-variant `GuardDecision`. Retained
  because `GuardDecision` is what the relays match on; it discards the reasons, matched
  rules, policy version, and latency, and cannot express `REQUIRE_APPROVAL`.

New code should use the gateway directly.

## Behavior changes

Two deliberate changes came with this refactor.

1. **`action: Confirm` now gates.** It previously logged a message, emitted a `Skipped`
   telemetry record, and let the call through — the confirmation never happened. It now
   maps to `REQUIRE_APPROVAL` and is resolved by the approval engine. For the shipped
   policy this changes nothing observable: the only `Confirm` rule is `execute_bash`, whose
   base risk of 75 already exceeded the default threshold of 70 and therefore already
   gated. It removes the redundant `Skipped` record that accompanied it.

2. **A failing Wasm extension denies instead of killing the relay.** The error previously
   propagated up through `evaluate_action` and terminated the relay task. It is now a
   `DENY` with an `extension_failed` reason, per the fail-closed rule for enforcement
   stages.

The subsequent failure-mode hardening changed behavior in a further set of previously
ambiguous cases — payloads the policy engine could not parse, unbounded approval prompts,
runaway extensions, and others. They are tabulated in
[`FAILURE_MODES.md`](./FAILURE_MODES.md#backwards-compatibility), along with the
`SQREEN_FAILURE_POLICY=observe` posture that restores the prior behavior for a staged
rollout.
