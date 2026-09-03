# Failure modes

> Broader threat model, trust boundaries, and known gaps: **[THREAT_MODEL.md](./THREAT_MODEL.md)**.

What Sqreen does when one of its own security controls breaks.

This is the authoritative reference for that question. The matrix below is mirrored in the
module documentation of `mcp-proxy/src/gateway/failure.rs` and asserted by
`mcp-proxy/tests/failure_modes.rs`; if the three ever disagree, one of them is a bug.

## The governing invariant

> **A broken control never produces a plain allow.**

An action may be denied, or escalated to a human, or — for the two subsystems that only
*record* — allowed while the failure is reported alongside the verdict. What is not
reachable is "an exception happened, so the action went through unexamined."

## Where the decision lives

No subsystem decides what its own failure means. The flow is:

1. A subsystem that cannot do its job reports a `SubsystemFailure` — the subsystem's
   identity plus a sanitized detail string.
2. `FailurePolicy` maps that subsystem to a `FailureMode`.
3. The gateway applies the resulting `FailureAction` and emits an audit event.

The practical consequence: changing a deployment's posture is editing one struct, and
auditing the posture is reading one table. There is no `unwrap_or(Allow)` anywhere in the
enforcement path, and adding one would have to survive review against this document.

## The three modes

| Mode | Effect | When it is right |
|---|---|---|
| `FAIL_OPEN` | Record the failure; the verdict stands. | The subsystem *describes*. Nothing reads it to decide, so losing it costs attribution, not enforcement. |
| `DEGRADE_SAFELY` | Record the failure; refuse to allow on the strength of a control that did not run — escalate to an approval. | The subsystem *inspects*. Its silence is not evidence of safety, but stopping outright would break more than it protects. |
| `FAIL_CLOSED` | Deny. | The subsystem exists to say "no". If it cannot answer, the answer is no. |

`DEGRADE_SAFELY` is what makes "never silently allow" achievable without making the proxy
brittle. An action that hits it is neither allowed nor rejected on its own merits: it goes
to an approver with the failure attached as the justification. If no approver is reachable,
the approval subsystem's own mode takes over — fail-closed by default — so a degraded
action cannot end up allowed by default through a second failure.

## The matrix

| Subsystem | Failure it reports | Default | Rationale |
|---|---|---|---|
| `normalization` | Malformed provider payload, unknown action type, unsupported provider event | **FAIL_CLOSED** | An action nobody can parse is an action nobody can evaluate. |
| `policy_missing` | No declarative policy loaded | **FAIL_CLOSED** | Default enforcement posture is `enforcing`. An absent policy must not silently become allow-all. Opt into FAIL_OPEN only via `SQREEN_ENFORCEMENT_POSTURE=development` (loud warning + structured reason). Managed fleets use `managed` (also FAIL_CLOSED; distinguishes `REMOTE_UNAVAILABLE`). |
| `policy_engine` | Corrupt policy, regex failure, redaction produced non-UTF-8 | **FAIL_CLOSED** | A policy that exists and cannot be applied is an enforcement outage, not an absence of rules. |
| `policy_payload` | Arguments unparseable, so no rule could match against them | **FAIL_CLOSED** | A payload the inspector cannot read is exactly the payload an attacker wants it to receive. |
| `policy_extension` | Wasm trap, fuel exhaustion, host error | **FAIL_CLOSED** | The extension was installed to make a decision. |
| `risk_scoring` | Scorer could not parse the payload and fell back to raw-text scanning | **DEGRADE_SAFELY** | The action is still scored, but by a weaker scanner — so it does not get to pass on that score alone. |
| `dlp_scanner` | Matched sensitive data, then failed to produce the masked payload | **FAIL_CLOSED** | The only two outcomes are "forward the unmasked secret" and "stop". |
| `threat_intel` | Indicator set could not be read | **DEGRADE_SAFELY** | Absence of indicators is not evidence of safety, but it is not grounds to stop everything either. |
| `approval` | Approver unreachable, prompt failed, prompt timed out | **FAIL_CLOSED** | An action awaiting a judgment that never came has not been judged. |
| `audit` | Sink rejected the event | **FAIL_OPEN** | See [below](#why-audit-and-control-plane-failures-are-the-open-ones). |
| `control_plane` | Control plane unreachable, telemetry dispatch failed | **FAIL_OPEN** | See [below](#why-audit-and-control-plane-failures-are-the-open-ones). |
| `internal` | Panic or unclassified error inside a stage | **FAIL_CLOSED** | An unexplained failure in a security control is the least safe thing to guess about. |

### Presets

| Preset | Posture |
|---|---|
| `FailurePolicy::default()` | The matrix above. |
| `FailurePolicy::strict()` | Every subsystem closed, including audit, control plane, and absent policy. |
| `FailurePolicy::observe()` | Only a broken approver fails closed. For validating the proxy against production traffic before letting it block, and for restoring pre-hardening behavior during a staged rollout. **Not a security posture.** |

Select one without a code change:

```bash
export SQREEN_FAILURE_POLICY=strict     # or: default, observe
```

An unrecognized value is reported on stderr and ignored in favor of the default —
silently applying a posture the operator did not ask for is the exact failure this design
exists to prevent.

## Enforcement posture (policy availability)

`policy_missing` is additionally governed by **`SQREEN_ENFORCEMENT_POSTURE`**:

| Posture | Env value | Missing / invalid / unobtainable policy |
|---|---|---|
| Development | `development` / `dev` / `permissive` | FAIL_OPEN + stderr warning + `policy_unavailable` reason (not silent) |
| Enforcing (default) | `enforcing` / `protected` | FAIL_CLOSED — decision `DENY`, reason `policy_unavailable`, `policy_state` metadata |
| Managed | `managed` / `fleet` / `enterprise` | FAIL_CLOSED; distinguishes `REMOTE_UNAVAILABLE` from `MISSING` when the control plane and cache are both gone |

Typed availability states on every outcome: `AVAILABLE`, `MISSING`, `INVALID`, `UNREADABLE`, `STALE`, `REMOTE_UNAVAILABLE`.

```bash
export SQREEN_ENFORCEMENT_POSTURE=enforcing   # production / installer default
# export SQREEN_ENFORCEMENT_POSTURE=development  # local DX only — conscious and visible
```

Adapters (MCP, OpenAI, Anthropic, Cursor, generic) and the guard facade all go through the
same gateway; none may override missing-policy behavior independently.

## Why audit and control-plane failures are the open ones

**Cloud connectivity is never required to make a security decision.** The gateway treats
the control plane as a *replica, not an oracle*: policy is evaluated from a local snapshot,
approvals resolve locally, and telemetry is dispatched on a detached task whose failure
cannot reach the verdict. Enforcement on an offline laptop is identical to enforcement on a
connected one.

Neither failure is ever swallowed. A failed audit adds an `audit_delivery_failed` reason to
the outcome the caller receives, so "we allowed this and could not log it" is visible in
the result itself rather than only in a log nobody reads.

A deployment where an unlogged action is itself a finding inverts the trade:

```rust
FailurePolicy { audit_error: FailureMode::FailClosed, ..FailurePolicy::default() }
```

paired with `GatewayConfig::audit_all_decisions = true`, so routine allows are in scope
too. Without that flag there is no event to lose on a clean allow, and the mandate has
nothing to enforce. `GatewayConfig::require_control_plane` is the equivalent for the
control plane, and is checked before anything else in the pipeline.

## Secrets in error text

Error details are operator-facing and audit-bound, and the most natural way to write one
is to include the input that caused it — which is how a credential ends up in a log.

`DecisionReason::new` sanitizes every detail it is given, so a leaking reason cannot be
constructed. Sanitization masks known secret shapes, strips credentials from URLs, removes
control characters, and truncates. The same function is exported as
`gateway::sanitize_detail` / `gateway::sanitize_error` for the relay and HTTP paths, which
build messages outside the gateway.

Two consequences worth knowing:

- The stdio debug log (`--debug-log`) masks secrets before writing frames. It previously
  wrote them verbatim, which made the log a higher-value target than the traffic.
- HTTP error responses carry a sanitized summary. The full chain goes to the operator's
  stderr; the agent, which is an untrusted consumer of error text, gets the summary.

## Timeouts

An unbounded wait inside a security control is a fail-open with extra steps: the action is
neither allowed nor denied, and the agent hangs.

| Operation | Bound | Override |
|---|---|---|
| Approval prompt | 300s, then deny | `SQREEN_APPROVAL_TIMEOUT_SECS` |
| Wasm extension | Fuel budget, then trap → deny | `SQREEN_WASM_FUEL` |

`TimeoutApprovalEngine` wraps any `ApprovalEngine`, so the bound holds regardless of which
approver a deployment uses.

## Failures in the audit trail

Every subsystem failure emits its own audit event, with a `pattern_matched` of
`security_failure:<subsystem>`. This happens regardless of the verdict and regardless of
`audit_all_decisions`, because a broken control is an operational event whether or not it
changed this particular outcome — and an attacker probing for a way to break one produces a
stream of them, which is a signature worth having in the trail.

Query the trail for `security_failure:` to answer "was any control degraded while this
agent was running?"

## Backwards compatibility

The hardening changed behavior in cases that were previously ambiguous. Each of these was
an implicit allow before, and is listed so an operator can recognize the change if they see
it:

| Behavior | Before | Now |
|---|---|---|
| `tools/call` params the policy engine cannot parse | Allowed — no verdict was read as no objection | Denied (`policy_payload`) |
| Client→server JSON-RPC frame the envelope parser cannot read | Forwarded to the server unexamined | Denied with a JSON-RPC error |
| MCP payload the adapter cannot normalize | Relay task aborted, killing the agent's connection | Denied with a JSON-RPC error; the session survives |
| Global secret redaction on a non-JSON frame | Original frame returned silently | Reported; pattern-based masking still applies |
| Approval prompt with no answer | Waited forever | Denied after the deadline |
| Runaway Wasm extension | Hung the relay | Traps on fuel exhaustion, then denies |
| Policy file deleted at runtime | Enforcement silently disappeared | Previous policy retained |
| Poisoned policy/threat-intel lock | Control silently disabled | Recovered and kept enforcing |
| Debug log | Raw frames, secrets included | Secrets masked |
| Debug log write failure | Killed the relay | Warned once; enforcement continues |
| Audit failure on a routine allow | Discarded, undetectable | Governed by `audit_error` like every other emit |
| Malformed device token | Replaced with the literal `invalid-token` on the wire | Header omitted; the condition is named once |

Every row is a case where the old behavior let something through. A deployment that was
depending on one of them — most plausibly the first, if some tool emits payloads the
engine cannot parse — should run `SQREEN_FAILURE_POLICY=observe` and watch for
`security_failure:` events before switching to the default posture.

## Managed policy sync integrity

When `MCP_CONTROL_PLANE_URL` is set, remote policy must arrive as a signed envelope (docs/POLICY_INTEGRITY.md).

| Failure | Mode |
|---------|------|
| Signature / digest / org / rollback rejection | Keep previous verified policy; emit reject event |
| Control plane unreachable | Last-known-good signed cache if re-verify succeeds (STALE); else fail closed for managed signed path |
| Expired envelope | Continue enforcing; emit policy_expired (no implicit ALLOW) |
| Unsigned remote body | Reject (unless explicit non-prod allow) |

