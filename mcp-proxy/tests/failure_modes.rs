//! Integration tests for the failure-mode matrix.
//!
//! [`agent_execution_gateway`](./agent_execution_gateway.rs) covers what the pipeline does
//! when its parts work. This file covers what it does when they do not, which is the part
//! an attacker is actually interested in.
//!
//! Every test here is written against one claim in `docs/FAILURE_MODES.md`, and the claim
//! is quoted where it is not obvious. If a test and the document disagree, one of them is
//! a bug; they are not allowed to drift quietly.
//!
//! The governing invariant, which several tests restate from different angles: **a broken
//! control never produces a plain allow.** It may deny, it may escalate to an approver, and
//! for the two recording-only subsystems it may proceed while saying so — but "an exception
//! happened, so the action went through unexamined" is not a reachable state.

use std::sync::Arc;
use std::time::Duration;

use mcp_proxy::adapters::{
    GenericAdapter, McpAdapter, McpToolsCall, NormalizationContext, ToolCallAdapter,
};
use mcp_proxy::gateway::{
    AgentExecutionGateway, AllowAllApprovalEngine, ApprovalEngine, ApprovalFuture, ApprovalOutcome,
    ApprovalRequest, AuditEvent, Decision, FailingAuditSink, FailureMode, FailurePolicy,
    GatewayBuilder, GatewayConfig, ReasonCode, RecordingAuditSink, Stage, Subsystem,
    TimeoutApprovalEngine, UnavailableApprovalEngine,
};
use mcp_proxy::guard::ToolInvocation;
use mcp_proxy::policy::PolicyEngine;
use mcp_proxy::AgentAction;

const POLICY: &str = r#"
version: "2026.1"
global:
  redact_keys: ["OPENAI_API_KEY"]
  risk_threshold: 70
  block_patterns: ["\\.ssh/"]
tools:
  - name: "read_file"
    action: "Allow"
    block_patterns: ["/etc/shadow"]
  - name: "drop_table"
    action: "Block"
    block_patterns: []
  - name: "deploy_release"
    action: "Confirm"
    block_patterns: []
"#;

fn policy() -> Arc<PolicyEngine> {
    Arc::new(PolicyEngine::from_yaml(POLICY).expect("compile policy"))
}

/// An action that reaches the approval stage.
///
/// `deploy_release` is declared `Confirm`, so policy gates it without deciding it. A
/// payload that a *block* rule catches would never reach an approver, which makes it
/// useless for testing approver failures.
fn action_needing_approval() -> AgentAction {
    mcp_action(r#"{"name":"deploy_release","arguments":{"target":"prod"}}"#)
}

fn mcp_action(params_json: &str) -> AgentAction {
    McpAdapter::decode(
        &NormalizationContext::new(),
        McpToolsCall::stdio(params_json),
    )
    .expect("decode mcp tools/call")
}

/// An action whose canonical payload is not JSON.
///
/// Reachable only through the legacy [`ToolInvocation`] bridge, which deliberately skips
/// validation so payloads that evaluated before normalization existed still evaluate. That
/// makes it the exact shape a parser-failure test needs: the adapters would have rejected
/// it at the edge, so this is what "the payload reached the engine and the engine cannot
/// read it" looks like.
fn unreadable_action(tool_name: &str) -> AgentAction {
    ToolInvocation {
        tool_name: tool_name.to_string(),
        params_json: "{ this is not json".to_string(),
    }
    .to_agent_action()
}

/// Events whose marker identifies them as a security-failure record.
fn failure_events(recorder: &RecordingAuditSink) -> Vec<AuditEvent> {
    recorder
        .events()
        .into_iter()
        .filter(|event| event.pattern_matched.starts_with("security_failure:"))
        .collect()
}

/// Renders an event the way a leak would escape: every field, nothing skipped.
///
/// Debug output is the strictest probe available here. A sink that formats selected fields
/// could hide a leak living in one it ignores; this sees all of them.
fn rendered(event: &AuditEvent) -> String {
    format!("{event:?}")
}

/* ------------------------------------------------------------------ */
/* Parser and policy-engine failures                                  */
/* ------------------------------------------------------------------ */

/// The headline regression. This payload used to be *allowed*: the policy engine could not
/// parse it, returned no verdict, and the pipeline read "no verdict" as "no objection".
#[tokio::test]
async fn a_payload_the_policy_engine_cannot_read_is_denied_not_allowed() {
    let recorder = Arc::new(RecordingAuditSink::new());
    let outcome = GatewayBuilder::default()
        .policy_engine(Some(policy()))
        .audit(recorder.clone())
        .build()
        .evaluate(&unreadable_action("read_file"))
        .await;

    assert_eq!(outcome.decision, Decision::Deny);
    assert!(outcome.has_reason(ReasonCode::PolicyPayloadUnreadable));
    assert!(
        !failure_events(&recorder).is_empty(),
        "an unreadable payload is a security failure and must be in the trail"
    );
}

/// Same payload, `observe` posture: the pre-hardening behavior, available deliberately and
/// by name rather than by accident.
#[tokio::test]
async fn the_observe_posture_restores_the_previous_forwarding_behavior() {
    let recorder = Arc::new(RecordingAuditSink::new());
    let outcome = GatewayBuilder::default()
        .policy_engine(Some(policy()))
        .audit(recorder.clone())
        .approval(Arc::new(AllowAllApprovalEngine))
        .failure_policy(FailurePolicy::observe())
        .build()
        .evaluate(&unreadable_action("read_file"))
        .await;

    assert_eq!(
        outcome.decision,
        Decision::Allow,
        "observe mode exists precisely so an operator can stage the rollout"
    );
    assert!(
        outcome.has_reason(ReasonCode::PolicyPayloadUnreadable),
        "but the failure is still reported — observe means do-not-block, not do-not-see"
    );
    assert!(
        !failure_events(&recorder).is_empty(),
        "and it is still audited"
    );
}

/// A denial from a broken control must not claim a rule fired. The verdict is the same
/// either way; the evidence behind it is not, and an investigator reading the trail needs
/// "the engine could not read this" to be distinct from "rule X matched".
#[tokio::test]
async fn a_failure_denial_does_not_fabricate_a_matched_rule() {
    let outcome = GatewayBuilder::default()
        .policy_engine(Some(policy()))
        .build()
        .evaluate(&unreadable_action("read_file"))
        .await;

    assert_eq!(outcome.decision, Decision::Deny);
    assert!(
        outcome.matched_policies.is_empty(),
        "nothing matched; the payload was never read"
    );
    assert!(
        outcome
            .reasons
            .iter()
            .any(|reason| reason.code.is_security_failure()),
        "the denial must be attributed to the failed subsystem"
    );

    // Reported to the agent as a prohibition rather than an operator judgment: a policy
    // that cannot be applied is a configuration problem, and "do not retry" is the honest
    // instruction. See `ReasonCode::is_rule_prohibition`.
    assert!(outcome.denied_by_rule());
}

/* ------------------------------------------------------------------ */
/* Missing and corrupted policy                                       */
/* ------------------------------------------------------------------ */

/// No policy configured is a security outage under the default enforcing posture.
/// Remaining controls (risk) do not get to run when declarative policy is required and
/// absent — the pipeline fails closed at the policy stage.
#[tokio::test]
async fn an_absent_policy_fails_closed_by_default() {
    let recorder = Arc::new(RecordingAuditSink::new());
    let outcome = GatewayBuilder::default()
        .policy_engine(None)
        .audit(recorder.clone())
        .build()
        .evaluate(&mcp_action(
            r#"{"name":"read_file","arguments":{"path":"/tmp/notes.md"}}"#,
        ))
        .await;

    assert_eq!(outcome.decision, Decision::Deny);
    assert!(outcome.has_reason(ReasonCode::PolicyUnavailable));
    assert_eq!(
        outcome.policy_availability,
        mcp_proxy::gateway::PolicyAvailability::Missing
    );
    assert_eq!(
        outcome.metadata.get("policy_state").map(String::as_str),
        Some("MISSING")
    );
    assert!(
        !failure_events(&recorder).is_empty(),
        "missing policy must be audited as a security failure"
    );
}

/// Local experimentation may opt into FAIL_OPEN, but never silently.
#[tokio::test]
async fn development_posture_may_fail_open_with_an_explicit_warning_reason() {
    use mcp_proxy::gateway::EnforcementPosture;

    let outcome = GatewayBuilder::default()
        .policy_engine(None)
        .failure_policy(FailurePolicy::for_posture(EnforcementPosture::Development))
        .build()
        .evaluate(&mcp_action(
            r#"{"name":"read_file","arguments":{"path":"/tmp/notes.md"}}"#,
        ))
        .await;

    assert_eq!(outcome.decision, Decision::Allow);
    assert!(outcome.has_reason(ReasonCode::PolicyUnavailable));
    assert!(outcome
        .reasons
        .iter()
        .any(|reason| reason.detail.contains("development posture: FAIL_OPEN")));
}

/// Managed posture also fails closed, and remote-unavailable is distinguishable.
#[tokio::test]
async fn managed_posture_denies_when_remote_policy_is_unavailable() {
    use mcp_proxy::gateway::{EnforcementPosture, PolicyAvailability};

    let outcome = GatewayBuilder::default()
        .policy_engine(None)
        .policy_availability(PolicyAvailability::RemoteUnavailable)
        .failure_policy(FailurePolicy::for_posture(EnforcementPosture::Managed))
        .build()
        .evaluate(&mcp_action(
            r#"{"name":"read_file","arguments":{"path":"/tmp/notes.md"}}"#,
        ))
        .await;

    assert_eq!(outcome.decision, Decision::Deny);
    assert_eq!(
        outcome.policy_availability,
        PolicyAvailability::RemoteUnavailable
    );
    assert!(outcome.has_reason(ReasonCode::PolicyUnavailable));
}

/// A deployment that treats a missing policy as a misconfiguration can say so.
#[tokio::test]
async fn an_absent_policy_can_be_made_fatal() {
    let outcome = GatewayBuilder::default()
        .policy_engine(None)
        .failure_policy(FailurePolicy::strict())
        .build()
        .evaluate(&mcp_action(
            r#"{"name":"read_file","arguments":{"path":"/tmp/notes.md"}}"#,
        ))
        .await;

    assert_eq!(outcome.decision, Decision::Deny);
    assert!(outcome.has_reason(ReasonCode::PolicyUnavailable));
}

/* ------------------------------------------------------------------ */
/* Approval-service failures                                          */
/* ------------------------------------------------------------------ */

/// An approver that cannot be reached is the failure most tempting to fail open on — the
/// action is often legitimate and the operator is often just asleep. It still denies.
#[tokio::test]
async fn an_unreachable_approver_denies_rather_than_allowing() {
    let recorder = Arc::new(RecordingAuditSink::new());
    let outcome = GatewayBuilder::default()
        .policy_engine(Some(policy()))
        .audit(recorder.clone())
        .approval(Arc::new(UnavailableApprovalEngine))
        .build()
        .evaluate(&action_needing_approval())
        .await;

    assert_eq!(outcome.decision, Decision::Deny);
    assert!(outcome.has_reason(ReasonCode::ApprovalUnavailable));
    assert!(
        recorder
            .patterns()
            .iter()
            .any(|pattern| pattern == &Subsystem::Approval.audit_marker()),
        "'nobody was there' must be separable from 'a human said no'"
    );
}

/// An approver that never answers must not hold the action — or the relay task — forever.
#[tokio::test]
async fn an_approver_that_never_answers_times_out_and_denies() {
    struct SilentApprover;

    impl ApprovalEngine for SilentApprover {
        fn request<'a>(&'a self, _request: ApprovalRequest<'a>) -> ApprovalFuture<'a> {
            Box::pin(async {
                tokio::time::sleep(Duration::from_secs(3600)).await;
                ApprovalOutcome::approve_once()
            })
        }

        fn name(&self) -> &'static str {
            "silent"
        }
    }

    let outcome = GatewayBuilder::default()
        .policy_engine(Some(policy()))
        .approval(Arc::new(TimeoutApprovalEngine::new(
            Arc::new(SilentApprover),
            Duration::from_millis(50),
        )))
        .build()
        .evaluate(&action_needing_approval())
        .await;

    assert_eq!(outcome.decision, Decision::Deny);
    assert!(
        outcome.has_reason(ReasonCode::ApprovalTimedOut),
        "a timeout must be recorded as a timeout, not as an operator's decision"
    );
}

/// Unattended deployments exist. They opt in explicitly.
#[tokio::test]
async fn an_unreachable_approver_can_be_configured_to_escalate_instead() {
    let outcome = GatewayBuilder::default()
        .policy_engine(Some(policy()))
        .approval(Arc::new(UnavailableApprovalEngine))
        .failure_policy(FailurePolicy {
            approval_unavailable: FailureMode::DegradeSafely,
            ..FailurePolicy::default()
        })
        .build()
        .evaluate(&action_needing_approval())
        .await;

    assert_eq!(
        outcome.decision,
        Decision::RequireApproval,
        "degrade-safely hands the action back to the caller unresolved"
    );
    assert!(
        !outcome.is_allowed(),
        "an unresolved action is never an allowed action"
    );
}

/* ------------------------------------------------------------------ */
/* Cloud and telemetry failures — requirement 6                       */
/* ------------------------------------------------------------------ */

/// The local-first guarantee, stated as a test: with no control plane configured at all,
/// enforcement is unaffected.
#[tokio::test]
async fn enforcement_is_complete_without_a_control_plane() {
    let outcome = GatewayBuilder::default()
        .policy_engine(Some(policy()))
        .build()
        .evaluate(&mcp_action(
            r#"{"name":"drop_table","arguments":{"table":"users"}}"#,
        ))
        .await;

    assert_eq!(outcome.decision, Decision::Deny);
    assert!(outcome.denied_by_rule());
    assert_eq!(outcome.policy_version.as_deref(), Some("2026.1"));
}

/// A dead audit sink is the telemetry-failure case: the event is lost, the decision is not.
#[tokio::test]
async fn a_dead_audit_sink_does_not_change_the_verdict() {
    let allowed = GatewayBuilder::default()
        .policy_engine(Some(policy()))
        .audit(Arc::new(FailingAuditSink))
        .config(GatewayConfig {
            audit_all_decisions: true,
            ..GatewayConfig::default()
        })
        .build()
        .evaluate(&mcp_action(
            r#"{"name":"read_file","arguments":{"path":"/tmp/notes.md"}}"#,
        ))
        .await;

    assert_eq!(allowed.decision, Decision::Allow);
    assert!(allowed.has_reason(ReasonCode::AuditDeliveryFailed));

    let denied = GatewayBuilder::default()
        .policy_engine(Some(policy()))
        .audit(Arc::new(FailingAuditSink))
        .build()
        .evaluate(&mcp_action(
            r#"{"name":"drop_table","arguments":{"table":"users"}}"#,
        ))
        .await;

    assert_eq!(
        denied.decision,
        Decision::Deny,
        "a lost audit event must not rescue a blocked action either"
    );
}

/// A deployment under an audit mandate inverts that trade: no trail, no action.
///
/// Such a deployment records every decision, so the routine-allow event is in scope — and
/// that event is the one whose loss used to be undetectable, because it was written after
/// the verdict was fixed and its result was discarded.
#[tokio::test]
async fn a_deployment_that_requires_a_trail_denies_when_it_cannot_write_one() {
    let outcome = GatewayBuilder::default()
        .policy_engine(Some(policy()))
        .audit(Arc::new(FailingAuditSink))
        .approval(Arc::new(AllowAllApprovalEngine))
        .config(GatewayConfig {
            audit_all_decisions: true,
            ..GatewayConfig::default()
        })
        .failure_policy(FailurePolicy {
            audit_error: FailureMode::FailClosed,
            ..FailurePolicy::default()
        })
        .build()
        .evaluate(&mcp_action(
            r#"{"name":"read_file","arguments":{"path":"/tmp/notes.md"}}"#,
        ))
        .await;

    assert_eq!(outcome.decision, Decision::Deny);
    assert!(outcome.has_reason(ReasonCode::AuditDeliveryFailed));
}

/// The counterpart: with routine auditing off there is no event to lose on a clean allow,
/// so the mandate has nothing to enforce and the action proceeds.
#[tokio::test]
async fn an_audit_mandate_does_not_invent_a_failure_when_nothing_was_to_be_recorded() {
    let outcome = GatewayBuilder::default()
        .policy_engine(Some(policy()))
        .audit(Arc::new(FailingAuditSink))
        .config(GatewayConfig {
            audit_all_decisions: false,
            ..GatewayConfig::default()
        })
        .failure_policy(FailurePolicy {
            audit_error: FailureMode::FailClosed,
            ..FailurePolicy::default()
        })
        .build()
        .evaluate(&mcp_action(
            r#"{"name":"read_file","arguments":{"path":"/tmp/notes.md"}}"#,
        ))
        .await;

    assert_eq!(outcome.decision, Decision::Allow);
    assert!(!outcome.has_reason(ReasonCode::AuditDeliveryFailed));
}

/// The one case where the control plane gates a decision: the operator demanded it.
#[tokio::test]
async fn a_mandated_control_plane_denies_when_it_is_absent() {
    let recorder = Arc::new(RecordingAuditSink::new());
    let outcome = GatewayBuilder::default()
        .policy_engine(Some(policy()))
        .audit(recorder.clone())
        .config(GatewayConfig {
            require_control_plane: true,
            ..GatewayConfig::default()
        })
        .build()
        .evaluate(&mcp_action(
            r#"{"name":"read_file","arguments":{"path":"/tmp/notes.md"}}"#,
        ))
        .await;

    assert_eq!(outcome.decision, Decision::Deny);
    assert!(outcome.has_reason(ReasonCode::CloudUnavailable));
    assert!(!failure_events(&recorder).is_empty());
}

/* ------------------------------------------------------------------ */
/* Unknown action types and unsupported providers                     */
/* ------------------------------------------------------------------ */

/// An action from a runtime with no dedicated adapter is still a normalized action, and
/// the engine treats it like any other. "Unsupported provider" is not a bypass.
#[tokio::test]
async fn an_action_from_an_unmodeled_runtime_is_still_enforced() {
    let action = GenericAdapter::shell_command(
        &NormalizationContext::new(),
        "cat ~/.ssh/id_rsa",
        Some("some-future-agent-framework"),
    )
    .expect("decode generic shell action");

    let outcome = GatewayBuilder::default()
        .policy_engine(Some(policy()))
        .build()
        .evaluate(&action)
        .await;

    assert_eq!(
        outcome.decision,
        Decision::Deny,
        "the global block pattern applies regardless of where the action came from"
    );
}

/// A tool nobody wrote a rule for is governed by the global rules and the risk stage, not
/// waved through for being unrecognized.
#[tokio::test]
async fn an_unknown_tool_is_governed_by_the_global_rules() {
    let outcome = GatewayBuilder::default()
        .policy_engine(Some(policy()))
        .build()
        .evaluate(&mcp_action(
            r#"{"name":"some_tool_nobody_declared","arguments":{"path":"~/.ssh/config"}}"#,
        ))
        .await;

    assert_eq!(outcome.decision, Decision::Deny);
}

/* ------------------------------------------------------------------ */
/* Requirement 5 — secrets must not travel in error text              */
/* ------------------------------------------------------------------ */

/// Reason details are operator-facing and audit-bound. A payload that contains a
/// credential must not turn the explanation into a second copy of it.
#[tokio::test]
async fn a_credential_in_the_payload_never_appears_in_the_reasons_or_the_audit_trail() {
    const TOKEN: &str = "sk-proj-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";

    let recorder = Arc::new(RecordingAuditSink::new());
    let outcome = GatewayBuilder::default()
        .policy_engine(Some(policy()))
        .audit(recorder.clone())
        .approval(Arc::new(AllowAllApprovalEngine))
        .config(GatewayConfig {
            audit_all_decisions: true,
            ..GatewayConfig::default()
        })
        .build()
        .evaluate(&mcp_action(&format!(
            r#"{{"name":"read_file","arguments":{{"path":"/tmp/a","token":"{TOKEN}"}}}}"#
        )))
        .await;

    let encoded = serde_json::to_string(&outcome).expect("serialize outcome");
    assert!(
        !encoded.contains(TOKEN),
        "the outcome leaked a credential: {encoded}"
    );

    for event in recorder.events() {
        let encoded = rendered(&event);
        assert!(
            !encoded.contains(TOKEN),
            "an audit event leaked a credential: {encoded}"
        );
    }
}

/// The same guarantee on the failure path, where the error text is built from a payload
/// the engine could not parse — historically the most likely place to echo raw input.
#[tokio::test]
async fn a_credential_in_an_unparseable_payload_never_reaches_the_reasons() {
    const TOKEN: &str = "ghp_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";

    let action = ToolInvocation {
        tool_name: "read_file".to_string(),
        params_json: format!("{{ broken \"token\": \"{TOKEN}\""),
    }
    .to_agent_action();

    let recorder = Arc::new(RecordingAuditSink::new());
    let outcome = GatewayBuilder::default()
        .policy_engine(Some(policy()))
        .audit(recorder.clone())
        .build()
        .evaluate(&action)
        .await;

    assert_eq!(outcome.decision, Decision::Deny);

    for reason in &outcome.reasons {
        assert!(
            !reason.detail.contains(TOKEN),
            "reason leaked a credential: {}",
            reason.detail
        );
    }

    for event in recorder.events() {
        assert!(
            !rendered(&event).contains(TOKEN),
            "audit event leaked a credential"
        );
    }
}

/* ------------------------------------------------------------------ */
/* Requirement 3 — every security failure is in the trail             */
/* ------------------------------------------------------------------ */

/// A security failure is audited even when ordinary allows are not, because the question
/// "was a control broken while this ran" must be answerable from the trail alone.
#[tokio::test]
async fn a_security_failure_is_audited_even_with_routine_auditing_off() {
    let recorder = Arc::new(RecordingAuditSink::new());
    let gateway = GatewayBuilder::default()
        .policy_engine(Some(policy()))
        .audit(recorder.clone())
        .config(GatewayConfig {
            audit_all_decisions: false,
            ..GatewayConfig::default()
        })
        .build();

    let allowed = gateway
        .evaluate(&mcp_action(
            r#"{"name":"read_file","arguments":{"path":"/tmp/notes.md"}}"#,
        ))
        .await;
    assert_eq!(allowed.decision, Decision::Allow);
    assert!(
        recorder.events().is_empty(),
        "a clean allow is not an event worth storing"
    );

    let denied = gateway.evaluate(&unreadable_action("read_file")).await;
    assert_eq!(denied.decision, Decision::Deny);

    let failures = failure_events(&recorder);
    assert!(!failures.is_empty(), "the broken control must be recorded");

    let event = &failures[0];
    assert_eq!(event.stage, Stage::Policy);
    assert_eq!(
        event.pattern_matched,
        Subsystem::PolicyPayload.audit_marker(),
        "the marker must name the subsystem that broke"
    );
    assert_eq!(event.tool_name, "read_file");
    assert!(
        !event.reasons.is_empty(),
        "an event with no reason is not evidence of anything"
    );
}

/* ------------------------------------------------------------------ */
/* Requirement 1 — the matrix is one place, and it is honored         */
/* ------------------------------------------------------------------ */

/// The property that makes the module worth having: no default lets a broken *inspection*
/// control produce a plain allow. Audit and control-plane are excluded by design;
/// `policy_missing` is FAIL_CLOSED by default (governed by enforcement posture).
#[test]
fn no_default_permits_an_allow_from_a_broken_inspection_control() {
    assert!(FailurePolicy::default().never_allows_on_inspection_failure());
    assert!(FailurePolicy::strict().never_allows_on_inspection_failure());
    assert_eq!(
        FailurePolicy::default().mode_for(Subsystem::PolicyMissing),
        FailureMode::FailClosed
    );
}

/// Every subsystem must resolve to a mode. A new subsystem added without a matrix entry
/// would not compile, but a new subsystem added and then forgotten in `ALL` would silently
/// escape `describe`, the startup banner, and the documentation check below.
#[test]
fn the_matrix_covers_every_subsystem() {
    let described = FailurePolicy::default().describe();

    assert_eq!(described.len(), Subsystem::ALL.len());

    for (name, mode) in described {
        assert!(!name.is_empty());
        assert!(
            ["FAIL_OPEN", "FAIL_CLOSED", "DEGRADE_SAFELY"].contains(&mode),
            "unexpected mode rendering: {mode}"
        );
    }
}

/// Requirement 7 is "clearly document the failure-mode matrix", and a document that can
/// drift from the code documents nothing. This reads the published matrix and checks each
/// subsystem's row against the compiled default.
///
/// The check is deliberately loose about formatting — it looks for the subsystem's
/// identifier and its mode on the same line — so the table can be reworded or reordered
/// without breaking the build. What it will not tolerate is a row that states the wrong
/// mode, or a subsystem that never made it into the document at all.
#[test]
fn the_published_matrix_matches_the_compiled_defaults() {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/../docs/FAILURE_MODES.md");
    let document = std::fs::read_to_string(path)
        .unwrap_or_else(|error| panic!("failure-mode documentation is missing at {path}: {error}"));

    let policy = FailurePolicy::default();

    for subsystem in Subsystem::ALL {
        let name = subsystem.as_str();
        let expected = policy.mode_for(subsystem).as_str();

        let row = document
            .lines()
            .find(|line| line.starts_with("| `") && line.contains(&format!("`{name}`")))
            .unwrap_or_else(|| panic!("`{name}` has no row in the documented matrix"));

        assert!(
            row.contains(expected),
            "the matrix says something other than {expected} for `{name}`: {row}"
        );
    }
}

/// The gateway must be assemblable in every posture without any of them panicking or
/// silently producing an allow for a denied action.
#[tokio::test]
async fn every_preset_still_blocks_what_the_rules_block() {
    for preset in [
        FailurePolicy::default(),
        FailurePolicy::strict(),
        FailurePolicy::observe(),
    ] {
        let outcome = GatewayBuilder::default()
            .policy_engine(Some(policy()))
            .failure_policy(preset)
            .build()
            .evaluate(&mcp_action(
                r#"{"name":"drop_table","arguments":{"table":"users"}}"#,
            ))
            .await;

        assert_eq!(
            outcome.decision,
            Decision::Deny,
            "a posture that relaxes failure handling must not relax the rules themselves"
        );
    }
}

/* ------------------------------------------------------------------ */
/* The pipeline stays observable when it fails                        */
/* ------------------------------------------------------------------ */

/// A failure path is still a decision path: it reports latency, the tool, and a reason.
/// Without that, a denial from a broken control is indistinguishable from a crash.
#[tokio::test]
async fn a_failure_verdict_carries_the_same_evidence_as_any_other() {
    let outcome = AgentExecutionGateway::builder()
        .policy_engine(Some(policy()))
        .build()
        .evaluate(&unreadable_action("read_file"))
        .await;

    assert_eq!(outcome.tool_name, "read_file");
    assert!(outcome.latency.as_nanos() > 0);
    assert!(!outcome.reasons.is_empty());
    assert!(outcome
        .reasons
        .iter()
        .all(|reason| !reason.detail.is_empty()));
}
