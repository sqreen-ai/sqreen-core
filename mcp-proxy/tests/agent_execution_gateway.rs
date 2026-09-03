//! Integration tests for the Agent Execution Gateway.
//!
//! These exercise the gateway the way a real integration does: build an action through a
//! provider adapter, run it through a gateway assembled from a builder, and assert on the
//! [`EvaluationOutcome`]. Anything that pins a *stage* in isolation belongs in that stage's
//! unit tests; what is proven here is the pipeline as a whole.

use std::sync::Arc;

use mcp_proxy::adapters::{
    AnthropicAdapter, AnthropicToolUse, CursorAdapter, CursorHookEvent, GenericAdapter, McpAdapter,
    McpToolsCall, NormalizationContext, OpenAiAdapter, OpenAiFunctionCall, ToolCallAdapter,
};
use mcp_proxy::behavior::SessionTracker;
use mcp_proxy::gateway::{
    AgentExecutionGateway, AllowAllApprovalEngine, AuditSink, CompositeAuditSink, Decision,
    DenyAllApprovalEngine, EnforcementPosture, FailingAuditSink, FailurePolicy, GatewayBuilder,
    GatewayConfig, NullAuditSink, PolicyAvailability, PolicySource, ReasonCode, RecordingAuditSink,
    Stage, StaticIdentityResolver, TELEMETRY_RISK_THRESHOLD,
};
use mcp_proxy::policy::PolicyEngine;
use mcp_proxy::threat_intel::ThreatIntelMatcher;
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
  - name: "set_env"
    action: "Redact"
    block_patterns: []
"#;

fn policy() -> Arc<PolicyEngine> {
    Arc::new(PolicyEngine::from_yaml(POLICY).expect("compile policy"))
}

/// A gateway with the shipped defaults and an in-memory audit sink.
fn gateway(recorder: Arc<RecordingAuditSink>) -> AgentExecutionGateway {
    GatewayBuilder::default()
        .policy_engine(Some(policy()))
        .audit(recorder)
        .approval(Arc::new(DenyAllApprovalEngine))
        .build()
}

fn mcp_action(params_json: &str) -> AgentAction {
    McpAdapter::decode(
        &NormalizationContext::new(),
        McpToolsCall::stdio(params_json),
    )
    .expect("decode mcp tools/call")
}

/* ------------------------------------------------------------------ */
/* The happy path and the decision model                              */
/* ------------------------------------------------------------------ */

#[tokio::test]
async fn allows_a_benign_action_and_reports_the_full_outcome() {
    let recorder = Arc::new(RecordingAuditSink::new());
    let outcome = gateway(recorder.clone())
        .evaluate(&mcp_action(
            r#"{"name":"read_file","arguments":{"path":"/tmp/notes.md"}}"#,
        ))
        .await;

    assert_eq!(outcome.decision, Decision::Allow);
    assert!(outcome.is_allowed());
    assert_eq!(outcome.policy_version.as_deref(), Some("2026.1"));
    assert_eq!(outcome.tool_name, "read_file");
    assert!(outcome.risk_score.is_some(), "a score must be reported");
    assert!(outcome.rewritten_arguments.is_none());
    assert!(outcome.latency.as_nanos() > 0, "latency must be measured");
    assert!(recorder.events().is_empty(), "no signal, no audit event");
}

#[tokio::test]
async fn the_outcome_serializes_for_an_audit_pipeline() {
    let outcome = gateway(Arc::new(RecordingAuditSink::new()))
        .evaluate(&mcp_action(
            r#"{"name":"read_file","arguments":{"path":"~/.ssh/id_rsa"}}"#,
        ))
        .await;

    let encoded = serde_json::to_value(&outcome).expect("serialize outcome");

    assert_eq!(encoded["decision"], "DENY");
    assert_eq!(encoded["policy_version"], "2026.1");
    assert_eq!(encoded["tool_name"], "read_file");
    assert!(encoded["latency_micros"].is_u64());
    assert_eq!(
        encoded["matched_policies"][0]["source"], "local_policy",
        "the matched rule must name its source"
    );
}

/* ------------------------------------------------------------------ */
/* Stage separation                                                   */
/* ------------------------------------------------------------------ */

#[tokio::test]
async fn a_policy_block_never_reaches_the_risk_stage() {
    let outcome = gateway(Arc::new(RecordingAuditSink::new()))
        .evaluate(&mcp_action(
            r#"{"name":"drop_table","arguments":{"table":"users"}}"#,
        ))
        .await;

    assert_eq!(outcome.decision, Decision::Deny);
    assert!(outcome.has_reason(ReasonCode::PolicyToolActionBlock));
    assert!(
        !outcome.has_reason(ReasonCode::RiskThresholdExceeded),
        "policy is terminal, so risk must not have run"
    );
    assert!(outcome
        .reasons
        .iter()
        .all(|reason| reason.stage == Stage::Policy));
}

#[tokio::test]
async fn a_redaction_rewrites_the_payload_and_short_circuits() {
    let recorder = Arc::new(RecordingAuditSink::new());
    let outcome = gateway(recorder.clone())
        .evaluate(&mcp_action(
            r#"{"name":"set_env","arguments":{"OPENAI_API_KEY":"sk-live-secret"}}"#,
        ))
        .await;

    assert_eq!(outcome.decision, Decision::Allow);

    let rewritten = outcome
        .rewritten_arguments
        .as_deref()
        .expect("redaction must produce a payload");
    assert!(
        !rewritten.contains("sk-live-secret"),
        "the secret must not survive redaction: {rewritten}"
    );
    assert!(outcome.has_reason(ReasonCode::PolicyRedaction));
    assert_eq!(recorder.patterns(), ["global_redact_keys"]);
}

#[tokio::test]
async fn the_risk_stage_gates_a_high_risk_action_the_policy_allowed() {
    let recorder = Arc::new(RecordingAuditSink::new());
    let outcome = gateway(recorder.clone())
        .evaluate(&mcp_action(
            r#"{"name":"execute_bash","arguments":{"command":"whoami"}}"#,
        ))
        .await;

    assert_eq!(outcome.decision, Decision::Deny);
    assert!(outcome.has_reason(ReasonCode::RiskThresholdExceeded));
    assert!(outcome.has_reason(ReasonCode::OperatorDenied));
    assert_eq!(recorder.patterns(), [TELEMETRY_RISK_THRESHOLD]);
    assert!(outcome
        .matched_policies
        .iter()
        .any(|matched| matched.source == PolicySource::RiskThreshold));
}

#[tokio::test]
async fn threat_intel_and_risk_are_separate_signals_on_one_outcome() {
    let outcome = GatewayBuilder::default()
        .policy_engine(Some(policy()))
        .threat_intel(Arc::new(ThreatIntelMatcher::from_blacklist(&[
            "evil-c2.example",
        ])))
        .approval(Arc::new(DenyAllApprovalEngine))
        .build()
        .evaluate(&mcp_action(
            r#"{"name":"fetch","arguments":{"url":"https://evil-c2.example/beacon"}}"#,
        ))
        .await;

    assert_eq!(outcome.decision, Decision::Deny);
    assert!(outcome.has_reason(ReasonCode::ThreatIntelMatch));
    assert_eq!(
        outcome.primary_detail(),
        Some("THREAT_INTEL_IOC_MATCH: operator denied IOC-tainted tool call"),
        "the denial message the stdio relay keys on must be preserved"
    );
}

/* ------------------------------------------------------------------ */
/* REQUIRE_APPROVAL                                                   */
/* ------------------------------------------------------------------ */

#[tokio::test]
async fn approval_is_deferred_to_the_caller_when_no_engine_is_configured() {
    let outcome = GatewayBuilder::default()
        .policy_engine(Some(policy()))
        .build()
        .evaluate(&mcp_action(
            r#"{"name":"deploy_release","arguments":{"target":"prod"}}"#,
        ))
        .await;

    assert_eq!(outcome.decision, Decision::RequireApproval);
    assert!(outcome.has_reason(ReasonCode::PolicyConfirmationRequired));
    assert!(outcome.has_reason(ReasonCode::ApprovalDeferred));
    assert!(
        outcome.stops_execution(),
        "an unresolved approval is not permission to run"
    );
    assert!(
        outcome.rewritten_arguments.is_none(),
        "a deferred action must not hand back a payload to forward"
    );
}

#[tokio::test]
async fn the_approval_engine_decides_a_confirm_rule_both_ways() {
    let action = mcp_action(r#"{"name":"deploy_release","arguments":{"target":"prod"}}"#);

    let approved = GatewayBuilder::default()
        .policy_engine(Some(policy()))
        .approval(Arc::new(AllowAllApprovalEngine))
        .build()
        .evaluate(&action)
        .await;

    let denied = GatewayBuilder::default()
        .policy_engine(Some(policy()))
        .approval(Arc::new(DenyAllApprovalEngine))
        .build()
        .evaluate(&action)
        .await;

    assert_eq!(approved.decision, Decision::Allow);
    assert!(approved.has_reason(ReasonCode::OperatorApproved));

    assert_eq!(denied.decision, Decision::Deny);
    assert!(denied.has_reason(ReasonCode::OperatorDenied));
}

/* ------------------------------------------------------------------ */
/* Provider independence                                              */
/* ------------------------------------------------------------------ */

/// The same logical action must reach the same verdict through every adapter.
#[tokio::test]
async fn every_provider_reaches_the_same_verdict() {
    let context = NormalizationContext::new();
    let blocked_path = "~/.ssh/id_rsa";
    let arguments = serde_json::json!({ "path": blocked_path });
    let cursor_payload = serde_json::json!({
        "hook_event_name": "beforeReadFile",
        "file_path": blocked_path,
    });

    let actions: Vec<(&str, AgentAction)> = vec![
        (
            "mcp",
            McpAdapter::decode(
                &context,
                McpToolsCall::stdio(r#"{"name":"read_file","arguments":{"path":"~/.ssh/id_rsa"}}"#),
            )
            .expect("mcp"),
        ),
        (
            "openai",
            OpenAiAdapter::decode(
                &context,
                OpenAiFunctionCall::new("read_file", &arguments).with_model(Some("gpt-4o")),
            )
            .expect("openai"),
        ),
        (
            "anthropic",
            AnthropicAdapter::decode(
                &context,
                AnthropicToolUse::new("read_file", &arguments).with_model(Some("claude-sonnet-4")),
            )
            .expect("anthropic"),
        ),
        (
            "cursor",
            CursorAdapter::decode(&context, CursorHookEvent::new(&cursor_payload)).expect("cursor"),
        ),
        (
            "generic",
            GenericAdapter::filesystem_operation(&context, "read_file", blocked_path)
                .expect("generic"),
        ),
    ];

    for (provider, action) in actions {
        let outcome = gateway(Arc::new(RecordingAuditSink::new()))
            .evaluate(&action)
            .await;

        assert_eq!(
            outcome.decision,
            Decision::Deny,
            "{provider} must be denied like every other provider"
        );
        assert!(
            outcome.has_reason(ReasonCode::PolicyGlobalBlockPattern),
            "{provider} must be attributed to the same rule"
        );
    }
}

/* ------------------------------------------------------------------ */
/* Local-only operation                                               */
/* ------------------------------------------------------------------ */

#[tokio::test]
async fn a_gateway_with_no_cloud_wiring_still_enforces() {
    let local = GatewayBuilder::default()
        .policy_engine(Some(policy()))
        .approval(Arc::new(DenyAllApprovalEngine))
        .audit(Arc::new(NullAuditSink))
        .build();

    assert!(local.is_local_only());
    assert!(!local.config().require_control_plane);

    let denied = local
        .evaluate(&mcp_action(
            r#"{"name":"read_file","arguments":{"path":"/etc/shadow"}}"#,
        ))
        .await;
    let allowed = local
        .evaluate(&mcp_action(
            r#"{"name":"read_file","arguments":{"path":"/tmp/ok"}}"#,
        ))
        .await;

    assert_eq!(denied.decision, Decision::Deny);
    assert_eq!(allowed.decision, Decision::Allow);
}

/// Cloud connectivity is opt-in, and opting in is what makes it mandatory.
#[tokio::test]
async fn requiring_the_control_plane_denies_when_it_is_absent() {
    let outcome = GatewayBuilder::default()
        .policy_engine(Some(policy()))
        .config(GatewayConfig {
            require_control_plane: true,
            ..GatewayConfig::default()
        })
        .build()
        .evaluate(&mcp_action(
            r#"{"name":"read_file","arguments":{"path":"/tmp/ok"}}"#,
        ))
        .await;

    assert_eq!(outcome.decision, Decision::Deny);
    assert!(outcome.has_reason(ReasonCode::CloudUnavailable));
    assert!(
        outcome.risk_score.is_none(),
        "the pipeline stops before scoring"
    );
}

/* ------------------------------------------------------------------ */
/* Fail-open / fail-closed                                            */
/* ------------------------------------------------------------------ */

#[tokio::test]
async fn an_absent_policy_fails_closed_by_default_and_open_only_in_development() {
    use mcp_proxy::gateway::{EnforcementPosture, PolicyAvailability};

    let benign = mcp_action(r#"{"name":"read_file","arguments":{"path":"/tmp/a"}}"#);

    let enforcing = GatewayBuilder::default()
        .approval(Arc::new(DenyAllApprovalEngine))
        .build()
        .evaluate(&benign)
        .await;

    let development = GatewayBuilder::default()
        .failure_policy(FailurePolicy::for_posture(EnforcementPosture::Development))
        .approval(Arc::new(DenyAllApprovalEngine))
        .build()
        .evaluate(&benign)
        .await;

    let managed = GatewayBuilder::default()
        .policy_availability(PolicyAvailability::RemoteUnavailable)
        .failure_policy(FailurePolicy::for_posture(EnforcementPosture::Managed))
        .approval(Arc::new(DenyAllApprovalEngine))
        .build()
        .evaluate(&benign)
        .await;

    assert_eq!(enforcing.decision, Decision::Deny);
    assert!(enforcing.has_reason(ReasonCode::PolicyUnavailable));
    assert_eq!(enforcing.policy_availability, PolicyAvailability::Missing);

    assert_eq!(
        development.decision,
        Decision::Allow,
        "development posture is the conscious permissive opt-in"
    );
    assert!(development.has_reason(ReasonCode::PolicyUnavailable));

    assert_eq!(managed.decision, Decision::Deny);
    assert_eq!(
        managed.policy_availability,
        PolicyAvailability::RemoteUnavailable
    );
}

#[tokio::test]
async fn an_audit_failure_cannot_change_a_verdict_by_default() {
    let outcome = GatewayBuilder::default()
        .policy_engine(Some(policy()))
        .audit(Arc::new(FailingAuditSink))
        .approval(Arc::new(AllowAllApprovalEngine))
        .build()
        .evaluate(&mcp_action(
            r#"{"name":"deploy_release","arguments":{"target":"prod"}}"#,
        ))
        .await;

    assert_eq!(
        outcome.decision,
        Decision::Allow,
        "telemetry availability must not gate a security decision"
    );
    assert!(
        outcome.has_reason(ReasonCode::AuditDeliveryFailed),
        "but the failure must be visible in the outcome"
    );
}

#[tokio::test]
async fn an_audit_failure_denies_when_the_deployment_requires_a_trail() {
    let outcome = GatewayBuilder::default()
        .policy_engine(Some(policy()))
        .audit(Arc::new(FailingAuditSink))
        .approval(Arc::new(AllowAllApprovalEngine))
        .failure_policy(FailurePolicy {
            missing_policy: mcp_proxy::gateway::FailureMode::FailOpen,
            ..FailurePolicy::strict()
        })
        .build()
        .evaluate(&mcp_action(
            r#"{"name":"deploy_release","arguments":{"target":"prod"}}"#,
        ))
        .await;

    assert_eq!(outcome.decision, Decision::Deny);
    assert!(outcome.has_reason(ReasonCode::AuditDeliveryFailed));
}

/// One broken sink must not silence the others.
#[tokio::test]
async fn a_composite_sink_records_everywhere_despite_one_failure() {
    let recorder = Arc::new(RecordingAuditSink::new());
    let outcome = GatewayBuilder::default()
        .policy_engine(Some(policy()))
        .audit(Arc::new(CompositeAuditSink::new(vec![
            Arc::new(FailingAuditSink),
            recorder.clone() as Arc<dyn AuditSink>,
        ])))
        .build()
        .evaluate(&mcp_action(
            r#"{"name":"drop_table","arguments":{"table":"users"}}"#,
        ))
        .await;

    assert_eq!(outcome.decision, Decision::Deny);
    assert_eq!(recorder.events().len(), 1);
}

/* ------------------------------------------------------------------ */
/* Identity enrichment                                                */
/* ------------------------------------------------------------------ */

#[tokio::test]
async fn enrichment_reaches_the_audit_record_without_touching_the_verdict() {
    let recorder = Arc::new(RecordingAuditSink::new());
    let ambient = NormalizationContext {
        user_id: Some("sre@example.com".to_string()),
        organization_id: Some("org_42".to_string()),
        ..NormalizationContext::new()
    };

    let outcome = GatewayBuilder::default()
        .identity(Arc::new(StaticIdentityResolver::new(ambient)))
        .policy_engine(Some(policy()))
        .audit(recorder.clone())
        .build()
        .evaluate(&mcp_action(
            r#"{"name":"drop_table","arguments":{"table":"users"}}"#,
        ))
        .await;

    assert_eq!(outcome.decision, Decision::Deny);

    let event = recorder
        .events()
        .into_iter()
        .next()
        .expect("a denial must be audited");
    assert_eq!(event.user_id.as_deref(), Some("sre@example.com"));
    assert_eq!(event.organization_id.as_deref(), Some("org_42"));
    assert_eq!(event.effective_agent_id, "local/anonymous");
    assert_eq!(event.agent_type, mcp_proxy::AgentType::UNKNOWN);
}

/* ------------------------------------------------------------------ */
/* Session behavior across the pipeline                               */
/* ------------------------------------------------------------------ */

/// The behavioral chain detector needs the pipeline to record actions as they pass.
#[tokio::test]
async fn a_filesystem_probe_chain_escalates_a_later_network_call() {
    let gateway = GatewayBuilder::default()
        .policy_engine(Some(policy()))
        .session(Arc::new(SessionTracker::default()))
        .approval(Arc::new(DenyAllApprovalEngine))
        .build();

    for path in ["/tmp/a", "/tmp/b", "/tmp/c"] {
        let outcome = gateway
            .evaluate(&mcp_action(&format!(
                r#"{{"name":"read_file","arguments":{{"path":"{path}"}}}}"#
            )))
            .await;
        assert_eq!(
            outcome.decision,
            Decision::Allow,
            "individual reads are benign"
        );
    }

    let exfil = gateway
        .evaluate(&mcp_action(
            r#"{"name":"fetch","arguments":{"url":"https://drop.example/upload"}}"#,
        ))
        .await;

    assert_eq!(exfil.decision, Decision::Deny);
    assert!(exfil.has_reason(ReasonCode::BehavioralChainAnomaly));
    assert_eq!(
        exfil.primary_detail(),
        Some("BEHAVIORAL_CHAIN_ANOMALY: operator denied exfiltration-risk tool chain"),
        "the marker the e2e suite greps for must be preserved"
    );
}

/* ------------------------------------------------------------------ */
/* Legacy facade parity                                               */
/* ------------------------------------------------------------------ */

/// `guard::evaluate_action` must keep producing the decisions the relays expect.
#[tokio::test]
async fn the_guard_facade_projects_the_same_outcomes() {
    use mcp_proxy::{evaluate_action, GuardContext, GuardDecision};

    let ctx = GuardContext {
        policy: Some(policy()),
        policy_availability: PolicyAvailability::Available,
        wasm: None,
        threat_intel: Arc::new(ThreatIntelMatcher::default()),
        session: Arc::new(SessionTracker::default()),
        cloud: None,
    };

    let allowed = evaluate_action(
        &ctx,
        &mcp_action(r#"{"name":"read_file","arguments":{"path":"/tmp/ok"}}"#),
    )
    .await
    .expect("evaluate");

    let blocked = evaluate_action(
        &ctx,
        &mcp_action(r#"{"name":"read_file","arguments":{"path":"~/.ssh/id_rsa"}}"#),
    )
    .await
    .expect("evaluate");

    assert!(matches!(allowed, GuardDecision::Allow { .. }));

    match blocked {
        GuardDecision::Block { reason, .. } => assert_eq!(
            reason, "global block pattern `\\.ssh/` matched tool `read_file`",
            "the JSON-RPC error message is part of the observable contract"
        ),
        other => panic!("expected a block, got {other:?}"),
    }
}

/// The relay derives its JSON-RPC error code from the typed reason rather than from the
/// reason text. These are the codes the pre-gateway string matching produced.
#[tokio::test]
async fn denials_map_onto_the_expected_jsonrpc_error_codes() {
    fn code_of(bytes: &[u8]) -> i64 {
        serde_json::from_slice::<serde_json::Value>(bytes).expect("valid json")["error"]["code"]
            .as_i64()
            .expect("numeric error code")
    }

    let request_id = serde_json::json!(7);
    let gateway = GatewayBuilder::default()
        .policy_engine(Some(policy()))
        .approval(Arc::new(DenyAllApprovalEngine))
        .build();

    let cases = [
        (
            r#"{"name":"read_file","arguments":{"path":"~/.ssh/id_rsa"}}"#,
            -32_000,
            "a policy rule prohibits the action",
        ),
        (
            r#"{"name":"drop_table","arguments":{"table":"users"}}"#,
            -32_000,
            "the tool is configured with action Block",
        ),
        (
            r#"{"name":"execute_bash","arguments":{"command":"whoami"}}"#,
            -32_003,
            "an operator refused this particular attempt",
        ),
    ];

    for (params, expected, why) in cases {
        let outcome = gateway.evaluate(&mcp_action(params)).await;
        assert_eq!(outcome.decision, Decision::Deny, "{why}");

        let reason = outcome.primary_detail().expect("a denial has a reason");
        let frame = if outcome.denied_by_rule() {
            mcp_proxy::policy::blocked_response(&request_id, reason)
        } else {
            mcp_proxy::policy::access_denied_response(&request_id, reason)
        };

        assert_eq!(code_of(&frame), expected, "{why}");
    }
}

#[tokio::test]
async fn the_guard_facade_exposes_the_full_outcome_too() {
    use mcp_proxy::guard::{evaluate_outcome, GuardContext};

    let ctx = GuardContext {
        policy: Some(policy()),
        policy_availability: PolicyAvailability::Available,
        wasm: None,
        threat_intel: Arc::new(ThreatIntelMatcher::default()),
        session: Arc::new(SessionTracker::default()),
        cloud: None,
    };

    let outcome = evaluate_outcome(
        &ctx,
        &mcp_action(r#"{"name":"drop_table","arguments":{"table":"users"}}"#),
    )
    .await;

    assert_eq!(outcome.decision, Decision::Deny);
    assert_eq!(outcome.policy_version.as_deref(), Some("2026.1"));
    assert!(!outcome.matched_policies.is_empty());
}
