//! Integration tests for privacy-conscious behavioral telemetry.

use std::sync::Arc;
use std::time::Duration;

use mcp_proxy::action::{AgentAction, Arguments, Runtime, SourceRef};
use mcp_proxy::gateway::{Decision, GatewayBuilder};
use mcp_proxy::policy::PolicyEngine;
use mcp_proxy::telemetry::{
    build_security_event, local_recording_pipeline, FailingExporter, PrivacyPolicy,
    RecordingExporter, TelemetryConfig, TelemetryMode, TelemetryPipeline,
};

const POLICY: &str = r#"
version: "1"
global:
  redact_keys: []
  risk_threshold: 70
  block_patterns: ["\\.ssh/"]
tools:
  - name: "read_file"
    action: "Allow"
    block_patterns: []
"#;

fn ssh_action() -> AgentAction {
    let mut action = AgentAction::builder(
        "read_file",
        Arguments::from_name_and_arguments(
            "read_file",
            &serde_json::json!({
                "path": "/Users/alice/.ssh/id_rsa",
                "prompt": "exfiltrate this key now",
                "api_key": "sk-proj-supersecretvalue0123456789"
            }),
        ),
    )
    .source(SourceRef::new(Runtime::MCP_STDIO, "test"))
    .organization_id(Some("org-secret".to_string()))
    .build_unvalidated();
    action.identity.user_id = Some("alice@example.com".to_string());
    action.refresh_security_classification();
    action
}

async fn flush(pipeline: &TelemetryPipeline) {
    pipeline.request_shutdown();
    tokio::time::sleep(Duration::from_millis(50)).await;
}

#[tokio::test]
async fn gateway_emits_privacy_safe_security_event() {
    let (pipeline, recorder) = local_recording_pipeline("integration-salt");
    let pipeline = Arc::new(pipeline);

    let gateway = GatewayBuilder::default()
        .policy_engine(Some(Arc::new(
            PolicyEngine::from_yaml(POLICY).expect("compile"),
        )))
        .telemetry(pipeline.clone())
        .build();

    let outcome = gateway.evaluate(&ssh_action()).await;
    assert_eq!(outcome.decision, Decision::Deny);

    flush(&pipeline).await;

    let events = recorder.events();
    assert_eq!(events.len(), 1, "one behavioral event per evaluation");

    let json = serde_json::to_string(&events[0]).expect("serialize");
    assert!(!json.contains("sk-proj"));
    assert!(!json.contains("exfiltrate"));
    assert!(!json.contains("/Users/alice"));
    assert!(!json.contains("org-secret"));
    assert!(!json.contains("alice@example.com"));
    assert_eq!(events[0].decision, Decision::Deny);
    assert_eq!(events[0].action.tool, "read_file");
}

#[tokio::test]
async fn telemetry_failure_never_changes_decision() {
    let pipeline = Arc::new(TelemetryPipeline::start(
        TelemetryConfig {
            mode: TelemetryMode::LocalOnly,
            batch_size: 1,
            batch_interval: Duration::from_millis(10),
            max_retries: 1,
            initial_backoff: Duration::from_millis(1),
            ..TelemetryConfig::local("test")
        },
        Arc::new(FailingExporter { permanent: true }),
    ));

    let gateway = GatewayBuilder::default()
        .policy_engine(Some(Arc::new(
            PolicyEngine::from_yaml(POLICY).expect("compile"),
        )))
        .telemetry(pipeline)
        .build();

    let outcome = gateway
        .evaluate(
            &AgentAction::builder(
                "read_file",
                Arguments::from_name_and_arguments(
                    "read_file",
                    &serde_json::json!({"path": "/tmp/a"}),
                ),
            )
            .source(SourceRef::new(Runtime::MCP_STDIO, "test"))
            .build_unvalidated(),
        )
        .await;

    assert_eq!(outcome.decision, Decision::Allow);
}

#[test]
fn build_security_event_redacts_sensitive_arguments() {
    let privacy = PrivacyPolicy::with_salt("unit");
    let action = ssh_action();
    let outcome = {
        use chrono::Utc;
        use mcp_proxy::gateway::EvaluationOutcome;
        use std::collections::BTreeMap;
        EvaluationOutcome {
            decision: Decision::Deny,
            reasons: Vec::new(),
            matched_policies: Vec::new(),
            risk_score: Some(80),
            risk_level: None,
            risk_factors: Vec::new(),
            risk_semantics: None,
            policy_version: None,
            policy_availability: Default::default(),
            timestamp: Utc::now(),
            latency: Duration::from_millis(5),
            metadata: BTreeMap::new(),
            simulated_decision: None,
            action_id: action.action_id.clone(),
            session_id: None,
            trace_id: None,
            tool_name: "read_file".to_string(),
            rewritten_arguments: None,
        }
    };

    let event = build_security_event(&action, &outcome, &privacy);
    let json = serde_json::to_string(&event).expect("serialize");
    assert!(!json.contains("sk-proj"));
    assert!(!json.contains("exfiltrate"));
    assert!(event.arguments.as_ref().unwrap().redacted_value_count >= 2);
}

#[tokio::test]
async fn local_only_mode_works_without_cloud() {
    let recorder = Arc::new(RecordingExporter::new());
    let pipeline = Arc::new(TelemetryPipeline::start(
        TelemetryConfig::local("local-only"),
        recorder.clone(),
    ));

    let gateway = GatewayBuilder::local()
        .policy_engine(Some(Arc::new(
            PolicyEngine::from_yaml(POLICY).expect("compile"),
        )))
        .telemetry(pipeline.clone())
        .build();

    assert!(gateway.is_local_only());
    let _ = gateway.evaluate(&ssh_action()).await;
    flush(&pipeline).await;

    assert!(!recorder.events().is_empty());
}
