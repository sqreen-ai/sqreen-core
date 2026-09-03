//! Integration tests for the typed agent identity foundation.

use std::sync::Arc;

use mcp_proxy::action::{Environment, EnvironmentTier, Operation};
use mcp_proxy::adapters::{McpAdapter, McpToolsCall, NormalizationContext, ToolCallAdapter};
use mcp_proxy::gateway::{Decision, GatewayBuilder, RecordingAuditSink, StaticIdentityResolver};
use mcp_proxy::identity::{AuthContext, LOCAL_ANONYMOUS_AGENT_ID};
use mcp_proxy::policy::PolicyEngine;
use mcp_proxy::{AgentAction, AgentType};

fn mcp_action(params_json: &str) -> AgentAction {
    McpAdapter::decode(
        &NormalizationContext::new(),
        McpToolsCall::stdio(params_json),
    )
    .expect("decode mcp tools/call")
}

const IDENTITY_POLICY: &str = r#"
version: "2026.2"
global:
  redact_keys: []
  block_patterns: []
identity_rules:
  - name: deny-coding-agents-in-prod
    when:
      agent_type: coding-agent
      environment: production
    action: Block
tools:
  - name: "read_file"
    action: "Allow"
    block_patterns: []
"#;

#[tokio::test]
async fn identity_enrichment_runs_before_policy_and_is_persisted_in_audit() {
    let recorder = Arc::new(RecordingAuditSink::new());
    let ambient = NormalizationContext {
        agent_id: Some("deployment-agent".to_string()),
        agent_type: AgentType::CODING_AGENT,
        user_id: Some("alice@example.com".to_string()),
        organization_id: Some("org_99".to_string()),
        environment: Environment {
            tier: EnvironmentTier::Production,
            ..Default::default()
        },
        ..NormalizationContext::new()
    };

    let outcome = GatewayBuilder::default()
        .identity(Arc::new(StaticIdentityResolver::new(ambient)))
        .policy_engine(Some(Arc::new(
            PolicyEngine::from_yaml(IDENTITY_POLICY).expect("compile policy"),
        )))
        .audit(recorder.clone())
        .build()
        .evaluate(&mcp_action(
            r#"{"name":"read_file","arguments":{"path":"/tmp/a"}}"#,
        ))
        .await;

    assert_eq!(outcome.decision, Decision::Deny);

    let event = recorder.events().into_iter().next().expect("audit event");
    assert_eq!(event.effective_agent_id, "deployment-agent");
    assert_eq!(event.agent_type, AgentType::CODING_AGENT);
    assert_eq!(event.environment_tier, EnvironmentTier::Production);
    assert_eq!(event.identity.user_id.as_deref(), Some("alice@example.com"));
}

#[tokio::test]
async fn anonymous_local_agents_receive_a_stable_effective_id() {
    let action = mcp_action(r#"{"name":"read_file","arguments":{"path":"/tmp/a"}}"#);

    assert!(action.identity.is_anonymous());
    assert_eq!(
        action.identity.effective_agent_id(),
        LOCAL_ANONYMOUS_AGENT_ID
    );
    assert!(matches!(action.identity.auth, AuthContext::Anonymous));
}

#[test]
fn model_execution_is_separate_from_agent_identity() {
    let action = mcp_action(r#"{"name":"read_file","arguments":{"path":"/tmp/a"}}"#);
    assert!(action.identity.agent_id.is_none());
    assert!(action.model.name.is_none());
}

#[tokio::test]
async fn identity_rules_gate_on_operation_without_touching_payload_rules() {
    let policy = r#"
version: "2026.2"
global:
  redact_keys: []
  block_patterns: []
identity_rules:
  - name: deployment-agent-deletes
    when:
      agent_id: deployment-agent
      operation: delete
    action: Block
tools: []
"#;

    let mut action = mcp_action(r#"{"name":"delete_release","arguments":{"target":"prod"}}"#);
    action.identity.agent_id = Some(mcp_proxy::AgentId::new("deployment-agent"));
    action.operation = Operation::Delete;

    let outcome = GatewayBuilder::default()
        .policy_engine(Some(Arc::new(
            PolicyEngine::from_yaml(policy).expect("compile policy"),
        )))
        .build()
        .evaluate(&action)
        .await;

    assert_eq!(outcome.decision, Decision::Deny);
}
