//! Gateway-level policy precedence and audit-mode integration tests.

use std::sync::Arc;

use mcp_proxy::action::{AgentAction, Arguments, Runtime, SourceRef};
use mcp_proxy::gateway::{Decision, GatewayBuilder, ReasonCode, Stage};
use mcp_proxy::policy::PolicyEngine;

const GUARDRAILS: &str = r#"
schema_version: "2026.3"
version: "gateway-precedence"
mode: enforce
global:
  redact_keys: []
  block_patterns: []
rules:
  - name: deny-ssh-reads
    priority: 1000
    effect: deny
    description: "Agents must not read SSH private keys"
    match:
      action: read
      path_pattern: "(~|/Users/[^/]+)/\\.ssh/"
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
    description: "Engineering agents may only read designated workspace paths"
    match:
      labels.team: engineering
      action: read
      path_not_prefix: /workspaces/engineering/
tools: []
"#;

fn ssh_read_action() -> AgentAction {
    AgentAction::builder(
        "read_file",
        Arguments::from_name_and_arguments(
            "read_file",
            &serde_json::json!({"path": "/Users/alice/.ssh/id_rsa"}),
        ),
    )
    .source(SourceRef::new(Runtime::MCP_STDIO, "test"))
    .build_unvalidated()
}

fn engine(yaml: &str) -> Arc<PolicyEngine> {
    Arc::new(PolicyEngine::from_yaml(yaml).expect("compile policy"))
}

#[tokio::test]
async fn higher_priority_deny_wins_over_engineering_allow() {
    let mut action = ssh_read_action();
    action
        .identity
        .labels
        .insert("team".to_string(), "engineering".to_string());

    let outcome = GatewayBuilder::default()
        .policy_engine(Some(engine(GUARDRAILS)))
        .build()
        .evaluate(&action)
        .await;

    assert_eq!(outcome.decision, Decision::Deny);
    assert!(outcome.has_reason(ReasonCode::PolicyToolActionBlock));
    assert!(
        outcome
            .matched_policies
            .iter()
            .any(|policy| policy.rule_id.contains("deny-ssh-reads")),
        "audit trail must list every matched rule"
    );
}

#[tokio::test]
async fn audit_mode_simulates_deny_but_allows_through_policy() {
    let yaml = GUARDRAILS.replace("mode: enforce", "mode: audit");
    let outcome = GatewayBuilder::default()
        .policy_engine(Some(engine(&yaml)))
        // Credential-path reads still need risk approval; resolve it so this test
        // isolates the audit-mode policy behavior.
        .approval(Arc::new(mcp_proxy::gateway::AllowAllApprovalEngine))
        .build()
        .evaluate(&ssh_read_action())
        .await;

    assert_eq!(outcome.decision, Decision::Allow);
    assert!(outcome.has_reason(ReasonCode::PolicyAuditOnly));
    assert_eq!(
        outcome
            .reasons
            .iter()
            .find(|reason| reason.stage == Stage::Policy)
            .map(|reason| reason.code),
        Some(ReasonCode::PolicyAuditOnly)
    );
}
