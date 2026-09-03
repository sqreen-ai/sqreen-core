//! Policy engine tests — legacy compatibility, precedence, and audit mode.

use super::*;
use crate::action::{
    AgentAction, AgentType, Arguments, Environment, EnvironmentTier, Runtime, SourceRef,
};

const EXAMPLE_POLICY: &str = r#"
version: "1"
global:
  redact_keys: ["OPENAI_API_KEY", "STRIPE_SECRET_KEY", "AWS_SECRET_ACCESS_KEY"]
tools:
  - name: "execute_bash"
    action: "Confirm"
    block_patterns: ["rm -rf .*", "curl.*\\|sh", "chmod .*"]
  - name: "read_file"
    action: "Allow"
    block_patterns: ["\\.\\./\\.\\./", "~/.ssh/.*", "~/.aws/.*"]
"#;

const NORMALIZED_GUARDRAILS: &str = r#"
schema_version: "2026.3"
version: "enterprise-guardrails"
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
  - name: deny-secrets-external
    priority: 900
    effect: deny
    description: "Secrets must not be sent to external destinations"
    match:
      risk.credential_access: "true"
      risk.external_destination: "true"
  - name: approve-destructive-prod
    priority: 800
    effect: require_approval
    description: "Destructive production actions require approval"
    match:
      risk.destructive: "true"
      risk.production: "true"
  - name: deny-anonymous-prod
    priority: 950
    effect: deny
    description: "Unknown agents may not operate in production"
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
    description: "Engineering agents may only read designated workspace paths"
    match:
      labels.team: engineering
      action: read
      path_not_prefix: /workspaces/engineering/
  - name: confirm-credential-access
    priority: 700
    effect: require_approval
    description: "Privileged credential access requires approval"
    match:
      risk.credential_access: "true"
tools: []
"#;

fn read_ssh_action() -> AgentAction {
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

#[test]
fn parses_example_policy_yaml() {
    let config = PolicyConfig::from_yaml(EXAMPLE_POLICY).expect("policy should parse");
    assert_eq!(config.version, "1");
    assert_eq!(config.global.redact_keys.len(), 3);
    assert_eq!(config.tools.len(), 2);
}

#[test]
fn blocks_dangerous_bash_command() {
    let engine = PolicyEngine::from_yaml(EXAMPLE_POLICY).expect("compile policy");
    let params = r#"{"name":"execute_bash","arguments":{"command":"rm -rf /"}}"#;
    assert!(matches!(
        engine.evaluate_tools_call(params),
        PolicyVerdict::Block { .. }
    ));
}

#[test]
fn blocks_sensitive_file_reads() {
    let engine = PolicyEngine::from_yaml(EXAMPLE_POLICY).expect("compile policy");
    let params = r#"{"name":"read_file","arguments":{"path":"~/.ssh/id_rsa"}}"#;
    assert!(matches!(
        engine.evaluate_tools_call(params),
        PolicyVerdict::Block { .. }
    ));
}

#[test]
fn normalized_policy_denies_ssh_reads() {
    let engine = PolicyEngine::from_yaml(NORMALIZED_GUARDRAILS).expect("compile");
    let evaluation = engine.evaluate_detailed(&read_ssh_action());
    assert!(matches!(
        evaluation.enforced_verdict,
        PolicyVerdict::Block { .. }
    ));
    assert_eq!(evaluation.winning_rule.as_deref(), Some("deny-ssh-reads"));
}

#[test]
fn higher_priority_deny_beats_lower_allow() {
    let engine = PolicyEngine::from_yaml(NORMALIZED_GUARDRAILS).expect("compile");
    let mut action = AgentAction::builder(
        "read_file",
        Arguments::from_name_and_arguments(
            "read_file",
            &serde_json::json!({"path": "/etc/passwd"}),
        ),
    )
    .build_unvalidated();
    action
        .identity
        .labels
        .insert("team".to_string(), "engineering".to_string());

    assert!(matches!(
        engine.evaluate_action(&action),
        PolicyVerdict::Block { .. }
    ));
}

#[test]
fn deny_beats_require_approval_at_same_priority() {
    let policy = r#"
schema_version: "2026.3"
version: "conflict-test"
global:
  redact_keys: []
  block_patterns: []
rules:
  - name: deny-rule
    priority: 500
    effect: deny
    match:
      action: read
  - name: approve-rule
    priority: 500
    effect: require_approval
    match:
      action: read
tools: []
"#;
    let engine = PolicyEngine::from_yaml(policy).expect("compile");
    let evaluation = engine.evaluate_detailed(&read_ssh_action());
    assert!(matches!(
        evaluation.enforced_verdict,
        PolicyVerdict::Block { .. }
    ));
    assert_eq!(evaluation.matched_rules.len(), 2);
}

#[test]
fn audit_mode_records_would_deny_but_allows() {
    let yaml = NORMALIZED_GUARDRAILS.replace("mode: enforce", "mode: audit");
    let engine = PolicyEngine::from_yaml(&yaml).expect("compile");
    let evaluation = engine.evaluate_detailed(&read_ssh_action());
    assert!(matches!(
        evaluation.enforced_verdict,
        PolicyVerdict::Block { .. }
    ));
    assert_eq!(
        engine.evaluate_action(&read_ssh_action()),
        PolicyVerdict::Allow
    );
    assert!(evaluation.audit_explanation().is_some());
}

#[test]
fn validation_rejects_unknown_match_keys() {
    let policy = r#"
schema_version: "2026.3"
version: "bad"
global:
  redact_keys: []
  block_patterns: []
rules:
  - name: bad-rule
    effect: deny
    match:
      totally_unknown_field: "true"
tools: []
"#;
    assert!(PolicyEngine::from_yaml(policy).is_err());
}

#[test]
fn risk_score_threshold_rules_match_explainable_score() {
    use crate::scoring::{RiskScoreEngine, RiskScoreInput};

    let policy = r#"
schema_version: "2026.3"
version: "risk-threshold"
global:
  redact_keys: []
  block_patterns: []
rules:
  - name: high-risk-shell
    priority: 900
    effect: require_approval
    match:
      risk.score_at_least: "50"
      risk.factor: "policy_sensitive_operation"
  - name: critical-band
    priority: 800
    effect: deny
    match:
      risk.level_at_least: "CRITICAL"
tools: []
"#;
    let engine = PolicyEngine::from_yaml(policy).expect("compile");
    let mut shell = AgentAction::builder(
        "execute_bash",
        Arguments::from_name_and_arguments("execute_bash", &serde_json::json!({"command": "ls"})),
    )
    .build_unvalidated();
    shell.refresh_security_classification();

    let scored = RiskScoreEngine::default().score(&shell, RiskScoreInput::default());
    assert!(scored.score >= 50);

    let evaluation = engine.evaluate_detailed_with_context(&shell, None, Some(&scored));
    assert!(matches!(
        evaluation.enforced_verdict,
        PolicyVerdict::Confirm { .. }
    ));
    assert!(evaluation
        .matched_rules
        .iter()
        .any(|rule| rule.name == "high-risk-shell"));
}

#[test]
fn unreadable_payload_is_unevaluable_not_allowed() {
    use crate::guard::ToolInvocation;

    let engine = PolicyEngine::from_yaml(EXAMPLE_POLICY).expect("compile policy");
    let action = ToolInvocation {
        tool_name: "read_file".to_string(),
        params_json: "{ this is not json".to_string(),
    }
    .to_agent_action();

    assert!(matches!(
        engine.evaluate_action(&action),
        PolicyVerdict::Unevaluable { .. }
    ));
}
