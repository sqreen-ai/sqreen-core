//! Execution identity trust: labels vs Bound agents, privilege invariant, approvals.

use mcp_proxy::action::{Arguments, Runtime, SourceRef};
use mcp_proxy::gateway::approval::{ActionBinding, ApprovalGrantStore, DEFAULT_ONCE_TTL};
use mcp_proxy::identity::{AgentId, IdentityTrust};
use mcp_proxy::policy::{compile_config, evaluate_policy, PolicyConfig, PolicyVerdict};
use mcp_proxy::AgentAction;

fn mcp(params: &str) -> AgentAction {
    AgentAction::builder(
        "read_file",
        Arguments::from_name_and_arguments(
            "read_file",
            &serde_json::from_str(params).expect("json"),
        ),
    )
    .source(SourceRef::new(Runtime::MCP_STDIO, "test"))
    .build_unvalidated()
}

#[test]
fn env_agent_id_is_self_asserted_label() {
    let mut action = mcp(r#"{"path":"/tmp/a"}"#);
    action
        .identity
        .set_self_asserted_agent("production-agent", "env:SQREEN_AGENT_ID");
    assert_eq!(action.identity.agent_trust, IdentityTrust::SelfAsserted);
    assert!(!action.identity.agent_trust.can_grant_privilege());
    assert!(action.identity.agent_bound_id.is_none());
}

#[test]
fn adapters_cannot_upgrade_to_bound_via_merge() {
    let mut left = mcp(r#"{"path":"/tmp/a"}"#).identity;
    let mut ambient = mcp(r#"{"path":"/tmp/a"}"#).identity;
    ambient.agent_id = Some(AgentId::new("spoof"));
    ambient.agent_trust = IdentityTrust::Bound; // hostile / buggy ambient
    ambient.agent_bound_id = Some(AgentId::new("ragt_x"));
    left.merge_from(&ambient);
    assert_eq!(left.agent_id.as_ref().unwrap().as_str(), "spoof");
    assert_eq!(left.agent_trust, IdentityTrust::SelfAsserted);
    assert!(left.agent_bound_id.is_none());
}

#[test]
fn self_asserted_agent_cannot_grant_allow_via_identity_rule() {
    let yaml = r#"
version: "1"
global:
  redact_keys: []
  risk_threshold: 100
identity_rules:
  - name: allow-finance
    when:
      agent_id: finance-agent
    action: Allow
tools: []
"#;
    let config: PolicyConfig = serde_yaml::from_str(yaml).expect("yaml");
    let policy = compile_config(config).expect("compile");

    let mut action = mcp(r#"{"path":"/tmp/a"}"#);
    action
        .identity
        .set_self_asserted_agent("finance-agent", "env:SQREEN_AGENT_ID");
    let eval = evaluate_policy(&policy, &action);
    // Privilege-sensitive Allow must not fire for SelfAsserted.
    assert!(
        matches!(eval.enforced_verdict, PolicyVerdict::Allow),
        "default allow when rule is gated"
    );
    assert!(
        !eval
            .matched_rules
            .iter()
            .any(|r| r.name == "allow-finance"),
        "self-asserted allow must not match: {:?}",
        eval.matched_rules
    );
}

#[test]
fn bound_agent_can_match_allow_identity_rule() {
    let yaml = r#"
version: "1"
global:
  redact_keys: []
  risk_threshold: 100
identity_rules:
  - name: allow-finance
    when:
      agent_id: finance-agent
    action: Allow
tools: []
"#;
    let config: PolicyConfig = serde_yaml::from_str(yaml).expect("yaml");
    let policy = compile_config(config).expect("compile");

    let mut action = mcp(r#"{"path":"/tmp/a"}"#);
    action
        .identity
        .set_bound_agent("ragt_finance", Some("finance-agent".into()), "binding:device");
    let eval = evaluate_policy(&policy, &action);
    assert!(eval
        .matched_rules
        .iter()
        .any(|r| r.name == "allow-finance"));
}

#[test]
fn self_asserted_can_still_deny() {
    let yaml = r#"
version: "1"
global:
  redact_keys: []
  risk_threshold: 100
identity_rules:
  - name: deny-finance
    when:
      agent_id: finance-agent
    action: Block
tools: []
"#;
    let config: PolicyConfig = serde_yaml::from_str(yaml).expect("yaml");
    let policy = compile_config(config).expect("compile");

    let mut action = mcp(r#"{"path":"/tmp/a"}"#);
    action
        .identity
        .set_self_asserted_agent("finance-agent", "adapter:openai");
    let eval = evaluate_policy(&policy, &action);
    assert!(matches!(
        eval.enforced_verdict,
        PolicyVerdict::Block { .. }
    ));
}

#[test]
fn approval_binding_includes_device_and_rejects_spoofed_label_replay() {
    let store = ApprovalGrantStore::new();
    let mut original = mcp(r#"{"path":"/tmp/a"}"#);
    original.identity.device_id = Some(mcp_proxy::DeviceId::new("dev_aaa"));
    original
        .identity
        .set_bound_agent("ragt_1", Some("finance-agent".into()), "binding:device");
    original.execution.session_id = Some(mcp_proxy::SessionId::new("sess-1"));
    original.refresh_security_classification();

    let grant = store.issue_once(
        "req-1",
        ActionBinding::from_action(&original),
        DEFAULT_ONCE_TTL,
    );

    let mut spoofed = mcp(r#"{"path":"/tmp/a"}"#);
    spoofed.identity.device_id = Some(mcp_proxy::DeviceId::new("dev_bbb"));
    spoofed
        .identity
        .set_self_asserted_agent("finance-agent", "env:SQREEN_AGENT_ID");
    spoofed.execution.session_id = Some(mcp_proxy::SessionId::new("sess-1"));
    spoofed.refresh_security_classification();

    assert!(
        store.redeem(&grant.token, &spoofed).is_err(),
        "spoofed label on another device must not redeem approval"
    );
    assert!(store.redeem(&grant.token, &original).is_ok());
}

#[test]
fn policy_can_match_agent_bound_id_and_trust() {
    let yaml = r#"
version: "1"
schema_version: "2026.3"
global:
  redact_keys: []
  risk_threshold: 100
rules:
  - name: bound-only
    effect: allow
    match:
      agent.bound_id: ragt_finance
      agent.trust: bound
tools: []
"#;
    let config: PolicyConfig = serde_yaml::from_str(yaml).expect("yaml");
    let policy = compile_config(config).expect("compile");

    let mut unbound = mcp(r#"{"path":"/tmp/a"}"#);
    unbound
        .identity
        .set_self_asserted_agent("finance-agent", "env");
    let eval = evaluate_policy(&policy, &unbound);
    assert!(!eval.matched_rules.iter().any(|r| r.name == "bound-only"));

    let mut bound = mcp(r#"{"path":"/tmp/a"}"#);
    bound
        .identity
        .set_bound_agent("ragt_finance", Some("finance-agent".into()), "binding");
    let eval = evaluate_policy(&policy, &bound);
    assert!(eval.matched_rules.iter().any(|r| r.name == "bound-only"));
}

#[test]
fn openai_anthropic_mcp_cursor_claims_stay_self_asserted() {
    for source in ["openai", "anthropic", "mcp", "cursor"] {
        let mut action = mcp(r#"{"path":"/tmp/a"}"#);
        action
            .identity
            .set_self_asserted_agent(format!("{source}-agent"), format!("adapter:{source}"));
        assert_eq!(action.identity.agent_trust, IdentityTrust::SelfAsserted);
        assert!(!action.identity.agent_trust.can_grant_privilege());
    }
}
