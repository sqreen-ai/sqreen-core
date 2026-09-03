//! Trust-layer precedence: org/local policy cannot weaken the mandatory baseline.

use std::collections::BTreeMap;

use crate::action::{AgentAction, Arguments, Runtime, SourceRef};

use super::compile::{compile_layered, PolicyTrustLayer};
use super::compose::{compose_effective_policy, mandatory_security_baseline};
use super::evaluation::{evaluate_policy, PolicyVerdict};
use super::schema::{
    GlobalPolicy, PolicyAction, PolicyConfig, PolicyMode, PolicyRule, RuleEffect, ToolPolicy,
    SCHEMA_2026_3,
};
use super::signed::*;
use super::PolicyEngine;

fn empty_org(version: &str) -> PolicyConfig {
    PolicyConfig {
        version: version.into(),
        // Legacy schema allows tool/global-only documents; 2026.3 requires rules[].
        schema_version: super::schema::SCHEMA_LEGACY.into(),
        mode: PolicyMode::Enforce,
        rules: vec![],
        global: GlobalPolicy {
            redact_keys: vec![],
            risk_threshold: 100,
            block_patterns: vec![],
        },
        identity_rules: vec![],
        taxonomy_rules: vec![],
        tools: vec![],
    }
}

fn org_with_rules(version: &str, rules: Vec<PolicyRule>) -> PolicyConfig {
    let mut cfg = empty_org(version);
    cfg.schema_version = SCHEMA_2026_3.into();
    cfg.rules = rules;
    cfg
}

fn rule(
    name: &str,
    priority: i32,
    effect: RuleEffect,
    when: BTreeMap<String, String>,
) -> PolicyRule {
    PolicyRule {
        name: name.into(),
        priority,
        effect,
        description: Some(format!("{name} ({})", effect.as_str())),
        when,
        tools: vec![],
    }
}

fn credential_when() -> BTreeMap<String, String> {
    let mut m = BTreeMap::new();
    m.insert("resource.credential".into(), "true".into());
    m.insert("action.read".into(), "true".into());
    m
}

fn shell_when() -> BTreeMap<String, String> {
    let mut m = BTreeMap::new();
    m.insert("action.execute".into(), "true".into());
    m.insert("resource.filesystem".into(), "true".into());
    m
}

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

fn read_ssh_openai_action() -> AgentAction {
    AgentAction::builder(
        "Read",
        Arguments::from_name_and_arguments(
            "Read",
            &serde_json::json!({"path": "/Users/alice/.ssh/id_rsa"}),
        ),
    )
    .source(SourceRef::new(Runtime::MCP_STDIO, "test"))
    .build_unvalidated()
}

fn shell_action() -> AgentAction {
    AgentAction::builder(
        "execute_bash",
        Arguments::from_name_and_arguments("execute_bash", &serde_json::json!({"command": "ls"})),
    )
    .source(SourceRef::new(Runtime::MCP_STDIO, "test"))
    .build_unvalidated()
}

fn assert_block(eval: &super::PolicyEvaluation) {
    assert!(
        matches!(eval.enforced_verdict, PolicyVerdict::Block { .. }),
        "expected DENY, got {:?} — {}",
        eval.enforced_verdict,
        eval.explanation
    );
}

fn assert_confirm(eval: &super::PolicyEvaluation) {
    assert!(
        matches!(eval.enforced_verdict, PolicyVerdict::Confirm { .. }),
        "expected CONFIRM, got {:?} — {}",
        eval.enforced_verdict,
        eval.explanation
    );
}

fn assert_redact(eval: &super::PolicyEvaluation) {
    assert!(
        matches!(eval.enforced_verdict, PolicyVerdict::Redact { .. }),
        "expected REDACT, got {:?} — {}",
        eval.enforced_verdict,
        eval.explanation
    );
}

#[test]
fn org_allow_priority_10000_cannot_beat_mandatory_deny() {
    let org = org_with_rules(
        "hostile-10k",
        vec![rule(
            "allow_cred_read",
            10_000,
            RuleEffect::Allow,
            credential_when(),
        )],
    );
    let engine = PolicyEngine::from_layered(&org, None).unwrap();
    let eval = engine.evaluate_detailed(&read_ssh_action());
    assert_block(&eval);
    assert_eq!(
        eval.winning_trust_layer,
        Some(PolicyTrustLayer::MandatoryBaseline.as_str())
    );
    assert!(eval.explanation.contains("mandatory baseline"));
    assert!(!eval.shadowed_rules.is_empty());
}

#[test]
fn org_allow_priority_i32_max_cannot_beat_mandatory_deny() {
    let org = org_with_rules(
        "hostile-max",
        vec![rule(
            "allow_cred_read_max",
            i32::MAX,
            RuleEffect::Allow,
            credential_when(),
        )],
    );
    let engine = PolicyEngine::from_layered(&org, None).unwrap();
    let eval = engine.evaluate_detailed(&read_ssh_action());
    assert_block(&eval);
    assert_eq!(
        eval.winning_rule.as_deref(),
        Some("baseline.deny_credential_read")
    );
}

#[test]
fn same_name_org_allow_cannot_replace_mandatory_deny() {
    let org = org_with_rules(
        "same-name",
        vec![rule(
            "baseline.deny_credential_read",
            i32::MAX,
            RuleEffect::Allow,
            credential_when(),
        )],
    );
    let compiled = compile_layered(&org, None).unwrap();
    let mandatory = compiled
        .rules
        .iter()
        .filter(|r| r.name == "baseline.deny_credential_read")
        .count();
    assert!(
        mandatory >= 2,
        "same name must preserve both trust layers, got {mandatory}"
    );
    assert!(compiled.rules.iter().any(|r| {
        r.name == "baseline.deny_credential_read"
            && r.trust_layer == PolicyTrustLayer::MandatoryBaseline
            && r.effect == RuleEffect::Deny
    }));
    assert!(compiled.rules.iter().any(|r| {
        r.name == "baseline.deny_credential_read"
            && r.trust_layer == PolicyTrustLayer::Organization
            && r.effect == RuleEffect::Allow
    }));

    let eval = evaluate_policy(&compiled, &read_ssh_action());
    assert_block(&eval);
    assert_eq!(
        eval.winning_trust_layer,
        Some(PolicyTrustLayer::MandatoryBaseline.as_str())
    );
}

#[test]
fn org_confirm_cannot_weaken_mandatory_deny() {
    let org = org_with_rules(
        "confirm-vs-deny",
        vec![rule(
            "soft_cred",
            i32::MAX,
            RuleEffect::RequireApproval,
            credential_when(),
        )],
    );
    let eval = PolicyEngine::from_layered(&org, None)
        .unwrap()
        .evaluate_detailed(&read_ssh_action());
    assert_block(&eval);
}

#[test]
fn org_allow_cannot_weaken_mandatory_confirm() {
    let org = org_with_rules(
        "allow-vs-confirm",
        vec![rule(
            "allow_shell",
            i32::MAX,
            RuleEffect::Allow,
            shell_when(),
        )],
    );
    let eval = PolicyEngine::from_layered(&org, None)
        .unwrap()
        .evaluate_detailed(&shell_action());
    assert_confirm(&eval);
    assert_eq!(
        eval.winning_trust_layer,
        Some(PolicyTrustLayer::MandatoryBaseline.as_str())
    );
}

#[test]
fn org_cannot_remove_mandatory_redact_keys() {
    let mut org = empty_org("strip-redact");
    org.global.redact_keys.clear();
    let effective = compose_effective_policy(&org, None);
    let baseline_keys = mandatory_security_baseline().global.redact_keys;
    assert!(!baseline_keys.is_empty());
    for key in &baseline_keys {
        assert!(
            effective.global.redact_keys.iter().any(|k| k == key),
            "missing mandatory redact key {key}"
        );
    }
}

#[test]
fn org_cannot_remove_mandatory_redact_effect() {
    // Synthetic layers: mandatory REDACT + org ALLOW with extreme priority on a benign path.
    let mut org = empty_org("redact-effect");
    org.rules.push(rule(
        "org_allow_all",
        i32::MAX,
        RuleEffect::Allow,
        BTreeMap::new(),
    ));
    let mut compiled = compile_layered(&org, None).unwrap();
    compiled.rules.push(super::compile::CompiledRule {
        id: "mandatory_baseline.rules[synthetic_redact]".into(),
        name: "synthetic_redact".into(),
        priority: 1,
        order: 0,
        effect: RuleEffect::Redact,
        description: Some("mandatory redact".into()),
        tools: Default::default(),
        predicates: vec![],
        source: super::compile::RuleSource::Normalized,
        trust_layer: PolicyTrustLayer::MandatoryBaseline,
    });
    let benign = AgentAction::builder(
        "read_file",
        Arguments::from_name_and_arguments(
            "read_file",
            &serde_json::json!({"path": "/tmp/hello.txt"}),
        ),
    )
    .build_unvalidated();
    let eval = evaluate_policy(&compiled, &benign);
    assert_redact(&eval);
    assert_eq!(eval.winning_rule.as_deref(), Some("synthetic_redact"));
}

#[test]
fn org_cannot_lower_mandatory_risk_threshold() {
    let mut org = empty_org("raise-risk");
    org.global.risk_threshold = 99;
    let effective = compose_effective_policy(&org, None);
    assert!(effective.global.risk_threshold <= mandatory_security_baseline().global.risk_threshold);
}

#[test]
fn org_deny_can_tighten_mandatory_allow_surface() {
    // Benign read is not denied by baseline; org DENY must apply.
    let mut when = BTreeMap::new();
    when.insert("action.read".into(), "true".into());
    let org = org_with_rules(
        "tighten",
        vec![rule("org_deny_reads", 100, RuleEffect::Deny, when)],
    );
    let benign = AgentAction::builder(
        "read_file",
        Arguments::from_name_and_arguments(
            "read_file",
            &serde_json::json!({"path": "/tmp/hello.txt"}),
        ),
    )
    .build_unvalidated();
    let eval = PolicyEngine::from_layered(&org, None)
        .unwrap()
        .evaluate_detailed(&benign);
    assert_block(&eval);
    assert_eq!(
        eval.winning_trust_layer,
        Some(PolicyTrustLayer::Organization.as_str())
    );
}

#[test]
fn local_deny_can_tighten_org_allow() {
    let mut when = BTreeMap::new();
    when.insert("action.read".into(), "true".into());
    let org = org_with_rules(
        "org-allow",
        vec![rule(
            "org_allow_reads",
            500,
            RuleEffect::Allow,
            when.clone(),
        )],
    );
    let local = org_with_rules(
        "local-deny",
        vec![rule("local_deny_reads", 1, RuleEffect::Deny, when)],
    );
    let benign = AgentAction::builder(
        "read_file",
        Arguments::from_name_and_arguments(
            "read_file",
            &serde_json::json!({"path": "/tmp/hello.txt"}),
        ),
    )
    .build_unvalidated();
    let eval = PolicyEngine::from_layered(&org, Some(&local))
        .unwrap()
        .evaluate_detailed(&benign);
    assert_block(&eval);
    assert_eq!(
        eval.winning_trust_layer,
        Some(PolicyTrustLayer::Local.as_str())
    );
}

#[test]
fn local_allow_cannot_weaken_org_deny() {
    let mut when = BTreeMap::new();
    when.insert("action.read".into(), "true".into());
    let org = org_with_rules(
        "org-deny",
        vec![rule("org_deny_reads", 1, RuleEffect::Deny, when.clone())],
    );
    let local = org_with_rules(
        "local-allow",
        vec![rule("local_allow_reads", i32::MAX, RuleEffect::Allow, when)],
    );
    let benign = AgentAction::builder(
        "read_file",
        Arguments::from_name_and_arguments(
            "read_file",
            &serde_json::json!({"path": "/tmp/hello.txt"}),
        ),
    )
    .build_unvalidated();
    let eval = PolicyEngine::from_layered(&org, Some(&local))
        .unwrap()
        .evaluate_detailed(&benign);
    assert_block(&eval);
    assert_eq!(
        eval.winning_trust_layer,
        Some(PolicyTrustLayer::Organization.as_str())
    );
}

#[test]
fn signed_org_policy_cannot_weaken_baseline() {
    let _g = super::signed::test_env_lock();
    std::env::set_var(ORG_ID_ENV, "acme");
    std::env::set_var(ALLOW_TEST_KEYS_ENV, "1");

    let mut policy = empty_org("signed-hostile");
    policy.rules.push(rule(
        "allow_all_creds",
        i32::MAX,
        RuleEffect::Allow,
        credential_when(),
    ));
    policy.global.risk_threshold = 100;
    policy.global.block_patterns.clear();
    policy.tools = vec![ToolPolicy {
        name: "execute_bash".into(),
        action: PolicyAction::Allow,
        block_patterns: vec![],
    }];

    let seed =
        hex::decode("394adcbf0d487810a28a6dc00f348b09b5ac2bc064e0488949b24c3fff16e7c0").unwrap();
    let mut seed_arr = [0u8; 32];
    seed_arr.copy_from_slice(&seed);

    let env = SignedPolicyEnvelope {
        schema_version: ENVELOPE_SCHEMA_VERSION,
        key_id: TEST_POLICY_KEY_ID.into(),
        policy_id: "default".into(),
        organization_id: "acme".into(),
        revision: 42,
        issued_at: "2026-09-02T12:00:00Z".into(),
        not_before: "2026-09-02T12:00:00Z".into(),
        expires_at: None,
        previous_revision: None,
        policy_digest: String::new(),
        policy,
        signature: String::new(),
    };
    let env = sign_envelope_with_seed(env, &seed_arr).expect("sign");
    let act = activate_signed_policy(env, &PolicyAcceptanceState::default(), None).unwrap();
    let eval = act.engine.evaluate_detailed(&read_ssh_action());
    assert_block(&eval);
    assert_eq!(
        eval.winning_trust_layer,
        Some(PolicyTrustLayer::MandatoryBaseline.as_str())
    );
}

#[test]
fn within_layer_priority_still_matters() {
    let mut when = BTreeMap::new();
    when.insert("action.read".into(), "true".into());
    let org = org_with_rules(
        "within-layer",
        vec![
            rule("low_deny", 10, RuleEffect::Deny, when.clone()),
            rule("high_allow", 100, RuleEffect::Allow, when),
        ],
    );
    let benign = AgentAction::builder(
        "read_file",
        Arguments::from_name_and_arguments(
            "read_file",
            &serde_json::json!({"path": "/tmp/hello.txt"}),
        ),
    )
    .build_unvalidated();
    let eval = PolicyEngine::from_layered(&org, None)
        .unwrap()
        .evaluate_detailed(&benign);
    // Within organization, higher priority Allow wins; no mandatory match for /tmp.
    assert!(matches!(eval.enforced_verdict, PolicyVerdict::Allow));
    assert_eq!(eval.winning_rule.as_deref(), Some("high_allow"));
}

#[test]
fn same_priority_across_layers_uses_trust_semantics() {
    let org = org_with_rules(
        "same-pri",
        vec![rule(
            "org_allow_cred",
            9000,
            RuleEffect::Allow,
            credential_when(),
        )],
    );
    let eval = PolicyEngine::from_layered(&org, None)
        .unwrap()
        .evaluate_detailed(&read_ssh_action());
    assert_block(&eval);
    assert_eq!(
        eval.winning_trust_layer,
        Some(PolicyTrustLayer::MandatoryBaseline.as_str())
    );
}

#[test]
fn negative_org_priority_cannot_escape_layer() {
    let org = org_with_rules(
        "neg",
        vec![rule(
            "allow_neg",
            i32::MIN,
            RuleEffect::Allow,
            credential_when(),
        )],
    );
    let eval = PolicyEngine::from_layered(&org, None)
        .unwrap()
        .evaluate_detailed(&read_ssh_action());
    assert_block(&eval);
}

#[test]
fn cross_provider_equivalent_actions_same_decision() {
    let org = org_with_rules(
        "xprov",
        vec![rule(
            "allow_creds",
            i32::MAX,
            RuleEffect::Allow,
            credential_when(),
        )],
    );
    let engine = PolicyEngine::from_layered(&org, None).unwrap();
    let a = engine.evaluate_detailed(&read_ssh_action());
    let b = engine.evaluate_detailed(&read_ssh_openai_action());
    assert_block(&a);
    assert_block(&b);
    assert_eq!(a.winning_trust_layer, b.winning_trust_layer);
}

#[test]
fn decision_explanation_identifies_mandatory_winner() {
    let org = org_with_rules(
        "explain",
        vec![rule(
            "allow_shell",
            i32::MAX,
            RuleEffect::Allow,
            shell_when(),
        )],
    );
    let eval = PolicyEngine::from_layered(&org, None)
        .unwrap()
        .evaluate_detailed(&shell_action());
    assert_confirm(&eval);
    assert!(eval.explanation.contains("mandatory baseline"));
    assert!(eval
        .shadowed_rules
        .iter()
        .any(|s| s.contains("allow_shell") || s.contains("organization")));
}

#[test]
fn org_stricter_risk_threshold_accepted() {
    let mut org = empty_org("strict-risk");
    org.global.risk_threshold = 10;
    let effective = compose_effective_policy(&org, None);
    assert_eq!(effective.global.risk_threshold, 10);
}

#[test]
fn compiled_rules_carry_trust_layer_provenance() {
    let org = empty_org("prov");
    let compiled = compile_layered(&org, None).unwrap();
    assert!(compiled
        .rules
        .iter()
        .any(|r| r.trust_layer == PolicyTrustLayer::MandatoryBaseline));
    assert!(compiled.rules.iter().any(|r| {
        r.name.starts_with("baseline.") && r.trust_layer == PolicyTrustLayer::MandatoryBaseline
    }));
}
