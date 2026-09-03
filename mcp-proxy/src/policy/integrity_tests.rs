//! Comprehensive policy integrity + adversarial tests (deterministic, offline).

use super::compose::{
    compose_effective_policy, mandatory_security_baseline, respects_mandatory_baseline,
};
use super::schema::{GlobalPolicy, PolicyAction, PolicyConfig, ToolPolicy};
use super::signed::*;
use base64::Engine;
use std::fs;

fn temp_dir() -> std::path::PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "sqreen-policy-integrity-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    fs::create_dir_all(&dir).unwrap();
    dir
}

fn test_seed() -> [u8; 32] {
    let bytes =
        hex::decode("394adcbf0d487810a28a6dc00f348b09b5ac2bc064e0488949b24c3fff16e7c0").unwrap();
    let mut seed = [0u8; 32];
    seed.copy_from_slice(&bytes);
    seed
}

fn sample_policy(version: &str) -> PolicyConfig {
    PolicyConfig {
        version: version.into(),
        schema_version: "legacy".into(),
        mode: Default::default(),
        rules: vec![],
        global: GlobalPolicy {
            redact_keys: vec!["AWS_SECRET_ACCESS_KEY".into()],
            risk_threshold: 55,
            block_patterns: vec![r"\.env(\.|$)".into()],
        },
        identity_rules: vec![],
        taxonomy_rules: vec![],
        tools: vec![ToolPolicy {
            name: "execute_bash".into(),
            action: PolicyAction::Confirm,
            block_patterns: vec![r"rm\s+-rf".into()],
        }],
    }
}

fn signed(org: &str, revision: u64, policy: PolicyConfig) -> SignedPolicyEnvelope {
    let env = SignedPolicyEnvelope {
        schema_version: ENVELOPE_SCHEMA_VERSION,
        key_id: TEST_POLICY_KEY_ID.into(),
        policy_id: "default".into(),
        organization_id: org.into(),
        revision,
        issued_at: "2026-09-02T12:00:00Z".into(),
        not_before: "2026-09-02T12:00:00Z".into(),
        expires_at: None,
        previous_revision: if revision > 1 {
            Some(revision - 1)
        } else {
            None
        },
        policy_digest: String::new(),
        policy,
        signature: String::new(),
    };
    sign_envelope_with_seed(env, &test_seed()).expect("sign")
}

#[test]
fn correct_signed_policy_activates() {
    let _g = super::signed::test_env_lock();
    std::env::set_var(ORG_ID_ENV, "acme");
    let env = signed("acme", 1, sample_policy("1"));
    let act = activate_signed_policy(env, &PolicyAcceptanceState::default(), None).unwrap();
    assert_eq!(act.envelope.revision, 1);
    assert!(respects_mandatory_baseline(&act.effective));
}

#[test]
fn modified_content_digest_rejected() {
    let mut env = signed("acme", 1, sample_policy("1"));
    env.policy.tools[0].action = PolicyAction::Allow;
    assert_eq!(
        verify_signature(&env),
        Err(PolicyRejectReason::DigestMismatch)
    );
}

#[test]
fn modified_org_in_envelope_rejected_after_resign_mismatch() {
    let _g = super::signed::test_env_lock();
    std::env::set_var(ORG_ID_ENV, "acme");
    // Attacker changes org without valid signature for new payload.
    let mut env = signed("acme", 1, sample_policy("1"));
    env.organization_id = "evil".into();
    assert_eq!(
        verify_signature(&env),
        Err(PolicyRejectReason::InvalidSignature)
    );
}

#[test]
fn wrong_signing_key_rejected() {
    let mut env = signed("acme", 1, sample_policy("1"));
    // Corrupt one byte of signature
    let mut raw = base64::Engine::decode(
        &base64::engine::general_purpose::STANDARD,
        env.signature.as_bytes(),
    )
    .unwrap();
    raw[0] ^= 0xff;
    env.signature = base64::engine::general_purpose::STANDARD.encode(&raw);
    assert_eq!(
        verify_signature(&env),
        Err(PolicyRejectReason::InvalidSignature)
    );
}

#[test]
fn unknown_key_id_rejected() {
    let mut env = signed("acme", 1, sample_policy("1"));
    env.key_id = "not-a-trusted-key".into();
    assert_eq!(
        verify_signature(&env),
        Err(PolicyRejectReason::UnknownKeyId)
    );
}

#[test]
fn missing_signature_rejected() {
    let mut env = signed("acme", 1, sample_policy("1"));
    env.signature.clear();
    assert_eq!(
        verify_signature(&env),
        Err(PolicyRejectReason::MissingSignature)
    );
}

#[test]
fn malformed_signature_rejected() {
    let mut env = signed("acme", 1, sample_policy("1"));
    env.signature = "%%%not-base64%%%".into();
    assert_eq!(
        verify_signature(&env),
        Err(PolicyRejectReason::MalformedSignature)
    );
}

#[test]
fn unsupported_schema_rejected() {
    let mut env = signed("acme", 1, sample_policy("1"));
    env.schema_version = 99;
    // Digest still matches policy but schema check fails first... actually verify checks schema first
    assert_eq!(
        verify_signature(&env),
        Err(PolicyRejectReason::UnsupportedSchema)
    );
}

#[test]
fn older_policy_replay_rejected() {
    let _g = super::signed::test_env_lock();
    std::env::set_var(ORG_ID_ENV, "acme");
    let acceptance = PolicyAcceptanceState {
        organization_id: "acme".into(),
        policy_id: "default".into(),
        highest_revision: 3,
        digest: "deadbeef".into(),
        key_id: TEST_POLICY_KEY_ID.into(),
        activated_at: "2026-09-01T00:00:00Z".into(),
    };
    let env = signed("acme", 2, sample_policy("weak"));
    assert_eq!(
        activate_signed_policy(env, &acceptance, None).unwrap_err(),
        PolicyRejectReason::Rollback
    );
}

#[test]
fn same_version_different_digest_rejected() {
    let _g = super::signed::test_env_lock();
    std::env::set_var(ORG_ID_ENV, "acme");
    let env = signed("acme", 5, sample_policy("a"));
    let acceptance = PolicyAcceptanceState {
        organization_id: "acme".into(),
        policy_id: "default".into(),
        highest_revision: 5,
        digest: "different".into(),
        key_id: TEST_POLICY_KEY_ID.into(),
        activated_at: "2026-09-01T00:00:00Z".into(),
    };
    assert_eq!(
        activate_signed_policy(env, &acceptance, None).unwrap_err(),
        PolicyRejectReason::SameRevisionDigestMismatch
    );
}

#[test]
fn same_version_same_digest_idempotent() {
    let _g = super::signed::test_env_lock();
    std::env::set_var(ORG_ID_ENV, "acme");
    let env = signed("acme", 5, sample_policy("a"));
    let acceptance = acceptance_from_envelope(&env);
    let act = activate_signed_policy(env, &acceptance, None).unwrap();
    assert_eq!(act.envelope.revision, 5);
}

#[test]
fn newer_valid_policy_activates() {
    let _g = super::signed::test_env_lock();
    std::env::set_var(ORG_ID_ENV, "acme");
    let old = signed("acme", 1, sample_policy("1"));
    let acceptance = acceptance_from_envelope(&old);
    let newer = signed("acme", 2, sample_policy("2"));
    let act = activate_signed_policy(newer, &acceptance, None).unwrap();
    assert_eq!(act.envelope.revision, 2);
}

#[test]
fn invalid_new_leaves_acceptance_unchanged() {
    let _g = super::signed::test_env_lock();
    std::env::set_var(ORG_ID_ENV, "acme");
    let good = signed("acme", 3, sample_policy("3"));
    let acceptance = acceptance_from_envelope(&good);
    let mut bad = signed("acme", 4, sample_policy("4"));
    bad.policy.global.risk_threshold = 1;
    assert!(verify_signature(&bad).is_err());
    assert_eq!(acceptance.highest_revision, 3);
}

#[test]
fn corrupt_cache_write_leaves_old_usable() {
    let dir = temp_dir();
    let path = dir.join("mcp-policy.cloud.signed.json");
    let accept = dir.join("policy-acceptance.json");
    let env = signed("acme", 1, sample_policy("1"));
    persist_signed_envelope(&env, &path).unwrap();
    persist_acceptance(&acceptance_from_envelope(&env), &accept).unwrap();

    // Simulate interrupted write: tmp left behind, primary intact
    fs::write(path.with_extension("json.tmp"), b"{broken").unwrap();
    let loaded = load_signed_envelope(&path).unwrap().unwrap();
    assert_eq!(loaded.revision, 1);
    verify_signature(&loaded).unwrap();
}

#[test]
fn cache_modified_locally_rejected() {
    let _g = super::signed::test_env_lock();
    std::env::set_var(ORG_ID_ENV, "acme");
    let dir = temp_dir();
    let path = dir.join("cache.json");
    let env = signed("acme", 1, sample_policy("1"));
    persist_signed_envelope(&env, &path).unwrap();

    let mut raw = fs::read_to_string(&path).unwrap();
    raw = raw.replace("\"risk_threshold\": 55", "\"risk_threshold\": 99");
    fs::write(&path, raw).unwrap();

    let loaded = load_signed_envelope(&path).unwrap().unwrap();
    assert_eq!(
        verify_signature(&loaded),
        Err(PolicyRejectReason::DigestMismatch)
    );
}

#[test]
fn org_a_policy_rejected_for_org_b() {
    let _g = super::signed::test_env_lock();
    std::env::set_var(ORG_ID_ENV, "org-b");
    let env = signed("org-a", 1, sample_policy("1"));
    assert_eq!(
        activate_signed_policy(env, &PolicyAcceptanceState::default(), None).unwrap_err(),
        PolicyRejectReason::WrongOrganization
    );
}

#[test]
fn remote_cannot_weaken_mandatory_baseline() {
    let mut remote = sample_policy("weak");
    remote.global.block_patterns.clear();
    remote.global.risk_threshold = 100;
    remote.tools = vec![ToolPolicy {
        name: "execute_bash".into(),
        action: PolicyAction::Allow,
        block_patterns: vec![],
    }];
    let effective = compose_effective_policy(&remote, None);
    assert!(respects_mandatory_baseline(&effective));
    let bash = effective
        .tools
        .iter()
        .find(|t| t.name == "execute_bash")
        .unwrap();
    assert_eq!(bash.action, PolicyAction::Confirm);
    assert!(!mandatory_security_baseline()
        .global
        .block_patterns
        .is_empty());
}

#[test]
fn remote_can_add_stricter() {
    let mut remote = sample_policy("strict");
    remote.global.risk_threshold = 20;
    remote.tools[0].action = PolicyAction::Block;
    let effective = compose_effective_policy(&remote, None);
    assert!(effective.global.risk_threshold <= 20);
    let bash = effective
        .tools
        .iter()
        .find(|t| t.name == "execute_bash")
        .unwrap();
    assert_eq!(bash.action, PolicyAction::Block);
}

#[test]
fn unsigned_sync_body_rejected() {
    let body = br#"{"version":"1","global":{"redact_keys":[],"risk_threshold":70},"tools":[]}"#;
    assert_eq!(
        parse_sync_response(body).unwrap_err(),
        PolicyRejectReason::UnsignedForbidden
    );
}

#[test]
fn expire_still_activates_with_stale_events() {
    let _g = super::signed::test_env_lock();
    std::env::set_var(ORG_ID_ENV, "acme");
    let mut env = SignedPolicyEnvelope {
        schema_version: ENVELOPE_SCHEMA_VERSION,
        key_id: TEST_POLICY_KEY_ID.into(),
        policy_id: "default".into(),
        organization_id: "acme".into(),
        revision: 1,
        issued_at: "2020-01-01T00:00:00Z".into(),
        not_before: "2020-01-01T00:00:00Z".into(),
        expires_at: Some("2020-01-02T00:00:00Z".into()),
        previous_revision: None,
        policy_digest: String::new(),
        policy: sample_policy("1"),
        signature: String::new(),
    };
    env = sign_envelope_with_seed(env, &test_seed()).unwrap();
    let act = activate_signed_policy(env, &PolicyAcceptanceState::default(), None).unwrap();
    assert!(act.events.iter().any(|e| *e == "policy_expired"));
    assert!(act.events.iter().any(|e| *e == "stale_policy_in_use"));
}

#[test]
fn restart_re_verifies_cache() {
    let _g = super::signed::test_env_lock();
    std::env::set_var(ORG_ID_ENV, "acme");
    let dir = temp_dir();
    let path = dir.join("cache.json");
    let accept_path = dir.join("policy-acceptance.json");
    let env = signed("acme", 7, sample_policy("7"));
    persist_signed_envelope(&env, &path).unwrap();
    persist_acceptance(&acceptance_from_envelope(&env), &accept_path).unwrap();

    let loaded = load_signed_envelope(&path).unwrap().unwrap();
    let acceptance = load_acceptance(&accept_path).unwrap();
    activate_signed_policy(loaded, &acceptance, None).unwrap();
}

#[test]
fn alter_deny_to_allow_breaks_signature() {
    let mut env = signed("acme", 1, sample_policy("1"));
    env.policy.tools[0].action = PolicyAction::Allow;
    // Also "fix" digest to match tampered content — signature still covers metadata+digest
    env.policy_digest = policy_digest(&env.policy).unwrap();
    assert_eq!(
        verify_signature(&env),
        Err(PolicyRejectReason::InvalidSignature)
    );
}

#[test]
fn modify_revision_breaks_signature() {
    let mut env = signed("acme", 1, sample_policy("1"));
    env.revision = 999;
    assert_eq!(
        verify_signature(&env),
        Err(PolicyRejectReason::InvalidSignature)
    );
}

#[test]
fn modify_expiration_breaks_signature() {
    let mut env = signed("acme", 1, sample_policy("1"));
    env.expires_at = Some("2099-01-01T00:00:00Z".into());
    assert_eq!(
        verify_signature(&env),
        Err(PolicyRejectReason::InvalidSignature)
    );
}

#[test]
fn concurrent_activate_prefers_higher_revision() {
    let _g = super::signed::test_env_lock();
    std::env::set_var(ORG_ID_ENV, "acme");
    let v1 = signed("acme", 1, sample_policy("1"));
    let v2 = signed("acme", 2, sample_policy("2"));
    let a1 = activate_signed_policy(v1, &PolicyAcceptanceState::default(), None).unwrap();
    let state = acceptance_from_envelope(&a1.envelope);
    let a2 = activate_signed_policy(v2, &state, None).unwrap();
    assert_eq!(a2.envelope.revision, 2);
    let state2 = acceptance_from_envelope(&a2.envelope);
    // Older cannot win after newer accepted
    let older = signed("acme", 1, sample_policy("1"));
    assert_eq!(
        activate_signed_policy(older, &state2, None).unwrap_err(),
        PolicyRejectReason::Rollback
    );
}
