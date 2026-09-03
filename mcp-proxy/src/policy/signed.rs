//! Signed managed-policy envelopes (Ed25519).
//!
//! Managed policy is executable security configuration. The edge activates a
//! remote/cached document only after signature, digest, org binding, schema,
//! and anti-rollback checks succeed.

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::OnceLock;
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{anyhow, Context, Result};
use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

use super::canonical::canonicalize;
use super::compile::compile_layered;
use super::compose::compose_effective_policy;
use super::schema::PolicyConfig;
use super::validate::validate_config;
use super::PolicyEngine;

/// Envelope schema version understood by this binary.
pub const ENVELOPE_SCHEMA_VERSION: u32 = 1;

/// Primary trust-root key id (pinned with the binary).
pub const PRIMARY_POLICY_KEY_ID: &str = "sqreen-policy-ed25519-1";

/// Test-only key id — never trusted in production.
pub const TEST_POLICY_KEY_ID: &str = "sqreen-policy-ed25519-test";

/// Env: expected organization id for managed policy binding.
pub const ORG_ID_ENV: &str = "SQREEN_ORG_ID";
/// Alternate org env (legacy).
pub const ORG_ID_ENV_ALT: &str = "MCP_ORGANIZATION_ID";
/// Opt-in: allow unsigned remote policy (migration / development only).
pub const ALLOW_UNSIGNED_ENV: &str = "SQREEN_ALLOW_UNSIGNED_POLICY";
/// Opt-in: trust the built-in test verification key (never in production).
pub const ALLOW_TEST_KEYS_ENV: &str = "SQREEN_POLICY_ALLOW_TEST_KEYS";
/// Extra trusted keys during rotation: `kid:hex32,...`
pub const EXTRA_TRUSTED_KEYS_ENV: &str = "SQREEN_POLICY_TRUSTED_KEYS";
/// Production marker — rejects test keys and unsigned paths.
pub const PRODUCTION_ENV: &str = "SQREEN_ENV";

/// Pinned Sqreen policy-signing public key (raw Ed25519, 32 bytes).
const PRIMARY_PUBKEY: [u8; 32] = [
    0xaa, 0x15, 0x6e, 0x94, 0x7a, 0x69, 0xde, 0x8c, 0x09, 0xad, 0x41, 0x37, 0xf4, 0x33, 0x3a, 0x12,
    0x00, 0x08, 0xa9, 0xea, 0x21, 0xae, 0xdf, 0xc1, 0xb5, 0xe3, 0x03, 0x1a, 0x89, 0x88, 0xdd, 0x0b,
];

/// Test fixture public key — only when explicitly enabled.
const TEST_PUBKEY: [u8; 32] = [
    0x70, 0x2a, 0x27, 0x91, 0x2a, 0xf8, 0xea, 0x36, 0x74, 0xaf, 0x9e, 0xd4, 0xb2, 0x53, 0x8c, 0xf8,
    0x1a, 0x4a, 0xa4, 0xd2, 0x2c, 0x80, 0x5e, 0xc9, 0xf2, 0x0f, 0x3f, 0xc0, 0x1f, 0x73, 0x6f, 0x10,
];

/// Wire format returned by GET /api/v1/policy/sync for managed fleets.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SignedPolicyEnvelope {
    pub schema_version: u32,
    pub key_id: String,
    pub policy_id: String,
    pub organization_id: String,
    pub revision: u64,
    pub issued_at: String,
    pub not_before: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub previous_revision: Option<u64>,
    pub policy_digest: String,
    pub policy: PolicyConfig,
    /// Base64-encoded Ed25519 signature over the canonical signing payload.
    pub signature: String,
}

/// Why a candidate envelope was rejected (security audit).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PolicyRejectReason {
    InvalidSchema,
    UnsupportedSchema,
    MissingSignature,
    MalformedSignature,
    UnknownKeyId,
    InvalidSignature,
    DigestMismatch,
    WrongOrganization,
    Rollback,
    SameRevisionDigestMismatch,
    InvalidPolicy,
    CompileFailed,
    Expired,
    NotYetValid,
    CanonicalMismatch,
    UnsignedForbidden,
}

impl PolicyRejectReason {
    pub fn as_event_name(&self) -> &'static str {
        match self {
            Self::InvalidSchema | Self::UnsupportedSchema => "policy_rejected_invalid_schema",
            Self::MissingSignature | Self::MalformedSignature | Self::InvalidSignature => {
                "policy_rejected_invalid_signature"
            }
            Self::UnknownKeyId => "policy_key_unknown",
            Self::DigestMismatch | Self::CanonicalMismatch => "policy_rejected_digest_mismatch",
            Self::WrongOrganization => "policy_rejected_wrong_org",
            Self::Rollback | Self::SameRevisionDigestMismatch => "policy_rejected_rollback",
            Self::InvalidPolicy | Self::CompileFailed => "policy_rejected_invalid_schema",
            Self::Expired => "policy_expired",
            Self::NotYetValid => "policy_rejected_invalid_schema",
            Self::UnsignedForbidden => "policy_rejected_invalid_signature",
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Self::InvalidSchema => "invalid_schema",
            Self::UnsupportedSchema => "unsupported_schema",
            Self::MissingSignature => "missing_signature",
            Self::MalformedSignature => "malformed_signature",
            Self::UnknownKeyId => "unknown_key_id",
            Self::InvalidSignature => "invalid_signature",
            Self::DigestMismatch => "digest_mismatch",
            Self::WrongOrganization => "wrong_organization",
            Self::Rollback => "rollback",
            Self::SameRevisionDigestMismatch => "same_revision_digest_mismatch",
            Self::InvalidPolicy => "invalid_policy",
            Self::CompileFailed => "compile_failed",
            Self::Expired => "expired",
            Self::NotYetValid => "not_yet_valid",
            Self::CanonicalMismatch => "canonical_mismatch",
            Self::UnsignedForbidden => "unsigned_forbidden",
        }
    }
}

/// Durable anti-rollback / last-known-good metadata.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct PolicyAcceptanceState {
    pub organization_id: String,
    pub policy_id: String,
    pub highest_revision: u64,
    pub digest: String,
    pub key_id: String,
    pub activated_at: String,
}

/// Result of a successful verify then validate then compose then compile pipeline.
#[derive(Debug)]
pub struct VerifiedPolicyActivation {
    pub envelope: SignedPolicyEnvelope,
    pub effective: PolicyConfig,
    pub engine: PolicyEngine,
    pub events: Vec<&'static str>,
}

/// Build the JSON object that is signed (does not include `signature` or `policy`).
pub fn signing_payload(env: &SignedPolicyEnvelope) -> Value {
    let mut map = serde_json::Map::new();
    if let Some(exp) = &env.expires_at {
        map.insert("expires_at".into(), Value::String(exp.clone()));
    } else {
        map.insert("expires_at".into(), Value::Null);
    }
    map.insert("issued_at".into(), Value::String(env.issued_at.clone()));
    map.insert("key_id".into(), Value::String(env.key_id.clone()));
    map.insert("not_before".into(), Value::String(env.not_before.clone()));
    map.insert(
        "organization_id".into(),
        Value::String(env.organization_id.clone()),
    );
    map.insert(
        "policy_digest".into(),
        Value::String(env.policy_digest.clone()),
    );
    map.insert("policy_id".into(), Value::String(env.policy_id.clone()));
    match env.previous_revision {
        Some(v) => map.insert("previous_revision".into(), json!(v)),
        None => map.insert("previous_revision".into(), Value::Null),
    };
    map.insert("revision".into(), json!(env.revision));
    map.insert("schema_version".into(), json!(env.schema_version));
    Value::Object(map)
}

/// Wire-compatible policy body for digests (matches Go `Policy` JSON shape).
/// Extra PolicyConfig fields are excluded so control-plane signatures verify on the edge.
pub fn policy_wire_value(policy: &PolicyConfig) -> Value {
    let mut global = serde_json::Map::new();
    global.insert(
        "redact_keys".into(),
        Value::Array(
            policy
                .global
                .redact_keys
                .iter()
                .cloned()
                .map(Value::String)
                .collect(),
        ),
    );
    global.insert("risk_threshold".into(), json!(policy.global.risk_threshold));
    if !policy.global.block_patterns.is_empty() {
        global.insert(
            "block_patterns".into(),
            Value::Array(
                policy
                    .global
                    .block_patterns
                    .iter()
                    .cloned()
                    .map(Value::String)
                    .collect(),
            ),
        );
    }
    let tools: Vec<Value> = policy
        .tools
        .iter()
        .map(|tool| {
            json!({
                "name": tool.name,
                "action": tool.action,
                "block_patterns": tool.block_patterns,
            })
        })
        .collect();
    json!({
        "version": policy.version,
        "global": Value::Object(global),
        "tools": tools,
    })
}

/// SHA-256 hex digest of the canonical wire policy body (Go-compatible).
pub fn policy_digest(policy: &PolicyConfig) -> Result<String> {
    let bytes = canonicalize(&policy_wire_value(policy));
    Ok(hex::encode(Sha256::digest(&bytes)))
}

/// Canonical bytes that are Ed25519-signed.
pub fn signed_message_bytes(env: &SignedPolicyEnvelope) -> Vec<u8> {
    canonicalize(&signing_payload(env))
}

fn trusted_keys() -> &'static BTreeMap<String, VerifyingKey> {
    static KEYS: OnceLock<BTreeMap<String, VerifyingKey>> = OnceLock::new();
    KEYS.get_or_init(|| {
        let mut map = BTreeMap::new();
        if let Ok(key) = VerifyingKey::from_bytes(&PRIMARY_PUBKEY) {
            map.insert(PRIMARY_POLICY_KEY_ID.to_string(), key);
        }

        let allow_test = cfg!(test)
            || std::env::var(ALLOW_TEST_KEYS_ENV)
                .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
                .unwrap_or(false);
        let production = std::env::var(PRODUCTION_ENV)
            .map(|v| v.eq_ignore_ascii_case("production") || v.eq_ignore_ascii_case("prod"))
            .unwrap_or(false);

        if allow_test && !production {
            if let Ok(key) = VerifyingKey::from_bytes(&TEST_PUBKEY) {
                map.insert(TEST_POLICY_KEY_ID.to_string(), key);
            }
        }

        if let Ok(raw) = std::env::var(EXTRA_TRUSTED_KEYS_ENV) {
            for part in raw.split(',') {
                let part = part.trim();
                if part.is_empty() {
                    continue;
                }
                let Some((kid, hex_key)) = part.split_once(':') else {
                    continue;
                };
                if let Ok(bytes) = hex::decode(hex_key.trim()) {
                    if bytes.len() == 32 {
                        let mut arr = [0u8; 32];
                        arr.copy_from_slice(&bytes);
                        if let Ok(key) = VerifyingKey::from_bytes(&arr) {
                            map.insert(kid.trim().to_string(), key);
                        }
                    }
                }
            }
        }

        map
    })
}

fn resolve_expected_org() -> Option<String> {
    std::env::var(ORG_ID_ENV)
        .ok()
        .filter(|v| !v.trim().is_empty())
        .or_else(|| {
            std::env::var(ORG_ID_ENV_ALT)
                .ok()
                .filter(|v| !v.trim().is_empty())
        })
        .map(|v| v.trim().to_string())
}

fn unsigned_allowed() -> bool {
    let production = std::env::var(PRODUCTION_ENV)
        .map(|v| v.eq_ignore_ascii_case("production") || v.eq_ignore_ascii_case("prod"))
        .unwrap_or(false);
    if production {
        return false;
    }
    std::env::var(ALLOW_UNSIGNED_ENV)
        .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
        .unwrap_or(false)
}

/// Parse sync response: signed envelope required unless explicitly allowed.
pub fn parse_sync_response(body: &[u8]) -> Result<SignedPolicyEnvelope, PolicyRejectReason> {
    let value: Value =
        serde_json::from_slice(body).map_err(|_| PolicyRejectReason::InvalidSchema)?;
    if value.get("signature").is_some() && value.get("policy_digest").is_some() {
        serde_json::from_value(value).map_err(|_| PolicyRejectReason::InvalidSchema)
    } else {
        Err(PolicyRejectReason::UnsignedForbidden)
    }
}

/// Verify cryptographic integrity only (no anti-rollback / org / compile).
pub fn verify_signature(env: &SignedPolicyEnvelope) -> Result<(), PolicyRejectReason> {
    if env.schema_version != ENVELOPE_SCHEMA_VERSION {
        return Err(PolicyRejectReason::UnsupportedSchema);
    }
    if env.signature.trim().is_empty() {
        return Err(PolicyRejectReason::MissingSignature);
    }

    let digest = policy_digest(&env.policy).map_err(|_| PolicyRejectReason::InvalidPolicy)?;
    if digest != env.policy_digest {
        return Err(PolicyRejectReason::DigestMismatch);
    }

    let keys = trusted_keys();
    let Some(vk) = keys.get(&env.key_id) else {
        return Err(PolicyRejectReason::UnknownKeyId);
    };

    let sig_bytes = B64
        .decode(env.signature.trim())
        .map_err(|_| PolicyRejectReason::MalformedSignature)?;
    let signature =
        Signature::from_slice(&sig_bytes).map_err(|_| PolicyRejectReason::MalformedSignature)?;
    let message = signed_message_bytes(env);
    vk.verify(&message, &signature)
        .map_err(|_| PolicyRejectReason::InvalidSignature)?;
    Ok(())
}

fn parse_rfc3339_secs(raw: &str) -> Option<i64> {
    chrono::DateTime::parse_from_rfc3339(raw)
        .ok()
        .map(|dt| dt.timestamp())
}

fn now_unix() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// Full activation gate: verify then org then time then anti-rollback then validate then compose then compile.
pub fn activate_signed_policy(
    env: SignedPolicyEnvelope,
    acceptance: &PolicyAcceptanceState,
    local: Option<PolicyConfig>,
) -> Result<VerifiedPolicyActivation, PolicyRejectReason> {
    verify_signature(&env)?;

    if let Some(expected) = resolve_expected_org() {
        if env.organization_id != expected {
            return Err(PolicyRejectReason::WrongOrganization);
        }
    }

    let now = now_unix();
    if let Some(nb) = parse_rfc3339_secs(&env.not_before) {
        if now + 60 < nb {
            return Err(PolicyRejectReason::NotYetValid);
        }
    }
    let mut expired = false;
    if let Some(exp) = env.expires_at.as_deref().and_then(parse_rfc3339_secs) {
        if now > exp {
            expired = true;
        }
    }

    if !acceptance.organization_id.is_empty()
        && acceptance.organization_id != env.organization_id
        && acceptance.highest_revision > 0
    {
        return Err(PolicyRejectReason::WrongOrganization);
    }

    if env.revision < acceptance.highest_revision {
        return Err(PolicyRejectReason::Rollback);
    }
    if env.revision == acceptance.highest_revision && acceptance.highest_revision > 0 {
        if env.policy_digest != acceptance.digest {
            return Err(PolicyRejectReason::SameRevisionDigestMismatch);
        }
    }

    validate_config(&env.policy).map_err(|_| PolicyRejectReason::InvalidPolicy)?;

    let effective = compose_effective_policy(&env.policy, local.as_ref());
    validate_config(&effective).map_err(|_| PolicyRejectReason::InvalidPolicy)?;

    // Enforcement uses trust-layered compilation — signature authenticity ≠ authority
    // to weaken the mandatory baseline via high-priority org rules.
    let compiled = compile_layered(&env.policy, local.as_ref())
        .map_err(|_| PolicyRejectReason::CompileFailed)?;
    let engine = PolicyEngine::from_compiled(compiled);

    let mut events = vec!["policy_downloaded", "policy_verified", "policy_activated"];
    if expired {
        events.insert(2, "policy_expired");
        events.insert(3, "stale_policy_in_use");
    }

    Ok(VerifiedPolicyActivation {
        envelope: env,
        effective,
        engine,
        events,
    })
}

/// Persist signed envelope atomically with restrictive permissions.
pub fn persist_signed_envelope(env: &SignedPolicyEnvelope, path: &Path) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = fs::set_permissions(parent, fs::Permissions::from_mode(0o700));
        }
    }
    let tmp = path.with_extension("json.tmp");
    let payload = serde_json::to_vec_pretty(env)?;
    fs::write(&tmp, &payload)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = fs::set_permissions(&tmp, fs::Permissions::from_mode(0o600));
    }
    fs::rename(&tmp, path)?;
    Ok(())
}

pub fn load_signed_envelope(path: &Path) -> Result<Option<SignedPolicyEnvelope>> {
    if !path.exists() {
        return Ok(None);
    }
    let bytes = fs::read(path)?;
    let env: SignedPolicyEnvelope = serde_json::from_slice(&bytes)?;
    Ok(Some(env))
}

pub fn acceptance_path_beside_cache(cache: &Path) -> PathBuf {
    // Prefer org-scoped acceptance beside the cache when SQREEN_ORG_ID is set,
    // so switching enrollment orgs cannot reuse another tenant's anti-rollback state.
    if let Some(org) = resolve_expected_org() {
        let safe: String = org
            .chars()
            .map(|c| {
                if c.is_ascii_alphanumeric() || c == '-' || c == '_' {
                    c
                } else {
                    '_'
                }
            })
            .collect();
        return cache.with_file_name(format!("policy-acceptance-{safe}.json"));
    }
    cache.with_file_name("policy-acceptance.json")
}

pub fn load_acceptance(path: &Path) -> Result<PolicyAcceptanceState> {
    if !path.exists() {
        return Ok(PolicyAcceptanceState::default());
    }
    let raw = fs::read_to_string(path)?;
    Ok(serde_json::from_str(&raw)?)
}

pub fn persist_acceptance(state: &PolicyAcceptanceState, path: &Path) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let tmp = path.with_extension("json.tmp");
    fs::write(&tmp, serde_json::to_vec_pretty(state)?)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = fs::set_permissions(&tmp, fs::Permissions::from_mode(0o600));
    }
    fs::rename(&tmp, path)?;
    Ok(())
}

pub fn acceptance_from_envelope(env: &SignedPolicyEnvelope) -> PolicyAcceptanceState {
    PolicyAcceptanceState {
        organization_id: env.organization_id.clone(),
        policy_id: env.policy_id.clone(),
        highest_revision: env.revision,
        digest: env.policy_digest.clone(),
        key_id: env.key_id.clone(),
        activated_at: chrono::Utc::now().to_rfc3339(),
    }
}

/// Emit a structured security event line (never includes signing material).
pub fn emit_policy_event(
    name: &str,
    org: &str,
    policy_id: &str,
    revision: u64,
    digest: &str,
    key_id: &str,
    reason: &str,
    previous_revision: Option<u64>,
) {
    eprintln!(
        "mcp-proxy security_event name={name} organization_id={org} policy_id={policy_id} \
         revision={revision} digest={digest} key_id={key_id} reason={reason} \
         previous_revision={}",
        previous_revision
            .map(|v| v.to_string())
            .unwrap_or_else(|| "-".into())
    );
}

/// Helper for tests: sign an envelope with a raw 32-byte seed.
#[cfg(test)]
pub fn sign_envelope_with_seed(
    mut env: SignedPolicyEnvelope,
    seed: &[u8; 32],
) -> Result<SignedPolicyEnvelope> {
    use ed25519_dalek::{Signer, SigningKey};
    env.policy_digest = policy_digest(&env.policy)?;
    let message = signed_message_bytes(&env);
    let sk = SigningKey::from_bytes(seed);
    let sig = sk.sign(&message);
    env.signature = B64.encode(sig.to_bytes());
    Ok(env)
}

pub fn require_signed_policy() -> bool {
    !unsigned_allowed()
}

pub fn is_production() -> bool {
    std::env::var(PRODUCTION_ENV)
        .map(|v| v.eq_ignore_ascii_case("production") || v.eq_ignore_ascii_case("prod"))
        .unwrap_or(false)
}

/// Map reject reason to anyhow for callers that prefer Result.
pub fn reject_err(reason: PolicyRejectReason) -> anyhow::Error {
    anyhow!("policy rejected: {}", reason.as_str())
}

#[cfg(test)]
pub(crate) fn test_env_lock() -> std::sync::MutexGuard<'static, ()> {
    use std::sync::{Mutex, OnceLock};
    static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| Mutex::new(()))
        .lock()
        .unwrap_or_else(|p| p.into_inner())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy::schema::{GlobalPolicy, PolicyAction, ToolPolicy};

    fn sample_policy() -> PolicyConfig {
        PolicyConfig {
            version: "1".into(),
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

    fn test_seed() -> [u8; 32] {
        let hex = "394adcbf0d487810a28a6dc00f348b09b5ac2bc064e0488949b24c3fff16e7c0";
        let bytes = hex::decode(hex).expect("seed hex");
        let mut seed = [0u8; 32];
        seed.copy_from_slice(&bytes);
        seed
    }

    fn signed_sample(org: &str, revision: u64) -> SignedPolicyEnvelope {
        let policy = sample_policy();
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
    fn valid_signature_activates() {
        let _g = test_env_lock();
        std::env::set_var(ORG_ID_ENV, "acme");
        let env = signed_sample("acme", 1);
        let act =
            activate_signed_policy(env, &PolicyAcceptanceState::default(), None).expect("activate");
        assert_eq!(act.envelope.revision, 1);
    }

    #[test]
    fn tampered_policy_rejected() {
        let mut env = signed_sample("acme", 1);
        env.policy.global.risk_threshold = 99;
        assert_eq!(
            verify_signature(&env),
            Err(PolicyRejectReason::DigestMismatch)
        );
    }

    #[test]
    fn wrong_org_rejected() {
        let _g = test_env_lock();
        std::env::set_var(ORG_ID_ENV, "acme");
        let env = signed_sample("other", 1);
        let err =
            activate_signed_policy(env, &PolicyAcceptanceState::default(), None).expect_err("org");
        assert_eq!(err, PolicyRejectReason::WrongOrganization);
    }

    #[test]
    fn rollback_rejected() {
        let _g = test_env_lock();
        std::env::set_var(ORG_ID_ENV, "acme");
        let acceptance = PolicyAcceptanceState {
            organization_id: "acme".into(),
            policy_id: "default".into(),
            highest_revision: 5,
            digest: "abc".into(),
            key_id: TEST_POLICY_KEY_ID.into(),
            activated_at: "2026-09-01T00:00:00Z".into(),
        };
        let env = signed_sample("acme", 4);
        assert_eq!(
            activate_signed_policy(env, &acceptance, None).unwrap_err(),
            PolicyRejectReason::Rollback
        );
    }

    #[test]
    fn unknown_key_rejected() {
        let mut env = signed_sample("acme", 1);
        env.key_id = "unknown-key".into();
        assert_eq!(
            verify_signature(&env),
            Err(PolicyRejectReason::UnknownKeyId)
        );
    }
}
