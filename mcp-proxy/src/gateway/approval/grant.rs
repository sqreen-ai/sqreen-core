//! Scoped approval grants — tokens that authorize a later evaluation without re-prompting.
//!
//! # Security properties
//!
//! 1. **Scoped** — a grant matches either the exact action fingerprint (tool + args +
//!    resource + destination + agent + session + environment) or a deliberately narrower
//!    session-tool scope that is only issued when [`session_approval_safe`] holds.
//! 2. **Replay-resistant** — single-use grants are consumed on first successful match;
//!    presenting a consumed token fails closed.
//! 3. **Expiring** — every grant carries `expires_at`; expired grants never authorize.
//! 4. **Arg-bound** — [`ApprovalScope::ExactAction`] embeds a digest of canonical arguments;
//!    any argument change produces a different fingerprint and fails to match.
//! 5. **Audited** — issue / consume / reject / expire events are retained in-process for
//!    the process lifetime (bounded ring).

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;
use std::time::Duration;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::action::AgentAction;
use crate::scoring::RiskLevel;
use crate::taxonomy::{ActionCategory, ResourceCategory};

use super::context::DEFAULT_TIMED_APPROVAL;

/// How long a single-use exact-action token remains redeemable when issued for out-of-band use.
pub const DEFAULT_ONCE_TTL: Duration = Duration::from_secs(5 * 60);

/// Default lifetime for session-scoped grants.
pub const DEFAULT_SESSION_TTL: Duration = Duration::from_secs(8 * 60 * 60);

/// Cap on retained audit history entries.
const HISTORY_CAP: usize = 2_048;

/// Cryptographic binding of an action under review.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ActionBinding {
    /// Hex-encoded SHA-256 over the canonical binding material.
    pub fingerprint: String,
    /// Hex digest of canonical tool arguments alone (for diagnostics / tamper tests).
    pub args_digest: String,
    pub tool_name: String,
    pub agent_id: String,
    /// Registered/bound agent id when available — preferred over spoofable labels.
    pub agent_bound_id: String,
    pub agent_trust: String,
    pub device_id: String,
    pub organization_id: String,
    pub session_id: String,
    pub environment: String,
    pub resource_digest: String,
    pub destination_digest: String,
}

impl ActionBinding {
    /// Builds a binding from the live action. Argument bytes come from
    /// [`AgentAction::canonical_params_json`] so DLP rewrites that change the forwarded
    /// payload still share the same pre-mask fingerprint as the evaluation that was scored.
    pub fn from_action(action: &AgentAction) -> Self {
        let tool_name = action.tool_name().to_string();
        let args = action.canonical_params_json();
        let args_digest = hex_sha256(args.as_bytes());
        let agent_id = action.identity.effective_agent_id().to_string();
        let agent_bound_id = action
            .identity
            .agent_bound_id
            .as_ref()
            .map(|id| id.as_str().to_string())
            .unwrap_or_default();
        let agent_trust = action.identity.agent_trust.as_str().to_string();
        let device_id = action
            .identity
            .device_id
            .as_ref()
            .map(|id| id.as_str().to_string())
            .unwrap_or_default();
        let organization_id = action
            .identity
            .organization_id
            .clone()
            .unwrap_or_default();
        let session_id = action
            .session_id()
            .map(|id| id.as_str().to_string())
            .unwrap_or_default();
        let environment = format!("{:?}", action.identity.environment.tier);
        let resource_digest = hex_sha256(
            action
                .target_resource
                .as_ref()
                .map(|resource| format!("{resource:?}"))
                .unwrap_or_default()
                .as_bytes(),
        );
        let destination_digest = hex_sha256(
            action
                .destination
                .as_ref()
                .map(|destination| format!("{destination:?}"))
                .unwrap_or_default()
                .as_bytes(),
        );

        // v2 binding includes authoritative device/org and bound agent when present so
        // spoofed labels alone cannot replay another agent's approval.
        let mut hasher = Sha256::new();
        hasher.update(b"sqreen.approval.v2\0");
        hasher.update(tool_name.as_bytes());
        hasher.update(b"\0");
        hasher.update(args_digest.as_bytes());
        hasher.update(b"\0");
        hasher.update(resource_digest.as_bytes());
        hasher.update(b"\0");
        hasher.update(destination_digest.as_bytes());
        hasher.update(b"\0");
        hasher.update(agent_id.as_bytes());
        hasher.update(b"\0");
        hasher.update(agent_bound_id.as_bytes());
        hasher.update(b"\0");
        hasher.update(agent_trust.as_bytes());
        hasher.update(b"\0");
        hasher.update(device_id.as_bytes());
        hasher.update(b"\0");
        hasher.update(organization_id.as_bytes());
        hasher.update(b"\0");
        hasher.update(session_id.as_bytes());
        hasher.update(b"\0");
        hasher.update(environment.as_bytes());

        Self {
            fingerprint: format!("{:x}", hasher.finalize()),
            args_digest,
            tool_name,
            agent_id,
            agent_bound_id,
            agent_trust,
            device_id,
            organization_id,
            session_id,
            environment,
            resource_digest,
            destination_digest,
        }
    }

    /// Stable seed used to mint request ids without embedding randomness into the binding.
    pub fn nonce_seed(&self) -> String {
        self.fingerprint.chars().take(24).collect()
    }

    /// Key used to look up session-tool grants (agent + session + tool + environment).
    pub fn session_scope_key(&self) -> String {
        // Prefer bound agent id when present so session grants cannot cross spoofed labels.
        let agent_key = if self.agent_bound_id.is_empty() {
            self.agent_id.as_str()
        } else {
            self.agent_bound_id.as_str()
        };
        format!(
            "{}|{}|{}|{}|{}",
            agent_key, self.device_id, self.session_id, self.tool_name, self.environment
        )
    }
}

/// What a grant is allowed to cover.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ApprovalScope {
    /// Exact tool + args + resource + destination + agent + session + environment.
    ExactAction,
    /// Same agent, session, tool, and environment — only issued when session-safe.
    SessionTool,
}

impl ApprovalScope {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ExactAction => "exact_action",
            Self::SessionTool => "session_tool",
        }
    }
}

/// Human / engine verdict that produced a grant or denial.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ApprovalVerdict {
    ApproveOnce,
    Deny,
    ApproveForSession,
    ApproveUntil { expires_at: DateTime<Utc> },
}

impl ApprovalVerdict {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::ApproveOnce => "APPROVE_ONCE",
            Self::Deny => "DENY",
            Self::ApproveForSession => "APPROVE_FOR_SESSION",
            Self::ApproveUntil { .. } => "APPROVE_UNTIL",
        }
    }
}

/// Issued capability token.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ApprovalGrant {
    /// Opaque token id (also the lookup key).
    pub token: String,
    /// Request id of the approval prompt that minted this grant.
    pub request_id: String,
    pub scope: ApprovalScope,
    /// Full binding captured at issuance (audit + ExactAction match).
    pub binding: ActionBinding,
    pub issued_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    /// `Some(1)` for once; `None` means unlimited until expiry.
    pub max_uses: Option<u32>,
    pub uses: u32,
    pub consumed: bool,
    pub verdict: ApprovalVerdict,
}

/// Why a redeem / authorize attempt failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GrantRejectReason {
    UnknownToken,
    Expired,
    Consumed,
    BindingMismatch,
    ArgsTampered,
    ScopeMismatch,
    SessionMissing,
}

impl GrantRejectReason {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::UnknownToken => "unknown_token",
            Self::Expired => "expired",
            Self::Consumed => "consumed",
            Self::BindingMismatch => "binding_mismatch",
            Self::ArgsTampered => "args_tampered",
            Self::ScopeMismatch => "scope_mismatch",
            Self::SessionMissing => "session_missing",
        }
    }
}

/// Result of consulting the grant store for an action.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GrantAuthorization {
    /// A live grant covers this action; it has been recorded as used.
    Authorized { grant: ApprovalGrant },
    /// No matching live grant.
    None,
}

/// One audit row for approval activity.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ApprovalHistoryEntry {
    pub timestamp: DateTime<Utc>,
    pub event: ApprovalHistoryEvent,
    pub request_id: Option<String>,
    pub token: Option<String>,
    pub scope: Option<ApprovalScope>,
    pub binding_fingerprint: Option<String>,
    pub args_digest: Option<String>,
    pub detail: String,
    /// Sanitized reviewer context snapshot when this was a prompt decision.
    pub sanitized_brief: Option<String>,
}

/// Kinds of history events retained by the store.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ApprovalHistoryEvent {
    Prompted,
    Approved,
    Denied,
    GrantIssued,
    GrantConsumed,
    GrantRejected,
    GrantExpired,
}

/// In-memory grant vault + approval audit ring.
#[derive(Debug, Default)]
pub struct ApprovalGrantStore {
    seq: AtomicU64,
    inner: Mutex<StoreInner>,
}

#[derive(Debug, Default)]
struct StoreInner {
    by_token: HashMap<String, ApprovalGrant>,
    /// Session-tool index: scope key → token.
    session_index: HashMap<String, String>,
    /// Exact-action index: fingerprint → token (for multi-use timed exact grants).
    exact_index: HashMap<String, String>,
    history: Vec<ApprovalHistoryEntry>,
}

impl ApprovalGrantStore {
    pub fn new() -> Self {
        Self::default()
    }

    /// Whether session-scoped reuse is permitted for this action at `level`.
    pub fn session_safe(action: &AgentAction, level: RiskLevel) -> bool {
        session_approval_safe(action, level)
    }

    /// Records a reviewer prompt / decision without necessarily issuing a grant.
    pub fn record_decision(
        &self,
        request_id: &str,
        binding: &ActionBinding,
        verdict: &ApprovalVerdict,
        sanitized_brief: &str,
    ) {
        let event = match verdict {
            ApprovalVerdict::Deny => ApprovalHistoryEvent::Denied,
            _ => ApprovalHistoryEvent::Approved,
        };
        self.push_history(ApprovalHistoryEntry {
            timestamp: Utc::now(),
            event,
            request_id: Some(request_id.to_string()),
            token: None,
            scope: None,
            binding_fingerprint: Some(binding.fingerprint.clone()),
            args_digest: Some(binding.args_digest.clone()),
            detail: format!("verdict={}", verdict.as_str()),
            sanitized_brief: Some(sanitized_brief.to_string()),
        });
    }

    /// Issues a single-use exact-action grant (out-of-band APPROVE_ONCE token).
    pub fn issue_once(
        &self,
        request_id: &str,
        binding: ActionBinding,
        ttl: Duration,
    ) -> ApprovalGrant {
        self.issue_inner(
            request_id,
            ApprovalScope::ExactAction,
            binding,
            ApprovalVerdict::ApproveOnce,
            ttl,
            Some(1),
        )
    }

    /// Issues a session-tool grant when safe.
    pub fn issue_session(
        &self,
        request_id: &str,
        binding: ActionBinding,
        ttl: Duration,
    ) -> Result<ApprovalGrant, GrantRejectReason> {
        if binding.session_id.trim().is_empty() {
            return Err(GrantRejectReason::SessionMissing);
        }
        Ok(self.issue_inner(
            request_id,
            ApprovalScope::SessionTool,
            binding,
            ApprovalVerdict::ApproveForSession,
            ttl,
            None,
        ))
    }

    /// Issues a time-limited exact-action grant (args remain bound).
    pub fn issue_until(
        &self,
        request_id: &str,
        binding: ActionBinding,
        expires_at: DateTime<Utc>,
    ) -> ApprovalGrant {
        self.issue_with_expiry(
            request_id,
            ApprovalScope::ExactAction,
            binding,
            ApprovalVerdict::ApproveUntil { expires_at },
            expires_at,
            None,
        )
    }

    /// Looks for a live grant covering `action` and consumes a use on match.
    pub fn authorize(&self, action: &AgentAction) -> GrantAuthorization {
        let binding = ActionBinding::from_action(action);
        let now = Utc::now();
        let mut inner = self.inner.lock().expect("approval grant store poisoned");

        // Prefer exact-action grants (stricter).
        if let Some(token) = inner.exact_index.get(&binding.fingerprint).cloned() {
            match Self::take_use(
                &mut inner,
                &token,
                &binding,
                now,
                ApprovalScope::ExactAction,
            ) {
                Ok(grant) => {
                    drop(inner);
                    self.push_history(ApprovalHistoryEntry {
                        timestamp: Utc::now(),
                        event: ApprovalHistoryEvent::GrantConsumed,
                        request_id: Some(grant.request_id.clone()),
                        token: Some(grant.token.clone()),
                        scope: Some(grant.scope),
                        binding_fingerprint: Some(binding.fingerprint.clone()),
                        args_digest: Some(binding.args_digest.clone()),
                        detail: "exact_action grant authorized".into(),
                        sanitized_brief: None,
                    });
                    return GrantAuthorization::Authorized { grant };
                }
                Err(reason) => {
                    Self::note_reject(&mut inner, &token, &binding, reason);
                }
            }
        }

        // Session-tool grants only when the action is still session-safe at Medium or below.
        // Risk level is not stored on the grant; we re-check taxonomy safety here.
        if session_approval_safe(action, RiskLevel::Medium) {
            let key = binding.session_scope_key();
            if let Some(token) = inner.session_index.get(&key).cloned() {
                match Self::take_use(
                    &mut inner,
                    &token,
                    &binding,
                    now,
                    ApprovalScope::SessionTool,
                ) {
                    Ok(grant) => {
                        drop(inner);
                        self.push_history(ApprovalHistoryEntry {
                            timestamp: Utc::now(),
                            event: ApprovalHistoryEvent::GrantConsumed,
                            request_id: Some(grant.request_id.clone()),
                            token: Some(grant.token.clone()),
                            scope: Some(grant.scope),
                            binding_fingerprint: Some(binding.fingerprint.clone()),
                            args_digest: Some(binding.args_digest.clone()),
                            detail: "session_tool grant authorized".into(),
                            sanitized_brief: None,
                        });
                        return GrantAuthorization::Authorized { grant };
                    }
                    Err(reason) => {
                        Self::note_reject(&mut inner, &token, &binding, reason);
                    }
                }
            }
        }

        GrantAuthorization::None
    }

    /// Redeems an explicit token against `action` (out-of-band / replay tests).
    pub fn redeem(
        &self,
        token: &str,
        action: &AgentAction,
    ) -> Result<ApprovalGrant, GrantRejectReason> {
        let binding = ActionBinding::from_action(action);
        let now = Utc::now();
        let mut inner = self.inner.lock().expect("approval grant store poisoned");

        let Some(grant) = inner.by_token.get(token).cloned() else {
            Self::note_reject_detail(
                &mut inner,
                None,
                &binding,
                GrantRejectReason::UnknownToken,
                "unknown approval token",
            );
            return Err(GrantRejectReason::UnknownToken);
        };

        let scope = grant.scope;
        match Self::take_use(&mut inner, token, &binding, now, scope) {
            Ok(grant) => {
                let detail = format!("token redeemed scope={}", scope.as_str());
                Self::note_event(
                    &mut inner,
                    ApprovalHistoryEvent::GrantConsumed,
                    Some(&grant.request_id),
                    Some(token),
                    Some(scope),
                    &binding,
                    detail,
                );
                Ok(grant)
            }
            Err(reason) => {
                Self::note_reject(&mut inner, token, &binding, reason);
                Err(reason)
            }
        }
    }

    /// Snapshot of audit history (oldest → newest).
    pub fn history(&self) -> Vec<ApprovalHistoryEntry> {
        self.inner
            .lock()
            .expect("approval grant store poisoned")
            .history
            .clone()
    }

    fn issue_inner(
        &self,
        request_id: &str,
        scope: ApprovalScope,
        binding: ActionBinding,
        verdict: ApprovalVerdict,
        ttl: Duration,
        max_uses: Option<u32>,
    ) -> ApprovalGrant {
        let issued_at = Utc::now();
        let expires_at = issued_at
            + chrono::Duration::from_std(ttl).unwrap_or_else(|_| {
                chrono::Duration::seconds(DEFAULT_TIMED_APPROVAL.as_secs() as i64)
            });
        self.issue_with_expiry(request_id, scope, binding, verdict, expires_at, max_uses)
    }

    fn issue_with_expiry(
        &self,
        request_id: &str,
        scope: ApprovalScope,
        binding: ActionBinding,
        verdict: ApprovalVerdict,
        expires_at: DateTime<Utc>,
        max_uses: Option<u32>,
    ) -> ApprovalGrant {
        let seq = self.seq.fetch_add(1, Ordering::Relaxed);
        let material = format!(
            "{}:{}:{}:{}",
            binding.fingerprint,
            request_id,
            seq,
            Utc::now().timestamp_nanos_opt().unwrap_or(0)
        );
        let token = format!("apgr_{}", &hex_sha256(material.as_bytes())[..32]);
        let issued_at = Utc::now();

        let grant = ApprovalGrant {
            token: token.clone(),
            request_id: request_id.to_string(),
            scope,
            binding: binding.clone(),
            issued_at,
            expires_at,
            max_uses,
            uses: 0,
            consumed: false,
            verdict,
        };

        let mut inner = self.inner.lock().expect("approval grant store poisoned");
        match scope {
            ApprovalScope::ExactAction => {
                inner
                    .exact_index
                    .insert(binding.fingerprint.clone(), token.clone());
            }
            ApprovalScope::SessionTool => {
                inner
                    .session_index
                    .insert(binding.session_scope_key(), token.clone());
            }
        }
        inner.by_token.insert(token.clone(), grant.clone());
        Self::note_event(
            &mut inner,
            ApprovalHistoryEvent::GrantIssued,
            Some(request_id),
            Some(&token),
            Some(scope),
            &binding,
            format!(
                "issued scope={} max_uses={:?} expires_at={}",
                scope.as_str(),
                max_uses,
                expires_at.to_rfc3339()
            ),
        );
        grant
    }

    fn take_use(
        inner: &mut StoreInner,
        token: &str,
        binding: &ActionBinding,
        now: DateTime<Utc>,
        expected_scope: ApprovalScope,
    ) -> Result<ApprovalGrant, GrantRejectReason> {
        let grant = inner
            .by_token
            .get_mut(token)
            .ok_or(GrantRejectReason::UnknownToken)?;

        if grant.scope != expected_scope {
            return Err(GrantRejectReason::ScopeMismatch);
        }
        if grant.consumed {
            return Err(GrantRejectReason::Consumed);
        }
        if now >= grant.expires_at {
            grant.consumed = true;
            let snapshot = grant.clone();
            Self::purge_indexes(inner, &snapshot);
            return Err(GrantRejectReason::Expired);
        }

        match grant.scope {
            ApprovalScope::ExactAction => {
                if grant.binding.fingerprint != binding.fingerprint {
                    if grant.binding.args_digest != binding.args_digest
                        && grant.binding.tool_name == binding.tool_name
                        && grant.binding.agent_id == binding.agent_id
                        && grant.binding.session_id == binding.session_id
                    {
                        return Err(GrantRejectReason::ArgsTampered);
                    }
                    return Err(GrantRejectReason::BindingMismatch);
                }
            }
            ApprovalScope::SessionTool => {
                if grant.binding.session_scope_key() != binding.session_scope_key() {
                    return Err(GrantRejectReason::BindingMismatch);
                }
            }
        }

        grant.uses = grant.uses.saturating_add(1);
        if let Some(max) = grant.max_uses {
            if grant.uses >= max {
                grant.consumed = true;
            }
        }

        let snapshot = grant.clone();
        if snapshot.consumed {
            Self::purge_indexes(inner, &snapshot);
        }
        Ok(snapshot)
    }

    fn purge_indexes(inner: &mut StoreInner, grant: &ApprovalGrant) {
        match grant.scope {
            ApprovalScope::ExactAction => {
                if inner
                    .exact_index
                    .get(&grant.binding.fingerprint)
                    .map(|token| token == &grant.token)
                    .unwrap_or(false)
                {
                    inner.exact_index.remove(&grant.binding.fingerprint);
                }
            }
            ApprovalScope::SessionTool => {
                let key = grant.binding.session_scope_key();
                if inner
                    .session_index
                    .get(&key)
                    .map(|token| token == &grant.token)
                    .unwrap_or(false)
                {
                    inner.session_index.remove(&key);
                }
            }
        }
    }

    fn note_reject(
        inner: &mut StoreInner,
        token: &str,
        binding: &ActionBinding,
        reason: GrantRejectReason,
    ) {
        Self::note_reject_detail(
            inner,
            Some(token),
            binding,
            reason,
            reason.as_str().to_string(),
        );
    }

    fn note_reject_detail(
        inner: &mut StoreInner,
        token: Option<&str>,
        binding: &ActionBinding,
        reason: GrantRejectReason,
        detail: impl Into<String>,
    ) {
        let _ = reason;
        Self::note_event(
            inner,
            ApprovalHistoryEvent::GrantRejected,
            None,
            token,
            None,
            binding,
            detail,
        );
    }

    fn note_event(
        inner: &mut StoreInner,
        event: ApprovalHistoryEvent,
        request_id: Option<&str>,
        token: Option<&str>,
        scope: Option<ApprovalScope>,
        binding: &ActionBinding,
        detail: impl Into<String>,
    ) {
        inner.history.push(ApprovalHistoryEntry {
            timestamp: Utc::now(),
            event,
            request_id: request_id.map(str::to_string),
            token: token.map(str::to_string),
            scope,
            binding_fingerprint: Some(binding.fingerprint.clone()),
            args_digest: Some(binding.args_digest.clone()),
            detail: detail.into(),
            sanitized_brief: None,
        });
        if inner.history.len() > HISTORY_CAP {
            let overflow = inner.history.len() - HISTORY_CAP;
            inner.history.drain(0..overflow);
        }
    }

    fn push_history(&self, entry: ApprovalHistoryEntry) {
        let mut inner = self.inner.lock().expect("approval grant store poisoned");
        inner.history.push(entry);
        if inner.history.len() > HISTORY_CAP {
            let overflow = inner.history.len() - HISTORY_CAP;
            inner.history.drain(0..overflow);
        }
    }
}

/// Returns `true` when APPROVE_FOR_SESSION / timed session reuse is allowed.
///
/// Destructive, credential, secret, external, execute, delete, deploy, escalate, send,
/// network, and authenticate actions are never session-safe. Risk must be ≤ MEDIUM.
pub fn session_approval_safe(action: &AgentAction, level: RiskLevel) -> bool {
    if level > RiskLevel::Medium {
        return false;
    }

    let security = &action.security;
    if security.risk.destructive
        || security.risk.external_destination
        || security.risk.credential_access
        || security.risk.irreversible
        || security.risk.privileged
    {
        return false;
    }

    if security.touches_resource(ResourceCategory::Credential)
        || security.touches_resource(ResourceCategory::Secret)
    {
        return false;
    }

    !matches!(
        security.action,
        ActionCategory::Delete
            | ActionCategory::Deploy
            | ActionCategory::Escalate
            | ActionCategory::Execute
            | ActionCategory::Authenticate
            | ActionCategory::Send
            | ActionCategory::NetworkRequest
    )
}

fn hex_sha256(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    format!("{:x}", hasher.finalize())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::action::{Arguments, Runtime, SessionId, SourceRef};

    fn action(tool: &str, args: serde_json::Value) -> AgentAction {
        let mut built = AgentAction::builder(tool, Arguments::from_name_and_arguments(tool, &args))
            .source(SourceRef::new(Runtime::MCP_STDIO, "test"))
            .session_id(Some(SessionId::new("sess-1")))
            .agent_id(Some("agent-1"))
            .build_unvalidated();
        built.refresh_security_classification();
        built
    }

    #[test]
    fn exact_once_grant_rejects_replay() {
        let store = ApprovalGrantStore::new();
        let probe = action("read_file", serde_json::json!({"path": "/tmp/a"}));
        let binding = ActionBinding::from_action(&probe);
        let grant = store.issue_once("req-1", binding, DEFAULT_ONCE_TTL);

        assert!(store.redeem(&grant.token, &probe).is_ok());
        assert_eq!(
            store.redeem(&grant.token, &probe),
            Err(GrantRejectReason::Consumed)
        );
    }

    #[test]
    fn modified_arguments_invalidate_exact_grant() {
        let store = ApprovalGrantStore::new();
        let original = action("read_file", serde_json::json!({"path": "/tmp/a"}));
        let tampered = action("read_file", serde_json::json!({"path": "/etc/passwd"}));
        let grant = store.issue_once(
            "req-2",
            ActionBinding::from_action(&original),
            DEFAULT_ONCE_TTL,
        );

        assert_eq!(
            store.redeem(&grant.token, &tampered),
            Err(GrantRejectReason::ArgsTampered)
        );
    }

    #[test]
    fn expired_grant_cannot_authorize() {
        let store = ApprovalGrantStore::new();
        let probe = action("read_file", serde_json::json!({"path": "/tmp/a"}));
        let binding = ActionBinding::from_action(&probe);
        let grant = store.issue_until("req-3", binding, Utc::now() - chrono::Duration::seconds(1));

        assert_eq!(
            store.redeem(&grant.token, &probe),
            Err(GrantRejectReason::Expired)
        );
        assert!(matches!(store.authorize(&probe), GrantAuthorization::None));
    }

    #[test]
    fn authorize_reuses_session_grant_for_safe_tool() {
        let store = ApprovalGrantStore::new();
        let first = action("list_dir", serde_json::json!({"path": "/tmp"}));
        assert!(session_approval_safe(&first, RiskLevel::Low));
        let binding = ActionBinding::from_action(&first);
        store
            .issue_session("req-4", binding, DEFAULT_SESSION_TTL)
            .expect("session grant");

        let second = action("list_dir", serde_json::json!({"path": "/var"}));
        assert!(matches!(
            store.authorize(&second),
            GrantAuthorization::Authorized { .. }
        ));
    }

    #[test]
    fn history_records_issue_and_reject() {
        let store = ApprovalGrantStore::new();
        let probe = action("read_file", serde_json::json!({"path": "/tmp/a"}));
        let grant = store.issue_once(
            "req-5",
            ActionBinding::from_action(&probe),
            DEFAULT_ONCE_TTL,
        );
        let _ = store.redeem(&grant.token, &probe);
        let _ = store.redeem(&grant.token, &probe);

        let events: Vec<_> = store.history().iter().map(|e| e.event).collect();
        assert!(events.contains(&ApprovalHistoryEvent::GrantIssued));
        assert!(events.contains(&ApprovalHistoryEvent::GrantConsumed));
        assert!(events.contains(&ApprovalHistoryEvent::GrantRejected));
    }

    #[test]
    fn binding_fingerprint_stable_for_identical_action() {
        let a = action("read_file", serde_json::json!({"path": "/tmp/a"}));
        let b = action("read_file", serde_json::json!({"path": "/tmp/a"}));
        assert_eq!(
            ActionBinding::from_action(&a).fingerprint,
            ActionBinding::from_action(&b).fingerprint
        );
    }
}
