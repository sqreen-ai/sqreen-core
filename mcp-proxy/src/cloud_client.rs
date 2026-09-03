//! HTTP client for the centralized mcp-control-plane management API.
//!
//! # Non-blocking relay invariant
//!
//! [`CloudClient::dispatch_telemetry`] **must never block** the stdio JSON-RPC relay path.
//! All network I/O runs inside detached `tokio::spawn` tasks; failures are logged to
//! stderr and dropped.
//!
//! # Fail-closed policy sync
//!
//! [`CloudClient::fetch_latest_policy`] attempts remote sync first, then falls back to
//! on-disk cache (`mcp-policy.cloud.json`), then local YAML. If all sources fail, the
//! error propagates and the proxy continues with the last loaded engine state.
//!
//! # Thread safety
//!
//! [`CloudClient`] is `Clone` via inner `reqwest::Client` arc; safe to share across
//! relay tasks. No interior mutability on the hot path.

use std::path::PathBuf;
use std::time::Duration;

use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use reqwest::header::{HeaderMap, HeaderValue};
use reqwest::StatusCode;
use serde::{Deserialize, Serialize};

use crate::policy::{
    acceptance_from_envelope, acceptance_path_beside_cache, activate_signed_policy,
    emit_policy_event, load_acceptance, load_config_optional, load_signed_envelope,
    persist_acceptance, persist_signed_envelope, reject_err, PolicyConfig, SignedPolicyEnvelope,
};
use crate::threat_intel::{resolve_local_threat_intel_path, ThreatIntelFeed, ThreatIntelMatcher};

/// Environment variable for the control plane base URL (e.g. `http://localhost:8080`).
pub const CONTROL_PLANE_URL_ENV: &str = "MCP_CONTROL_PLANE_URL";

/// Environment variable for the edge device authentication token.
pub const DEVICE_TOKEN_ENV: &str = "MCP_DEVICE_TOKEN";

/// Non-secret opaque device identity (never the bearer). Optional — server fills from enrollment.
pub const DEVICE_ID_ENV: &str = "SQREEN_DEVICE_ID";
/// Legacy alias for [`DEVICE_ID_ENV`].
pub const DEVICE_ID_ENV_LEGACY: &str = "MCP_DEVICE_ID";

/// Header name required by the control plane for device authentication.
pub const DEVICE_TOKEN_HEADER: &str = "X-Device-Token";

const POLICY_SYNC_PATH: &str = "/api/v1/policy/sync";
const THREAT_INTEL_SYNC_PATH: &str = "/api/v1/threat-intel/sync";
const TELEMETRY_PATH: &str = "/api/v1/telemetry/log";
const DEFAULT_REQUEST_TIMEOUT: Duration = Duration::from_secs(5);
const CLOUD_POLICY_CACHE_NAME: &str = "mcp-policy.cloud.signed.json";
const CLOUD_THREAT_INTEL_CACHE_NAME: &str = "threat-intel.cloud.json";

/// Where a synced policy document originated.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PolicySyncSource {
    ControlPlane,
    Cache,
    LocalYaml,
}

/// Where a synced threat-intel feed originated.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ThreatIntelSyncSource {
    ControlPlane,
    Cache,
    LocalFile,
}

/// Operator decision recorded alongside violation telemetry.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum UserDecision {
    Approved,
    Denied,
    Skipped,
}

/// Structured violation payload aligned with the Go control plane schema.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TelemetryRecord {
    pub timestamp: DateTime<Utc>,
    pub device_id: String,
    pub tool_name: String,
    pub risk_score: u8,
    pub pattern_matched: String,
    pub user_decision: UserDecision,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub agent_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub agent_label: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub agent_trust: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub agent_identity_source: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub agent_bound_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub user_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub user_label: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub user_trust: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session_label: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session_trust: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub runtime: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub model_provider: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub risk_factors: Vec<String>,
}

impl TelemetryRecord {
    /// Builds a telemetry record with the current UTC timestamp.
    pub fn new(
        device_id: impl Into<String>,
        tool_name: impl Into<String>,
        risk_score: u8,
        pattern_matched: impl Into<String>,
        user_decision: UserDecision,
    ) -> Self {
        Self {
            timestamp: Utc::now(),
            device_id: device_id.into(),
            tool_name: tool_name.into(),
            risk_score,
            pattern_matched: pattern_matched.into(),
            user_decision,
            agent_id: None,
            agent_label: None,
            agent_trust: None,
            agent_identity_source: None,
            agent_bound_id: None,
            user_id: None,
            user_label: None,
            user_trust: None,
            session_id: None,
            session_label: None,
            session_trust: None,
            runtime: None,
            model_provider: None,
            risk_factors: Vec::new(),
        }
    }

    /// Attaches execution-identity provenance from an evaluated action.
    pub fn with_execution_identity(mut self, action: &crate::action::AgentAction) -> Self {
        let principal = action.identity.execution_principal(
            action.execution.session_id.as_ref(),
            &action.execution.runtime,
            &action.model,
            Some(action.source.adapter.as_str()),
        );
        if let Some(agent) = principal.agent {
            self.agent_label = Some(agent.value.clone());
            self.agent_id = Some(agent.value);
            self.agent_trust = Some(agent.trust.as_str().to_string());
            self.agent_identity_source = Some(agent.source);
        }
        self.agent_bound_id = principal.agent_bound_id;
        if let Some(user) = principal.user {
            self.user_label = Some(user.value.clone());
            self.user_id = Some(user.value);
            self.user_trust = Some(user.trust.as_str().to_string());
        }
        if let Some(session) = principal.session {
            self.session_label = Some(session.value.clone());
            self.session_id = Some(session.value);
            self.session_trust = Some(session.trust.as_str().to_string());
        }
        self.runtime = Some(principal.runtime);
        self.model_provider = principal.provider;
        self
    }

    /// Attaches identity trust fields from a privacy-safe security event.
    pub fn with_identity_from_event(mut self, event: &crate::telemetry::AgentSecurityEvent) -> Self {
        self.agent_id = Some(event.agent.agent_id.clone());
        self.agent_label = Some(event.agent.agent_id.clone());
        self.agent_trust = Some(event.agent.agent_trust.clone());
        self.agent_identity_source = event.agent.agent_identity_source.clone();
        self.agent_bound_id = event.agent.agent_bound_id.clone();
        self.user_id = event.agent.user_id.clone();
        self.user_label = event.agent.user_id.clone();
        self.user_trust = Some(event.agent.user_trust.clone());
        self.session_id = event.session.session_id.clone();
        self.session_label = event.session.session_id.clone();
        self.session_trust = Some("self_asserted".to_string());
        self.runtime = Some(event.session.runtime.clone());
        self.risk_factors = event.risk.factors.clone();
        self
    }
}

/// Network client for policy sync and asynchronous telemetry dispatch.
#[derive(Clone)]
pub struct CloudClient {
    http: reqwest::Client,
    base_url: String,
    /// Authentication bearer — NEVER use as device_id / telemetry attribute / Display.
    device_token: String,
    /// Non-secret opaque device identity. May be empty; control plane derives from enrollment.
    device_id: String,
    policy_cache_path: PathBuf,
    threat_intel_cache_path: PathBuf,
    local_threat_intel_path: PathBuf,
}

impl CloudClient {
    /// Creates a client targeting `base_url` with the given device token.
    pub fn new(base_url: &str, device_token: &str) -> Self {
        Self::new_with_device_id(base_url, device_token, resolve_nonsecret_device_id())
    }

    /// Creates a client with an explicit non-secret device id (tests / enrollment).
    pub fn new_with_device_id(
        base_url: &str,
        device_token: &str,
        device_id: impl Into<String>,
    ) -> Self {
        let http = reqwest::Client::builder()
            .timeout(DEFAULT_REQUEST_TIMEOUT)
            .build()
            .expect("reqwest client should build");

        let mut device_id = device_id.into().trim().to_string();
        if looks_like_device_bearer(&device_id) || device_id == device_token.trim() {
            // Never allow credential material to masquerade as identity.
            device_id.clear();
        }

        Self {
            http,
            base_url: trim_trailing_slash(base_url),
            device_token: device_token.to_string(),
            device_id,
            policy_cache_path: resolve_cloud_policy_cache_path(),
            threat_intel_cache_path: resolve_cloud_threat_intel_cache_path(),
            local_threat_intel_path: resolve_local_threat_intel_path(),
        }
    }

    /// Initializes a client when both [`CONTROL_PLANE_URL_ENV`] and [`DEVICE_TOKEN_ENV`] are set.
    pub fn load_optional() -> Option<Self> {
        let base_url = std::env::var(CONTROL_PLANE_URL_ENV)
            .ok()
            .filter(|value| !value.trim().is_empty())?;
        let device_token = std::env::var(DEVICE_TOKEN_ENV)
            .ok()
            .filter(|value| !value.trim().is_empty())?;

        Some(Self::new(base_url.trim(), device_token.trim()))
    }

    /// Returns the non-secret device identifier for telemetry (never the bearer).
    ///
    /// Empty means "omit / let the control plane assign from enrollment".
    pub fn device_id(&self) -> &str {
        &self.device_id
    }

    /// Authentication bearer for `X-Device-Token` only — not for identity fields.
    pub(crate) fn device_token_for_auth(&self) -> &str {
        &self.device_token
    }

    /// Pulls the latest *signed* policy from the control plane.
    ///
    /// Activation order: download → verify → validate → compose → compile → atomic cache.
    /// On remote failure, re-verifies last-known-good signed cache (never activates
    /// tampered cache). Unsigned remote payloads are rejected unless explicitly allowed.
    pub async fn fetch_latest_policy(&self) -> Result<(PolicyConfig, PolicySyncSource)> {
        match self.fetch_remote_signed_policy().await {
            Ok(env) => match self.activate_envelope(env, PolicySyncSource::ControlPlane) {
                Ok(pair) => Ok(pair),
                Err(error) => {
                    eprintln!(
                        "mcp-proxy cloud: remote policy rejected after download: {error:#}; \
                         attempting verified cache / local fallback"
                    );
                    self.load_verified_fallback()
                }
            },
            Err(remote_error) => {
                emit_policy_event(
                    "policy_sync_failed",
                    "-",
                    "-",
                    0,
                    "-",
                    "-",
                    &format!("{}", crate::gateway::sanitize_error(&remote_error)),
                    None,
                );
                eprintln!(
                    "mcp-proxy cloud: remote policy sync failed: {}; \
                     falling back to verified cache / local policy",
                    crate::gateway::sanitize_error(&remote_error)
                );
                self.load_verified_fallback()
            }
        }
    }

    /// Pulls the latest threat-intel feed from the control plane, falling back to cache/local file.
    pub async fn fetch_latest_threat_intel(
        &self,
    ) -> Result<(ThreatIntelFeed, ThreatIntelSyncSource)> {
        match self.fetch_remote_threat_intel().await {
            Ok(feed) => {
                if let Err(error) = persist_threat_intel_cache(&feed, &self.threat_intel_cache_path)
                {
                    eprintln!("mcp-proxy cloud: failed to persist threat-intel cache: {error:#}");
                }
                Ok((feed, ThreatIntelSyncSource::ControlPlane))
            }
            Err(remote_error) => {
                eprintln!(
                    "mcp-proxy cloud: security control degraded [{}=FAIL_OPEN] \
                     remote threat-intel sync failed: {}; falling back to cached/local feed",
                    crate::gateway::Subsystem::ControlPlane,
                    crate::gateway::sanitize_error(&remote_error)
                );
                self.load_threat_intel_fallback()
            }
        }
    }

    /// Dispatches telemetry without blocking the active relay task.
    pub fn dispatch_telemetry(&self, record: TelemetryRecord) {
        let client = self.clone();

        // `tokio::spawn` panics when there is no runtime, and the decision path that calls
        // this is reachable from synchronous contexts (tests, CLI subcommands). Telemetry
        // is `FAIL_OPEN` by matrix; a panic here would convert an unsent event into a lost
        // enforcement decision, which is precisely the inversion the matrix forbids.
        let Ok(handle) = tokio::runtime::Handle::try_current() else {
            warn_once("no async runtime available for telemetry dispatch; event dropped");
            return;
        };

        handle.spawn(async move {
            if let Err(error) = client.post_telemetry(record).await {
                eprintln!(
                    "mcp-proxy cloud: security control degraded [{}=FAIL_OPEN] \
                     telemetry dispatch failed: {}; local enforcement is unaffected",
                    crate::gateway::Subsystem::ControlPlane,
                    crate::gateway::sanitize_error(&error)
                );
            }
        });
    }

    async fn fetch_remote_threat_intel(&self) -> Result<ThreatIntelFeed> {
        let url = format!("{}{THREAT_INTEL_SYNC_PATH}", self.base_url);
        let response = self
            .http
            .get(&url)
            .headers(self.auth_headers())
            .send()
            .await
            .with_context(|| format!("failed to reach control plane at {url}"))?
            .error_for_status()
            .with_context(|| format!("control plane rejected threat-intel sync at {url}"))?;

        response
            .json::<ThreatIntelFeed>()
            .await
            .context("failed to decode threat-intel sync response")
    }

    async fn fetch_remote_signed_policy(&self) -> Result<SignedPolicyEnvelope> {
        let url = format!("{}{POLICY_SYNC_PATH}", self.base_url);
        let response = self
            .http
            .get(&url)
            .headers(self.auth_headers())
            .send()
            .await
            .with_context(|| format!("failed to reach control plane at {url}"))?
            .error_for_status()
            .with_context(|| format!("control plane rejected policy sync at {url}"))?;

        let bytes = response
            .bytes()
            .await
            .context("failed to read policy sync body")?;
        // Reject truncated / empty bodies before parse.
        if bytes.is_empty() {
            anyhow::bail!("empty policy sync response");
        }
        crate::policy::parse_sync_response(&bytes).map_err(crate::policy::reject_err)
    }

    fn activate_envelope(
        &self,
        env: SignedPolicyEnvelope,
        source: PolicySyncSource,
    ) -> Result<(PolicyConfig, PolicySyncSource)> {
        let accept_path = acceptance_path_beside_cache(&self.policy_cache_path);
        let acceptance = load_acceptance(&accept_path).unwrap_or_default();
        let previous = acceptance.highest_revision;
        let local = load_config_optional().ok().flatten();

        match activate_signed_policy(env, &acceptance, local) {
            Ok(activated) => {
                for event in &activated.events {
                    emit_policy_event(
                        event,
                        &activated.envelope.organization_id,
                        &activated.envelope.policy_id,
                        activated.envelope.revision,
                        &activated.envelope.policy_digest,
                        &activated.envelope.key_id,
                        "ok",
                        if previous > 0 { Some(previous) } else { None },
                    );
                }
                if let Err(error) =
                    persist_signed_envelope(&activated.envelope, &self.policy_cache_path)
                {
                    eprintln!("mcp-proxy cloud: failed to persist signed policy cache: {error:#}");
                }
                let state = acceptance_from_envelope(&activated.envelope);
                if let Err(error) = persist_acceptance(&state, &accept_path) {
                    eprintln!("mcp-proxy cloud: failed to persist acceptance state: {error:#}");
                }
                Ok((activated.effective, source))
            }
            Err(reason) => {
                emit_policy_event(
                    reason.as_event_name(),
                    "-",
                    "-",
                    0,
                    "-",
                    "-",
                    reason.as_str(),
                    if previous > 0 { Some(previous) } else { None },
                );
                Err(reject_err(reason))
            }
        }
    }

    fn load_verified_fallback(&self) -> Result<(PolicyConfig, PolicySyncSource)> {
        let accept_path = acceptance_path_beside_cache(&self.policy_cache_path);
        let acceptance = load_acceptance(&accept_path).unwrap_or_default();

        if let Ok(Some(env)) = load_signed_envelope(&self.policy_cache_path) {
            match activate_signed_policy(env, &acceptance, load_config_optional().ok().flatten()) {
                Ok(activated) => {
                    emit_policy_event(
                        "stale_policy_in_use",
                        &activated.envelope.organization_id,
                        &activated.envelope.policy_id,
                        activated.envelope.revision,
                        &activated.envelope.policy_digest,
                        &activated.envelope.key_id,
                        "remote_unavailable",
                        None,
                    );
                    eprintln!(
                        "mcp-proxy cloud: enforcing last-known-good signed policy revision {}",
                        activated.envelope.revision
                    );
                    return Ok((activated.effective, PolicySyncSource::Cache));
                }
                Err(reason) => {
                    emit_policy_event(
                        reason.as_event_name(),
                        "-",
                        "-",
                        0,
                        "-",
                        "-",
                        reason.as_str(),
                        None,
                    );
                    eprintln!(
                        "mcp-proxy cloud: cached signed policy failed re-verification: {}",
                        reason.as_str()
                    );
                }
            }
        }

        // Managed / signed-required path: do NOT silently fall back to weaker unsigned YAML
        // when cloud is configured — unless unsigned is explicitly allowed.
        if crate::policy::require_signed_policy() {
            anyhow::bail!(
                "control plane unreachable and no verified signed policy cache is available"
            );
        }

        if let Some(config) = load_config_optional()? {
            eprintln!(
                "mcp-proxy cloud: loaded local policy v{} from disk (unsigned allowed)",
                config.version
            );
            return Ok((config, PolicySyncSource::LocalYaml));
        }

        anyhow::bail!("control plane unreachable and no local policy cache is available")
    }

    async fn post_telemetry(&self, record: TelemetryRecord) -> Result<()> {
        let url = format!("{}{TELEMETRY_PATH}", self.base_url);
        let response = self
            .http
            .post(&url)
            .headers(self.auth_headers())
            .json(&record)
            .send()
            .await
            .with_context(|| format!("failed to post telemetry to {url}"))?;

        if response.status() == StatusCode::ACCEPTED || response.status().is_success() {
            return Ok(());
        }

        anyhow::bail!(
            "control plane rejected telemetry with status {}",
            response.status()
        );
    }

    fn load_threat_intel_fallback(&self) -> Result<(ThreatIntelFeed, ThreatIntelSyncSource)> {
        if let Some(feed) = load_threat_intel_cache(&self.threat_intel_cache_path)? {
            eprintln!(
                "mcp-proxy cloud: loaded cached threat-intel v{} from {}",
                feed.version,
                self.threat_intel_cache_path.display()
            );
            return Ok((feed, ThreatIntelSyncSource::Cache));
        }

        let local = ThreatIntelMatcher::from_file(&self.local_threat_intel_path);
        if local.indicator_count() > 0 {
            eprintln!(
                "mcp-proxy cloud: using {} local threat-intel indicators from {}",
                local.indicator_count(),
                self.local_threat_intel_path.display()
            );
            return Ok((
                ThreatIntelFeed {
                    version: "local".to_string(),
                    indicators: local.indicators().to_vec(),
                },
                ThreatIntelSyncSource::LocalFile,
            ));
        }

        anyhow::bail!("control plane unreachable and no threat-intel cache is available")
    }

    /// Builds the device-authentication headers.
    ///
    /// A token that is not a legal header value (a stray newline from a copy-paste, a
    /// non-ASCII character) used to be silently replaced with the literal
    /// `invalid-token`. That produced a 401 from the control plane and an operator
    /// hunting a credential problem that was really a formatting problem — and it put a
    /// value on the wire that was never configured. Now the header is simply omitted and
    /// the condition is named once, so the resulting rejection points at the token.
    fn auth_headers(&self) -> HeaderMap {
        let mut headers = HeaderMap::new();

        match HeaderValue::from_str(&self.device_token) {
            Ok(mut value) => {
                value.set_sensitive(true);
                headers.insert(DEVICE_TOKEN_HEADER, value);
            }
            Err(_) => warn_once(
                "device token is not a valid HTTP header value (check for whitespace or \
                 non-ASCII characters); sending an unauthenticated request",
            ),
        }

        headers
    }
}

/// Reports a control-plane degradation at most once per condition.
///
/// These conditions repeat at the rate of the traffic that triggers them — a malformed
/// token is malformed on every request — so an unconditional print would bury the rest of
/// the operator's stderr under a message that says the same thing each time.
fn warn_once(message: &str) {
    use std::collections::HashSet;
    use std::sync::Mutex;
    use std::sync::OnceLock;

    static SEEN: OnceLock<Mutex<HashSet<String>>> = OnceLock::new();

    let seen = SEEN.get_or_init(|| Mutex::new(HashSet::new()));
    let mut seen = seen.lock().unwrap_or_else(|poisoned| poisoned.into_inner());

    if seen.insert(message.to_string()) {
        eprintln!(
            "mcp-proxy cloud: security control degraded [{}=FAIL_OPEN] {message}",
            crate::gateway::Subsystem::ControlPlane
        );
    }
}

fn trim_trailing_slash(base_url: &str) -> String {
    base_url.trim_end_matches('/').to_string()
}

fn resolve_cloud_policy_cache_path() -> PathBuf {
    if let Ok(path) = std::env::var(crate::policy::POLICY_PATH_ENV) {
        if let Some(parent) = PathBuf::from(path).parent() {
            return parent.join(CLOUD_POLICY_CACHE_NAME);
        }
    }

    if let Some(home) = std::env::var_os("HOME") {
        return PathBuf::from(home)
            .join(".config")
            .join("mcp-proxy")
            .join(CLOUD_POLICY_CACHE_NAME);
    }

    PathBuf::from(CLOUD_POLICY_CACHE_NAME)
}

fn resolve_cloud_threat_intel_cache_path() -> PathBuf {
    if let Ok(path) = std::env::var(crate::threat_intel::THREAT_INTEL_PATH_ENV) {
        if let Some(parent) = PathBuf::from(path).parent() {
            return parent.join(CLOUD_THREAT_INTEL_CACHE_NAME);
        }
    }

    if let Some(home) = std::env::var_os("HOME") {
        return PathBuf::from(home)
            .join(".config")
            .join("mcp-proxy")
            .join(CLOUD_THREAT_INTEL_CACHE_NAME);
    }

    PathBuf::from(CLOUD_THREAT_INTEL_CACHE_NAME)
}

fn persist_threat_intel_cache(feed: &ThreatIntelFeed, path: &PathBuf) -> Result<()> {
    let parent = path
        .parent()
        .context("threat-intel cache path must have a parent directory")?;
    std::fs::create_dir_all(parent)
        .with_context(|| format!("create cache directory {}", parent.display()))?;
    let payload = serde_json::to_string_pretty(feed).context("serialize threat-intel cache")?;
    std::fs::write(path, payload)
        .with_context(|| format!("write threat-intel cache {}", path.display()))
}

fn load_threat_intel_cache(path: &PathBuf) -> Result<Option<ThreatIntelFeed>> {
    if !path.is_file() {
        return Ok(None);
    }

    let contents = std::fs::read_to_string(path)
        .with_context(|| format!("read threat-intel cache {}", path.display()))?;
    let feed = serde_json::from_str(&contents).context("parse threat-intel cache json")?;
    Ok(Some(feed))
}

fn looks_like_device_bearer(value: &str) -> bool {
    let lower = value.trim().to_ascii_lowercase();
    lower.starts_with("sqreen_device_")
        || lower.starts_with("sq_dev_")
        || lower.starts_with("sqreen_admin_")
        || lower.starts_with("dev-device-token")
        || lower.starts_with("bootstrap-env-token")
}

fn resolve_nonsecret_device_id() -> String {
    for key in [DEVICE_ID_ENV, DEVICE_ID_ENV_LEGACY] {
        if let Ok(raw) = std::env::var(key) {
            let trimmed = raw.trim().to_string();
            if !trimmed.is_empty() && !looks_like_device_bearer(&trimmed) {
                return trimmed;
            }
        }
    }
    String::new()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn telemetry_record_serializes_go_shape() {
        let record = TelemetryRecord {
            timestamp: DateTime::parse_from_rfc3339("2026-06-27T12:00:00Z")
                .expect("timestamp")
                .with_timezone(&Utc),
            device_id: "laptop-abc123".to_string(),
            tool_name: "execute_bash".to_string(),
            risk_score: 82,
            pattern_matched: r"rm\s+-rf\s+.*".to_string(),
            user_decision: UserDecision::Denied,
            agent_id: None,
            agent_label: None,
            agent_trust: None,
            agent_identity_source: None,
            agent_bound_id: None,
            user_id: None,
            user_label: None,
            user_trust: None,
            session_id: None,
            session_label: None,
            session_trust: None,
            runtime: None,
            model_provider: None,
            risk_factors: Vec::new(),
        };

        let json = serde_json::to_string(&record).expect("serialize");
        assert!(json.contains("\"device_id\":\"laptop-abc123\""));
        assert!(json.contains("\"user_decision\":\"denied\""));
        assert!(json.contains("\"risk_score\":82"));
    }

    #[test]
    fn device_id_never_returns_bearer_token() {
        let token =
            "sqreen_device_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        let client = CloudClient::new("http://127.0.0.1:8080", token);
        assert_ne!(client.device_id(), token);
        assert!(!client.device_id().contains(token));
        let payload = serde_json::to_string(&TelemetryRecord::new(
            client.device_id(),
            "shell",
            1,
            "none",
            UserDecision::Skipped,
        ))
        .expect("serialize");
        assert!(
            !payload.contains(token),
            "telemetry must not embed bearer: {payload}"
        );
    }

    #[test]
    fn explicit_device_id_used_when_non_secret() {
        let token =
            "sqreen_device_bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
        let client = CloudClient::new_with_device_id("http://127.0.0.1:8080", token, "dev_abc123");
        assert_eq!(client.device_id(), "dev_abc123");
        assert_ne!(client.device_id(), token);
    }

    #[test]
    fn bearer_shaped_device_id_env_is_rejected() {
        let token =
            "sqreen_device_cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";
        let client = CloudClient::new_with_device_id("http://127.0.0.1:8080", token, token);
        assert!(client.device_id().is_empty());
    }

    #[test]
    fn trims_trailing_slash_from_base_url() {
        assert_eq!(
            trim_trailing_slash("http://localhost:8080/"),
            "http://localhost:8080"
        );
    }
}
