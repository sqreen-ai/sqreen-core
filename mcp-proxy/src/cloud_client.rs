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

use crate::policy::{load_config_cache, load_config_optional, persist_config_cache, PolicyConfig};
use crate::threat_intel::{resolve_local_threat_intel_path, ThreatIntelFeed, ThreatIntelMatcher};

/// Environment variable for the control plane base URL (e.g. `http://localhost:8080`).
pub const CONTROL_PLANE_URL_ENV: &str = "MCP_CONTROL_PLANE_URL";

/// Environment variable for the edge device authentication token.
pub const DEVICE_TOKEN_ENV: &str = "MCP_DEVICE_TOKEN";

/// Header name required by the control plane for device authentication.
pub const DEVICE_TOKEN_HEADER: &str = "X-Device-Token";

const POLICY_SYNC_PATH: &str = "/api/v1/policy/sync";
const THREAT_INTEL_SYNC_PATH: &str = "/api/v1/threat-intel/sync";
const TELEMETRY_PATH: &str = "/api/v1/telemetry/log";
const DEFAULT_REQUEST_TIMEOUT: Duration = Duration::from_secs(5);
const CLOUD_POLICY_CACHE_NAME: &str = "mcp-policy.cloud.json";
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
        }
    }
}

/// Network client for policy sync and asynchronous telemetry dispatch.
#[derive(Clone)]
pub struct CloudClient {
    http: reqwest::Client,
    base_url: String,
    device_token: String,
    policy_cache_path: PathBuf,
    threat_intel_cache_path: PathBuf,
    local_threat_intel_path: PathBuf,
}

impl CloudClient {
    /// Creates a client targeting `base_url` with the given device token.
    pub fn new(base_url: &str, device_token: &str) -> Self {
        let http = reqwest::Client::builder()
            .timeout(DEFAULT_REQUEST_TIMEOUT)
            .build()
            .expect("reqwest client should build");

        Self {
            http,
            base_url: trim_trailing_slash(base_url),
            device_token: device_token.to_string(),
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

    /// Returns the device identifier attached to outbound telemetry records.
    pub fn device_id(&self) -> &str {
        &self.device_token
    }

    /// Pulls the latest policy from the control plane, falling back to local cache on failure.
    pub async fn fetch_latest_policy(&self) -> Result<(PolicyConfig, PolicySyncSource)> {
        match self.fetch_remote_policy().await {
            Ok(config) => {
                if let Err(error) = persist_config_cache(&config, &self.policy_cache_path) {
                    eprintln!("mcp-proxy cloud: failed to persist policy cache: {error:#}");
                }
                Ok((config, PolicySyncSource::ControlPlane))
            }
            Err(remote_error) => {
                eprintln!("mcp-proxy cloud: remote policy sync failed: {remote_error:#}");
                self.load_local_fallback()
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
                    eprintln!(
                        "mcp-proxy cloud: failed to persist threat-intel cache: {error:#}"
                    );
                }
                Ok((feed, ThreatIntelSyncSource::ControlPlane))
            }
            Err(remote_error) => {
                eprintln!("mcp-proxy cloud: remote threat-intel sync failed: {remote_error:#}");
                self.load_threat_intel_fallback()
            }
        }
    }

    /// Dispatches telemetry without blocking the active relay task.
    pub fn dispatch_telemetry(&self, record: TelemetryRecord) {
        let client = self.clone();
        tokio::spawn(async move {
            if let Err(error) = client.post_telemetry(record).await {
                eprintln!("mcp-proxy cloud: telemetry dispatch failed: {error:#}");
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

    async fn fetch_remote_policy(&self) -> Result<PolicyConfig> {
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

        response
            .json::<PolicyConfig>()
            .await
            .context("failed to decode policy sync response")
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

    fn load_local_fallback(&self) -> Result<(PolicyConfig, PolicySyncSource)> {
        if let Some(config) = load_config_cache(&self.policy_cache_path)? {
            eprintln!(
                "mcp-proxy cloud: loaded cached policy v{} from {}",
                config.version,
                self.policy_cache_path.display()
            );
            return Ok((config, PolicySyncSource::Cache));
        }

        if let Some(config) = load_config_optional()? {
            eprintln!(
                "mcp-proxy cloud: loaded local policy v{} from disk",
                config.version
            );
            return Ok((config, PolicySyncSource::LocalYaml));
        }

        anyhow::bail!("control plane unreachable and no local policy cache is available")
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

    fn auth_headers(&self) -> HeaderMap {
        let mut headers = HeaderMap::new();
        headers.insert(
            DEVICE_TOKEN_HEADER,
            HeaderValue::from_str(&self.device_token)
                .unwrap_or_else(|_| HeaderValue::from_static("invalid-token")),
        );
        headers
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
        };

        let json = serde_json::to_string(&record).expect("serialize");
        assert!(json.contains("\"device_id\":\"laptop-abc123\""));
        assert!(json.contains("\"user_decision\":\"denied\""));
        assert!(json.contains("\"risk_score\":82"));
    }

    #[test]
    fn trims_trailing_slash_from_base_url() {
        assert_eq!(
            trim_trailing_slash("http://localhost:8080/"),
            "http://localhost:8080"
        );
    }
}
