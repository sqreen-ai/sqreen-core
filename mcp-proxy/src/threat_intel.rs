//! Local threat-intelligence IOC matcher for domains and IP blocklists.
//!
//! Indicators are loaded once at startup and matched with ASCII case-insensitive
//! substring scans — no per-request heap allocation on the hot path.

use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::{RwLock};
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};

/// Environment variable pointing at a newline-delimited IOC file.
pub const THREAT_INTEL_PATH_ENV: &str = "MCP_THREAT_INTEL_PATH";

/// Default IOC file location (one indicator per line, `#` comments ignored).
pub const DEFAULT_THREAT_INTEL_FILE: &str = "threat-intel.txt";

/// Minimum interval between control-plane threat-intel sync attempts.
pub const THREAT_INTEL_REFRESH_INTERVAL: Duration = Duration::from_secs(5);

/// Risk score for IOC matches — always exceeds default block thresholds.
pub const IOC_BLOCK_SCORE: u8 = 100;

/// Telemetry marker appended for control-plane ingest when an IOC hits.
pub const TELEMETRY_IOC_MATCH: &str = "THREAT_INTEL_IOC_MATCH";

/// Remote threat-intel document synced from the control plane.
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
pub struct ThreatIntelFeed {
    pub version: String,
    pub indicators: Vec<String>,
}

/// Fast local matcher over normalized lowercase indicators.
#[derive(Debug, Clone)]
pub struct ThreatIntelMatcher {
    indicators: Vec<String>,
}

impl ThreatIntelMatcher {
    /// Fast compile from a blacklist slice (C2 domains, IP blocks, malicious registries).
    ///
    /// Indicators are normalized once at init; the hot path only scans haystacks with
    /// ASCII case-insensitive substring windows — no per-call allocations.
    pub fn from_blacklist(indicators: &[&str]) -> Self {
        Self::from_indicators(indicators.iter().copied())
    }

    /// Builds a matcher from an explicit indicator list (domains, IPs, host fragments).
    pub fn from_indicators<'a>(indicators: impl IntoIterator<Item = &'a str>) -> Self {
        let mut normalized = indicators
            .into_iter()
            .map(str::trim)
            .filter(|line| !line.is_empty() && !line.starts_with('#'))
            .map(str::to_ascii_lowercase)
            .collect::<Vec<_>>();
        normalized.sort_unstable();
        normalized.dedup();
        Self {
            indicators: normalized,
        }
    }

    /// Loads indicators from a local file; missing files yield an empty matcher.
    pub fn from_file(path: &Path) -> Self {
        match fs::read_to_string(path) {
            Ok(contents) => Self::from_indicators(contents.lines()),
            Err(_) => Self::from_indicators(std::iter::empty()),
        }
    }

    /// Loads from [`THREAT_INTEL_PATH_ENV`] or `~/.config/mcp-proxy/threat-intel.txt`.
    pub fn load_optional() -> Self {
        Self::from_file(&resolve_local_threat_intel_path())
    }

    /// Merges remote indicators with the current local set (deduplicated).
    pub fn merge_remote(&self, remote: &[String]) -> Self {
        let mut parts: Vec<&str> = self.indicators.iter().map(String::as_str).collect();
        parts.extend(remote.iter().map(String::as_str));
        Self::from_indicators(parts)
    }

    /// Returns the compiled indicator strings (lowercase).
    pub fn indicators(&self) -> &[String] {
        &self.indicators
    }

    /// Returns the number of compiled indicators.
    pub fn indicator_count(&self) -> usize {
        self.indicators.len()
    }

    /// Returns `true` when `input` contains a blacklisted domain or IP fragment.
    pub fn matches_ioc(&self, input: &str) -> bool {
        if self.indicators.is_empty() || input.is_empty() {
            return false;
        }

        self.indicators
            .iter()
            .any(|indicator| contains_ascii_ci(input, indicator))
    }

    /// Scans a full `tools/call` params JSON payload for IOC hits.
    pub fn matches_payload(&self, params_json: &str) -> bool {
        self.matches_ioc(params_json)
    }
}

/// Thread-safe, periodically refreshed threat-intel snapshot.
#[derive(Debug)]
pub struct ThreatIntelStore {
    matcher: RwLock<ThreatIntelMatcher>,
    last_refresh: RwLock<Instant>,
    local_path: PathBuf,
}

impl ThreatIntelStore {
    /// Creates a store seeded with indicators loaded at process startup.
    pub fn new(initial: ThreatIntelMatcher) -> Self {
        Self {
            matcher: RwLock::new(initial),
            last_refresh: RwLock::new(
                Instant::now()
                    .checked_sub(THREAT_INTEL_REFRESH_INTERVAL)
                    .unwrap_or_else(Instant::now),
            ),
            local_path: resolve_local_threat_intel_path(),
        }
    }

    /// Returns the current compiled matcher.
    pub fn snapshot(&self) -> ThreatIntelMatcher {
        self.matcher
            .read()
            .ok()
            .map(|guard| guard.clone())
            .unwrap_or_else(|| ThreatIntelMatcher::from_indicators([] as [&str; 0]))
    }

    /// Reloads indicators when the refresh interval has elapsed.
    pub async fn refresh_if_stale(
        &self,
        cloud_client: Option<&crate::cloud_client::CloudClient>,
    ) {
        let stale = self
            .last_refresh
            .read()
            .map(|instant| instant.elapsed() >= THREAT_INTEL_REFRESH_INTERVAL)
            .unwrap_or(true);

        if !stale {
            return;
        }

        let local = ThreatIntelMatcher::from_file(&self.local_path);
        let merged = if let Some(client) = cloud_client {
            match client.fetch_latest_threat_intel().await {
                Ok((feed, source)) => {
                    let label = match source {
                        crate::cloud_client::ThreatIntelSyncSource::ControlPlane => {
                            "control plane"
                        }
                        crate::cloud_client::ThreatIntelSyncSource::Cache => "cache",
                        crate::cloud_client::ThreatIntelSyncSource::LocalFile => "local file",
                    };
                    eprintln!(
                        "mcp-proxy: loaded threat-intel v{} from {label} ({} remote indicators, {} total)",
                        feed.version,
                        feed.indicators.len(),
                        local.merge_remote(&feed.indicators).indicator_count()
                    );
                    local.merge_remote(&feed.indicators)
                }
                Err(error) => {
                    eprintln!("mcp-proxy: cloud threat-intel sync unavailable: {error:#}");
                    local
                }
            }
        } else {
            local
        };

        if let Ok(mut guard) = self.matcher.write() {
            *guard = merged;
        }
        if let Ok(mut guard) = self.last_refresh.write() {
            *guard = Instant::now();
        }
    }
}

/// Loads local indicators merged with the control-plane feed when configured.
pub async fn load_threat_intel_matcher(
    cloud_client: Option<&crate::cloud_client::CloudClient>,
) -> ThreatIntelMatcher {
    let local = ThreatIntelMatcher::load_optional();

    let Some(client) = cloud_client else {
        return local;
    };

    match client.fetch_latest_threat_intel().await {
        Ok((feed, source)) => {
            let label = match source {
                crate::cloud_client::ThreatIntelSyncSource::ControlPlane => "control plane",
                crate::cloud_client::ThreatIntelSyncSource::Cache => "cache",
                crate::cloud_client::ThreatIntelSyncSource::LocalFile => "local file",
            };
            let merged = local.merge_remote(&feed.indicators);
            eprintln!(
                "mcp-proxy: loaded threat-intel v{} from {label} ({} indicators total)",
                feed.version,
                merged.indicator_count()
            );
            merged
        }
        Err(error) => {
            eprintln!("mcp-proxy: startup threat-intel sync unavailable: {error:#}");
            local
        }
    }
}

pub fn resolve_local_threat_intel_path() -> PathBuf {
    if let Ok(path) = env::var(THREAT_INTEL_PATH_ENV) {
        let trimmed = path.trim();
        if !trimmed.is_empty() {
            return PathBuf::from(trimmed);
        }
    }

    default_threat_intel_path()
}

fn default_threat_intel_path() -> PathBuf {
    dirs_fallback()
        .join("mcp-proxy")
        .join(DEFAULT_THREAT_INTEL_FILE)
}

fn dirs_fallback() -> PathBuf {
    if let Ok(home) = env::var("HOME") {
        return PathBuf::from(home).join(".config");
    }
    PathBuf::from(".")
}

/// ASCII case-insensitive substring search without allocating a lowered haystack.
fn contains_ascii_ci(haystack: &str, needle: &str) -> bool {
    if needle.is_empty() || haystack.len() < needle.len() {
        return false;
    }

    haystack
        .as_bytes()
        .windows(needle.len())
        .any(|window| window.eq_ignore_ascii_case(needle.as_bytes()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn matches_domains_case_insensitively() {
        let matcher = ThreatIntelMatcher::from_indicators([
            "evil-c2.example",
            "185.220.101.45",
            "malware.biz",
        ]);

        assert!(matcher.matches_ioc("https://Evil-C2.example/exfil"));
        assert!(matcher.matches_ioc("curl http://185.220.101.45:8080/beacon"));
        assert!(!matcher.matches_ioc("https://api.github.com/repos"));
    }

    #[test]
    fn merge_remote_deduplicates_indicators() {
        let local = ThreatIntelMatcher::from_indicators(["evil-c2.example"]);
        let merged = local.merge_remote(&[
            "evil-c2.example".to_string(),
            "bad.host".to_string(),
        ]);
        assert_eq!(merged.indicator_count(), 2);
        assert!(merged.matches_ioc("https://bad.host/x"));
    }

    #[test]
    fn loads_indicators_from_file() {
        let path = env::temp_dir().join(format!(
            "mcp-proxy-ioc-{}",
            std::process::id()
        ));
        fs::write(
            &path,
            "# comment\nbad.domain\n\n# another\n10.0.0.99\n",
        )
        .expect("write ioc file");

        let matcher = ThreatIntelMatcher::from_file(&path);
        let _ = fs::remove_file(&path);
        assert_eq!(matcher.indicator_count(), 2);
        assert!(matcher.matches_ioc("fetch https://bad.domain/payload"));
    }

    #[test]
    fn empty_matcher_never_hits() {
        let matcher = ThreatIntelMatcher::from_indicators([] as [&str; 0]);
        assert!(!matcher.matches_ioc("anything"));
    }

    #[test]
    fn from_blacklist_compiles_and_matches_payload_values() {
        let matcher = ThreatIntelMatcher::from_blacklist(&[
            "pastebin.com",
            "192.168.99.1",
        ]);
        assert!(matcher.matches_ioc(r#"{"arguments":{"url":"https://pastebin.com/raw/abc"}}"#));
        assert!(matcher.matches_payload(r#"{"name":"fetch","arguments":{"target":"192.168.99.1"}}"#));
        assert!(!matcher.matches_ioc("benign.local"));
    }

    #[test]
    fn store_snapshot_returns_clone() {
        let store = ThreatIntelStore::new(ThreatIntelMatcher::from_indicators(["evil-c2.example"]));
        assert_eq!(store.snapshot().indicator_count(), 1);
    }
}

