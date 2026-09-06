//! Local activity markers for truthful status (not a credential store).
//!
//! Records the last protected evaluation and last successful Cloud contact so
//! `mcp-proxy status` can distinguish **configured** from **verified**.
//!
//! Writes are best-effort and must never affect enforcement decisions.

use std::fs;
use std::path::PathBuf;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

const ACTIVITY_FILE: &str = "activity.json";

/// How long a protected evaluation counts as "verified active" coverage.
pub const PROTECTED_VERIFY_WINDOW: chrono::Duration = chrono::Duration::hours(24);

/// How long a successful Cloud contact counts as "connection verified".
pub const CLOUD_VERIFY_WINDOW: chrono::Duration = chrono::Duration::hours(1);

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct ActivitySnapshot {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_protected_at: Option<DateTime<Utc>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_protected_tool: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_protected_decision: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_protected_runtime: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_cloud_ok_at: Option<DateTime<Utc>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_cloud_err_at: Option<DateTime<Utc>>,
}

fn activity_path() -> PathBuf {
    crate::local_env::config_dir().join(ACTIVITY_FILE)
}

/// Loads activity markers (empty if missing/corrupt).
pub fn load() -> ActivitySnapshot {
    let path = activity_path();
    let Ok(text) = fs::read_to_string(&path) else {
        return ActivitySnapshot::default();
    };
    serde_json::from_str(&text).unwrap_or_default()
}

fn save(snapshot: &ActivitySnapshot) {
    let dir = crate::local_env::config_dir();
    if fs::create_dir_all(&dir).is_err() {
        return;
    }
    let path = dir.join(ACTIVITY_FILE);
    let Ok(body) = serde_json::to_string_pretty(snapshot) else {
        return;
    };
    let _ = fs::write(&path, body);
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = fs::set_permissions(&path, fs::Permissions::from_mode(0o600));
    }
}

/// Records that Sqreen evaluated a real agent tool action on the MCP stdio wrap path.
///
/// OpenAI HTTP `serve` currently evaluates response `tool_calls` but does **not** call this
/// (coverage minting for serve is tracked separately).
pub fn record_protected_evaluation(runtime: &str, tool: &str, decision: &str) {
    let mut snap = load();
    snap.last_protected_at = Some(Utc::now());
    snap.last_protected_runtime = Some(runtime.to_string());
    snap.last_protected_tool = Some(tool.to_string());
    snap.last_protected_decision = Some(decision.to_string());
    save(&snap);
}

/// Records a successful authenticated Cloud exchange (telemetry or policy sync).
pub fn record_cloud_ok() {
    let mut snap = load();
    snap.last_cloud_ok_at = Some(Utc::now());
    save(&snap);
}

/// Records a failed Cloud exchange (reachability / auth). Does not clear last OK.
pub fn record_cloud_err() {
    let mut snap = load();
    snap.last_cloud_err_at = Some(Utc::now());
    save(&snap);
}

/// True when a protected evaluation was recorded inside [`PROTECTED_VERIFY_WINDOW`].
pub fn protected_traffic_verified(now: DateTime<Utc>) -> bool {
    match load().last_protected_at {
        Some(at) => now.signed_duration_since(at) <= PROTECTED_VERIFY_WINDOW,
        None => false,
    }
}

/// Human-readable age string for a timestamp, or None.
pub fn format_age(at: DateTime<Utc>, now: DateTime<Utc>) -> String {
    let secs = now.signed_duration_since(at).num_seconds().max(0);
    if secs < 60 {
        format!("{secs}s ago")
    } else if secs < 3600 {
        format!("{}m ago", secs / 60)
    } else if secs < 86400 {
        format!("{}h ago", secs / 3600)
    } else {
        format!("{}d ago", secs / 86400)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::local_env::test_env_lock;

    #[test]
    fn records_and_loads_protected_evaluation() {
        let _guard = test_env_lock();
        let tmp = std::env::temp_dir().join(format!("sqreen-activity-{}", std::process::id()));
        let _ = fs::remove_dir_all(&tmp);
        fs::create_dir_all(&tmp).unwrap();
        unsafe {
            std::env::set_var("HOME", &tmp);
            std::env::remove_var("XDG_CONFIG_HOME");
        }
        assert!(!protected_traffic_verified(Utc::now()));
        record_protected_evaluation("mcp_stdio", "read_file", "deny");
        let snap = load();
        assert!(snap.last_protected_at.is_some());
        assert_eq!(snap.last_protected_tool.as_deref(), Some("read_file"));
        assert!(protected_traffic_verified(Utc::now()));
        let _ = fs::remove_dir_all(&tmp);
    }
}
