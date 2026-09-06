//! Session-scoped tool history for correlation and local audit.
//!
//! Open-core keeps a bounded ring buffer for recording recent tool names.
//! Multi-step exfiltration-chain detection lives under the `enterprise` feature.

use std::collections::VecDeque;
use std::sync::Mutex;

/// Default ring-buffer capacity for recent tool calls.
pub const DEFAULT_SESSION_CAPACITY: usize = 10;

/// Minimum filesystem exploration calls historically used by enterprise chain detection.
pub const MIN_FILESYSTEM_PROBES: usize = 2;

/// Telemetry marker for behavioral exfiltration chain detections (enterprise).
pub const TELEMETRY_BEHAVIORAL_CHAIN: &str = "BEHAVIORAL_CHAIN_ANOMALY";

/// Filesystem tool names (shared taxonomy surface; used by enterprise detectors).
pub const FILESYSTEM_TOOLS: &[&str] = &[
    "read_file",
    "read_text_file",
    "read_media_file",
    "read_multiple_files",
    "get_file_info",
    "search_files",
    "list_directory",
    "glob_file_search",
    "directory_tree",
];

/// Tool names that perform outbound network requests directly.
pub const NETWORK_TOOLS: &[&str] = &["fetch", "http_request", "http_get", "http_post"];

/// Tool names that execute shell commands.
pub const SHELL_TOOLS: &[&str] = &["execute_bash", "run_terminal_cmd"];

/// Thread-safe sliding window of recent MCP tool invocations for one proxy session.
#[derive(Debug)]
pub struct SessionTracker {
    inner: Mutex<VecDeque<String>>,
    capacity: usize,
}

impl SessionTracker {
    /// Creates a tracker retaining the last `capacity` tool names (clamped 5–10).
    pub fn new(capacity: usize) -> Self {
        let capacity = capacity.clamp(5, DEFAULT_SESSION_CAPACITY);
        Self {
            inner: Mutex::new(VecDeque::with_capacity(capacity)),
            capacity,
        }
    }

    /// Records a tool invocation after policy/risk evaluation completes.
    pub fn record(&self, tool_name: &str) {
        let normalized = normalize_tool_name(tool_name);
        let mut history = self
            .inner
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());

        if history.len() >= self.capacity {
            history.pop_front();
        }
        history.push_back(normalized);
    }

    /// Records a normalized action after evaluation completes.
    pub fn record_action(&self, action: &crate::action::AgentAction) {
        self.record(action.tool_name());
    }

    /// Returns a snapshot of the current ring buffer (newest last).
    pub fn snapshot(&self) -> Vec<String> {
        self.inner
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .iter()
            .cloned()
            .collect()
    }

    /// Exfiltration-chain check — enterprise only; open-core always returns `false`.
    pub fn verify_behavioral_chain(&self, current_tool: &str, params_json: &str) -> bool {
        #[cfg(feature = "enterprise")]
        {
            crate::enterprise::exfil_chain::verify(self, current_tool, params_json)
        }
        #[cfg(not(feature = "enterprise"))]
        {
            let _ = (current_tool, params_json);
            false
        }
    }

    /// [`SessionTracker::verify_behavioral_chain`] for a normalized action.
    pub fn verify_action_chain(&self, action: &crate::action::AgentAction) -> bool {
        self.verify_behavioral_chain(action.tool_name(), action.canonical_params_json())
    }
}

impl Default for SessionTracker {
    fn default() -> Self {
        Self::new(DEFAULT_SESSION_CAPACITY)
    }
}

pub(crate) fn normalize_tool_name(tool_name: &str) -> String {
    tool_name.trim().to_ascii_lowercase()
}

pub(crate) fn is_filesystem_tool(tool_name: &str) -> bool {
    let name = normalize_tool_name(tool_name);
    FILESYSTEM_TOOLS.contains(&name.as_str())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn records_and_snapshots() {
        let tracker = SessionTracker::new(10);
        tracker.record("read_file");
        tracker.record("list_directory");
        assert_eq!(tracker.snapshot(), vec!["read_file", "list_directory"]);
    }

    #[test]
    #[cfg(not(feature = "enterprise"))]
    fn open_core_never_flags_exfil_chain() {
        let tracker = SessionTracker::new(10);
        tracker.record("read_file");
        tracker.record("list_directory");
        assert!(!tracker.verify_behavioral_chain(
            "fetch",
            r#"{"arguments":{"url":"https://example.com"}}"#
        ));
    }
}
