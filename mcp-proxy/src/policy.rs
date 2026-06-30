//! Declarative policy engine for MCP runtime traffic.
//!
//! # Design
//!
//! Policies are authored as YAML (`mcp-policy.yaml`) or synced as JSON from the control
//! plane, parsed once at startup, and compiled into regex-backed rules. At runtime the
//! engine evaluates `tools/call` payloads and returns a [`PolicyVerdict`].
//!
//! # Thread safety
//!
//! [`PolicyEngine`] is immutable after construction and may be shared across async relay
//! tasks via `Arc`. Regex sets are compiled at load time — no runtime mutation.
//!
//! # Fail-closed behavior
//!
//! - [`PolicyVerdict::Block`] prevents downstream forwarding.
//! - [`PolicyVerdict::Confirm`] logs and emits telemetry but does not alone block; the
//!   risk gate enforces operator confirmation when scores exceed threshold.
//! - [`PolicyVerdict::Redact`] rewrites the frame in place before forwarding.

use std::collections::{HashMap, HashSet};
use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};
use regex::Regex;
use serde::{Deserialize, Serialize};
use serde_json::Value;

/// Default policy file name in the working directory.
pub const DEFAULT_POLICY_FILE: &str = "mcp-policy.yaml";

/// Environment variable used to override the policy file path.
pub const POLICY_PATH_ENV: &str = "MCP_POLICY_PATH";

/// Top-level policy document loaded from YAML or JSON (control plane sync).
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
pub struct PolicyConfig {
    pub version: String,
    pub global: GlobalPolicy,
    pub tools: Vec<ToolPolicy>,
}

/// Global settings applied across all traffic.
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
pub struct GlobalPolicy {
    pub redact_keys: Vec<String>,
    #[serde(default = "default_risk_threshold")]
    pub risk_threshold: u8,
    /// Path patterns applied to every `tools/call`, regardless of tool name.
    #[serde(default)]
    pub block_patterns: Vec<String>,
}

fn default_risk_threshold() -> u8 {
    crate::risk::DEFAULT_RISK_THRESHOLD
}

/// Per-tool policy rule authored in YAML.
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
pub struct ToolPolicy {
    pub name: String,
    pub action: PolicyAction,
    pub block_patterns: Vec<String>,
}

/// Declarative action applied when a tool invocation is evaluated.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "PascalCase")]
pub enum PolicyAction {
    Allow,
    Block,
    Redact,
    Confirm,
}

/// Compiled, runtime-ready policy loaded at startup.
#[derive(Debug)]
pub struct PolicyEngine {
    version: String,
    redact_keys: HashSet<String>,
    risk_threshold: u8,
    global_block_patterns: Vec<Regex>,
    tools: HashMap<String, CompiledToolRule>,
}

#[derive(Debug)]
struct CompiledToolRule {
    action: PolicyAction,
    block_patterns: Vec<Regex>,
}

/// Outcome of evaluating a single frame against the active policy.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PolicyVerdict {
    Allow,
    Block { reason: String },
    Redact { frame: Vec<u8> },
    Confirm { message: String },
}

#[derive(Debug, Deserialize)]
struct ToolsCallParams {
    name: String,
    #[serde(default)]
    arguments: Value,
}

impl PolicyConfig {
    /// Parses a policy document from YAML text.
    pub fn from_yaml(source: &str) -> Result<Self> {
        serde_yaml::from_str(source).context("failed to parse policy yaml")
    }

    /// Parses a policy document from JSON (control plane sync payload).
    pub fn from_json(source: &str) -> Result<Self> {
        serde_json::from_str(source).context("failed to parse policy json")
    }
}

/// Loads a declarative policy document from the local YAML file, if present.
pub fn load_config_optional() -> Result<Option<PolicyConfig>> {
    let path = resolve_policy_path();
    if !path.exists() {
        return Ok(None);
    }

    let source = fs::read_to_string(&path)
        .with_context(|| format!("failed to read policy file at {}", path.display()))?;
    Ok(Some(PolicyConfig::from_yaml(&source)?))
}

/// Persists a synced policy document to the local JSON cache.
pub fn persist_config_cache(config: &PolicyConfig, path: &Path) -> Result<()> {
    let serialized =
        serde_json::to_string_pretty(config).context("failed to serialize policy cache")?;
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("failed to create policy cache dir {}", parent.display()))?;
    }
    fs::write(path, serialized)
        .with_context(|| format!("failed to write policy cache to {}", path.display()))?;
    Ok(())
}

/// Loads a previously synced policy document from the JSON cache.
pub fn load_config_cache(path: &Path) -> Result<Option<PolicyConfig>> {
    if !path.exists() {
        return Ok(None);
    }

    let source = fs::read_to_string(path)
        .with_context(|| format!("failed to read policy cache at {}", path.display()))?;
    Ok(Some(PolicyConfig::from_json(&source)?))
}

/// Merges remote (control plane) and local policy documents.
///
/// Remote values win for overlapping tool names and the global risk threshold.
/// Local tool rules fill gaps; redact keys and global block patterns are unioned.
pub fn merge_configs(remote: PolicyConfig, local: PolicyConfig) -> PolicyConfig {
    let mut tools_by_name: HashMap<String, ToolPolicy> = remote
        .tools
        .into_iter()
        .map(|tool| (tool.name.clone(), tool))
        .collect();

    for tool in local.tools {
        tools_by_name.entry(tool.name.clone()).or_insert(tool);
    }

    let mut redact_keys: HashSet<String> = remote.global.redact_keys.into_iter().collect();
    redact_keys.extend(local.global.redact_keys);

    let mut block_patterns: HashSet<String> = remote.global.block_patterns.into_iter().collect();
    block_patterns.extend(local.global.block_patterns);

    PolicyConfig {
        version: remote.version,
        global: GlobalPolicy {
            redact_keys: redact_keys.into_iter().collect(),
            risk_threshold: remote.global.risk_threshold,
            block_patterns: block_patterns.into_iter().collect(),
        },
        tools: tools_by_name.into_values().collect(),
    }
}

/// Builds a runtime engine, merging remote and local configs when both exist.
pub fn build_engine(
    remote_config: Option<PolicyConfig>,
    local_config: Option<PolicyConfig>,
) -> Result<Option<PolicyEngine>> {
    let config = match (remote_config, local_config) {
        (Some(remote), Some(local)) => Some(merge_configs(remote, local)),
        (Some(remote), None) => Some(remote),
        (None, Some(local)) => Some(local),
        (None, None) => None,
    };

    config.map(PolicyEngine::from_config).transpose()
}

impl PolicyEngine {
    /// Loads and compiles a policy file from disk.
    pub fn load(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref();
        let source = fs::read_to_string(path)
            .with_context(|| format!("failed to read policy file at {}", path.display()))?;
        Self::from_yaml(&source)
    }

    /// Loads a policy from the default path or [`POLICY_PATH_ENV`] override.
    ///
    /// Returns `None` when no policy file exists, allowing passthrough mode.
    pub fn load_optional() -> Result<Option<Self>> {
        let path = resolve_policy_path();
        if !path.exists() {
            return Ok(None);
        }
        Ok(Some(Self::load(path)?))
    }

    /// Compiles a parsed [`PolicyConfig`] into runtime matchers.
    pub fn from_config(config: PolicyConfig) -> Result<Self> {
        let mut tools = HashMap::new();

        for tool in config.tools {
            if tools.contains_key(&tool.name) {
                bail!("duplicate tool policy for `{}`", tool.name);
            }

            let block_patterns = compile_block_patterns(&tool.block_patterns, &tool.name)?;

            tools.insert(
                tool.name.clone(),
                CompiledToolRule {
                    action: tool.action,
                    block_patterns,
                },
            );
        }

        let global_block_patterns = compile_block_patterns(
            &config.global.block_patterns,
            "global",
        )?;

        Ok(Self {
            version: config.version,
            redact_keys: config.global.redact_keys.into_iter().collect(),
            risk_threshold: config.global.risk_threshold,
            global_block_patterns,
            tools,
        })
    }

    /// Parses YAML and compiles the resulting policy.
    pub fn from_yaml(source: &str) -> Result<Self> {
        Self::from_config(PolicyConfig::from_yaml(source)?)
    }

    /// Returns the configured policy schema version.
    pub fn version(&self) -> &str {
        &self.version
    }

    /// Returns the number of compiled per-tool rules.
    pub fn tool_count(&self) -> usize {
        self.tools.len()
    }

    /// Returns the configured interactive risk threshold.
    pub fn risk_threshold(&self) -> u8 {
        self.risk_threshold
    }

    /// Evaluates a `tools/call` params JSON payload from the client direction.
    pub fn evaluate_tools_call(&self, params_json: &str) -> PolicyVerdict {
        let Ok(params) = serde_json::from_str::<ToolsCallParams>(params_json) else {
            return PolicyVerdict::Allow;
        };

        let inspection_text = inspection_surface(&params);

        if let Some(matched) = self
            .global_block_patterns
            .iter()
            .find(|pattern| pattern.is_match(&inspection_text))
        {
            return PolicyVerdict::Block {
                reason: format!(
                    "global block pattern `{}` matched tool `{}`",
                    matched.as_str(),
                    params.name
                ),
            };
        }

        let Some(rule) = self.tools.get(&params.name) else {
            return PolicyVerdict::Allow;
        };

        if let Some(matched) = rule
            .block_patterns
            .iter()
            .find(|pattern| pattern.is_match(&inspection_text))
        {
            return PolicyVerdict::Block {
                reason: format!(
                    "tool `{}` matched block pattern `{}`",
                    params.name,
                    matched.as_str()
                ),
            };
        }

        match rule.action {
            PolicyAction::Allow => PolicyVerdict::Allow,
            PolicyAction::Block => PolicyVerdict::Block {
                reason: format!("tool `{}` is configured with action Block", params.name),
            },
            PolicyAction::Redact => PolicyVerdict::Redact {
                frame: redact_json_text(params_json, &self.redact_keys),
            },
            PolicyAction::Confirm => PolicyVerdict::Confirm {
                message: format!(
                    "confirmation required for tool `{}` invocation",
                    params.name
                ),
            },
        }
    }

    /// Applies global secret redaction to any JSON frame (for example server responses).
    pub fn redact_global_secrets(&self, frame: &[u8]) -> Vec<u8> {
        if self.redact_keys.is_empty() {
            return frame.to_vec();
        }

        let Ok(text) = std::str::from_utf8(frame) else {
            return frame.to_vec();
        };

        redact_json_text(text, &self.redact_keys)
    }
}

/// Builds a JSON-RPC error frame for a blocked request.
pub fn blocked_response(id: &Value, reason: &str) -> Vec<u8> {
    let response = serde_json::json!({
        "jsonrpc": "2.0",
        "id": id,
        "error": {
            "code": -32_000,
            "message": format!("blocked by mcp-proxy policy: {reason}"),
        }
    });

    response.to_string().into_bytes()
}

/// Builds a JSON-RPC error frame for a user-denied request.
pub fn access_denied_response(id: &Value, reason: &str) -> Vec<u8> {
    let response = serde_json::json!({
        "jsonrpc": "2.0",
        "id": id,
        "error": {
            "code": -32_003,
            "message": format!("access denied: {reason}"),
        }
    });

    response.to_string().into_bytes()
}

/// Re-wraps redacted params into a full `tools/call` JSON-RPC request frame.
pub fn rewrite_tools_call_frame(original_frame: &[u8], redacted_params: &[u8]) -> Result<Vec<u8>> {
    let mut value: Value =
        serde_json::from_slice(original_frame).context("failed to parse request frame")?;
    let params_value: Value =
        serde_json::from_slice(redacted_params).context("failed to parse redacted params")?;

    if let Some(object) = value.as_object_mut() {
        object.insert("params".to_string(), params_value);
    }

    Ok(value.to_string().into_bytes())
}

fn resolve_policy_path() -> PathBuf {
    std::env::var(POLICY_PATH_ENV)
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from(DEFAULT_POLICY_FILE))
}

fn inspection_surface(params: &ToolsCallParams) -> String {
    match &params.arguments {
        Value::Null => params.name.clone(),
        other => other.to_string(),
    }
}

fn compile_block_patterns(patterns: &[String], scope: &str) -> Result<Vec<Regex>> {
    patterns
        .iter()
        .enumerate()
        .map(|(index, pattern)| {
            Regex::new(pattern).with_context(|| {
                format!("invalid {scope} block_pattern `{pattern}` at index {index}")
            })
        })
        .collect()
}

fn redact_json_text(source: &str, keys: &HashSet<String>) -> Vec<u8> {
    match serde_json::from_str::<Value>(source) {
        Ok(mut value) => {
            redact_value(&mut value, keys);
            value.to_string().into_bytes()
        }
        Err(_) => source.as_bytes().to_vec(),
    }
}

fn redact_value(value: &mut Value, keys: &HashSet<String>) {
    match value {
        Value::Object(map) => {
            for (key, entry) in map.iter_mut() {
                if keys.contains(key) {
                    *entry = Value::String("[REDACTED]".to_string());
                } else {
                    redact_value(entry, keys);
                }
            }
        }
        Value::Array(items) => {
            for item in items {
                redact_value(item, keys);
            }
        }
        _ => {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const EXAMPLE_POLICY: &str = r#"
version: "1"
global:
  redact_keys: ["OPENAI_API_KEY", "STRIPE_SECRET_KEY", "AWS_SECRET_ACCESS_KEY"]
tools:
  - name: "execute_bash"
    action: "Confirm"
    block_patterns: ["rm -rf .*", "curl.*\\|sh", "chmod .*"]
  - name: "read_file"
    action: "Allow"
    block_patterns: ["\\.\\./\\.\\./", "~/.ssh/.*", "~/.aws/.*"]
"#;

    #[test]
    fn parses_example_policy_yaml() {
        let config = PolicyConfig::from_yaml(EXAMPLE_POLICY).expect("policy should parse");
        assert_eq!(config.version, "1");
        assert_eq!(config.global.redact_keys.len(), 3);
        assert_eq!(config.tools.len(), 2);
        assert_eq!(config.tools[0].name, "execute_bash");
        assert_eq!(config.tools[0].action, PolicyAction::Confirm);
    }

    #[test]
    fn blocks_dangerous_bash_command() {
        let engine = PolicyEngine::from_yaml(EXAMPLE_POLICY).expect("compile policy");
        let params = r#"{"name":"execute_bash","arguments":{"command":"rm -rf /"}}"#;

        assert!(matches!(
            engine.evaluate_tools_call(params),
            PolicyVerdict::Block { .. }
        ));
    }

    #[test]
    fn confirms_non_blocked_bash_command() {
        let engine = PolicyEngine::from_yaml(EXAMPLE_POLICY).expect("compile policy");
        let params = r#"{"name":"execute_bash","arguments":{"command":"ls -la"}}"#;

        assert!(matches!(
            engine.evaluate_tools_call(params),
            PolicyVerdict::Confirm { .. }
        ));
    }

    #[test]
    fn blocks_sensitive_file_reads() {
        let engine = PolicyEngine::from_yaml(EXAMPLE_POLICY).expect("compile policy");
        let params = r#"{"name":"read_file","arguments":{"path":"~/.ssh/id_rsa"}}"#;

        assert!(matches!(
            engine.evaluate_tools_call(params),
            PolicyVerdict::Block { .. }
        ));
    }

    #[test]
    fn allows_safe_file_reads() {
        let engine = PolicyEngine::from_yaml(EXAMPLE_POLICY).expect("compile policy");
        let params = r#"{"name":"read_file","arguments":{"path":"/tmp/readme.txt"}}"#;

        assert_eq!(engine.evaluate_tools_call(params), PolicyVerdict::Allow);
    }

    #[test]
    fn global_block_patterns_apply_to_unknown_tools() {
        let policy = r#"
version: "1"
global:
  redact_keys: []
  block_patterns: ["\\.ssh/"]
tools: []
"#;
        let engine = PolicyEngine::from_yaml(policy).expect("compile policy");
        let params =
            r#"{"name":"get_file_info","arguments":{"path":"/Users/seddik/.ssh/id_rsa"}}"#;

        assert!(matches!(
            engine.evaluate_tools_call(params),
            PolicyVerdict::Block { .. }
        ));
    }

    #[test]
    fn merge_configs_fills_missing_remote_tools_from_local() {
        let remote = PolicyConfig {
            version: "1".to_string(),
            global: GlobalPolicy {
                redact_keys: vec!["REMOTE".to_string()],
                risk_threshold: 55,
                block_patterns: vec![],
            },
            tools: vec![ToolPolicy {
                name: "read_file".to_string(),
                action: PolicyAction::Allow,
                block_patterns: vec!["~/.ssh/.*".to_string()],
            }],
        };
        let local = PolicyConfig {
            version: "1".to_string(),
            global: GlobalPolicy {
                redact_keys: vec!["LOCAL".to_string()],
                risk_threshold: 70,
                block_patterns: vec!["\\.ssh/".to_string()],
            },
            tools: vec![ToolPolicy {
                name: "get_file_info".to_string(),
                action: PolicyAction::Allow,
                block_patterns: vec!["\\.ssh/".to_string()],
            }],
        };

        let merged = merge_configs(remote, local);
        assert_eq!(merged.global.risk_threshold, 55);
        assert!(merged.global.block_patterns.contains(&"\\.ssh/".to_string()));
        assert_eq!(merged.tools.len(), 2);
    }

    #[test]
    fn redacts_global_secret_keys() {
        let engine = PolicyEngine::from_yaml(EXAMPLE_POLICY).expect("compile policy");
        let frame = br#"{"OPENAI_API_KEY":"sk-secret","nested":{"STRIPE_SECRET_KEY":"abc"}}"#;
        let redacted = engine.redact_global_secrets(frame);
        let text = String::from_utf8(redacted).expect("utf8");

        assert!(text.contains("[REDACTED]"));
        assert!(!text.contains("sk-secret"));
        assert!(!text.contains("\"abc\""));
    }
}
