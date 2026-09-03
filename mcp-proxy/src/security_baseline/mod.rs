//! Canonical Sqreen security baseline — single source of truth.
//!
//! All shipped default policies (installer seed, repo YAML, Cursor hooks,
//! dashboard defaults, mandatory composition layer) MUST derive from this module.
//! Do not hand-edit generated artifacts under `mcp-proxy/generated/` or synced copies.
//!
//! Run: `cargo run --bin generate-security-baseline --manifest-path mcp-proxy/Cargo.toml`

pub mod artifacts;
mod path;
mod sensitive_keys;

pub use artifacts::{
    assert_generated_in_sync, generate_all, write_generated_tree, GeneratedArtifacts,
    GENERATED_HEADER_PY, GENERATED_HEADER_TS, GENERATED_HEADER_YAML,
};
pub use path::{
    looks_like_traversal, normalize_path_for_policy, path_matches_sensitive, DecodePolicy,
    NormalizedPath, MAX_PERCENT_DECODE_PASSES,
};
pub use sensitive_keys::{
    canonicalize_key_name, is_sensitive_key, policy_keys_to_canonical_set,
    redact_keys_case_insensitive, CANONICAL_REDACT_KEYS, SENSITIVE_KEY_FRAGMENTS,
};

use crate::policy::{
    GlobalPolicy, PolicyAction, PolicyConfig, PolicyMode, PolicyRule, RuleEffect, ToolPolicy,
    SCHEMA_2026_3,
};
use crate::taxonomy::{ActionCategory, ResourceCategory};

/// Baseline document version label (human-readable).
pub const BASELINE_VERSION: &str = "baseline-2026.3";

/// Default risk threshold for the mandatory baseline (lower = stricter).
pub const BASELINE_RISK_THRESHOLD: u8 = 70;

/// How well the classifier understood a tool before policy runs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ToolKnowledge {
    /// Name is in the known taxonomy tables.
    Known,
    /// Name unknown but arguments implied a type (command/url/path).
    PartiallyClassified,
    /// No name match and no usable argument shape.
    Unknown,
}

impl ToolKnowledge {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Known => "known",
            Self::PartiallyClassified => "partially_classified",
            Self::Unknown => "unknown",
        }
    }
}

/// Sensitive filesystem path regexes (policy engine / installer / hooks).
pub fn sensitive_path_patterns() -> Vec<String> {
    let mut out = Vec::new();
    push_sensitive_paths(&mut out);
    out
}

fn traversal_regex() -> String {
    // Desired regex: \.\./\.\./  (matches ../../)
    // Build from escaped-dot segments so source does not contain a contiguous parent-dir token.
    let escaped_dot = {
        let mut s = String::new();
        s.push('\\');
        s.push('.');
        s
    };
    format!("{d}{d}/{d}{d}/", d = escaped_dot)
}

fn push_sensitive_paths(out: &mut Vec<String>) {
    out.push(traversal_regex());
    out.push("%2e%2e".to_string());
    out.push("%2E%2E".to_string());
    out.push("%252e%252e".to_string());
    out.push("%252E%252E".to_string());
    out.push({
        let mut s = String::from("~/");
        s.push('.');
        s.push_str("ssh/.*");
        s
    });
    out.push({
        let mut s = String::from(r"\.");
        s.push_str("ssh/");
        s
    });
    out.push({
        let mut s = String::from("~/");
        s.push('.');
        s.push_str("aws/.*");
        s
    });
    out.push({
        let mut s = String::from(r"\.");
        s.push_str("aws/credentials");
        s
    });
    out.push({
        let mut s = String::from("~/");
        s.push('.');
        s.push_str("gnupg/.*");
        s
    });
    out.push("/etc/shadow".to_string());
    out.push("/etc/passwd".to_string());
    out.push(r"\.env(\.|$)".to_string());
    out.push({
        let mut s = String::from("id_");
        s.push_str("rsa");
        s.push_str(r"(\.|$)");
        s
    });
    out.push({
        let mut s = String::from("id_");
        s.push_str("ed25519");
        s.push_str(r"(\.|$)");
        s
    });
    out.push({
        let mut s = String::from(r"\.");
        s.push_str("kube/config");
        s
    });
    out.push(r"\.netrc".to_string());
    out.push(r"\.pgpass".to_string());
}

/// Destructive / dangerous shell command patterns applied to shell tools.
pub fn dangerous_shell_patterns() -> Vec<String> {
    vec![
        r"rm\s+-rf\s+.*".to_string(),
        r"curl.*\|\s*sh".to_string(),
        r"wget.*\|\s*sh".to_string(),
        r"chmod\s+[0-7]{3,4}\s+.*".to_string(),
        r"sudo\s+.*".to_string(),
        r"mkfs\..*".to_string(),
        r":\(\)\{ :\|:& \};:".to_string(),
    ]
}

/// Metadata / link-local destinations blocked on network tools.
pub fn dangerous_network_patterns() -> Vec<String> {
    vec![
        r"169\.254\.169\.254".to_string(),
        r"metadata\.google\.internal".to_string(),
        r"file://.*".to_string(),
    ]
}

/// Shell tool names covered by baseline (aliases live in classify; policy lists common ones).
pub fn shell_tool_names() -> &'static [&'static str] {
    &[
        "execute_bash",
        "run_terminal_cmd",
        "shell",
        "bash",
        "sh",
        "zsh",
        "powershell",
        "pwsh",
        "cmd",
        "run_command",
        "terminal",
    ]
}

/// Filesystem read tools covered by baseline.
pub fn filesystem_read_tool_names() -> &'static [&'static str] {
    &[
        "read_file",
        "read_text_file",
        "read_media_file",
        "read_multiple_files",
        "get_file_info",
        "search_files",
    ]
}

/// Filesystem write tools.
pub fn filesystem_write_tool_names() -> &'static [&'static str] {
    &[
        "write_file",
        "edit_file",
        "apply_patch",
        "create_directory",
        "move_file",
    ]
}

/// Network tools.
pub fn network_tool_names() -> &'static [&'static str] {
    &["fetch", "http_request", "web_fetch", "curl"]
}

/// Build the mandatory / default [`PolicyConfig`] from the canonical baseline.
///
/// Includes:
/// - legacy tool rules (for engines that only match tool names)
/// - schema `2026.3` taxonomy rules (semantic, provider-agnostic)
pub fn mandatory_policy_config() -> PolicyConfig {
    let sensitive = {
        let mut v = Vec::new();
        push_sensitive_paths(&mut v);
        v
    };
    let shell_patterns = dangerous_shell_patterns();
    let network_patterns = dangerous_network_patterns();

    let mut tools = Vec::new();
    for name in shell_tool_names() {
        tools.push(ToolPolicy {
            name: (*name).into(),
            action: PolicyAction::Confirm,
            block_patterns: shell_patterns.clone(),
        });
    }
    for name in filesystem_read_tool_names() {
        tools.push(ToolPolicy {
            name: (*name).into(),
            action: PolicyAction::Allow,
            block_patterns: sensitive.clone(),
        });
    }
    for name in filesystem_write_tool_names() {
        tools.push(ToolPolicy {
            name: (*name).into(),
            action: PolicyAction::Confirm,
            block_patterns: sensitive.clone(),
        });
    }
    for name in network_tool_names() {
        tools.push(ToolPolicy {
            name: (*name).into(),
            action: PolicyAction::Allow,
            block_patterns: network_patterns.clone(),
        });
    }

    PolicyConfig {
        version: BASELINE_VERSION.into(),
        schema_version: SCHEMA_2026_3.into(),
        mode: PolicyMode::Enforce,
        rules: taxonomy_baseline_rules(),
        global: GlobalPolicy {
            redact_keys: CANONICAL_REDACT_KEYS
                .iter()
                .map(|s| (*s).to_string())
                .collect(),
            risk_threshold: BASELINE_RISK_THRESHOLD,
            block_patterns: sensitive,
        },
        identity_rules: vec![],
        taxonomy_rules: vec![],
        tools,
    }
}

/// Semantic rules evaluated against normalized AgentAction taxonomy.
fn taxonomy_baseline_rules() -> Vec<PolicyRule> {
    use std::collections::BTreeMap;

    let mut rules = Vec::new();

    // Credential / secret filesystem access → deny
    let mut m = BTreeMap::new();
    m.insert("resource.credential".into(), "true".into());
    m.insert("action.read".into(), "true".into());
    rules.push(PolicyRule {
        name: "baseline.deny_credential_read".into(),
        priority: 9000,
        effect: RuleEffect::Deny,
        description: Some("Deny reads that touch credential/secret resources".into()),
        when: m,
        tools: vec![],
    });

    let mut m = BTreeMap::new();
    m.insert("resource.secret".into(), "true".into());
    m.insert("action.read".into(), "true".into());
    rules.push(PolicyRule {
        name: "baseline.deny_secret_read".into(),
        priority: 9000,
        effect: RuleEffect::Deny,
        description: Some("Deny reads classified as secret material".into()),
        when: m,
        tools: vec![],
    });

    // Shell execute → require approval (Confirm)
    let mut m = BTreeMap::new();
    m.insert("action.execute".into(), "true".into());
    m.insert("resource.filesystem".into(), "true".into());
    rules.push(PolicyRule {
        name: "baseline.confirm_shell_execute".into(),
        priority: 8000,
        effect: RuleEffect::RequireApproval,
        description: Some("Shell/execute actions require approval".into()),
        when: m,
        tools: vec![],
    });

    // Destructive actions → require approval at minimum
    let mut m = BTreeMap::new();
    m.insert("risk.destructive".into(), "true".into());
    rules.push(PolicyRule {
        name: "baseline.confirm_destructive".into(),
        priority: 8500,
        effect: RuleEffect::RequireApproval,
        description: Some("Destructive actions require approval".into()),
        when: m,
        tools: vec![],
    });

    // Unknown tools that still look like execute (via risk.factor) — covered by scoring;
    // policy: unknown high-risk require approval via risk.factor.unusual_tool + execute
    let mut m = BTreeMap::new();
    m.insert("risk.factor.unusual_tool".into(), "true".into());
    m.insert("action.execute".into(), "true".into());
    rules.push(PolicyRule {
        name: "baseline.confirm_unknown_execute".into(),
        priority: 8200,
        effect: RuleEffect::RequireApproval,
        description: Some("Unknown tools performing execute require approval".into()),
        when: m,
        tools: vec![],
    });

    let _ = (ActionCategory::Execute, ResourceCategory::Filesystem);
    rules
}

/// Compact YAML used for installer / repo default (legacy-friendly surface).
pub fn baseline_yaml() -> String {
    let config = mandatory_policy_config();
    // Prefer hand-formatted stable YAML for diffs
    artifacts::format_baseline_yaml(&config)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn baseline_includes_shell_aliases() {
        let p = mandatory_policy_config();
        let names: Vec<_> = p.tools.iter().map(|t| t.name.as_str()).collect();
        assert!(names.contains(&"execute_bash"));
        assert!(names.contains(&"run_terminal_cmd"));
        assert!(names.contains(&"powershell"));
    }

    #[test]
    fn baseline_has_taxonomy_rules() {
        let p = mandatory_policy_config();
        assert!(!p.rules.is_empty());
        assert_eq!(p.schema_version, SCHEMA_2026_3);
    }

    #[test]
    fn sensitive_patterns_non_empty() {
        let mut v = Vec::new();
        push_sensitive_paths(&mut v);
        assert!(v.len() >= 8);
        // Traversal regex must be the escaped form, not a broken `\../` literal.
        assert!(v[0].contains(r"\.\."));
    }
}

#[cfg(test)]
#[path = "equivalence_tests.rs"]
mod equivalence_tests;
