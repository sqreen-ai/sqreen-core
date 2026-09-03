//! Policy document schema — versioned, validated before activation.
//!
//! # Schema versions
//!
//! | Version   | Meaning |
//! |-----------|---------|
//! | `legacy`  | Implicit when `schema_version` is absent. Tool-centric YAML only. |
//! | `2026.3`  | Normalized rules on [`AgentAction`] + identity + taxonomy. |

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

/// Supported `schema_version` values.
pub const SCHEMA_LEGACY: &str = "legacy";
pub const SCHEMA_2026_3: &str = "2026.3";

pub const SUPPORTED_SCHEMA_VERSIONS: &[&str] = &[SCHEMA_LEGACY, SCHEMA_2026_3];

/// How a loaded policy document is applied at runtime.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PolicyMode {
    /// Matched effects are enforced.
    #[default]
    Enforce,
    /// Evaluate and audit what *would* happen; actions are not blocked by policy alone.
    Audit,
}

/// Effect of a matched rule.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RuleEffect {
    Allow,
    Deny,
    RequireApproval,
    /// Legacy: rewrite configured secret keys in the payload, then allow.
    Redact,
}

impl RuleEffect {
    pub fn severity(self) -> u8 {
        match self {
            Self::Deny => 3,
            Self::RequireApproval => 2,
            Self::Redact => 1,
            Self::Allow => 0,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Allow => "allow",
            Self::Deny => "deny",
            Self::RequireApproval => "require_approval",
            Self::Redact => "redact",
        }
    }
}

/// Declarative action applied when a tool invocation is evaluated (legacy YAML).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "PascalCase")]
pub enum PolicyAction {
    Allow,
    Block,
    Redact,
    Confirm,
}

impl From<PolicyAction> for RuleEffect {
    fn from(action: PolicyAction) -> Self {
        match action {
            PolicyAction::Allow => Self::Allow,
            PolicyAction::Block => Self::Deny,
            PolicyAction::Redact => Self::Redact,
            PolicyAction::Confirm => Self::RequireApproval,
        }
    }
}

/// Top-level policy document loaded from YAML or JSON (control plane sync).
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
pub struct PolicyConfig {
    /// Human-readable bundle identifier (also exposed as engine version).
    pub version: String,
    /// Schema version governing interpretation. Absent documents are treated as `legacy`.
    #[serde(default = "default_schema_version")]
    pub schema_version: String,
    /// Enforce matched effects, or audit-only (dry-run).
    #[serde(default)]
    pub mode: PolicyMode,
    /// Normalized rules — primary authoring surface for schema `2026.3`.
    #[serde(default)]
    pub rules: Vec<PolicyRule>,
    pub global: GlobalPolicy,
    #[serde(default)]
    pub identity_rules: Vec<IdentityRule>,
    #[serde(default)]
    pub taxonomy_rules: Vec<TaxonomyRule>,
    pub tools: Vec<ToolPolicy>,
}

fn default_schema_version() -> String {
    SCHEMA_LEGACY.to_string()
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

/// A normalized policy rule targeting agent identity, taxonomy, and resource shape.
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
pub struct PolicyRule {
    /// Stable name for audit attribution. Must be unique within the document.
    pub name: String,
    /// Higher priority wins conflicts **within the same trust layer**. Default `0`.
    /// Cross-layer authority uses tighten-only effect merge, not this number.
    #[serde(default)]
    pub priority: i32,
    /// What happens when every predicate matches.
    pub effect: RuleEffect,
    /// Operator-facing explanation recorded in audit logs.
    #[serde(default)]
    pub description: Option<String>,
    /// Predicates — every entry must match (logical AND).
    ///
    /// See [`crate::policy::match_ctx`] for supported field names.
    #[serde(default, rename = "match")]
    pub when: BTreeMap<String, String>,
    /// Optional tool-name filter. Empty means every tool.
    #[serde(default)]
    pub tools: Vec<String>,
}

/// One declarative rule keyed on agent identity rather than payload bytes (legacy).
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
pub struct IdentityRule {
    pub name: String,
    #[serde(default)]
    pub when: BTreeMap<String, String>,
    pub action: PolicyAction,
    #[serde(default)]
    pub tools: Vec<String>,
}

/// One declarative rule keyed on normalized security taxonomy (legacy transitional).
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
pub struct TaxonomyRule {
    pub name: String,
    #[serde(default)]
    pub when: BTreeMap<String, String>,
    pub action: PolicyAction,
    #[serde(default)]
    pub tools: Vec<String>,
}

/// Per-tool policy rule authored in YAML (legacy).
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
pub struct ToolPolicy {
    pub name: String,
    pub action: PolicyAction,
    pub block_patterns: Vec<String>,
}

impl PolicyConfig {
    /// Returns true when the document uses the normalized rules schema.
    pub fn uses_normalized_rules(&self) -> bool {
        self.schema_version == SCHEMA_2026_3 || !self.rules.is_empty()
    }
}
