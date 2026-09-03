//! Structured, privacy-conscious security event for one evaluated agent action.

use std::collections::BTreeMap;
use std::time::Duration;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::gateway::{Decision, PolicySource};
use crate::taxonomy::{ActionCategory, ResourceCategory, RiskProfile};

/// Schema version for [`AgentSecurityEvent`].
pub const EVENT_SCHEMA_VERSION: &str = "2026.3";

/// Behavioral security event — signals only, never raw secrets or file contents.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AgentSecurityEvent {
    /// Event schema version.
    pub schema_version: String,
    /// When the evaluation completed.
    pub timestamp: DateTime<Utc>,
    /// Hashed organization identifier, when known.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub organization_id: Option<String>,

    /// Privacy-safe agent identity signals.
    pub agent: AgentIdentitySignal,
    /// Session / correlation signals.
    pub session: SessionSignal,
    /// Normalized action description.
    pub action: ActionSignal,
    /// Destination category/domain when the action targeted a remote host.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub destination: Option<DestinationSignal>,
    /// Deployment environment.
    pub environment: EnvironmentSignal,

    /// Final gateway decision.
    pub decision: Decision,
    /// Decision that would have applied under enforce mode, when audit-only.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub simulated_decision: Option<Decision>,
    /// Policies that matched during evaluation.
    pub policies_matched: Vec<PolicyMatchSignal>,
    /// Aggregated risk signals.
    pub risk: RiskSignal,
    /// Approval outcome when an approval stage ran.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub approval: Option<ApprovalSignal>,

    /// Evaluation latency in microseconds.
    pub latency_micros: u64,
    /// Whether the security pipeline itself succeeded or degraded.
    pub outcome: PipelineOutcome,

    /// Redacted argument summary — keys and hashed structural hints only.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub arguments: Option<ArgumentSummary>,

    /// Free-form non-sensitive annotations.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub metadata: BTreeMap<String, String>,
}

impl AgentSecurityEvent {
    /// Returns the latency as a [`Duration`].
    pub fn latency(&self) -> Duration {
        Duration::from_micros(self.latency_micros)
    }
}

/// Hashed agent identity fields suitable for cloud analytics.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AgentIdentitySignal {
    /// Hashed durable agent id (or local anonymous sentinel hash).
    pub agent_id: String,
    /// Agent kind slug.
    pub agent_type: String,
    /// Whether the agent had no registered id.
    pub anonymous: bool,
    /// Trust level: authenticated | bound | derived | self_asserted.
    #[serde(default = "default_self_asserted_trust")]
    pub agent_trust: String,
    /// Provenance of the agent claim.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub agent_identity_source: Option<String>,
    /// Hashed registered/bound agent id when trust is Bound.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub agent_bound_id: Option<String>,
    /// Hashed human user id, when known.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub user_id: Option<String>,
    #[serde(default = "default_self_asserted_trust")]
    pub user_trust: String,
    /// Hashed workspace id, when known.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub workspace_id: Option<String>,
    /// Selected non-sensitive labels (values hashed when they look like identifiers).
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub labels: BTreeMap<String, String>,
}

fn default_self_asserted_trust() -> String {
    "self_asserted".to_string()
}

/// Session correlation without raw session tokens.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SessionSignal {
    /// Hashed session id.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session_id: Option<String>,
    /// Hashed trace id.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub trace_id: Option<String>,
    /// Hashed action id.
    pub action_id: String,
    /// Runtime / integration that observed the action.
    pub runtime: String,
}

/// Normalized action + tool surface.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ActionSignal {
    /// Taxonomy action category (`read`, `delete`, …).
    pub action_type: ActionCategory,
    /// Taxonomy resource categories touched.
    pub resource_types: Vec<ResourceCategory>,
    /// Provider tool name — not used as a security semantic, recorded for attribution.
    pub tool: String,
    /// Structural operation when known.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub operation: Option<String>,
}

/// Destination without full URLs or credentials.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DestinationSignal {
    /// `localhost` | `internal` | `external` | `unknown` | `file` | `process`.
    pub category: String,
    /// Hostname / registrable domain only — never userinfo or path.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub domain: Option<String>,
}

/// Environment tier and OS family (not hostname).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EnvironmentSignal {
    /// `development` | `staging` | `production` | `unknown`.
    pub tier: String,
    /// OS family when known (`macos`, `linux`, …).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub os: Option<String>,
}

/// One matched policy rule, privacy-safe.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PolicyMatchSignal {
    /// Subsystem that owns the rule.
    pub source: PolicySource,
    /// Rule identifier within the source.
    pub rule_id: String,
    /// Ruleset version when tracked.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
    /// Effect the rule requested.
    pub effect: Decision,
}

/// Risk score and taxonomy risk flags.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RiskSignal {
    /// Numeric risk score when computed (ordinal severity — not a probability).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub score: Option<u8>,
    /// Coarse risk band when computed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub level: Option<String>,
    /// Factor kinds that contributed to the score.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub factors: Vec<String>,
    /// Ordinal-severity disclaimer when a score is present.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub semantics: Option<String>,
    /// Taxonomy risk profile flags.
    pub profile: RiskProfile,
    /// Machine-readable reason codes observed during evaluation.
    pub reason_codes: Vec<String>,
}

/// Approval stage outcome.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ApprovalSignal {
    /// `approved` | `denied` | `unavailable` | `timed_out` | `deferred` | `skipped`.
    pub outcome: String,
}

/// Whether the security evaluation pipeline completed cleanly.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PipelineOutcome {
    /// All stages completed without a security-control failure.
    Success,
    /// At least one control degraded; decision may still be valid.
    Degraded,
    /// Evaluation itself could not complete a required control (still produced a decision).
    Failure,
}

impl PipelineOutcome {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Success => "success",
            Self::Degraded => "degraded",
            Self::Failure => "failure",
        }
    }
}

/// Argument keys and hashed structural hints — never raw values for sensitive keys.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ArgumentSummary {
    /// Present argument key names (including sensitive ones — keys only).
    pub keys: Vec<String>,
    /// Hashed path summaries for path-like arguments.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub paths: Vec<super::privacy::PathSummary>,
    /// Domains extracted from URL-like arguments.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub domains: Vec<String>,
    /// Count of argument keys whose values were withheld as sensitive.
    pub redacted_value_count: u32,
}
