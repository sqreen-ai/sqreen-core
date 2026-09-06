//! Shared risk-scoring types (public Core).
//!
//! Advanced weighted engines live under the `enterprise` feature.

use serde::{Deserialize, Serialize};

use crate::behavior::BehaviorFinding;
use crate::risk::RiskAnalysis;

/// Disclaimer attached to every scored result.
pub const SCORE_SEMANTICS: &str = "ordinal severity index (0-100), not a mathematical probability";

/// Coarse severity band derived from [`ExplainableRiskScore::score`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum RiskLevel {
    Low,
    Medium,
    High,
    Critical,
}

impl RiskLevel {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Low => "LOW",
            Self::Medium => "MEDIUM",
            Self::High => "HIGH",
            Self::Critical => "CRITICAL",
        }
    }

    pub fn parse(value: &str) -> Option<Self> {
        match value.trim().to_ascii_uppercase().as_str() {
            "LOW" => Some(Self::Low),
            "MEDIUM" => Some(Self::Medium),
            "HIGH" => Some(Self::High),
            "CRITICAL" => Some(Self::Critical),
            _ => None,
        }
    }

    pub fn rank(self) -> u8 {
        match self {
            Self::Low => 1,
            Self::Medium => 2,
            Self::High => 3,
            Self::Critical => 4,
        }
    }
}

/// Kind of deterministic signal that contributed to the score.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RiskFactorKind {
    SecretAccess,
    SensitiveResource,
    ExternalDestination,
    UnknownDestination,
    DestructiveAction,
    ProductionEnvironment,
    PrivilegedCredential,
    BehavioralAnomaly,
    UnknownAgent,
    HighVolumeAction,
    PolicySensitiveOperation,
    UnusualTool,
    BulkOperation,
    ContentSecret,
    ThreatIntel,
}

impl RiskFactorKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::SecretAccess => "secret_access",
            Self::SensitiveResource => "sensitive_resource",
            Self::ExternalDestination => "external_destination",
            Self::UnknownDestination => "unknown_destination",
            Self::DestructiveAction => "destructive_action",
            Self::ProductionEnvironment => "production_environment",
            Self::PrivilegedCredential => "privileged_credential",
            Self::BehavioralAnomaly => "behavioral_anomaly",
            Self::UnknownAgent => "unknown_agent",
            Self::HighVolumeAction => "high_volume_action",
            Self::PolicySensitiveOperation => "policy_sensitive_operation",
            Self::UnusualTool => "unusual_tool",
            Self::BulkOperation => "bulk_operation",
            Self::ContentSecret => "content_secret",
            Self::ThreatIntel => "threat_intel",
        }
    }

    pub fn parse(value: &str) -> Option<Self> {
        match value.trim().to_ascii_lowercase().as_str() {
            "secret_access" => Some(Self::SecretAccess),
            "sensitive_resource" => Some(Self::SensitiveResource),
            "external_destination" => Some(Self::ExternalDestination),
            "unknown_destination" => Some(Self::UnknownDestination),
            "destructive_action" => Some(Self::DestructiveAction),
            "production_environment" => Some(Self::ProductionEnvironment),
            "privileged_credential" => Some(Self::PrivilegedCredential),
            "behavioral_anomaly" => Some(Self::BehavioralAnomaly),
            "unknown_agent" => Some(Self::UnknownAgent),
            "high_volume_action" => Some(Self::HighVolumeAction),
            "policy_sensitive_operation" => Some(Self::PolicySensitiveOperation),
            "unusual_tool" | "unknown_tool" => Some(Self::UnusualTool),
            "bulk_operation" => Some(Self::BulkOperation),
            "content_secret" => Some(Self::ContentSecret),
            "threat_intel" => Some(Self::ThreatIntel),
            _ => None,
        }
    }

    pub(crate) fn is_strong(self) -> bool {
        matches!(
            self,
            Self::SecretAccess
                | Self::PrivilegedCredential
                | Self::DestructiveAction
                | Self::BehavioralAnomaly
                | Self::ContentSecret
                | Self::ThreatIntel
                | Self::PolicySensitiveOperation
        )
    }
}

/// One explainable contribution to the score.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RiskFactor {
    pub kind: RiskFactorKind,
    pub weight: u8,
    pub contribution: u8,
    pub detail: String,
}

/// Complete explainable score for one action.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExplainableRiskScore {
    pub score: u8,
    pub level: RiskLevel,
    pub factors: Vec<RiskFactor>,
    pub semantics: &'static str,
}

impl ExplainableRiskScore {
    pub fn has_factor(&self, kind: RiskFactorKind) -> bool {
        self.factors.iter().any(|factor| factor.kind == kind)
    }

    pub fn factor_kinds(&self) -> Vec<RiskFactorKind> {
        self.factors.iter().map(|factor| factor.kind).collect()
    }
}

/// Maps score bands onto [`RiskLevel`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RiskLevelThresholds {
    pub medium: u8,
    pub high: u8,
    pub critical: u8,
}

impl Default for RiskLevelThresholds {
    fn default() -> Self {
        Self {
            medium: 25,
            high: 50,
            critical: 75,
        }
    }
}

impl RiskLevelThresholds {
    pub fn level_for(&self, score: u8) -> RiskLevel {
        if score >= self.critical {
            RiskLevel::Critical
        } else if score >= self.high {
            RiskLevel::High
        } else if score >= self.medium {
            RiskLevel::Medium
        } else {
            RiskLevel::Low
        }
    }
}

/// Inputs beyond the action itself.
#[derive(Debug, Clone, Default)]
pub struct RiskScoreInput<'a> {
    pub behavior: Option<&'a BehaviorFinding>,
    pub content: Option<&'a RiskAnalysis>,
    pub ioc_match: bool,
}
