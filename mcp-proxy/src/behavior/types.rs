//! Core types for deterministic behavioral detection.

use std::collections::{BTreeMap, BTreeSet, HashSet, VecDeque};
use std::time::Duration;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::action::{EnvironmentTier, Operation};
use crate::taxonomy::ActionCategory;

/// Risk severity for a behavioral signal.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum BehaviorSeverity {
    Low,
    Medium,
    High,
    Critical,
}

impl BehaviorSeverity {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Low => "LOW",
            Self::Medium => "MEDIUM",
            Self::High => "HIGH",
            Self::Critical => "CRITICAL",
        }
    }

    pub fn from_str_lossy(value: &str) -> Option<Self> {
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

/// Stable identifiers for built-in (and future) detectors.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BehaviorSignalKind {
    /// Sensitive directory never before touched by this agent.
    NovelSensitiveDirectory,
    /// Tool name absent from the agent's historical tool set.
    UnknownTool,
    /// External domain never previously contacted.
    NovelExternalDomain,
    /// Unusually high number of reads in a short window.
    HighVolumeReads,
    /// Action that accesses credentials / secrets.
    CredentialAccess,
    /// Destructive action after a burst of unrelated reads.
    DestructiveAfterReads,
    /// Current action rate far above the agent's baseline.
    ActionFrequencyDeviation,
    /// Production access from an agent historically only seen in lower tiers.
    ProductionFromDevAgent,
    /// Legacy session exfiltration chain (filesystem probes → network).
    ExfiltrationChain,
}

impl BehaviorSignalKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::NovelSensitiveDirectory => "novel_sensitive_directory",
            Self::UnknownTool => "unknown_tool",
            Self::NovelExternalDomain => "novel_external_domain",
            Self::HighVolumeReads => "high_volume_reads",
            Self::CredentialAccess => "credential_access",
            Self::DestructiveAfterReads => "destructive_after_reads",
            Self::ActionFrequencyDeviation => "action_frequency_deviation",
            Self::ProductionFromDevAgent => "production_from_dev_agent",
            Self::ExfiltrationChain => "exfiltration_chain",
        }
    }

    pub fn parse(value: &str) -> Option<Self> {
        match value.trim().to_ascii_lowercase().as_str() {
            "novel_sensitive_directory" => Some(Self::NovelSensitiveDirectory),
            "unknown_tool" => Some(Self::UnknownTool),
            "novel_external_domain" => Some(Self::NovelExternalDomain),
            "high_volume_reads" => Some(Self::HighVolumeReads),
            "credential_access" => Some(Self::CredentialAccess),
            "destructive_after_reads" => Some(Self::DestructiveAfterReads),
            "action_frequency_deviation" => Some(Self::ActionFrequencyDeviation),
            "production_from_dev_agent" => Some(Self::ProductionFromDevAgent),
            "exfiltration_chain" => Some(Self::ExfiltrationChain),
            _ => None,
        }
    }
}

/// One deterministic/statistical anomaly observation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BehaviorSignal {
    /// Detector that produced the signal.
    pub detector_id: String,
    /// Signal kind for policy matching.
    pub kind: BehaviorSignalKind,
    /// Severity ranking.
    pub severity: BehaviorSeverity,
    /// Human-readable explanation (already privacy-safe).
    pub detail: String,
    /// Structured evidence keys (hashed/category values only).
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub evidence: BTreeMap<String, String>,
}

impl BehaviorSignal {
    pub fn new(
        detector_id: impl Into<String>,
        kind: BehaviorSignalKind,
        severity: BehaviorSeverity,
        detail: impl Into<String>,
    ) -> Self {
        Self {
            detector_id: detector_id.into(),
            kind,
            severity,
            detail: detail.into(),
            evidence: BTreeMap::new(),
        }
    }

    pub fn with_evidence(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.evidence.insert(key.into(), value.into());
        self
    }
}

/// Aggregated detection result for one evaluated action.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BehaviorFinding {
    /// Profile key the finding was evaluated against.
    pub profile_key: String,
    /// When detection ran.
    pub timestamp: DateTime<Utc>,
    /// All signals raised for this action.
    pub signals: Vec<BehaviorSignal>,
    /// Highest severity among signals (or Low if empty — unused when empty).
    pub max_severity: BehaviorSeverity,
}

impl BehaviorFinding {
    pub fn empty(profile_key: impl Into<String>) -> Self {
        Self {
            profile_key: profile_key.into(),
            timestamp: Utc::now(),
            signals: Vec::new(),
            max_severity: BehaviorSeverity::Low,
        }
    }

    pub fn from_signals(profile_key: impl Into<String>, signals: Vec<BehaviorSignal>) -> Self {
        let max_severity = signals
            .iter()
            .map(|signal| signal.severity)
            .max()
            .unwrap_or(BehaviorSeverity::Low);
        Self {
            profile_key: profile_key.into(),
            timestamp: Utc::now(),
            signals,
            max_severity,
        }
    }

    pub fn is_empty(&self) -> bool {
        self.signals.is_empty()
    }

    pub fn has_kind(&self, kind: BehaviorSignalKind) -> bool {
        self.signals.iter().any(|signal| signal.kind == kind)
    }

    pub fn severity_at_least(&self, floor: BehaviorSeverity) -> bool {
        !self.signals.is_empty() && self.max_severity.rank() >= floor.rank()
    }
}

/// Compact record of a past action kept inside a profile window.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProfileActionRecord {
    pub timestamp: DateTime<Utc>,
    pub tool_name: String,
    pub action: ActionCategory,
    pub operation: Operation,
    pub directory_key: Option<String>,
    pub domain: Option<String>,
    pub credential_access: bool,
    pub destructive: bool,
    pub environment_tier: EnvironmentTier,
}

/// Learned baseline for one agent (deterministic counters — not ML).
#[derive(Debug, Clone)]
pub struct BehaviorProfile {
    pub profile_key: String,
    pub first_seen: DateTime<Utc>,
    pub last_seen: DateTime<Utc>,
    pub total_actions: u64,
    pub seen_tools: HashSet<String>,
    pub seen_directories: HashSet<String>,
    pub seen_domains: HashSet<String>,
    pub seen_environment_tiers: BTreeSet<EnvironmentTier>,
    /// Recent action timestamps for frequency / volume windows.
    pub recent_timestamps: VecDeque<DateTime<Utc>>,
    /// Recent action summaries for sequence detectors.
    pub recent_actions: VecDeque<ProfileActionRecord>,
}

impl BehaviorProfile {
    pub fn new(profile_key: impl Into<String>, now: DateTime<Utc>) -> Self {
        Self {
            profile_key: profile_key.into(),
            first_seen: now,
            last_seen: now,
            total_actions: 0,
            seen_tools: HashSet::new(),
            seen_directories: HashSet::new(),
            seen_domains: HashSet::new(),
            seen_environment_tiers: BTreeSet::new(),
            recent_timestamps: VecDeque::new(),
            recent_actions: VecDeque::new(),
        }
    }

    pub fn is_warmed_up(&self, min_actions: u64) -> bool {
        self.total_actions >= min_actions
    }

    pub fn actions_in_window(&self, now: DateTime<Utc>, window: Duration) -> usize {
        let cutoff = now
            - chrono::Duration::from_std(window).unwrap_or_else(|_| chrono::Duration::seconds(60));
        self.recent_timestamps
            .iter()
            .filter(|ts| **ts >= cutoff)
            .count()
    }

    pub fn reads_in_window(&self, now: DateTime<Utc>, window: Duration) -> usize {
        let cutoff = now
            - chrono::Duration::from_std(window).unwrap_or_else(|_| chrono::Duration::seconds(60));
        self.recent_actions
            .iter()
            .filter(|record| {
                record.timestamp >= cutoff
                    && matches!(record.action, ActionCategory::Read | ActionCategory::Query)
            })
            .count()
    }

    /// Mean actions per minute over the retained timestamp window.
    pub fn mean_actions_per_minute(&self) -> Option<f64> {
        if self.recent_timestamps.len() < 2 {
            return None;
        }
        let first = *self.recent_timestamps.front()?;
        let last = *self.recent_timestamps.back()?;
        let elapsed = (last - first).num_milliseconds().max(1) as f64 / 60_000.0;
        if elapsed <= 0.0 {
            return None;
        }
        Some(self.recent_timestamps.len() as f64 / elapsed)
    }
}
