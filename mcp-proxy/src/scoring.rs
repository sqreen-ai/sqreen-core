//! Explainable, deterministic risk scoring for [`crate::action::AgentAction`].
//!
//! # What the number means
//!
//! `risk_score` is an **ordinal severity index** on 0–100 assembled from weighted
//! security signals. It is **not** a probability, likelihood, or calibrated confidence.
//! Operators should treat it as a ranked severity cue alongside [`RiskFactor`] explanations.
//!
//! # Design constraints
//!
//! - Fully deterministic for identical inputs and config
//! - Every non-zero score carries at least one explaining factor
//! - Weak signals are capped so one alone cannot reach CRITICAL
//! - Weights and level thresholds are configurable

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::action::{AgentAction, Destination, EnvironmentTier};
use crate::behavior::{BehaviorFinding, BehaviorSignalKind};
use crate::risk::RiskAnalysis;
use crate::taxonomy::{ActionCategory, ResourceCategory};
use crate::telemetry::{destination_category, extract_domain};

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
    /// Content/DLP scanner found secret-shaped material in the payload.
    ContentSecret,
    /// Threat-intel indicator matched.
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

    fn is_strong(self) -> bool {
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
    /// Configured weight before caps.
    pub weight: u8,
    /// Points actually added after per-factor caps and diminishing returns.
    pub contribution: u8,
    pub detail: String,
}

/// Complete explainable score for one action.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExplainableRiskScore {
    pub score: u8,
    pub level: RiskLevel,
    pub factors: Vec<RiskFactor>,
    /// Always [`SCORE_SEMANTICS`].
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

/// Per-factor weights (0–100 scale points before caps).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RiskScoreWeights {
    pub secret_access: u8,
    pub sensitive_resource: u8,
    pub external_destination: u8,
    pub unknown_destination: u8,
    pub destructive_action: u8,
    pub production_environment: u8,
    pub privileged_credential: u8,
    pub behavioral_anomaly: u8,
    pub unknown_agent: u8,
    pub high_volume_action: u8,
    pub policy_sensitive_operation: u8,
    pub unusual_tool: u8,
    pub bulk_operation: u8,
    pub content_secret: u8,
    pub threat_intel: u8,
}

impl Default for RiskScoreWeights {
    fn default() -> Self {
        Self {
            secret_access: 35,
            sensitive_resource: 20,
            external_destination: 15,
            unknown_destination: 20,
            destructive_action: 30,
            production_environment: 15,
            privileged_credential: 30,
            behavioral_anomaly: 40,
            unknown_agent: 10,
            high_volume_action: 15,
            policy_sensitive_operation: 55,
            unusual_tool: 15,
            bulk_operation: 15,
            content_secret: 35,
            threat_intel: 40,
        }
    }
}

impl RiskScoreWeights {
    fn weight_for(&self, kind: RiskFactorKind) -> u8 {
        match kind {
            RiskFactorKind::SecretAccess => self.secret_access,
            RiskFactorKind::SensitiveResource => self.sensitive_resource,
            RiskFactorKind::ExternalDestination => self.external_destination,
            RiskFactorKind::UnknownDestination => self.unknown_destination,
            RiskFactorKind::DestructiveAction => self.destructive_action,
            RiskFactorKind::ProductionEnvironment => self.production_environment,
            RiskFactorKind::PrivilegedCredential => self.privileged_credential,
            RiskFactorKind::BehavioralAnomaly => self.behavioral_anomaly,
            RiskFactorKind::UnknownAgent => self.unknown_agent,
            RiskFactorKind::HighVolumeAction => self.high_volume_action,
            RiskFactorKind::PolicySensitiveOperation => self.policy_sensitive_operation,
            RiskFactorKind::UnusualTool => self.unusual_tool,
            RiskFactorKind::BulkOperation => self.bulk_operation,
            RiskFactorKind::ContentSecret => self.content_secret,
            RiskFactorKind::ThreatIntel => self.threat_intel,
        }
    }
}

/// Maps score bands onto [`RiskLevel`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RiskLevelThresholds {
    /// Scores at or above this are MEDIUM (below are LOW).
    pub medium: u8,
    /// Scores at or above this are HIGH.
    pub high: u8,
    /// Scores at or above this are CRITICAL.
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

/// Caps and diminishing-return knobs.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RiskScoreCaps {
    /// Max points a weak factor may contribute.
    pub max_weak_contribution: u8,
    /// Max points a strong factor may contribute.
    pub max_strong_contribution: u8,
    /// Ceiling when the only firing factors are weak.
    pub weak_only_ceiling: u8,
}

impl Default for RiskScoreCaps {
    fn default() -> Self {
        Self {
            max_weak_contribution: 25,
            max_strong_contribution: 70,
            weak_only_ceiling: 60,
        }
    }
}

/// Full scorer configuration.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct RiskScoreConfig {
    pub weights: RiskScoreWeights,
    pub levels: RiskLevelThresholds,
    pub caps: RiskScoreCaps,
}

/// Inputs beyond the action itself.
#[derive(Debug, Clone, Default)]
pub struct RiskScoreInput<'a> {
    pub behavior: Option<&'a BehaviorFinding>,
    pub content: Option<&'a RiskAnalysis>,
    pub ioc_match: bool,
}

/// Deterministic explainable risk scorer.
#[derive(Debug, Clone, Default)]
pub struct RiskScoreEngine {
    config: RiskScoreConfig,
}

impl RiskScoreEngine {
    pub fn new(config: RiskScoreConfig) -> Self {
        Self { config }
    }

    pub fn config(&self) -> &RiskScoreConfig {
        &self.config
    }

    /// Scores an action. Identical inputs + config ⇒ identical output.
    pub fn score(&self, action: &AgentAction, input: RiskScoreInput<'_>) -> ExplainableRiskScore {
        let mut candidates: Vec<(RiskFactorKind, String)> = Vec::new();

        collect_structural_factors(action, &mut candidates);
        collect_behavior_factors(input.behavior, &mut candidates);
        collect_content_factors(input.content, &mut candidates);

        if input.ioc_match {
            candidates.push((
                RiskFactorKind::ThreatIntel,
                "threat-intel indicator matched action payload".to_string(),
            ));
        }

        // Deduplicate by kind — first detail wins (stable insertion order).
        let mut seen = BTreeMap::new();
        for (kind, detail) in candidates {
            seen.entry(kind).or_insert(detail);
        }

        let mut raw_factors: Vec<(RiskFactorKind, u8, String, bool)> = seen
            .into_iter()
            .map(|(kind, detail)| {
                let weight = self.config.weights.weight_for(kind);
                let strong = kind.is_strong();
                let capped = if strong {
                    weight.min(self.config.caps.max_strong_contribution)
                } else {
                    weight.min(self.config.caps.max_weak_contribution)
                };
                (kind, capped, detail, strong)
            })
            .collect();

        // Deterministic ordering: strong first, then weight desc, then kind name.
        raw_factors.sort_by(|left, right| {
            right
                .3
                .cmp(&left.3)
                .then_with(|| right.1.cmp(&left.1))
                .then_with(|| left.0.as_str().cmp(right.0.as_str()))
        });

        let only_weak = !raw_factors.is_empty() && raw_factors.iter().all(|factor| !factor.3);
        let contributions =
            apply_diminishing_returns(raw_factors.iter().map(|factor| factor.1).collect());

        let mut total: u32 = contributions.iter().map(|value| u32::from(*value)).sum();
        if only_weak {
            total = total.min(u32::from(self.config.caps.weak_only_ceiling));
        }
        let score = total.min(100) as u8;

        let factors: Vec<RiskFactor> = raw_factors
            .into_iter()
            .zip(contributions)
            .map(|((kind, weight, detail, _), contribution)| RiskFactor {
                kind,
                weight,
                contribution,
                detail,
            })
            .filter(|factor| factor.contribution > 0)
            .collect();

        // Zero score must not invent factors; non-zero must always explain.
        debug_assert!(score == 0 || !factors.is_empty());

        ExplainableRiskScore {
            score,
            level: self.config.levels.level_for(score),
            factors,
            semantics: SCORE_SEMANTICS,
        }
    }
}

/// First factor keeps full points; later factors are discounted so stacks don't explode.
fn apply_diminishing_returns(weights: Vec<u8>) -> Vec<u8> {
    weights
        .into_iter()
        .enumerate()
        .map(|(index, weight)| match index {
            0 => weight,
            1 => ((u16::from(weight) * 85) / 100) as u8,
            _ => ((u16::from(weight) * 70) / 100) as u8,
        })
        .collect()
}

fn collect_structural_factors(action: &AgentAction, out: &mut Vec<(RiskFactorKind, String)>) {
    let security = &action.security;
    let tool = action.tool_name();

    if security.risk.credential_access
        || security.touches_resource(ResourceCategory::Secret)
        || security.touches_resource(ResourceCategory::Credential)
    {
        out.push((
            RiskFactorKind::SecretAccess,
            format!("action touches credential/secret material via `{tool}`"),
        ));
        out.push((
            RiskFactorKind::PrivilegedCredential,
            format!("privileged credential access indicated for `{tool}`"),
        ));
    }

    if security.touches_resource(ResourceCategory::Pii)
        || security.touches_resource(ResourceCategory::FinancialData)
        || security.touches_resource(ResourceCategory::SourceCode)
        || security.risk.sensitive_data_access
    {
        out.push((
            RiskFactorKind::SensitiveResource,
            format!("action targets a sensitive resource class via `{tool}`"),
        ));
    }

    if security.risk.destructive
        || matches!(
            security.action,
            ActionCategory::Delete | ActionCategory::Deploy | ActionCategory::Escalate
        )
    {
        out.push((
            RiskFactorKind::DestructiveAction,
            format!(
                "destructive/irreversible action category `{}`",
                security.action.as_str()
            ),
        ));
    }

    if security.risk.production || action.identity.environment.tier == EnvironmentTier::Production {
        out.push((
            RiskFactorKind::ProductionEnvironment,
            "action executes in a production environment tier".to_string(),
        ));
    }

    if security.risk.bulk_operation {
        out.push((
            RiskFactorKind::BulkOperation,
            format!("bulk/recursive operation shape detected for `{tool}`"),
        ));
    }

    if action.identity.is_anonymous() {
        out.push((
            RiskFactorKind::UnknownAgent,
            "acting agent has no registered durable identity".to_string(),
        ));
    }

    match destination_signal(action) {
        Some(("external", domain)) => out.push((
            RiskFactorKind::ExternalDestination,
            format!("external destination `{domain}`"),
        )),
        Some(("unknown", _)) => out.push((
            RiskFactorKind::UnknownDestination,
            "destination host could not be classified".to_string(),
        )),
        Some((category, domain)) if category != "localhost" && category != "internal" => {
            out.push((
                RiskFactorKind::UnknownDestination,
                format!("unrecognized destination category `{category}` for `{domain}`"),
            ))
        }
        _ => {}
    }

    if is_policy_sensitive_tool(tool) {
        out.push((
            RiskFactorKind::PolicySensitiveOperation,
            format!("tool `{tool}` is a high-impact policy-sensitive operation"),
        ));
    }

    // Taxonomy-unknown tools (not in classify name tables, no usable arg shape)
    // always contribute UnusualTool — does not require behavioral warmup.
    let knowledge = crate::classify::classify(tool, &action.arguments).tool_knowledge;
    match knowledge {
        crate::security_baseline::ToolKnowledge::Unknown => {
            out.push((
                RiskFactorKind::UnusualTool,
                format!("tool `{tool}` is unknown to the classifier"),
            ));
        }
        crate::security_baseline::ToolKnowledge::PartiallyClassified => {
            out.push((
                RiskFactorKind::UnusualTool,
                format!("tool `{tool}` is only partially classified from arguments"),
            ));
        }
        crate::security_baseline::ToolKnowledge::Known => {}
    }
}

fn collect_behavior_factors(
    behavior: Option<&BehaviorFinding>,
    out: &mut Vec<(RiskFactorKind, String)>,
) {
    let Some(finding) = behavior else {
        return;
    };

    for signal in &finding.signals {
        match signal.kind {
            BehaviorSignalKind::ExfiltrationChain
            | BehaviorSignalKind::DestructiveAfterReads
            | BehaviorSignalKind::NovelSensitiveDirectory
            | BehaviorSignalKind::NovelExternalDomain
            | BehaviorSignalKind::ProductionFromDevAgent => {
                out.push((RiskFactorKind::BehavioralAnomaly, signal.detail.clone()));
            }
            BehaviorSignalKind::HighVolumeReads | BehaviorSignalKind::ActionFrequencyDeviation => {
                out.push((RiskFactorKind::HighVolumeAction, signal.detail.clone()));
            }
            BehaviorSignalKind::UnknownTool => {
                out.push((RiskFactorKind::UnusualTool, signal.detail.clone()));
            }
            BehaviorSignalKind::CredentialAccess => {
                out.push((RiskFactorKind::SecretAccess, signal.detail.clone()));
            }
        }
    }
}

fn collect_content_factors(
    content: Option<&RiskAnalysis>,
    out: &mut Vec<(RiskFactorKind, String)>,
) {
    let Some(analysis) = content else {
        return;
    };

    if analysis
        .sanitized_params
        .as_deref()
        .is_some_and(|text| text.contains(crate::risk::SECRET_MASK_TOKEN))
        || analysis.score >= 45 && analysis.sanitized_params.is_some()
    {
        // Prefer explicit secret token; also treat DLP-masked payloads as content secrets
        // when the scanner rewrote the body.
        if analysis
            .sanitized_params
            .as_deref()
            .is_some_and(|text| text.contains(crate::risk::SECRET_MASK_TOKEN))
        {
            out.push((
                RiskFactorKind::ContentSecret,
                "content scanner masked secret-shaped material in arguments".to_string(),
            ));
        }
    }
}

fn destination_signal(action: &AgentAction) -> Option<(&'static str, String)> {
    match &action.destination {
        Some(Destination::Host { host, .. }) => {
            let domain = extract_domain(host).unwrap_or_else(|| host.to_ascii_lowercase());
            Some((destination_category(&domain), domain))
        }
        Some(Destination::Url { url, host }) => {
            let domain = host
                .as_deref()
                .and_then(extract_domain)
                .or_else(|| extract_domain(url))?;
            Some((destination_category(&domain), domain))
        }
        _ => {
            if let Some((_, raw)) = action
                .arguments
                .first_string_field(["url", "uri", "endpoint", "host"].iter().copied())
            {
                let domain = extract_domain(raw)?;
                return Some((destination_category(&domain), domain));
            }
            None
        }
    }
}

fn is_policy_sensitive_tool(tool_name: &str) -> bool {
    let name = tool_name.to_ascii_lowercase();
    matches!(
        name.as_str(),
        "execute_bash"
            | "run_terminal_cmd"
            | "shell"
            | "bash"
            | "write_file"
            | "edit_file"
            | "apply_patch"
            | "delete_file"
            | "remove_file"
            | "deploy_release"
            | "kubectl"
    ) || name.contains("deploy")
        || name.contains("sudo")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::action::{Arguments, Runtime, SourceRef};

    fn action(tool: &str, args: serde_json::Value) -> AgentAction {
        let mut built = AgentAction::builder(tool, Arguments::from_name_and_arguments(tool, &args))
            .source(SourceRef::new(Runtime::MCP_STDIO, "test"))
            .build_unvalidated();
        built.refresh_security_classification();
        built
    }

    #[test]
    fn score_is_stable_across_repeated_calls() {
        let engine = RiskScoreEngine::default();
        let probe = action(
            "fetch",
            serde_json::json!({"url": "https://api.example.com/v1"}),
        );
        let first = engine.score(&probe, RiskScoreInput::default());
        let second = engine.score(&probe, RiskScoreInput::default());
        assert_eq!(first, second);
        assert_eq!(first.semantics, SCORE_SEMANTICS);
    }

    #[test]
    fn single_weak_signal_cannot_reach_critical() {
        let engine = RiskScoreEngine::default();
        // Anonymous read of a temp file — unknown agent is weak.
        let probe = action("read_file", serde_json::json!({"path": "/tmp/a"}));
        let scored = engine.score(&probe, RiskScoreInput::default());
        assert!(scored.has_factor(RiskFactorKind::UnknownAgent));
        assert!(scored.score <= engine.config.caps.weak_only_ceiling);
        assert!(scored.level < RiskLevel::Critical);
    }

    #[test]
    fn shell_tool_is_policy_sensitive_and_explainable() {
        let engine = RiskScoreEngine::default();
        let probe = action("execute_bash", serde_json::json!({"command": "ls"}));
        let scored = engine.score(&probe, RiskScoreInput::default());
        assert!(scored.has_factor(RiskFactorKind::PolicySensitiveOperation));
        assert!(!scored.factors.is_empty());
        assert!(scored.score >= 50);
    }

    #[test]
    fn credential_path_adds_secret_factors() {
        let engine = RiskScoreEngine::default();
        let probe = action(
            "read_file",
            serde_json::json!({"path": "/Users/x/.ssh/id_rsa"}),
        );
        let scored = engine.score(&probe, RiskScoreInput::default());
        assert!(scored.has_factor(RiskFactorKind::SecretAccess));
        assert!(scored.score > 0);
        let factor_sum: u32 = scored
            .factors
            .iter()
            .map(|factor| u32::from(factor.contribution))
            .sum();
        assert_eq!(
            scored.score,
            factor_sum.min(100) as u8,
            "score must equal the capped sum of factor contributions"
        );
    }

    #[test]
    fn production_plus_destructive_raises_level() {
        let engine = RiskScoreEngine::default();
        let mut probe = action("delete_file", serde_json::json!({"path": "/data/users"}));
        probe.identity.environment.tier = EnvironmentTier::Production;
        probe.refresh_security_classification();
        let scored = engine.score(&probe, RiskScoreInput::default());
        assert!(scored.has_factor(RiskFactorKind::DestructiveAction));
        assert!(scored.has_factor(RiskFactorKind::ProductionEnvironment));
        assert!(scored.level >= RiskLevel::High);
    }

    #[test]
    fn level_thresholds_are_configurable() {
        let mut config = RiskScoreConfig::default();
        config.levels.critical = 40;
        let engine = RiskScoreEngine::new(config);
        let probe = action("execute_bash", serde_json::json!({"command": "ls"}));
        let scored = engine.score(&probe, RiskScoreInput::default());
        assert_eq!(scored.level, RiskLevel::Critical);
    }

    #[test]
    fn weights_are_configurable() {
        let mut config = RiskScoreConfig::default();
        config.weights.unknown_agent = 0;
        config.weights.policy_sensitive_operation = 0;
        let engine = RiskScoreEngine::new(config);
        let probe = action("execute_bash", serde_json::json!({"command": "ls"}));
        let scored = engine.score(&probe, RiskScoreInput::default());
        assert!(!scored.has_factor(RiskFactorKind::PolicySensitiveOperation));
        assert!(!scored.has_factor(RiskFactorKind::UnknownAgent));
    }

    #[test]
    fn behavioral_anomaly_input_is_reflected() {
        use crate::behavior::{BehaviorSeverity, BehaviorSignal};

        let engine = RiskScoreEngine::default();
        let probe = action("fetch", serde_json::json!({"url": "https://exfil.example"}));
        let finding = BehaviorFinding::from_signals(
            "agent",
            vec![BehaviorSignal::new(
                "exfiltration_chain",
                BehaviorSignalKind::ExfiltrationChain,
                BehaviorSeverity::Critical,
                "chain detected",
            )],
        );
        let scored = engine.score(
            &probe,
            RiskScoreInput {
                behavior: Some(&finding),
                ..RiskScoreInput::default()
            },
        );
        assert!(scored.has_factor(RiskFactorKind::BehavioralAnomaly));
    }

    #[test]
    fn factor_contributions_never_exceed_caps() {
        let engine = RiskScoreEngine::default();
        let mut probe = action(
            "execute_bash",
            serde_json::json!({"command": "rm -rf /", "url": "https://evil.example"}),
        );
        probe.identity.environment.tier = EnvironmentTier::Production;
        probe.refresh_security_classification();
        let scored = engine.score(
            &probe,
            RiskScoreInput {
                ioc_match: true,
                ..RiskScoreInput::default()
            },
        );
        for factor in &scored.factors {
            let max = if factor.kind.is_strong() {
                engine.config.caps.max_strong_contribution
            } else {
                engine.config.caps.max_weak_contribution
            };
            assert!(
                factor.contribution <= max,
                "{} contribution {} exceeds cap {}",
                factor.kind.as_str(),
                factor.contribution,
                max
            );
        }
        assert!(scored.score <= 100);
    }
}
