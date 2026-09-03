//! Risk evaluation stage: content scoring, threat intel, behavioral chains, and DLP.
//!
//! Unlike the policy stage this one never reaches a verdict on its own. It produces a score
//! and a set of signals, and answers one question: **does this action need an approval?**
//! Turning that into [`crate::gateway::Decision`] is the orchestrator's job.
//!
//! # Session recording is the caller's responsibility
//!
//! [`RiskStage::evaluate`] reads the session chain but does not append to it.
//! [`RiskStage::record`] does, and the orchestrator calls it *after* an approval resolves
//! so a chain observed mid-prompt sees the same history the prompt was based on.
//!
//! # Failure modes
//!
//! The stage cannot produce "no answer", but it can produce a *weaker* one, and it says so
//! rather than letting a degraded score pass as an equal one:
//!
//! - **Payload not JSON** — [`crate::risk::analyze_params`] falls back to scanning raw
//!   text. Reported as [`Subsystem::RiskScoring`], which degrades safely by default.
//! - **Masking failed** — the scanner found something and could not produce the masked
//!   payload. Reported as [`Subsystem::DlpScanner`], which fails closed: the alternatives
//!   are forwarding the unmasked secret or stopping.
//!
//! Neither is decided here. The stage reports; [`super::FailurePolicy`] rules.

use std::sync::Arc;

use super::decision::{Decision, DecisionReason, MatchedPolicy, PolicySource, ReasonCode, Stage};
use super::failure::{Subsystem, SubsystemFailure};
use crate::action::AgentAction;
use crate::behavior::{BehaviorFinding, SessionTracker, TELEMETRY_BEHAVIORAL_CHAIN};
use crate::risk::{analyze_params, resolve_risk_threshold, RiskAnalysis};
use crate::scoring::{
    ExplainableRiskScore, RiskFactorKind, RiskLevel, RiskScoreEngine, RiskScoreInput,
};
use crate::threat_intel::{ThreatIntelMatcher, TELEMETRY_IOC_MATCH};

/// Telemetry marker when secret-value DLP masks a payload.
pub const TELEMETRY_SECRET_EGRESS: &str = "SECRET_EGRESS_MASK";

/// Telemetry marker when non-secret sensitive data is masked.
pub const TELEMETRY_DLP_MASK: &str = "risk_dlp_mask";

/// Telemetry marker when only the numeric threshold forced the gate.
pub const TELEMETRY_RISK_THRESHOLD: &str = "risk_threshold_exceeded";

/// Signals and score the risk stage derived from an action.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RiskAssessment {
    /// Effective score after explainable scoring and content-scan floor.
    pub score: u8,
    /// Coarse band for the effective score (ordinal severity — not a probability).
    pub level: RiskLevel,
    /// Threshold the score was compared against.
    pub threshold: u8,
    /// Whether an approval is required before the action may proceed.
    pub requires_approval: bool,
    /// Explainable factor breakdown (ordinal index — not a probability).
    pub explanation: ExplainableRiskScore,
    /// Signals gathered, in evaluation order.
    pub reasons: Vec<DecisionReason>,
    /// Rules that fired.
    pub matched_policies: Vec<MatchedPolicy>,
    /// Payload with sensitive spans masked, when the scanner masked anything.
    pub sanitized_payload: Option<String>,
    /// Legacy telemetry marker for the DLP audit event, when one is warranted.
    pub dlp_marker: Option<&'static str>,
    /// Legacy telemetry marker for the approval audit event.
    pub telemetry_marker: &'static str,
    /// The payload matched a threat-intel indicator.
    pub ioc_match: bool,
    /// The session's tool sequence matched an exfiltration chain.
    pub behavioral_anomaly: bool,
    /// Subsystems that could not do their job, for the orchestrator to rule on and audit.
    pub failures: Vec<SubsystemFailure>,
}

impl RiskAssessment {
    /// Returns the payload the approval prompt and downstream stages should see.
    pub fn effective_payload<'a>(&'a self, original: &'a str) -> &'a str {
        self.sanitized_payload.as_deref().unwrap_or(original)
    }

    /// Builds the denial message for an action the operator refused.
    ///
    /// These strings are the observable contract: the stdio relay picks its JSON-RPC error
    /// code by inspecting them and the end-to-end suite greps the log for the markers.
    pub fn denial_detail(&self) -> String {
        if self.behavioral_anomaly {
            "BEHAVIORAL_CHAIN_ANOMALY: operator denied exfiltration-risk tool chain".to_string()
        } else if self.ioc_match {
            "THREAT_INTEL_IOC_MATCH: operator denied IOC-tainted tool call".to_string()
        } else {
            "user denied high-risk tool call".to_string()
        }
    }
}

/// Content risk, threat intel, behavioral analytics, and DLP as one stage.
#[derive(Clone)]
pub struct RiskStage {
    threat_intel: Arc<ThreatIntelMatcher>,
    session: Arc<SessionTracker>,
    scorer: RiskScoreEngine,
}

impl Default for RiskStage {
    fn default() -> Self {
        Self {
            threat_intel: Arc::new(ThreatIntelMatcher::default()),
            session: Arc::new(SessionTracker::default()),
            scorer: RiskScoreEngine::default(),
        }
    }
}

impl RiskStage {
    /// Builds a stage from the shared matchers.
    pub fn new(threat_intel: Arc<ThreatIntelMatcher>, session: Arc<SessionTracker>) -> Self {
        Self {
            threat_intel,
            session,
            scorer: RiskScoreEngine::default(),
        }
    }

    /// Overrides the explainable scorer configuration.
    pub fn with_scorer(mut self, scorer: RiskScoreEngine) -> Self {
        self.scorer = scorer;
        self
    }

    /// Returns a reference to the explainable scorer.
    pub fn scorer(&self) -> &RiskScoreEngine {
        &self.scorer
    }

    /// Scans an action's payload for sensitive content.
    ///
    /// Pure and side-effect free, so the orchestrator can run it before policy evaluation
    /// in order to attach a risk score to policy-stage audit records without scanning the
    /// payload twice.
    ///
    /// Infallible by construction, including against a panicking scanner: a scan that
    /// aborts yields a maximum-score analysis flagged as degraded, so an input crafted to
    /// crash the scorer scores as dangerous rather than as absent.
    pub fn scan(&self, action: &AgentAction) -> RiskAnalysis {
        let tool_name = action.tool_name();
        let payload = action.canonical_params_json();

        std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            analyze_params(tool_name, payload)
        }))
        .unwrap_or_else(|_| {
            eprintln!("mcp-proxy: risk scan of tool `{tool_name}` panicked; scoring as maximum");
            RiskAnalysis {
                score: 100,
                sanitized_params: None,
                degraded: true,
                masking_failed: false,
            }
        })
    }

    /// Computes an explainable score without deciding whether approval is required.
    ///
    /// Used before policy evaluation so rules can match on `risk.level` /
    /// `risk.score_at_least` / `risk.factor` with the same deterministic inputs the risk
    /// stage later uses.
    pub fn explain(
        &self,
        action: &AgentAction,
        analysis: &RiskAnalysis,
        behavior: Option<&BehaviorFinding>,
    ) -> ExplainableRiskScore {
        let ioc_match = self.threat_intel.matches_action(action);
        self.scorer.score(
            action,
            RiskScoreInput {
                behavior,
                content: Some(analysis),
                ioc_match,
            },
        )
    }

    /// Scores an action and decides whether it needs an approval.
    ///
    /// `analysis` comes from [`RiskStage::scan`]. `configured_threshold` is the
    /// policy-declared threshold, if any; [`crate::risk::resolve_risk_threshold`] applies
    /// the environment override on top.
    pub fn evaluate(
        &self,
        action: &AgentAction,
        analysis: RiskAnalysis,
        configured_threshold: Option<u8>,
        behavior: Option<&BehaviorFinding>,
    ) -> RiskAssessment {
        let tool_name = action.tool_name();

        let ioc_match = self.threat_intel.matches_action(action);
        let behavioral_anomaly = self.session.verify_action_chain(action);

        let explanation = self.scorer.score(
            action,
            RiskScoreInput {
                behavior,
                content: Some(&analysis),
                ioc_match,
            },
        );

        // Content-scan floor preserves tool-base severity (e.g. shell = 75) for threshold
        // gating. Session exfiltration chains still clamp to 100.
        let mut score = explanation.score.max(analysis.score);
        if behavioral_anomaly {
            score = 100;
        }
        score = score.min(100);

        let level = self.scorer.config().levels.level_for(score);
        let threshold = resolve_risk_threshold(configured_threshold);

        let force_gate = ioc_match
            || behavioral_anomaly
            || explanation.has_factor(RiskFactorKind::BehavioralAnomaly)
            || explanation.has_factor(RiskFactorKind::ThreatIntel);

        // When DLP already masked secret material, the content-scan total and the
        // content_secret factor can push the gate over threshold even though the outbound
        // payload is remade. Gate without the remediable content_secret contribution so
        // masking remains the remediation rather than an interactive deny.
        let remediable_masked_secret = analysis.sanitized_params.is_some()
            && explanation.has_factor(RiskFactorKind::ContentSecret)
            && !force_gate;
        let gate_score = if remediable_masked_secret {
            let content_points = explanation
                .factors
                .iter()
                .find(|factor| factor.kind == RiskFactorKind::ContentSecret)
                .map(|factor| factor.contribution)
                .unwrap_or(0);
            explanation.score.saturating_sub(content_points)
        } else {
            score
        };
        let requires_approval = force_gate || gate_score >= threshold;

        let telemetry_marker = if behavioral_anomaly {
            TELEMETRY_BEHAVIORAL_CHAIN
        } else if ioc_match {
            TELEMETRY_IOC_MATCH
        } else {
            TELEMETRY_RISK_THRESHOLD
        };

        let mut reasons = Vec::new();
        let mut matched_policies = Vec::new();
        let mut failures = Vec::new();

        if analysis.degraded {
            failures.push(SubsystemFailure::new(
                Subsystem::RiskScoring,
                format!(
                    "arguments of tool `{tool_name}` are not valid json; \
                     scored by raw-text scan without structural masking"
                ),
            ));
        }

        if analysis.masking_failed {
            failures.push(SubsystemFailure::new(
                Subsystem::DlpScanner,
                format!(
                    "sensitive data found in arguments of tool `{tool_name}` \
                     but the masked payload could not be produced"
                ),
            ));
        }

        if ioc_match {
            reasons.push(DecisionReason::new(
                Stage::Risk,
                ReasonCode::ThreatIntelMatch,
                format!("threat-intel indicator matched arguments of tool `{tool_name}`"),
            ));
            matched_policies.push(MatchedPolicy::new(
                PolicySource::ThreatIntel,
                "threat_intel.indicators",
                Decision::RequireApproval,
            ));
        }

        if behavioral_anomaly {
            reasons.push(DecisionReason::new(
                Stage::Risk,
                ReasonCode::BehavioralChainAnomaly,
                format!("tool `{tool_name}` completes an exfiltration-risk chain in this session"),
            ));
            matched_policies.push(MatchedPolicy::new(
                PolicySource::BehavioralAnalytics,
                "behavior.exfiltration_chain",
                Decision::RequireApproval,
            ));
        }

        let dlp_marker = analysis.sanitized_params.as_deref().map(|sanitized| {
            if sanitized.contains(crate::risk::SECRET_MASK_TOKEN) {
                TELEMETRY_SECRET_EGRESS
            } else {
                TELEMETRY_DLP_MASK
            }
        });

        if let Some(marker) = dlp_marker {
            let (code, detail) = if marker == TELEMETRY_SECRET_EGRESS {
                (
                    ReasonCode::SecretEgressMasked,
                    format!("secret value masked in arguments of tool `{tool_name}`"),
                )
            } else {
                (
                    ReasonCode::SensitiveDataMasked,
                    format!("sensitive data masked in arguments of tool `{tool_name}`"),
                )
            };

            reasons.push(DecisionReason::new(Stage::Risk, code, detail));
            matched_policies.push(MatchedPolicy::new(
                PolicySource::DataLossPrevention,
                "risk.dlp_scanner",
                Decision::Allow,
            ));
        }

        if requires_approval && !ioc_match && !behavioral_anomaly {
            reasons.push(DecisionReason::new(
                Stage::Risk,
                ReasonCode::RiskThresholdExceeded,
                format!("risk score {score} met threshold {threshold} for tool `{tool_name}`"),
            ));
            matched_policies.push(MatchedPolicy::new(
                PolicySource::RiskThreshold,
                "global.risk_threshold",
                Decision::RequireApproval,
            ));
        }

        RiskAssessment {
            score,
            level,
            threshold,
            requires_approval,
            explanation,
            reasons,
            matched_policies,
            sanitized_payload: analysis.sanitized_params,
            dlp_marker,
            telemetry_marker,
            ioc_match,
            behavioral_anomaly,
            failures,
        }
    }

    /// Appends the action to the session chain.
    ///
    /// Called by the orchestrator once the outcome is settled. Splitting this from
    /// [`RiskStage::evaluate`] keeps the chain history stable for the duration of an
    /// approval prompt.
    pub fn record(&self, action: &AgentAction) {
        self.session.record_action(action);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::action::{Arguments, Runtime, SourceRef};
    use crate::scoring::SCORE_SEMANTICS;

    fn action(tool: &str, arguments: serde_json::Value) -> AgentAction {
        let mut built =
            AgentAction::builder(tool, Arguments::from_name_and_arguments(tool, &arguments))
                .source(SourceRef::new(Runtime::MCP_STDIO, "test"))
                .build_unvalidated();
        built.refresh_security_classification();
        built
    }

    /// Runs both halves of the stage the way the orchestrator does.
    fn assess(stage: &RiskStage, action: &AgentAction, threshold: Option<u8>) -> RiskAssessment {
        let analysis = stage.scan(action);
        stage.evaluate(action, analysis, threshold, None)
    }

    #[test]
    fn low_risk_action_needs_no_approval() {
        let stage = RiskStage::default();
        let assessment = assess(
            &stage,
            &action("read_file", serde_json::json!({"path": "/tmp/a"})),
            None,
        );

        assert!(!assessment.requires_approval);
        assert!(assessment.reasons.is_empty());
        assert!(assessment.sanitized_payload.is_none());
        assert_eq!(assessment.explanation.semantics, SCORE_SEMANTICS);
    }

    #[test]
    fn shell_execution_crosses_the_default_threshold() {
        let stage = RiskStage::default();
        let assessment = assess(
            &stage,
            &action("execute_bash", serde_json::json!({"command": "ls"})),
            None,
        );

        assert!(assessment.requires_approval);
        assert_eq!(assessment.telemetry_marker, TELEMETRY_RISK_THRESHOLD);
        assert!(assessment
            .reasons
            .iter()
            .any(|reason| reason.code == ReasonCode::RiskThresholdExceeded));
        assert!(assessment
            .explanation
            .has_factor(RiskFactorKind::PolicySensitiveOperation));
    }

    #[test]
    fn threshold_from_policy_is_honored() {
        let stage = RiskStage::default();
        let low = action("read_file", serde_json::json!({"path": "/tmp/a"}));

        assert!(!assess(&stage, &low, Some(100)).requires_approval);
        assert!(assess(&stage, &low, Some(0)).requires_approval);
    }

    /// Effective score is at least the content-scan baseline (tool floor / DLP).
    #[test]
    fn scan_score_is_a_floor_for_the_risk_stage() {
        let stage = RiskStage::default();
        let probe = action("execute_bash", serde_json::json!({"command": "ls"}));

        let analysis = stage.scan(&probe);
        let baseline = analysis.score;
        let assessment = stage.evaluate(&probe, analysis, None, None);

        assert!(
            assessment.score >= baseline,
            "effective score {} must not drop below scan score {}",
            assessment.score,
            baseline
        );
        assert!(!assessment.explanation.factors.is_empty());
    }

    #[test]
    fn explainable_score_is_stable_across_evaluate_calls() {
        let stage = RiskStage::default();
        let probe = action(
            "fetch",
            serde_json::json!({"url": "https://api.example.com/v1"}),
        );
        let first = assess(&stage, &probe, None);
        let second = assess(&stage, &probe, None);
        assert_eq!(first.explanation, second.explanation);
        assert_eq!(first.score, second.score);
        assert_eq!(first.level, second.level);
    }

    #[test]
    fn ioc_match_forces_approval_and_sets_the_denial_message() {
        let matcher = Arc::new(ThreatIntelMatcher::from_blacklist(&["evil-c2.example"]));
        let stage = RiskStage::new(matcher, Arc::new(SessionTracker::default()));

        let assessment = assess(
            &stage,
            &action(
                "fetch",
                serde_json::json!({"url": "https://evil-c2.example/exfil"}),
            ),
            None,
        );

        assert!(assessment.ioc_match);
        assert!(assessment.requires_approval);
        assert!(assessment
            .explanation
            .has_factor(RiskFactorKind::ThreatIntel));
        assert_eq!(
            assessment.denial_detail(),
            "THREAT_INTEL_IOC_MATCH: operator denied IOC-tainted tool call"
        );
    }

    #[test]
    fn behavioral_chain_outranks_ioc_in_the_denial_message() {
        let assessment = RiskAssessment {
            score: 100,
            level: RiskLevel::Critical,
            threshold: 70,
            requires_approval: true,
            explanation: ExplainableRiskScore {
                score: 100,
                level: RiskLevel::Critical,
                factors: Vec::new(),
                semantics: SCORE_SEMANTICS,
            },
            reasons: Vec::new(),
            matched_policies: Vec::new(),
            sanitized_payload: None,
            dlp_marker: None,
            telemetry_marker: TELEMETRY_RISK_THRESHOLD,
            ioc_match: true,
            behavioral_anomaly: true,
            failures: Vec::new(),
        };

        assert_eq!(
            assessment.denial_detail(),
            "BEHAVIORAL_CHAIN_ANOMALY: operator denied exfiltration-risk tool chain"
        );
    }

    #[test]
    fn masked_secret_selects_the_secret_egress_marker() {
        let stage = RiskStage::default();
        let assessment = assess(
            &stage,
            &action(
                "post_message",
                serde_json::json!({"body": "sk-proj-abcdefghijklmnopqrstuvwxyz0123456789ABCD"}),
            ),
            None,
        );

        if let Some(marker) = assessment.dlp_marker {
            assert_eq!(marker, TELEMETRY_SECRET_EGRESS);
            assert!(assessment.sanitized_payload.is_some());
            assert!(assessment
                .reasons
                .iter()
                .any(|reason| reason.code == ReasonCode::SecretEgressMasked));
            assert!(assessment
                .explanation
                .has_factor(RiskFactorKind::ContentSecret));
        }
    }

    #[test]
    fn evaluate_does_not_append_to_the_session_chain() {
        let session = Arc::new(SessionTracker::default());
        let stage = RiskStage::new(Arc::new(ThreatIntelMatcher::default()), session.clone());
        let probe = action("read_file", serde_json::json!({"path": "/tmp/a"}));

        for _ in 0..5 {
            assess(&stage, &probe, None);
        }

        let fetch = action("fetch", serde_json::json!({"url": "https://example.com"}));
        assert!(
            !assess(&stage, &fetch, None).behavioral_anomaly,
            "no filesystem reads were recorded, so no chain should be detected"
        );
    }
}
