//! Typed decision model produced by the [Agent Execution Gateway](crate::gateway).
//!
//! Every evaluation ends in exactly one [`Decision`] wrapped in an [`EvaluationOutcome`]
//! that carries why the gateway landed there. The outcome is the only thing a caller needs
//! in order to enforce: it holds the verdict, the reasons, the rules that matched, the risk
//! score when one was computed, and the rewritten payload when a stage mutated it.
//!
//! # Why a separate type from `GuardDecision`
//!
//! [`crate::guard::GuardDecision`] is a two-variant enum (`Allow`/`Block`) that collapses
//! "the operator approved this" and "nothing objected" into the same value, and cannot
//! express "this needs approval but I have no operator to ask". It is kept as the wire type
//! for the existing relays; [`EvaluationOutcome`] is the model the pipeline actually reasons
//! in, and [`EvaluationOutcome::into_guard_decision`] projects one onto the other.

use std::collections::BTreeMap;
use std::time::Duration;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use super::posture::PolicyAvailability;
use crate::action::{ActionId, SessionId, TraceId};
use crate::scoring::{RiskFactor, RiskLevel};

/// The three terminal verdicts the gateway can reach.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum Decision {
    /// The action may proceed, possibly with a rewritten payload.
    Allow,
    /// The action must not proceed.
    Deny,
    /// The action needs an out-of-band approval before it can proceed.
    ///
    /// The gateway only returns this when no [`crate::gateway::ApprovalEngine`] is
    /// configured to resolve it in-band. A caller that receives it must either obtain an
    /// approval and re-submit, or treat it as [`Decision::Deny`] — never as
    /// [`Decision::Allow`].
    RequireApproval,
}

impl Decision {
    /// Returns the stable wire representation.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Allow => "ALLOW",
            Self::Deny => "DENY",
            Self::RequireApproval => "REQUIRE_APPROVAL",
        }
    }

    /// Returns `true` when the action may proceed without further gating.
    pub fn is_allowed(&self) -> bool {
        matches!(self, Self::Allow)
    }

    /// Returns `true` when the action must be stopped as-is.
    ///
    /// Groups [`Decision::Deny`] with [`Decision::RequireApproval`] because an unresolved
    /// approval is not permission to run.
    pub fn stops_execution(&self) -> bool {
        !self.is_allowed()
    }
}

/// Pipeline stage that produced a reason.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Stage {
    /// Provider adapter turning a wire format into an [`crate::action::AgentAction`].
    Normalization,
    /// Identity and ambient-context enrichment.
    Identity,
    /// Declarative policy plus Wasm policy extensions.
    Policy,
    /// Risk scoring, threat intel, behavioral chains, and DLP.
    Risk,
    /// Operator or external approval resolution.
    Approval,
    /// Behavioral detection signals (deterministic / statistical).
    Behavior,
    /// Payload mutation applied on the way out.
    Enforcement,
    /// Audit event emission.
    Audit,
}

impl Stage {
    /// Returns the stable wire representation.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Normalization => "normalization",
            Self::Identity => "identity",
            Self::Policy => "policy",
            Self::Risk => "risk",
            Self::Approval => "approval",
            Self::Behavior => "behavior",
            Self::Enforcement => "enforcement",
            Self::Audit => "audit",
        }
    }
}

/// Machine-readable classification of a single reason.
///
/// Codes are stable identifiers meant for dashboards, alert routing, and tests. The
/// human-readable text lives in [`DecisionReason::detail`], which for block paths is the
/// verbatim string the pre-gateway guard produced.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReasonCode {
    /// A provider payload could not be normalized into an action.
    NormalizationFailed,
    /// A global block pattern matched.
    PolicyGlobalBlockPattern,
    /// A per-tool block pattern matched.
    PolicyToolBlockPattern,
    /// The tool is configured with `action: Block`.
    PolicyToolActionBlock,
    /// The tool is configured with `action: Confirm`.
    PolicyConfirmationRequired,
    /// Policy evaluated in audit-only mode — action was allowed but would have been blocked.
    PolicyAuditOnly,
    /// Global redact keys rewrote the payload.
    PolicyRedaction,
    /// An identity resolver failed to enrich the action.
    IdentityEnrichmentFailed,
    /// No policy engine was loaded.
    PolicyUnavailable,
    /// The policy engine failed while evaluating.
    PolicyEvaluationFailed,
    /// The action's arguments could not be parsed, so no rule could be matched on them.
    PolicyPayloadUnreadable,
    /// A Wasm policy extension blocked the action.
    ExtensionBlock,
    /// A Wasm policy extension rewrote the payload.
    ExtensionRewrite,
    /// A Wasm policy extension failed to execute.
    ExtensionFailed,
    /// The payload matched a threat-intel indicator.
    ThreatIntelMatch,
    /// The threat-intel indicator set could not be read.
    ThreatIntelUnavailable,
    /// The session's tool sequence matched an exfiltration chain.
    BehavioralChainAnomaly,
    /// A deterministic behavioral detector raised a signal (policy may act on it).
    BehavioralSignal,
    /// The computed risk score met or exceeded the configured threshold.
    RiskThresholdExceeded,
    /// The risk scorer ran in a degraded mode and its score is less trustworthy.
    RiskScoringDegraded,
    /// A secret value was masked before forwarding.
    SecretEgressMasked,
    /// Sensitive non-secret data was masked before forwarding.
    SensitiveDataMasked,
    /// The DLP scanner found sensitive data and could not produce the masked payload.
    DlpScannerFailed,
    /// An operator approved the action.
    OperatorApproved,
    /// An operator denied the action.
    OperatorDenied,
    /// A previously issued scoped approval grant authorized this action.
    ApprovalGrantReused,
    /// An approval grant was presented but did not match the action binding (tamper/replay).
    ApprovalGrantInvalid,
    /// An approval grant was past its expiry.
    ApprovalGrantExpired,
    /// Approval was required but no approver could be reached.
    ApprovalUnavailable,
    /// An approval request exceeded its deadline.
    ApprovalTimedOut,
    /// Approval was required and no approval engine is configured to resolve it.
    ApprovalDeferred,
    /// A subsystem failed and its failure mode escalated the action to an approval.
    DegradedToApproval,
    /// The control plane was unreachable while a policy required it.
    CloudUnavailable,
    /// An audit sink failed to record the event.
    AuditDeliveryFailed,
    /// A stage panicked or failed in a way nothing classified.
    InternalError,
}

impl ReasonCode {
    /// Returns `true` when this code represents a *rule prohibition* rather than a
    /// *judgment about risk*.
    ///
    /// The distinction is what a caller needs in order to tell the agent why it was
    /// stopped: a prohibition means "this is not permitted here, do not retry", while a
    /// judgment means "a human refused this particular attempt". The stdio relay uses it to
    /// choose between its two JSON-RPC error codes.
    ///
    /// Enforcement failures count as prohibitions: a policy that exists and cannot be
    /// applied is a configuration problem, not a verdict on the action.
    pub fn is_rule_prohibition(&self) -> bool {
        matches!(
            self,
            Self::NormalizationFailed
                | Self::PolicyGlobalBlockPattern
                | Self::PolicyToolBlockPattern
                | Self::PolicyToolActionBlock
                | Self::PolicyRedaction
                | Self::PolicyUnavailable
                | Self::PolicyEvaluationFailed
                | Self::PolicyPayloadUnreadable
                | Self::ExtensionBlock
                | Self::ExtensionRewrite
                | Self::ExtensionFailed
                | Self::DlpScannerFailed
                | Self::CloudUnavailable
                | Self::AuditDeliveryFailed
                | Self::InternalError
        )
    }

    /// Returns `true` when this code reports a subsystem that could not do its job.
    ///
    /// Distinct from [`ReasonCode::is_rule_prohibition`], which asks *how to tell the
    /// agent*. This asks *whether an operator needs to go fix something*, and is what
    /// selects the reasons that get their own audit event regardless of verdict.
    pub fn is_security_failure(&self) -> bool {
        matches!(
            self,
            Self::NormalizationFailed
                | Self::PolicyUnavailable
                | Self::PolicyEvaluationFailed
                | Self::PolicyPayloadUnreadable
                | Self::ExtensionFailed
                | Self::RiskScoringDegraded
                | Self::DlpScannerFailed
                | Self::ThreatIntelUnavailable
                | Self::ApprovalUnavailable
                | Self::ApprovalTimedOut
                | Self::IdentityEnrichmentFailed
                | Self::AuditDeliveryFailed
                | Self::CloudUnavailable
                | Self::InternalError
        )
    }

    /// Returns the stable wire representation.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::NormalizationFailed => "normalization_failed",
            Self::PolicyGlobalBlockPattern => "policy_global_block_pattern",
            Self::PolicyToolBlockPattern => "policy_tool_block_pattern",
            Self::PolicyToolActionBlock => "policy_tool_action_block",
            Self::PolicyConfirmationRequired => "policy_confirmation_required",
            Self::PolicyAuditOnly => "policy_audit_only",
            Self::PolicyRedaction => "policy_redaction",
            Self::IdentityEnrichmentFailed => "identity_enrichment_failed",
            Self::PolicyUnavailable => "policy_unavailable",
            Self::PolicyEvaluationFailed => "policy_evaluation_failed",
            Self::PolicyPayloadUnreadable => "policy_payload_unreadable",
            Self::ExtensionBlock => "extension_block",
            Self::ExtensionRewrite => "extension_rewrite",
            Self::ExtensionFailed => "extension_failed",
            Self::ThreatIntelMatch => "threat_intel_match",
            Self::ThreatIntelUnavailable => "threat_intel_unavailable",
            Self::BehavioralChainAnomaly => "behavioral_chain_anomaly",
            Self::BehavioralSignal => "behavioral_signal",
            Self::RiskThresholdExceeded => "risk_threshold_exceeded",
            Self::RiskScoringDegraded => "risk_scoring_degraded",
            Self::SecretEgressMasked => "secret_egress_masked",
            Self::SensitiveDataMasked => "sensitive_data_masked",
            Self::DlpScannerFailed => "dlp_scanner_failed",
            Self::OperatorApproved => "operator_approved",
            Self::OperatorDenied => "operator_denied",
            Self::ApprovalGrantReused => "approval_grant_reused",
            Self::ApprovalGrantInvalid => "approval_grant_invalid",
            Self::ApprovalGrantExpired => "approval_grant_expired",
            Self::ApprovalUnavailable => "approval_unavailable",
            Self::ApprovalTimedOut => "approval_timed_out",
            Self::ApprovalDeferred => "approval_deferred",
            Self::DegradedToApproval => "degraded_to_approval",
            Self::CloudUnavailable => "cloud_unavailable",
            Self::AuditDeliveryFailed => "audit_delivery_failed",
            Self::InternalError => "internal_error",
        }
    }
}

/// One contributing factor behind a decision.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DecisionReason {
    /// Stage that raised this reason.
    pub stage: Stage,
    /// Machine-readable classification.
    pub code: ReasonCode,
    /// Operator-facing explanation.
    ///
    /// For decisions that stop execution this string is surfaced to the calling agent, and
    /// the stdio relay selects its JSON-RPC error code by inspecting it, so its exact
    /// wording is part of the observable contract.
    ///
    /// Always sanitized: see [`DecisionReason::new`].
    pub detail: String,
}

impl DecisionReason {
    /// Builds a reason, sanitizing `detail`.
    ///
    /// `detail` passes through [`super::redact::sanitize_detail`], which masks secrets,
    /// strips URL credentials, removes control characters, and truncates. This is the
    /// choke point that makes a leaking reason unconstructible: a reason is the only way
    /// text reaches an outcome, an audit record, or a JSON-RPC error, and there is no
    /// constructor that skips the sanitizer.
    ///
    /// Sanitizing is idempotent and leaves clean text — every deliberate block message in
    /// this crate — byte-identical, so the strings the end-to-end suite greps for are
    /// unaffected.
    pub fn new(stage: Stage, code: ReasonCode, detail: impl Into<String>) -> Self {
        Self {
            stage,
            code,
            detail: super::redact::sanitize_detail(&detail.into()),
        }
    }
}

/// Where a matched rule came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PolicySource {
    /// The declarative YAML policy, local file or control-plane synced.
    LocalPolicy,
    /// A Wasm policy extension.
    WasmExtension,
    /// The threat-intel indicator feed.
    ThreatIntel,
    /// Session behavioral analytics.
    BehavioralAnalytics,
    /// The numeric risk threshold.
    RiskThreshold,
    /// The content DLP scanner.
    DataLossPrevention,
}

/// A rule that fired during evaluation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MatchedPolicy {
    /// Subsystem that owns the rule.
    pub source: PolicySource,
    /// Identifier of the rule within its source — a tool name, pattern, or marker.
    pub rule_id: String,
    /// Version of the ruleset, when the source tracks one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
    /// What this rule asked for, before other rules were merged in.
    pub effect: Decision,
}

impl MatchedPolicy {
    /// Builds a matched rule record.
    pub fn new(source: PolicySource, rule_id: impl Into<String>, effect: Decision) -> Self {
        Self {
            source,
            rule_id: rule_id.into(),
            version: None,
            effect,
        }
    }

    /// Attaches a ruleset version.
    pub fn with_version(mut self, version: Option<String>) -> Self {
        self.version = version;
        self
    }
}

/// Serializes [`Duration`] as whole microseconds so the field is stable across languages.
mod latency_micros {
    use std::time::Duration;

    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(value: &Duration, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_u64(u64::try_from(value.as_micros()).unwrap_or(u64::MAX))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Duration, D::Error> {
        Ok(Duration::from_micros(u64::deserialize(deserializer)?))
    }
}

/// The complete result of evaluating one [`crate::action::AgentAction`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EvaluationOutcome {
    /// The verdict.
    pub decision: Decision,
    /// Everything that contributed, in the order the stages ran.
    pub reasons: Vec<DecisionReason>,
    /// Rules that fired.
    pub matched_policies: Vec<MatchedPolicy>,
    /// Effective risk score, absent when no stage computed one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub risk_score: Option<u8>,
    /// Coarse risk band derived from the explainable score.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub risk_level: Option<RiskLevel>,
    /// Explainable factors behind the score (empty when not scored).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub risk_factors: Vec<RiskFactor>,
    /// Ordinal-severity disclaimer — not a probability.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub risk_semantics: Option<String>,
    /// Version of the declarative policy that evaluated the action.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub policy_version: Option<String>,
    /// Whether a usable declarative policy snapshot was present for this evaluation.
    #[serde(default)]
    pub policy_availability: PolicyAvailability,
    /// When evaluation completed.
    pub timestamp: DateTime<Utc>,
    /// Wall-clock time the pipeline spent reaching this decision.
    #[serde(with = "latency_micros", rename = "latency_micros")]
    pub latency: Duration,
    /// Free-form annotations for telemetry and debugging.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub metadata: BTreeMap<String, String>,
    /// When policy runs in audit mode, the decision that would have applied under enforcement.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub simulated_decision: Option<Decision>,

    /// Action this outcome describes.
    pub action_id: ActionId,
    /// Session the action belonged to.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session_id: Option<SessionId>,
    /// Trace the action belonged to.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub trace_id: Option<TraceId>,
    /// Tool the action targeted, denormalized so an outcome is self-describing in logs.
    pub tool_name: String,

    /// Payload the enforcement stage produced, when a stage mutated it.
    ///
    /// Only meaningful for [`Decision::Allow`]. The caller must forward these bytes
    /// instead of the original payload.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rewritten_arguments: Option<String>,
}

impl EvaluationOutcome {
    /// Returns `true` when the action may proceed.
    pub fn is_allowed(&self) -> bool {
        self.decision.is_allowed()
    }

    /// Returns `true` when the action must not proceed as-is.
    pub fn stops_execution(&self) -> bool {
        self.decision.stops_execution()
    }

    /// Returns the reason that best explains the decision.
    ///
    /// For a stopped action this is the last reason recorded, which is the one the
    /// terminal stage produced.
    pub fn primary_reason(&self) -> Option<&DecisionReason> {
        if self.decision.is_allowed() {
            self.reasons.first()
        } else {
            self.reasons.last()
        }
    }

    /// Returns [`DecisionReason::detail`] of [`EvaluationOutcome::primary_reason`].
    pub fn primary_detail(&self) -> Option<&str> {
        self.primary_reason().map(|reason| reason.detail.as_str())
    }

    /// Returns `true` when any reason carries `code`.
    pub fn has_reason(&self, code: ReasonCode) -> bool {
        self.reasons.iter().any(|reason| reason.code == code)
    }

    /// Returns `true` when a rule prohibited the action, as opposed to a human or a risk
    /// judgment refusing it.
    ///
    /// See [`ReasonCode::is_rule_prohibition`]. Always `false` for an allowed action.
    pub fn denied_by_rule(&self) -> bool {
        self.stops_execution()
            && self
                .primary_reason()
                .is_some_and(|reason| reason.code.is_rule_prohibition())
    }

    /// Projects the outcome onto the legacy guard decision type.
    ///
    /// [`Decision::RequireApproval`] maps to `Block`: an unresolved approval is not
    /// permission to run, and the legacy type cannot express deferral.
    pub fn into_guard_decision(self) -> crate::guard::GuardDecision {
        let risk_score = self.risk_score.unwrap_or(0);

        if self.decision.is_allowed() {
            return crate::guard::GuardDecision::Allow {
                rewritten_params_json: self.rewritten_arguments,
                risk_score,
            };
        }

        let reason = self
            .primary_detail()
            .map(str::to_string)
            .unwrap_or_else(|| format!("blocked by {}", self.decision.as_str()));

        crate::guard::GuardDecision::Block { reason, risk_score }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn outcome(decision: Decision) -> EvaluationOutcome {
        EvaluationOutcome {
            decision,
            reasons: Vec::new(),
            matched_policies: Vec::new(),
            risk_score: Some(42),
            risk_level: Some(RiskLevel::Medium),
            risk_factors: Vec::new(),
            risk_semantics: Some(crate::scoring::SCORE_SEMANTICS.to_string()),
            policy_version: Some("1".to_string()),
            policy_availability: PolicyAvailability::Available,
            timestamp: Utc::now(),
            latency: Duration::from_micros(1234),
            metadata: BTreeMap::new(),
            action_id: ActionId::new("act_test"),
            session_id: None,
            trace_id: None,
            tool_name: "read_file".to_string(),
            rewritten_arguments: None,
            simulated_decision: None,
        }
    }

    #[test]
    fn require_approval_stops_execution() {
        assert!(Decision::RequireApproval.stops_execution());
        assert!(!Decision::RequireApproval.is_allowed());
    }

    #[test]
    fn unresolved_approval_projects_onto_block() {
        let decision = outcome(Decision::RequireApproval).into_guard_decision();
        assert!(matches!(
            decision,
            crate::guard::GuardDecision::Block { .. }
        ));
    }

    #[test]
    fn block_reason_is_the_terminal_reason_verbatim() {
        let mut outcome = outcome(Decision::Deny);
        outcome.reasons.push(DecisionReason::new(
            Stage::Risk,
            ReasonCode::ThreatIntelMatch,
            "earlier signal",
        ));
        outcome.reasons.push(DecisionReason::new(
            Stage::Approval,
            ReasonCode::OperatorDenied,
            "THREAT_INTEL_IOC_MATCH: operator denied IOC-tainted tool call",
        ));

        match outcome.into_guard_decision() {
            crate::guard::GuardDecision::Block { reason, risk_score } => {
                assert_eq!(
                    reason,
                    "THREAT_INTEL_IOC_MATCH: operator denied IOC-tainted tool call"
                );
                assert_eq!(risk_score, 42);
            }
            other => panic!("expected block, got {other:?}"),
        }
    }

    #[test]
    fn allow_carries_the_rewritten_payload() {
        let mut outcome = outcome(Decision::Allow);
        outcome.rewritten_arguments = Some(r#"{"name":"read_file"}"#.to_string());

        match outcome.into_guard_decision() {
            crate::guard::GuardDecision::Allow {
                rewritten_params_json,
                ..
            } => assert_eq!(
                rewritten_params_json.as_deref(),
                Some(r#"{"name":"read_file"}"#)
            ),
            other => panic!("expected allow, got {other:?}"),
        }
    }

    /// Pins the JSON-RPC error-code split the stdio relay derives from this
    /// classification. Before the gateway the relay inferred it by pattern-matching on the
    /// reason text; these are the cases that mapping produced.
    #[test]
    fn rule_prohibitions_are_separated_from_risk_judgments() {
        for code in [
            ReasonCode::PolicyGlobalBlockPattern,
            ReasonCode::PolicyToolBlockPattern,
            ReasonCode::PolicyToolActionBlock,
            ReasonCode::ExtensionBlock,
            ReasonCode::PolicyUnavailable,
            ReasonCode::CloudUnavailable,
        ] {
            assert!(
                code.is_rule_prohibition(),
                "{} must map to the policy-block error code",
                code.as_str()
            );
        }

        for code in [
            ReasonCode::OperatorDenied,
            ReasonCode::ApprovalUnavailable,
            ReasonCode::ApprovalDeferred,
            ReasonCode::ThreatIntelMatch,
            ReasonCode::BehavioralChainAnomaly,
            ReasonCode::RiskThresholdExceeded,
        ] {
            assert!(
                !code.is_rule_prohibition(),
                "{} must map to the access-denied error code",
                code.as_str()
            );
        }
    }

    #[test]
    fn denied_by_rule_reads_the_terminal_reason() {
        let mut policy_block = outcome(Decision::Deny);
        policy_block.reasons.push(DecisionReason::new(
            Stage::Policy,
            ReasonCode::PolicyGlobalBlockPattern,
            "global block pattern `\\.ssh/` matched tool `read_file`",
        ));

        let mut operator_denial = outcome(Decision::Deny);
        operator_denial.reasons.push(DecisionReason::new(
            Stage::Risk,
            ReasonCode::BehavioralChainAnomaly,
            "chain detected",
        ));
        operator_denial.reasons.push(DecisionReason::new(
            Stage::Approval,
            ReasonCode::OperatorDenied,
            "BEHAVIORAL_CHAIN_ANOMALY: operator denied exfiltration-risk tool chain",
        ));

        assert!(policy_block.denied_by_rule());
        assert!(
            !operator_denial.denied_by_rule(),
            "the approval judgment is terminal, not the earlier risk signal"
        );
    }

    #[test]
    fn an_allowed_action_is_never_denied_by_rule() {
        let mut allowed = outcome(Decision::Allow);
        allowed.reasons.push(DecisionReason::new(
            Stage::Policy,
            ReasonCode::PolicyRedaction,
            "redacted",
        ));

        assert!(!allowed.denied_by_rule());
    }

    #[test]
    fn latency_round_trips_as_microseconds() {
        let encoded = serde_json::to_value(outcome(Decision::Allow)).expect("serialize");
        assert_eq!(encoded["latency_micros"], 1234);
        assert_eq!(encoded["decision"], "ALLOW");

        let decoded: EvaluationOutcome = serde_json::from_value(encoded).expect("deserialize");
        assert_eq!(decoded.latency, Duration::from_micros(1234));
    }
}
