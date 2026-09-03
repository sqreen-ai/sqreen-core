//! The failure-mode strategy: one place that decides what every broken subsystem means.
//!
//! # Why this module exists
//!
//! The dangerous thing about an error in a security control is not the error, it is the
//! `unwrap_or(Allow)` somebody writes three files away to make the error go away. Once
//! that fallback exists nobody can answer "what does Sqreen do when the DLP scanner
//! fails?" without reading every call site, and the answer is usually "it depends".
//!
//! So no subsystem in this crate decides what its own failure means. A subsystem that
//! cannot do its job reports a [`SubsystemFailure`]; [`FailurePolicy`] turns that into a
//! [`FailureAction`]; the gateway applies it. Changing the posture of a deployment is
//! editing one struct, and auditing the posture is reading one table.
//!
//! # The three modes
//!
//! | Mode | Meaning | When it is right |
//! |---|---|---|
//! | [`FailureMode::FailOpen`] | Record the failure, keep the verdict. | The subsystem *describes*; nothing reads it to decide. Losing it costs attribution, not enforcement. |
//! | [`FailureMode::DegradeSafely`] | Record the failure, and refuse to allow the action on the strength of a control that did not run — escalate it to an approval. | The subsystem *inspects*. Its silence is not evidence of safety, but stopping outright would break more than it protects. |
//! | [`FailureMode::FailClosed`] | Deny. | The subsystem exists to say "no". If it cannot answer, the answer is no. |
//!
//! [`FailureMode::DegradeSafely`] is the mode that makes "never silently allow" achievable
//! without making the proxy brittle. An action that reaches it is neither allowed nor
//! rejected on its own merits: it is handed to an approver with the failure attached as
//! the justification. When no approver is reachable the approval subsystem's own mode
//! ([`FailurePolicy::approval_unavailable`], fail-closed by default) takes over, so a
//! degraded action can never end up allowed by default.
//!
//! # The matrix
//!
//! | Subsystem | Failure it reports | Default | Rationale |
//! |---|---|---|---|
//! | [`Subsystem::Normalization`] | Malformed provider payload, unknown action type, unsupported provider event | **FAIL_CLOSED** | An action nobody can parse is an action nobody can evaluate. Enforced at the adapters, before the gateway. |
//! | [`Subsystem::PolicyMissing`] | No declarative policy loaded | **FAIL_CLOSED** | Default posture is [`crate::gateway::EnforcementPosture::Enforcing`]. Opt into FAIL_OPEN only via `SQREEN_ENFORCEMENT_POSTURE=development`. |
//! | [`Subsystem::PolicyEngine`] | Corrupt policy, regex failure, redaction produced non-UTF-8 | **FAIL_CLOSED** | A policy that exists and cannot be applied is an enforcement outage, not an absence of rules. |
//! | [`Subsystem::PolicyPayload`] | Arguments could not be parsed, so no rule could be matched against them | **FAIL_CLOSED** | The historical silent allow. A payload the inspector cannot read is exactly the payload an attacker wants it to receive. |
//! | [`Subsystem::PolicyExtension`] | Wasm trap, fuel exhaustion, host error | **FAIL_CLOSED** | The extension was installed to make a decision. |
//! | [`Subsystem::RiskScoring`] | Scorer could not parse the payload and fell back to raw-text scanning | **DEGRADE_SAFELY** | The action is still scored, but with a weaker scanner, so it does not get to pass on that score alone. |
//! | [`Subsystem::DlpScanner`] | Scanner matched sensitive data and then failed to produce the masked payload | **FAIL_CLOSED** | The only outcomes are "forward the unmasked secret" and "stop". |
//! | [`Subsystem::ThreatIntel`] | Indicator set could not be read | **DEGRADE_SAFELY** | Absence of indicators is not evidence of safety, but it is also not grounds to stop everything. |
//! | [`Subsystem::Approval`] | Approver unreachable, prompt failed, prompt timed out | **FAIL_CLOSED** | Already the invariant in [`crate::risk::prompt_user_confirmation`]. |
//! | [`Subsystem::Audit`] | Sink rejected the event | **FAIL_OPEN** | See below. |
//! | [`Subsystem::ControlPlane`] | Control plane unreachable | **FAIL_OPEN** | See below. |
//! | [`Subsystem::Internal`] | Panic or unclassified error inside a stage | **FAIL_CLOSED** | An unexplained failure in a security control is the least safe thing to guess about. |
//!
//! # Why audit and control-plane failures are the two open ones
//!
//! Requirement: *cloud connectivity must not be required to make a security decision.* The
//! gateway treats the control plane as a **replica, not an oracle** — policy is evaluated
//! from a local snapshot, approvals resolve locally, and telemetry is dispatched on a
//! detached task whose failure cannot reach the verdict. Enforcement on a laptop that is
//! offline, or pointed at a control plane that is down, is identical to enforcement on a
//! connected one.
//!
//! Both are *recorded*, never swallowed: a failed audit emits a
//! [`ReasonCode::AuditDeliveryFailed`] reason onto the outcome, so "we allowed this and
//! could not log it" is itself visible in the outcome the caller receives.
//!
//! A deployment where an unlogged action is itself a finding opts into the other trade by
//! setting these to [`FailureMode::FailClosed`], which is what [`FailurePolicy::strict`]
//! does. That buys auditability with availability, and is never the default.

use std::fmt;

use serde::{Deserialize, Serialize};

use super::decision::{Decision, DecisionReason, ReasonCode, Stage};
use super::posture::EnforcementPosture;

/// Environment variable selecting a [`FailurePolicy`] preset.
///
/// Accepts `strict`, `default`, or `observe`. An unrecognized value is reported on stderr
/// and ignored in favor of [`FailurePolicy::default`], because silently applying a
/// posture the operator did not ask for is the failure this module exists to prevent.
///
/// Composes with [`crate::gateway::ENFORCEMENT_POSTURE_ENV`]: the enforcement posture
/// sets the default for [`FailurePolicy::missing_policy`] unless `observe` / `strict`
/// already made an explicit choice.
pub const FAILURE_POLICY_ENV: &str = "SQREEN_FAILURE_POLICY";

/// Which way a subsystem fails when it cannot do its job.
///
/// Ordered by severity, so merging the modes of several failures is `max()`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum FailureMode {
    /// Record the failure and let the verdict stand.
    FailOpen,
    /// Record the failure and escalate the action to an approval rather than allowing it.
    DegradeSafely,
    /// Deny the action.
    FailClosed,
}

impl FailureMode {
    /// Returns the stable wire representation.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::FailOpen => "FAIL_OPEN",
            Self::DegradeSafely => "DEGRADE_SAFELY",
            Self::FailClosed => "FAIL_CLOSED",
        }
    }

    /// Returns `true` when this mode stops the action outright.
    pub fn is_closed(&self) -> bool {
        matches!(self, Self::FailClosed)
    }

    /// Returns `true` when this mode lets the action be allowed on its own merits.
    ///
    /// Only [`FailureMode::FailOpen`] does. [`FailureMode::DegradeSafely`] does not: it
    /// withholds the allow and asks a human instead.
    pub fn permits_allow(&self) -> bool {
        matches!(self, Self::FailOpen)
    }

    /// Maps the mode onto the action it implies.
    pub fn action(&self) -> FailureAction {
        match self {
            Self::FailOpen => FailureAction::Continue,
            Self::DegradeSafely => FailureAction::Escalate,
            Self::FailClosed => FailureAction::Deny,
        }
    }
}

impl fmt::Display for FailureMode {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// What the gateway does about a failure, after [`FailurePolicy`] has ruled on it.
///
/// Ordered by severity so the orchestrator can fold several failures with `max()`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum FailureAction {
    /// Keep evaluating; the failure is recorded as a reason.
    Continue,
    /// Keep evaluating, but withhold the allow: the action must clear an approval.
    Escalate,
    /// Stop the action.
    Deny,
}

impl FailureAction {
    /// Returns the decision this action forces, or `None` to leave the verdict alone.
    pub fn forced_decision(&self) -> Option<Decision> {
        match self {
            Self::Continue => None,
            Self::Escalate => Some(Decision::RequireApproval),
            Self::Deny => Some(Decision::Deny),
        }
    }
}

/// A security-sensitive subsystem whose failure needs a defined meaning.
///
/// Each variant owns the [`Stage`] it belongs to and the [`ReasonCode`] its failure
/// produces, so the classification of a failure is decided here rather than at the dozen
/// places that can raise one.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Subsystem {
    /// Provider adapters: malformed payloads, unknown action types, unsupported providers.
    Normalization,
    /// No declarative policy is loaded.
    PolicyMissing,
    /// The declarative policy engine could not be applied.
    PolicyEngine,
    /// The action's arguments could not be parsed, so no rule could be matched on them.
    PolicyPayload,
    /// A Wasm policy extension trapped, ran out of fuel, or failed in the host.
    PolicyExtension,
    /// The risk scorer ran in a degraded mode.
    RiskScoring,
    /// The DLP scanner could not produce the masked payload it decided was needed.
    DlpScanner,
    /// The threat-intel indicator set could not be read.
    ThreatIntel,
    /// No approval could be obtained: unreachable, failed, or timed out.
    Approval,
    /// An audit sink rejected an event.
    Audit,
    /// The control plane was unreachable.
    ControlPlane,
    /// A panic or otherwise unclassified failure inside a stage.
    Internal,
}

impl Subsystem {
    /// Every subsystem, for exhaustive iteration in tests and documentation.
    pub const ALL: [Subsystem; 12] = [
        Self::Normalization,
        Self::PolicyMissing,
        Self::PolicyEngine,
        Self::PolicyPayload,
        Self::PolicyExtension,
        Self::RiskScoring,
        Self::DlpScanner,
        Self::ThreatIntel,
        Self::Approval,
        Self::Audit,
        Self::ControlPlane,
        Self::Internal,
    ];

    /// Returns the stable wire representation.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Normalization => "normalization",
            Self::PolicyMissing => "policy_missing",
            Self::PolicyEngine => "policy_engine",
            Self::PolicyPayload => "policy_payload",
            Self::PolicyExtension => "policy_extension",
            Self::RiskScoring => "risk_scoring",
            Self::DlpScanner => "dlp_scanner",
            Self::ThreatIntel => "threat_intel",
            Self::Approval => "approval",
            Self::Audit => "audit",
            Self::ControlPlane => "control_plane",
            Self::Internal => "internal",
        }
    }

    /// Returns the pipeline stage this subsystem belongs to.
    pub fn stage(&self) -> Stage {
        match self {
            Self::Normalization => Stage::Normalization,
            Self::PolicyMissing
            | Self::PolicyEngine
            | Self::PolicyPayload
            | Self::PolicyExtension => Stage::Policy,
            Self::RiskScoring | Self::DlpScanner | Self::ThreatIntel => Stage::Risk,
            Self::Approval => Stage::Approval,
            Self::Audit => Stage::Audit,
            Self::ControlPlane => Stage::Policy,
            Self::Internal => Stage::Enforcement,
        }
    }

    /// Returns the reason code a failure of this subsystem carries.
    pub fn reason_code(&self) -> ReasonCode {
        match self {
            Self::Normalization => ReasonCode::NormalizationFailed,
            Self::PolicyMissing => ReasonCode::PolicyUnavailable,
            Self::PolicyEngine => ReasonCode::PolicyEvaluationFailed,
            Self::PolicyPayload => ReasonCode::PolicyPayloadUnreadable,
            Self::PolicyExtension => ReasonCode::ExtensionFailed,
            Self::RiskScoring => ReasonCode::RiskScoringDegraded,
            Self::DlpScanner => ReasonCode::DlpScannerFailed,
            Self::ThreatIntel => ReasonCode::ThreatIntelUnavailable,
            Self::Approval => ReasonCode::ApprovalUnavailable,
            Self::Audit => ReasonCode::AuditDeliveryFailed,
            Self::ControlPlane => ReasonCode::CloudUnavailable,
            Self::Internal => ReasonCode::InternalError,
        }
    }

    /// Returns the audit `pattern_matched` marker for a failure of this subsystem.
    ///
    /// Prefixed so a control-plane query can select every security failure with one
    /// `LIKE 'security_failure:%'`, rather than enumerating markers.
    pub fn audit_marker(&self) -> String {
        format!("security_failure:{}", self.as_str())
    }
}

impl fmt::Display for Subsystem {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// A subsystem reporting that it could not do its job.
///
/// The only way a failure enters the pipeline. Construction sanitizes `detail` through
/// [`super::redact::sanitize_detail`], so a failure carrying a payload fragment cannot
/// leak it into a reason, an audit record, or a log line.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SubsystemFailure {
    /// What broke.
    pub subsystem: Subsystem,
    /// Operator-facing explanation, already sanitized.
    pub detail: String,
}

impl SubsystemFailure {
    /// Reports a failure of `subsystem`.
    pub fn new(subsystem: Subsystem, detail: impl AsRef<str>) -> Self {
        Self {
            subsystem,
            detail: super::redact::sanitize_detail(detail.as_ref()),
        }
    }

    /// Renders the failure as a decision reason.
    pub fn to_reason(&self) -> DecisionReason {
        DecisionReason::new(
            self.subsystem.stage(),
            self.subsystem.reason_code(),
            format!("{} unavailable: {}", self.subsystem, self.detail),
        )
    }
}

impl fmt::Display for SubsystemFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}: {}", self.subsystem, self.detail)
    }
}

/// The failure mode of every security-sensitive subsystem, in one value.
///
/// See the [module documentation](self) for the matrix and the reasoning behind each
/// default. Construct with [`FailurePolicy::default`], [`FailurePolicy::strict`],
/// [`FailurePolicy::observe`], or [`FailurePolicy::from_env`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct FailurePolicy {
    /// A provider payload could not be normalized into an action.
    pub normalization_error: FailureMode,
    /// No declarative policy engine is loaded.
    pub missing_policy: FailureMode,
    /// The declarative policy engine failed to evaluate.
    pub policy_error: FailureMode,
    /// The action's arguments could not be parsed, so no rule could match on them.
    pub policy_payload_unreadable: FailureMode,
    /// A Wasm policy extension failed to execute.
    pub extension_error: FailureMode,
    /// The risk scorer ran in a degraded mode.
    pub risk_error: FailureMode,
    /// The DLP scanner failed to produce a masked payload it had decided was needed.
    pub dlp_error: FailureMode,
    /// The threat-intel indicator set could not be read.
    pub threat_intel_error: FailureMode,
    /// Approval was required and no approver could be reached.
    pub approval_unavailable: FailureMode,
    /// An audit sink failed to record an event.
    pub audit_error: FailureMode,
    /// The control plane was unreachable.
    pub cloud_unavailable: FailureMode,
    /// A stage panicked or failed in a way nothing classified.
    pub internal_error: FailureMode,
}

impl Default for FailurePolicy {
    /// The shipped posture. See the matrix in the [module documentation](self).
    ///
    /// [`Subsystem::PolicyMissing`] is **FAIL_CLOSED** so an absent policy cannot silently
    /// become allow-all. Local experimentation opts into FAIL_OPEN via
    /// `SQREEN_ENFORCEMENT_POSTURE=development`.
    fn default() -> Self {
        Self {
            normalization_error: FailureMode::FailClosed,
            missing_policy: FailureMode::FailClosed,
            policy_error: FailureMode::FailClosed,
            policy_payload_unreadable: FailureMode::FailClosed,
            extension_error: FailureMode::FailClosed,
            risk_error: FailureMode::DegradeSafely,
            dlp_error: FailureMode::FailClosed,
            threat_intel_error: FailureMode::DegradeSafely,
            approval_unavailable: FailureMode::FailClosed,
            audit_error: FailureMode::FailOpen,
            cloud_unavailable: FailureMode::FailOpen,
            internal_error: FailureMode::FailClosed,
        }
    }
}

impl FailurePolicy {
    /// Reads [`FAILURE_POLICY_ENV`] and [`EnforcementPosture::from_env`], falling back to
    /// [`FailurePolicy::default`].
    ///
    /// An unrecognized failure-policy value warns on stderr rather than being applied as
    /// some nearest match, because a typo silently selecting a weaker posture is the class
    /// of bug this module exists to eliminate.
    pub fn from_env() -> Self {
        let posture = EnforcementPosture::from_env();
        let mut policy = match std::env::var(FAILURE_POLICY_ENV) {
            Ok(raw) => match raw.trim().to_ascii_lowercase().as_str() {
                "" => Self::default(),
                "strict" => Self::strict(),
                "default" | "balanced" => Self::default(),
                "observe" | "observability" | "monitor" => {
                    eprintln!(
                        "mcp-proxy: WARNING — {FAILURE_POLICY_ENV}=observe is not a security \
                         posture; broken controls will not deny by default"
                    );
                    Self::observe()
                }
                other => {
                    eprintln!(
                        "mcp-proxy: unrecognized {FAILURE_POLICY_ENV}=`{other}`; \
                         using the default failure policy (expected strict|default|observe)"
                    );
                    Self::default()
                }
            },
            Err(_) => Self::default(),
        };

        // Enforcement posture owns missing-policy unless the operator picked `observe`
        // (explicit open) or `strict` (already closed).
        let failure_preset = std::env::var(FAILURE_POLICY_ENV)
            .ok()
            .map(|raw| raw.trim().to_ascii_lowercase())
            .unwrap_or_default();
        if !matches!(
            failure_preset.as_str(),
            "observe" | "observability" | "monitor" | "strict"
        ) {
            policy.missing_policy = posture.missing_policy_mode();
        }

        policy
    }

    /// Builds a matrix for an explicit [`EnforcementPosture`] (tests / embedded callers).
    pub fn for_posture(posture: EnforcementPosture) -> Self {
        let mut policy = Self::default();
        policy.missing_policy = posture.missing_policy_mode();
        policy
    }

    /// Every subsystem fails closed, including audit and the control plane.
    ///
    /// For regulated deployments where an unlogged action is itself a finding. Trades
    /// availability for auditability: the agent stops working when the control plane is
    /// unreachable.
    pub fn strict() -> Self {
        Self {
            normalization_error: FailureMode::FailClosed,
            missing_policy: FailureMode::FailClosed,
            policy_error: FailureMode::FailClosed,
            policy_payload_unreadable: FailureMode::FailClosed,
            extension_error: FailureMode::FailClosed,
            risk_error: FailureMode::FailClosed,
            dlp_error: FailureMode::FailClosed,
            threat_intel_error: FailureMode::FailClosed,
            approval_unavailable: FailureMode::FailClosed,
            audit_error: FailureMode::FailClosed,
            cloud_unavailable: FailureMode::FailClosed,
            internal_error: FailureMode::FailClosed,
        }
    }

    /// Nothing fails closed except an unreachable approver.
    ///
    /// For validating the proxy against production traffic before letting it block, and
    /// for restoring the pre-hardening behavior of a deployment that was relying on
    /// unparseable payloads being forwarded. **Not a security posture** — every failure
    /// is still recorded, but a broken control stops protecting anything.
    pub fn observe() -> Self {
        Self {
            normalization_error: FailureMode::FailOpen,
            missing_policy: FailureMode::FailOpen,
            policy_error: FailureMode::FailOpen,
            policy_payload_unreadable: FailureMode::FailOpen,
            extension_error: FailureMode::FailOpen,
            risk_error: FailureMode::FailOpen,
            dlp_error: FailureMode::FailOpen,
            threat_intel_error: FailureMode::FailOpen,
            approval_unavailable: FailureMode::FailClosed,
            audit_error: FailureMode::FailOpen,
            cloud_unavailable: FailureMode::FailOpen,
            internal_error: FailureMode::FailOpen,
        }
    }

    /// Returns the mode configured for `subsystem`.
    pub fn mode_for(&self, subsystem: Subsystem) -> FailureMode {
        match subsystem {
            Subsystem::Normalization => self.normalization_error,
            Subsystem::PolicyMissing => self.missing_policy,
            Subsystem::PolicyEngine => self.policy_error,
            Subsystem::PolicyPayload => self.policy_payload_unreadable,
            Subsystem::PolicyExtension => self.extension_error,
            Subsystem::RiskScoring => self.risk_error,
            Subsystem::DlpScanner => self.dlp_error,
            Subsystem::ThreatIntel => self.threat_intel_error,
            Subsystem::Approval => self.approval_unavailable,
            Subsystem::Audit => self.audit_error,
            Subsystem::ControlPlane => self.cloud_unavailable,
            Subsystem::Internal => self.internal_error,
        }
    }

    /// Rules on a reported failure.
    ///
    /// The single decision point. Every fallback in the crate resolves here.
    pub fn decide(&self, failure: &SubsystemFailure) -> FailureAction {
        self.mode_for(failure.subsystem).action()
    }

    /// Returns `true` when no subsystem that *inspects* an action may fail open.
    ///
    /// Three subsystems are excluded, because an open mode on them is a property of the
    /// design rather than a hole in it:
    ///
    /// - [`Subsystem::Audit`] and [`Subsystem::ControlPlane`] record rather than inspect,
    ///   and their open defaults are what make the gateway local-first.
    /// - [`Subsystem::PolicyMissing`] is governed by [`EnforcementPosture`]: enforcing and
    ///   managed fail closed; development may fail open deliberately.
    pub fn never_allows_on_inspection_failure(&self) -> bool {
        Subsystem::ALL
            .iter()
            .filter(|subsystem| {
                !matches!(
                    subsystem,
                    Subsystem::Audit | Subsystem::ControlPlane | Subsystem::PolicyMissing
                )
            })
            .all(|subsystem| !self.mode_for(*subsystem).permits_allow())
    }

    /// Renders the matrix as `subsystem=MODE` pairs, for a startup banner or a test.
    pub fn describe(&self) -> Vec<(&'static str, &'static str)> {
        Subsystem::ALL
            .iter()
            .map(|subsystem| (subsystem.as_str(), self.mode_for(*subsystem).as_str()))
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::gateway::posture::EnforcementPosture;

    #[test]
    fn every_subsystem_has_a_configured_mode() {
        let policy = FailurePolicy::default();

        for subsystem in Subsystem::ALL {
            // Panics if `mode_for` ever grows a hole.
            let _ = policy.mode_for(subsystem);
            assert!(!subsystem.as_str().is_empty());
            assert!(subsystem.audit_marker().starts_with("security_failure:"));
        }
    }

    /// The property the whole module is for: no default lets a broken inspection control
    /// hand back a plain allow.
    #[test]
    fn no_inspecting_subsystem_may_fail_open_by_default() {
        let policy = FailurePolicy::default();

        for subsystem in [
            Subsystem::Normalization,
            Subsystem::PolicyEngine,
            Subsystem::PolicyPayload,
            Subsystem::PolicyExtension,
            Subsystem::RiskScoring,
            Subsystem::DlpScanner,
            Subsystem::ThreatIntel,
            Subsystem::Approval,
            Subsystem::Internal,
        ] {
            assert!(
                !policy.mode_for(subsystem).permits_allow(),
                "{subsystem} must not fail open by default"
            );
        }

        assert!(policy.never_allows_on_inspection_failure());
    }

    #[test]
    fn absent_policy_defaults_to_fail_closed_telemetry_remain_open() {
        let policy = FailurePolicy::default();

        assert_eq!(
            policy.mode_for(Subsystem::PolicyMissing),
            FailureMode::FailClosed
        );
        assert_eq!(policy.mode_for(Subsystem::Audit), FailureMode::FailOpen);
        assert_eq!(
            policy.mode_for(Subsystem::ControlPlane),
            FailureMode::FailOpen
        );
    }

    #[test]
    fn development_posture_permits_missing_policy_fail_open() {
        let policy = FailurePolicy::for_posture(EnforcementPosture::Development);
        assert_eq!(
            policy.mode_for(Subsystem::PolicyMissing),
            FailureMode::FailOpen
        );
    }

    #[test]
    fn degrade_safely_escalates_rather_than_allowing_or_denying() {
        let action = FailureMode::DegradeSafely.action();

        assert_eq!(action, FailureAction::Escalate);
        assert_eq!(action.forced_decision(), Some(Decision::RequireApproval));
        assert!(!FailureMode::DegradeSafely.permits_allow());
        assert!(!FailureMode::DegradeSafely.is_closed());
    }

    #[test]
    fn actions_and_modes_order_by_severity() {
        assert!(FailureAction::Deny > FailureAction::Escalate);
        assert!(FailureAction::Escalate > FailureAction::Continue);
        assert!(FailureMode::FailClosed > FailureMode::DegradeSafely);
        assert!(FailureMode::DegradeSafely > FailureMode::FailOpen);
    }

    #[test]
    fn strict_closes_every_subsystem() {
        let policy = FailurePolicy::strict();

        for subsystem in Subsystem::ALL {
            assert!(
                policy.mode_for(subsystem).is_closed(),
                "{subsystem} must fail closed under the strict preset"
            );
        }
    }

    #[test]
    fn observe_is_not_a_security_posture_but_still_gates_approvals() {
        let policy = FailurePolicy::observe();

        assert!(!policy.never_allows_on_inspection_failure());
        assert!(policy.mode_for(Subsystem::Approval).is_closed());
    }

    #[test]
    fn failures_sanitize_their_detail() {
        let failure = SubsystemFailure::new(
            Subsystem::PolicyPayload,
            "could not parse sk-proj-abcdefghijklmnopqrstuvwxyz0123456789ABCD",
        );

        assert!(!failure
            .detail
            .contains("sk-proj-abcdefghijklmnopqrstuvwxyz0123456789ABCD"));
        assert_eq!(failure.subsystem, Subsystem::PolicyPayload);
    }

    #[test]
    fn a_failure_renders_as_a_reason_on_its_own_stage() {
        let reason = SubsystemFailure::new(Subsystem::DlpScanner, "boom").to_reason();

        assert_eq!(reason.stage, Stage::Risk);
        assert_eq!(reason.code, ReasonCode::DlpScannerFailed);
        assert!(reason.detail.contains("dlp_scanner unavailable"));
    }

    #[test]
    fn describe_covers_the_whole_matrix() {
        assert_eq!(
            FailurePolicy::default().describe().len(),
            Subsystem::ALL.len()
        );
    }
}
