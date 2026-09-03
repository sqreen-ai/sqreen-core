//! Audit event pipeline.
//!
//! # Signal-driven by default
//!
//! The gateway emits an audit event at each stage boundary that produced a *signal* — a
//! block, a rewrite, a mask, an approval — and, by default, nothing at all for an action
//! that passed cleanly. That reproduces the pre-gateway telemetry volume exactly, which
//! matters because the control plane stores every record.
//!
//! Set [`crate::gateway::GatewayConfig::audit_all_decisions`] to also emit one event per
//! evaluation regardless of outcome. That gives a complete audit trail at the cost of one
//! record per tool call, so it is opt-in rather than default.
//!
//! # Auditing cannot change a decision
//!
//! [`AuditSink::record`] is called after the verdict is settled and its result is folded
//! into the outcome as a reason, never as a verdict — unless
//! [`crate::gateway::FailurePolicy::audit_error`] is set to
//! [`crate::gateway::FailureMode::Closed`], which is how a deployment opts into "no audit
//! trail means no execution".

use std::fmt;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use chrono::{DateTime, Utc};

use super::decision::{Decision, DecisionReason, MatchedPolicy, Stage};
use crate::action::{ActionId, AgentAction, Runtime, SessionId, TraceId};
use crate::cloud_client::{CloudClient, TelemetryRecord, UserDecision};
use crate::identity::AgentIdentity;
use crate::scoring::{ExplainableRiskScore, RiskFactor, RiskLevel};

/// A sink failed to record an event.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuditError {
    /// Sink that failed.
    pub sink: &'static str,
    /// What went wrong.
    pub detail: String,
}

impl AuditError {
    /// Builds an audit error.
    pub fn new(sink: &'static str, detail: impl Into<String>) -> Self {
        Self {
            sink,
            detail: detail.into(),
        }
    }
}

impl fmt::Display for AuditError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}: {}", self.sink, self.detail)
    }
}

impl std::error::Error for AuditError {}

/// One durable record of something the gateway observed or decided.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuditEvent {
    /// When the event was produced.
    pub timestamp: DateTime<Utc>,
    /// Stage that produced it.
    pub stage: Stage,

    /// Action the event describes.
    pub action_id: ActionId,
    /// Session the action belonged to.
    pub session_id: Option<SessionId>,
    /// Trace the action belonged to.
    pub trace_id: Option<TraceId>,
    /// Integration the action arrived through.
    pub runtime: Runtime,
    /// Tool the action targeted.
    pub tool_name: String,
    /// Agent that attempted the action.
    pub agent_id: Option<String>,
    /// Human the agent acted for.
    pub user_id: Option<String>,
    /// Owning organization.
    pub organization_id: Option<String>,

    /// Full agent identity snapshot at evaluation time.
    pub identity: AgentIdentity,
    /// Effective agent id recorded for anonymous/local agents.
    pub effective_agent_id: String,
    /// Agent instance identifier, when known.
    pub agent_instance_id: Option<String>,
    /// Agent kind.
    pub agent_type: crate::action::AgentType,
    /// Model vendor — not agent identity, but recorded for forensics.
    pub model_provider: Option<crate::action::ModelProvider>,
    /// Model name — not agent identity.
    pub model_name: Option<String>,
    /// Deployment environment tier.
    pub environment_tier: crate::action::EnvironmentTier,

    /// Effective risk score at the time of the event.
    pub risk_score: u8,
    /// Coarse risk band for the explainable score, when computed.
    pub risk_level: Option<RiskLevel>,
    /// Explainable factors that produced the score (empty when score was not explained).
    pub risk_factors: Vec<RiskFactor>,
    /// Always the ordinal-severity disclaimer when factors are present.
    pub risk_semantics: Option<&'static str>,
    /// Verdict, when the event accompanies one.
    pub decision: Option<Decision>,
    /// Legacy telemetry classification, preserved for control-plane compatibility.
    pub pattern_matched: String,
    /// Legacy operator-decision field, preserved for control-plane compatibility.
    pub user_decision: UserDecision,

    /// Reasons known at the time of the event.
    pub reasons: Vec<DecisionReason>,
    /// Rules that fired.
    pub matched_policies: Vec<MatchedPolicy>,
    /// Declarative policy version in force.
    pub policy_version: Option<String>,
    /// Evaluation latency, present on terminal events.
    pub latency: Option<Duration>,
}

impl AuditEvent {
    /// Builds an event describing `action`.
    pub fn new(
        action: &AgentAction,
        stage: Stage,
        risk_score: u8,
        pattern_matched: impl Into<String>,
        user_decision: UserDecision,
    ) -> Self {
        Self {
            timestamp: Utc::now(),
            stage,
            action_id: action.action_id.clone(),
            session_id: action.execution.session_id.clone(),
            trace_id: action.execution.trace_id.clone(),
            runtime: action.runtime().clone(),
            tool_name: action.tool_name().to_string(),
            agent_id: action
                .identity
                .agent_id
                .as_ref()
                .map(|id| id.as_str().to_string()),
            user_id: action.identity.user_id.clone(),
            organization_id: action.identity.organization_id.clone(),
            identity: action.identity.clone(),
            effective_agent_id: action.identity.effective_agent_id().to_string(),
            agent_instance_id: action
                .execution
                .agent_instance_id
                .as_ref()
                .map(|id| id.as_str().to_string()),
            agent_type: action.identity.agent_type.clone(),
            model_provider: action.model.provider.clone(),
            model_name: action.model.name.clone(),
            environment_tier: action.identity.environment.tier,
            risk_score,
            risk_level: None,
            risk_factors: Vec::new(),
            risk_semantics: None,
            decision: None,
            pattern_matched: pattern_matched.into(),
            user_decision,
            reasons: Vec::new(),
            matched_policies: Vec::new(),
            policy_version: None,
            latency: None,
        }
    }

    /// Attaches an explainable risk score breakdown.
    pub fn with_risk_explanation(mut self, explanation: &ExplainableRiskScore) -> Self {
        self.risk_level = Some(explanation.level);
        self.risk_factors = explanation.factors.clone();
        self.risk_semantics = Some(explanation.semantics);
        self
    }

    /// Attaches the verdict this event accompanies.
    pub fn with_decision(mut self, decision: Decision) -> Self {
        self.decision = Some(decision);
        self
    }

    /// Attaches the reasons known so far.
    pub fn with_reasons(mut self, reasons: Vec<DecisionReason>) -> Self {
        self.reasons = reasons;
        self
    }

    /// Attaches the rules that fired.
    pub fn with_matched_policies(mut self, matched: Vec<MatchedPolicy>) -> Self {
        self.matched_policies = matched;
        self
    }

    /// Attaches the declarative policy version.
    pub fn with_policy_version(mut self, version: Option<String>) -> Self {
        self.policy_version = version;
        self
    }

    /// Attaches the evaluation latency.
    pub fn with_latency(mut self, latency: Duration) -> Self {
        self.latency = Some(latency);
        self
    }
}

/// Destination for audit events.
pub trait AuditSink: Send + Sync {
    /// Records an event.
    ///
    /// Implementations must not block for long: this is called on the evaluation path.
    /// A sink that talks to the network should hand off to a background task.
    fn record(&self, event: &AuditEvent) -> Result<(), AuditError>;

    /// Stable name for diagnostics.
    fn name(&self) -> &'static str;
}

/// Discards every event.
///
/// The default for a gateway with no control plane configured.
#[derive(Debug, Clone, Copy, Default)]
pub struct NullAuditSink;

impl AuditSink for NullAuditSink {
    fn record(&self, _event: &AuditEvent) -> Result<(), AuditError> {
        Ok(())
    }

    fn name(&self) -> &'static str {
        "null"
    }
}

/// Forwards events to the control plane as [`TelemetryRecord`]s.
///
/// Dispatch is fire-and-forget on a detached task, so a control plane that is slow or down
/// cannot delay or influence a decision. This is the mechanism behind the "cloud is a
/// replica, not an oracle" property described in [`crate::gateway::FailurePolicy`].
#[derive(Clone)]
pub struct CloudAuditSink {
    client: Arc<CloudClient>,
}

impl CloudAuditSink {
    /// Wraps a control-plane client.
    pub fn new(client: Arc<CloudClient>) -> Self {
        Self { client }
    }
}

impl AuditSink for CloudAuditSink {
    fn record(&self, event: &AuditEvent) -> Result<(), AuditError> {
        self.client.dispatch_telemetry(TelemetryRecord::new(
            self.client.device_id(),
            &event.tool_name,
            event.risk_score,
            &event.pattern_matched,
            event.user_decision,
        ));
        Ok(())
    }

    fn name(&self) -> &'static str {
        "cloud"
    }
}

/// Writes a one-line summary of each event to stderr.
///
/// Gives a fully local deployment an audit trail without a control plane.
#[derive(Debug, Clone, Copy, Default)]
pub struct StderrAuditSink;

impl AuditSink for StderrAuditSink {
    fn record(&self, event: &AuditEvent) -> Result<(), AuditError> {
        let decision = event
            .decision
            .map(|decision| decision.as_str())
            .unwrap_or("-");

        eprintln!(
            "mcp-proxy audit: stage={} tool={} decision={} risk={} pattern={} action={}",
            event.stage.as_str(),
            event.tool_name,
            decision,
            event.risk_score,
            event.pattern_matched,
            event.action_id,
        );
        Ok(())
    }

    fn name(&self) -> &'static str {
        "stderr"
    }
}

/// Fans events out to several sinks.
///
/// Records to every sink even if an earlier one fails, then reports the first failure, so
/// one broken destination cannot silently suppress the others.
#[derive(Clone, Default)]
pub struct CompositeAuditSink {
    sinks: Vec<Arc<dyn AuditSink>>,
}

impl CompositeAuditSink {
    /// Builds a fan-out sink.
    pub fn new(sinks: Vec<Arc<dyn AuditSink>>) -> Self {
        Self { sinks }
    }

    /// Appends a sink.
    pub fn with(mut self, sink: Arc<dyn AuditSink>) -> Self {
        self.sinks.push(sink);
        self
    }
}

impl AuditSink for CompositeAuditSink {
    fn record(&self, event: &AuditEvent) -> Result<(), AuditError> {
        let mut first_error = None;

        for sink in &self.sinks {
            if let Err(error) = sink.record(event) {
                first_error.get_or_insert(error);
            }
        }

        match first_error {
            Some(error) => Err(error),
            None => Ok(()),
        }
    }

    fn name(&self) -> &'static str {
        "composite"
    }
}

/// Keeps events in memory so a test can assert on them.
///
/// Exported rather than test-gated because the integration suite is a separate crate.
#[derive(Debug, Clone, Default)]
pub struct RecordingAuditSink {
    events: Arc<Mutex<Vec<AuditEvent>>>,
}

impl RecordingAuditSink {
    /// Builds an empty recorder.
    pub fn new() -> Self {
        Self::default()
    }

    /// Returns a snapshot of the recorded events, oldest first.
    pub fn events(&self) -> Vec<AuditEvent> {
        self.events
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clone()
    }

    /// Returns the `pattern_matched` value of each recorded event, in order.
    pub fn patterns(&self) -> Vec<String> {
        self.events()
            .into_iter()
            .map(|event| event.pattern_matched)
            .collect()
    }

    /// Discards recorded events.
    pub fn clear(&self) {
        self.events
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clear();
    }
}

impl AuditSink for RecordingAuditSink {
    fn record(&self, event: &AuditEvent) -> Result<(), AuditError> {
        self.events
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .push(event.clone());
        Ok(())
    }

    fn name(&self) -> &'static str {
        "recording"
    }
}

/// Always fails, so a test can exercise audit failure handling.
#[derive(Debug, Clone, Copy, Default)]
pub struct FailingAuditSink;

impl AuditSink for FailingAuditSink {
    fn record(&self, _event: &AuditEvent) -> Result<(), AuditError> {
        Err(AuditError::new("failing", "sink is configured to fail"))
    }

    fn name(&self) -> &'static str {
        "failing"
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::action::{Arguments, SourceRef};

    fn action() -> AgentAction {
        AgentAction::builder(
            "read_file",
            Arguments::from_name_and_arguments("read_file", &serde_json::json!({"path": "/tmp/a"})),
        )
        .source(SourceRef::new(Runtime::MCP_STDIO, "test"))
        .build_unvalidated()
    }

    fn event() -> AuditEvent {
        AuditEvent::new(
            &action(),
            Stage::Policy,
            42,
            "global_redact_keys",
            UserDecision::Skipped,
        )
    }

    #[test]
    fn events_denormalize_the_action_identity() {
        let action = action();
        let event = AuditEvent::new(&action, Stage::Risk, 10, "x", UserDecision::Skipped);

        assert_eq!(event.tool_name, "read_file");
        assert_eq!(event.action_id, action.action_id);
        assert_eq!(event.runtime, Runtime::MCP_STDIO);
    }

    #[test]
    fn recording_sink_preserves_order() {
        let sink = RecordingAuditSink::new();
        let mut second = event();
        second.pattern_matched = "risk_dlp_mask".to_string();

        sink.record(&event()).expect("record");
        sink.record(&second).expect("record");

        assert_eq!(sink.patterns(), ["global_redact_keys", "risk_dlp_mask"]);

        sink.clear();
        assert!(sink.events().is_empty());
    }

    #[test]
    fn composite_records_to_every_sink_despite_a_failure() {
        let recorder = Arc::new(RecordingAuditSink::new());
        let composite = CompositeAuditSink::new(vec![
            Arc::new(FailingAuditSink),
            recorder.clone(),
            Arc::new(NullAuditSink),
        ]);

        let result = composite.record(&event());

        assert!(result.is_err(), "the failure must be reported");
        assert_eq!(
            recorder.events().len(),
            1,
            "a failing sink must not suppress later sinks"
        );
    }

    #[test]
    fn composite_with_no_failures_succeeds() {
        let composite = CompositeAuditSink::default()
            .with(Arc::new(NullAuditSink))
            .with(Arc::new(RecordingAuditSink::new()));

        assert!(composite.record(&event()).is_ok());
    }
}
