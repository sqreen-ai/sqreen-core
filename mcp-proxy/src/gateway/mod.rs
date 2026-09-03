//! The Agent Execution Gateway: the single entry point for evaluating an agent action.
//!
//! ```text
//!   Agent runtime
//!        │
//!        ▼
//!   Provider adapter ──────────────── crate::adapters
//!        │
//!        ▼
//!   Normalized AgentAction ────────── crate::action
//!        │
//!        ▼
//!   Identity + context enrichment ─── gateway::identity
//!        │
//!        ▼
//!   Policy evaluation ─────────────── gateway::policy_stage   (YAML → Wasm)
//!        │
//!        ▼
//!   Risk evaluation ───────────────── gateway::risk_stage     (score, IOC, chains, DLP)
//!        │
//!        ▼
//!   Approval, if required ─────────── gateway::approval
//!        │
//!        ▼
//!   ALLOW / DENY / REQUIRE_APPROVAL ─ gateway::decision
//!        │
//!        ▼
//!   Tool / API / filesystem          (the caller enforces)
//!        │
//!        ▼
//!   Audit event ───────────────────── gateway::audit
//!        │
//!        ▼
//!   Behavioral telemetry ──────────── crate::telemetry  (privacy-safe signals)
//! ```
//!
//! # The gateway always produces a decision
//!
//! [`AgentExecutionGateway::evaluate`] is infallible. Every internal failure is converted
//! into a [`DecisionReason`] plus whatever [`FailurePolicy`] says that failure implies, so
//! a caller never has to decide what an error means — which is exactly the decision that
//! tends to get made wrong under pressure. See [`failure`] for the full matrix.
//!
//! # Local-first
//!
//! Nothing on the evaluation path touches the network. Policy comes from a local snapshot,
//! risk scoring is in-process, approval is resolved by a local
//! [`ApprovalEngine`], audit dispatch is fire-and-forget on a detached task, and behavioral
//! telemetry is optional with a bounded local queue. A gateway built with
//! [`GatewayBuilder::local`] has no control-plane wiring at all and reaches the
//! same verdicts as a cloud-connected one.
//!
//! A deployment that genuinely requires the control plane in the loop sets
//! [`GatewayConfig::require_control_plane`], which turns an absent control plane into a
//! denial instead of an ignored detail.
//!
//! # Adding a provider
//!
//! Nothing in this module mentions MCP, OpenAI, Anthropic, Cursor, or Claude Code. A new
//! runtime — a browser driver, a database proxy, a cloud SDK shim — is added by writing an
//! adapter that produces an [`AgentAction`] and calling [`AgentExecutionGateway::evaluate`].
//! No stage changes.

pub mod approval;
pub mod audit;
pub mod decision;
pub mod failure;
pub mod identity;
pub mod policy_stage;
pub mod posture;
pub mod redact;
pub mod risk_stage;

use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Instant;

use chrono::Utc;

pub use approval::{
    select_approval_engine, session_approval_safe, ActionBinding, AllowAllApprovalEngine,
    ApprovalContext, ApprovalEngine, ApprovalFuture, ApprovalGrant, ApprovalGrantStore,
    ApprovalHistoryEntry, ApprovalHistoryEvent, ApprovalMode, ApprovalOutcome, ApprovalRequest,
    ApprovalScope, ApprovalVerdict, DenyAllApprovalEngine, GrantAuthorization, GrantRejectReason,
    RemoteApprovalEngine, TerminalApprovalEngine, TimeoutApprovalEngine, UnavailableApprovalEngine,
    APPROVAL_MODE_ENV, DEFAULT_ONCE_TTL, DEFAULT_REMOTE_POLL_INTERVAL, DEFAULT_SESSION_TTL,
    DEFAULT_TIMED_APPROVAL,
};
pub use audit::{
    AuditError, AuditEvent, AuditSink, CloudAuditSink, CompositeAuditSink, FailingAuditSink,
    NullAuditSink, RecordingAuditSink, StderrAuditSink,
};
pub use decision::{
    Decision, DecisionReason, EvaluationOutcome, MatchedPolicy, PolicySource, ReasonCode, Stage,
};
pub use failure::{
    FailureAction, FailureMode, FailurePolicy, Subsystem, SubsystemFailure, FAILURE_POLICY_ENV,
};
pub use identity::{IdentityError, IdentityResolver, NoopIdentityResolver, StaticIdentityResolver};
pub use policy_stage::{PolicyAssessment, PolicyStage};
pub use posture::{EnforcementPosture, PolicyAvailability, ENFORCEMENT_POSTURE_ENV};
pub use redact::{sanitize_detail, sanitize_error};
pub use risk_stage::{
    RiskAssessment, RiskStage, TELEMETRY_DLP_MASK, TELEMETRY_RISK_THRESHOLD,
    TELEMETRY_SECRET_EGRESS,
};

use crate::action::AgentAction;
use crate::behavior::{BehaviorEngine, SessionTracker};
use crate::cloud_client::{CloudClient, UserDecision};
use crate::policy::PolicyEngine;
use crate::scoring::ExplainableRiskScore;
use crate::telemetry::{emit_evaluation, TelemetryPipeline};
use crate::threat_intel::ThreatIntelMatcher;
use crate::wasm_engine::WasmPolicyEngine;

/// Tuning that is orthogonal to the failure matrix.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct GatewayConfig {
    /// Emit one audit event per evaluation, including for actions that passed cleanly.
    ///
    /// Off by default: the shipped control plane stores every record, and a record per
    /// tool call is a meaningful write-volume increase. Turn it on where a complete trail
    /// matters more than storage.
    pub audit_all_decisions: bool,

    /// Require a reachable control plane before any action may be allowed.
    ///
    /// Off by default, which is what makes the gateway local-first. Turning it on trades
    /// availability for centralized attestation: with no control plane attached, every
    /// action is denied with [`ReasonCode::CloudUnavailable`].
    pub require_control_plane: bool,
}

/// Evaluates [`AgentAction`]s through the full pipeline.
///
/// Cheap to clone and cheap to construct — every field is an `Arc` or a small value — so a
/// caller with a hot-reloading policy store may rebuild one per action to pick up the
/// latest snapshot.
#[derive(Clone)]
pub struct AgentExecutionGateway {
    identity: Option<Arc<dyn IdentityResolver>>,
    behavior: Option<Arc<BehaviorEngine>>,
    policy: PolicyStage,
    risk: RiskStage,
    approval: Option<Arc<dyn ApprovalEngine>>,
    approval_grants: Arc<ApprovalGrantStore>,
    audit: Arc<dyn AuditSink>,
    telemetry: Option<Arc<TelemetryPipeline>>,
    failure: FailurePolicy,
    config: GatewayConfig,
    control_plane_attached: bool,
}

impl AgentExecutionGateway {
    /// Starts configuring a gateway.
    pub fn builder() -> GatewayBuilder {
        GatewayBuilder::default()
    }

    /// Returns the failure matrix in force.
    pub fn failure_policy(&self) -> &FailurePolicy {
        &self.failure
    }

    /// Returns the tuning in force.
    pub fn config(&self) -> &GatewayConfig {
        &self.config
    }

    /// Returns `true` when no control plane is wired up.
    pub fn is_local_only(&self) -> bool {
        !self.control_plane_attached
    }

    /// Returns the approval grant store (scoped tokens + approval audit history).
    pub fn approval_grants(&self) -> &ApprovalGrantStore {
        &self.approval_grants
    }

    /// Evaluates an action.
    ///
    /// Clones the action only when an identity resolver is configured and would therefore
    /// need to mutate it. Callers that own their action can use
    /// [`AgentExecutionGateway::evaluate_in_place`] to skip the clone entirely.
    pub async fn evaluate(&self, action: &AgentAction) -> EvaluationOutcome {
        let mut owned = action.clone();
        self.evaluate_in_place(&mut owned).await
    }

    /// Evaluates an action, enriching it in place.
    ///
    /// Avoids the clone in [`AgentExecutionGateway::evaluate`]. The action is left enriched
    /// so the caller can reuse the identity fields for its own logging.
    pub async fn evaluate_in_place(&self, action: &mut AgentAction) -> EvaluationOutcome {
        let started = Instant::now();

        let error = match self.identity.as_deref() {
            Some(resolver) => resolver.enrich(action).err(),
            None => None,
        };

        action.refresh_security_classification();

        let mut outcome = self.run(action, started).await;

        // Enrichment fails open: identity is descriptive, no engine reads it to decide.
        // The failure is still recorded, because "we do not know who did this" is
        // something an investigator needs to see rather than infer from an empty field.
        if let Some(error) = error {
            outcome.reasons.insert(
                0,
                DecisionReason::new(
                    Stage::Identity,
                    ReasonCode::IdentityEnrichmentFailed,
                    format!("identity enrichment failed: {error}"),
                ),
            );
        }

        // Behavioral telemetry is best-effort and never influences the verdict.
        if let Some(pipeline) = self.telemetry.as_deref() {
            emit_evaluation(pipeline, action, &outcome);
        }

        outcome
    }

    /// The pipeline proper, on an already-enriched action.
    async fn run(&self, action: &mut AgentAction, started: Instant) -> EvaluationOutcome {
        let mut trace = Trace::new(action);

        // Checked before anything else, and deliberately *not* routed through
        // `FailurePolicy::cloud_unavailable`. That mode answers "what if the control plane
        // is down", which is fail-open because the gateway is local-first. This answers
        // "the operator declared the control plane mandatory", which is an explicit demand
        // that outranks the general posture.
        if self.config.require_control_plane && !self.control_plane_attached {
            trace.reason(
                Stage::Policy,
                ReasonCode::CloudUnavailable,
                "control plane is required by configuration but not attached",
            );

            self.emit(
                &mut trace,
                action,
                Stage::Policy,
                0,
                Subsystem::ControlPlane.audit_marker().as_str(),
                UserDecision::Denied,
                Some(Decision::Deny),
                started,
            );

            return trace.finish(&self.failure, Decision::Deny, None, started);
        }

        // Scanned before policy so policy-stage audit records carry a risk score, matching
        // the pre-gateway telemetry. `scan` is pure, so running it first changes nothing.
        let analysis = self.risk.scan(action);
        let preliminary_score = analysis.score;

        /* ---- Behavior (detect only; policy decides) ---- */

        let behavior_finding = self.behavior.as_ref().map(|engine| engine.evaluate(action));
        if let Some(finding) = behavior_finding.as_ref() {
            for signal in &finding.signals {
                trace.reason(
                    Stage::Behavior,
                    ReasonCode::BehavioralSignal,
                    signal.detail.clone(),
                );
                // Signal-only attribution — effect Allow until a policy rule overrides.
                trace.matched_policies.push(MatchedPolicy::new(
                    PolicySource::BehavioralAnalytics,
                    format!("behavior.{}", signal.kind.as_str()),
                    Decision::Allow,
                ));
            }
        }

        // Explainable score before policy so rules can match risk.level / risk.factor /
        // risk.score_at_least with the same inputs the risk stage will use.
        let preliminary_explanation =
            self.risk
                .explain(action, &analysis, behavior_finding.as_ref());
        trace.risk_explanation = Some(preliminary_explanation.clone());

        /* ---- Policy ---- */

        let policy = self.policy.evaluate(
            action,
            behavior_finding.as_ref(),
            Some(&preliminary_explanation),
            &self.failure,
        );
        trace.policy_version = policy.policy_version.clone();
        trace.policy_availability = policy.policy_availability;
        trace.absorb(policy.reasons.clone(), policy.matched_policies.clone());
        trace.simulated_decision = policy.simulated_decision;
        self.report_failures(&mut trace, action, &policy.failures, preliminary_score);

        if policy.terminal {
            let (user_decision, marker) = match policy.decision {
                Decision::Allow => (
                    UserDecision::Skipped,
                    policy.telemetry_marker.unwrap_or("policy_rewrite"),
                ),
                _ => (
                    UserDecision::Denied,
                    policy
                        .reasons
                        .last()
                        .map(|reason| reason.detail.as_str())
                        .unwrap_or("policy_block"),
                ),
            };

            self.emit(
                &mut trace,
                action,
                Stage::Policy,
                preliminary_score,
                marker,
                user_decision,
                Some(policy.decision),
                started,
            );

            let mut outcome = trace.finish(
                &self.failure,
                policy.decision,
                Some(preliminary_score),
                started,
            );
            outcome.rewritten_arguments = policy.rewrite;
            return outcome;
        }

        /* ---- Risk ---- */

        let risk = self.risk.evaluate(
            action,
            analysis,
            self.policy.risk_threshold(),
            behavior_finding.as_ref(),
        );
        trace.risk_explanation = Some(risk.explanation.clone());
        trace.absorb(risk.reasons.clone(), risk.matched_policies.clone());

        let risk_failure = self.report_failures(&mut trace, action, &risk.failures, risk.score);

        // A failing inspection control cannot be resolved by carrying on: the payload it
        // was supposed to read is still unread. Deny outright, or hand it to an approver —
        // never fall through to the ordinary allow path.
        if risk_failure == FailureAction::Deny {
            self.emit(
                &mut trace,
                action,
                Stage::Risk,
                risk.score,
                Subsystem::DlpScanner.audit_marker().as_str(),
                UserDecision::Denied,
                Some(Decision::Deny),
                started,
            );

            return trace.finish(&self.failure, Decision::Deny, Some(risk.score), started);
        }

        if let Some(marker) = risk.dlp_marker {
            self.emit(
                &mut trace,
                action,
                Stage::Risk,
                risk.score,
                marker,
                UserDecision::Skipped,
                None,
                started,
            );
        }

        let rewrite = risk.sanitized_payload.clone();
        let degraded = risk_failure == FailureAction::Escalate;
        let needs_approval =
            risk.requires_approval || degraded || policy.decision == Decision::RequireApproval;

        if degraded {
            trace.reason(
                Stage::Risk,
                ReasonCode::DegradedToApproval,
                "a risk-stage control could not run, so the action needs an approval \
                 rather than an allow",
            );
        }

        if !needs_approval {
            self.risk.record(action);
            if let Some(engine) = self.behavior.as_ref() {
                engine.record(action);
            }

            // Emitted before the outcome is materialized, so a sink failure on the
            // routine-allow event is governed by `audit_error` like every other emit. The
            // earlier ordering recorded this one after the verdict was already fixed and
            // discarded the result — which meant the single most common event in the
            // system was the one event whose loss a mandated-trail deployment could not
            // detect.
            if self.config.audit_all_decisions {
                self.emit(
                    &mut trace,
                    action,
                    Stage::Audit,
                    risk.score,
                    "allowed",
                    UserDecision::Skipped,
                    Some(Decision::Allow),
                    started,
                );
            }

            let mut outcome =
                trace.finish(&self.failure, Decision::Allow, Some(risk.score), started);

            if outcome.is_allowed() {
                outcome.rewritten_arguments = rewrite;
            }

            return outcome;
        }

        /* ---- Approval ---- */

        let sanitized_payload = risk.effective_payload(action.canonical_params_json());
        let approval_context = ApprovalContext::build(
            action,
            sanitized_payload,
            risk.score,
            Some(&risk.explanation),
            &trace.reasons,
            &trace.matched_policies,
        );

        // Scoped grant reuse — exact-action and (when safe) session-tool grants.
        if let GrantAuthorization::Authorized { grant } = self.approval_grants.authorize(action) {
            self.risk.record(action);
            if let Some(behavior) = self.behavior.as_ref() {
                behavior.record(action);
            }

            trace.reason(
                Stage::Approval,
                ReasonCode::ApprovalGrantReused,
                format!(
                    "authorized by {} grant {} (scope={})",
                    grant.verdict.as_str(),
                    &grant.token[..grant.token.len().min(18)],
                    grant.scope.as_str()
                ),
            );

            self.emit(
                &mut trace,
                action,
                Stage::Approval,
                risk.score,
                risk.telemetry_marker,
                UserDecision::Approved,
                Some(Decision::Allow),
                started,
            );

            let mut result =
                trace.finish(&self.failure, Decision::Allow, Some(risk.score), started);
            if result.is_allowed() {
                result.rewritten_arguments = rewrite;
            }
            return result;
        }

        let Some(engine) = self.approval.as_deref() else {
            self.risk.record(action);
            if let Some(behavior) = self.behavior.as_ref() {
                behavior.record(action);
            }

            trace.reason(
                Stage::Approval,
                ReasonCode::ApprovalDeferred,
                "approval required and no approval engine is configured to resolve it",
            );

            self.emit(
                &mut trace,
                action,
                Stage::Approval,
                risk.score,
                risk.telemetry_marker,
                UserDecision::Skipped,
                Some(Decision::RequireApproval),
                started,
            );

            return trace.finish(
                &self.failure,
                Decision::RequireApproval,
                Some(risk.score),
                started,
            );
        };

        // The most recent reason is the one that triggered the gate, so it is the most
        // useful thing to show an approver.
        let justification = trace
            .reasons
            .last()
            .map(|reason| reason.detail.clone())
            .unwrap_or_else(|| risk.denial_detail());

        let outcome = engine
            .request(ApprovalRequest {
                action,
                risk_score: risk.score,
                payload: sanitized_payload,
                justification: &justification,
                context: &approval_context,
            })
            .await;

        // Recorded after the prompt resolves, matching the pre-gateway ordering so a chain
        // observed mid-prompt sees the history the prompt was based on.
        self.risk.record(action);
        if let Some(behavior) = self.behavior.as_ref() {
            behavior.record(action);
        }

        let decision = outcome.as_decision(self.failure.approval_unavailable);
        let engine_name = engine.name();

        match &outcome {
            ApprovalOutcome::Approved { verdict } => {
                self.approval_grants.record_decision(
                    &approval_context.request_id,
                    &approval_context.binding,
                    verdict,
                    &approval_context.render_brief(),
                );
                if let Some(grant) = approval::mint_grants_for_verdict(
                    &self.approval_grants,
                    &approval_context,
                    verdict,
                ) {
                    trace.reason(
                        Stage::Approval,
                        ReasonCode::OperatorApproved,
                        format!(
                            "approved via {engine_name} as {} (grant {} scope={})",
                            verdict.as_str(),
                            &grant.token[..grant.token.len().min(18)],
                            grant.scope.as_str()
                        ),
                    );
                } else {
                    trace.reason(
                        Stage::Approval,
                        ReasonCode::OperatorApproved,
                        format!("approved via {engine_name} as {}", verdict.as_str()),
                    );
                }
            }
            ApprovalOutcome::Denied => {
                self.approval_grants.record_decision(
                    &approval_context.request_id,
                    &approval_context.binding,
                    &ApprovalVerdict::Deny,
                    &approval_context.render_brief(),
                );
                trace.reason(
                    Stage::Approval,
                    ReasonCode::OperatorDenied,
                    risk.denial_detail(),
                );
            }
            ApprovalOutcome::Unavailable => trace.reason(
                Stage::Approval,
                ReasonCode::ApprovalUnavailable,
                format!("no approver reachable via {engine_name}"),
            ),
            ApprovalOutcome::TimedOut => trace.reason(
                Stage::Approval,
                ReasonCode::ApprovalTimedOut,
                format!("approval via {engine_name} was not answered before its deadline"),
            ),
        }

        // An approver that could not answer is a security failure in its own right, and
        // gets its own audit record so "denied because a human said no" and "denied
        // because nobody was there" are separable in the trail.
        if !outcome.is_judgment() {
            self.emit(
                &mut trace,
                action,
                Stage::Approval,
                risk.score,
                Subsystem::Approval.audit_marker().as_str(),
                UserDecision::Skipped,
                Some(decision),
                started,
            );
        }

        self.emit(
            &mut trace,
            action,
            Stage::Approval,
            risk.score,
            risk.telemetry_marker,
            match &outcome {
                ApprovalOutcome::Approved { .. } => UserDecision::Approved,
                ApprovalOutcome::Denied => UserDecision::Denied,
                ApprovalOutcome::Unavailable | ApprovalOutcome::TimedOut => UserDecision::Skipped,
            },
            Some(decision),
            started,
        );

        let mut result = trace.finish(&self.failure, decision, Some(risk.score), started);
        if result.is_allowed() {
            result.rewritten_arguments = rewrite;
        }
        result
    }

    /// Rules on the failures a stage reported and audits each one.
    ///
    /// The gateway's half of the contract in [`failure`]: stages report, this decides.
    /// Every failure produces its own audit event with a `security_failure:` marker
    /// regardless of the verdict or of [`GatewayConfig::audit_all_decisions`], because a
    /// broken control is an operational event whether or not it changed this particular
    /// outcome — and an attacker probing for a way to break one produces a stream of them.
    ///
    /// Returns the most severe [`FailureAction`] across the batch.
    fn report_failures(
        &self,
        trace: &mut Trace,
        action: &AgentAction,
        failures: &[SubsystemFailure],
        risk_score: u8,
    ) -> FailureAction {
        let mut severest = FailureAction::Continue;

        for failure in failures {
            let verdict = self.failure.decide(failure);
            severest = severest.max(verdict);

            let mode = self.failure.mode_for(failure.subsystem);
            eprintln!(
                "mcp-proxy: security control degraded [{}={}] {}",
                failure.subsystem, mode, failure.detail
            );

            let started = Instant::now();
            self.emit(
                trace,
                action,
                failure.subsystem.stage(),
                risk_score,
                failure.subsystem.audit_marker().as_str(),
                UserDecision::Skipped,
                verdict.forced_decision(),
                started,
            );
        }

        severest
    }

    /// Records an audit event, folding a sink failure into the trace.
    #[allow(clippy::too_many_arguments)]
    fn emit(
        &self,
        trace: &mut Trace,
        action: &AgentAction,
        stage: Stage,
        risk_score: u8,
        pattern: &str,
        user_decision: UserDecision,
        decision: Option<Decision>,
        started: Instant,
    ) {
        let mut event = AuditEvent::new(action, stage, risk_score, pattern, user_decision)
            .with_reasons(trace.reasons.clone())
            .with_matched_policies(trace.matched_policies.clone())
            .with_policy_version(trace.policy_version.clone())
            .with_latency(started.elapsed());

        if let Some(explanation) = trace.risk_explanation.as_ref() {
            event = event.with_risk_explanation(explanation);
        }

        if let Some(decision) = decision {
            event = event.with_decision(decision);
        }

        if let Err(error) = self.audit.record(&event) {
            trace.reason(
                Stage::Audit,
                ReasonCode::AuditDeliveryFailed,
                format!("audit sink failed: {error}"),
            );
            trace.audit_failed = true;
        }
    }
}

/// Accumulates reasons and matched rules across stages.
struct Trace {
    action_id: crate::action::ActionId,
    session_id: Option<crate::action::SessionId>,
    trace_id: Option<crate::action::TraceId>,
    tool_name: String,
    reasons: Vec<DecisionReason>,
    matched_policies: Vec<MatchedPolicy>,
    policy_version: Option<String>,
    policy_availability: PolicyAvailability,
    audit_failed: bool,
    simulated_decision: Option<Decision>,
    risk_explanation: Option<ExplainableRiskScore>,
}

impl Trace {
    fn new(action: &AgentAction) -> Self {
        Self {
            action_id: action.action_id.clone(),
            session_id: action.execution.session_id.clone(),
            trace_id: action.execution.trace_id.clone(),
            tool_name: action.tool_name().to_string(),
            reasons: Vec::new(),
            matched_policies: Vec::new(),
            policy_version: None,
            policy_availability: PolicyAvailability::Available,
            audit_failed: false,
            simulated_decision: None,
            risk_explanation: None,
        }
    }

    fn reason(&mut self, stage: Stage, code: ReasonCode, detail: impl Into<String>) {
        self.reasons.push(DecisionReason::new(stage, code, detail));
    }

    fn absorb(&mut self, reasons: Vec<DecisionReason>, matched: Vec<MatchedPolicy>) {
        self.reasons.extend(reasons);
        self.matched_policies.extend(matched);
    }

    /// Materializes the outcome.
    ///
    /// Applies [`FailurePolicy::audit_error`] here rather than at the emit site so that a
    /// sink failure anywhere in the pipeline is handled once, at the only place a verdict
    /// is decided.
    fn finish(
        self,
        failure: &FailurePolicy,
        decision: Decision,
        risk_score: Option<u8>,
        started: Instant,
    ) -> EvaluationOutcome {
        let decision = if self.audit_failed && failure.audit_error.is_closed() {
            Decision::Deny
        } else {
            decision
        };

        let (risk_level, risk_factors, risk_semantics) = match self.risk_explanation {
            Some(explanation) => (
                Some(explanation.level),
                explanation.factors,
                Some(explanation.semantics.to_string()),
            ),
            None => (None, Vec::new(), None),
        };

        EvaluationOutcome {
            decision,
            reasons: self.reasons,
            matched_policies: self.matched_policies,
            risk_score,
            risk_level,
            risk_factors,
            risk_semantics,
            policy_version: self.policy_version,
            policy_availability: self.policy_availability,
            timestamp: Utc::now(),
            latency: started.elapsed(),
            metadata: {
                let mut meta = BTreeMap::new();
                meta.insert(
                    "policy_state".to_string(),
                    self.policy_availability.as_str().to_string(),
                );
                meta
            },
            simulated_decision: self.simulated_decision,
            action_id: self.action_id,
            session_id: self.session_id,
            trace_id: self.trace_id,
            tool_name: self.tool_name,
            rewritten_arguments: None,
        }
    }
}

/// Assembles an [`AgentExecutionGateway`].
#[derive(Clone, Default)]
pub struct GatewayBuilder {
    identity: Option<Arc<dyn IdentityResolver>>,
    policy_engine: Option<Arc<PolicyEngine>>,
    policy_availability: Option<PolicyAvailability>,
    extension: Option<Arc<WasmPolicyEngine>>,
    threat_intel: Option<Arc<ThreatIntelMatcher>>,
    session: Option<Arc<SessionTracker>>,
    behavior: Option<Arc<BehaviorEngine>>,
    approval: Option<Arc<dyn ApprovalEngine>>,
    approval_grants: Option<Arc<ApprovalGrantStore>>,
    audit: Option<Arc<dyn AuditSink>>,
    telemetry: Option<Arc<TelemetryPipeline>>,
    failure: FailurePolicy,
    config: GatewayConfig,
    control_plane_attached: bool,
}

impl GatewayBuilder {
    /// A fully local gateway: bounded terminal approvals, stderr audit, no control plane.
    ///
    /// The starting point for a workstation deployment. Add a policy engine and threat-intel
    /// matcher, and the result enforces without any network dependency. The failure matrix
    /// comes from [`FailurePolicy::from_env`], so an operator can select a posture without
    /// a code change.
    pub fn local() -> Self {
        Self::default()
            .identity(Arc::new(StaticIdentityResolver::from_env()))
            .approval(Arc::new(TimeoutApprovalEngine::with_default_deadline(
                Arc::new(TerminalApprovalEngine),
            )))
            .audit(Arc::new(StderrAuditSink))
            .failure_policy(FailurePolicy::from_env())
    }

    /// Sets the identity resolver. Omit it when adapters are authoritative.
    pub fn identity(mut self, resolver: Arc<dyn IdentityResolver>) -> Self {
        self.identity = Some(resolver);
        self
    }

    /// Sets the declarative policy engine.
    pub fn policy_engine(mut self, engine: Option<Arc<PolicyEngine>>) -> Self {
        self.policy_engine = engine;
        self
    }

    /// Sets the policy availability state reported on every outcome.
    ///
    /// Use this when the [`crate::policy_store::PolicyStore`] knows the snapshot is
    /// stale or that a managed remote source is unreachable. Adapters must not invent
    /// their own missing-policy behavior — they pass the store's state through.
    pub fn policy_availability(mut self, availability: PolicyAvailability) -> Self {
        self.policy_availability = Some(availability);
        self
    }

    /// Sets the Wasm policy extension.
    pub fn extension(mut self, extension: Option<Arc<WasmPolicyEngine>>) -> Self {
        self.extension = extension;
        self
    }

    /// Sets the threat-intel matcher.
    pub fn threat_intel(mut self, matcher: Arc<ThreatIntelMatcher>) -> Self {
        self.threat_intel = Some(matcher);
        self
    }

    /// Sets the session tracker backing behavioral chain detection.
    pub fn session(mut self, session: Arc<SessionTracker>) -> Self {
        self.session = Some(session);
        self
    }

    /// Sets the behavioral detection engine.
    ///
    /// Findings augment policy match context; they never auto-block without a matching rule.
    pub fn behavior(mut self, engine: Arc<BehaviorEngine>) -> Self {
        self.behavior = Some(engine);
        self
    }

    /// Sets the approval engine.
    ///
    /// Without one, actions needing approval resolve to
    /// [`Decision::RequireApproval`] for the caller to handle.
    pub fn approval(mut self, engine: Arc<dyn ApprovalEngine>) -> Self {
        self.approval = Some(engine);
        self
    }

    /// Sets the approval grant store used for scoped token reuse and approval audit history.
    pub fn approval_grants(mut self, store: Arc<ApprovalGrantStore>) -> Self {
        self.approval_grants = Some(store);
        self
    }

    /// Sets the audit sink.
    pub fn audit(mut self, sink: Arc<dyn AuditSink>) -> Self {
        self.audit = Some(sink);
        self
    }

    /// Routes audit events to the control plane.
    ///
    /// Also marks the control plane as attached, which satisfies
    /// [`GatewayConfig::require_control_plane`].
    pub fn cloud_audit(mut self, client: Arc<CloudClient>) -> Self {
        self.audit = Some(Arc::new(CloudAuditSink::new(client)));
        self.control_plane_attached = true;
        self
    }

    /// Attaches a behavioral telemetry pipeline.
    ///
    /// Telemetry failures never change decisions. Omit this (or pass a disabled pipeline)
    /// for a fully local, silent deployment.
    pub fn telemetry(mut self, pipeline: Arc<TelemetryPipeline>) -> Self {
        self.telemetry = Some(pipeline);
        self
    }

    /// Enables cloud behavioral telemetry via the control-plane client.
    ///
    /// Also marks the control plane as attached.
    pub fn cloud_telemetry(mut self, client: Arc<CloudClient>) -> Self {
        self.telemetry = Some(Arc::new(crate::telemetry::cloud_pipeline(client)));
        self.control_plane_attached = true;
        self
    }

    /// Sets the failure matrix.
    pub fn failure_policy(mut self, failure: FailurePolicy) -> Self {
        self.failure = failure;
        self
    }

    /// Sets the tuning.
    pub fn config(mut self, config: GatewayConfig) -> Self {
        self.config = config;
        self
    }

    /// Builds the gateway.
    pub fn build(self) -> AgentExecutionGateway {
        let mut policy = PolicyStage::new(self.policy_engine, self.extension);
        if let Some(availability) = self.policy_availability {
            policy = policy.with_availability(availability);
        }

        AgentExecutionGateway {
            identity: self.identity,
            behavior: self.behavior,
            policy,
            risk: RiskStage::new(
                self.threat_intel
                    .unwrap_or_else(|| Arc::new(ThreatIntelMatcher::default())),
                self.session
                    .unwrap_or_else(|| Arc::new(SessionTracker::default())),
            ),
            approval: self.approval,
            approval_grants: self
                .approval_grants
                .unwrap_or_else(|| Arc::new(ApprovalGrantStore::new())),
            audit: self.audit.unwrap_or_else(|| Arc::new(NullAuditSink)),
            telemetry: self.telemetry,
            failure: self.failure,
            config: self.config,
            control_plane_attached: self.control_plane_attached,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::action::{Arguments, Runtime, SourceRef};

    const POLICY: &str = r#"
version: "3"
global:
  redact_keys: []
  risk_threshold: 70
  block_patterns: ["\\.ssh/"]
tools:
  - name: "read_file"
    action: "Allow"
    block_patterns: []
  - name: "drop_table"
    action: "Block"
    block_patterns: []
  - name: "deploy"
    action: "Confirm"
    block_patterns: []
"#;

    fn action(tool: &str, arguments: serde_json::Value) -> AgentAction {
        AgentAction::builder(tool, Arguments::from_name_and_arguments(tool, &arguments))
            .source(SourceRef::new(Runtime::MCP_STDIO, "test"))
            .build_unvalidated()
    }

    fn gateway(
        approval: Option<Arc<dyn ApprovalEngine>>,
    ) -> (AgentExecutionGateway, Arc<RecordingAuditSink>) {
        let sink = Arc::new(RecordingAuditSink::new());
        let mut builder = GatewayBuilder::default()
            .policy_engine(Some(Arc::new(
                PolicyEngine::from_yaml(POLICY).expect("compile"),
            )))
            .audit(sink.clone());

        if let Some(engine) = approval {
            builder = builder.approval(engine);
        }

        (builder.build(), sink)
    }

    #[tokio::test]
    async fn allows_a_low_risk_action_without_auditing() {
        let (gateway, sink) = gateway(None);
        let outcome = gateway
            .evaluate(&action("read_file", serde_json::json!({"path": "/tmp/a"})))
            .await;

        assert_eq!(outcome.decision, Decision::Allow);
        assert_eq!(outcome.policy_version.as_deref(), Some("3"));
        assert!(outcome.risk_score.is_some());
        assert!(
            sink.events().is_empty(),
            "a clean action emits no signal event by default"
        );
    }

    #[tokio::test]
    async fn audit_all_decisions_records_clean_actions_too() {
        let sink = Arc::new(RecordingAuditSink::new());
        let gateway = GatewayBuilder::default()
            .policy_engine(Some(Arc::new(
                PolicyEngine::from_yaml(POLICY).expect("compile"),
            )))
            .audit(sink.clone())
            .config(GatewayConfig {
                audit_all_decisions: true,
                ..GatewayConfig::default()
            })
            .build();

        gateway
            .evaluate(&action("read_file", serde_json::json!({"path": "/tmp/a"})))
            .await;

        assert_eq!(sink.patterns(), ["allowed"]);
    }

    #[tokio::test]
    async fn policy_block_denies_and_audits_the_verbatim_reason() {
        let (gateway, sink) = gateway(None);
        let outcome = gateway
            .evaluate(&action(
                "read_file",
                serde_json::json!({"path": "~/.ssh/id_rsa"}),
            ))
            .await;

        assert_eq!(outcome.decision, Decision::Deny);
        assert_eq!(
            outcome.primary_detail(),
            Some("global block pattern `\\.ssh/` matched tool `read_file`")
        );
        assert_eq!(sink.events().len(), 1);
        assert_eq!(sink.events()[0].user_decision, UserDecision::Denied);
    }

    #[tokio::test]
    async fn latency_and_timestamp_are_populated() {
        let (gateway, _) = gateway(None);
        let outcome = gateway
            .evaluate(&action("read_file", serde_json::json!({"path": "/tmp/a"})))
            .await;

        assert!(outcome.latency.as_nanos() > 0);
        assert!(outcome.timestamp <= Utc::now());
    }

    #[tokio::test]
    async fn confirm_policy_defers_when_no_approval_engine_exists() {
        let (gateway, _) = gateway(None);
        let outcome = gateway
            .evaluate(&action("deploy", serde_json::json!({"target": "prod"})))
            .await;

        assert_eq!(outcome.decision, Decision::RequireApproval);
        assert!(outcome.has_reason(ReasonCode::PolicyConfirmationRequired));
        assert!(outcome.has_reason(ReasonCode::ApprovalDeferred));
        assert!(outcome.stops_execution());
    }

    #[tokio::test]
    async fn confirm_policy_resolves_through_the_approval_engine() {
        let (approving, _) = gateway(Some(Arc::new(AllowAllApprovalEngine)));
        let (denying, _) = gateway(Some(Arc::new(DenyAllApprovalEngine)));
        let probe = action("deploy", serde_json::json!({"target": "prod"}));

        assert_eq!(approving.evaluate(&probe).await.decision, Decision::Allow);
        assert_eq!(denying.evaluate(&probe).await.decision, Decision::Deny);
    }

    #[tokio::test]
    async fn timed_exact_grant_reuses_without_reprompt_and_rejects_arg_tamper() {
        use crate::action::SessionId;

        let store = Arc::new(ApprovalGrantStore::new());
        let gateway = GatewayBuilder::default()
            .policy_engine(Some(Arc::new(
                PolicyEngine::from_yaml(POLICY).expect("compile"),
            )))
            .approval(Arc::new(DenyAllApprovalEngine))
            .approval_grants(store.clone())
            .audit(Arc::new(RecordingAuditSink::new()))
            .build();

        let mut probe = action("deploy", serde_json::json!({"target": "prod"}));
        probe.execution.session_id = Some(SessionId::new("sess-grant"));
        probe.identity.agent_id = Some(crate::identity::AgentId::new("agent-grant"));
        probe.refresh_security_classification();

        let binding = ActionBinding::from_action(&probe);
        store.issue_until(
            "req-gw",
            binding,
            Utc::now() + chrono::Duration::minutes(10),
        );

        let allowed = gateway.evaluate(&probe).await;
        assert_eq!(allowed.decision, Decision::Allow);
        assert!(allowed.has_reason(ReasonCode::ApprovalGrantReused));

        let mut tampered = probe.clone();
        tampered.arguments =
            Arguments::from_name_and_arguments("deploy", &serde_json::json!({"target": "evil"}));
        tampered.refresh_security_classification();

        // DenyAll would refuse — proving we did not silently reuse the grant.
        let denied = gateway.evaluate(&tampered).await;
        assert_eq!(denied.decision, Decision::Deny);
        assert!(denied.has_reason(ReasonCode::OperatorDenied));
    }

    #[tokio::test]
    async fn high_risk_action_is_denied_by_the_approval_engine() {
        let (gateway, sink) = gateway(Some(Arc::new(DenyAllApprovalEngine)));
        let outcome = gateway
            .evaluate(&action(
                "execute_bash",
                serde_json::json!({"command": "ls"}),
            ))
            .await;

        assert_eq!(outcome.decision, Decision::Deny);
        assert_eq!(
            outcome.primary_detail(),
            Some("user denied high-risk tool call")
        );
        assert_eq!(sink.patterns(), [TELEMETRY_RISK_THRESHOLD]);
    }

    #[tokio::test]
    async fn audit_failure_does_not_change_the_verdict_by_default() {
        let gateway = GatewayBuilder::default()
            .policy_engine(Some(Arc::new(
                PolicyEngine::from_yaml(POLICY).expect("compile"),
            )))
            .audit(Arc::new(FailingAuditSink))
            .build();

        let outcome = gateway
            .evaluate(&action("drop_table", serde_json::json!({"table": "users"})))
            .await;

        assert_eq!(outcome.decision, Decision::Deny, "the policy block stands");
        assert!(outcome.has_reason(ReasonCode::AuditDeliveryFailed));
    }

    #[tokio::test]
    async fn require_control_plane_denies_when_none_is_attached() {
        let gateway = GatewayBuilder::default()
            .policy_engine(Some(Arc::new(
                PolicyEngine::from_yaml(POLICY).expect("compile"),
            )))
            .config(GatewayConfig {
                require_control_plane: true,
                ..GatewayConfig::default()
            })
            .build();

        let outcome = gateway
            .evaluate(&action("read_file", serde_json::json!({"path": "/tmp/a"})))
            .await;

        assert_eq!(outcome.decision, Decision::Deny);
        assert!(outcome.has_reason(ReasonCode::CloudUnavailable));
        assert!(gateway.is_local_only());
    }

    #[tokio::test]
    async fn identity_enrichment_runs_before_evaluation() {
        let gateway = GatewayBuilder::default()
            .identity(Arc::new(StaticIdentityResolver::new(
                crate::adapters::NormalizationContext {
                    user_id: Some("enriched-user".to_string()),
                    ..crate::adapters::NormalizationContext::new()
                },
            )))
            .policy_engine(Some(Arc::new(
                PolicyEngine::from_yaml(POLICY).expect("compile"),
            )))
            .audit(Arc::new(RecordingAuditSink::new()))
            .build();

        let mut probe = action("read_file", serde_json::json!({"path": "/tmp/a"}));
        gateway.evaluate_in_place(&mut probe).await;

        assert_eq!(probe.identity.user_id.as_deref(), Some("enriched-user"));
    }
}
