//! Policy evaluation stage: declarative rules, then Wasm policy extensions.
//!
//! # Ordering
//!
//! The declarative policy runs first and the Wasm extension second, because the
//! declarative layer is the one an operator can audit by reading a file. An extension can
//! tighten a verdict the declarative layer allowed; it never sees an action the
//! declarative layer already blocked.
//!
//! # Short-circuiting
//!
//! A verdict that rewrites the payload — `Redact` or a Wasm `Rewrite` — is terminal: the
//! risk stage does not run. That is the pre-gateway behavior and it is preserved
//! deliberately, because the rewritten payload is the redacted one and rescoring it would
//! report a risk level for bytes that no longer describe the action. `Confirm` is *not*
//! terminal: the risk stage still runs and can escalate the reason for the approval.

use std::sync::Arc;

use super::decision::{Decision, DecisionReason, MatchedPolicy, PolicySource, ReasonCode, Stage};
use super::failure::{FailureAction, FailurePolicy, Subsystem, SubsystemFailure};
use super::posture::PolicyAvailability;
use crate::action::AgentAction;
use crate::behavior::BehaviorFinding;
use crate::policy::{BlockedRule, PolicyEngine, PolicyEvaluation, PolicyVerdict, RuleEffect};
use crate::scoring::ExplainableRiskScore;
use crate::wasm_engine::{WasmDecision, WasmPolicyEngine};

/// What the policy stage concluded about an action.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PolicyAssessment {
    /// The stage's verdict.
    pub decision: Decision,
    /// Why.
    pub reasons: Vec<DecisionReason>,
    /// Rules that fired.
    pub matched_policies: Vec<MatchedPolicy>,
    /// Payload a rewriting rule produced.
    pub rewrite: Option<String>,
    /// When `true`, the pipeline must not continue to the risk stage.
    pub terminal: bool,
    /// Version of the declarative policy that evaluated the action.
    pub policy_version: Option<String>,
    /// Legacy telemetry marker, preserved so audit records keep their existing values.
    pub telemetry_marker: Option<&'static str>,
    /// Subsystems that failed during this stage, for the orchestrator to audit.
    pub failures: Vec<SubsystemFailure>,
    /// Populated when policy `mode: audit` — what enforcement would have decided.
    pub simulated_decision: Option<Decision>,
    /// Whether a declarative policy snapshot was available for this evaluation.
    pub policy_availability: PolicyAvailability,
}

impl PolicyAssessment {
    /// Nothing objected; continue the pipeline.
    fn proceed(policy_version: Option<String>) -> Self {
        Self {
            decision: Decision::Allow,
            reasons: Vec::new(),
            matched_policies: Vec::new(),
            rewrite: None,
            terminal: false,
            policy_version,
            telemetry_marker: None,
            failures: Vec::new(),
            simulated_decision: None,
            policy_availability: PolicyAvailability::Available,
        }
    }

    /// Folds a reported subsystem failure into the assessment.
    ///
    /// The single place the policy stage turns "something broke" into "and therefore".
    /// Applies whatever [`FailurePolicy`] rules, records the reason either way, and never
    /// leaves the failure as a bare allow.
    fn absorb_failure(&mut self, failure: SubsystemFailure, policy: &FailurePolicy) {
        self.reasons.push(failure.to_reason());

        match policy.decide(&failure) {
            FailureAction::Continue => {}
            FailureAction::Escalate => {
                self.decision = Decision::RequireApproval;
                self.rewrite = None;
            }
            FailureAction::Deny => {
                self.decision = Decision::Deny;
                self.terminal = true;
                self.rewrite = None;
                self.telemetry_marker = None;
            }
        }

        self.failures.push(failure);
    }
}

/// Declarative policy plus Wasm extensions, evaluated as one stage.
///
/// Cheap to construct — it holds `Arc`s — so a caller may rebuild one per action to pick
/// up a hot-reloaded policy snapshot.
#[derive(Clone, Default)]
pub struct PolicyStage {
    engine: Option<Arc<PolicyEngine>>,
    extension: Option<Arc<WasmPolicyEngine>>,
    /// Caller-supplied availability (e.g. STALE / REMOTE_UNAVAILABLE from [`crate::policy_store`]).
    availability: PolicyAvailability,
}

impl PolicyStage {
    /// Builds a stage from the engines a deployment has available.
    pub fn new(
        engine: Option<Arc<PolicyEngine>>,
        extension: Option<Arc<WasmPolicyEngine>>,
    ) -> Self {
        let availability = if engine.is_some() {
            PolicyAvailability::Available
        } else {
            PolicyAvailability::Missing
        };
        Self {
            engine,
            extension,
            availability,
        }
    }

    /// Overrides the reported [`PolicyAvailability`] (stale cache, remote outage, …).
    pub fn with_availability(mut self, availability: PolicyAvailability) -> Self {
        self.availability = availability;
        self
    }

    /// Returns the active declarative policy version, when a policy is loaded.
    pub fn policy_version(&self) -> Option<String> {
        self.engine
            .as_ref()
            .map(|engine| engine.version().to_string())
    }

    /// Returns the configured risk threshold, when a policy is loaded.
    pub fn risk_threshold(&self) -> Option<u8> {
        self.engine.as_ref().map(|engine| engine.risk_threshold())
    }

    /// Returns `true` when no declarative policy is loaded.
    pub fn is_unconfigured(&self) -> bool {
        self.engine.is_none()
    }

    /// Evaluates an action against both policy layers.
    pub fn evaluate(
        &self,
        action: &AgentAction,
        behavior: Option<&BehaviorFinding>,
        risk_score: Option<&ExplainableRiskScore>,
        failure: &FailurePolicy,
    ) -> PolicyAssessment {
        let version = self.policy_version();

        let Some(engine) = self.engine.as_deref() else {
            return self.unconfigured(action, failure, version);
        };

        let evaluation = match catch_stage_panic(|| {
            engine.evaluate_detailed_with_context(action, behavior, risk_score)
        }) {
            Ok(evaluation) => evaluation,
            Err(detail) => {
                let mut assessment = PolicyAssessment::proceed(version);
                assessment.policy_availability = PolicyAvailability::Invalid;
                assessment.absorb_failure(
                    SubsystemFailure::new(Subsystem::PolicyEngine, detail),
                    failure,
                );
                return assessment;
            }
        };

        if evaluation.mode == crate::policy::PolicyMode::Audit {
            if let Some(note) = evaluation.audit_explanation() {
                let mut assessment = assessment_from_evaluation(
                    &evaluation,
                    evaluation.verdict_for_enforcement(),
                    version.clone(),
                );
                assessment.policy_availability = self.engine_availability();
                assessment.simulated_decision =
                    Some(simulated_decision(&evaluation.enforced_verdict));
                assessment.reasons.push(DecisionReason::new(
                    Stage::Policy,
                    ReasonCode::PolicyAuditOnly,
                    note,
                ));
                return self.apply_extension(action, assessment, failure);
            }
        }

        let verdict = evaluation.verdict_for_enforcement();
        let availability = self.engine_availability();

        let assessment = match verdict {
            PolicyVerdict::Allow => {
                let mut assessment =
                    assessment_from_evaluation(&evaluation, verdict, version.clone());
                assessment.policy_availability = availability;
                assessment
            }
            PolicyVerdict::Block { reason, rule } => {
                let mut assessment = blocked_by_policy(reason, rule, version, &evaluation);
                assessment.policy_availability = availability;
                return assessment;
            }
            PolicyVerdict::Confirm { message } => {
                let mut assessment = confirmation_required(action, message, &version, &evaluation);
                assessment.policy_availability = availability;
                return assessment;
            }
            PolicyVerdict::Unevaluable { detail } => {
                let mut assessment = PolicyAssessment::proceed(version);
                assessment.policy_availability = availability;
                assessment.absorb_failure(
                    SubsystemFailure::new(Subsystem::PolicyPayload, detail),
                    failure,
                );
                return assessment;
            }
            PolicyVerdict::Redact { frame } => match String::from_utf8(frame) {
                Ok(rewritten) => {
                    let mut assessment = redacted(action, rewritten, version, &evaluation);
                    assessment.policy_availability = availability;
                    return assessment;
                }
                Err(error) => {
                    let mut assessment = PolicyAssessment::proceed(version);
                    assessment.policy_availability = PolicyAvailability::Invalid;
                    assessment.absorb_failure(
                        SubsystemFailure::new(
                            Subsystem::PolicyEngine,
                            format!("redaction produced non-utf8 params: {error}"),
                        ),
                        failure,
                    );
                    return assessment;
                }
            },
        };

        self.apply_extension(action, assessment, failure)
    }

    fn engine_availability(&self) -> PolicyAvailability {
        match self.availability {
            PolicyAvailability::Stale => PolicyAvailability::Stale,
            PolicyAvailability::Available
            | PolicyAvailability::Missing
            | PolicyAvailability::Invalid
            | PolicyAvailability::Unreadable
            | PolicyAvailability::RemoteUnavailable => {
                if self.engine.is_some() {
                    PolicyAvailability::Available
                } else {
                    self.availability
                }
            }
        }
    }

    /// Runs the Wasm extension over an action the declarative layer did not block.
    fn apply_extension(
        &self,
        action: &AgentAction,
        mut assessment: PolicyAssessment,
        failure: &FailurePolicy,
    ) -> PolicyAssessment {
        let Some(extension) = self.extension.as_deref() else {
            return assessment;
        };

        let tool_name = action.tool_name();
        let outcome = match catch_stage_panic(|| {
            extension.evaluate_tool_call(tool_name, action.canonical_params_json())
        }) {
            Ok(outcome) => outcome,
            Err(detail) => Err(anyhow::anyhow!("{detail}")),
        };

        match outcome {
            Ok(WasmDecision::Allow) => assessment,
            Ok(WasmDecision::Block { reason }) => {
                // The `wasm: ` prefix is load-bearing: the stdio relay selects its
                // JSON-RPC error code by matching on it.
                let detail = format!("wasm: {reason}");
                assessment.decision = Decision::Deny;
                assessment.terminal = true;
                assessment.rewrite = None;
                assessment.telemetry_marker = None;
                assessment.reasons.push(DecisionReason::new(
                    Stage::Policy,
                    ReasonCode::ExtensionBlock,
                    detail.clone(),
                ));
                assessment.matched_policies.push(MatchedPolicy::new(
                    PolicySource::WasmExtension,
                    tool_name,
                    Decision::Deny,
                ));
                assessment
            }
            Ok(WasmDecision::Rewrite { modified_params }) => {
                assessment.decision = Decision::Allow;
                assessment.terminal = true;
                assessment.rewrite = Some(modified_params);
                assessment.telemetry_marker = Some("wasm_rewrite");
                assessment.reasons.push(DecisionReason::new(
                    Stage::Policy,
                    ReasonCode::ExtensionRewrite,
                    format!("wasm extension rewrote arguments for tool `{tool_name}`"),
                ));
                assessment.matched_policies.push(MatchedPolicy::new(
                    PolicySource::WasmExtension,
                    tool_name,
                    Decision::Allow,
                ));
                assessment
            }
            Err(error) => {
                assessment.absorb_failure(
                    SubsystemFailure::new(
                        Subsystem::PolicyExtension,
                        format!("extension failed for tool `{tool_name}`: {error:#}"),
                    ),
                    failure,
                );
                assessment
            }
        }
    }

    /// Handles the case where no declarative policy is loaded at all.
    fn unconfigured(
        &self,
        action: &AgentAction,
        failure: &FailurePolicy,
        version: Option<String>,
    ) -> PolicyAssessment {
        let mut assessment = PolicyAssessment::proceed(version);
        let state = match self.availability {
            PolicyAvailability::Available => PolicyAvailability::Missing,
            other => other,
        };
        assessment.policy_availability = state;

        let detail = format!("policy_unavailable: {state} — no declarative policy is loaded");

        if !failure.missing_policy.permits_allow() {
            assessment.absorb_failure(
                SubsystemFailure::new(Subsystem::PolicyMissing, detail),
                failure,
            );
            return assessment;
        }

        // Development posture: fail open, but never silently — record the reason and
        // still run Wasm extensions if present.
        assessment.reasons.push(DecisionReason::new(
            Stage::Policy,
            ReasonCode::PolicyUnavailable,
            format!("{detail} (development posture: FAIL_OPEN — Sqreen is not enforcing a policy)"),
        ));
        assessment.failures.push(SubsystemFailure::new(
            Subsystem::PolicyMissing,
            "no declarative policy is loaded (development FAIL_OPEN)",
        ));

        self.apply_extension(action, assessment, failure)
    }
}

/// Runs a synchronous stage body, converting a panic into a failure detail.
///
/// Regex evaluation, Wasm host calls, and payload walking are the places a malformed input
/// has historically been able to abort a process. A panic inside one of them used to take
/// down the relay task and, with it, the agent's connection; containing it here turns an
/// unexpected crash into an ordinary [`Subsystem`] failure that the matrix already has an
/// answer for.
fn catch_stage_panic<T>(body: impl FnOnce() -> T) -> Result<T, String> {
    std::panic::catch_unwind(std::panic::AssertUnwindSafe(body)).map_err(|payload| {
        let detail = payload
            .downcast_ref::<&str>()
            .map(|message| (*message).to_string())
            .or_else(|| payload.downcast_ref::<String>().cloned())
            .unwrap_or_else(|| "unknown panic".to_string());

        format!("panicked during evaluation: {detail}")
    })
}

fn blocked_by_policy(
    reason: String,
    rule: BlockedRule,
    version: Option<String>,
    evaluation: &PolicyEvaluation,
) -> PolicyAssessment {
    let code = match rule {
        BlockedRule::GlobalBlockPattern { .. } => ReasonCode::PolicyGlobalBlockPattern,
        BlockedRule::ToolBlockPattern { .. } => ReasonCode::PolicyToolBlockPattern,
        BlockedRule::ToolAction { .. }
        | BlockedRule::IdentityRule { .. }
        | BlockedRule::TaxonomyRule { .. }
        | BlockedRule::NormalizedRule { .. } => ReasonCode::PolicyToolActionBlock,
    };

    let mut assessment = assessment_from_evaluation(
        evaluation,
        PolicyVerdict::Block {
            reason: reason.clone(),
            rule,
        },
        version.clone(),
    );
    assessment.decision = Decision::Deny;
    assessment.terminal = true;
    assessment.reasons = vec![DecisionReason::new(Stage::Policy, code, reason)];
    assessment
}

fn confirmation_required(
    action: &AgentAction,
    message: String,
    version: &Option<String>,
    evaluation: &PolicyEvaluation,
) -> PolicyAssessment {
    let _ = action;
    eprintln!("mcp-proxy: {message}");

    let mut assessment = assessment_from_evaluation(
        evaluation,
        PolicyVerdict::Confirm {
            message: message.clone(),
        },
        version.clone(),
    );
    assessment.decision = Decision::RequireApproval;
    assessment.terminal = false;
    assessment.reasons = vec![DecisionReason::new(
        Stage::Policy,
        ReasonCode::PolicyConfirmationRequired,
        message,
    )];
    assessment
}

fn redacted(
    action: &AgentAction,
    rewritten: String,
    version: Option<String>,
    evaluation: &PolicyEvaluation,
) -> PolicyAssessment {
    let mut assessment =
        assessment_from_evaluation(evaluation, PolicyVerdict::Allow, version.clone());
    assessment.decision = Decision::Allow;
    assessment.terminal = true;
    assessment.rewrite = Some(rewritten);
    assessment.telemetry_marker = Some("global_redact_keys");
    assessment.reasons = vec![DecisionReason::new(
        Stage::Policy,
        ReasonCode::PolicyRedaction,
        format!(
            "global redact keys rewrote arguments for tool `{}`",
            action.tool_name()
        ),
    )];
    assessment
}

fn assessment_from_evaluation(
    evaluation: &PolicyEvaluation,
    _verdict: PolicyVerdict,
    version: Option<String>,
) -> PolicyAssessment {
    PolicyAssessment {
        decision: Decision::Allow,
        reasons: Vec::new(),
        matched_policies: evaluation
            .matched_rules
            .iter()
            .map(|rule| {
                MatchedPolicy::new(
                    PolicySource::LocalPolicy,
                    rule.id.clone(),
                    effect_to_decision(rule.effect),
                )
                .with_version(version.clone())
            })
            .collect(),
        rewrite: None,
        terminal: false,
        policy_version: version,
        telemetry_marker: None,
        failures: Vec::new(),
        simulated_decision: None,
        policy_availability: PolicyAvailability::Available,
    }
}

fn effect_to_decision(effect: RuleEffect) -> Decision {
    match effect {
        RuleEffect::Deny => Decision::Deny,
        RuleEffect::RequireApproval => Decision::RequireApproval,
        RuleEffect::Allow | RuleEffect::Redact => Decision::Allow,
    }
}

fn simulated_decision(verdict: &PolicyVerdict) -> Decision {
    match verdict {
        PolicyVerdict::Allow | PolicyVerdict::Redact { .. } => Decision::Allow,
        PolicyVerdict::Block { .. } => Decision::Deny,
        PolicyVerdict::Confirm { .. } => Decision::RequireApproval,
        PolicyVerdict::Unevaluable { .. } => Decision::Deny,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::action::{Arguments, Runtime, SourceRef};

    fn action(tool: &str, arguments: serde_json::Value) -> AgentAction {
        AgentAction::builder(tool, Arguments::from_name_and_arguments(tool, &arguments))
            .source(SourceRef::new(Runtime::MCP_STDIO, "test"))
            .build_unvalidated()
    }

    fn engine(yaml: &str) -> Arc<PolicyEngine> {
        Arc::new(PolicyEngine::from_yaml(yaml).expect("compile policy"))
    }

    const POLICY: &str = r#"
version: "7"
global:
  redact_keys: []
  risk_threshold: 70
  block_patterns: ["\\.ssh/"]
tools:
  - name: "read_file"
    action: "Allow"
    block_patterns: ["/etc/shadow"]
  - name: "drop_table"
    action: "Block"
    block_patterns: []
  - name: "execute_bash"
    action: "Confirm"
    block_patterns: []
"#;

    #[test]
    fn allows_and_continues_to_the_risk_stage() {
        let stage = PolicyStage::new(Some(engine(POLICY)), None);
        let assessment = stage.evaluate(
            &action("read_file", serde_json::json!({"path": "/tmp/a"})),
            None,
            None,
            &FailurePolicy::default(),
        );

        assert_eq!(assessment.decision, Decision::Allow);
        assert!(!assessment.terminal);
        assert_eq!(assessment.policy_version.as_deref(), Some("7"));
    }

    #[test]
    fn global_pattern_block_is_attributed_to_the_global_rule() {
        let stage = PolicyStage::new(Some(engine(POLICY)), None);
        let assessment = stage.evaluate(
            &action("read_file", serde_json::json!({"path": "~/.ssh/id_rsa"})),
            None,
            None,
            &FailurePolicy::default(),
        );

        assert_eq!(assessment.decision, Decision::Deny);
        assert!(assessment.terminal);
        assert_eq!(
            assessment.reasons[0].code,
            ReasonCode::PolicyGlobalBlockPattern
        );
        assert_eq!(
            assessment.matched_policies[0].rule_id,
            "organization.global.block_patterns[\\.ssh/]"
        );
        assert_eq!(assessment.matched_policies[0].version.as_deref(), Some("7"));
    }

    #[test]
    fn tool_pattern_block_is_attributed_to_the_tool_rule() {
        let stage = PolicyStage::new(Some(engine(POLICY)), None);
        let assessment = stage.evaluate(
            &action("read_file", serde_json::json!({"path": "/etc/shadow"})),
            None,
            None,
            &FailurePolicy::default(),
        );

        assert_eq!(
            assessment.reasons[0].code,
            ReasonCode::PolicyToolBlockPattern
        );
        assert_eq!(
            assessment.matched_policies[0].rule_id,
            "organization.tools[read_file].block_patterns[/etc/shadow]"
        );
    }

    #[test]
    fn tool_action_block_is_attributed_to_the_action() {
        let stage = PolicyStage::new(Some(engine(POLICY)), None);
        let assessment = stage.evaluate(
            &action("drop_table", serde_json::json!({"table": "users"})),
            None,
            None,
            &FailurePolicy::default(),
        );

        assert_eq!(
            assessment.reasons[0].code,
            ReasonCode::PolicyToolActionBlock
        );
        assert_eq!(
            assessment.matched_policies[0].rule_id,
            "organization.tools[drop_table].action"
        );
    }

    /// `Confirm` must reach the approval stage rather than being logged and dropped.
    #[test]
    fn confirm_requires_approval_and_still_runs_risk() {
        let stage = PolicyStage::new(Some(engine(POLICY)), None);
        let assessment = stage.evaluate(
            &action("execute_bash", serde_json::json!({"command": "ls"})),
            None,
            None,
            &FailurePolicy::default(),
        );

        assert_eq!(assessment.decision, Decision::RequireApproval);
        assert!(
            !assessment.terminal,
            "risk evaluation must still run so it can escalate the reason"
        );
        assert_eq!(
            assessment.reasons[0].code,
            ReasonCode::PolicyConfirmationRequired
        );
    }

    #[test]
    fn redaction_rewrites_and_short_circuits() {
        let stage = PolicyStage::new(
            Some(engine(
                r#"
version: "1"
global:
  redact_keys: ["OPENAI_API_KEY"]
  risk_threshold: 70
  block_patterns: []
tools:
  - name: "set_env"
    action: "Redact"
    block_patterns: []
"#,
            )),
            None,
        );

        let assessment = stage.evaluate(
            &action("set_env", serde_json::json!({"OPENAI_API_KEY": "sk-live"})),
            None,
            None,
            &FailurePolicy::default(),
        );

        assert_eq!(assessment.decision, Decision::Allow);
        assert!(assessment.terminal);
        assert!(assessment.rewrite.is_some());
        assert_eq!(assessment.telemetry_marker, Some("global_redact_keys"));
    }

    #[test]
    fn absent_policy_fails_closed_by_default() {
        let stage = PolicyStage::new(None, None);
        let assessment = stage.evaluate(
            &action("read_file", serde_json::json!({"path": "~/.ssh/id_rsa"})),
            None,
            None,
            &FailurePolicy::default(),
        );

        assert_eq!(assessment.decision, Decision::Deny);
        assert!(assessment.terminal);
        assert!(stage.is_unconfigured());
        assert_eq!(assessment.policy_availability, PolicyAvailability::Missing);
        assert_eq!(assessment.reasons[0].code, ReasonCode::PolicyUnavailable);
        assert!(assessment.reasons[0].detail.contains("policy_unavailable"));
    }

    #[test]
    fn absent_policy_fails_open_only_under_development_posture() {
        use crate::gateway::EnforcementPosture;

        let stage = PolicyStage::new(None, None);
        let assessment = stage.evaluate(
            &action("read_file", serde_json::json!({"path": "/tmp/a"})),
            None,
            None,
            &FailurePolicy::for_posture(EnforcementPosture::Development),
        );

        assert_eq!(assessment.decision, Decision::Allow);
        assert!(!assessment.terminal);
        assert!(assessment
            .reasons
            .iter()
            .any(|reason| reason.code == ReasonCode::PolicyUnavailable));
        assert!(assessment.reasons[0]
            .detail
            .contains("development posture: FAIL_OPEN"));
    }

    #[test]
    fn remote_unavailable_without_engine_denies_under_managed() {
        use crate::gateway::EnforcementPosture;

        let stage =
            PolicyStage::new(None, None).with_availability(PolicyAvailability::RemoteUnavailable);
        let assessment = stage.evaluate(
            &action("read_file", serde_json::json!({"path": "/tmp/a"})),
            None,
            None,
            &FailurePolicy::for_posture(EnforcementPosture::Managed),
        );

        assert_eq!(assessment.decision, Decision::Deny);
        assert_eq!(
            assessment.policy_availability,
            PolicyAvailability::RemoteUnavailable
        );
        assert_eq!(assessment.reasons[0].code, ReasonCode::PolicyUnavailable);
    }
}
