//! Priority-based policy evaluation over normalized actions.

use std::collections::HashSet;

use super::compile::{CompiledPolicy, CompiledRule, PolicyTrustLayer, RuleSource};
use super::match_ctx::PolicyMatchContext;
use super::schema::{PolicyMode, RuleEffect};
use crate::action::{AgentAction, Arguments};
use crate::behavior::BehaviorFinding;
use crate::scoring::ExplainableRiskScore;

/// Identifies which rule produced a block or approval requirement.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BlockedRule {
    GlobalBlockPattern { pattern: String },
    ToolBlockPattern { tool: String, pattern: String },
    ToolAction { tool: String },
    IdentityRule { name: String },
    TaxonomyRule { name: String },
    NormalizedRule { name: String },
}

impl BlockedRule {
    pub fn rule_id(&self) -> String {
        match self {
            Self::GlobalBlockPattern { pattern } => format!("global.block_patterns[{pattern}]"),
            Self::ToolBlockPattern { tool, pattern } => {
                format!("tools[{tool}].block_patterns[{pattern}]")
            }
            Self::ToolAction { tool } => format!("tools[{tool}].action"),
            Self::IdentityRule { name } => format!("identity_rules[{name}]"),
            Self::TaxonomyRule { name } => format!("taxonomy_rules[{name}]"),
            Self::NormalizedRule { name } => format!("rules[{name}]"),
        }
    }

    fn from_rule(rule: &CompiledRule) -> Self {
        match rule.source {
            RuleSource::Normalized => Self::NormalizedRule {
                name: rule.name.clone(),
            },
            RuleSource::LegacyIdentity => Self::IdentityRule {
                name: rule.name.clone(),
            },
            RuleSource::LegacyTaxonomy => Self::TaxonomyRule {
                name: rule.name.clone(),
            },
            RuleSource::LegacyGlobalBlock => Self::GlobalBlockPattern {
                pattern: rule
                    .name
                    .strip_prefix("global-block-")
                    .unwrap_or(&rule.name)
                    .to_string(),
            },
            RuleSource::LegacyToolBlock => Self::ToolBlockPattern {
                tool: rule
                    .tools
                    .iter()
                    .next()
                    .cloned()
                    .unwrap_or_else(|| "unknown".to_string()),
                pattern: rule.name.clone(),
            },
            RuleSource::LegacyToolAction => Self::ToolAction {
                tool: rule
                    .tools
                    .iter()
                    .next()
                    .cloned()
                    .unwrap_or_else(|| "unknown".to_string()),
            },
        }
    }
}

/// Summary of one rule that matched during evaluation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MatchedRuleSummary {
    pub id: String,
    pub name: String,
    pub priority: i32,
    pub effect: RuleEffect,
    pub trust_layer: &'static str,
    pub explanation: String,
}

/// Outcome of evaluating a single frame against the active policy.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PolicyVerdict {
    Allow,
    Block { reason: String, rule: BlockedRule },
    Redact { frame: Vec<u8> },
    Confirm { message: String },
    Unevaluable { detail: String },
}

/// Detailed evaluation result including every matched rule.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PolicyEvaluation {
    pub mode: PolicyMode,
    pub enforced_verdict: PolicyVerdict,
    pub explanation: String,
    pub winning_rule: Option<String>,
    /// Trust layer of the rule that determined the enforced effect.
    pub winning_trust_layer: Option<&'static str>,
    pub matched_rules: Vec<MatchedRuleSummary>,
    /// Lower-trust matches that did not weaken a stronger constraint.
    pub shadowed_rules: Vec<String>,
}

impl PolicyEvaluation {
    /// Returns the verdict callers should enforce — `Allow` in audit mode unless redaction applies.
    pub fn verdict_for_enforcement(&self) -> PolicyVerdict {
        match self.mode {
            PolicyMode::Enforce => self.enforced_verdict.clone(),
            PolicyMode::Audit => match &self.enforced_verdict {
                PolicyVerdict::Redact { .. } => self.enforced_verdict.clone(),
                PolicyVerdict::Unevaluable { .. } => self.enforced_verdict.clone(),
                _ => PolicyVerdict::Allow,
            },
        }
    }

    pub fn audit_explanation(&self) -> Option<String> {
        if self.mode != PolicyMode::Audit {
            return None;
        }

        match &self.enforced_verdict {
            PolicyVerdict::Allow => None,
            _ => Some(format!(
                "audit-only: would have been `{}` — {}",
                verdict_label(&self.enforced_verdict),
                self.explanation
            )),
        }
    }
}

fn verdict_label(verdict: &PolicyVerdict) -> &'static str {
    match verdict {
        PolicyVerdict::Allow => "allow",
        PolicyVerdict::Block { .. } => "deny",
        PolicyVerdict::Confirm { .. } => "require_approval",
        PolicyVerdict::Redact { .. } => "redact",
        PolicyVerdict::Unevaluable { .. } => "unevaluable",
    }
}

pub fn evaluate_policy(policy: &CompiledPolicy, action: &AgentAction) -> PolicyEvaluation {
    evaluate_policy_with_context(policy, action, None, None)
}

pub fn evaluate_policy_with_behavior(
    policy: &CompiledPolicy,
    action: &AgentAction,
    behavior: Option<&BehaviorFinding>,
) -> PolicyEvaluation {
    evaluate_policy_with_context(policy, action, behavior, None)
}

pub fn evaluate_policy_with_context(
    policy: &CompiledPolicy,
    action: &AgentAction,
    behavior: Option<&BehaviorFinding>,
    risk_score: Option<&ExplainableRiskScore>,
) -> PolicyEvaluation {
    if let Err(detail) = policy_payload_readable(action) {
        return unevaluable_evaluation(policy, detail);
    }

    let ctx = PolicyMatchContext::build_with_context(action, behavior, risk_score);
    let matched: Vec<&CompiledRule> = policy
        .rules
        .iter()
        .filter(|rule| rule.matches(&ctx))
        .collect();

    let matched_rules: Vec<MatchedRuleSummary> = matched
        .iter()
        .map(|rule| MatchedRuleSummary {
            id: rule.id.clone(),
            name: rule.name.clone(),
            priority: rule.priority,
            effect: rule.effect,
            trust_layer: rule.trust_layer.as_str(),
            explanation: rule
                .description
                .clone()
                .unwrap_or_else(|| default_explanation(rule, action)),
        })
        .collect();

    let (winner, shadowed) = select_cross_layer_winner(&matched);

    let enforced_verdict = if let Some(winner) = winner {
        verdict_for_rule(winner, action, &policy.redact_keys)
    } else {
        PolicyVerdict::Allow
    };

    let winning_rule = winner.map(|rule| rule.name.clone());
    let winning_trust_layer = winner.map(|rule| rule.trust_layer.as_str());
    let explanation = if let Some(rule) = winner {
        let mut base = rule
            .description
            .clone()
            .unwrap_or_else(|| default_explanation(rule, action));
        if !shadowed.is_empty() {
            base.push_str("; shadowed: ");
            base.push_str(&shadowed.join("; "));
        }
        if rule.trust_layer == PolicyTrustLayer::MandatoryBaseline {
            base = format!("mandatory baseline rule `{}` — {base}", rule.name);
        }
        base
    } else {
        "no policy rules matched; default allow".to_string()
    };

    PolicyEvaluation {
        mode: policy.mode,
        enforced_verdict,
        explanation,
        winning_rule,
        winning_trust_layer,
        matched_rules,
        shadowed_rules: shadowed,
    }
}

/// Pick the within-layer winner (priority, then effect severity, then order/name).
fn winner_within_layer<'a>(rules: &[&'a CompiledRule]) -> Option<&'a CompiledRule> {
    let mut layer_matches = rules.to_vec();
    layer_matches.sort_by(|left, right| {
        right
            .priority
            .cmp(&left.priority)
            .then_with(|| right.effect.severity().cmp(&left.effect.severity()))
            .then_with(|| left.order.cmp(&right.order))
            .then_with(|| left.name.cmp(&right.name))
    });
    layer_matches.into_iter().next()
}

/// Cross-layer decision: take the strongest effect among per-layer winners.
/// Lower-trust weaker effects are recorded as shadowed (cannot weaken).
fn select_cross_layer_winner<'a>(
    matched: &[&'a CompiledRule],
) -> (Option<&'a CompiledRule>, Vec<String>) {
    let layers = [
        PolicyTrustLayer::MandatoryBaseline,
        PolicyTrustLayer::Organization,
        PolicyTrustLayer::Local,
    ];

    let mut layer_winners: Vec<&CompiledRule> = Vec::new();
    for layer in layers {
        let layer_rules: Vec<&CompiledRule> = matched
            .iter()
            .copied()
            .filter(|r| r.trust_layer == layer)
            .collect();
        if let Some(w) = winner_within_layer(&layer_rules) {
            layer_winners.push(w);
        }
    }

    if layer_winners.is_empty() {
        return (None, Vec::new());
    }

    // Strongest effect wins; on equal severity prefer higher-trust layer for explainability.
    let mut best = layer_winners[0];
    for candidate in &layer_winners[1..] {
        let cand = *candidate;
        if cand.effect.severity() > best.effect.severity()
            || (cand.effect.severity() == best.effect.severity()
                && cand.trust_layer.rank() > best.trust_layer.rank())
        {
            best = cand;
        }
    }

    let mut shadowed = Vec::new();
    for candidate in &layer_winners {
        let cand = *candidate;
        if cand.id == best.id {
            continue;
        }
        // Weaker (or equal-but-lower-trust) effects from lower-trust layers are shadowed.
        if cand.effect.severity() < best.effect.severity()
            || (cand.effect.severity() == best.effect.severity()
                && cand.trust_layer.rank() < best.trust_layer.rank())
        {
            shadowed.push(format!(
                "{} rule `{}` (effect {}, priority {}) did not weaken {} constraint",
                cand.trust_layer.as_str(),
                cand.name,
                cand.effect.as_str(),
                cand.priority,
                best.trust_layer.as_str()
            ));
        }
    }

    (Some(best), shadowed)
}

fn verdict_for_rule(
    rule: &CompiledRule,
    action: &AgentAction,
    redact_keys: &HashSet<String>,
) -> PolicyVerdict {
    match rule.effect {
        RuleEffect::Deny => PolicyVerdict::Block {
            reason: rule
                .description
                .clone()
                .unwrap_or_else(|| default_explanation(rule, action)),
            rule: BlockedRule::from_rule(rule),
        },
        RuleEffect::RequireApproval => PolicyVerdict::Confirm {
            message: rule
                .description
                .clone()
                .unwrap_or_else(|| default_explanation(rule, action)),
        },
        RuleEffect::Redact => PolicyVerdict::Redact {
            frame: super::redact::redact_json_text(action.canonical_params_json(), redact_keys),
        },
        RuleEffect::Allow => PolicyVerdict::Allow,
    }
}

fn default_explanation(rule: &CompiledRule, action: &AgentAction) -> String {
    match rule.source {
        RuleSource::LegacyGlobalBlock => format!(
            "global block pattern `{}` matched tool `{}`",
            rule.name
                .strip_prefix("global-block-")
                .unwrap_or(&rule.name),
            action.tool_name()
        ),
        RuleSource::LegacyToolBlock => {
            format!("tool `{}` matched block pattern", action.tool_name())
        }
        RuleSource::LegacyToolAction => format!(
            "tool `{}` is configured with action Block",
            action.tool_name()
        ),
        _ => format!(
            "policy rule `{}` (priority {}) matched tool `{}` with effect `{}`",
            rule.name,
            rule.priority,
            action.tool_name(),
            rule.effect.as_str()
        ),
    }
}

/// Returns an error when the policy engine cannot structurally read an action payload.
///
/// Legacy [`ToolInvocation`] bridges may carry byte-identical payloads that skip adapter
/// validation; those must not fall through to "no rules matched → allow".
fn policy_payload_readable(action: &AgentAction) -> Result<(), String> {
    match Arguments::from_canonical_params(action.canonical_params_json()) {
        Ok((declared, _)) => {
            if declared != action.tool_name() {
                return Err(format!(
                    "arguments payload declares tool `{declared}` but action is `{}`",
                    action.tool_name()
                ));
            }
            Ok(())
        }
        Err(error) => Err(error.to_string()),
    }
}

fn unevaluable_evaluation(policy: &CompiledPolicy, detail: String) -> PolicyEvaluation {
    PolicyEvaluation {
        mode: policy.mode,
        enforced_verdict: PolicyVerdict::Unevaluable {
            detail: detail.clone(),
        },
        explanation: format!("policy payload is not evaluable: {detail}"),
        winning_rule: None,
        winning_trust_layer: None,
        matched_rules: Vec::new(),
        shadowed_rules: Vec::new(),
    }
}
