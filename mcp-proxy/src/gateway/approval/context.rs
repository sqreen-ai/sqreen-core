//! Reviewer-facing approval context — the security brief for a human decision.
//!
//! Every field here is already sanitized. Secrets must never appear in approval UI or
//! approval audit events; builders run the same masking path used for decision reasons.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use super::grant::{session_approval_safe, ActionBinding};
use crate::action::{AgentAction, Destination, EnvironmentTier, Resource};
use crate::gateway::decision::{DecisionReason, MatchedPolicy};
use crate::gateway::redact::sanitize_detail;
use crate::scoring::{ExplainableRiskScore, RiskLevel};

/// Default ceiling for optional time-limited approvals.
pub const DEFAULT_TIMED_APPROVAL: std::time::Duration = std::time::Duration::from_secs(15 * 60);

/// Everything a reviewer must see before judging an action.
///
/// Built once per approval prompt and attached to audit history. Arguments are always the
/// DLP-sanitized form when masking ran; otherwise they still pass through
/// [`sanitize_detail`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ApprovalContext {
    /// Unique id for this approval prompt (also used as a nonce / request id).
    pub request_id: String,
    /// When the approval was requested.
    pub timestamp: DateTime<Utc>,
    /// Durable or effective agent id that requested the action.
    pub requesting_agent: String,
    /// Human the agent is acting for, when known.
    pub delegated_user: Option<String>,
    /// Tool / action name under evaluation.
    pub action: String,
    /// Taxonomy action category (`read`, `execute`, …).
    pub action_category: String,
    /// Target resource summary for the reviewer (path/host/command — sanitized).
    pub target_resource: Option<String>,
    /// Deployment environment tier.
    pub environment: String,
    /// Coarse risk band.
    pub risk_level: RiskLevel,
    /// Numeric ordinal severity index (not a probability).
    pub risk_score: u8,
    /// Human-readable risk / policy reasons that triggered the gate.
    pub risk_reasons: Vec<String>,
    /// Rule ids that matched during evaluation.
    pub matched_policies: Vec<String>,
    /// Egress destination summary, when present.
    pub destination: Option<String>,
    /// Sanitized argument payload — never raw secrets.
    pub sanitized_arguments: String,
    /// Cryptographic binding of the exact action under review.
    pub binding: ActionBinding,
    /// Whether [`ApprovalVerdict::ApproveForSession`] is permitted for this action.
    pub session_approval_eligible: bool,
    /// Whether a time-limited approval may be issued.
    pub timed_approval_eligible: bool,
    /// Suggested TTL when a timed approval is offered.
    pub timed_approval_ttl_secs: u64,
}

impl ApprovalContext {
    /// Assembles a reviewer brief from the live evaluation state.
    pub fn build(
        action: &AgentAction,
        sanitized_payload: &str,
        risk_score: u8,
        risk: Option<&ExplainableRiskScore>,
        reasons: &[DecisionReason],
        matched_policies: &[MatchedPolicy],
    ) -> Self {
        let level = risk
            .map(|explanation| explanation.level)
            .unwrap_or_else(|| RiskLevel::High);
        let risk_reasons = {
            let mut items: Vec<String> = reasons
                .iter()
                .map(|reason| sanitize_detail(&reason.detail))
                .collect();
            if let Some(explanation) = risk {
                for factor in &explanation.factors {
                    let line = sanitize_detail(&format!(
                        "{} (+{}) — {}",
                        factor.kind.as_str(),
                        factor.contribution,
                        factor.detail
                    ));
                    if !items.iter().any(|existing| existing == &line) {
                        items.push(line);
                    }
                }
            }
            items
        };

        let binding = ActionBinding::from_action(action);
        let session_ok = session_approval_safe(action, level);
        // Timed approvals use the same safety bar as session grants.
        let timed_ok = session_ok;

        Self {
            request_id: format!("aprq_{}", binding.nonce_seed()),
            timestamp: Utc::now(),
            requesting_agent: action.identity.effective_agent_id().to_string(),
            delegated_user: action
                .identity
                .user_id
                .as_ref()
                .map(|user| sanitize_detail(user)),
            action: action.tool_name().to_string(),
            action_category: action.security.action.as_str().to_string(),
            target_resource: action
                .target_resource
                .as_ref()
                .map(summarize_resource)
                .map(|text| sanitize_detail(&text)),
            environment: environment_label(action.identity.environment.tier).to_string(),
            risk_level: level,
            risk_score,
            risk_reasons,
            matched_policies: matched_policies
                .iter()
                .map(|policy| sanitize_detail(&policy.rule_id))
                .collect(),
            destination: action
                .destination
                .as_ref()
                .map(summarize_destination)
                .map(|text| sanitize_detail(&text)),
            sanitized_arguments: sanitize_detail(sanitized_payload),
            binding,
            session_approval_eligible: session_ok,
            timed_approval_eligible: timed_ok,
            timed_approval_ttl_secs: DEFAULT_TIMED_APPROVAL.as_secs(),
        }
    }

    /// Renders a terminal / log brief for a human reviewer.
    pub fn render_brief(&self) -> String {
        let mut lines = Vec::new();
        lines.push(format!("Request   : {}", self.request_id));
        lines.push(format!("Time      : {}", self.timestamp.to_rfc3339()));
        lines.push(format!("Agent     : {}", self.requesting_agent));
        if let Some(user) = &self.delegated_user {
            lines.push(format!("User      : {user}"));
        }
        lines.push(format!(
            "Action    : {} ({})",
            self.action, self.action_category
        ));
        if let Some(resource) = &self.target_resource {
            lines.push(format!("Resource  : {resource}"));
        }
        if let Some(destination) = &self.destination {
            lines.push(format!("Destination: {destination}"));
        }
        lines.push(format!("Environment: {}", self.environment));
        lines.push(format!(
            "Risk      : {} ({}/100 — ordinal severity, not probability)",
            self.risk_level.as_str(),
            self.risk_score
        ));
        if !self.risk_reasons.is_empty() {
            lines.push("Reasons   :".to_string());
            for reason in self.risk_reasons.iter().take(8) {
                lines.push(format!("  - {reason}"));
            }
        }
        if !self.matched_policies.is_empty() {
            lines.push(format!("Policies  : {}", self.matched_policies.join(", ")));
        }
        lines.push("Arguments :".to_string());
        lines.push(truncate_for_ui(&self.sanitized_arguments, 400));
        lines.push(String::new());
        lines.push(format!(
            "Binding   : {}",
            &self.binding.fingerprint[..self.binding.fingerprint.len().min(16)]
        ));

        let mut choices = vec!["[y] APPROVE_ONCE".to_string(), "[n] DENY".to_string()];
        if self.session_approval_eligible {
            choices.push("[s] APPROVE_FOR_SESSION".to_string());
        }
        if self.timed_approval_eligible {
            choices.push(format!(
                "[t] APPROVE for {}m",
                self.timed_approval_ttl_secs / 60
            ));
        }
        lines.push(format!("Decide    : {}", choices.join("  ")));

        lines.join("\n")
    }
}

fn environment_label(tier: EnvironmentTier) -> &'static str {
    match tier {
        EnvironmentTier::Development => "development",
        EnvironmentTier::Staging => "staging",
        EnvironmentTier::Production => "production",
        EnvironmentTier::Unknown => "unknown",
    }
}

fn summarize_resource(resource: &Resource) -> String {
    match resource {
        Resource::File { path } | Resource::Directory { path } => path.clone(),
        Resource::Command { program, raw } => program
            .as_ref()
            .map(|name| format!("{name} ({raw})"))
            .unwrap_or_else(|| raw.clone()),
        Resource::Url { url, host } => host
            .as_ref()
            .map(|value| format!("url:{value}"))
            .unwrap_or_else(|| format!("url:{url}")),
        Resource::Host { host, port } => match port {
            Some(port) => format!("{host}:{port}"),
            None => host.clone(),
        },
        Resource::Database {
            system,
            database,
            table,
            ..
        } => format!(
            "db:{}:{}.{}",
            system.as_deref().unwrap_or("?"),
            database.as_deref().unwrap_or("?"),
            table.as_deref().unwrap_or("?")
        ),
        Resource::BrowserTarget { url, selector } => format!(
            "browser:{} {}",
            url.as_deref().unwrap_or("?"),
            selector.as_deref().unwrap_or("")
        ),
        Resource::Opaque { descriptor } => descriptor.clone(),
    }
}

fn summarize_destination(destination: &Destination) -> String {
    match destination {
        Destination::Host { host, port } => match port {
            Some(port) => format!("{host}:{port}"),
            None => host.clone(),
        },
        Destination::Url { url, host } => host.clone().unwrap_or_else(|| url.clone()),
        Destination::File { path } => format!("file:{path}"),
        Destination::Process { command } => format!("process:{command}"),
    }
}

fn truncate_for_ui(text: &str, max_len: usize) -> String {
    if text.chars().count() <= max_len {
        return text.to_string();
    }
    let truncated: String = text.chars().take(max_len).collect();
    format!("{truncated}…")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::action::{Arguments, Runtime, SourceRef};
    use crate::gateway::decision::{Decision, PolicySource, ReasonCode, Stage};
    use crate::risk::SECRET_MASK_TOKEN;

    fn action(tool: &str, args: serde_json::Value) -> AgentAction {
        let mut built = AgentAction::builder(tool, Arguments::from_name_and_arguments(tool, &args))
            .source(SourceRef::new(Runtime::MCP_STDIO, "test"))
            .build_unvalidated();
        built.refresh_security_classification();
        built
    }

    #[test]
    fn context_never_embeds_raw_secrets() {
        let probe = action(
            "fetch",
            serde_json::json!({"token": "sk-proj-abcdefghijklmnopqrstuvwxyz012345"}),
        );
        let payload =
            format!(r#"{{"name":"fetch","arguments":{{"token":"{SECRET_MASK_TOKEN}"}}}}"#);
        let ctx = ApprovalContext::build(
            &probe,
            &payload,
            80,
            None,
            &[DecisionReason::new(
                Stage::Risk,
                ReasonCode::RiskThresholdExceeded,
                "risk score 80 met threshold 70",
            )],
            &[MatchedPolicy::new(
                PolicySource::RiskThreshold,
                "global.risk_threshold",
                Decision::RequireApproval,
            )],
        );

        let brief = ctx.render_brief();
        assert!(!brief.contains("sk-proj-abcdefghijklmnopqrstuvwxyz012345"));
        assert!(brief.contains(SECRET_MASK_TOKEN) || brief.contains("MASKED"));
        assert!(!ctx.sanitized_arguments.contains("sk-proj-abcdefghijklmnop"));
    }
}
