//! Compatibility facade over the [Agent Execution Gateway](crate::gateway).
//!
//! # What lives here now
//!
//! The pipeline moved to [`crate::gateway`], which separates identity enrichment, policy
//! evaluation, risk evaluation, approvals, and auditing into stages with a typed
//! [`EvaluationOutcome`]. This module is what remains: the [`GuardContext`] bundle the
//! relays already hold, the two-variant [`GuardDecision`] they already match on, and the
//! translation between them.
//!
//! New integrations should build a gateway with [`crate::gateway::GatewayBuilder`] and read
//! [`EvaluationOutcome`] directly — it carries the reasons, matched rules, policy version,
//! and latency that [`GuardDecision`] throws away, and it can express
//! [`crate::gateway::Decision::RequireApproval`].
//!
//! # Entry points
//!
//! - [`evaluate_action`] — evaluates a normalized action and projects the outcome onto
//!   [`GuardDecision`].
//! - [`evaluate_tool_invocation`] — retained for compatibility. Bridges the older
//!   [`ToolInvocation`] into an action and delegates.
//!
//! # Payload contract
//!
//! Every engine still consumes the canonical params string rather than the typed fields on
//! the action, reached through [`AgentAction::canonical_params_json`]. That is deliberate:
//! the policy regexes, IOC substrings, Wasm guest ABI, and DLP scanner were all written
//! against those exact bytes. Teaching the engines to read
//! [`AgentAction::target_resource`] and [`AgentAction::destination`] is a separate change
//! with its own behavioral surface.

use std::sync::Arc;

use anyhow::Result;
use serde_json::Value;

use crate::action::{AgentAction, Arguments, Runtime, SourceRef};
use crate::behavior::SessionTracker;
use crate::cloud_client::CloudClient;
use crate::gateway::{
    select_approval_engine, AgentExecutionGateway, EvaluationOutcome, FailurePolicy, NullAuditSink,
    PolicyAvailability, TimeoutApprovalEngine,
};
use crate::policy::PolicyEngine;
use crate::threat_intel::ThreatIntelMatcher;
use crate::wasm_engine::WasmPolicyEngine;

/// Telemetry marker when secret-value DLP masks a payload.
pub use crate::gateway::TELEMETRY_SECRET_EGRESS;

/// A single tool invocation expressed in MCP `tools/call` params shape.
///
/// # Deprecated in favor of [`AgentAction`]
///
/// This was the pre-normalization internal contract, and every non-MCP integration had to
/// fabricate an MCP envelope to use it. It is retained so external callers and the existing
/// tests keep compiling; new code should build an [`AgentAction`] through
/// [`crate::adapters`] and call [`evaluate_action`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ToolInvocation {
    pub tool_name: String,
    /// Full params JSON: `{"name":"...","arguments":...}`.
    pub params_json: String,
}

impl ToolInvocation {
    /// Builds an invocation from an MCP `tools/call` params object.
    pub fn from_tools_call_params(params_json: &str) -> Result<Self> {
        let tool_name = crate::wasm_engine::parse_tool_name(params_json)?;
        Ok(Self {
            tool_name,
            params_json: params_json.to_string(),
        })
    }

    /// Builds an invocation from an OpenAI-style function tool call.
    pub fn from_openai_function(name: &str, arguments: &Value) -> Result<Self> {
        let args = match arguments {
            Value::String(raw) => serde_json::from_str(raw).unwrap_or(Value::String(raw.clone())),
            other => other.clone(),
        };
        let params = serde_json::json!({
            "name": name,
            "arguments": args,
        });
        Ok(Self {
            tool_name: name.to_string(),
            params_json: params.to_string(),
        })
    }

    /// Bridges a legacy invocation into a normalized action.
    ///
    /// Intentionally skips validation. A caller that constructed a [`ToolInvocation`]
    /// directly may hold a payload the current validator would reject, and rejecting it
    /// here would turn a previously-evaluated call into an error. The name and payload are
    /// carried across verbatim, so the guard sees byte-identical input either way.
    pub fn to_agent_action(&self) -> AgentAction {
        let parsed = serde_json::from_str::<Value>(&self.params_json)
            .ok()
            .and_then(|root| root.get("arguments").cloned())
            .unwrap_or(Value::Null);

        AgentAction::builder(
            &self.tool_name,
            Arguments::from_parts_unchecked(self.params_json.clone(), parsed),
        )
        .source(SourceRef::new(Runtime::UNKNOWN, "legacy_tool_invocation"))
        .build_unvalidated()
    }
}

/// Final decision after policy, Wasm, and risk layers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GuardDecision {
    Allow {
        rewritten_params_json: Option<String>,
        risk_score: u8,
    },
    Block {
        reason: String,
        risk_score: u8,
    },
}

/// Shared engines used to evaluate a tool invocation.
///
/// Retained as the bundle the relays already thread through their call stacks.
/// [`GuardContext::gateway`] turns one into an [`AgentExecutionGateway`].
#[derive(Clone)]
pub struct GuardContext {
    pub policy: Option<Arc<PolicyEngine>>,
    /// Availability of `policy` (MISSING / STALE / REMOTE_UNAVAILABLE / …).
    pub policy_availability: PolicyAvailability,
    pub wasm: Option<Arc<WasmPolicyEngine>>,
    pub threat_intel: Arc<ThreatIntelMatcher>,
    pub session: Arc<SessionTracker>,
    pub cloud: Option<Arc<CloudClient>>,
}

impl GuardContext {
    /// Builds the gateway this context describes.
    ///
    /// Configures the local runtime's stages: no identity resolver beyond env static claims;
    /// approval engine selected by `SQREEN_APPROVAL_MODE` (`local` default, `remote` /
    /// `auto` when a cloud client is present); and control-plane auditing when configured.
    ///
    /// Construction is cheap — every field is an `Arc` — which is what lets the relays call
    /// this per frame and pick up a hot-reloaded policy snapshot.
    pub fn gateway(&self) -> AgentExecutionGateway {
        let approval = TimeoutApprovalEngine::with_default_deadline(select_approval_engine(
            self.cloud.as_ref(),
        ));
        let builder = AgentExecutionGateway::builder()
            .policy_engine(self.policy.clone())
            .policy_availability(self.policy_availability)
            .extension(self.wasm.clone())
            .threat_intel(self.threat_intel.clone())
            .session(self.session.clone())
            .identity(Arc::new(crate::gateway::StaticIdentityResolver::from_env()))
            .failure_policy(FailurePolicy::from_env())
            .approval(Arc::new(approval));

        match self.cloud.clone() {
            Some(client) => builder.cloud_audit(client),
            None => builder.audit(Arc::new(NullAuditSink)),
        }
        .build()
    }
}

/// Evaluates a legacy [`ToolInvocation`].
///
/// Retained for backwards compatibility; delegates to [`evaluate_action`] after bridging.
/// Prefer building an action through [`crate::adapters`] and calling [`evaluate_action`].
pub async fn evaluate_tool_invocation(
    ctx: &GuardContext,
    invocation: &ToolInvocation,
) -> Result<GuardDecision> {
    evaluate_action(ctx, &invocation.to_agent_action()).await
}

/// Evaluates a normalized action and projects the outcome onto [`GuardDecision`].
///
/// A thin wrapper over [`AgentExecutionGateway::evaluate`]. The `Result` is retained for
/// signature compatibility and is always `Ok`: the gateway converts every internal failure
/// into a decision governed by [`crate::gateway::FailurePolicy`], so there is no error
/// left for a caller to interpret.
///
/// Prefer [`evaluate_outcome`] when you want the reasons, matched rules, policy version, or
/// latency rather than just allow-or-block.
pub async fn evaluate_action(ctx: &GuardContext, action: &AgentAction) -> Result<GuardDecision> {
    Ok(evaluate_outcome(ctx, action).await.into_guard_decision())
}

/// Evaluates a normalized action and returns the full outcome.
pub async fn evaluate_outcome(ctx: &GuardContext, action: &AgentAction) -> EvaluationOutcome {
    ctx.gateway().evaluate(action).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::behavior::SessionTracker;
    use crate::threat_intel::ThreatIntelMatcher;
    use std::sync::Arc;

    fn empty_ctx() -> GuardContext {
        GuardContext {
            policy: None,
            policy_availability: PolicyAvailability::Missing,
            threat_intel: Arc::new(ThreatIntelMatcher::default()),
            session: Arc::new(SessionTracker::default()),
            wasm: None,
            cloud: None,
        }
    }

    #[tokio::test]
    async fn missing_policy_blocks_under_default_enforcing_posture() {
        let ctx = empty_ctx();
        let invocation = ToolInvocation::from_tools_call_params(
            r#"{"name":"read_file","arguments":{"path":"/tmp/a"}}"#,
        )
        .unwrap();
        let decision = evaluate_tool_invocation(&ctx, &invocation)
            .await
            .expect("evaluate");
        assert!(
            matches!(decision, GuardDecision::Block { .. }),
            "default posture must deny when no policy is loaded"
        );
    }

    #[test]
    fn builds_openai_function_invocation() {
        let args = serde_json::json!({"path":"/tmp/x"});
        let inv = ToolInvocation::from_openai_function("read_file", &args).unwrap();
        assert_eq!(inv.tool_name, "read_file");
        assert!(inv.params_json.contains("read_file"));
        assert!(inv.params_json.contains("/tmp/x"));
    }

    #[tokio::test]
    async fn missing_policy_blocks_normalized_action_under_default_posture() {
        use crate::adapters::{McpAdapter, McpToolsCall, NormalizationContext, ToolCallAdapter};

        let ctx = empty_ctx();
        let action = McpAdapter::decode(
            &NormalizationContext::new(),
            McpToolsCall::stdio(r#"{"name":"read_file","arguments":{"path":"/tmp/a"}}"#),
        )
        .expect("decode");

        let decision = evaluate_action(&ctx, &action).await.expect("evaluate");
        assert!(matches!(decision, GuardDecision::Block { .. }));
    }

    #[test]
    fn legacy_bridge_carries_the_payload_verbatim() {
        let params = r#"{ "name" : "read_file" , "arguments" : { "path":"/tmp/a" } }"#;
        let invocation = ToolInvocation::from_tools_call_params(params).expect("invocation");
        let action = invocation.to_agent_action();

        assert_eq!(action.canonical_params_json(), params);
        assert_eq!(action.tool_name(), "read_file");
        assert_eq!(action.arguments.string_field("path"), Some("/tmp/a"));
    }

    /// A hand-built invocation the current validator would reject must still evaluate,
    /// because it evaluated before normalization existed.
    #[test]
    fn legacy_bridge_does_not_reject_payloads_the_validator_would() {
        let invocation = ToolInvocation {
            tool_name: "weird_tool".to_string(),
            params_json: "not even json".to_string(),
        };

        let action = invocation.to_agent_action();
        assert_eq!(action.tool_name(), "weird_tool");
        assert_eq!(action.canonical_params_json(), "not even json");
        assert!(action.validate().is_err());
    }
}
