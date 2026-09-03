//! Formal provider / runtime adapter framework.
//!
//! # Contract
//!
//! Adding a new agent runtime must not require changing the policy engine, risk engine,
//! approval engine, or gateway core. A contributor implements [`ToolCallAdapter`] (decode)
//! and optionally [`RuntimeAdapter`] (enforce + outcome emission), then wires the transport
//! to [`process_with_adapter`].
//!
//! ```text
//! Provider / runtime
//!        │
//!        ▼
//! 1. intercept  ── provider-specific wire value
//!        │
//!        ▼
//! 2. decode     ── ToolCallAdapter::decode → AgentAction
//!        │
//!        ▼
//! 3. evaluate   ── AgentExecutionGateway (policy → risk → approval)
//!        │
//!        ▼
//! 4. enforce    ── RuntimeAdapter::enforce → provider-native effect
//!        │
//!        ▼
//! 5. emit       ── RuntimeAdapter::emit_outcome (privacy-safe record)
//! ```
//!
//! See `docs/PROVIDER_ADAPTERS.md` for the contributor guide.

use std::time::Duration;

use crate::action::{AgentAction, Runtime};
use crate::gateway::{AgentExecutionGateway, Decision, EvaluationOutcome};

use super::{AdapterError, NormalizationContext, ToolCallAdapter};

/// Whether a catalog entry ships today or is reserved for a future adapter.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RuntimeSupport {
    /// Decode (+ typically enforce) is implemented in-tree.
    Shipped,
    /// Reserved id / runtime slug; no adapter yet — use [`super::GenericAdapter`] meanwhile.
    Planned,
}

/// One row in the provider/runtime catalog.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RuntimeDescriptor {
    /// Stable adapter id (`SourceRef::adapter`, logs, docs).
    pub id: &'static str,
    /// Canonical [`Runtime`] slug when known; planned entries may use a provisional slug.
    pub runtime_slug: &'static str,
    pub support: RuntimeSupport,
    /// One-line description for docs and diagnostics.
    pub summary: &'static str,
}

/// Known and planned runtimes. New adapters should add a row here when they land (or when
/// reserved), without touching gateway/policy/risk.
pub const RUNTIME_CATALOG: &[RuntimeDescriptor] = &[
    RuntimeDescriptor {
        id: "mcp",
        runtime_slug: "mcp_stdio",
        support: RuntimeSupport::Shipped,
        summary: "MCP tools/call over stdio or streamable HTTP",
    },
    RuntimeDescriptor {
        id: "openai",
        runtime_slug: "openai_http",
        support: RuntimeSupport::Shipped,
        summary: "OpenAI Chat Completions / Responses tool_calls",
    },
    RuntimeDescriptor {
        id: "anthropic",
        runtime_slug: "anthropic_http",
        support: RuntimeSupport::Shipped,
        summary: "Anthropic Messages tool_use content blocks",
    },
    RuntimeDescriptor {
        id: "cursor",
        runtime_slug: "cursor_hook",
        support: RuntimeSupport::Shipped,
        summary: "Cursor IDE before*/after* hooks",
    },
    RuntimeDescriptor {
        id: "claude_code",
        runtime_slug: "claude_code_hook",
        support: RuntimeSupport::Shipped,
        summary: "Claude Code PreToolUse / PostToolUse hooks",
    },
    RuntimeDescriptor {
        id: "generic",
        runtime_slug: "custom",
        support: RuntimeSupport::Shipped,
        summary: "Nameless JSON tool calls and direct shell/fs/http/db/browser intercepts",
    },
    // --- Planned (do not implement yet) ---
    RuntimeDescriptor {
        id: "gemini",
        runtime_slug: "gemini_http",
        support: RuntimeSupport::Planned,
        summary: "Google Gemini function calling",
    },
    RuntimeDescriptor {
        id: "langchain",
        runtime_slug: "langchain",
        support: RuntimeSupport::Planned,
        summary: "LangChain / LangGraph tool invocations",
    },
    RuntimeDescriptor {
        id: "crewai",
        runtime_slug: "crewai",
        support: RuntimeSupport::Planned,
        summary: "CrewAI agent tool calls",
    },
    RuntimeDescriptor {
        id: "openai_agents_sdk",
        runtime_slug: "openai_agents_sdk",
        support: RuntimeSupport::Planned,
        summary: "OpenAI Agents SDK tool runs",
    },
    RuntimeDescriptor {
        id: "browser_computer_use",
        runtime_slug: "browser_computer_use",
        support: RuntimeSupport::Planned,
        summary: "Browser / computer-use action streams",
    },
    RuntimeDescriptor {
        id: "shell",
        runtime_slug: "shell_interceptor",
        support: RuntimeSupport::Planned,
        summary: "Dedicated shell interceptor (GenericAdapter covers this today)",
    },
    RuntimeDescriptor {
        id: "rest_api_gateway",
        runtime_slug: "rest_api_gateway",
        support: RuntimeSupport::Planned,
        summary: "REST / API gateway request interception",
    },
    RuntimeDescriptor {
        id: "database",
        runtime_slug: "database_proxy",
        support: RuntimeSupport::Planned,
        summary: "Database proxy / query interception",
    },
];

/// Looks up a catalog row by adapter id.
pub fn runtime_descriptor(id: &str) -> Option<&'static RuntimeDescriptor> {
    RUNTIME_CATALOG.iter().find(|row| row.id == id)
}

/// Privacy-safe summary of one adapter evaluation, for transport logs and hooks.
///
/// Never carries raw arguments, secrets, or full payloads — only identifiers and verdict
/// metadata already safe for audit-style logging.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AdapterExecutionRecord {
    pub adapter_id: &'static str,
    pub runtime: String,
    pub tool_name: String,
    pub action_id: String,
    pub decision: Decision,
    pub risk_score: Option<u8>,
    pub reason_codes: Vec<String>,
    pub stopped: bool,
    pub rewritten: bool,
    pub latency: Duration,
}

impl AdapterExecutionRecord {
    /// Builds a record from the evaluated action and gateway outcome.
    pub fn from_evaluation(
        adapter_id: &'static str,
        action: &AgentAction,
        outcome: &EvaluationOutcome,
    ) -> Self {
        Self {
            adapter_id,
            runtime: action.runtime().as_str().to_string(),
            tool_name: action.tool_name().to_string(),
            action_id: action.action_id.as_str().to_string(),
            decision: outcome.decision,
            risk_score: outcome.risk_score,
            reason_codes: outcome
                .reasons
                .iter()
                .map(|reason| reason.code.as_str().to_string())
                .collect(),
            stopped: outcome.stops_execution(),
            rewritten: outcome.rewritten_arguments.is_some(),
            latency: outcome.latency,
        }
    }
}

/// Result of running the full adapter pipeline once.
#[derive(Debug, Clone)]
pub struct AdapterProcessResult<Effect> {
    /// Normalized action that was evaluated.
    pub action: AgentAction,
    /// Gateway verdict and evidence.
    pub outcome: EvaluationOutcome,
    /// Provider-native enforcement artifact.
    pub effect: Effect,
    /// Privacy-safe execution outcome record (also passed to [`RuntimeAdapter::emit_outcome`]).
    pub record: AdapterExecutionRecord,
}

/// Full provider/runtime adapter: decode + enforce + emit.
///
/// Extends [`ToolCallAdapter`]. Policy, risk, approval, and the gateway never depend on
/// this trait — only transports and contributor docs do.
pub trait RuntimeAdapter<'wire>: ToolCallAdapter<'wire> {
    /// Provider-specific enforcement result (JSON-RPC error, hook document, drop, …).
    type Effect;

    /// Translates a gateway outcome into provider-native behavior.
    ///
    /// Must not re-run policy/risk/approval. Must not embed secrets from the original
    /// payload into `Effect` when a sanitized rewrite exists on the outcome.
    fn enforce(
        wire: &Self::Wire,
        action: &AgentAction,
        outcome: &EvaluationOutcome,
    ) -> Result<Self::Effect, AdapterError>;

    /// Emits execution-outcome information after enforcement.
    ///
    /// Default: log a single sanitized line when the action was stopped or rewritten.
    fn emit_outcome(record: &AdapterExecutionRecord) {
        if !(record.stopped || record.rewritten) {
            return;
        }
        eprintln!(
            "mcp-proxy: adapter_outcome adapter={} runtime={} tool={} decision={} \
             risk={:?} stopped={} rewritten={} latency_ms={}",
            record.adapter_id,
            record.runtime,
            record.tool_name,
            record.decision.as_str(),
            record.risk_score,
            record.stopped,
            record.rewritten,
            record.latency.as_millis()
        );
    }
}

/// Runs the formal adapter lifecycle against the Agent Execution Gateway.
///
/// 1. Decode wire → [`AgentAction`]
/// 2. Evaluate through [`AgentExecutionGateway`]
/// 3. Enforce via [`RuntimeAdapter::enforce`]
/// 4. Emit via [`RuntimeAdapter::emit_outcome`]
pub async fn process_with_adapter<'wire, A>(
    gateway: &AgentExecutionGateway,
    context: &NormalizationContext,
    wire: A::Wire,
) -> Result<AdapterProcessResult<A::Effect>, AdapterError>
where
    A: RuntimeAdapter<'wire>,
    A::Wire: Copy,
{
    let action = A::decode(context, wire)?;
    let outcome = gateway.evaluate(&action).await;
    let effect = A::enforce(&wire, &action, &outcome)?;
    let record = AdapterExecutionRecord::from_evaluation(A::ADAPTER_ID, &action, &outcome);
    A::emit_outcome(&record);

    Ok(AdapterProcessResult {
        action,
        outcome,
        effect,
        record,
    })
}

/// Same as [`process_with_adapter`] for wire types that are not `Copy` (owned envelopes).
pub async fn process_with_adapter_owned<'wire, A>(
    gateway: &AgentExecutionGateway,
    context: &NormalizationContext,
    wire: A::Wire,
) -> Result<AdapterProcessResult<A::Effect>, AdapterError>
where
    A: RuntimeAdapter<'wire>,
    A::Wire: Clone,
{
    let action = A::decode(context, wire.clone())?;
    let outcome = gateway.evaluate(&action).await;
    let effect = A::enforce(&wire, &action, &outcome)?;
    let record = AdapterExecutionRecord::from_evaluation(A::ADAPTER_ID, &action, &outcome);
    A::emit_outcome(&record);

    Ok(AdapterProcessResult {
        action,
        outcome,
        effect,
        record,
    })
}

/// Helper for docs/tests: shipped adapter ids.
pub fn shipped_adapter_ids() -> impl Iterator<Item = &'static str> {
    RUNTIME_CATALOG
        .iter()
        .filter(|row| row.support == RuntimeSupport::Shipped)
        .map(|row| row.id)
}

/// Helper for docs/tests: planned adapter ids.
pub fn planned_adapter_ids() -> impl Iterator<Item = &'static str> {
    RUNTIME_CATALOG
        .iter()
        .filter(|row| row.support == RuntimeSupport::Planned)
        .map(|row| row.id)
}

/// Convenience: runtime constant used when recording catalog consistency in tests.
pub fn runtime_matches_slug(runtime: &Runtime, slug: &str) -> bool {
    runtime.as_str() == slug || (slug == "custom" && !runtime.is_known())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::adapters::{
        McpAdapter, McpToolsCall, OpenAiAdapter, OpenAiFunctionCall, RuntimeAdapter,
    };
    use crate::gateway::{AllowAllApprovalEngine, DenyAllApprovalEngine, GatewayBuilder};
    use crate::policy::PolicyEngine;
    use std::sync::Arc;

    const POLICY: &str = r#"
version: "3"
global:
  redact_keys: []
  risk_threshold: 100
  block_patterns: []
tools:
  - name: "deploy"
    action: "Confirm"
    block_patterns: []
  - name: "read_file"
    action: "Allow"
    block_patterns: []
"#;

    #[test]
    fn catalog_lists_shipped_and_planned_runtimes() {
        assert!(shipped_adapter_ids().any(|id| id == "mcp"));
        assert!(shipped_adapter_ids().any(|id| id == "openai"));
        assert!(shipped_adapter_ids().any(|id| id == "cursor"));
        assert!(planned_adapter_ids().any(|id| id == "gemini"));
        assert!(planned_adapter_ids().any(|id| id == "langchain"));
        assert!(runtime_descriptor("crewai").unwrap().support == RuntimeSupport::Planned);
    }

    #[tokio::test]
    async fn process_with_adapter_decodes_evaluates_and_enforces_mcp() {
        let gateway = GatewayBuilder::default()
            .policy_engine(Some(Arc::new(
                PolicyEngine::from_yaml(POLICY).expect("compile"),
            )))
            .approval(Arc::new(DenyAllApprovalEngine))
            .build();

        let context = NormalizationContext::new();
        let result = process_with_adapter::<McpAdapter>(
            &gateway,
            &context,
            McpToolsCall::stdio(r#"{"name":"deploy","arguments":{"target":"prod"}}"#),
        )
        .await
        .expect("pipeline");

        assert!(result.outcome.stops_execution());
        assert!(matches!(
            result.effect,
            crate::adapters::mcp::McpEffect::Block { .. }
        ));
        assert_eq!(result.record.adapter_id, "mcp");
        assert!(result.record.stopped);
    }

    #[tokio::test]
    async fn process_with_adapter_allows_openai_through_gateway() {
        let gateway = GatewayBuilder::default()
            .policy_engine(Some(Arc::new(
                PolicyEngine::from_yaml(POLICY).expect("compile"),
            )))
            .approval(Arc::new(AllowAllApprovalEngine))
            .build();

        let context = NormalizationContext::new();
        let arguments = serde_json::json!({"path": "/tmp/a"});
        let result = process_with_adapter::<OpenAiAdapter>(
            &gateway,
            &context,
            OpenAiFunctionCall::new("read_file", &arguments),
        )
        .await
        .expect("pipeline");

        assert!(result.outcome.is_allowed());
        assert!(matches!(
            result.effect,
            crate::adapters::openai::OpenAiEffect::Forward { .. }
        ));
    }

    #[tokio::test]
    async fn execution_record_never_embeds_argument_payloads() {
        let action = McpAdapter::decode(
            &NormalizationContext::new(),
            McpToolsCall::stdio(
                r#"{"name":"read_file","arguments":{"token":"sk-proj-abcdefghijklmnopqrstuvwxyz012345"}}"#,
            ),
        )
        .expect("decode");
        let outcome = GatewayBuilder::default().build().evaluate(&action).await;
        let record = AdapterExecutionRecord::from_evaluation("mcp", &action, &outcome);
        let rendered = format!("{record:?}");
        assert!(!rendered.contains("sk-proj-"));
        assert!(!rendered.contains("abcdefghijklmnopqrstuvwxyz"));
    }
}
