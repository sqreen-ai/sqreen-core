//! MCP `tools/call` adapter.
//!
//! # Payload fidelity
//!
//! The params document is carried through **verbatim**. Before normalization the guard
//! received `raw_params.get().to_string()` straight off the wire, and the policy engine,
//! Wasm sandbox, IOC matcher, and DLP scanner all match against those exact bytes —
//! including key order and whitespace. Re-serializing would silently change what a regex
//! sees, so this adapter never rebuilds the JSON.

use serde_json::Value;

use super::{AdapterError, NormalizationContext, ToolCallAdapter};
use crate::action::{AgentAction, Arguments, Runtime, SourceRef};

/// An MCP `tools/call` request as it appeared on the wire.
#[derive(Debug, Clone, Copy)]
pub struct McpToolsCall<'a> {
    /// Verbatim `params` object: `{"name": …, "arguments": …}`.
    pub params_json: &'a str,
    /// JSON-RPC request id, when the transport exposes one.
    pub request_id: Option<&'a str>,
    /// Transport the request arrived on.
    pub transport: McpTransport,
}

/// Which MCP transport carried the request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum McpTransport {
    /// Newline-delimited JSON-RPC over stdio.
    Stdio,
    /// Streamable HTTP.
    Http,
}

impl McpTransport {
    fn runtime(self) -> Runtime {
        match self {
            Self::Stdio => Runtime::MCP_STDIO,
            Self::Http => Runtime::MCP_HTTP,
        }
    }
}

impl<'a> McpToolsCall<'a> {
    /// Builds a stdio `tools/call`.
    pub fn stdio(params_json: &'a str) -> Self {
        Self {
            params_json,
            request_id: None,
            transport: McpTransport::Stdio,
        }
    }

    /// Builds an HTTP `tools/call`.
    pub fn http(params_json: &'a str) -> Self {
        Self {
            params_json,
            request_id: None,
            transport: McpTransport::Http,
        }
    }

    /// Attaches the JSON-RPC request id.
    pub fn with_request_id(mut self, request_id: Option<&'a str>) -> Self {
        self.request_id = request_id;
        self
    }
}

/// Normalizes MCP `tools/call` requests.
#[derive(Debug, Clone, Copy, Default)]
pub struct McpAdapter;

impl<'wire> ToolCallAdapter<'wire> for McpAdapter {
    type Wire = McpToolsCall<'wire>;

    const ADAPTER_ID: &'static str = "mcp";
    const RUNTIME: Runtime = Runtime::MCP_STDIO;

    fn decode(
        context: &NormalizationContext,
        wire: Self::Wire,
    ) -> Result<AgentAction, AdapterError> {
        let (tool_name, arguments) = Arguments::from_canonical_params(wire.params_json)?;

        let source = SourceRef::new(wire.transport.runtime(), Self::ADAPTER_ID)
            .with_call_id(wire.request_id.map(str::to_string))
            .with_event(Some("tools/call".to_string()));

        let mut builder = context.begin(&tool_name, arguments, source);

        if let Some(meta) = progress_token(wire.params_json) {
            builder = builder.metadata_entry("mcp.progress_token", meta);
        }

        Ok(builder.build()?)
    }
}

/// How an MCP JSON-RPC denial should be framed for the client.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum McpDenyStyle {
    /// Rule prohibition → JSON-RPC `-32000` style block.
    RuleProhibition,
    /// Operator / risk / approval denial → JSON-RPC `-32003` access denied.
    AccessDenied,
}

/// Provider-native enforcement for MCP `tools/call`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum McpEffect {
    /// Forward the call, optionally replacing params with the gateway rewrite.
    Forward {
        rewritten_params_json: Option<String>,
    },
    /// Do not forward; respond with a JSON-RPC error.
    Block { reason: String, style: McpDenyStyle },
}

impl<'wire> super::RuntimeAdapter<'wire> for McpAdapter {
    type Effect = McpEffect;

    fn enforce(
        _wire: &Self::Wire,
        _action: &AgentAction,
        outcome: &crate::gateway::EvaluationOutcome,
    ) -> Result<Self::Effect, AdapterError> {
        if outcome.stops_execution() {
            let reason = outcome
                .primary_detail()
                .unwrap_or("blocked by mcp-proxy")
                .to_string();
            let style = if outcome.denied_by_rule() {
                McpDenyStyle::RuleProhibition
            } else {
                McpDenyStyle::AccessDenied
            };
            return Ok(McpEffect::Block { reason, style });
        }

        Ok(McpEffect::Forward {
            rewritten_params_json: outcome.rewritten_arguments.clone(),
        })
    }
}

/// Extracts `_meta.progressToken`, which MCP clients use to correlate long-running calls.
fn progress_token(params_json: &str) -> Option<String> {
    let root: Value = serde_json::from_str(params_json).ok()?;
    let token = root.pointer("/_meta/progressToken")?;
    match token {
        Value::String(value) => Some(value.clone()),
        Value::Number(value) => Some(value.to_string()),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::action::{Operation, Resource, ToolType};

    fn context() -> NormalizationContext {
        NormalizationContext::new()
    }

    #[test]
    fn normalizes_a_tools_call_request() {
        let wire = r#"{"name":"read_file","arguments":{"path":"/etc/hosts"}}"#;
        let action = McpAdapter::decode(&context(), McpToolsCall::stdio(wire)).expect("decode");

        assert_eq!(action.tool_name(), "read_file");
        assert_eq!(action.runtime(), &Runtime::MCP_STDIO);
        assert_eq!(action.source.adapter, "mcp");
        assert_eq!(action.source.provider_event.as_deref(), Some("tools/call"));
        assert_eq!(action.tool_type, ToolType::FILESYSTEM);
        assert_eq!(action.operation, Operation::Read);
        assert_eq!(
            action.target_resource,
            Some(Resource::File {
                path: "/etc/hosts".to_string()
            })
        );
    }

    /// The single most important guarantee in this crate: what the engines see must be
    /// exactly what the wire carried.
    #[test]
    fn preserves_the_wire_payload_byte_for_byte() {
        let wire = r#"{ "arguments" : { "path":"/etc/hosts" } , "name":"read_file" }"#;
        let action = McpAdapter::decode(&context(), McpToolsCall::stdio(wire)).expect("decode");

        assert_eq!(action.canonical_params_json(), wire);
    }

    #[test]
    fn records_the_http_transport_separately() {
        let wire = r#"{"name":"fetch","arguments":{"url":"https://example.com"}}"#;
        let action = McpAdapter::decode(&context(), McpToolsCall::http(wire)).expect("decode");

        assert_eq!(action.runtime(), &Runtime::MCP_HTTP);
    }

    #[test]
    fn carries_the_request_id_as_the_provider_call_id() {
        let wire = r#"{"name":"read_file","arguments":{"path":"/tmp/a"}}"#;
        let action = McpAdapter::decode(
            &context(),
            McpToolsCall::stdio(wire).with_request_id(Some("42")),
        )
        .expect("decode");

        assert_eq!(action.source.provider_call_id.as_deref(), Some("42"));
    }

    #[test]
    fn captures_the_progress_token_when_present() {
        let wire = r#"{"name":"read_file","arguments":{},"_meta":{"progressToken":"abc"}}"#;
        let action = McpAdapter::decode(&context(), McpToolsCall::stdio(wire)).expect("decode");

        assert_eq!(
            action
                .metadata
                .get("mcp.progress_token")
                .map(String::as_str),
            Some("abc")
        );
    }

    #[test]
    fn tolerates_a_missing_arguments_object() {
        let wire = r#"{"name":"list_allowed_directories"}"#;
        let action = McpAdapter::decode(&context(), McpToolsCall::stdio(wire)).expect("decode");

        assert_eq!(action.tool_name(), "list_allowed_directories");
        assert_eq!(action.canonical_params_json(), wire);
    }

    #[test]
    fn rejects_params_without_a_name() {
        let error = McpAdapter::decode(
            &context(),
            McpToolsCall::stdio(r#"{"arguments":{"path":"/tmp"}}"#),
        )
        .expect_err("missing name must be rejected");

        assert!(matches!(
            error,
            AdapterError::Validation(crate::action::ActionValidationError::MissingToolName)
        ));
    }

    #[test]
    fn rejects_unparseable_params() {
        let error = McpAdapter::decode(&context(), McpToolsCall::stdio("{ not json"))
            .expect_err("malformed json must be rejected");

        assert!(matches!(
            error,
            AdapterError::Validation(
                crate::action::ActionValidationError::MalformedArguments { .. }
            )
        ));
    }

    #[test]
    fn rejects_a_non_object_params_document() {
        let error = McpAdapter::decode(&context(), McpToolsCall::stdio(r#""read_file""#))
            .expect_err("string params must be rejected");

        assert!(matches!(
            error,
            AdapterError::Validation(crate::action::ActionValidationError::ArgumentsNotObject)
        ));
    }

    #[test]
    fn rejects_a_blank_tool_name() {
        let error = McpAdapter::decode(&context(), McpToolsCall::stdio(r#"{"name":"   "}"#))
            .expect_err("blank name must be rejected");

        assert!(matches!(
            error,
            AdapterError::Validation(crate::action::ActionValidationError::EmptyToolName)
        ));
    }
}
