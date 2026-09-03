//! OpenAI tool / function call adapter.
//!
//! Handles both the modern `tool_calls[].function` shape and the deprecated
//! `function_call` shape, which differ only in envelope.
//!
//! # Payload fidelity
//!
//! OpenAI sends `arguments` as a JSON-encoded *string*. The pre-existing code re-parsed
//! that string when it was valid JSON and kept it as a string when it was not, then
//! rebuilt an MCP-shaped params document. [`Arguments::from_name_and_arguments`] performs
//! exactly that sequence, so the bytes handed to the policy engine are unchanged.

use serde_json::Value;

use super::{AdapterError, NormalizationContext, ToolCallAdapter};
use crate::action::{AgentAction, Arguments, ModelProvider, Runtime, SourceRef};

/// An OpenAI function tool call.
#[derive(Debug, Clone, Copy)]
pub struct OpenAiFunctionCall<'a> {
    /// Function name.
    pub name: &'a str,
    /// Function arguments, typically a JSON-encoded string.
    pub arguments: &'a Value,
    /// `tool_calls[].id`, when present.
    pub call_id: Option<&'a str>,
    /// Model that produced the call, when the response body names one.
    pub model: Option<&'a str>,
}

impl<'a> OpenAiFunctionCall<'a> {
    /// Builds a call from a name and arguments.
    pub fn new(name: &'a str, arguments: &'a Value) -> Self {
        Self {
            name,
            arguments,
            call_id: None,
            model: None,
        }
    }

    /// Attaches the tool call id.
    pub fn with_call_id(mut self, call_id: Option<&'a str>) -> Self {
        self.call_id = call_id;
        self
    }

    /// Attaches the model name.
    pub fn with_model(mut self, model: Option<&'a str>) -> Self {
        self.model = model;
        self
    }

    /// Extracts a call from a `tool_calls[]` entry.
    ///
    /// Mirrors the pre-existing enforcement path, including its `unknown_tool` fallback for
    /// a call whose function name is missing: dropping such a call silently would let it
    /// past the guard, so it is evaluated under a placeholder name instead.
    pub fn from_tool_call_entry(entry: &'a Value) -> Self {
        Self {
            name: entry
                .pointer("/function/name")
                .and_then(Value::as_str)
                .unwrap_or(UNKNOWN_TOOL),
            arguments: entry.pointer("/function/arguments").unwrap_or(&Value::Null),
            call_id: entry.get("id").and_then(Value::as_str),
            model: None,
        }
    }
}

/// Placeholder name used when a `tool_calls[]` entry omits its function name.
pub const UNKNOWN_TOOL: &str = "unknown_tool";

/// Normalizes OpenAI tool calls.
#[derive(Debug, Clone, Copy, Default)]
pub struct OpenAiAdapter;

impl<'wire> ToolCallAdapter<'wire> for OpenAiAdapter {
    type Wire = OpenAiFunctionCall<'wire>;

    const ADAPTER_ID: &'static str = "openai";
    const RUNTIME: Runtime = Runtime::OPENAI_HTTP;

    fn decode(
        context: &NormalizationContext,
        wire: Self::Wire,
    ) -> Result<AgentAction, AdapterError> {
        let arguments = Arguments::from_name_and_arguments(wire.name, wire.arguments);

        let source = SourceRef::new(Self::RUNTIME, Self::ADAPTER_ID)
            .with_call_id(wire.call_id.map(str::to_string))
            .with_event(Some("tool_calls".to_string()));

        let mut builder = context
            .begin(wire.name, arguments, source)
            .model_provider(Some(ModelProvider::OPENAI));

        if let Some(model) = wire.model {
            builder = builder.model_name(Some(model.to_string()));
        }

        if wire.name == UNKNOWN_TOOL {
            builder = builder.metadata_entry("openai.name_missing", "true");
        }

        Ok(builder.build()?)
    }
}

/// Provider-native enforcement for an OpenAI `tool_calls[]` entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OpenAiEffect {
    /// Keep the tool call; optionally replace `function.arguments` with rewritten bytes.
    Forward {
        /// MCP-shaped params JSON from the gateway, when a stage rewrote arguments.
        rewritten_params_json: Option<String>,
    },
    /// Drop this tool call from the response.
    Drop { reason: String },
}

impl<'wire> super::RuntimeAdapter<'wire> for OpenAiAdapter {
    type Effect = OpenAiEffect;

    fn enforce(
        _wire: &Self::Wire,
        _action: &AgentAction,
        outcome: &crate::gateway::EvaluationOutcome,
    ) -> Result<Self::Effect, AdapterError> {
        if outcome.stops_execution() {
            return Ok(OpenAiEffect::Drop {
                reason: outcome
                    .primary_detail()
                    .unwrap_or("blocked by mcp-proxy")
                    .to_string(),
            });
        }

        Ok(OpenAiEffect::Forward {
            rewritten_params_json: outcome.rewritten_arguments.clone(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::action::{Operation, ToolType};
    use crate::guard::ToolInvocation;

    fn context() -> NormalizationContext {
        NormalizationContext::new()
    }

    #[test]
    fn normalizes_a_function_call_with_object_arguments() {
        let arguments = serde_json::json!({"path": "/tmp/x"});
        let action =
            OpenAiAdapter::decode(&context(), OpenAiFunctionCall::new("read_file", &arguments))
                .expect("decode");

        assert_eq!(action.tool_name(), "read_file");
        assert_eq!(action.runtime(), &Runtime::OPENAI_HTTP);
        assert_eq!(action.model.provider, Some(ModelProvider::OPENAI));
        assert_eq!(action.tool_type, ToolType::FILESYSTEM);
        assert_eq!(action.operation, Operation::Read);
    }

    #[test]
    fn reparses_json_encoded_argument_strings() {
        let arguments = Value::String(r#"{"path":"/tmp/x"}"#.to_string());
        let action =
            OpenAiAdapter::decode(&context(), OpenAiFunctionCall::new("read_file", &arguments))
                .expect("decode");

        assert_eq!(action.arguments.string_field("path"), Some("/tmp/x"));
    }

    #[test]
    fn keeps_unparseable_argument_strings_as_strings() {
        let arguments = Value::String("this is not json".to_string());
        let action =
            OpenAiAdapter::decode(&context(), OpenAiFunctionCall::new("read_file", &arguments))
                .expect("decode");

        assert_eq!(
            action.arguments.value(),
            &Value::String("this is not json".to_string())
        );
    }

    /// Guards the migration itself: the adapter must produce the same payload the
    /// pre-existing constructor did, or deployed policy regexes change meaning.
    #[test]
    fn payload_matches_the_legacy_constructor() {
        let cases = [
            serde_json::json!({"path": "/tmp/x"}),
            Value::String(r#"{"path":"/tmp/x"}"#.to_string()),
            Value::String("not json".to_string()),
            Value::Null,
            serde_json::json!({"nested": {"a": [1, 2, {"b": "c"}]}}),
        ];

        for arguments in cases {
            let legacy = ToolInvocation::from_openai_function("read_file", &arguments)
                .expect("legacy constructor");
            let action =
                OpenAiAdapter::decode(&context(), OpenAiFunctionCall::new("read_file", &arguments))
                    .expect("decode");

            assert_eq!(
                action.canonical_params_json(),
                legacy.params_json,
                "payload drift for {arguments}"
            );
            assert_eq!(action.tool_name(), legacy.tool_name);
        }
    }

    #[test]
    fn extracts_a_call_from_a_tool_calls_entry() {
        let entry = serde_json::json!({
            "id": "call_abc",
            "type": "function",
            "function": {"name": "execute_bash", "arguments": "{\"command\":\"ls\"}"}
        });

        let action =
            OpenAiAdapter::decode(&context(), OpenAiFunctionCall::from_tool_call_entry(&entry))
                .expect("decode");

        assert_eq!(action.tool_name(), "execute_bash");
        assert_eq!(action.source.provider_call_id.as_deref(), Some("call_abc"));
        assert_eq!(action.tool_type, ToolType::SHELL);
        assert_eq!(action.arguments.string_field("command"), Some("ls"));
    }

    #[test]
    fn falls_back_to_a_placeholder_when_the_name_is_missing() {
        let entry = serde_json::json!({"id": "call_1", "function": {"arguments": "{}"}});
        let action =
            OpenAiAdapter::decode(&context(), OpenAiFunctionCall::from_tool_call_entry(&entry))
                .expect("decode");

        assert_eq!(action.tool_name(), UNKNOWN_TOOL);
        assert_eq!(
            action
                .metadata
                .get("openai.name_missing")
                .map(String::as_str),
            Some("true")
        );
    }

    #[test]
    fn records_the_model_when_the_response_names_one() {
        let arguments = serde_json::json!({});
        let action = OpenAiAdapter::decode(
            &context(),
            OpenAiFunctionCall::new("read_file", &arguments).with_model(Some("gpt-4o")),
        )
        .expect("decode");

        assert_eq!(action.model.name.as_deref(), Some("gpt-4o"));
    }

    #[test]
    fn rejects_a_blank_function_name() {
        let arguments = serde_json::json!({});
        let error = OpenAiAdapter::decode(&context(), OpenAiFunctionCall::new("  ", &arguments))
            .expect_err("blank name must be rejected");

        assert!(matches!(
            error,
            AdapterError::Validation(crate::action::ActionValidationError::EmptyToolName)
        ));
    }
}
