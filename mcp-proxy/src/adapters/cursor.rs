//! Cursor IDE hook adapter.
//!
//! Cursor invokes hooks with a JSON payload on stdin and expects an allow/deny document on
//! stdout. The payload shape varies per event, so this adapter folds each event into the
//! shared taxonomy:
//!
//! | Hook event             | Normalized tool     |
//! |------------------------|---------------------|
//! | `beforeShellExecution` | `run_terminal_cmd`  |
//! | `beforeReadFile`       | `read_file`         |
//! | `afterFileEdit`        | `edit_file`         |
//! | `beforeMCPExecution`   | the payload's own `tool_name` |
//!
//! Canonicalizing here is safe because no Cursor hook currently reaches
//! [`crate::guard`] — `.cursor/hooks/block-sensitive-paths.py` reimplements a subset of the
//! proxy's block patterns in Python. Normalizing the payload is the prerequisite for
//! deleting that duplication; this adapter does not delete it, and the Python hook keeps
//! working untouched.

use serde_json::{Map, Value};

use super::{AdapterError, NormalizationContext, ToolCallAdapter};
use crate::action::{AgentAction, AgentType, Arguments, Runtime, SessionId, SourceRef, TraceId};

/// Adapter identifier used in errors and provenance.
const ADAPTER: &str = "cursor";

/// A Cursor hook invocation.
#[derive(Debug, Clone, Copy)]
pub struct CursorHookEvent<'a> {
    /// Raw hook payload as read from stdin.
    pub payload: &'a Value,
}

impl<'a> CursorHookEvent<'a> {
    /// Wraps a decoded hook payload.
    pub fn new(payload: &'a Value) -> Self {
        Self { payload }
    }

    fn event_name(&self) -> Option<&str> {
        self.payload.get("hook_event_name").and_then(Value::as_str)
    }
}

/// Normalizes Cursor hook payloads.
#[derive(Debug, Clone, Copy, Default)]
pub struct CursorAdapter;

impl<'wire> ToolCallAdapter<'wire> for CursorAdapter {
    type Wire = CursorHookEvent<'wire>;

    const ADAPTER_ID: &'static str = ADAPTER;
    const RUNTIME: Runtime = Runtime::CURSOR_HOOK;

    fn decode(
        context: &NormalizationContext,
        wire: Self::Wire,
    ) -> Result<AgentAction, AdapterError> {
        let event = wire.event_name().ok_or(AdapterError::MissingField {
            adapter: ADAPTER,
            field: "hook_event_name",
        })?;

        let (tool_name, argument_value) = match event {
            "beforeShellExecution" => (
                "run_terminal_cmd".to_string(),
                shell_arguments(wire.payload, event)?,
            ),
            "beforeReadFile" => (
                "read_file".to_string(),
                path_arguments(wire.payload, event)?,
            ),
            "afterFileEdit" => (
                "edit_file".to_string(),
                path_arguments(wire.payload, event)?,
            ),
            "beforeMCPExecution" => {
                let tool_name = wire
                    .payload
                    .get("tool_name")
                    .and_then(Value::as_str)
                    .ok_or(AdapterError::MissingField {
                        adapter: ADAPTER,
                        field: "tool_name",
                    })?;
                (
                    tool_name.to_string(),
                    wire.payload
                        .get("tool_input")
                        .cloned()
                        .unwrap_or(Value::Null),
                )
            }
            other => {
                return Err(AdapterError::UnsupportedEvent {
                    adapter: ADAPTER,
                    event: other.to_string(),
                })
            }
        };

        let arguments = Arguments::from_name_and_arguments(&tool_name, &argument_value);

        let source = SourceRef::new(Self::RUNTIME, ADAPTER)
            .with_call_id(
                wire.payload
                    .get("generation_id")
                    .and_then(Value::as_str)
                    .map(str::to_string),
            )
            .with_event(Some(event.to_string()));

        let mut builder = context
            .begin(&tool_name, arguments, source)
            .agent_type(AgentType::IDE_ASSISTANT);

        // Cursor's conversation is the natural session boundary, and its generation is the
        // natural trace, so prefer them over anything the process environment supplied.
        if let Some(conversation) = wire.payload.get("conversation_id").and_then(Value::as_str) {
            builder = builder.session_id(Some(SessionId::new(conversation)));
        }
        if let Some(generation) = wire.payload.get("generation_id").and_then(Value::as_str) {
            builder = builder.trace_id(Some(TraceId::new(generation)));
        }

        if let Some(workspace) = first_workspace_root(wire.payload) {
            let mut environment = context.environment.clone();
            environment.workspace = Some(workspace);
            builder = builder.environment(environment);
        }

        if event == "beforeMCPExecution" {
            if let Some(url) = wire.payload.get("url").and_then(Value::as_str) {
                builder = builder.metadata_entry("cursor.mcp_server_url", url);
            }
        }

        Ok(builder.build()?)
    }
}

/// Cursor hook permission response.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CursorEffect {
    /// Permit the hook action.
    Allow,
    /// Deny with a message shown to the user / agent.
    Deny { user_message: String },
}

impl CursorEffect {
    /// Serializes the effect into the JSON document Cursor expects on stdout.
    pub fn to_hook_response(&self) -> Value {
        match self {
            Self::Allow => serde_json::json!({
                "permission": "allow"
            }),
            Self::Deny { user_message } => serde_json::json!({
                "permission": "deny",
                "user_message": user_message,
            }),
        }
    }
}

impl<'wire> super::RuntimeAdapter<'wire> for CursorAdapter {
    type Effect = CursorEffect;

    fn enforce(
        _wire: &Self::Wire,
        _action: &AgentAction,
        outcome: &crate::gateway::EvaluationOutcome,
    ) -> Result<Self::Effect, AdapterError> {
        if outcome.stops_execution() {
            return Ok(CursorEffect::Deny {
                user_message: outcome
                    .primary_detail()
                    .unwrap_or("blocked by mcp-proxy")
                    .to_string(),
            });
        }
        Ok(CursorEffect::Allow)
    }
}

fn shell_arguments(payload: &Value, event: &str) -> Result<Value, AdapterError> {
    let command =
        payload
            .get("command")
            .and_then(Value::as_str)
            .ok_or(AdapterError::MissingField {
                adapter: ADAPTER,
                field: "command",
            })?;

    let mut object = Map::new();
    object.insert("command".to_string(), Value::String(command.to_string()));
    if let Some(cwd) = payload.get("cwd").and_then(Value::as_str) {
        object.insert("cwd".to_string(), Value::String(cwd.to_string()));
    }

    debug_assert_eq!(event, "beforeShellExecution");
    Ok(Value::Object(object))
}

fn path_arguments(payload: &Value, event: &str) -> Result<Value, AdapterError> {
    let path = payload
        .get("file_path")
        .or_else(|| payload.get("filePath"))
        .or_else(|| payload.get("path"))
        .and_then(Value::as_str)
        .ok_or(AdapterError::MissingField {
            adapter: ADAPTER,
            field: "file_path",
        })?;

    let mut object = Map::new();
    object.insert("path".to_string(), Value::String(path.to_string()));

    if event == "afterFileEdit" {
        if let Some(edits) = payload.get("edits") {
            object.insert("edits".to_string(), edits.clone());
        }
    }

    Ok(Value::Object(object))
}

fn first_workspace_root(payload: &Value) -> Option<String> {
    payload
        .get("workspace_roots")
        .and_then(Value::as_array)
        .and_then(|roots| roots.first())
        .and_then(Value::as_str)
        .map(str::to_string)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::action::{Operation, Resource, ToolType};

    fn context() -> NormalizationContext {
        NormalizationContext::new()
    }

    #[test]
    fn normalizes_a_shell_execution_hook() {
        let payload = serde_json::json!({
            "hook_event_name": "beforeShellExecution",
            "conversation_id": "conv_1",
            "generation_id": "gen_1",
            "command": "cat ~/.ssh/id_rsa",
            "cwd": "/Users/x/project",
            "workspace_roots": ["/Users/x/project"]
        });

        let action =
            CursorAdapter::decode(&context(), CursorHookEvent::new(&payload)).expect("decode");

        assert_eq!(action.tool_name(), "run_terminal_cmd");
        assert_eq!(action.tool_type, ToolType::SHELL);
        assert_eq!(action.operation, Operation::Execute);
        assert_eq!(action.runtime(), &Runtime::CURSOR_HOOK);
        assert_eq!(action.identity.agent_type, AgentType::IDE_ASSISTANT);
        assert_eq!(
            action.execution.session_id.as_ref().map(SessionId::as_str),
            Some("conv_1")
        );
        assert_eq!(
            action.execution.trace_id.as_ref().map(TraceId::as_str),
            Some("gen_1")
        );
        assert_eq!(
            action.identity.environment.workspace.as_deref(),
            Some("/Users/x/project")
        );
        assert_eq!(
            action.target_resource,
            Some(Resource::Command {
                program: Some("cat".to_string()),
                raw: "cat ~/.ssh/id_rsa".to_string(),
            })
        );
    }

    #[test]
    fn normalizes_a_read_file_hook() {
        let payload = serde_json::json!({
            "hook_event_name": "beforeReadFile",
            "file_path": "/Users/x/.aws/credentials"
        });

        let action =
            CursorAdapter::decode(&context(), CursorHookEvent::new(&payload)).expect("decode");

        assert_eq!(action.tool_name(), "read_file");
        assert_eq!(action.operation, Operation::Read);
        assert_eq!(
            action.data_classification.sensitivity,
            crate::action::Sensitivity::Restricted
        );
    }

    #[test]
    fn normalizes_a_file_edit_hook() {
        let payload = serde_json::json!({
            "hook_event_name": "afterFileEdit",
            "file_path": "/Users/x/project/src/main.rs",
            "edits": [{"old": "a", "new": "b"}]
        });

        let action =
            CursorAdapter::decode(&context(), CursorHookEvent::new(&payload)).expect("decode");

        assert_eq!(action.tool_name(), "edit_file");
        assert_eq!(action.operation, Operation::Write);
        assert!(action.arguments.value().get("edits").is_some());
    }

    #[test]
    fn passes_through_the_mcp_tool_name_verbatim() {
        let payload = serde_json::json!({
            "hook_event_name": "beforeMCPExecution",
            "tool_name": "read_text_file",
            "tool_input": {"path": "/tmp/a"},
            "url": "http://127.0.0.1:9000/mcp"
        });

        let action =
            CursorAdapter::decode(&context(), CursorHookEvent::new(&payload)).expect("decode");

        assert_eq!(action.tool_name(), "read_text_file");
        assert_eq!(action.tool_type, ToolType::FILESYSTEM);
        assert_eq!(
            action
                .metadata
                .get("cursor.mcp_server_url")
                .map(String::as_str),
            Some("http://127.0.0.1:9000/mcp")
        );
    }

    #[test]
    fn rejects_a_payload_without_an_event_name() {
        let payload = serde_json::json!({"command": "ls"});
        let error = CursorAdapter::decode(&context(), CursorHookEvent::new(&payload))
            .expect_err("missing event must be rejected");

        assert_eq!(
            error,
            AdapterError::MissingField {
                adapter: "cursor",
                field: "hook_event_name"
            }
        );
    }

    #[test]
    fn rejects_a_shell_hook_without_a_command() {
        let payload = serde_json::json!({"hook_event_name": "beforeShellExecution"});
        let error = CursorAdapter::decode(&context(), CursorHookEvent::new(&payload))
            .expect_err("missing command must be rejected");

        assert_eq!(
            error,
            AdapterError::MissingField {
                adapter: "cursor",
                field: "command"
            }
        );
    }

    #[test]
    fn rejects_an_mcp_hook_without_a_tool_name() {
        let payload = serde_json::json!({
            "hook_event_name": "beforeMCPExecution",
            "tool_input": {}
        });
        let error = CursorAdapter::decode(&context(), CursorHookEvent::new(&payload))
            .expect_err("missing tool name must be rejected");

        assert_eq!(
            error,
            AdapterError::MissingField {
                adapter: "cursor",
                field: "tool_name"
            }
        );
    }

    #[test]
    fn rejects_hook_events_that_are_not_tool_calls() {
        for event in ["beforeSubmitPrompt", "stop", "somethingNew"] {
            let payload = serde_json::json!({"hook_event_name": event});
            let error = CursorAdapter::decode(&context(), CursorHookEvent::new(&payload))
                .expect_err("non tool-call event must be rejected");

            assert_eq!(
                error,
                AdapterError::UnsupportedEvent {
                    adapter: "cursor",
                    event: event.to_string()
                }
            );
        }
    }
}
