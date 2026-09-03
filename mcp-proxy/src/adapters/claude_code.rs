//! Claude Code hook adapter.
//!
//! Claude Code hooks receive a payload of the form:
//!
//! ```json
//! {"session_id": "…", "cwd": "/repo", "hook_event_name": "PreToolUse",
//!  "tool_name": "Bash", "tool_input": {"command": "ls"}}
//! ```
//!
//! Claude Code names its built-in tools in PascalCase (`Bash`, `Read`, `Edit`). Those names
//! are mapped onto the shared taxonomy so a single policy rule covers the same capability
//! across providers, and the original name is kept in
//! [`crate::action::SourceRef::provider_event`] and in metadata for audit.

use serde_json::Value;

use super::{AdapterError, NormalizationContext, ToolCallAdapter};
use crate::action::{
    AgentAction, AgentType, Arguments, ModelProvider, Runtime, SessionId, SourceRef,
};

/// Adapter identifier used in errors and provenance.
const ADAPTER: &str = "claude_code";

/// Hook events that carry a tool call.
const TOOL_CALL_EVENTS: &[&str] = &["PreToolUse", "PostToolUse"];

/// Claude Code built-in tool names mapped onto the shared taxonomy.
const TOOL_NAME_MAP: &[(&str, &str)] = &[
    ("bash", "execute_bash"),
    ("bashoutput", "execute_bash"),
    ("read", "read_file"),
    ("write", "write_file"),
    ("edit", "edit_file"),
    ("multiedit", "edit_file"),
    ("notebookedit", "edit_file"),
    ("glob", "glob_file_search"),
    ("grep", "search_files"),
    ("webfetch", "fetch"),
    ("websearch", "web_search"),
];

/// A Claude Code hook invocation.
#[derive(Debug, Clone, Copy)]
pub struct ClaudeCodeHookEvent<'a> {
    /// `hook_event_name` from the payload.
    pub hook_event_name: &'a str,
    /// `tool_name` from the payload, in Claude Code's own vocabulary.
    pub tool_name: &'a str,
    /// `tool_input` from the payload.
    pub tool_input: &'a Value,
    /// `session_id` from the payload.
    pub session_id: Option<&'a str>,
    /// `cwd` from the payload.
    pub cwd: Option<&'a str>,
}

impl<'a> ClaudeCodeHookEvent<'a> {
    /// Builds an event from its three required parts.
    pub fn new(hook_event_name: &'a str, tool_name: &'a str, tool_input: &'a Value) -> Self {
        Self {
            hook_event_name,
            tool_name,
            tool_input,
            session_id: None,
            cwd: None,
        }
    }

    /// Attaches the session identifier.
    pub fn with_session_id(mut self, session_id: Option<&'a str>) -> Self {
        self.session_id = session_id;
        self
    }

    /// Attaches the working directory.
    pub fn with_cwd(mut self, cwd: Option<&'a str>) -> Self {
        self.cwd = cwd;
        self
    }

    /// Extracts an event from a raw hook payload.
    pub fn from_payload(payload: &'a Value) -> Result<Self, AdapterError> {
        let hook_event_name = payload
            .get("hook_event_name")
            .and_then(Value::as_str)
            .ok_or(AdapterError::MissingField {
                adapter: ADAPTER,
                field: "hook_event_name",
            })?;

        let tool_name =
            payload
                .get("tool_name")
                .and_then(Value::as_str)
                .ok_or(AdapterError::MissingField {
                    adapter: ADAPTER,
                    field: "tool_name",
                })?;

        Ok(Self {
            hook_event_name,
            tool_name,
            tool_input: payload.get("tool_input").unwrap_or(&Value::Null),
            session_id: payload.get("session_id").and_then(Value::as_str),
            cwd: payload.get("cwd").and_then(Value::as_str),
        })
    }
}

/// Normalizes Claude Code hook payloads.
#[derive(Debug, Clone, Copy, Default)]
pub struct ClaudeCodeAdapter;

impl<'wire> ToolCallAdapter<'wire> for ClaudeCodeAdapter {
    type Wire = ClaudeCodeHookEvent<'wire>;

    const ADAPTER_ID: &'static str = ADAPTER;
    const RUNTIME: Runtime = Runtime::CLAUDE_CODE_HOOK;

    fn decode(
        context: &NormalizationContext,
        wire: Self::Wire,
    ) -> Result<AgentAction, AdapterError> {
        if !TOOL_CALL_EVENTS.contains(&wire.hook_event_name) {
            return Err(AdapterError::UnsupportedEvent {
                adapter: ADAPTER,
                event: wire.hook_event_name.to_string(),
            });
        }

        if wire.tool_name.trim().is_empty() {
            return Err(AdapterError::MissingField {
                adapter: ADAPTER,
                field: "tool_name",
            });
        }

        let canonical_name = canonical_tool_name(wire.tool_name);
        let arguments = Arguments::from_name_and_arguments(&canonical_name, wire.tool_input);

        let source = SourceRef::new(Self::RUNTIME, ADAPTER)
            .with_event(Some(wire.hook_event_name.to_string()));

        let mut builder = context
            .begin(&canonical_name, arguments, source)
            .agent_type(AgentType::CLI_AGENT)
            .model_provider(Some(ModelProvider::ANTHROPIC))
            .metadata_entry("claude_code.tool_name", wire.tool_name);

        if let Some(session) = wire.session_id.filter(|value| !value.trim().is_empty()) {
            builder = builder.session_id(Some(SessionId::new(session)));
        }

        if let Some(cwd) = wire.cwd {
            let mut environment = context.environment.clone();
            environment.workspace = Some(cwd.to_string());
            builder = builder.environment(environment);
        }

        Ok(builder.build()?)
    }
}

/// Claude Code PreToolUse permission response.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ClaudeCodeEffect {
    /// Permit the tool use.
    Allow,
    /// Deny with a reason Claude Code can surface.
    Deny { reason: String },
}

impl ClaudeCodeEffect {
    /// Serializes the effect into the JSON document Claude Code hooks expect.
    pub fn to_hook_response(&self) -> Value {
        match self {
            Self::Allow => serde_json::json!({
                "decision": "approve"
            }),
            Self::Deny { reason } => serde_json::json!({
                "decision": "block",
                "reason": reason,
            }),
        }
    }
}

impl<'wire> super::RuntimeAdapter<'wire> for ClaudeCodeAdapter {
    type Effect = ClaudeCodeEffect;

    fn enforce(
        _wire: &Self::Wire,
        _action: &AgentAction,
        outcome: &crate::gateway::EvaluationOutcome,
    ) -> Result<Self::Effect, AdapterError> {
        if outcome.stops_execution() {
            return Ok(ClaudeCodeEffect::Deny {
                reason: outcome
                    .primary_detail()
                    .unwrap_or("blocked by mcp-proxy")
                    .to_string(),
            });
        }
        Ok(ClaudeCodeEffect::Allow)
    }
}

/// Maps a Claude Code tool name onto the shared taxonomy, passing unknown names through.
fn canonical_tool_name(tool_name: &str) -> String {
    let lowered = tool_name.trim().to_ascii_lowercase();

    // MCP tools surface as `mcp__<server>__<tool>`; the trailing segment is the real name.
    if let Some(rest) = lowered.strip_prefix("mcp__") {
        if let Some((_, tool)) = rest.rsplit_once("__") {
            return tool.to_string();
        }
    }

    TOOL_NAME_MAP
        .iter()
        .find(|(claude, _)| *claude == lowered)
        .map(|(_, canonical)| (*canonical).to_string())
        .unwrap_or(lowered)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::action::{Operation, Resource, ToolType};

    fn context() -> NormalizationContext {
        NormalizationContext::new()
    }

    #[test]
    fn normalizes_a_bash_pre_tool_use_event() {
        let payload = serde_json::json!({
            "session_id": "sess_abc",
            "cwd": "/repo",
            "hook_event_name": "PreToolUse",
            "tool_name": "Bash",
            "tool_input": {"command": "rm -rf /tmp/x"}
        });

        let wire = ClaudeCodeHookEvent::from_payload(&payload).expect("payload");
        let action = ClaudeCodeAdapter::decode(&context(), wire).expect("decode");

        assert_eq!(action.tool_name(), "execute_bash");
        assert_eq!(action.tool_type, ToolType::SHELL);
        assert_eq!(action.operation, Operation::Execute);
        assert_eq!(action.runtime(), &Runtime::CLAUDE_CODE_HOOK);
        assert_eq!(action.identity.agent_type, AgentType::CLI_AGENT);
        assert_eq!(action.model.provider, Some(ModelProvider::ANTHROPIC));
        assert_eq!(
            action.execution.session_id.as_ref().map(SessionId::as_str),
            Some("sess_abc")
        );
        assert_eq!(
            action.identity.environment.workspace.as_deref(),
            Some("/repo")
        );
    }

    #[test]
    fn keeps_the_original_tool_name_for_audit() {
        let input = serde_json::json!({"file_path": "/tmp/a"});
        let action = ClaudeCodeAdapter::decode(
            &context(),
            ClaudeCodeHookEvent::new("PreToolUse", "Read", &input),
        )
        .expect("decode");

        assert_eq!(action.tool_name(), "read_file");
        assert_eq!(
            action
                .metadata
                .get("claude_code.tool_name")
                .map(String::as_str),
            Some("Read")
        );
        assert_eq!(action.source.provider_event.as_deref(), Some("PreToolUse"));
    }

    #[test]
    fn maps_the_built_in_tool_vocabulary() {
        let cases = [
            ("Bash", "execute_bash"),
            ("Read", "read_file"),
            ("Write", "write_file"),
            ("Edit", "edit_file"),
            ("MultiEdit", "edit_file"),
            ("Glob", "glob_file_search"),
            ("Grep", "search_files"),
            ("WebFetch", "fetch"),
            ("WebSearch", "web_search"),
        ];

        for (claude, canonical) in cases {
            assert_eq!(canonical_tool_name(claude), canonical, "{claude} drifted");
        }
    }

    #[test]
    fn unwraps_namespaced_mcp_tool_names() {
        assert_eq!(
            canonical_tool_name("mcp__filesystem__read_text_file"),
            "read_text_file"
        );
    }

    #[test]
    fn passes_unknown_tool_names_through_lowercased() {
        assert_eq!(canonical_tool_name("AcmeCustomTool"), "acmecustomtool");
    }

    #[test]
    fn resolves_file_targets_from_claude_argument_names() {
        let input = serde_json::json!({"file_path": "/Users/x/.ssh/id_rsa"});
        let action = ClaudeCodeAdapter::decode(
            &context(),
            ClaudeCodeHookEvent::new("PreToolUse", "Read", &input),
        )
        .expect("decode");

        assert_eq!(
            action.target_resource,
            Some(Resource::File {
                path: "/Users/x/.ssh/id_rsa".to_string()
            })
        );
        assert_eq!(
            action.data_classification.sensitivity,
            crate::action::Sensitivity::Restricted
        );
    }

    #[test]
    fn rejects_events_that_are_not_tool_calls() {
        let input = serde_json::json!({});
        for event in ["SessionStart", "Stop", "UserPromptSubmit", "Notification"] {
            let error = ClaudeCodeAdapter::decode(
                &context(),
                ClaudeCodeHookEvent::new(event, "Bash", &input),
            )
            .expect_err("non tool-call event must be rejected");

            assert_eq!(
                error,
                AdapterError::UnsupportedEvent {
                    adapter: "claude_code",
                    event: event.to_string()
                }
            );
        }
    }

    #[test]
    fn rejects_a_payload_without_a_tool_name() {
        let payload = serde_json::json!({"hook_event_name": "PreToolUse"});
        let error = ClaudeCodeHookEvent::from_payload(&payload)
            .expect_err("missing tool name must be rejected");

        assert_eq!(
            error,
            AdapterError::MissingField {
                adapter: "claude_code",
                field: "tool_name"
            }
        );
    }

    #[test]
    fn rejects_a_blank_tool_name() {
        let input = serde_json::json!({});
        let error = ClaudeCodeAdapter::decode(
            &context(),
            ClaudeCodeHookEvent::new("PreToolUse", "   ", &input),
        )
        .expect_err("blank tool name must be rejected");

        assert_eq!(
            error,
            AdapterError::MissingField {
                adapter: "claude_code",
                field: "tool_name"
            }
        );
    }
}
