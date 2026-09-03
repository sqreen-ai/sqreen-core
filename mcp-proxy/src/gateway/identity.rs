//! Identity and ambient-context enrichment.
//!
//! Adapters fill the identity fields their wire format actually carries, which is usually
//! very little: an OpenAI `tool_calls` entry knows the model but not the operating system
//! user, and a Cursor `beforeShellExecution` hook knows the workspace but not the model.
//! This stage fills the gaps from deployment-level knowledge.
//!
//! # The fill-only-if-absent invariant
//!
//! A resolver may only populate fields the action left unset. The wire format is always
//! more specific than ambient configuration — if an adapter read `model_name` out of the
//! request body, an environment variable must not overwrite it. Every resolver here
//! upholds that, and [`tests::wire_values_win_over_ambient_context`] pins it.
//!
//! # Failure mode
//!
//! Enrichment fails **open**. Identity is descriptive: no engine downstream reads it to
//! decide anything, so a resolver error degrades attribution rather than enforcement. See
//! [`crate::gateway::FailurePolicy`].

use std::fmt;

use crate::action::{AgentAction, AgentType, EnvironmentTier};
use crate::adapters::NormalizationContext;
use crate::identity::{AgentId, AgentInstanceId, DeviceId, WorkspaceId};

/// A resolver failed to enrich an action.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IdentityError {
    /// Resolver that failed.
    pub resolver: &'static str,
    /// What went wrong.
    pub detail: String,
}

impl IdentityError {
    /// Builds an enrichment error.
    pub fn new(resolver: &'static str, detail: impl Into<String>) -> Self {
        Self {
            resolver,
            detail: detail.into(),
        }
    }
}

impl fmt::Display for IdentityError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}: {}", self.resolver, self.detail)
    }
}

impl std::error::Error for IdentityError {}

/// Fills identity and environment fields an adapter could not determine.
pub trait IdentityResolver: Send + Sync {
    /// Enriches `action` in place, leaving already-populated fields untouched.
    fn enrich(&self, action: &mut AgentAction) -> Result<(), IdentityError>;

    /// Stable name for audit records and diagnostics.
    fn name(&self) -> &'static str;
}

/// Leaves actions exactly as the adapter produced them.
///
/// The right choice when the adapter is authoritative — an in-process interception point
/// that already knows the user and session.
#[derive(Debug, Clone, Copy, Default)]
pub struct NoopIdentityResolver;

impl IdentityResolver for NoopIdentityResolver {
    fn enrich(&self, _action: &mut AgentAction) -> Result<(), IdentityError> {
        Ok(())
    }

    fn name(&self) -> &'static str {
        "noop"
    }
}

/// Applies a fixed [`NormalizationContext`] as a backstop for unset fields.
///
/// This is the resolver the local runtime uses. It is constructed once per process from
/// the environment, so enrichment costs a few `Option` checks per action and never touches
/// the filesystem or network on the hot path.
#[derive(Debug, Clone)]
pub struct StaticIdentityResolver {
    context: NormalizationContext,
}

impl StaticIdentityResolver {
    /// Wraps a context.
    pub fn new(context: NormalizationContext) -> Self {
        Self { context }
    }

    /// Reads the context from the process environment once.
    pub fn from_env() -> Self {
        Self::new(NormalizationContext::from_env())
    }

    /// Returns the backing context.
    pub fn context(&self) -> &NormalizationContext {
        &self.context
    }
}

impl IdentityResolver for StaticIdentityResolver {
    fn enrich(&self, action: &mut AgentAction) -> Result<(), IdentityError> {
        let context = &self.context;

        fill(&mut action.execution.session_id, context.session_id.clone());
        fill(&mut action.execution.trace_id, context.trace_id.clone());
        fill(
            &mut action.parent_action_id,
            context.parent_action_id.clone(),
        );
        if action.identity.agent_id.is_none() {
            if let Some(agent_id) = context.agent_id.as_deref() {
                action
                    .identity
                    .set_self_asserted_agent(agent_id, "env:SQREEN_AGENT_ID");
            }
        }
        fill_agent_instance_id(
            &mut action.execution.agent_instance_id,
            context.agent_instance_id.as_deref(),
        );
        fill(&mut action.model.provider, context.model_provider.clone());
        fill(&mut action.model.name, context.model_name.clone());
        if action.identity.user_id.is_none() {
            if let Some(user_id) = context.user_id.clone() {
                action.identity.user_id = Some(user_id);
                action.identity.user_trust = crate::identity::IdentityTrust::SelfAsserted;
                action.identity.user_identity_source = Some("env:SQREEN_USER_ID".to_string());
            }
        }
        fill(
            &mut action.identity.delegated_by,
            context.delegated_by.clone(),
        );
        if action.identity.organization_id.is_none() {
            if let Some(org) = context.organization_id.clone() {
                action.identity.organization_id = Some(org);
                action.identity.organization_trust =
                    crate::identity::IdentityTrust::SelfAsserted;
            }
        }
        fill_workspace_id(
            &mut action.identity.workspace_id,
            context.workspace_id.as_deref(),
        );
        if action.identity.device_id.is_none() {
            if let Some(device_id) = context.device_id.as_deref() {
                action.identity.device_id = Some(crate::identity::DeviceId::new(device_id));
                action.identity.device_trust = crate::identity::IdentityTrust::SelfAsserted;
            }
        }

        if action.identity.agent_type == AgentType::UNKNOWN {
            action.identity.agent_type = context.agent_type.clone();
        }

        if action.execution.runtime == crate::action::Runtime::UNKNOWN {
            action.execution.runtime = action.source.runtime.clone();
        }

        fill(
            &mut action.identity.environment.hostname,
            context.environment.hostname.clone(),
        );
        fill(
            &mut action.identity.environment.os,
            context.environment.os.clone(),
        );
        fill(
            &mut action.identity.environment.workspace,
            context.environment.workspace.clone(),
        );

        if action.identity.environment.tier == EnvironmentTier::Unknown {
            action.identity.environment.tier = context.environment.tier;
        }

        if action.identity.auth.is_anonymous() {
            action.identity.auth = crate::adapters::local_auth_context();
        }

        for (key, value) in &context.labels {
            action
                .identity
                .labels
                .entry(key.clone())
                .or_insert_with(|| value.clone());
        }

        Ok(())
    }

    fn name(&self) -> &'static str {
        "static"
    }
}

/// Writes `value` into `slot` only when `slot` is empty.
fn fill<T>(slot: &mut Option<T>, value: Option<T>) {
    if slot.is_none() {
        *slot = value;
    }
}

fn fill_agent_id(slot: &mut Option<AgentId>, value: Option<&str>) {
    if slot.is_none() {
        *slot = value.map(AgentId::new);
    }
}

fn fill_agent_instance_id(slot: &mut Option<AgentInstanceId>, value: Option<&str>) {
    if slot.is_none() {
        *slot = value.map(AgentInstanceId::new);
    }
}

fn fill_workspace_id(slot: &mut Option<WorkspaceId>, value: Option<&str>) {
    if slot.is_none() {
        *slot = value.map(WorkspaceId::new);
    }
}

fn fill_device_id(slot: &mut Option<DeviceId>, value: Option<&str>) {
    if slot.is_none() {
        *slot = value.map(DeviceId::new);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::action::{
        ActionId, Arguments, Environment, ModelProvider, Runtime, SessionId, SourceRef, TraceId,
    };
    use crate::identity::ModelExecution;
    use std::collections::BTreeMap;

    fn action() -> AgentAction {
        AgentAction::builder(
            "read_file",
            Arguments::from_name_and_arguments("read_file", &serde_json::json!({"path": "/tmp/a"})),
        )
        .source(SourceRef::new(Runtime::MCP_STDIO, "test"))
        .runtime(Runtime::MCP_STDIO)
        .build_unvalidated()
    }

    fn context() -> NormalizationContext {
        NormalizationContext {
            session_id: Some(SessionId::new("ambient-session")),
            trace_id: Some(TraceId::new("ambient-trace")),
            parent_action_id: Some(ActionId::new("ambient-parent")),
            agent_id: Some("ambient-agent".to_string()),
            agent_instance_id: Some("ambient-instance".to_string()),
            agent_type: AgentType::IDE_ASSISTANT,
            model_provider: Some(ModelProvider::ANTHROPIC),
            model_name: Some("ambient-model".to_string()),
            user_id: Some("ambient-user".to_string()),
            delegated_by: Some("ambient-delegator".to_string()),
            organization_id: Some("ambient-org".to_string()),
            workspace_id: Some("ambient-workspace".to_string()),
            device_id: Some("ambient-device".to_string()),
            labels: BTreeMap::from([("team".to_string(), "engineering".to_string())]),
            environment: Environment {
                hostname: Some("ambient-host".to_string()),
                os: Some("ambient-os".to_string()),
                workspace: Some("/ambient".to_string()),
                tier: EnvironmentTier::Production,
            },
        }
    }

    #[test]
    fn fills_every_unset_field() {
        let mut action = action();
        StaticIdentityResolver::new(context())
            .enrich(&mut action)
            .expect("enrich");

        assert_eq!(
            action.execution.session_id.unwrap().as_str(),
            "ambient-session"
        );
        assert_eq!(action.execution.trace_id.unwrap().as_str(), "ambient-trace");
        assert_eq!(action.parent_action_id.unwrap().as_str(), "ambient-parent");
        assert_eq!(action.identity.agent_id.unwrap().as_str(), "ambient-agent");
        assert_eq!(
            action.execution.agent_instance_id.unwrap().as_str(),
            "ambient-instance"
        );
        assert_eq!(action.identity.agent_type, AgentType::IDE_ASSISTANT);
        assert_eq!(action.model.provider, Some(ModelProvider::ANTHROPIC));
        assert_eq!(action.model.name.as_deref(), Some("ambient-model"));
        assert_eq!(action.identity.user_id.as_deref(), Some("ambient-user"));
        assert_eq!(
            action.identity.organization_id.as_deref(),
            Some("ambient-org")
        );
        assert_eq!(
            action.identity.labels.get("team").map(String::as_str),
            Some("engineering")
        );
        assert_eq!(
            action.identity.environment.hostname.as_deref(),
            Some("ambient-host")
        );
        assert_eq!(
            action.identity.environment.tier,
            EnvironmentTier::Production
        );
    }

    #[test]
    fn wire_values_win_over_ambient_context() {
        let mut action = action();
        action.execution.session_id = Some(SessionId::new("wire-session"));
        action.model.name = Some("wire-model".to_string());
        action.identity.agent_type = AgentType::CLI_AGENT;
        action.identity.environment.tier = EnvironmentTier::Development;

        StaticIdentityResolver::new(context())
            .enrich(&mut action)
            .expect("enrich");

        assert_eq!(
            action.execution.session_id.unwrap().as_str(),
            "wire-session"
        );
        assert_eq!(action.model.name.as_deref(), Some("wire-model"));
        assert_eq!(action.identity.agent_type, AgentType::CLI_AGENT);
        assert_eq!(
            action.identity.environment.tier,
            EnvironmentTier::Development
        );
        assert_eq!(action.identity.user_id.as_deref(), Some("ambient-user"));
    }

    #[test]
    fn enrichment_never_touches_the_payload() {
        let mut action = action();
        let payload = action.canonical_params_json().to_string();

        StaticIdentityResolver::new(context())
            .enrich(&mut action)
            .expect("enrich");

        assert_eq!(action.canonical_params_json(), payload);
        assert_eq!(action.tool_name(), "read_file");
    }

    #[test]
    fn noop_resolver_changes_nothing() {
        let mut action = action();
        let before = action.clone();

        NoopIdentityResolver.enrich(&mut action).expect("enrich");

        assert_eq!(action, before);
    }
}
