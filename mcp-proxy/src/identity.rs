//! Typed agent identity for the execution gateway.
//!
//! # What this answers
//!
//! Sqreen must be able to say, for every action:
//!
//! - **Which agent** attempted it (`agent_id`, `agent_type`, labels)
//! - **Which human** delegated authority (`user_id`, `delegated_by`, `auth`)
//! - **Which model produced it** ([`ModelExecution`] — deliberately *not* agent identity)
//! - **Which runtime** observed it (`runtime` on [`ExecutionContext`])
//! - **Which org/device/session** it belonged to
//! - **Which policies** could target it (via [`IdentityMatchContext`])
//!
//! # Durable vs ephemeral
//!
//! [`AgentIdentity`] holds the *registrable* agent and its deployment context.
//! [`ExecutionContext`] holds the *this-run* binding: instance, session, trace.
//! A model name is neither — it describes the inference call, not who the agent is.
//!
//! # Anonymous and local agents
//!
//! When no IdP or control plane has registered an agent, [`AuthContext::anonymous`] is the
//! default and [`AgentIdentity::effective_agent_id`] falls back to a stable local sentinel
//! so audit records never carry a blank "who".

use std::collections::BTreeMap;
use std::fmt;

use serde::{Deserialize, Serialize};

use crate::action::{
    AgentAction, AgentType, Environment, EnvironmentTier, ModelProvider, Operation, Runtime,
    SessionId, TraceId,
};

/* ------------------------------------------------------------------------ */
/* Typed identifiers                                                        */
/* ------------------------------------------------------------------------ */

macro_rules! identity_string_id {
    ($(#[$meta:meta])* $name:ident, $prefix:literal) => {
        $(#[$meta])*
        #[derive(
            Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize,
        )]
        #[serde(transparent)]
        pub struct $name(String);

        impl $name {
            pub fn new(value: impl Into<String>) -> Self {
                Self(value.into())
            }

            pub fn as_str(&self) -> &str {
                &self.0
            }

            pub fn is_blank(&self) -> bool {
                self.0.trim().is_empty()
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str(&self.0)
            }
        }
    };
}

identity_string_id!(
    /// Durable identifier of a registered agent definition.
    ///
    /// Stable across runs — "the deployment agent", not "this invocation of it".
    AgentId,
    "agt"
);
identity_string_id!(
    /// Identifier of one running instance of an agent.
    ///
    /// Changes when the process restarts or a new cloud run is allocated.
    AgentInstanceId,
    "inst"
);
identity_string_id!(
    /// Workspace or project scope the agent operates in.
    WorkspaceId,
    "wsp"
);
identity_string_id!(
    /// Device or host installation the local proxy represents.
    DeviceId,
    "dev"
);

/// Sentinel returned by [`AgentIdentity::effective_agent_id`] when no agent was registered.
pub const LOCAL_ANONYMOUS_AGENT_ID: &str = "local/anonymous";

/* ------------------------------------------------------------------------ */
/* Identity trust — LABEL != VERIFIED IDENTITY                              */
/* ------------------------------------------------------------------------ */

/// How strongly Sqreen trusts an identity claim.
///
/// Self-asserted values are useful for correlation and restrictive matching,
/// but must never grant additional privilege.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IdentityTrust {
    /// Validated through a Sqreen security credential (e.g. enrolled device).
    Authenticated,
    /// Bound to an authenticated principal via explicit registration (agent↔device).
    Bound,
    /// Derived by Sqreen from trusted runtime context (not independently authenticated).
    Derived,
    /// Supplied by agent/runtime/request/environment without cryptographic proof.
    #[default]
    SelfAsserted,
}

impl IdentityTrust {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Authenticated => "authenticated",
            Self::Bound => "bound",
            Self::Derived => "derived",
            Self::SelfAsserted => "self_asserted",
        }
    }

    /// Returns true when this trust level may grant privilege-sensitive identity matches.
    pub fn can_grant_privilege(self) -> bool {
        matches!(self, Self::Authenticated | Self::Bound)
    }

    pub fn parse(raw: &str) -> Option<Self> {
        match raw.trim().to_ascii_lowercase().as_str() {
            "authenticated" => Some(Self::Authenticated),
            "bound" => Some(Self::Bound),
            "derived" => Some(Self::Derived),
            "self_asserted" | "self-asserted" | "selfasserted" => Some(Self::SelfAsserted),
            _ => None,
        }
    }
}

/// A typed identity claim with explicit trust and provenance.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IdentityClaim {
    /// Claimed value (label or registered id).
    pub value: String,
    pub trust: IdentityTrust,
    /// Provenance (e.g. `env:SQREEN_AGENT_ID`, `adapter:openai`, `binding:device`).
    pub source: String,
}

impl IdentityClaim {
    pub fn self_asserted(value: impl Into<String>, source: impl Into<String>) -> Self {
        Self {
            value: value.into(),
            trust: IdentityTrust::SelfAsserted,
            source: source.into(),
        }
    }

    pub fn derived(value: impl Into<String>, source: impl Into<String>) -> Self {
        Self {
            value: value.into(),
            trust: IdentityTrust::Derived,
            source: source.into(),
        }
    }

    pub fn bound(value: impl Into<String>, source: impl Into<String>) -> Self {
        Self {
            value: value.into(),
            trust: IdentityTrust::Bound,
            source: source.into(),
        }
    }

    pub fn authenticated(value: impl Into<String>, source: impl Into<String>) -> Self {
        Self {
            value: value.into(),
            trust: IdentityTrust::Authenticated,
            source: source.into(),
        }
    }
}

/// Canonical execution attribution for one agent action.
///
/// Organization/device are authoritative when authenticated via device enrollment.
/// Agent/user/session claims carry explicit trust — adapters cannot silently upgrade trust.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExecutionPrincipal {
    pub organization_id: Option<String>,
    pub organization_trust: IdentityTrust,
    pub device_id: Option<String>,
    pub device_trust: IdentityTrust,
    pub agent: Option<IdentityClaim>,
    /// Registered agent id when [`IdentityTrust::Bound`].
    pub agent_bound_id: Option<String>,
    pub user: Option<IdentityClaim>,
    pub session: Option<IdentityClaim>,
    pub runtime: String,
    pub provider: Option<String>,
    pub adapter: Option<String>,
}


/* ------------------------------------------------------------------------ */
/* Auth context — extension point for future IdPs                         */
/* ------------------------------------------------------------------------ */

/// How the acting principal was authenticated.
///
/// Designed so future resolvers can populate `subject`, `issuer`, and `claims` from Okta,
/// Entra ID, GitHub tokens, Kubernetes service-account JWTs, or cloud workload identity
/// without changing the shape downstream engines consume.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum AuthContext {
    /// No authentication material — typical for a local workstation proxy.
    #[default]
    Anonymous,
    /// Process-local identity only (env vars, OS user). Not federated.
    Local {
        /// Optional local principal name (e.g. `$USER`).
        principal: Option<String>,
    },
    /// Federated identity from an external provider (reserved for future integrations).
    Federated {
        /// Provider slug (`okta`, `entra`, `github`, `k8s`, …).
        provider: String,
        /// Stable subject within the provider.
        subject: String,
        /// Issuer URL or tenant identifier, when applicable.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        issuer: Option<String>,
        /// Normalized claim bag for policy predicates (`groups`, `roles`, …).
        #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
        claims: BTreeMap<String, String>,
    },
}

impl AuthContext {
    /// Returns an anonymous context — the default for an unconfigured deployment.
    pub fn anonymous() -> Self {
        Self::Anonymous
    }

    /// Returns a local-only context bound to an OS principal.
    pub fn local(principal: impl Into<String>) -> Self {
        Self::Local {
            principal: Some(principal.into()),
        }
    }

    /// Returns `true` when no federated authentication was established.
    pub fn is_anonymous(&self) -> bool {
        matches!(self, Self::Anonymous)
    }
}

/* ------------------------------------------------------------------------ */
/* Model execution — explicitly NOT agent identity                          */
/* ------------------------------------------------------------------------ */

/// The model inference call that produced an action.
///
/// Kept separate from [`AgentIdentity`] so a policy cannot conflate "Claude Sonnet ran"
/// with "the deployment agent ran". Model fields may still be matched by identity rules
/// when operators want vendor-specific guardrails, but they live in their own struct.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ModelExecution {
    /// Model vendor, when known.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub provider: Option<ModelProvider>,
    /// Model name or slug, when known.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
}

impl ModelExecution {
    pub fn new(provider: Option<ModelProvider>, name: Option<String>) -> Self {
        Self { provider, name }
    }
}

/* ------------------------------------------------------------------------ */
/* Execution context — this run / session                                   */
/* ------------------------------------------------------------------------ */

/// Ephemeral binding for one agent execution.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExecutionContext {
    /// Running instance of the agent, when distinguishable from [`AgentIdentity::agent_id`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub agent_instance_id: Option<AgentInstanceId>,
    /// Session grouping (IDE window, CLI run, chat thread).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session_id: Option<SessionId>,
    /// Cross-integration task correlation identifier.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub trace_id: Option<TraceId>,
    /// Integration that observed the action.
    #[serde(default)]
    pub runtime: Runtime,
}

/* ------------------------------------------------------------------------ */
/* Agent identity — durable + deployment                                    */
/* ------------------------------------------------------------------------ */

/// Who the agent is, who it acts for, and where it runs.
///
/// # Trust semantics
///
/// `agent_id` from env/adapters is a **label** ([`IdentityTrust::SelfAsserted`]) unless
/// resolved to a device-bound registered agent ([`IdentityTrust::Bound`]).
/// Edge resolvers and adapters must never set Authenticated/Bound trust directly —
/// Bound is established via control-plane registration + device binding.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AgentIdentity {
    /// Durable agent registration identifier or self-asserted label.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub agent_id: Option<AgentId>,
    /// Trust level for `agent_id` (default SelfAsserted).
    #[serde(default)]
    pub agent_trust: IdentityTrust,
    /// Provenance for the agent claim (`env:SQREEN_AGENT_ID`, `adapter:…`, `binding:device`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub agent_identity_source: Option<String>,
    /// Registered agent id when `agent_trust` is Bound (provider-neutral).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub agent_bound_id: Option<AgentId>,
    /// Kind of software driving the action.
    #[serde(default)]
    pub agent_type: AgentType,

    /// Execution user claim (NOT Cloud SOC OIDC human identity).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub user_id: Option<String>,
    #[serde(default)]
    pub user_trust: IdentityTrust,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub user_identity_source: Option<String>,
    /// Human or service that delegated authority to this agent, when known.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub delegated_by: Option<String>,
    /// Owning organization claim (authoritative only when device-authenticated).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub organization_id: Option<String>,
    #[serde(default)]
    pub organization_trust: IdentityTrust,

    /// Workspace or project scope.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub workspace_id: Option<WorkspaceId>,
    /// Device or installation identifier.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub device_id: Option<DeviceId>,
    #[serde(default)]
    pub device_trust: IdentityTrust,

    /// Machine and deployment tier.
    #[serde(default)]
    pub environment: Environment,

    /// Authentication material for the acting principal.
    #[serde(default)]
    pub auth: AuthContext,

    /// Operator-defined labels for policy targeting (`team=engineering`, …).
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub labels: BTreeMap<String, String>,
}

impl Default for AgentIdentity {
    fn default() -> Self {
        Self {
            agent_id: None,
            agent_trust: IdentityTrust::SelfAsserted,
            agent_identity_source: None,
            agent_bound_id: None,
            agent_type: AgentType::UNKNOWN,
            user_id: None,
            user_trust: IdentityTrust::SelfAsserted,
            user_identity_source: None,
            delegated_by: None,
            organization_id: None,
            organization_trust: IdentityTrust::SelfAsserted,
            workspace_id: None,
            device_id: None,
            device_trust: IdentityTrust::SelfAsserted,
            environment: Environment::default(),
            auth: AuthContext::anonymous(),
            labels: BTreeMap::new(),
        }
    }
}

impl AgentIdentity {
    /// Builds an anonymous local identity — the default when nothing else is configured.
    pub fn anonymous_local() -> Self {
        Self {
            auth: AuthContext::anonymous(),
            ..Self::default()
        }
    }

    /// Returns the agent id to record in audit trails, never blank.
    pub fn effective_agent_id(&self) -> &str {
        self.agent_id
            .as_ref()
            .map(AgentId::as_str)
            .filter(|id| !id.trim().is_empty())
            .unwrap_or(LOCAL_ANONYMOUS_AGENT_ID)
    }

    /// Returns `true` when no durable agent id was supplied.
    pub fn is_anonymous(&self) -> bool {
        self.agent_id.is_none()
    }

    /// Marks the agent claim as a self-asserted label from `source`.
    ///
    /// Adapters and env resolvers must use this — they cannot upgrade to Bound/Authenticated.
    pub fn set_self_asserted_agent(
        &mut self,
        agent_id: impl Into<String>,
        source: impl Into<String>,
    ) {
        if self.agent_id.is_none() {
            self.agent_id = Some(AgentId::new(agent_id));
            self.agent_trust = IdentityTrust::SelfAsserted;
            self.agent_identity_source = Some(source.into());
            // Never inherit Bound from ambient fill.
            self.agent_bound_id = None;
        }
    }

    /// Applies a Bound agent identity resolved against an authenticated device binding.
    ///
    /// Only control-plane / local binding resolution should call this.
    pub fn set_bound_agent(
        &mut self,
        registered_id: impl Into<String>,
        label: Option<String>,
        source: impl Into<String>,
    ) {
        let registered_id = registered_id.into();
        self.agent_bound_id = Some(AgentId::new(registered_id.clone()));
        self.agent_id = Some(AgentId::new(
            label.filter(|v| !v.trim().is_empty())
                .unwrap_or(registered_id),
        ));
        self.agent_trust = IdentityTrust::Bound;
        self.agent_identity_source = Some(source.into());
    }

    /// Builds the canonical execution principal view for telemetry / SOC.
    pub fn execution_principal(
        &self,
        session: Option<&SessionId>,
        runtime: &Runtime,
        model: &ModelExecution,
        adapter: Option<&str>,
    ) -> ExecutionPrincipal {
        let agent = self.agent_id.as_ref().map(|id| IdentityClaim {
            value: id.as_str().to_string(),
            trust: self.agent_trust,
            source: self
                .agent_identity_source
                .clone()
                .unwrap_or_else(|| "unknown".to_string()),
        });
        let user = self.user_id.as_ref().map(|id| IdentityClaim {
            value: id.clone(),
            trust: self.user_trust,
            source: self
                .user_identity_source
                .clone()
                .unwrap_or_else(|| "unknown".to_string()),
        });
        let session = session.map(|id| IdentityClaim {
            value: id.as_str().to_string(),
            // Execution session != Cloud OIDC session.
            trust: IdentityTrust::SelfAsserted,
            source: "execution_session".to_string(),
        });
        ExecutionPrincipal {
            organization_id: self.organization_id.clone(),
            organization_trust: self.organization_trust,
            device_id: self.device_id.as_ref().map(|d| d.as_str().to_string()),
            device_trust: self.device_trust,
            agent,
            agent_bound_id: self
                .agent_bound_id
                .as_ref()
                .map(|id| id.as_str().to_string()),
            user,
            session,
            runtime: runtime.as_str().to_string(),
            provider: model.provider.as_ref().map(|p| p.as_str().to_string()),
            adapter: adapter.map(str::to_string),
        }
    }


    /// Sets a label, returning `self` for chaining in tests and resolvers.
    pub fn with_label(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.labels.insert(key.into(), value.into());
        self
    }

    /// Merges `other` into `self`, keeping values already set in `self`.
    pub fn merge_from(&mut self, other: &Self) {
        if self.agent_id.is_none() {
            self.agent_id = other.agent_id.clone();
            // Ambient fill can only contribute SelfAsserted/Derived — never upgrade trust.
            if !other.agent_trust.can_grant_privilege() {
                self.agent_trust = other.agent_trust;
                self.agent_identity_source = other.agent_identity_source.clone();
            } else {
                self.agent_trust = IdentityTrust::SelfAsserted;
                self.agent_identity_source = Some(
                    other
                        .agent_identity_source
                        .clone()
                        .unwrap_or_else(|| "downgraded_from_privileged_claim".to_string()),
                );
            }
            self.agent_bound_id = None;
        }
        if self.agent_type == AgentType::UNKNOWN {
            self.agent_type = other.agent_type.clone();
        }
        if self.user_id.is_none() {
            self.user_id = other.user_id.clone();
            if !other.user_trust.can_grant_privilege() {
                self.user_trust = other.user_trust;
                self.user_identity_source = other.user_identity_source.clone();
            } else {
                self.user_trust = IdentityTrust::SelfAsserted;
                self.user_identity_source = Some("downgraded_execution_user_claim".to_string());
            }
        }
        if self.delegated_by.is_none() {
            self.delegated_by = other.delegated_by.clone();
        }
        if self.organization_id.is_none() {
            self.organization_id = other.organization_id.clone();
            // Edge org from env is SelfAsserted until device auth proves otherwise.
            self.organization_trust = IdentityTrust::SelfAsserted;
        }
        if self.workspace_id.is_none() {
            self.workspace_id = other.workspace_id.clone();
        }
        if self.device_id.is_none() {
            self.device_id = other.device_id.clone();
            self.device_trust = IdentityTrust::SelfAsserted;
        }
        if self.environment.hostname.is_none() {
            self.environment.hostname = other.environment.hostname.clone();
        }
        if self.environment.os.is_none() {
            self.environment.os = other.environment.os.clone();
        }
        if self.environment.workspace.is_none() {
            self.environment.workspace = other.environment.workspace.clone();
        }
        if self.environment.tier == EnvironmentTier::Unknown {
            self.environment.tier = other.environment.tier;
        }
        if self.auth.is_anonymous() {
            self.auth = other.auth.clone();
        }
        for (key, value) in &other.labels {
            self.labels
                .entry(key.clone())
                .or_insert_with(|| value.clone());
        }
    }
}

/* ------------------------------------------------------------------------ */
/* Policy matching surface                                                  */
/* ------------------------------------------------------------------------ */

/// Flattened identity view used by declarative policy predicates.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IdentityMatchContext<'a> {
    pub agent_id: Option<&'a str>,
    pub agent_trust: IdentityTrust,
    pub agent_bound_id: Option<&'a str>,
    pub agent_instance_id: Option<&'a str>,
    pub agent_type: &'a AgentType,
    pub runtime: &'a Runtime,
    pub model_provider: Option<&'a ModelProvider>,
    pub model_name: Option<&'a str>,
    pub organization_id: Option<&'a str>,
    pub workspace_id: Option<&'a str>,
    pub device_id: Option<&'a str>,
    pub user_id: Option<&'a str>,
    pub user_trust: IdentityTrust,
    pub delegated_by: Option<&'a str>,
    pub session_id: Option<&'a str>,
    pub environment_tier: EnvironmentTier,
    pub operation: Operation,
    pub labels: &'a BTreeMap<String, String>,
}

impl<'a> IdentityMatchContext<'a> {
    /// Builds the match surface from an action after identity enrichment.
    pub fn from_action(action: &'a AgentAction) -> Self {
        Self {
            agent_id: action
                .identity
                .agent_id
                .as_ref()
                .map(AgentId::as_str)
                .or_else(|| {
                    if action.identity.is_anonymous() {
                        Some(LOCAL_ANONYMOUS_AGENT_ID)
                    } else {
                        None
                    }
                }),
            agent_trust: action.identity.agent_trust,
            agent_bound_id: action
                .identity
                .agent_bound_id
                .as_ref()
                .map(AgentId::as_str),
            agent_instance_id: action
                .execution
                .agent_instance_id
                .as_ref()
                .map(AgentInstanceId::as_str),
            agent_type: &action.identity.agent_type,
            runtime: &action.execution.runtime,
            model_provider: action.model.provider.as_ref(),
            model_name: action.model.name.as_deref(),
            organization_id: action.identity.organization_id.as_deref(),
            workspace_id: action
                .identity
                .workspace_id
                .as_ref()
                .map(WorkspaceId::as_str),
            device_id: action.identity.device_id.as_ref().map(DeviceId::as_str),
            user_id: action.identity.user_id.as_deref(),
            user_trust: action.identity.user_trust,
            delegated_by: action.identity.delegated_by.as_deref(),
            session_id: action.execution.session_id.as_ref().map(SessionId::as_str),
            environment_tier: action.identity.environment.tier,
            operation: action.operation,
            labels: &action.identity.labels,
        }
    }

    /// Returns the string value of field `name` for policy matching.
    ///
    /// Supports dotted label keys (`labels.team`) and `environment` as an alias for tier.
    pub fn field(&self, name: &str) -> Option<String> {
        let key = name.trim();
        if key.is_empty() {
            return None;
        }

        if let Some(label_key) = key.strip_prefix("labels.") {
            return self.labels.get(label_key).cloned();
        }

        match key {
            // Legacy agent_id == agent.label (self-asserted unless Bound).
            "agent_id" | "agent.label" => self.agent_id.map(str::to_string),
            "agent.trust" | "agent_trust" => Some(self.agent_trust.as_str().to_string()),
            "agent.bound_id" | "agent.id" | "agent_bound_id" => {
                self.agent_bound_id.map(str::to_string)
            }
            "agent_instance_id" => self.agent_instance_id.map(str::to_string),
            "agent_type" => Some(self.agent_type.as_str().to_string()),
            "runtime" => Some(self.runtime.as_str().to_string()),
            "model_provider" => self
                .model_provider
                .map(|provider| provider.as_str().to_string()),
            "model_name" => self.model_name.map(str::to_string),
            "organization_id" => self.organization_id.map(str::to_string),
            "workspace_id" => self.workspace_id.map(str::to_string),
            "device_id" => self.device_id.map(str::to_string),
            "user_id" | "user.label" => self.user_id.map(str::to_string),
            "user.trust" | "user_trust" => Some(self.user_trust.as_str().to_string()),
            "delegated_by" => self.delegated_by.map(str::to_string),
            "session_id" | "session.label" => self.session_id.map(str::to_string),
            "environment" | "environment.tier" => {
                Some(environment_tier_slug(self.environment_tier))
            }
            "operation" => Some(operation_slug(self.operation)),
            _ => None,
        }
    }
}

fn environment_tier_slug(tier: EnvironmentTier) -> String {
    match tier {
        EnvironmentTier::Development => "development".to_string(),
        EnvironmentTier::Staging => "staging".to_string(),
        EnvironmentTier::Production => "production".to_string(),
        EnvironmentTier::Unknown => "unknown".to_string(),
    }
}

fn operation_slug(operation: Operation) -> String {
    match operation {
        Operation::Read => "read".to_string(),
        Operation::Write => "write".to_string(),
        Operation::Execute => "execute".to_string(),
        Operation::Delete => "delete".to_string(),
        Operation::List => "list".to_string(),
        Operation::Search => "search".to_string(),
        Operation::Connect => "connect".to_string(),
        Operation::Query => "query".to_string(),
        Operation::Navigate => "navigate".to_string(),
        Operation::Invoke => "invoke".to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::action::{ActionId, Arguments, SourceRef};

    fn sample_action() -> AgentAction {
        AgentAction::builder(
            "delete_file",
            Arguments::from_name_and_arguments(
                "delete_file",
                &serde_json::json!({"path": "/tmp/a"}),
            ),
        )
        .source(SourceRef::new(Runtime::MCP_STDIO, "test"))
        .operation(Operation::Delete)
        .build_unvalidated()
    }

    #[test]
    fn effective_agent_id_falls_back_for_anonymous_agents() {
        let identity = AgentIdentity::anonymous_local();
        assert_eq!(identity.effective_agent_id(), LOCAL_ANONYMOUS_AGENT_ID);
        assert!(identity.is_anonymous());
    }

    #[test]
    fn merge_from_is_fill_only_if_absent() {
        let mut left = AgentIdentity {
            agent_id: Some(AgentId::new("wire-agent")),
            user_id: Some("wire-user".to_string()),
            ..AgentIdentity::default()
        };
        let right = AgentIdentity {
            agent_id: Some(AgentId::new("ambient-agent")),
            user_id: Some("ambient-user".to_string()),
            organization_id: Some("ambient-org".to_string()),
            ..AgentIdentity::default()
        };

        left.merge_from(&right);

        assert_eq!(left.agent_id.unwrap().as_str(), "wire-agent");
        assert_eq!(left.user_id.as_deref(), Some("wire-user"));
        assert_eq!(left.organization_id.as_deref(), Some("ambient-org"));
    }

    #[test]
    fn match_context_exposes_labels_and_operation() {
        let mut action = sample_action();
        action.identity.agent_type = AgentType::custom("coding-agent");
        action.identity.environment.tier = EnvironmentTier::Production;
        action
            .identity
            .labels
            .insert("team".to_string(), "engineering".to_string());

        let ctx = IdentityMatchContext::from_action(&action);

        assert_eq!(ctx.field("agent_type"), Some("coding-agent".to_string()));
        assert_eq!(ctx.field("environment"), Some("production".to_string()));
        assert_eq!(ctx.field("operation"), Some("delete".to_string()));
        assert_eq!(ctx.field("labels.team"), Some("engineering".to_string()));
    }

    #[test]
    fn model_fields_are_exposed_but_live_outside_agent_identity() {
        let mut action = sample_action();
        action.model = ModelExecution::new(
            Some(ModelProvider::ANTHROPIC),
            Some("claude-sonnet".to_string()),
        );

        let ctx = IdentityMatchContext::from_action(&action);
        assert_eq!(ctx.field("model_name"), Some("claude-sonnet".to_string()));
        assert!(action.identity.agent_id.is_none());
    }
}
