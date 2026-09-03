//! Provider-independent model of a single agent action.
//!
//! # Why this exists
//!
//! Before this module the internal contract was [`crate::guard::ToolInvocation`], whose
//! `params_json` field is documented as "MCP `tools/call` params shape". Every non-MCP
//! integration had to synthesize an MCP envelope on the way in and take it apart on the
//! way out, so the security engine could not be reasoned about independently of MCP.
//!
//! [`AgentAction`] replaces that contract with a description of *what an agent is
//! attempting*, independent of how the attempt was observed. Provider translation happens
//! in [`crate::adapters`]; everything downstream of an adapter sees only this type.
//!
//! # Optionality
//!
//! Most descriptive fields are optional on purpose. A Cursor `beforeShellExecution` hook
//! knows the command but not the model that produced it; an OpenAI `tool_calls` entry
//! knows the model but not the operating system user. Adapters fill what their wire format
//! actually carries and leave the rest `None` rather than inventing values.
//!
//! # Byte-exact payload preservation
//!
//! [`Arguments::canonical_params_json`] is the single most behavior-sensitive field. The
//! policy engine, the Wasm sandbox, the IOC matcher, the behavioral tracker, and the DLP
//! scanner all operate on those exact bytes today. Adapters must produce a payload that is
//! byte-identical to what the corresponding pre-existing code path produced, and the
//! normalization tests assert this.
//!
//! # Classification
//!
//! [`crate::classify`] derives provider-oriented capability metadata on each action.
//! [`crate::taxonomy`] maps those structural facts into normalized security semantics on
//! [`AgentAction::security`], which policy evaluates before payload rules.

use std::borrow::Cow;
use std::collections::BTreeMap;
use std::fmt;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;

/// Maximum accepted length of a tool name.
pub const MAX_TOOL_NAME_LEN: usize = 256;

/// Maximum accepted size of a canonical argument payload.
///
/// Matches [`crate::wasm_engine`]'s guest I/O ceiling so an action that validates here
/// cannot be rejected later by the sandbox for size alone.
pub const MAX_PAYLOAD_BYTES: usize = 1 << 20;

/* ------------------------------------------------------------------------ */
/* Identifiers                                                              */
/* ------------------------------------------------------------------------ */

/// Generates a process-unique, sortable identifier without pulling in a UUID dependency.
fn generate_id(prefix: &str) -> String {
    static COUNTER: AtomicU64 = AtomicU64::new(0);

    let sequence = COUNTER.fetch_add(1, Ordering::Relaxed);
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|elapsed| elapsed.as_nanos())
        .unwrap_or(0);

    format!("{prefix}_{nanos:x}{sequence:04x}")
}

macro_rules! string_id {
    ($(#[$meta:meta])* $name:ident, $prefix:literal) => {
        $(#[$meta])*
        #[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
        #[serde(transparent)]
        pub struct $name(String);

        impl $name {
            /// Wraps an externally supplied identifier.
            pub fn new(value: impl Into<String>) -> Self {
                Self(value.into())
            }

            /// Mints a fresh identifier.
            pub fn generate() -> Self {
                Self(generate_id($prefix))
            }

            /// Returns the identifier as a string slice.
            pub fn as_str(&self) -> &str {
                &self.0
            }

            /// Returns `true` when the identifier is empty or whitespace-only.
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

string_id!(
    /// Unique identity of one attempted action.
    ActionId,
    "act"
);
string_id!(
    /// Groups actions belonging to one agent session (an IDE window, a CLI run, a chat).
    SessionId,
    "ses"
);
string_id!(
    /// Correlates actions across integrations that participate in the same agent task.
    TraceId,
    "trc"
);

/* ------------------------------------------------------------------------ */
/* Open string enums                                                        */
/* ------------------------------------------------------------------------ */

/// Declares an open enum: a set of well-known constants plus an escape hatch, serialized
/// as a plain string so new values never break a stored record.
macro_rules! open_enum {
    (
        $(#[$meta:meta])*
        $name:ident {
            $( $(#[$vmeta:meta])* $konst:ident => $value:literal ),* $(,)?
        }
    ) => {
        $(#[$meta])*
        #[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
        #[serde(transparent)]
        pub struct $name(Cow<'static, str>);

        impl $name {
            $(
                $(#[$vmeta])*
                pub const $konst: Self = $name(Cow::Borrowed($value));
            )*

            /// Wraps a value outside the well-known set.
            pub fn custom(value: impl Into<String>) -> Self {
                $name(Cow::Owned(value.into()))
            }

            /// Returns the wire representation.
            pub fn as_str(&self) -> &str {
                &self.0
            }

            /// Returns `true` when this is one of the well-known constants.
            pub fn is_known(&self) -> bool {
                matches!(self.as_str(), $( $value )|*)
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str(&self.0)
            }
        }
    };
}

open_enum!(
    /// Where the action was observed — the integration that produced it.
    ///
    /// Distinct from [`ToolType`]: a shell command observed through a Cursor hook has
    /// runtime `cursor_hook` and tool type `shell`. Conflating the two is what made the
    /// pre-existing code treat "arrived over MCP" and "touches the filesystem" as the
    /// same question.
    Runtime {
        /// MCP server proxied over stdio.
        MCP_STDIO => "mcp_stdio",
        /// MCP server reached over Streamable HTTP.
        MCP_HTTP => "mcp_http",
        /// OpenAI-compatible chat completions endpoint.
        OPENAI_HTTP => "openai_http",
        /// Anthropic Messages endpoint.
        ANTHROPIC_HTTP => "anthropic_http",
        /// Cursor IDE hook.
        CURSOR_HOOK => "cursor_hook",
        /// Claude Code hook.
        CLAUDE_CODE_HOOK => "claude_code_hook",
        /// Direct shell interception.
        SHELL => "shell",
        /// Browser automation driver.
        BROWSER => "browser",
        /// Database driver or gateway.
        DATABASE => "database",
        /// Outbound HTTP client interception.
        HTTP_CLIENT => "http_client",
        /// Filesystem interception.
        FILESYSTEM => "filesystem",
        /// Runtime not identified.
        UNKNOWN => "unknown",
    }
);

open_enum!(
    /// The kind of software driving the action.
    AgentType {
        /// Editor-embedded assistant.
        IDE_ASSISTANT => "ide_assistant",
        /// Terminal agent such as Claude Code.
        CLI_AGENT => "cli_agent",
        /// Conversational assistant.
        CHAT_ASSISTANT => "chat_assistant",
        /// Long-running autonomous agent.
        AUTONOMOUS_AGENT => "autonomous_agent",
        /// Agent running inside CI.
        CI_AGENT => "ci_agent",
        /// Code-editing agent (Cursor, Copilot, etc.).
        CODING_AGENT => "coding-agent",
        /// Agent kind not identified.
        UNKNOWN => "unknown",
    }
);

impl Default for Runtime {
    fn default() -> Self {
        Self::UNKNOWN
    }
}

impl Default for AgentType {
    fn default() -> Self {
        Self::UNKNOWN
    }
}

open_enum!(
    /// Vendor of the model that produced the action, when known.
    ModelProvider {
        /// OpenAI.
        OPENAI => "openai",
        /// Anthropic.
        ANTHROPIC => "anthropic",
        /// Google.
        GOOGLE => "google",
        /// Azure OpenAI.
        AZURE_OPENAI => "azure_openai",
        /// AWS Bedrock.
        BEDROCK => "bedrock",
        /// Locally hosted model.
        LOCAL => "local",
    }
);

open_enum!(
    /// The capability class a tool belongs to.
    ToolType {
        /// Reads or writes local files and directories.
        FILESYSTEM => "filesystem",
        /// Executes commands through a shell or process spawn.
        SHELL => "shell",
        /// Performs outbound network requests.
        NETWORK => "network",
        /// Issues database queries or migrations.
        DATABASE => "database",
        /// Drives a browser.
        BROWSER => "browser",
        /// Searches an index or the web.
        SEARCH => "search",
        /// Operates on a version control system.
        VERSION_CONTROL => "version_control",
        /// Sends messages to people or channels.
        MESSAGING => "messaging",
        /// Edits code in place.
        CODE_EDIT => "code_edit",
        /// Reads or writes agent memory.
        MEMORY => "memory",
        /// Capability class not identified.
        UNKNOWN => "unknown",
    }
);

impl Default for ToolType {
    fn default() -> Self {
        Self::UNKNOWN
    }
}

/* ------------------------------------------------------------------------ */
/* Closed enums                                                             */
/* ------------------------------------------------------------------------ */

/// The verb an action performs against its target.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Operation {
    /// Retrieves content without modifying it.
    Read,
    /// Creates or modifies content.
    Write,
    /// Runs code or a command.
    Execute,
    /// Removes content.
    Delete,
    /// Enumerates a container without reading item contents.
    List,
    /// Matches content against a query.
    Search,
    /// Opens a connection to a remote endpoint.
    Connect,
    /// Issues a structured query.
    Query,
    /// Moves a browsing context.
    Navigate,
    /// Calls a tool whose verb could not be determined.
    Invoke,
}

/// How sensitive the data touched by an action is believed to be.
#[derive(
    Debug, Clone, Copy, Default, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize,
)]
#[serde(rename_all = "snake_case")]
pub enum Sensitivity {
    /// No signal either way.
    #[default]
    Unknown,
    /// Safe to disclose.
    Public,
    /// Ordinary business data.
    Internal,
    /// Disclosure would cause harm.
    Confidential,
    /// Disclosure would cause severe harm.
    Restricted,
}

/// A category of regulated or sensitive content observed in an action.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DataCategory {
    /// API keys, tokens, private keys.
    Secret,
    /// Personally identifiable information.
    Pii,
    /// Payment or account data.
    Financial,
    /// Source code.
    SourceCode,
    /// Infrastructure or deployment configuration.
    Infrastructure,
    /// Credentials belonging to a person.
    Credential,
}

/// The kind of credential an action references.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CredentialKind {
    /// Service API key.
    ApiKey,
    /// Bearer or session token.
    BearerToken,
    /// Asymmetric private key.
    PrivateKey,
    /// Password or passphrase.
    Password,
    /// Cloud provider access key.
    CloudAccessKey,
    /// Kind not identified.
    Unknown,
}

/// Deployment tier the action is running against.
#[derive(
    Debug, Clone, Copy, Default, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize,
)]
#[serde(rename_all = "snake_case")]
pub enum EnvironmentTier {
    /// Tier not identified.
    #[default]
    Unknown,
    /// Developer machine.
    Development,
    /// Pre-production.
    Staging,
    /// Production.
    Production,
}

/* ------------------------------------------------------------------------ */
/* Resources and destinations                                               */
/* ------------------------------------------------------------------------ */

/// The thing an action operates on.
///
/// This is the field that makes policy expressible as "no reads outside the workspace"
/// rather than "no serialized argument blob matching this regex".
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Resource {
    /// A single file.
    File {
        /// Path exactly as the agent supplied it, un-normalized.
        path: String,
    },
    /// A directory.
    Directory {
        /// Path exactly as the agent supplied it, un-normalized.
        path: String,
    },
    /// A command line.
    Command {
        /// First token of the command, when it could be isolated.
        program: Option<String>,
        /// Full command as supplied.
        raw: String,
    },
    /// An absolute or relative URL.
    Url {
        /// URL as supplied.
        url: String,
        /// Host component, when it could be isolated.
        host: Option<String>,
    },
    /// A network endpoint addressed without a URL.
    Host {
        /// Hostname or address.
        host: String,
        /// Port, when supplied.
        port: Option<u16>,
    },
    /// A database object or statement.
    Database {
        /// Engine, when known.
        system: Option<String>,
        /// Database or schema name, when supplied.
        database: Option<String>,
        /// Table name, when supplied.
        table: Option<String>,
        /// Statement text, when supplied.
        statement: Option<String>,
    },
    /// A browsing context or element within one.
    BrowserTarget {
        /// Target URL, when supplied.
        url: Option<String>,
        /// Element selector or reference, when supplied.
        selector: Option<String>,
    },
    /// A target that does not fit the categories above.
    Opaque {
        /// Human-readable descriptor.
        descriptor: String,
    },
}

/// Where data produced or carried by an action is going.
///
/// Populated only when an action moves data outward; a local file read has no destination.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Destination {
    /// A remote host.
    Host {
        /// Hostname or address.
        host: String,
        /// Port, when known.
        port: Option<u16>,
    },
    /// A full URL.
    Url {
        /// URL as supplied.
        url: String,
        /// Host component, when it could be isolated.
        host: Option<String>,
    },
    /// A local path being written.
    File {
        /// Path as supplied.
        path: String,
    },
    /// A spawned process receiving data on stdin.
    Process {
        /// Command as supplied.
        command: String,
    },
}

/* ------------------------------------------------------------------------ */
/* Supporting records                                                       */
/* ------------------------------------------------------------------------ */

/// What is known about the data an action touches.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct DataClassification {
    /// Overall sensitivity.
    pub sensitivity: Sensitivity,
    /// Categories observed, sorted and deduplicated.
    pub categories: Vec<DataCategory>,
}

impl DataClassification {
    /// Builds a classification from an unsorted category list.
    pub fn with_categories(
        sensitivity: Sensitivity,
        categories: impl IntoIterator<Item = DataCategory>,
    ) -> Self {
        let mut categories: Vec<DataCategory> = categories.into_iter().collect();
        categories.sort_unstable();
        categories.dedup();
        Self {
            sensitivity,
            categories,
        }
    }

    /// Returns `true` when no signal was recorded.
    pub fn is_unclassified(&self) -> bool {
        self.sensitivity == Sensitivity::Unknown && self.categories.is_empty()
    }
}

/// A reference to a credential an action involves.
///
/// Deliberately records only *where* a credential appears and what kind it is. Storing the
/// value would put live secrets into the audit path, which is the mistake the existing
/// telemetry record already makes with device tokens.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CredentialRef {
    /// Kind of credential.
    pub kind: CredentialKind,
    /// Identifier such as an environment variable or header name, when known.
    pub name: Option<String>,
    /// Where in the action the credential appears.
    pub location: CredentialLocation,
}

/// Where a referenced credential lives.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum CredentialLocation {
    /// Inside the action arguments, at a JSON pointer.
    Argument {
        /// RFC 6901 pointer into the arguments document.
        pointer: String,
    },
    /// In a request header.
    Header {
        /// Header name.
        name: String,
    },
    /// In the process environment.
    Environment {
        /// Variable name.
        variable: String,
    },
    /// Location not identified.
    Unknown,
}

/// The machine and workspace the action is running on.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Environment {
    /// Host name, when resolvable.
    pub hostname: Option<String>,
    /// Operating system family.
    pub os: Option<String>,
    /// Workspace or repository root.
    pub workspace: Option<String>,
    /// Deployment tier.
    pub tier: EnvironmentTier,
}

/* ------------------------------------------------------------------------ */
/* Arguments                                                                */
/* ------------------------------------------------------------------------ */

/// The argument payload of an action.
///
/// Holds two views of the same data:
///
/// - [`Arguments::canonical_params_json`] — the exact bytes the security engines consume.
///   For historical reasons this is an MCP-shaped `{"name": …, "arguments": …}` document,
///   because the policy engine, Wasm sandbox, IOC matcher, and DLP scanner were all written
///   against it. Adapters are responsible for producing it; nothing downstream constructs it.
/// - [`Arguments::value`] — the parsed `arguments` subtree, used by classification and by
///   future policy predicates that need structure rather than text.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(into = "String", try_from = "String")]
pub struct Arguments {
    canonical: String,
    parsed: Value,
}

impl Arguments {
    /// Wraps a verbatim MCP `tools/call` params document, returning the declared tool name.
    ///
    /// The input string is retained byte-for-byte so downstream regex and substring matching
    /// sees exactly what the wire carried, including key order and whitespace.
    pub fn from_canonical_params(
        params_json: &str,
    ) -> Result<(String, Self), ActionValidationError> {
        let root: Value = serde_json::from_str(params_json).map_err(|error| {
            ActionValidationError::MalformedArguments {
                detail: error.to_string(),
            }
        })?;

        let object = root
            .as_object()
            .ok_or(ActionValidationError::ArgumentsNotObject)?;

        let name = object
            .get("name")
            .and_then(Value::as_str)
            .ok_or(ActionValidationError::MissingToolName)?;

        if name.trim().is_empty() {
            return Err(ActionValidationError::EmptyToolName);
        }

        let parsed = object.get("arguments").cloned().unwrap_or(Value::Null);

        Ok((
            name.to_string(),
            Self {
                canonical: params_json.to_string(),
                parsed,
            },
        ))
    }

    /// Builds a canonical payload from a tool name and an argument value.
    ///
    /// Mirrors the pre-existing OpenAI normalization exactly: a `Value::String` argument is
    /// re-parsed as JSON when possible and left as a string when not, so providers that send
    /// arguments as an encoded string produce the same payload they did before.
    pub fn from_name_and_arguments(name: &str, arguments: &Value) -> Self {
        let parsed = match arguments {
            Value::String(raw) => serde_json::from_str(raw).unwrap_or(Value::String(raw.clone())),
            other => other.clone(),
        };

        let canonical = serde_json::json!({
            "name": name,
            "arguments": parsed,
        })
        .to_string();

        Self { canonical, parsed }
    }

    /// Builds a payload from parts without validating, for the legacy compatibility bridge.
    pub fn from_parts_unchecked(canonical: impl Into<String>, parsed: Value) -> Self {
        Self {
            canonical: canonical.into(),
            parsed,
        }
    }

    /// Returns the exact bytes the security engines consume.
    pub fn canonical_params_json(&self) -> &str {
        &self.canonical
    }

    /// Returns the parsed `arguments` subtree.
    pub fn value(&self) -> &Value {
        &self.parsed
    }

    /// Returns a string-valued argument by key, when the payload is an object.
    pub fn string_field(&self, key: &str) -> Option<&str> {
        self.parsed.get(key).and_then(Value::as_str)
    }

    /// Returns the first present string-valued argument among `keys`.
    pub fn first_string_field<'a>(
        &self,
        keys: impl IntoIterator<Item = &'a str>,
    ) -> Option<(&'a str, &str)> {
        keys.into_iter()
            .find_map(|key| self.string_field(key).map(|value| (key, value)))
    }

    /// Returns the payload size in bytes.
    pub fn byte_len(&self) -> usize {
        self.canonical.len()
    }
}

impl From<Arguments> for String {
    fn from(arguments: Arguments) -> Self {
        arguments.canonical
    }
}

impl TryFrom<String> for Arguments {
    type Error = ActionValidationError;

    fn try_from(canonical: String) -> Result<Self, Self::Error> {
        let (_, arguments) = Arguments::from_canonical_params(&canonical)?;
        Ok(arguments)
    }
}

/* ------------------------------------------------------------------------ */
/* Provenance                                                               */
/* ------------------------------------------------------------------------ */

/// Where an action came from and how it was named there.
///
/// Retained so a [`crate::guard::GuardDecision`] can be encoded back onto the originating
/// wire format without the core needing to know what that format is.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SourceRef {
    /// The integration that observed the action.
    pub runtime: Runtime,
    /// Stable identifier of the adapter that produced the action.
    pub adapter: String,
    /// Provider-native call identifier, when the wire format carries one.
    pub provider_call_id: Option<String>,
    /// Provider-native event name, when the wire format carries one.
    pub provider_event: Option<String>,
}

impl SourceRef {
    /// Builds a provenance record for `runtime` produced by `adapter`.
    pub fn new(runtime: Runtime, adapter: impl Into<String>) -> Self {
        Self {
            runtime,
            adapter: adapter.into(),
            provider_call_id: None,
            provider_event: None,
        }
    }

    /// Attaches the provider-native call identifier.
    pub fn with_call_id(mut self, call_id: Option<String>) -> Self {
        self.provider_call_id = call_id;
        self
    }

    /// Attaches the provider-native event name.
    pub fn with_event(mut self, event: Option<String>) -> Self {
        self.provider_event = event;
        self
    }
}

/* ------------------------------------------------------------------------ */
/* AgentAction                                                              */
/* ------------------------------------------------------------------------ */

/// A single action an agent is attempting, described independently of how it was observed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AgentAction {
    /// Unique identity of this attempt.
    pub action_id: ActionId,
    /// When the attempt was observed.
    pub timestamp: DateTime<Utc>,
    /// The action that caused this one, for nested or retried calls.
    pub parent_action_id: Option<ActionId>,

    /// Who the agent is and who it acts for.
    pub identity: crate::identity::AgentIdentity,
    /// Ephemeral binding for this run (instance, session, trace, runtime).
    pub execution: crate::identity::ExecutionContext,
    /// Model that produced the action — not agent identity.
    pub model: crate::identity::ModelExecution,

    /// Where the action was observed and what it was called there.
    pub source: SourceRef,

    /// Tool name exactly as the provider spelled it.
    pub tool_name: String,
    /// Capability class the tool belongs to.
    pub tool_type: ToolType,
    /// Verb the action performs.
    pub operation: Operation,
    /// Argument payload.
    pub arguments: Arguments,

    /// What the action operates on, when it could be identified.
    pub target_resource: Option<Resource>,
    /// Where the action sends data, when it sends any outward.
    pub destination: Option<Destination>,
    /// What is known about the sensitivity of the data involved.
    pub data_classification: DataClassification,
    /// Credentials referenced by the action. Never contains credential values.
    pub credentials: Vec<CredentialRef>,
    /// Normalized security semantics derived before policy evaluation.
    pub security: crate::taxonomy::SecurityClassification,
    /// Adapter-specific detail that does not fit a typed field.
    pub metadata: BTreeMap<String, String>,
}

impl AgentAction {
    /// Starts building an action for `tool_name` with `arguments`.
    pub fn builder(tool_name: impl Into<String>, arguments: Arguments) -> AgentActionBuilder {
        AgentActionBuilder::new(tool_name, arguments)
    }

    /// Returns the bytes the security engines consume.
    ///
    /// Every engine call site goes through this accessor so the payload contract has exactly
    /// one definition.
    pub fn canonical_params_json(&self) -> &str {
        self.arguments.canonical_params_json()
    }

    /// Returns the tool name.
    pub fn tool_name(&self) -> &str {
        &self.tool_name
    }

    /// Returns the runtime the action was observed on.
    pub fn runtime(&self) -> &Runtime {
        &self.execution.runtime
    }

    /// Returns the durable agent identifier, when registered.
    pub fn agent_id(&self) -> Option<&str> {
        self.identity
            .agent_id
            .as_ref()
            .map(crate::identity::AgentId::as_str)
    }

    /// Returns the agent kind.
    pub fn agent_type(&self) -> &AgentType {
        &self.identity.agent_type
    }

    /// Returns the session identifier.
    pub fn session_id(&self) -> Option<&SessionId> {
        self.execution.session_id.as_ref()
    }

    /// Returns the trace identifier.
    pub fn trace_id(&self) -> Option<&TraceId> {
        self.execution.trace_id.as_ref()
    }

    /// Returns the acting user.
    pub fn user_id(&self) -> Option<&str> {
        self.identity.user_id.as_deref()
    }

    /// Returns the owning organization.
    pub fn organization_id(&self) -> Option<&str> {
        self.identity.organization_id.as_deref()
    }

    /// Returns the model vendor.
    pub fn model_provider(&self) -> Option<&ModelProvider> {
        self.model.provider.as_ref()
    }

    /// Returns the model name.
    pub fn model_name(&self) -> Option<&str> {
        self.model.name.as_deref()
    }

    /// Returns the deployment environment.
    pub fn environment(&self) -> &Environment {
        &self.identity.environment
    }

    /// Checks structural invariants that every adapter output must satisfy.
    ///
    /// Adapters call this at the edge. The engines do not, because an action that reaches
    /// them has already been validated and re-validating would be a second place for the
    /// rules to drift.
    pub fn validate(&self) -> Result<(), ActionValidationError> {
        if self.action_id.is_blank() {
            return Err(ActionValidationError::BlankIdentifier { field: "action_id" });
        }

        if let Some(session) = &self.execution.session_id {
            if session.is_blank() {
                return Err(ActionValidationError::BlankIdentifier {
                    field: "session_id",
                });
            }
        }

        if let Some(trace) = &self.execution.trace_id {
            if trace.is_blank() {
                return Err(ActionValidationError::BlankIdentifier { field: "trace_id" });
            }
        }

        if let Some(parent) = &self.parent_action_id {
            if parent.is_blank() {
                return Err(ActionValidationError::BlankIdentifier {
                    field: "parent_action_id",
                });
            }
            if parent == &self.action_id {
                return Err(ActionValidationError::SelfParentedAction);
            }
        }

        if self.tool_name.trim().is_empty() {
            return Err(ActionValidationError::EmptyToolName);
        }

        if self.tool_name.len() > MAX_TOOL_NAME_LEN {
            return Err(ActionValidationError::ToolNameTooLong {
                len: self.tool_name.len(),
                max: MAX_TOOL_NAME_LEN,
            });
        }

        if self.source.adapter.trim().is_empty() {
            return Err(ActionValidationError::BlankIdentifier { field: "adapter" });
        }

        let payload_len = self.arguments.byte_len();
        if payload_len > MAX_PAYLOAD_BYTES {
            return Err(ActionValidationError::PayloadTooLarge {
                len: payload_len,
                max: MAX_PAYLOAD_BYTES,
            });
        }

        let (declared, _) = Arguments::from_canonical_params(self.canonical_params_json())?;
        if declared != self.tool_name {
            return Err(ActionValidationError::ToolNameMismatch {
                declared,
                action: self.tool_name.clone(),
            });
        }

        Ok(())
    }

    /// Recomputes [`Self::security`] from structural fields and deployment context.
    pub fn refresh_security_classification(&mut self) {
        self.security = crate::taxonomy::classify_action(self);
    }
}

/* ------------------------------------------------------------------------ */
/* Builder                                                                  */
/* ------------------------------------------------------------------------ */

/// Incremental constructor for [`AgentAction`].
#[derive(Debug, Clone)]
pub struct AgentActionBuilder {
    action: AgentAction,
}

impl AgentActionBuilder {
    /// Starts a builder with generated identity and unknown descriptive fields.
    pub fn new(tool_name: impl Into<String>, arguments: Arguments) -> Self {
        Self {
            action: AgentAction {
                action_id: ActionId::generate(),
                timestamp: Utc::now(),
                parent_action_id: None,
                identity: crate::identity::AgentIdentity::default(),
                execution: crate::identity::ExecutionContext::default(),
                model: crate::identity::ModelExecution::default(),
                source: SourceRef::new(Runtime::UNKNOWN, "unknown"),
                tool_name: tool_name.into(),
                tool_type: ToolType::UNKNOWN,
                operation: Operation::Invoke,
                arguments,
                target_resource: None,
                destination: None,
                data_classification: DataClassification::default(),
                credentials: Vec::new(),
                security: crate::taxonomy::SecurityClassification::default(),
                metadata: BTreeMap::new(),
            },
        }
    }

    /// Overrides the generated action identifier.
    pub fn action_id(mut self, action_id: ActionId) -> Self {
        self.action.action_id = action_id;
        self
    }

    /// Overrides the observation timestamp.
    pub fn timestamp(mut self, timestamp: DateTime<Utc>) -> Self {
        self.action.timestamp = timestamp;
        self
    }

    /// Sets the session identifier.
    pub fn session_id(mut self, session_id: Option<SessionId>) -> Self {
        self.action.execution.session_id = session_id;
        self
    }

    /// Sets the trace identifier.
    pub fn trace_id(mut self, trace_id: Option<TraceId>) -> Self {
        self.action.execution.trace_id = trace_id;
        self
    }

    /// Sets the causing action.
    pub fn parent_action_id(mut self, parent: Option<ActionId>) -> Self {
        self.action.parent_action_id = parent;
        self
    }

    /// Sets the agent identifier.
    pub fn agent_id(mut self, agent_id: Option<impl Into<String>>) -> Self {
        if let Some(id) = agent_id {
            let id = id.into();
            if !id.trim().is_empty() {
                self.action
                    .identity
                    .set_self_asserted_agent(id, "builder:agent_id");
            }
        }
        self
    }

    /// Sets the agent instance identifier.
    pub fn agent_instance_id(mut self, agent_instance_id: Option<impl Into<String>>) -> Self {
        self.action.execution.agent_instance_id =
            agent_instance_id.map(crate::identity::AgentInstanceId::new);
        self
    }

    /// Sets the agent kind.
    pub fn agent_type(mut self, agent_type: AgentType) -> Self {
        self.action.identity.agent_type = agent_type;
        self
    }

    /// Sets the model vendor.
    pub fn model_provider(mut self, provider: Option<ModelProvider>) -> Self {
        self.action.model.provider = provider;
        self
    }

    /// Sets the model name.
    pub fn model_name(mut self, model_name: Option<String>) -> Self {
        self.action.model.name = model_name;
        self
    }

    /// Sets the acting user.
    pub fn user_id(mut self, user_id: Option<String>) -> Self {
        self.action.identity.user_id = user_id;
        self
    }

    /// Sets the delegating principal.
    pub fn delegated_by(mut self, delegated_by: Option<String>) -> Self {
        self.action.identity.delegated_by = delegated_by;
        self
    }

    /// Sets the owning organization.
    pub fn organization_id(mut self, organization_id: Option<String>) -> Self {
        self.action.identity.organization_id = organization_id;
        self
    }

    /// Sets the workspace identifier.
    pub fn workspace_id(mut self, workspace_id: Option<impl Into<String>>) -> Self {
        self.action.identity.workspace_id = workspace_id.map(crate::identity::WorkspaceId::new);
        self
    }

    /// Sets the device identifier.
    pub fn device_id(mut self, device_id: Option<impl Into<String>>) -> Self {
        self.action.identity.device_id = device_id.map(crate::identity::DeviceId::new);
        self
    }

    /// Sets the runtime that observed the action.
    pub fn runtime(mut self, runtime: Runtime) -> Self {
        self.action.execution.runtime = runtime;
        self
    }

    /// Sets the authentication context.
    pub fn auth_context(mut self, auth: crate::identity::AuthContext) -> Self {
        self.action.identity.auth = auth;
        self
    }

    /// Adds an operator label for policy targeting.
    pub fn label(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.action.identity.labels.insert(key.into(), value.into());
        self
    }

    /// Replaces the full label set.
    pub fn labels(mut self, labels: BTreeMap<String, String>) -> Self {
        self.action.identity.labels = labels;
        self
    }

    /// Sets the provenance record.
    pub fn source(mut self, source: SourceRef) -> Self {
        if self.action.execution.runtime == Runtime::UNKNOWN {
            self.action.execution.runtime = source.runtime.clone();
        }
        self.action.source = source;
        self
    }

    /// Sets the capability class.
    pub fn tool_type(mut self, tool_type: ToolType) -> Self {
        self.action.tool_type = tool_type;
        self
    }

    /// Sets the verb.
    pub fn operation(mut self, operation: Operation) -> Self {
        self.action.operation = operation;
        self
    }

    /// Sets the target.
    pub fn target_resource(mut self, resource: Option<Resource>) -> Self {
        self.action.target_resource = resource;
        self
    }

    /// Sets the egress destination.
    pub fn destination(mut self, destination: Option<Destination>) -> Self {
        self.action.destination = destination;
        self
    }

    /// Sets the data classification.
    pub fn data_classification(mut self, classification: DataClassification) -> Self {
        self.action.data_classification = classification;
        self
    }

    /// Sets the referenced credentials.
    pub fn credentials(mut self, credentials: Vec<CredentialRef>) -> Self {
        self.action.credentials = credentials;
        self
    }

    /// Sets the machine and workspace context.
    pub fn environment(mut self, environment: Environment) -> Self {
        self.action.identity.environment = environment;
        self
    }

    /// Adds one metadata entry.
    pub fn metadata_entry(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.action.metadata.insert(key.into(), value.into());
        self
    }

    /// Replaces the metadata map.
    pub fn metadata(mut self, metadata: BTreeMap<String, String>) -> Self {
        self.action.metadata = metadata;
        self
    }

    /// Finishes without validating. Used by the legacy bridge, which must not reject input
    /// that the pre-existing code path accepted.
    pub fn build_unvalidated(mut self) -> AgentAction {
        self.action.refresh_security_classification();
        self.action
    }

    /// Finishes and validates.
    pub fn build(mut self) -> Result<AgentAction, ActionValidationError> {
        self.action.refresh_security_classification();
        self.action.validate()?;
        Ok(self.action)
    }
}

/* ------------------------------------------------------------------------ */
/* Validation errors                                                        */
/* ------------------------------------------------------------------------ */

/// Why an action failed structural validation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ActionValidationError {
    /// An identifier was present but empty or whitespace-only.
    BlankIdentifier {
        /// Field that was blank.
        field: &'static str,
    },
    /// The tool name was empty or whitespace-only.
    EmptyToolName,
    /// The tool name exceeded [`MAX_TOOL_NAME_LEN`].
    ToolNameTooLong {
        /// Observed length.
        len: usize,
        /// Permitted length.
        max: usize,
    },
    /// The argument payload was not valid JSON.
    MalformedArguments {
        /// Parser detail.
        detail: String,
    },
    /// The argument payload was valid JSON but not an object.
    ArgumentsNotObject,
    /// The argument payload had no string `name` field.
    MissingToolName,
    /// The payload's declared name disagreed with the action's tool name.
    ToolNameMismatch {
        /// Name found in the payload.
        declared: String,
        /// Name on the action.
        action: String,
    },
    /// The argument payload exceeded [`MAX_PAYLOAD_BYTES`].
    PayloadTooLarge {
        /// Observed size.
        len: usize,
        /// Permitted size.
        max: usize,
    },
    /// The action declared itself as its own parent.
    SelfParentedAction,
}

impl fmt::Display for ActionValidationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::BlankIdentifier { field } => {
                write!(formatter, "`{field}` was present but blank")
            }
            Self::EmptyToolName => formatter.write_str("tool name was empty"),
            Self::ToolNameTooLong { len, max } => {
                write!(formatter, "tool name length {len} exceeds maximum {max}")
            }
            Self::MalformedArguments { detail } => {
                write!(formatter, "arguments were not valid json: {detail}")
            }
            Self::ArgumentsNotObject => {
                formatter.write_str("arguments payload was not a json object")
            }
            Self::MissingToolName => {
                formatter.write_str("arguments payload had no string `name` field")
            }
            Self::ToolNameMismatch { declared, action } => write!(
                formatter,
                "arguments payload declares tool `{declared}` but action is `{action}`"
            ),
            Self::PayloadTooLarge { len, max } => {
                write!(
                    formatter,
                    "arguments payload {len} bytes exceeds maximum {max}"
                )
            }
            Self::SelfParentedAction => {
                formatter.write_str("action declared itself as its own parent")
            }
        }
    }
}

impl std::error::Error for ActionValidationError {}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_arguments() -> Arguments {
        Arguments::from_name_and_arguments("read_file", &serde_json::json!({"path": "/tmp/a"}))
    }

    #[test]
    fn generated_identifiers_are_unique_and_prefixed() {
        let first = ActionId::generate();
        let second = ActionId::generate();
        assert_ne!(first, second);
        assert!(first.as_str().starts_with("act_"));
        assert!(SessionId::generate().as_str().starts_with("ses_"));
        assert!(TraceId::generate().as_str().starts_with("trc_"));
    }

    #[test]
    fn canonical_params_are_preserved_byte_for_byte() {
        let wire = r#"{"name":"read_file","arguments":{"path":"/etc/hosts"},"_meta":{"x":1}}"#;
        let (name, arguments) = Arguments::from_canonical_params(wire).expect("valid params");

        assert_eq!(name, "read_file");
        assert_eq!(arguments.canonical_params_json(), wire);
        assert_eq!(arguments.string_field("path"), Some("/etc/hosts"));
    }

    #[test]
    fn string_encoded_arguments_are_reparsed() {
        let arguments = Arguments::from_name_and_arguments(
            "read_file",
            &Value::String(r#"{"path":"/tmp/x"}"#.to_string()),
        );

        assert_eq!(arguments.string_field("path"), Some("/tmp/x"));
        assert!(arguments.canonical_params_json().contains("/tmp/x"));
    }

    #[test]
    fn unparseable_string_arguments_stay_strings() {
        let arguments =
            Arguments::from_name_and_arguments("read_file", &Value::String("not json".to_string()));

        assert_eq!(arguments.value(), &Value::String("not json".to_string()));
    }

    #[test]
    fn open_enums_accept_custom_values() {
        let custom = Runtime::custom("langgraph");
        assert_eq!(custom.as_str(), "langgraph");
        assert!(!custom.is_known());
        assert!(Runtime::MCP_STDIO.is_known());
    }

    #[test]
    fn open_enums_serialize_as_plain_strings() {
        let json = serde_json::to_string(&ToolType::FILESYSTEM).expect("serialize");
        assert_eq!(json, "\"filesystem\"");

        let round_trip: Runtime =
            serde_json::from_str("\"langgraph\"").expect("deserialize custom runtime");
        assert_eq!(round_trip, Runtime::custom("langgraph"));
    }

    #[test]
    fn arguments_round_trip_through_serde_as_canonical_json() {
        let arguments = sample_arguments();
        let encoded = serde_json::to_string(&arguments).expect("serialize");
        let decoded: Arguments = serde_json::from_str(&encoded).expect("deserialize");
        assert_eq!(
            decoded.canonical_params_json(),
            arguments.canonical_params_json()
        );
    }

    #[test]
    fn classification_sorts_and_deduplicates_categories() {
        let classification = DataClassification::with_categories(
            Sensitivity::Confidential,
            [DataCategory::Pii, DataCategory::Secret, DataCategory::Pii],
        );

        assert_eq!(
            classification.categories,
            vec![DataCategory::Secret, DataCategory::Pii]
        );
        assert!(!classification.is_unclassified());
    }

    #[test]
    fn builder_produces_a_valid_action() {
        let action = AgentAction::builder("read_file", sample_arguments())
            .source(SourceRef::new(Runtime::MCP_STDIO, "mcp"))
            .build()
            .expect("valid action");

        assert_eq!(action.tool_name(), "read_file");
        assert_eq!(action.runtime(), &Runtime::MCP_STDIO);
        assert!(action.execution.session_id.is_none());
        assert!(action.model.provider.is_none());
    }

    #[test]
    fn rejects_blank_tool_name() {
        let arguments = Arguments::from_parts_unchecked(r#"{"name":"  "}"#, Value::Null);
        let error = AgentAction::builder("   ", arguments)
            .source(SourceRef::new(Runtime::MCP_STDIO, "mcp"))
            .build()
            .expect_err("blank tool name must be rejected");

        assert_eq!(error, ActionValidationError::EmptyToolName);
    }

    #[test]
    fn rejects_tool_name_over_the_limit() {
        let long = "t".repeat(MAX_TOOL_NAME_LEN + 1);
        let arguments = Arguments::from_name_and_arguments(&long, &Value::Null);
        let error = AgentAction::builder(long, arguments)
            .source(SourceRef::new(Runtime::MCP_STDIO, "mcp"))
            .build()
            .expect_err("oversized tool name must be rejected");

        assert!(matches!(
            error,
            ActionValidationError::ToolNameTooLong {
                max: MAX_TOOL_NAME_LEN,
                ..
            }
        ));
    }

    #[test]
    fn rejects_payload_that_disagrees_with_the_tool_name() {
        let arguments = Arguments::from_name_and_arguments("write_file", &Value::Null);
        let error = AgentAction::builder("read_file", arguments)
            .source(SourceRef::new(Runtime::MCP_STDIO, "mcp"))
            .build()
            .expect_err("mismatched name must be rejected");

        assert_eq!(
            error,
            ActionValidationError::ToolNameMismatch {
                declared: "write_file".to_string(),
                action: "read_file".to_string(),
            }
        );
    }

    #[test]
    fn rejects_malformed_argument_payloads() {
        let error = Arguments::from_canonical_params("{not json")
            .expect_err("malformed json must be rejected");
        assert!(matches!(
            error,
            ActionValidationError::MalformedArguments { .. }
        ));
    }

    #[test]
    fn rejects_non_object_argument_payloads() {
        let error = Arguments::from_canonical_params("[1,2,3]")
            .expect_err("array payload must be rejected");
        assert_eq!(error, ActionValidationError::ArgumentsNotObject);
    }

    #[test]
    fn rejects_payload_without_a_tool_name() {
        let error = Arguments::from_canonical_params(r#"{"arguments":{"path":"/tmp"}}"#)
            .expect_err("missing name must be rejected");
        assert_eq!(error, ActionValidationError::MissingToolName);
    }

    #[test]
    fn rejects_non_string_tool_name_in_payload() {
        let error = Arguments::from_canonical_params(r#"{"name":42}"#)
            .expect_err("numeric name must be rejected");
        assert_eq!(error, ActionValidationError::MissingToolName);
    }

    #[test]
    fn rejects_blank_session_identifier() {
        let error = AgentAction::builder("read_file", sample_arguments())
            .source(SourceRef::new(Runtime::MCP_STDIO, "mcp"))
            .session_id(Some(SessionId::new("   ")))
            .build()
            .expect_err("blank session id must be rejected");

        assert_eq!(
            error,
            ActionValidationError::BlankIdentifier {
                field: "session_id"
            }
        );
    }

    #[test]
    fn rejects_self_parented_action() {
        let action_id = ActionId::new("act_self");
        let error = AgentAction::builder("read_file", sample_arguments())
            .source(SourceRef::new(Runtime::MCP_STDIO, "mcp"))
            .action_id(action_id.clone())
            .parent_action_id(Some(action_id))
            .build()
            .expect_err("self-parenting must be rejected");

        assert_eq!(error, ActionValidationError::SelfParentedAction);
    }

    #[test]
    fn rejects_oversized_payload() {
        let filler = "a".repeat(MAX_PAYLOAD_BYTES);
        let arguments =
            Arguments::from_name_and_arguments("read_file", &serde_json::json!({"blob": filler}));
        let error = AgentAction::builder("read_file", arguments)
            .source(SourceRef::new(Runtime::MCP_STDIO, "mcp"))
            .build()
            .expect_err("oversized payload must be rejected");

        assert!(matches!(
            error,
            ActionValidationError::PayloadTooLarge {
                max: MAX_PAYLOAD_BYTES,
                ..
            }
        ));
    }

    #[test]
    fn rejects_blank_adapter_identifier() {
        let error = AgentAction::builder("read_file", sample_arguments())
            .source(SourceRef::new(Runtime::MCP_STDIO, "  "))
            .build()
            .expect_err("blank adapter must be rejected");

        assert_eq!(
            error,
            ActionValidationError::BlankIdentifier { field: "adapter" }
        );
    }

    #[test]
    fn build_unvalidated_accepts_what_build_rejects() {
        let arguments = Arguments::from_parts_unchecked("not json at all", Value::Null);
        let action = AgentAction::builder("legacy_tool", arguments).build_unvalidated();

        assert_eq!(action.tool_name(), "legacy_tool");
        assert!(action.validate().is_err());
    }
}
