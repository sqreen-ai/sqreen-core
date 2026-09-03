//! # mcp-proxy library
//!
//! Shared policy, DLP, risk, and agent-firewall engines used by the `mcp-proxy` binary
//! (MCP stdio relay and OpenAI-compatible HTTP serve mode).
//!
//! ## Layering
//!
//! ```text
//!   provider wire formats
//!            │
//!            ▼
//!   adapters ──────► action::AgentAction ◄────── classify → taxonomy
//!     (RuntimeAdapter: decode → gateway → enforce → emit)
//!                            │
//!                            ▼
//!            gateway::AgentExecutionGateway
//!              identity → policy → risk → approval → audit
//!                            │
//!                            ▼
//!            gateway::EvaluationOutcome  (ALLOW / DENY / REQUIRE_APPROVAL)
//!                            │
//!                            ▼
//!            adapters::RuntimeAdapter::enforce  (provider-native effect)
//!                            │
//!                            ▼
//!            guard::GuardDecision  (compatibility projection)
//! ```
//!
//! [`adapters`] is the only layer that knows about MCP, OpenAI, Anthropic, Cursor, or
//! Claude Code. Everything below it operates on [`action::AgentAction`].
//!
//! [`gateway`] is the entry point for new integrations. [`guard`] remains as a thin
//! compatibility facade over it for the existing relays.

pub mod action;
pub mod adapters;
pub mod behavior;
pub mod classify;
pub mod cloud_client;
pub mod demo;
pub mod gateway;
pub mod guard;
pub mod http_serve;
pub mod identity;
pub mod peeker;
pub mod policy;
pub mod policy_store;
pub mod risk;
pub mod scoring;
pub mod security_baseline;
pub mod taxonomy;
pub mod telemetry;
pub mod threat_intel;
pub mod wasm_engine;

pub use action::{
    ActionId, ActionValidationError, AgentAction, AgentType, Arguments, DataClassification,
    Destination, Environment, ModelProvider, Operation, Resource, Runtime, SessionId, SourceRef,
    ToolType, TraceId,
};
pub use adapters::{
    AdapterError, AdapterExecutionRecord, NormalizationContext, RuntimeAdapter, ToolCallAdapter,
    RUNTIME_CATALOG,
};
pub use behavior::{
    BehaviorConfig, BehaviorEngine, BehaviorFinding, BehaviorProfile, BehaviorSeverity,
    BehaviorSignal, BehaviorSignalKind, SessionTracker,
};
pub use gateway::{
    AgentExecutionGateway, ApprovalContext, ApprovalEngine, ApprovalGrantStore, ApprovalOutcome,
    ApprovalRequest, ApprovalVerdict, AuditEvent, AuditSink, Decision, DecisionReason,
    EnforcementPosture, EvaluationOutcome, FailureAction, FailureMode, FailurePolicy,
    GatewayBuilder, GatewayConfig, IdentityResolver, MatchedPolicy, PolicyAvailability,
    PolicySource, ReasonCode, Stage, Subsystem, SubsystemFailure, ENFORCEMENT_POSTURE_ENV,
};
pub use guard::{
    evaluate_action, evaluate_tool_invocation, GuardContext, GuardDecision, ToolInvocation,
    TELEMETRY_SECRET_EGRESS,
};
pub use identity::{
    AgentId, AgentIdentity, AgentInstanceId, AuthContext, DeviceId, ExecutionContext,
    ExecutionPrincipal, IdentityClaim, IdentityMatchContext, IdentityTrust, ModelExecution,
    WorkspaceId, LOCAL_ANONYMOUS_AGENT_ID,
};
pub use policy::{
    BlockedRule, MatchedRuleSummary, PolicyConfig, PolicyEngine, PolicyEvaluation, PolicyMode,
    PolicyRule, PolicyVerdict, RuleEffect, SCHEMA_2026_3, SUPPORTED_SCHEMA_VERSIONS,
};
pub use scoring::{
    ExplainableRiskScore, RiskFactor, RiskFactorKind, RiskLevel, RiskLevelThresholds,
    RiskScoreCaps, RiskScoreConfig, RiskScoreEngine, RiskScoreInput, RiskScoreWeights,
    SCORE_SEMANTICS,
};
pub use telemetry::{
    build_security_event, emit_evaluation, AgentSecurityEvent, PrivacyPolicy, TelemetryConfig,
    TelemetryMode, TelemetryPipeline, TelemetryStatsSnapshot,
};
