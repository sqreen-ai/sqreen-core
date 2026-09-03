//! Regression suite for policy-availability / enforcement posture.
//!
//! Covers the P0: missing or unloadable policy must not silently become allow-all under
//! enforcing or managed deployments. Development may fail open, but only explicitly.

use std::sync::Arc;
use std::time::Duration;

use mcp_proxy::adapters::{
    AnthropicAdapter, AnthropicToolUse, CursorAdapter, CursorHookEvent, GenericAdapter, McpAdapter,
    McpToolsCall, NormalizationContext, OpenAiAdapter, OpenAiFunctionCall, ToolCallAdapter,
};
use mcp_proxy::gateway::{
    Decision, EnforcementPosture, FailurePolicy, GatewayBuilder, PolicyAvailability, ReasonCode,
    RecordingAuditSink,
};
use mcp_proxy::guard::{evaluate_outcome, GuardContext};
use mcp_proxy::policy::{load_config_optional, PolicyEngine};
use mcp_proxy::policy_store::PolicyStore;
use mcp_proxy::threat_intel::ThreatIntelMatcher;
use mcp_proxy::{evaluate_action, AgentAction, SessionTracker};
use std::path::PathBuf;

const ALLOW_POLICY: &str = r#"
version: "avail-1"
global:
  redact_keys: []
  risk_threshold: 99
  block_patterns: ["\\.ssh/"]
tools:
  - name: "read_file"
    action: "Allow"
    block_patterns: []
"#;

fn policy() -> Arc<PolicyEngine> {
    Arc::new(PolicyEngine::from_yaml(ALLOW_POLICY).expect("compile"))
}

fn mcp(path: &str) -> AgentAction {
    McpAdapter::decode(
        &NormalizationContext::new(),
        McpToolsCall::stdio(&format!(
            r#"{{"name":"read_file","arguments":{{"path":"{path}"}}}}"#
        )),
    )
    .expect("mcp")
}

#[tokio::test]
async fn enforcing_denies_missing_policy_with_machine_readable_state() {
    let recorder = Arc::new(RecordingAuditSink::new());
    let outcome = GatewayBuilder::default()
        .failure_policy(FailurePolicy::for_posture(EnforcementPosture::Enforcing))
        .audit(recorder.clone())
        .build()
        .evaluate(&mcp("/tmp/ok"))
        .await;

    assert_eq!(outcome.decision, Decision::Deny);
    assert_eq!(outcome.policy_availability, PolicyAvailability::Missing);
    assert_eq!(
        outcome.metadata.get("policy_state").map(String::as_str),
        Some("MISSING")
    );
    assert!(outcome.has_reason(ReasonCode::PolicyUnavailable));
    assert!(
        outcome
            .reasons
            .iter()
            .any(|r| r.detail.contains("policy_unavailable")),
        "reason must be machine-searchable"
    );
}

#[tokio::test]
async fn development_allows_with_loud_reason_never_silently() {
    let outcome = GatewayBuilder::default()
        .failure_policy(FailurePolicy::for_posture(EnforcementPosture::Development))
        .build()
        .evaluate(&mcp("/tmp/ok"))
        .await;

    assert_eq!(outcome.decision, Decision::Allow);
    assert!(outcome.has_reason(ReasonCode::PolicyUnavailable));
    assert!(outcome
        .reasons
        .iter()
        .any(|r| r.detail.contains("FAIL_OPEN")));
}

#[tokio::test]
async fn managed_remote_unavailable_without_snapshot_denies() {
    let outcome = GatewayBuilder::default()
        .policy_availability(PolicyAvailability::RemoteUnavailable)
        .failure_policy(FailurePolicy::for_posture(EnforcementPosture::Managed))
        .build()
        .evaluate(&mcp("/tmp/ok"))
        .await;

    assert_eq!(outcome.decision, Decision::Deny);
    assert_eq!(
        outcome.policy_availability,
        PolicyAvailability::RemoteUnavailable
    );
}

#[tokio::test]
async fn stale_cached_policy_still_enforces_rules() {
    let outcome = GatewayBuilder::default()
        .policy_engine(Some(policy()))
        .policy_availability(PolicyAvailability::Stale)
        .failure_policy(FailurePolicy::for_posture(EnforcementPosture::Managed))
        .build()
        .evaluate(&mcp("~/.ssh/id_rsa"))
        .await;

    assert_eq!(outcome.decision, Decision::Deny);
    assert_eq!(outcome.policy_availability, PolicyAvailability::Stale);
    assert!(outcome.has_reason(ReasonCode::PolicyGlobalBlockPattern));
}

#[tokio::test]
async fn every_provider_entry_point_agrees_when_policy_is_missing() {
    let context = NormalizationContext::new();
    let cursor_payload = serde_json::json!({
        "hook_event_name": "beforeReadFile",
        "file_path": "/tmp/ok",
    });
    let arguments = serde_json::json!({ "path": "/tmp/ok" });

    let actions: Vec<(&str, AgentAction)> = vec![
        (
            "mcp",
            McpAdapter::decode(
                &context,
                McpToolsCall::stdio(r#"{"name":"read_file","arguments":{"path":"/tmp/ok"}}"#),
            )
            .expect("mcp"),
        ),
        (
            "openai",
            OpenAiAdapter::decode(
                &context,
                OpenAiFunctionCall::new("read_file", &arguments).with_model(Some("gpt-4o")),
            )
            .expect("openai"),
        ),
        (
            "anthropic",
            AnthropicAdapter::decode(
                &context,
                AnthropicToolUse::new("read_file", &arguments).with_model(Some("claude-sonnet-4")),
            )
            .expect("anthropic"),
        ),
        (
            "cursor",
            CursorAdapter::decode(&context, CursorHookEvent::new(&cursor_payload)).expect("cursor"),
        ),
        (
            "generic",
            GenericAdapter::filesystem_operation(&context, "read_file", "/tmp/ok")
                .expect("generic"),
        ),
    ];

    let gateway = GatewayBuilder::default()
        .failure_policy(FailurePolicy::for_posture(EnforcementPosture::Enforcing))
        .build();

    for (provider, action) in &actions {
        let outcome = gateway.evaluate(action).await;
        assert_eq!(
            outcome.decision,
            Decision::Deny,
            "{provider} must deny when policy is missing"
        );
        assert_eq!(
            outcome.policy_availability,
            PolicyAvailability::Missing,
            "{provider} must report MISSING"
        );
        assert!(
            outcome.has_reason(ReasonCode::PolicyUnavailable),
            "{provider} must use policy_unavailable"
        );
    }
}

#[tokio::test]
async fn guard_facade_and_direct_gateway_agree_on_missing_policy() {
    let action = mcp("/tmp/ok");
    let guard = GuardContext {
        policy: None,
        policy_availability: PolicyAvailability::Missing,
        wasm: None,
        threat_intel: Arc::new(ThreatIntelMatcher::default()),
        session: Arc::new(SessionTracker::default()),
        cloud: None,
    };

    let via_guard = evaluate_outcome(&guard, &action).await;
    let via_gateway = GatewayBuilder::default()
        .failure_policy(FailurePolicy::from_env())
        .build()
        .evaluate(&action)
        .await;

    assert_eq!(via_guard.decision, via_gateway.decision);
    assert_eq!(
        via_guard.policy_availability,
        via_gateway.policy_availability
    );
    assert_eq!(via_guard.decision, Decision::Deny);
}

#[tokio::test]
async fn startup_race_before_policy_load_denies_under_enforcing() {
    // Simulates initialization before any snapshot is ready: engine None + Missing.
    let store = PolicyStore::new(None);
    assert_eq!(store.availability(), PolicyAvailability::Missing);

    let outcome = GatewayBuilder::default()
        .policy_engine(store.snapshot())
        .policy_availability(store.availability())
        .failure_policy(FailurePolicy::for_posture(EnforcementPosture::Enforcing))
        .build()
        .evaluate(&mcp("/tmp/ok"))
        .await;

    assert_eq!(outcome.decision, Decision::Deny);
    assert_eq!(outcome.policy_availability, PolicyAvailability::Missing);
}

#[tokio::test]
async fn policy_file_removal_keeps_previous_snapshot_as_stale() {
    let engine = PolicyEngine::from_yaml(ALLOW_POLICY).expect("compile");
    let store = PolicyStore::new(Some(engine));
    assert_eq!(store.availability(), PolicyAvailability::Available);

    // Simulate a refresh that finds nothing after the file disappeared: keep previous,
    // mark STALE. (PolicyStore::refresh_if_stale does this; we assert the contract here.)
    let store = PolicyStore::with_availability(
        Some(PolicyEngine::from_yaml(ALLOW_POLICY).expect("compile")),
        PolicyAvailability::Stale,
    );

    let outcome = GatewayBuilder::default()
        .policy_engine(store.snapshot())
        .policy_availability(store.availability())
        .build()
        .evaluate(&mcp("~/.ssh/id_rsa"))
        .await;

    assert_eq!(outcome.decision, Decision::Deny);
    assert_eq!(outcome.policy_availability, PolicyAvailability::Stale);
    assert!(
        outcome.has_reason(ReasonCode::PolicyGlobalBlockPattern),
        "stale snapshot must still enforce"
    );
}

#[test]
fn empty_policy_file_is_rejected_not_treated_as_allow_all() {
    let path = unique_policy_path("empty");
    std::fs::write(&path, "   \n").expect("write empty");

    let result = with_policy_path_env(&path, load_config_optional);
    let _ = std::fs::remove_file(&path);

    assert!(
        result.is_err(),
        "empty policy must error, not Ok(None)/Ok(empty)"
    );
    let message = format!("{:#}", result.unwrap_err()).to_ascii_lowercase();
    assert!(
        message.contains("empty"),
        "error should name emptiness without dumping secrets: {message}"
    );
}

#[test]
fn corrupted_policy_file_is_rejected() {
    let path = unique_policy_path("corrupt");
    std::fs::write(&path, "version: [\nnot: yaml:::").expect("write corrupt");

    let result = with_policy_path_env(&path, load_config_optional);
    let _ = std::fs::remove_file(&path);

    assert!(result.is_err());
}

fn unique_policy_path(label: &str) -> PathBuf {
    let mut path = std::env::temp_dir();
    path.push(format!(
        "sqreen-policy-avail-{}-{}-{}.yaml",
        label,
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0)
    ));
    path
}

fn with_policy_path_env<T>(path: &PathBuf, body: impl FnOnce() -> T) -> T {
    use std::sync::{Mutex, OnceLock};
    static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    let _guard = LOCK
        .get_or_init(|| Mutex::new(()))
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());

    let previous = std::env::var_os("MCP_POLICY_PATH");
    std::env::set_var("MCP_POLICY_PATH", path);
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(body));
    match previous {
        Some(value) => std::env::set_var("MCP_POLICY_PATH", value),
        None => std::env::remove_var("MCP_POLICY_PATH"),
    }
    match result {
        Ok(value) => value,
        Err(payload) => std::panic::resume_unwind(payload),
    }
}

#[tokio::test]
async fn cloud_unavailable_with_cached_policy_enforces_as_stale() {
    let outcome = GatewayBuilder::default()
        .policy_engine(Some(policy()))
        .policy_availability(PolicyAvailability::Stale)
        .failure_policy(FailurePolicy::for_posture(EnforcementPosture::Managed))
        .build()
        .evaluate(&mcp("~/.ssh/id_rsa"))
        .await;

    assert_eq!(outcome.decision, Decision::Deny);
    assert_eq!(outcome.policy_availability, PolicyAvailability::Stale);
}

#[tokio::test]
async fn cloud_unavailable_without_cached_policy_denies_as_remote_unavailable() {
    let outcome = GatewayBuilder::default()
        .policy_engine(None)
        .policy_availability(PolicyAvailability::RemoteUnavailable)
        .failure_policy(FailurePolicy::for_posture(EnforcementPosture::Managed))
        .audit(Arc::new(RecordingAuditSink::new()))
        .build()
        .evaluate(&mcp("/tmp/ok"))
        .await;

    assert_eq!(outcome.decision, Decision::Deny);
    assert_eq!(
        outcome.policy_availability,
        PolicyAvailability::RemoteUnavailable
    );
    assert!(outcome.has_reason(ReasonCode::PolicyUnavailable));
}

#[tokio::test]
async fn observe_preset_is_explicit_opt_in_not_the_default() {
    let default = FailurePolicy::default();
    let observe = FailurePolicy::observe();

    assert!(!default
        .mode_for(mcp_proxy::gateway::Subsystem::PolicyMissing)
        .permits_allow());
    assert!(observe
        .mode_for(mcp_proxy::gateway::Subsystem::PolicyMissing)
        .permits_allow());

    let outcome = GatewayBuilder::default()
        .failure_policy(observe)
        .build()
        .evaluate(&mcp("/tmp/ok"))
        .await;
    assert_eq!(outcome.decision, Decision::Allow);
}

#[test]
fn default_enforcement_posture_is_enforcing() {
    assert_eq!(EnforcementPosture::default(), EnforcementPosture::Enforcing);
    assert!(!EnforcementPosture::Enforcing.allows_missing_policy_passthrough());
    assert!(!EnforcementPosture::Managed.allows_missing_policy_passthrough());
    assert!(EnforcementPosture::Development.allows_missing_policy_passthrough());
}

#[tokio::test]
async fn evaluate_action_facade_blocks_when_policy_missing() {
    let guard = GuardContext {
        policy: None,
        policy_availability: PolicyAvailability::Missing,
        wasm: None,
        threat_intel: Arc::new(ThreatIntelMatcher::default()),
        session: Arc::new(SessionTracker::default()),
        cloud: None,
    };
    let decision = evaluate_action(&guard, &mcp("/tmp/ok"))
        .await
        .expect("evaluate");
    assert!(matches!(decision, mcp_proxy::GuardDecision::Block { .. }));
}

#[tokio::test]
async fn latency_is_still_reported_on_policy_unavailable_denials() {
    let outcome = GatewayBuilder::default()
        .build()
        .evaluate(&mcp("/tmp/ok"))
        .await;
    assert_eq!(outcome.decision, Decision::Deny);
    assert!(outcome.latency > Duration::from_nanos(0));
}
