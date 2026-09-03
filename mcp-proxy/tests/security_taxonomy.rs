//! Integration tests for normalized security taxonomy across providers and policy.

use mcp_proxy::action::{
    AgentAction, Arguments, Environment, EnvironmentTier, Operation, Runtime, SourceRef,
};
use mcp_proxy::adapters::{
    CursorAdapter, CursorHookEvent, GenericAdapter, GenericToolCall, McpAdapter, McpToolsCall,
    NormalizationContext, ToolCallAdapter,
};
use mcp_proxy::policy::{PolicyEngine, PolicyVerdict};
use mcp_proxy::taxonomy::{ActionCategory, ResourceCategory};

fn assert_same_semantics(left: &AgentAction, right: &AgentAction) {
    assert_eq!(left.security.action, right.security.action);
    assert_eq!(left.security.resources, right.security.resources);
    assert_eq!(left.security.risk, right.security.risk);
}

#[test]
fn mcp_and_cursor_read_file_share_taxonomy() {
    let context = NormalizationContext::new();

    let mcp = McpAdapter::decode(
        &context,
        McpToolsCall::stdio(r#"{"name":"read_file","arguments":{"path":"/tmp/report.txt"}}"#),
    )
    .expect("mcp decode");

    let cursor_payload = serde_json::json!({
        "hook_event_name": "beforeReadFile",
        "path": "/tmp/report.txt"
    });
    let cursor = CursorAdapter::decode(&context, CursorHookEvent::new(&cursor_payload))
        .expect("cursor decode");

    assert_eq!(mcp.security.action, ActionCategory::Read);
    assert_eq!(cursor.security.action, ActionCategory::Read);
    assert!(mcp.security.touches_resource(ResourceCategory::Filesystem));
    assert!(cursor
        .security
        .touches_resource(ResourceCategory::Filesystem));
}

#[test]
fn generic_adapter_infers_delete_from_command_not_tool_name() {
    let context = NormalizationContext::new();
    let args = serde_json::json!({"command": "rm -rf /tmp/build"});
    let action = GenericAdapter::decode(
        &context,
        GenericToolCall::new(Runtime::custom("test"), "acme_runner", &args),
    )
    .expect("generic decode");

    assert_eq!(action.security.action, ActionCategory::Delete);
    assert!(action.security.risk.destructive);
    assert!(action.security.risk.irreversible);
}

#[test]
fn production_environment_marks_production_risk_after_refresh() {
    let mut action = AgentAction::builder(
        "read_file",
        Arguments::from_name_and_arguments("read_file", &serde_json::json!({"path": "/tmp/a"})),
    )
    .environment(Environment {
        tier: EnvironmentTier::Production,
        ..Default::default()
    })
    .source(SourceRef::new(Runtime::MCP_STDIO, "test"))
    .build_unvalidated();

    action.refresh_security_classification();
    assert!(action.security.risk.production);
    assert!(action
        .security
        .touches_resource(ResourceCategory::ProductionSystem));
}

#[test]
fn taxonomy_policy_blocks_network_requests_to_external_services() {
    let policy = r#"
version: "2026.2"
global:
  redact_keys: []
  block_patterns: []
taxonomy_rules:
  - name: block-external-network
    when:
      action: network_request
      resource.external_service: "true"
    action: Block
tools: []
"#;
    let engine = PolicyEngine::from_yaml(policy).expect("compile policy");

    for tool_name in ["fetch", "WebFetch", "vendor_http_get"] {
        let action = AgentAction::builder(
            tool_name,
            Arguments::from_name_and_arguments(
                tool_name,
                &serde_json::json!({"url": "https://api.example.com/v1/data"}),
            ),
        )
        .operation(Operation::Connect)
        .build_unvalidated();

        assert!(
            matches!(engine.evaluate_action(&action), PolicyVerdict::Block { .. }),
            "expected block for tool {tool_name}"
        );
    }
}

#[test]
fn provider_rename_does_not_change_sql_query_taxonomy() {
    let context = NormalizationContext::new();
    let sql = serde_json::json!({"query": "SELECT id FROM accounts"});

    let mcp = GenericAdapter::decode(
        &context,
        GenericToolCall::new(Runtime::custom("test"), "execute_sql", &sql),
    )
    .expect("execute_sql");

    let renamed = GenericAdapter::decode(
        &context,
        GenericToolCall::new(Runtime::custom("test"), "vendor_db_query", &sql),
    )
    .expect("vendor_db_query");

    assert_same_semantics(&mcp, &renamed);
    assert_eq!(mcp.security.action, ActionCategory::Query);
    assert!(mcp.security.touches_resource(ResourceCategory::Database));
}

#[test]
fn gateway_refreshes_taxonomy_after_identity_enrichment() {
    use std::sync::Arc;

    use mcp_proxy::gateway::{Decision, GatewayBuilder, StaticIdentityResolver};

    let policy = r#"
version: "2026.2"
global:
  redact_keys: []
  block_patterns: []
taxonomy_rules:
  - name: block-prod-reads
    when:
      risk.production: "true"
      action: read
    action: Block
tools: []
"#;

    let ambient = NormalizationContext {
        environment: Environment {
            tier: EnvironmentTier::Production,
            ..Default::default()
        },
        ..NormalizationContext::new()
    };

    let gateway = GatewayBuilder::default()
        .policy_engine(Some(Arc::new(
            PolicyEngine::from_yaml(policy).expect("compile policy"),
        )))
        .identity(Arc::new(StaticIdentityResolver::new(ambient)))
        .build();

    let mut action = AgentAction::builder(
        "read_file",
        Arguments::from_name_and_arguments("read_file", &serde_json::json!({"path": "/tmp/a"})),
    )
    .build_unvalidated();

    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("runtime");
    let outcome = runtime.block_on(gateway.evaluate_in_place(&mut action));

    assert_eq!(outcome.decision, Decision::Deny);
    assert!(action.security.risk.production);
}
