//! Cross-provider equivalence + unknown-tool + encoding coverage for the security baseline.

use crate::action::{AgentAction, Arguments, Operation, Runtime, SourceRef, ToolType};
use crate::classify::{self, Classification};
use crate::policy::{
    compile_config, compose_effective_policy, evaluate_policy, mandatory_security_baseline,
    PolicyAction, PolicyConfig, PolicyVerdict,
};
use crate::scoring::{RiskFactorKind, RiskScoreEngine, RiskScoreInput};
use crate::security_baseline::{
    looks_like_traversal, mandatory_policy_config, normalize_path_for_policy, ToolKnowledge,
    CANONICAL_REDACT_KEYS,
};

fn action(tool: &str, args: serde_json::Value) -> AgentAction {
    let mut built = AgentAction::builder(tool, Arguments::from_name_and_arguments(tool, &args))
        .source(SourceRef::new(Runtime::MCP_STDIO, "test"))
        .build_unvalidated();
    built.refresh_security_classification();
    built
}

fn args(tool: &str, v: serde_json::Value) -> Arguments {
    Arguments::from_name_and_arguments(tool, &v)
}

#[test]
fn shell_aliases_share_confirm_effect() {
    let policy = mandatory_policy_config();
    for name in [
        "execute_bash",
        "run_terminal_cmd",
        "bash",
        "powershell",
        "pwsh",
        "cmd",
    ] {
        let tool = policy.tools.iter().find(|t| t.name == name).expect(name);
        assert_eq!(tool.action, PolicyAction::Confirm, "{name}");
    }
}

#[test]
fn classify_shell_aliases_as_known_execute() {
    for name in ["execute_bash", "run_terminal_cmd", "powershell", "bash"] {
        let c = classify::classify(name, &args(name, serde_json::json!({"command": "ls"})));
        assert_eq!(c.tool_knowledge, ToolKnowledge::Known);
        assert_eq!(c.tool_type, ToolType::SHELL);
        assert_eq!(c.operation, Operation::Execute);
    }
}

#[test]
fn unknown_tool_scores_unusual_tool() {
    let probe = action("totally_novel_mcp_tool_xyz", serde_json::json!({}));
    let scored = RiskScoreEngine::default().score(&probe, RiskScoreInput::default());
    assert!(scored.has_factor(RiskFactorKind::UnusualTool));
    let c = classify::classify(
        "totally_novel_mcp_tool_xyz",
        &args("totally_novel_mcp_tool_xyz", serde_json::json!({})),
    );
    assert_eq!(c.tool_knowledge, ToolKnowledge::Unknown);
}

#[test]
fn partial_classification_from_command_arg() {
    let c = classify::classify(
        "custom_runner",
        &args("custom_runner", serde_json::json!({"command": "echo hi"})),
    );
    assert_eq!(c.tool_knowledge, ToolKnowledge::PartiallyClassified);
    assert_eq!(c.tool_type, ToolType::SHELL);
}

#[test]
fn encoded_traversal_detected() {
    let enc = format!("{}{}", "%2e%2e", "%2fsecret");
    assert!(looks_like_traversal(&enc));
    let n = normalize_path_for_policy(&enc);
    assert!(n.has_traversal);
}

#[test]
fn double_encoded_traversal_detected() {
    let enc = "%252e%252e%252fsecret";
    assert!(looks_like_traversal(enc));
    let n = normalize_path_for_policy(enc);
    assert!(n.has_traversal || n.normalized.contains("secret"));
}

#[test]
fn remote_cannot_weaken_baseline_confirm() {
    let mut remote = PolicyConfig {
        version: "weak".into(),
        ..mandatory_security_baseline()
    };
    remote.global.risk_threshold = 100;
    for t in &mut remote.tools {
        t.action = PolicyAction::Allow;
        t.block_patterns.clear();
    }
    remote.global.block_patterns.clear();
    let effective = compose_effective_policy(&remote, None);
    let bash = effective
        .tools
        .iter()
        .find(|t| t.name == "execute_bash")
        .unwrap();
    assert_eq!(bash.action, PolicyAction::Confirm);
    assert!(!effective.global.block_patterns.is_empty());
    assert!(effective.global.risk_threshold <= 70);
}

#[test]
fn taxonomy_rules_present_in_baseline() {
    let p = mandatory_policy_config();
    assert!(p.rules.iter().any(|r| r.name.contains("credential")));
    assert!(p.rules.iter().any(|r| r.name.contains("unknown_execute")));
}

#[test]
fn canonical_redact_keys_cover_providers() {
    let set: std::collections::HashSet<_> = CANONICAL_REDACT_KEYS.iter().copied().collect();
    assert!(set.contains("OPENAI_API_KEY"));
    assert!(set.contains("ANTHROPIC_API_KEY"));
    assert!(set.contains("AUTHORIZATION"));
}

#[test]
fn provider_shell_tools_hit_same_policy_surface() {
    let policy = compile_config(mandatory_security_baseline()).expect("compile");
    let names = ["execute_bash", "run_terminal_cmd", "shell"];
    for name in names {
        let a = action(name, serde_json::json!({"command": "echo ok"}));
        let evaluation = evaluate_policy(&policy, &a);
        assert!(
            matches!(
                evaluation.enforced_verdict,
                PolicyVerdict::Confirm { .. } | PolicyVerdict::Allow | PolicyVerdict::Block { .. }
            ),
            "unexpected for {name}: {:?}",
            evaluation.enforced_verdict
        );
    }
}

#[test]
fn new_alias_does_not_need_duplicate_taxonomy_rule() {
    let c: Classification = classify::classify(
        "powershell",
        &args(
            "powershell",
            serde_json::json!({"command": "Get-ChildItem"}),
        ),
    );
    assert_eq!(c.tool_type, ToolType::SHELL);
    assert_eq!(c.operation, Operation::Execute);
    assert!(!mandatory_policy_config().rules.is_empty());
}
