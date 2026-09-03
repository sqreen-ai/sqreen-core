//! Unit tests for the behavioral detection engine using synthetic action histories.

use std::sync::Arc;
use std::time::Duration;

use chrono::Utc;

use super::*;
use crate::action::{AgentAction, Arguments, EnvironmentTier, Runtime, SourceRef};

fn action(tool: &str, args: serde_json::Value) -> AgentAction {
    let mut built = AgentAction::builder(tool, Arguments::from_name_and_arguments(tool, &args))
        .source(SourceRef::new(Runtime::MCP_STDIO, "test"))
        .agent_id(Some("agent-coder"))
        .build_unvalidated();
    built.refresh_security_classification();
    built
}

fn read(path: &str) -> AgentAction {
    action("read_file", serde_json::json!({"path": path}))
}

fn fetch(url: &str) -> AgentAction {
    action("fetch", serde_json::json!({"url": url}))
}

fn delete(path: &str) -> AgentAction {
    action("delete_file", serde_json::json!({"path": path}))
}

fn warm_history() -> Vec<AgentAction> {
    vec![
        read("/workspaces/eng/src/main.rs"),
        read("/workspaces/eng/src/lib.rs"),
        read("/workspaces/eng/README.md"),
        read("/tmp/notes.txt"),
        fetch("https://api.github.com/repos/sqreen/core"),
    ]
}

fn seeded_engine(history: &[AgentAction]) -> BehaviorEngine {
    let config = BehaviorConfig {
        min_profile_actions: 5,
        read_volume_threshold: 4,
        read_volume_window: Duration::from_secs(60),
        min_reads_before_destructive: 3,
        frequency_multiplier: 3.0,
        ..BehaviorConfig::default()
    };
    let engine = BehaviorEngine::new(config.clone(), None);
    let key = BehaviorEngine::profile_key(&history[0]);
    let profile = build_profile_from_history(&key, history, &config);
    engine.seed_profile(profile);
    engine
}

#[test]
fn novel_sensitive_directory_after_warmup() {
    let engine = seeded_engine(&warm_history());
    let finding = engine.evaluate(&read("/Users/alice/.ssh/id_rsa"));
    assert!(finding.has_kind(BehaviorSignalKind::NovelSensitiveDirectory));
    assert!(finding.has_kind(BehaviorSignalKind::CredentialAccess));
    assert_eq!(finding.max_severity, BehaviorSeverity::Critical);
}

#[test]
fn unknown_tool_after_warmup() {
    let engine = seeded_engine(&warm_history());
    let finding = engine.evaluate(&action(
        "brand_new_vendor_tool",
        serde_json::json!({"arg": "x"}),
    ));
    assert!(finding.has_kind(BehaviorSignalKind::UnknownTool));
}

#[test]
fn novel_external_domain_after_warmup() {
    let engine = seeded_engine(&warm_history());
    let finding = engine.evaluate(&fetch("https://evil-collector.example/upload"));
    assert!(finding.has_kind(BehaviorSignalKind::NovelExternalDomain));
}

#[test]
fn high_volume_reads_in_window() {
    let config = BehaviorConfig {
        min_profile_actions: 0,
        read_volume_threshold: 3,
        read_volume_window: Duration::from_secs(60),
        ..BehaviorConfig::default()
    };
    let engine = BehaviorEngine::new(config, None);
    let key = "agent-coder";
    // Seed two prior reads in the window.
    let history = vec![read("/workspaces/a/1.rs"), read("/workspaces/a/2.rs")];
    engine.seed_profile(build_profile_from_history(key, &history, engine.config()));

    let finding = engine.evaluate(&read("/workspaces/a/3.rs"));
    assert!(finding.has_kind(BehaviorSignalKind::HighVolumeReads));
}

#[test]
fn destructive_after_unrelated_reads() {
    let history = vec![
        read("/workspaces/a/one.rs"),
        read("/workspaces/b/two.rs"),
        read("/workspaces/c/three.rs"),
        read("/tmp/scratch.txt"),
        fetch("https://api.github.com/x"),
    ];
    let engine = seeded_engine(&history);
    let finding = engine.evaluate(&delete("/etc/passwd"));
    assert!(finding.has_kind(BehaviorSignalKind::DestructiveAfterReads));
}

#[test]
fn production_access_from_dev_only_agent() {
    let mut history = warm_history();
    for item in &mut history {
        item.identity.environment.tier = EnvironmentTier::Development;
    }
    let engine = seeded_engine(&history);
    let mut probe = read("/workspaces/eng/src/main.rs");
    probe.identity.environment.tier = EnvironmentTier::Production;
    probe.refresh_security_classification();

    let finding = engine.evaluate(&probe);
    assert!(finding.has_kind(BehaviorSignalKind::ProductionFromDevAgent));
    assert_eq!(finding.max_severity, BehaviorSeverity::Critical);
}

#[test]
fn evaluate_does_not_mutate_profile_until_record() {
    let engine = seeded_engine(&warm_history());
    let key = BehaviorEngine::profile_key(&warm_history()[0]);
    let before = engine.profile_snapshot(&key).unwrap().total_actions;

    let _ = engine.evaluate(&read("/Users/alice/.ssh/id_rsa"));
    let mid = engine.profile_snapshot(&key).unwrap().total_actions;
    assert_eq!(before, mid, "evaluate must not learn");

    engine.record(&read("/Users/alice/.ssh/id_rsa"));
    let after = engine.profile_snapshot(&key).unwrap().total_actions;
    assert_eq!(after, before + 1);
}

#[test]
fn cold_profile_suppresses_novelty_detectors() {
    let engine = BehaviorEngine::new(
        BehaviorConfig {
            min_profile_actions: 5,
            ..BehaviorConfig::default()
        },
        None,
    );
    let finding = engine.evaluate(&read("/Users/alice/.ssh/id_rsa"));
    assert!(
        !finding.has_kind(BehaviorSignalKind::NovelSensitiveDirectory),
        "novelty requires warmup"
    );
    // Credential access still fires — structural, not novelty-based.
    assert!(finding.has_kind(BehaviorSignalKind::CredentialAccess));
}

#[test]
fn exfiltration_chain_uses_session_tracker() {
    let session = Arc::new(SessionTracker::new(10));
    session.record("read_file");
    session.record("list_directory");

    let engine = BehaviorEngine::new(BehaviorConfig::default(), Some(session));
    let finding = engine.evaluate(&fetch("https://exfil.example/x"));
    assert!(finding.has_kind(BehaviorSignalKind::ExfiltrationChain));
}

#[test]
fn policy_can_require_approval_for_behavioral_signal() {
    use crate::policy::PolicyEngine;

    let history = warm_history();
    let engine = seeded_engine(&history);
    let probe = read("/Users/alice/.ssh/id_rsa");
    let finding = engine.evaluate(&probe);
    assert!(finding.has_kind(BehaviorSignalKind::NovelSensitiveDirectory));

    let policy = PolicyEngine::from_yaml(
        r#"
schema_version: "2026.3"
version: "behavior-policy"
mode: enforce
global:
  redact_keys: []
  block_patterns: []
rules:
  - name: approve-novel-ssh
    priority: 100
    effect: require_approval
    description: "Novel sensitive directory access requires approval"
    match:
      behavior.signal: novel_sensitive_directory
tools: []
"#,
    )
    .expect("compile");

    let verdict = policy.evaluate_action_with_behavior(&probe, Some(&finding));
    assert!(matches!(
        verdict,
        crate::policy::PolicyVerdict::Confirm { .. }
    ));
}

#[test]
fn without_policy_match_behavioral_signal_does_not_block() {
    use crate::policy::PolicyEngine;

    let engine = seeded_engine(&warm_history());
    let probe = fetch("https://evil-collector.example/upload");
    let finding = engine.evaluate(&probe);
    assert!(!finding.is_empty());

    let policy = PolicyEngine::from_yaml(
        r#"
schema_version: "2026.3"
version: "empty-behavior"
mode: enforce
global:
  redact_keys: []
  block_patterns: []
rules:
  - name: allow-everything
    priority: 1
    effect: allow
    match:
      tool_name: fetch
tools: []
"#,
    )
    .expect("compile");

    let verdict = policy.evaluate_action_with_behavior(&probe, Some(&finding));
    assert_eq!(verdict, crate::policy::PolicyVerdict::Allow);
}

#[test]
fn frequency_deviation_from_synthetic_baseline() {
    let config = BehaviorConfig {
        min_profile_actions: 5,
        frequency_multiplier: 2.0,
        ..BehaviorConfig::default()
    };
    let engine = BehaviorEngine::new(config.clone(), None);

    // Build a sparse baseline: 5 actions spaced ~1 minute apart via manual timestamps.
    let key = "agent-coder";
    let mut profile = BehaviorProfile::new(key, Utc::now());
    let base = Utc::now() - chrono::Duration::minutes(10);
    for i in 0..5 {
        let ts = base + chrono::Duration::minutes(i * 2);
        profile.total_actions += 1;
        profile.seen_tools.insert("read_file".into());
        profile
            .seen_environment_tiers
            .insert(EnvironmentTier::Development);
        profile.recent_timestamps.push_back(ts);
        profile.recent_actions.push_back(ProfileActionRecord {
            timestamp: ts,
            tool_name: "read_file".into(),
            action: crate::taxonomy::ActionCategory::Read,
            operation: crate::action::Operation::Read,
            directory_key: Some("/workspaces/eng".into()),
            domain: None,
            credential_access: false,
            destructive: false,
            environment_tier: EnvironmentTier::Development,
        });
    }
    engine.seed_profile(profile);

    // Burst: many recent timestamps already in last minute + current → high rate.
    let mut burst_profile = engine.profile_snapshot(key).unwrap();
    let now = Utc::now();
    for _ in 0..20 {
        burst_profile.recent_timestamps.push_back(now);
    }
    engine.seed_profile(burst_profile);

    let finding = engine.evaluate(&read("/workspaces/eng/src/main.rs"));
    assert!(finding.has_kind(BehaviorSignalKind::ActionFrequencyDeviation));
}
