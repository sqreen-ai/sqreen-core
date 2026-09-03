//! Shared fixtures for the enforcement benchmark suite.
//!
//! Synthetic paths only — no real secrets or destructive commands.
//! Policy block patterns use `secret_store/` (not live credential paths).

#![allow(dead_code)]

use std::sync::Arc;

use mcp_proxy::adapters::{McpAdapter, McpToolsCall, NormalizationContext, ToolCallAdapter};
use mcp_proxy::behavior::{BehaviorConfig, BehaviorEngine};
use mcp_proxy::gateway::{
    AllowAllApprovalEngine, FailurePolicy, GatewayBuilder, NullAuditSink, PolicyStage, RiskStage,
};
use mcp_proxy::policy::PolicyEngine;
use mcp_proxy::threat_intel::ThreatIntelMatcher;
use mcp_proxy::{AgentAction, AgentExecutionGateway, SessionTracker};

/// Representative payload sizes (bytes of the MCP params JSON document).
#[derive(Clone, Copy, Debug)]
pub enum PayloadSize {
    /// ~100 B — typical filesystem read.
    Small,
    /// ~4 KiB — richer tool args.
    Medium,
    /// ~64 KiB — large structured args.
    Large,
    /// ~256 KiB — stress case under MAX_PAYLOAD_BYTES.
    XLarge,
}

impl PayloadSize {
    pub fn label(self) -> &'static str {
        match self {
            Self::Small => "small",
            Self::Medium => "medium",
            Self::Large => "large",
            Self::XLarge => "xlarge",
        }
    }

    pub fn padding_bytes(self) -> usize {
        match self {
            Self::Small => 0,
            Self::Medium => 4 * 1024,
            Self::Large => 64 * 1024,
            Self::XLarge => 256 * 1024,
        }
    }
}

/// Builds a synthetic MCP `tools/call` params document for `read_file`.
pub fn mcp_params_json(size: PayloadSize, path: &str) -> String {
    let pad = size.padding_bytes();
    if pad == 0 {
        return format!(r#"{{"name":"read_file","arguments":{{"path":"{path}"}}}}"#);
    }
    // Keep JSON valid: pad lives in a string field the scanners still walk.
    let padding = "x".repeat(pad);
    format!(r#"{{"name":"read_file","arguments":{{"path":"{path}","note":"{padding}"}}}}"#)
}

/// Params that include a synthetic API-key *shape* for DLP benches (not a real credential).
pub fn mcp_params_with_synthetic_secret(size: PayloadSize) -> String {
    let pad = size.padding_bytes();
    let padding = if pad == 0 {
        String::new()
    } else {
        format!(r#","note":"{}""#, "y".repeat(pad))
    };
    // sk- shape is what the DLP scanner looks for in tests.
    format!(
        r#"{{"name":"read_file","arguments":{{"path":"/tmp/sqreen-bench-ok.txt","token":"sk-benchFAKESECRET_e3f4g5h6i7j8k9l0m1n2"{padding}}}}}"#
    )
}

pub fn normalize_mcp(params_json: &str) -> AgentAction {
    let ctx = NormalizationContext::new();
    McpAdapter::decode(&ctx, McpToolsCall::stdio(params_json)).expect("normalize fixture")
}

/// `rule_count` distinct tool policies. `read_file` is always included so the fixture action matches.
/// Extra tools are decoys to scale the compiled rule list.
pub fn policy_yaml(rule_count: usize) -> String {
    let n = rule_count.max(1);
    let mut yaml = String::from(
        r#"version: "1"
global:
  risk_threshold: 70
  redact_keys: ["OPENAI_API_KEY"]
  block_patterns: ["secret_store/"]
tools:
  - name: "read_file"
    action: "Allow"
    block_patterns: ["secret_store/"]
"#,
    );
    for i in 0..n.saturating_sub(1) {
        yaml.push_str(&format!(
            r#"  - name: "decoy_tool_{i}"
    action: "Allow"
    block_patterns: ["secret_store/"]
"#
        ));
    }
    yaml
}

pub fn policy_engine(rule_count: usize) -> Arc<PolicyEngine> {
    let yaml = policy_yaml(rule_count);
    Arc::new(PolicyEngine::from_yaml(&yaml).expect("compile bench policy"))
}

pub fn policy_stage(rule_count: usize) -> PolicyStage {
    PolicyStage::new(Some(policy_engine(rule_count)), None)
}

pub fn risk_stage() -> RiskStage {
    RiskStage::new(
        Arc::new(ThreatIntelMatcher::default()),
        Arc::new(SessionTracker::default()),
    )
}

pub fn behavior_engine() -> Arc<BehaviorEngine> {
    Arc::new(BehaviorEngine::new(
        BehaviorConfig {
            // Allow novel detectors without a long warm-up for stable timing.
            min_profile_actions: 0,
            ..BehaviorConfig::default()
        },
        Some(Arc::new(SessionTracker::default())),
    ))
}

/// Local gateway with auto-approve (no TTY) and silent audit — measures enforcement, not I/O.
pub fn gateway(rule_count: usize, with_behavior: bool) -> AgentExecutionGateway {
    let mut builder = GatewayBuilder::default()
        .policy_engine(Some(policy_engine(rule_count)))
        .approval(Arc::new(AllowAllApprovalEngine))
        .audit(Arc::new(NullAuditSink))
        .failure_policy(FailurePolicy::default())
        .threat_intel(Arc::new(ThreatIntelMatcher::default()))
        .session(Arc::new(SessionTracker::default()));
    if with_behavior {
        builder = builder.behavior(behavior_engine());
    }
    builder.build()
}

/// Best-effort process RSS in KiB (macOS/Linux via `ps`).
pub fn rss_kib() -> Option<u64> {
    let pid = std::process::id().to_string();
    let output = std::process::Command::new("ps")
        .args(["-o", "rss=", "-p", &pid])
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    let text = String::from_utf8_lossy(&output.stdout);
    text.trim().parse().ok()
}

pub fn print_rss(label: &str) {
    match rss_kib() {
        Some(kib) => eprintln!(
            "[bench-memory] {label}: rss={kib} KiB ({:.2} MiB)",
            kib as f64 / 1024.0
        ),
        None => eprintln!("[bench-memory] {label}: rss unavailable"),
    }
}
