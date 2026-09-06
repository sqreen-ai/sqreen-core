//! `mcp-proxy prove` — gateway/policy self-check (ALLOW + DENY).
//!
//! Uses the same Agent Execution Gateway decision path as wrap/serve, but does **not**
//! record runtime-coverage activity. Only a real wrapped MCP `tools/call` through
//! `mcp-proxy -- run` (including Cursor Core wrap) can mint `VERIFIED_ACTIVE` today.
//! OpenAI HTTP `serve` evaluates tool_calls but does not currently record coverage activity.

use std::fs;
use std::path::PathBuf;
use std::sync::Arc;

use anyhow::{bail, Context, Result};

use super::day1::{self, DAY1_ALLOW_PATH, DAY1_DENY_PATH, PRIMARY_RUNTIME, PROVE_COMMAND};
use super::integrations::{detect_integrations, has_core_wrap_configured};
use super::status::{collect_status, RuntimeCoverageState};
use crate::adapters::{McpAdapter, McpToolsCall, NormalizationContext, ToolCallAdapter};
use crate::behavior::SessionTracker;
use crate::gateway::PolicyAvailability;
use crate::guard::{evaluate_outcome_self_check, GuardContext};
use crate::policy::{resolve_policy_path_for_load, PolicyEngine};
use crate::threat_intel::ThreatIntelMatcher;

/// Runs allow + deny through the production gateway (self-check) and prints Day-1 next steps.
pub async fn run_prove() -> Result<()> {
    println!();
    println!("Sqreen Core · prove (gateway self-check)");
    println!("────────────────────────────────────────");
    println!("  Primary path: {PRIMARY_RUNTIME}");
    println!("  This is NOT `mcp-proxy demo`.");
    println!("  In-process evaluations do NOT prove that Cursor/MCP/agent traffic is protected.");
    println!();

    let policy_path = resolve_policy_path_for_load()
        .filter(|p| p.exists())
        .ok_or_else(|| {
            anyhow::anyhow!(
                "no policy loaded.\n\
                 Install first, then: source ~/.config/mcp-proxy/env && {PROVE_COMMAND}"
            )
        })?;
    let engine = PolicyEngine::load(&policy_path)
        .with_context(|| format!("failed to load {}", policy_path.display()))?;

    let ctx = GuardContext {
        policy: Some(Arc::new(engine)),
        policy_availability: PolicyAvailability::Available,
        wasm: None,
        threat_intel: Arc::new(ThreatIntelMatcher::default()),
        session: Arc::new(SessionTracker::default()),
        cloud: None,
    };
    let normalization = NormalizationContext::new();

    println!("1) Allowed Agent Action (gateway self-check · mcp_stdio shape)");
    println!("   Tool:     read_file");
    println!("   Resource: {DAY1_ALLOW_PATH}");
    let allow = evaluate_tools_call(&ctx, &normalization, DAY1_ALLOW_PATH).await?;
    if !allow.is_allowed() {
        bail!(
            "expected ALLOW for {DAY1_ALLOW_PATH}, got {}",
            allow.decision.as_str()
        );
    }
    println!("   Decision: ALLOW");
    println!();

    println!("2) Blocked Agent Action (gateway self-check · mcp_stdio shape)");
    println!("   Tool:     read_file");
    println!("   Resource: {DAY1_DENY_PATH}");
    println!("   (synthetic fixture under /tmp — not your real ~/.ssh)");
    let deny = evaluate_tools_call(&ctx, &normalization, DAY1_DENY_PATH).await?;
    if deny.is_allowed() {
        bail!(
            "expected DENY for {DAY1_DENY_PATH}, got ALLOW.\n\
             Restore baseline .ssh / id_rsa block patterns."
        );
    }
    println!("   Decision: {}", deny.decision.as_str());
    if let Some(detail) = deny.primary_detail() {
        println!("   WHY:      {detail}");
    }
    println!();

    let wrap_configured = has_core_wrap_configured(&detect_integrations());
    let status = collect_status();

    println!("3) Coverage");
    println!("   Gateway self-check:    PASS");
    if status.runtime_coverage == RuntimeCoverageState::VerifiedActive
        && status.protected_traffic_verified
    {
        println!("   Runtime protection:    VERIFIED (wrap + recent protected evaluation)");
        println!(
            "   Runtime coverage:      {}",
            status.runtime_coverage.as_str()
        );
    } else {
        println!("   Runtime protection:    NOT VERIFIED");
        println!(
            "   Runtime coverage:      {}",
            status.runtime_coverage.as_str()
        );
        if !wrap_configured {
            println!("   (No Core wrap/serve path configured — Cursor traffic is not protected.)");
        } else {
            println!(
                "   (Wrap configured — take a real tools/call through Cursor after restart.)"
            );
        }
    }
    println!();
    println!("Next:");
    if status.runtime_coverage == RuntimeCoverageState::VerifiedActive {
        println!("  `mcp-proxy status`  (confirm VERIFIED_ACTIVE)");
        println!(
            "  In Cursor, ask the agent to read {DAY1_DENY_PATH} — expect a real block."
        );
        day1::print_optional_cloud_next();
    } else if !wrap_configured {
        day1::print_integrate_next();
    } else {
        day1::print_verify_traffic_next();
    }
    println!();
    println!("✔  Prove finished — gateway self-check completed (not a wrap-traffic proof).");
    Ok(())
}

async fn evaluate_tools_call(
    ctx: &GuardContext,
    normalization: &NormalizationContext,
    path: &str,
) -> Result<crate::gateway::EvaluationOutcome> {
    let params = format!(r#"{{"name":"read_file","arguments":{{"path":"{path}"}}}}"#);
    let action = McpAdapter::decode(normalization, McpToolsCall::stdio(&params))
        .context("normalize tools/call")?;
    Ok(evaluate_outcome_self_check(ctx, &action).await)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pilot::activity;
    use crate::pilot::config::test_env_lock;
    use crate::pilot::status::{collect_status, RuntimeCoverageState};

    fn write_policy(home: &std::path::Path) -> PathBuf {
        let policy = home.join(".config/mcp-proxy/mcp-policy.yaml");
        let repo = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("mcp-policy.yaml");
        if repo.exists() {
            fs::copy(&repo, &policy).unwrap();
        } else {
            fs::write(
                &policy,
                r#"
version: "1"
global:
  redact_keys: []
  risk_threshold: 70
  block_patterns: ["\\.ssh/", "id_rsa(\\.|$)"]
tools:
  - name: read_file
    action: Allow
    block_patterns: ["\\.ssh/", "id_rsa(\\.|$)"]
"#,
            )
            .unwrap();
        }
        unsafe {
            std::env::set_var("MCP_POLICY_PATH", &policy);
        }
        policy
    }

    fn write_cursor_wrap(home: &std::path::Path) {
        let dir = home.join(".cursor");
        fs::create_dir_all(&dir).unwrap();
        fs::write(
            dir.join("mcp.json"),
            r#"{
  "mcpServers": {
    "filesystem": {
      "command": "/tmp/mcp-proxy",
      "args": ["--", "run", "npx", "-y", "@modelcontextprotocol/server-filesystem", "."]
    }
  }
}"#,
        )
        .unwrap();
    }

    #[tokio::test]
    async fn prove_without_wrap_is_not_verified_active() {
        let _guard = test_env_lock();
        let tmp = std::env::temp_dir().join(format!("sqreen-prove-nowrap-{}", std::process::id()));
        let _ = fs::remove_dir_all(&tmp);
        fs::create_dir_all(tmp.join(".config/mcp-proxy")).unwrap();
        unsafe {
            std::env::set_var("HOME", &tmp);
            std::env::remove_var("XDG_CONFIG_HOME");
            std::env::remove_var("OPENAI_BASE_URL");
            std::env::remove_var("MCP_CONTROL_PLANE_URL");
            std::env::remove_var("MCP_DEVICE_TOKEN");
        }
        write_policy(&tmp);

        let before = activity::load();
        assert!(before.last_protected_at.is_none());

        run_prove().await.expect("prove self-check");

        let after_activity = activity::load();
        assert!(
            after_activity.last_protected_at.is_none(),
            "prove must not record runtime-coverage activity"
        );

        let status = collect_status();
        assert_eq!(status.runtime_coverage, RuntimeCoverageState::NotConfigured);
        assert!(!status.protected_traffic_verified);

        let _ = fs::remove_dir_all(&tmp);
    }

    #[tokio::test]
    async fn prove_with_wrap_still_does_not_mint_verified_active() {
        let _guard = test_env_lock();
        let tmp = std::env::temp_dir().join(format!("sqreen-prove-wrap-{}", std::process::id()));
        let _ = fs::remove_dir_all(&tmp);
        fs::create_dir_all(tmp.join(".config/mcp-proxy")).unwrap();
        unsafe {
            std::env::set_var("HOME", &tmp);
            std::env::remove_var("XDG_CONFIG_HOME");
            std::env::remove_var("OPENAI_BASE_URL");
            std::env::remove_var("MCP_CONTROL_PLANE_URL");
            std::env::remove_var("MCP_DEVICE_TOKEN");
        }
        write_policy(&tmp);
        write_cursor_wrap(&tmp);

        run_prove().await.expect("prove self-check");

        let status = collect_status();
        assert_eq!(status.runtime_coverage, RuntimeCoverageState::Configured);
        assert!(!status.protected_traffic_verified);
        assert!(activity::load().last_protected_at.is_none());

        let _ = fs::remove_dir_all(&tmp);
    }

    #[tokio::test]
    async fn wrap_plus_real_evaluation_is_verified_active() {
        let _guard = test_env_lock();
        let tmp = std::env::temp_dir().join(format!("sqreen-prove-real-{}", std::process::id()));
        let _ = fs::remove_dir_all(&tmp);
        fs::create_dir_all(tmp.join(".config/mcp-proxy")).unwrap();
        unsafe {
            std::env::set_var("HOME", &tmp);
            std::env::remove_var("XDG_CONFIG_HOME");
            std::env::remove_var("OPENAI_BASE_URL");
        }
        write_policy(&tmp);
        write_cursor_wrap(&tmp);

        // Simulate a real wrap/serve evaluation (records activity).
        activity::record_protected_evaluation("mcp_stdio", "read_file", "DENY");

        let status = collect_status();
        assert!(status.protected_traffic_verified);
        assert_eq!(status.runtime_coverage, RuntimeCoverageState::VerifiedActive);

        let _ = fs::remove_dir_all(&tmp);
    }
}
