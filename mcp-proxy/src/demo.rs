//! Local-first first-run demo — ALLOW / DENY / optional Confirm without Cloud.

use std::path::PathBuf;

use anyhow::{bail, Context, Result};

use crate::policy::{PolicyEngine, PolicyVerdict, POLICY_PATH_ENV};

/// Synthetic sensitive path used in demos — never a real home `.ssh` file.
pub const DEMO_BLOCKED_PATH: &str = "/tmp/sqreen-demo.ssh/id_rsa";
/// Safe path that default policy should allow.
pub const DEMO_ALLOWED_PATH: &str = "/tmp/sqreen-demo-ok.txt";
/// Benign Confirm-shaped command (never executed).
pub const DEMO_CONFIRM_CMD: &str = "echo sqreen-demo-ok";

/// Runs the interactive first-time developer demo against the active local policy.
pub fn run_first_block_demo() -> Result<()> {
    println!();
    println!("Sqreen Core · first protected Agent Action demo");
    println!("───────────────────────────────────────────────");
    println!("This uses synthetic paths only — no real secrets or destructive commands.");
    println!("No Cloud / enrollment / remote approval is required.");
    println!();

    let policy_path = resolve_demo_policy_path();
    let Some(path) = policy_path else {
        bail!(
            "no policy file found.\n\
             Install first:  curl -fsSL https://sqreen.ai/install.sh | bash\n\
             Then:           source ~/.config/mcp-proxy/env && mcp-proxy demo"
        );
    };

    if !path.exists() {
        bail!(
            "policy not found at {}.\n\
             Run the installer or set {POLICY_PATH_ENV}.",
            path.display()
        );
    }

    let engine = PolicyEngine::load(&path)
        .with_context(|| format!("failed to load policy from {}", path.display()))?;

    println!("Policy:  {}", path.display());
    println!(
        "Version: {} · {} tool rules",
        engine.version(),
        engine.tool_count()
    );
    println!(
        "Posture: {}",
        crate::gateway::EnforcementPosture::from_env().enforcement_banner()
    );
    println!();

    println!("1) Allowed Agent Action");
    println!("   Tool:     read_file");
    println!("   Resource: {DEMO_ALLOWED_PATH}");
    let allow_params =
        format!(r#"{{"name":"read_file","arguments":{{"path":"{DEMO_ALLOWED_PATH}"}}}}"#);
    match engine.evaluate_tools_call(&allow_params) {
        PolicyVerdict::Allow | PolicyVerdict::Redact { .. } => {
            println!("   Decision: ALLOW");
            println!("   → Safe project paths pass through to the Tool.");
        }
        other => {
            println!("   Decision: {other:?}");
            bail!(
                "expected ALLOW for {DEMO_ALLOWED_PATH}, got {other:?}.\n\
                 Check that your policy still allows ordinary /tmp reads."
            );
        }
    }
    println!();

    println!("2) Blocked sensitive Agent Action");
    println!("   Tool:     read_file");
    println!("   Resource: {DEMO_BLOCKED_PATH}");
    let block_params =
        format!(r#"{{"name":"read_file","arguments":{{"path":"{DEMO_BLOCKED_PATH}"}}}}"#);
    let block_verdict = engine.evaluate_tools_call(&block_params);
    match &block_verdict {
        PolicyVerdict::Block { reason, .. } => {
            println!("   Decision: DENY");
            println!("   WHY:      {reason}");
        }
        other => {
            println!("   Decision: {other:?}");
            bail!(
                "expected BLOCK/DENY for {DEMO_BLOCKED_PATH}, got {other:?}.\n\
                 Your policy may be missing .ssh / id_rsa block patterns."
            );
        }
    }
    println!();

    println!("3) Local approval / Confirm (policy shape)");
    println!("   Tool:     execute_bash");
    println!("   Command:  {DEMO_CONFIRM_CMD}  (synthetic — not executed)");
    let confirm_params = format!(
        r#"{{"name":"execute_bash","arguments":{{"command":"{DEMO_CONFIRM_CMD}"}}}}"#
    );
    let confirm_verdict = engine.evaluate_tools_call(&confirm_params);
    match &confirm_verdict {
        PolicyVerdict::Confirm { message } => {
            println!("   Decision: REQUIRE_APPROVAL (Confirm)");
            println!("   Message:  {message}");
            println!("   Channel:  local TTY / stdin (open-core default)");
        }
        PolicyVerdict::Block { reason, .. } => {
            println!("   Decision: DENY (stricter than Confirm)");
            println!("   WHY:      {reason}");
            println!("   Note:     Overlay tightened execute_bash to Deny — that is OK.");
        }
        other => {
            println!("   Decision: {other:?}");
            bail!(
                "expected Confirm (REQUIRE_APPROVAL) or DENY for execute_bash.\n\
                 Check mcp-proxy/mcp-policy.yaml baseline Confirm rules."
            );
        }
    }
    println!();

    println!("4) What just happened");
    println!("   Sqreen evaluated the Agent Action before it reached a real Tool.");
    println!("   Local policy + mandatory baseline remain authoritative offline.");
    println!();
    println!("IMPORTANT");
    println!("   Local Sqreen Core is working.");
    println!("   Real agent traffic is NOT verified until a wrapped runtime");
    println!("   sends an action through Sqreen (`demo` alone does not count).");
    println!();
    println!("Next:");
    println!("  1. {}", crate::pilot::day1::INTEGRATE_COMMAND);
    println!("     (skip if installer already printed Cursor integration: CONFIGURED)");
    println!("  2. Restart Cursor / reload MCP");
    println!(
        "  3. Ask Cursor to read {} (real wrapped tools/call)",
        crate::pilot::day1::DAY1_ALLOW_PATH
    );
    println!(
        "     `{}` = gateway self-check only — does not mint VERIFIED_ACTIVE",
        crate::pilot::day1::PROVE_COMMAND
    );
    println!("  4. mcp-proxy status");
    println!();
    Ok(())
}

fn resolve_demo_policy_path() -> Option<PathBuf> {
    if let Ok(path) = std::env::var(POLICY_PATH_ENV) {
        let trimmed = path.trim();
        if !trimmed.is_empty() {
            return Some(PathBuf::from(trimmed));
        }
    }
    let candidates = [
        PathBuf::from("mcp-policy.yaml"),
        PathBuf::from("mcp-proxy/mcp-policy.yaml"),
    ];
    candidates.into_iter().find(|path| path.exists())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn demo_constants_are_synthetic_tmp_paths() {
        assert!(DEMO_ALLOWED_PATH.starts_with("/tmp/"));
        assert!(DEMO_BLOCKED_PATH.starts_with("/tmp/"));
        assert!(!DEMO_BLOCKED_PATH.contains("/.ssh/"));
    }
}
