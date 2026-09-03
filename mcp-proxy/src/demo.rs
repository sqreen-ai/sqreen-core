//! First-run security demo — allow / block / explain without real secrets or shells.

use std::path::PathBuf;

use anyhow::{bail, Context, Result};

use crate::policy::{PolicyEngine, PolicyVerdict, POLICY_PATH_ENV};

/// Synthetic sensitive path used in demos — never a real home `.ssh` file.
pub const DEMO_BLOCKED_PATH: &str = "/tmp/sqreen-demo.ssh/id_rsa";
/// Safe path that default policy should allow.
pub const DEMO_ALLOWED_PATH: &str = "/tmp/sqreen-demo-ok.txt";

/// Runs the interactive first-time developer demo against the active local policy.
pub fn run_first_block_demo() -> Result<()> {
    println!();
    println!("Sqreen Core · first protected Agent Action demo");
    println!("───────────────────────────────────────────────");
    println!("This uses synthetic paths only — no real secrets or destructive commands.");
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

    // ── 1. Allowed ──────────────────────────────────────────────────────────
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

    // ── 2. Blocked ──────────────────────────────────────────────────────────
    println!("2) Blocked sensitive Agent Action");
    println!("   Tool:     read_file");
    println!("   Resource: {DEMO_BLOCKED_PATH}");
    let block_params =
        format!(r#"{{"name":"read_file","arguments":{{"path":"{DEMO_BLOCKED_PATH}"}}}}"#);
    let block_verdict = engine.evaluate_tools_call(&block_params);
    match &block_verdict {
        PolicyVerdict::Block { reason, .. } => {
            println!("   Decision: BLOCK");
            println!("   Why:      {reason}");
        }
        other => {
            println!("   Decision: {other:?}");
            bail!(
                "expected BLOCK for {DEMO_BLOCKED_PATH}, got {other:?}.\n\
                 Your policy may be missing .ssh / id_rsa block patterns.\n\
                 Restore defaults from the installer or see mcp-proxy/mcp-policy.yaml."
            );
        }
    }
    println!();

    // ── 3. Explanation ──────────────────────────────────────────────────────
    println!("3) What just happened");
    println!("   Sqreen evaluated the Agent Action before it reached a real Tool.");
    println!("   Sensitive Resources that look like SSH keys / credential paths are denied.");
    println!("   In Cursor or Claude, the same Policy runs on every MCP tools/call.");
    println!();
    println!("Next steps");
    println!("  • Restart Cursor / Claude Desktop (if the installer wrapped MCP).");
    println!("  • Ask the agent to read a normal project file — it should work.");
    println!("  • Ask it to read something under .ssh — it should be blocked.");
    println!("  • HTTP agents:  mcp-proxy serve --listen 127.0.0.1:8787 \\");
    println!("                  --upstream https://api.openai.com");
    println!("                  export OPENAI_BASE_URL=http://127.0.0.1:8787/v1");
    println!("  • Docs: https://sqreen.ai/products");
    println!();
    println!("✔  Demo passed — you have a working security control point.");
    Ok(())
}

fn resolve_demo_policy_path() -> Option<PathBuf> {
    if let Ok(path) = std::env::var(POLICY_PATH_ENV) {
        let p = PathBuf::from(path);
        if p.exists() {
            return Some(p);
        }
    }
    crate::policy::resolve_policy_path_for_load()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy::PolicyEngine;

    fn demo_policy() -> PolicyEngine {
        PolicyEngine::from_yaml(
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
        .expect("demo policy")
    }

    #[test]
    fn demo_paths_allow_then_block() {
        let engine = demo_policy();
        let allow =
            format!(r#"{{"name":"read_file","arguments":{{"path":"{DEMO_ALLOWED_PATH}"}}}}"#);
        assert!(matches!(
            engine.evaluate_tools_call(&allow),
            PolicyVerdict::Allow | PolicyVerdict::Redact { .. }
        ));

        let block =
            format!(r#"{{"name":"read_file","arguments":{{"path":"{DEMO_BLOCKED_PATH}"}}}}"#);
        assert!(matches!(
            engine.evaluate_tools_call(&block),
            PolicyVerdict::Block { .. }
        ));
    }
}
