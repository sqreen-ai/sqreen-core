//! First-run security demo — allow / block / confirm / explain without real secrets or shells.

use std::path::PathBuf;

use anyhow::{bail, Context, Result};

use crate::cloud_client::{
    CloudClient, CreateRemoteApprovalBody, CONTROL_PLANE_URL_ENV, DEVICE_TOKEN_ENV,
};
use crate::gateway::ApprovalMode;
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
            print_block_explanation(reason);
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

    // ── 3. Confirm / approval simulation ────────────────────────────────────
    println!("3) REQUIRE APPROVAL · Confirm simulation");
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
            explain_approval_channel();
            maybe_create_remote_demo_approval();
        }
        PolicyVerdict::Block { reason, .. } => {
            // Some overlays may block shell entirely — still a useful demo signal.
            println!("   Decision: BLOCK (stricter than Confirm)");
            print_block_explanation(reason);
            println!("   Note:     Default baseline uses Confirm for execute_bash;");
            println!("             your overlay tightened it to Deny — that is OK.");
        }
        other => {
            println!("   Decision: {other:?}");
            bail!(
                "expected Confirm (REQUIRE_APPROVAL) for execute_bash with a benign command.\n\
                 Restore security baseline Confirm on execute_bash, or see mcp-proxy/mcp-policy.yaml."
            );
        }
    }
    println!();

    // ── 4. Explanation ──────────────────────────────────────────────────────
    println!("4) What just happened");
    println!("   Sqreen evaluated the Agent Action before it reached a real Tool.");
    println!("   Sensitive Resources that look like SSH keys / credential paths are denied.");
    println!("   Confirm-shaped shell tools pause for human approval (local TTY or Cloud SOC).");
    println!("   In Cursor or Claude, the same Policy runs on every MCP tools/call.");
    println!();
    println!("Next steps");
    println!("  • mcp-proxy status / mcp-proxy doctor");
    println!("  • Restart Cursor / Claude Desktop (if the installer wrapped MCP).");
    println!("  • Ask the agent to read a normal project file — it should work.");
    println!("  • Ask it to read something under .ssh — it should be blocked.");
    println!("  • HTTP agents:  mcp-proxy serve --listen 127.0.0.1:8787 \\");
    println!("                  --upstream https://api.openai.com");
    println!("                  export OPENAI_BASE_URL=http://127.0.0.1:8787/v1");
    println!("  • Docs: docs/QUICKSTART.md");
    println!();
    println!("✔  Demo passed — you have a working security control point.");
    Ok(())
}

fn print_block_explanation(reason: &str) {
    println!("   WHAT:     Agent Action `read_file` on a credential-shaped path");
    println!("   WHY:      Policy treats SSH-key / secret path patterns as denied");
    println!("   RULE:     {reason}");
    println!("   NEXT:     Use project paths; keep baseline block patterns enabled.");
    println!("             Do not disable the security baseline to “make it work”.");
}

fn explain_approval_channel() {
    let mode = ApprovalMode::from_env();
    match mode {
        ApprovalMode::Local => {
            println!("   Channel:  local TTY / stdin (SQREEN_APPROVAL_MODE=local)");
            println!("             In a real wrap, Confirm prompts on the Runtime terminal.");
            println!("             Remote IDE chats without a TTY cannot answer local prompts");
            println!("             — enroll + SQREEN_APPROVAL_MODE=remote|auto for Cloud SOC.");
        }
        ApprovalMode::Remote => {
            println!("   Channel:  remote Cloud SOC only (SQREEN_APPROVAL_MODE=remote)");
            println!("             Operators approve in the dashboard Approvals queue.");
        }
        ApprovalMode::Auto => {
            println!("   Channel:  auto — remote when cloud enrolled, else local TTY");
        }
    }
}

fn maybe_create_remote_demo_approval() {
    let mode = ApprovalMode::from_env();
    let wants_remote = matches!(mode, ApprovalMode::Remote | ApprovalMode::Auto);
    let cloud_ready = std::env::var(CONTROL_PLANE_URL_ENV)
        .ok()
        .filter(|s| !s.trim().is_empty())
        .is_some()
        && std::env::var(DEVICE_TOKEN_ENV)
            .ok()
            .filter(|s| !s.trim().is_empty())
            .is_some();

    if !(wants_remote && cloud_ready) {
        return;
    }

    let Some(client) = CloudClient::load_optional() else {
        return;
    };

    println!();
    println!("   Remote approval (optional demo step)…");

    // Synthetic destructive-*shaped action for the queue — not executed locally.
    let body = CreateRemoteApprovalBody {
        action_digest: format!(
            "demo-{}",
            chrono::Utc::now().timestamp_millis()
        ),
        tool_name: "execute_bash".into(),
        sanitized_arguments: r#"{"command":"echo sqreen-demo-destructive-shape"}"#.into(),
        agent_bound_id: None,
        agent_label: Some("mcp-proxy-demo".into()),
        agent_trust: Some("self_asserted".into()),
        execution_session_id: None,
        action_id: None,
        action_category: Some("shell".into()),
        target_resource: Some("demo".into()),
        environment: Some("non_prod".into()),
        risk_score: 75,
        risk_level: Some("high".into()),
        risk_factors: vec!["demo_confirm".into()],
        matched_policies: vec!["execute_bash:Confirm".into()],
        idempotency_key: Some(format!("demo-{}", std::process::id())),
    };

    // Block on a short runtime so the sync demo can show an approval id.
    let result = std::thread::spawn(move || {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build();
        match rt {
            Ok(rt) => rt.block_on(client.create_approval_request(body)),
            Err(err) => Err(anyhow::anyhow!("runtime: {err}")),
        }
    })
    .join();

    match result {
        Ok(Ok(status)) => {
            println!("   Approval id: {}", status.id);
            println!("   Status:      {}", status.status);
            println!("   → Open Cloud SOC → Approvals to decide this request.");
        }
        Ok(Err(err)) => {
            println!(
                "   Remote create skipped: {}",
                crate::gateway::sanitize_error(&err)
            );
            println!("   Checklist: URL, device token active, network, control plane up.");
        }
        Err(_) => {
            println!("   Remote create skipped: internal join error");
        }
    }
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
  - name: execute_bash
    action: Confirm
    block_patterns: []
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

    #[test]
    fn demo_confirm_execute_bash() {
        let engine = demo_policy();
        let params = format!(
            r#"{{"name":"execute_bash","arguments":{{"command":"{DEMO_CONFIRM_CMD}"}}}}"#
        );
        assert!(matches!(
            engine.evaluate_tools_call(&params),
            PolicyVerdict::Confirm { .. }
        ));
    }
}
