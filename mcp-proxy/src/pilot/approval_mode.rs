//! `mcp-proxy approval-mode` — persist SQREEN_APPROVAL_MODE without manual env editing.

use anyhow::{bail, Result};

use super::config::{env_file_path, upsert_env_file};
use crate::gateway::approval::APPROVAL_MODE_ENV;

/// Sets local|remote|auto in ~/.config/mcp-proxy/env (0600).
pub fn run_approval_mode(mode: &str) -> Result<()> {
    let normalized = mode.trim().to_ascii_lowercase();
    match normalized.as_str() {
        "local" | "remote" | "auto" => {}
        _ => bail!(
            "unknown approval mode `{mode}`\n\
             Usage: mcp-proxy approval-mode <local|remote|auto>\n\
             Prefer `remote` for Cloud SOC human gates after enroll + VERIFIED connection."
        ),
    }

    let path = upsert_env_file(&[(APPROVAL_MODE_ENV, &normalized)])?;
    // Also set process env for this session.
    std::env::set_var(APPROVAL_MODE_ENV, &normalized);

    println!();
    println!("Sqreen Core · approval-mode");
    println!("───────────────────────────");
    println!("  Wrote:  {}", path.display());
    println!("  {APPROVAL_MODE_ENV}={normalized}");
    println!();
    if normalized == "remote" {
        println!("Next:");
        println!("  1. Restart Cursor / reload MCP (wrapped process must reload env)");
        println!("  2. mcp-proxy test-remote-approval");
        println!("  3. Approve or deny in Cloud SOC → Approvals");
    } else {
        println!("Restart Cursor / reload MCP so the wrapped runtime picks up the mode.");
    }
    println!();
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pilot::config::test_env_lock;

    #[test]
    fn persists_remote_mode() {
        let _guard = test_env_lock();
        let tmp = std::env::temp_dir().join(format!("sqreen-apr-mode-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&tmp);
        std::fs::create_dir_all(tmp.join(".config/mcp-proxy")).unwrap();
        unsafe {
            std::env::set_var("HOME", &tmp);
            std::env::remove_var("XDG_CONFIG_HOME");
        }
        run_approval_mode("remote").unwrap();
        let text = std::fs::read_to_string(env_file_path()).unwrap();
        assert!(text.contains("SQREEN_APPROVAL_MODE=remote") || text.contains("SQREEN_APPROVAL_MODE=\"remote\""));
        let _ = std::fs::remove_dir_all(&tmp);
    }
}
