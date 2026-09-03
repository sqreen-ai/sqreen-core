//! `mcp-proxy status` — protection posture summary (no secrets).

use std::path::PathBuf;

use anyhow::Result;

use super::config::{config_dir, device_id_from_env, env_file_path, org_id_from_env};
use super::integrations::{detect_integrations, IntegrationState};
use crate::cloud_client::{CONTROL_PLANE_URL_ENV, DEVICE_TOKEN_ENV};
use crate::gateway::{ApprovalMode, EnforcementPosture};
use crate::policy::{resolve_policy_path_for_load, PolicyEngine, POLICY_PATH_ENV};

/// Snapshot used by status and support-bundle.
#[derive(Debug, Clone)]
pub struct StatusReport {
    pub protection: ProtectionState,
    pub policy_path: Option<PathBuf>,
    pub policy_version: Option<String>,
    pub tool_rules: Option<usize>,
    pub posture: String,
    pub org_id: Option<String>,
    pub device_id: Option<String>,
    pub cloud_configured: bool,
    pub cloud_url: Option<String>,
    pub device_token_present: bool,
    pub approval_mode: String,
    pub config_dir: PathBuf,
    pub env_file: PathBuf,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProtectionState {
    Active,
    Inactive,
}

impl ProtectionState {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Active => "ACTIVE",
            Self::Inactive => "INACTIVE",
        }
    }
}

/// Collects current protection status without printing secrets.
pub fn collect_status() -> StatusReport {
    let policy_path = resolve_policy_path_for_load();
    let mut policy_version = None;
    let mut tool_rules = None;
    let mut policy_loads = false;

    if let Some(ref path) = policy_path {
        if path.exists() {
            if let Ok(engine) = PolicyEngine::load(path) {
                policy_version = Some(engine.version().to_string());
                tool_rules = Some(engine.tool_count());
                policy_loads = true;
            }
        }
    }

    let cloud_url = std::env::var(CONTROL_PLANE_URL_ENV)
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .or_else(|| {
            super::config::read_env_file(&env_file_path())
                .ok()
                .and_then(|pairs| {
                    pairs.into_iter().find_map(|(k, v)| {
                        (k == CONTROL_PLANE_URL_ENV && !v.trim().is_empty()).then_some(v)
                    })
                })
        });
    let device_token_present = std::env::var(DEVICE_TOKEN_ENV)
        .ok()
        .map(|s| !s.trim().is_empty())
        .unwrap_or(false)
        || super::config::read_env_file(&env_file_path())
            .ok()
            .map(|pairs| {
                pairs.iter().any(|(k, v)| {
                    k == DEVICE_TOKEN_ENV && !v.trim().is_empty()
                })
            })
            .unwrap_or(false);
    let cloud_configured = cloud_url.is_some() && device_token_present;

    let protection = if policy_loads {
        ProtectionState::Active
    } else {
        ProtectionState::Inactive
    };

    StatusReport {
        protection,
        policy_path,
        policy_version,
        tool_rules,
        posture: EnforcementPosture::from_env().as_str().to_string(),
        org_id: org_id_from_env(),
        device_id: device_id_from_env(),
        cloud_configured,
        cloud_url,
        device_token_present,
        approval_mode: ApprovalMode::from_env().as_str().to_string(),
        config_dir: config_dir(),
        env_file: env_file_path(),
    }
}

/// Prints operator-facing status.
pub fn run_status() -> Result<()> {
    let s = collect_status();
    let version = env!("CARGO_PKG_VERSION");

    println!();
    println!("Sqreen Core (mcp-proxy) · status");
    println!("────────────────────────────────");
    println!("  Binary:           mcp-proxy {version}");
    println!("  Protection:       {}", s.protection.as_str());
    match (&s.policy_path, &s.policy_version, s.tool_rules) {
        (Some(path), Some(ver), Some(n)) => {
            println!("  Policy path:      {}", path.display());
            println!("  Policy version:   {ver} · {n} tool rules");
        }
        (Some(path), _, _) => {
            println!("  Policy path:      {} (failed to load)", path.display());
        }
        _ => {
            println!(
                "  Policy path:      (none — set {POLICY_PATH_ENV} or install policy)"
            );
        }
    }
    println!("  Posture:          {}", s.posture);
    println!(
        "  Org ID:           {}",
        s.org_id.as_deref().unwrap_or("(unset)")
    );
    println!(
        "  Device ID:        {}",
        s.device_id.as_deref().unwrap_or("(unset)")
    );
    if s.cloud_configured {
        println!(
            "  Cloud:            configured ({})",
            s.cloud_url.as_deref().unwrap_or("?")
        );
    } else {
        println!("  Cloud:            not configured (local-only)");
    }
    println!(
        "  Device token:     {}",
        if s.device_token_present {
            "[SET]"
        } else {
            "[EMPTY]"
        }
    );
    println!("  Approval mode:    {}", s.approval_mode);
    println!("  Config dir:       {}", s.config_dir.display());

    println!();
    println!("Integrations");
    for report in detect_integrations() {
        let mark = match report.state {
            IntegrationState::Active => "●",
            IntegrationState::NotConfigured => "○",
            IntegrationState::Unknown => "?",
        };
        println!(
            "  {mark} {:<26} {}",
            report.name,
            report.state.as_str()
        );
    }

    println!();
    println!("Protection boundary");
    println!("  Protected:  MCP tools/call (stdio wrap) and OpenAI/Anthropic-shaped");
    println!("              HTTP agent tool calls via `mcp-proxy serve`.");
    println!("  Not covered: model prompts themselves, IDE chat without MCP/HTTP wrap,");
    println!("               OS-level processes, IAM, or network firewalls.");
    println!();
    if s.protection == ProtectionState::Inactive {
        println!("Next: install policy (`curl -fsSL https://sqreen.ai/install.sh | bash`)");
        println!("      then `source ~/.config/mcp-proxy/env && mcp-proxy demo`");
    } else {
        println!("Next: `mcp-proxy doctor` · wrap MCP or `mcp-proxy serve`");
    }
    println!();
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    #[test]
    fn status_inactive_without_policy() {
        let _guard = crate::pilot::config::test_env_lock();
        let tmp = std::env::temp_dir().join(format!("sqreen-status-{}", std::process::id()));
        let _ = fs::remove_dir_all(&tmp);
        fs::create_dir_all(&tmp).unwrap();
        unsafe {
            std::env::set_var("HOME", &tmp);
            std::env::remove_var("XDG_CONFIG_HOME");
            std::env::remove_var("MCP_POLICY_PATH");
            std::env::remove_var("MCP_CONTROL_PLANE_URL");
            std::env::remove_var("MCP_DEVICE_TOKEN");
        }
        let report = collect_status();
        let _ = report.protection;
        let _ = fs::remove_dir_all(&tmp);
    }
}
