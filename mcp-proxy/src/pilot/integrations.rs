//! Integration detection — Cursor / Claude mcp.json wrap, hooks, control plane, OpenAI base URL.
//!
//! States are conservative:
//! - **INSTALLED** — secondary layer present (e.g. IDE hooks); not Core wrap
//! - **CONFIGURED** — wrap / enrollment / local serve target present
//! - **VERIFIED_ACTIVE** — configured **and** recent observed evidence
//!
//! Config files alone never equal verified traffic.

use std::fs;
use std::path::{Path, PathBuf};

use chrono::Utc;
use serde_json::Value;

use super::activity;

/// How an integration was detected.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IntegrationState {
    NotConfigured,
    /// Present but not Core MCP/HTTP wrap (e.g. IDE hooks).
    Installed,
    /// Wrap / credentials / local serve target configured.
    Configured,
    /// Configured plus recent trustworthy evidence (protected traffic or Cloud OK).
    VerifiedActive,
    Unknown,
}

impl IntegrationState {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::NotConfigured => "NOT_CONFIGURED",
            Self::Installed => "INSTALLED",
            Self::Configured => "CONFIGURED",
            Self::VerifiedActive => "VERIFIED_ACTIVE",
            Self::Unknown => "UNKNOWN",
        }
    }
}

#[derive(Debug, Clone)]
pub struct IntegrationReport {
    pub name: String,
    pub state: IntegrationState,
    pub detail: String,
}

/// Detects local IDE wraps, hooks, and HTTP-agent configuration.
pub fn detect_integrations() -> Vec<IntegrationReport> {
    let mut reports = Vec::new();
    reports.push(detect_cursor_mcp());
    reports.push(detect_cursor_hooks());
    reports.push(detect_claude_desktop_mcp());
    #[cfg(feature = "enterprise")]
    reports.push(detect_control_plane());
    reports.push(detect_openai_base_url());
    reports
}

/// True when a Core wrap path is configured (mcp.json wrap or local OPENAI_BASE_URL).
///
/// IDE hooks alone do **not** count.
pub fn has_core_wrap_configured(reports: &[IntegrationReport]) -> bool {
    reports.iter().any(|r| {
        let is_wrap_surface = r.name.contains("mcp.json")
            || r.name.contains("Claude Desktop")
            || r.name == "OPENAI_BASE_URL";
        is_wrap_surface
            && matches!(
                r.state,
                IntegrationState::Configured | IntegrationState::VerifiedActive
            )
    })
}

/// Prints a human-readable integrations summary.
pub fn run_integrations() -> anyhow::Result<()> {
    println!();
    println!("Sqreen Core · integrations");
    println!("──────────────────────────");
    println!("  States: INSTALLED = secondary (hooks); CONFIGURED = wrap present;");
    println!("          VERIFIED_ACTIVE = configured + recent observed evidence.");
    println!();
    for report in detect_integrations() {
        println!(
            "  {:<28} {:<16} {}",
            report.name,
            report.state.as_str(),
            report.detail
        );
    }
    println!();
    println!("Tip: `mcp-proxy integrate cursor` (Day-1), or `mcp-proxy -- run …` / `serve`.");
    println!("     IDE hooks alone do not wrap Core runtime traffic.");
    println!("     Config alone ≠ VERIFIED_ACTIVE — take a real tools/call through the wrap.");
    println!("     `mcp-proxy prove` is a gateway self-check only (does not mint VERIFIED_ACTIVE).");
    #[cfg(not(feature = "enterprise"))]
    println!("     Enterprise features are not included in this build.");
    println!();
    Ok(())
}

fn mcp_traffic_recent() -> bool {
    let snap = activity::load();
    let Some(at) = snap.last_protected_at else {
        return false;
    };
    if Utc::now().signed_duration_since(at) > activity::PROTECTED_VERIFY_WINDOW {
        return false;
    }
    matches!(
        snap.last_protected_runtime.as_deref(),
        Some("mcp_stdio" | "mcp_http")
    )
}

fn http_agent_traffic_recent() -> bool {
    let snap = activity::load();
    let Some(at) = snap.last_protected_at else {
        return false;
    };
    if Utc::now().signed_duration_since(at) > activity::PROTECTED_VERIFY_WINDOW {
        return false;
    }
    matches!(
        snap.last_protected_runtime.as_deref(),
        Some("openai_http" | "anthropic_http")
    )
}

#[cfg(feature = "enterprise")]
fn cloud_ok_recent() -> bool {
    let snap = activity::load();
    match snap.last_cloud_ok_at {
        Some(at) => Utc::now().signed_duration_since(at) <= activity::CLOUD_VERIFY_WINDOW,
        None => false,
    }
}

#[cfg(feature = "enterprise")]
fn detect_control_plane() -> IntegrationReport {
    let url = crate::local_env::lookup(crate::cloud_client::CONTROL_PLANE_URL_ENV)
        .unwrap_or_default();
    let token = crate::local_env::lookup(crate::cloud_client::DEVICE_TOKEN_ENV).unwrap_or_default();
    if !url.trim().is_empty() && !token.trim().is_empty() {
        if cloud_ok_recent() {
            IntegrationReport {
                name: "Control plane".into(),
                state: IntegrationState::VerifiedActive,
                detail: format!(
                    "enrollment CONFIGURED; recent Cloud exchange OK ({})",
                    url.trim()
                ),
            }
        } else {
            IntegrationReport {
                name: "Control plane".into(),
                state: IntegrationState::Configured,
                detail: format!(
                    "enrollment CONFIGURED ({}); connection not yet verified",
                    url.trim()
                ),
            }
        }
    } else if !url.trim().is_empty() {
        IntegrationReport {
            name: "Control plane".into(),
            state: IntegrationState::NotConfigured,
            detail: "URL set but MCP_DEVICE_TOKEN missing — run `mcp-proxy enroll`".into(),
        }
    } else {
        IntegrationReport {
            name: "Control plane".into(),
            state: IntegrationState::NotConfigured,
            detail: "MCP_CONTROL_PLANE_URL unset (local-only OK)".into(),
        }
    }
}

fn detect_openai_base_url() -> IntegrationReport {
    match std::env::var("OPENAI_BASE_URL") {
        Ok(url) if !url.trim().is_empty() => {
            let lower = url.to_ascii_lowercase();
            let local = lower.contains("127.0.0.1")
                || lower.contains("localhost")
                || lower.contains("[::1]");
            if local {
                let state = if http_agent_traffic_recent() {
                    IntegrationState::VerifiedActive
                } else {
                    IntegrationState::Configured
                };
                IntegrationReport {
                    name: "OPENAI_BASE_URL".into(),
                    state,
                    detail: format!(
                        "points at local serve ({}); traffic {}",
                        url.trim(),
                        if state == IntegrationState::VerifiedActive {
                            "verified"
                        } else {
                            "not yet verified"
                        }
                    ),
                }
            } else {
                IntegrationReport {
                    name: "OPENAI_BASE_URL".into(),
                    state: IntegrationState::Unknown,
                    detail: format!(
                        "set to {} — confirm it targets `mcp-proxy serve`",
                        url.trim()
                    ),
                }
            }
        }
        _ => IntegrationReport {
            name: "OPENAI_BASE_URL".into(),
            state: IntegrationState::NotConfigured,
            detail: "unset (HTTP agent shield not active in this shell)".into(),
        },
    }
}

fn detect_cursor_mcp() -> IntegrationReport {
    let paths = cursor_mcp_paths();
    match find_mcp_proxy_wrap(&paths) {
        Some((path, detail)) => {
            let state = if mcp_traffic_recent() {
                IntegrationState::VerifiedActive
            } else {
                IntegrationState::Configured
            };
            IntegrationReport {
                name: "Cursor mcp.json".into(),
                state,
                detail: format!(
                    "{} ({}); traffic {}",
                    detail,
                    path.display(),
                    if state == IntegrationState::VerifiedActive {
                        "verified"
                    } else {
                        "not yet verified"
                    }
                ),
            }
        }
        None if paths.iter().any(|p| p.exists()) => IntegrationReport {
            name: "Cursor mcp.json".into(),
            state: IntegrationState::NotConfigured,
            detail: "mcp.json found but no mcp-proxy wrap detected".into(),
        },
        None => IntegrationReport {
            name: "Cursor mcp.json".into(),
            state: IntegrationState::Unknown,
            detail: "no Cursor mcp.json found in common locations".into(),
        },
    }
}

fn detect_cursor_hooks() -> IntegrationReport {
    let paths = cursor_hooks_paths();
    for path in &paths {
        if hooks_look_installed(path) {
            return IntegrationReport {
                name: "Cursor IDE hooks".into(),
                state: IntegrationState::Installed,
                detail: format!(
                    "hooks present at {} — secondary path filter, not Core MCP wrap",
                    path.display()
                ),
            };
        }
    }
    IntegrationReport {
        name: "Cursor IDE hooks".into(),
        state: IntegrationState::NotConfigured,
        detail: "no project/user hooks.json with Sqreen hook script detected".into(),
    }
}

fn detect_claude_desktop_mcp() -> IntegrationReport {
    let paths = claude_desktop_mcp_paths();
    match find_mcp_proxy_wrap(&paths) {
        Some((path, detail)) => {
            let state = if mcp_traffic_recent() {
                IntegrationState::VerifiedActive
            } else {
                IntegrationState::Configured
            };
            IntegrationReport {
                name: "Claude Desktop mcp.json".into(),
                state,
                detail: format!(
                    "{} ({}); traffic {}",
                    detail,
                    path.display(),
                    if state == IntegrationState::VerifiedActive {
                        "verified"
                    } else {
                        "not yet verified"
                    }
                ),
            }
        }
        None if paths.iter().any(|p| p.exists()) => IntegrationReport {
            name: "Claude Desktop mcp.json".into(),
            state: IntegrationState::NotConfigured,
            detail: "config found but no mcp-proxy wrap detected".into(),
        },
        None => IntegrationReport {
            name: "Claude Desktop mcp.json".into(),
            state: IntegrationState::Unknown,
            detail: "no Claude Desktop config found in common locations".into(),
        },
    }
}

fn cursor_mcp_paths() -> Vec<PathBuf> {
    let mut paths = Vec::new();
    if let Some(home) = std::env::var_os("HOME") {
        let home = PathBuf::from(home);
        paths.push(home.join(".cursor/mcp.json"));
    }
    paths.push(PathBuf::from(".cursor/mcp.json"));
    paths
}

fn cursor_hooks_paths() -> Vec<PathBuf> {
    let mut paths = Vec::new();
    if let Some(home) = std::env::var_os("HOME") {
        paths.push(PathBuf::from(home).join(".cursor/hooks.json"));
    }
    paths.push(PathBuf::from(".cursor/hooks.json"));
    paths
}

fn hooks_look_installed(path: &Path) -> bool {
    let Ok(text) = fs::read_to_string(path) else {
        return false;
    };
    let lower = text.to_ascii_lowercase();
    lower.contains("block-sensitive-paths")
        || lower.contains("hooks/block-sensitive")
        || (lower.contains("beforeshellexecution") && lower.contains("hook"))
}

fn claude_desktop_mcp_paths() -> Vec<PathBuf> {
    let mut paths = Vec::new();
    if let Some(home) = std::env::var_os("HOME") {
        let home = PathBuf::from(home);
        #[cfg(target_os = "macos")]
        {
            paths.push(
                home.join("Library/Application Support/Claude/claude_desktop_config.json"),
            );
        }
        #[cfg(target_os = "linux")]
        {
            paths.push(home.join(".config/Claude/claude_desktop_config.json"));
        }
        #[cfg(target_os = "windows")]
        {
            if let Some(appdata) = std::env::var_os("APPDATA") {
                paths.push(PathBuf::from(appdata).join("Claude/claude_desktop_config.json"));
            }
        }
    }
    paths
}

fn find_mcp_proxy_wrap(paths: &[PathBuf]) -> Option<(PathBuf, String)> {
    for path in paths {
        if let Some(detail) = inspect_mcp_json(path) {
            return Some((path.clone(), detail));
        }
    }
    None
}

fn inspect_mcp_json(path: &Path) -> Option<String> {
    let text = fs::read_to_string(path).ok()?;
    let value: Value = serde_json::from_str(&text).ok()?;
    let servers = value
        .get("mcpServers")
        .or_else(|| value.get("mcp").and_then(|m| m.get("servers")))?;
    let obj = servers.as_object()?;
    let mut wrapped = 0usize;
    for (_name, server) in obj {
        let command = server
            .get("command")
            .and_then(|v| v.as_str())
            .unwrap_or("");
        let args = server
            .get("args")
            .and_then(|v| v.as_array())
            .map(|a| {
                a.iter()
                    .filter_map(|v| v.as_str())
                    .collect::<Vec<_>>()
                    .join(" ")
            })
            .unwrap_or_default();
        let blob = format!("{command} {args}");
        if blob.contains("mcp-proxy") || blob.contains("sqreen") {
            wrapped += 1;
        }
    }
    if wrapped > 0 {
        Some(format!("{wrapped} server(s) wrapped via mcp-proxy"))
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pilot::config::test_env_lock;

    #[test]
    fn detects_wrap_in_json() {
        let tmp = std::env::temp_dir().join(format!("sqreen-mcp-json-{}", std::process::id()));
        let _ = fs::remove_dir_all(&tmp);
        fs::create_dir_all(&tmp).unwrap();
        let path = tmp.join("mcp.json");
        fs::write(
            &path,
            r#"{
  "mcpServers": {
    "filesystem": {
      "command": "/Users/me/.local/bin/mcp-proxy",
      "args": ["--", "run", "npx", "-y", "@modelcontextprotocol/server-filesystem", "."]
    }
  }
}"#,
        )
        .unwrap();
        let detail = inspect_mcp_json(&path).expect("should detect wrap");
        assert!(detail.contains("1 server"));
        let _ = fs::remove_dir_all(&tmp);
    }

    #[test]
    fn wrap_config_is_configured_not_verified_without_traffic() {
        let _guard = test_env_lock();
        let tmp = std::env::temp_dir().join(format!(
            "sqreen-integ-wrap-{}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&tmp);
        fs::create_dir_all(tmp.join(".cursor")).unwrap();
        fs::create_dir_all(tmp.join(".config/mcp-proxy")).unwrap();
        unsafe {
            std::env::set_var("HOME", &tmp);
            std::env::remove_var("XDG_CONFIG_HOME");
            std::env::remove_var("OPENAI_BASE_URL");
            std::env::remove_var("MCP_CONTROL_PLANE_URL");
            std::env::remove_var("MCP_DEVICE_TOKEN");
        }
        fs::write(
            tmp.join(".cursor/mcp.json"),
            r#"{"mcpServers":{"fs":{"command":"mcp-proxy","args":["--","run","true"]}}}"#,
        )
        .unwrap();
        let reports = detect_integrations();
        let cursor = reports
            .iter()
            .find(|r| r.name.contains("Cursor mcp"))
            .unwrap();
        assert_eq!(cursor.state, IntegrationState::Configured);
        assert!(has_core_wrap_configured(&reports));
        let _ = fs::remove_dir_all(&tmp);
    }

    #[cfg(feature = "enterprise")]
    #[test]
    fn enrollment_alone_is_configured_not_verified() {
        let _guard = test_env_lock();
        let tmp = std::env::temp_dir().join(format!(
            "sqreen-integ-enroll-{}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&tmp);
        fs::create_dir_all(tmp.join(".config/mcp-proxy")).unwrap();
        unsafe {
            std::env::set_var("HOME", &tmp);
            std::env::remove_var("XDG_CONFIG_HOME");
            std::env::remove_var("MCP_CONTROL_PLANE_URL");
            std::env::remove_var("MCP_DEVICE_TOKEN");
            std::env::remove_var("OPENAI_BASE_URL");
        }
        crate::pilot::config::upsert_env_file(&[
            ("MCP_CONTROL_PLANE_URL", "http://127.0.0.1:9"),
            ("MCP_DEVICE_TOKEN", "tok"),
        ])
        .unwrap();
        let reports = detect_integrations();
        let cp = reports.iter().find(|r| r.name == "Control plane").unwrap();
        assert_eq!(cp.state, IntegrationState::Configured);
        assert!(!cp.detail.to_ascii_lowercase().contains("connected"));
        let _ = fs::remove_dir_all(&tmp);
    }
}
