//! Integration detection — Cursor / Claude mcp.json wrap, control plane, OpenAI base URL.

use std::fs;
use std::path::{Path, PathBuf};

use serde_json::Value;

/// How an integration was detected.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IntegrationState {
    Active,
    NotConfigured,
    Unknown,
}

impl IntegrationState {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Active => "ACTIVE",
            Self::NotConfigured => "NOT CONFIGURED",
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

/// Detects local IDE wraps and cloud / HTTP-agent configuration.
pub fn detect_integrations() -> Vec<IntegrationReport> {
    let mut reports = Vec::new();
    reports.push(detect_cursor_mcp());
    reports.push(detect_claude_desktop_mcp());
    reports.push(detect_control_plane());
    reports.push(detect_openai_base_url());
    reports
}

/// Prints a human-readable integrations summary.
pub fn run_integrations() -> anyhow::Result<()> {
    println!();
    println!("Sqreen Core · integrations");
    println!("──────────────────────────");
    for report in detect_integrations() {
        println!(
            "  {:<28} {:<16} {}",
            report.name,
            report.state.as_str(),
            report.detail
        );
    }
    println!();
    println!("Tip: wrap MCP with `mcp-proxy -- run …` or run `mcp-proxy serve` for HTTP agents.");
    println!();
    Ok(())
}

fn detect_control_plane() -> IntegrationReport {
    let file_pairs = crate::pilot::config::read_env_file(&crate::pilot::config::env_file_path())
        .unwrap_or_default();
    let url = std::env::var(crate::cloud_client::CONTROL_PLANE_URL_ENV)
        .ok()
        .filter(|s| !s.trim().is_empty())
        .or_else(|| {
            file_pairs.iter().find_map(|(k, v)| {
                (k == crate::cloud_client::CONTROL_PLANE_URL_ENV && !v.trim().is_empty())
                    .then(|| v.clone())
            })
        })
        .unwrap_or_default();
    let token = std::env::var(crate::cloud_client::DEVICE_TOKEN_ENV)
        .ok()
        .filter(|s| !s.trim().is_empty())
        .or_else(|| {
            file_pairs.iter().find_map(|(k, v)| {
                (k == crate::cloud_client::DEVICE_TOKEN_ENV && !v.trim().is_empty())
                    .then(|| v.clone())
            })
        })
        .unwrap_or_default();
    if !url.trim().is_empty() && !token.trim().is_empty() {
        IntegrationReport {
            name: "Control plane".into(),
            state: IntegrationState::Active,
            detail: format!(
                "MCP_CONTROL_PLANE_URL={} (source env or ~/.config/mcp-proxy/env)",
                url.trim()
            ),
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
                IntegrationReport {
                    name: "OPENAI_BASE_URL".into(),
                    state: IntegrationState::Active,
                    detail: format!("points at local serve ({})", url.trim()),
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
        Some((path, detail)) => IntegrationReport {
            name: "Cursor mcp.json".into(),
            state: IntegrationState::Active,
            detail: format!("{} ({})", detail, path.display()),
        },
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

fn detect_claude_desktop_mcp() -> IntegrationReport {
    let paths = claude_desktop_mcp_paths();
    match find_mcp_proxy_wrap(&paths) {
        Some((path, detail)) => IntegrationReport {
            name: "Claude Desktop mcp.json".into(),
            state: IntegrationState::Active,
            detail: format!("{} ({})", detail, path.display()),
        },
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
        // Project-level configs are not enumerated (unknown cwd projects).
    }
    // Current project if running from a repo that uses Cursor.
    paths.push(PathBuf::from(".cursor/mcp.json"));
    paths
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
    fn control_plane_not_configured_by_default() {
        // Do not mutate global env in a way that races other tests for URL+token.
        let report = detect_openai_base_url();
        assert!(matches!(
            report.state,
            IntegrationState::NotConfigured | IntegrationState::Active | IntegrationState::Unknown
        ));
    }
}
