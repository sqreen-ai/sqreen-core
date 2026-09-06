//! Local enrollment / shell env file (`~/.config/mcp-proxy/env`).
//!
//! Shared by the runtime ([`crate::cloud_client`]) and pilot CLI so a Cursor/MCP wrap
//! process can discover Cloud credentials after `mcp-proxy enroll` without injecting
//! secrets into `mcp.json`.
//!
//! # Precedence
//!
//! For each key, [`lookup`] resolves:
//! 1. Process environment (non-empty after trim) — explicit override
//! 2. Persisted enrollment file (`env_file_path`) — from `enroll` / install
//! 3. Absent
//!
//! Missing or unreadable files are treated as empty (local-only Core).

use std::fs;
use std::path::{Path, PathBuf};

/// Serializes tests that mutate process-global env (`HOME`, enrollment path, etc.).
#[cfg(test)]
pub fn test_env_lock() -> std::sync::MutexGuard<'static, ()> {
    use std::sync::{Mutex, OnceLock};
    static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| Mutex::new(()))
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

/// Config directory: `$XDG_CONFIG_HOME/mcp-proxy` or `~/.config/mcp-proxy`.
pub fn config_dir() -> PathBuf {
    if let Ok(xdg) = std::env::var("XDG_CONFIG_HOME") {
        let trimmed = xdg.trim();
        if !trimmed.is_empty() {
            return PathBuf::from(trimmed).join("mcp-proxy");
        }
    }
    let home = std::env::var_os("HOME").unwrap_or_else(|| "/tmp".into());
    PathBuf::from(home).join(".config/mcp-proxy")
}

/// Path to the enrollment / shell env file.
pub fn env_file_path() -> PathBuf {
    config_dir().join("env")
}

/// Reads `KEY=VALUE` / `export KEY=VALUE` lines (no shell expansion).
pub fn read_env_file(path: &Path) -> std::io::Result<Vec<(String, String)>> {
    if !path.exists() {
        return Ok(Vec::new());
    }
    let text = fs::read_to_string(path)?;
    Ok(parse_env_lines(&text))
}

/// Parses env-style lines from a string.
pub fn parse_env_lines(text: &str) -> Vec<(String, String)> {
    let mut out = Vec::new();
    for line in text.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        let body = trimmed.strip_prefix("export ").unwrap_or(trimmed);
        let Some((key, value)) = body.split_once('=') else {
            continue;
        };
        let key = key.trim().to_string();
        let mut value = value.trim().to_string();
        if (value.starts_with('"') && value.ends_with('"') && value.len() >= 2)
            || (value.starts_with('\'') && value.ends_with('\'') && value.len() >= 2)
        {
            value = value[1..value.len() - 1].to_string();
        }
        if !key.is_empty() {
            out.push((key, value));
        }
    }
    out
}

/// Looks up `key` with process-env-first, then enrollment file.
///
/// Never logs or returns a reason that embeds the value.
pub fn lookup(key: &str) -> Option<String> {
    if let Ok(raw) = std::env::var(key) {
        let trimmed = raw.trim().to_string();
        if !trimmed.is_empty() {
            return Some(trimmed);
        }
    }
    lookup_file_only(key)
}

/// Enrollment-file value only (ignores process env). Used by tests and diagnostics.
pub fn lookup_file_only(key: &str) -> Option<String> {
    let path = env_file_path();
    let pairs = match read_env_file(&path) {
        Ok(pairs) => pairs,
        Err(_) => return None,
    };
    pairs.into_iter().find_map(|(k, v)| {
        if k == key {
            let trimmed = v.trim().to_string();
            if trimmed.is_empty() {
                None
            } else {
                Some(trimmed)
            }
        } else {
            None
        }
    })
}

/// Unix mode bits for a path, if available.
#[cfg(unix)]
pub fn file_mode(path: &Path) -> Option<u32> {
    use std::os::unix::fs::PermissionsExt;
    fs::metadata(path)
        .ok()
        .map(|m| m.permissions().mode() & 0o777)
}

#[cfg(not(unix))]
pub fn file_mode(_path: &Path) -> Option<u32> {
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_export_and_quotes() {
        let lines = parse_env_lines(
            "# c\nexport FOO=bar\nBAZ=\"hello world\"\nexport EMPTY=\nMCP_DEVICE_TOKEN=sekret\n",
        );
        assert_eq!(lines[0], ("FOO".into(), "bar".into()));
        assert_eq!(lines[1], ("BAZ".into(), "hello world".into()));
        assert_eq!(lines[2], ("EMPTY".into(), "".into()));
        assert_eq!(lines[3].0, "MCP_DEVICE_TOKEN");
    }

    #[test]
    fn process_env_overrides_file() {
        let _guard = test_env_lock();
        let tmp = std::env::temp_dir().join(format!("sqreen-local-env-{}", std::process::id()));
        let _ = fs::remove_dir_all(&tmp);
        fs::create_dir_all(tmp.join(".config/mcp-proxy")).unwrap();
        unsafe {
            std::env::set_var("HOME", &tmp);
            std::env::remove_var("XDG_CONFIG_HOME");
            std::env::remove_var("MCP_CONTROL_PLANE_URL");
        }
        fs::write(
            tmp.join(".config/mcp-proxy/env"),
            "export MCP_CONTROL_PLANE_URL=https://from-file.example\n",
        )
        .unwrap();
        assert_eq!(
            lookup("MCP_CONTROL_PLANE_URL").as_deref(),
            Some("https://from-file.example")
        );
        unsafe {
            std::env::set_var("MCP_CONTROL_PLANE_URL", "https://from-process.example");
        }
        assert_eq!(
            lookup("MCP_CONTROL_PLANE_URL").as_deref(),
            Some("https://from-process.example")
        );
        unsafe {
            std::env::remove_var("MCP_CONTROL_PLANE_URL");
        }
        let _ = fs::remove_dir_all(&tmp);
    }

    #[test]
    fn missing_file_is_absent() {
        let _guard = test_env_lock();
        let tmp = std::env::temp_dir().join(format!("sqreen-local-env-miss-{}", std::process::id()));
        let _ = fs::remove_dir_all(&tmp);
        fs::create_dir_all(&tmp).unwrap();
        unsafe {
            std::env::set_var("HOME", &tmp);
            std::env::remove_var("XDG_CONFIG_HOME");
            std::env::remove_var("MCP_DEVICE_TOKEN");
        }
        assert!(lookup("MCP_DEVICE_TOKEN").is_none());
        let _ = fs::remove_dir_all(&tmp);
    }
}
