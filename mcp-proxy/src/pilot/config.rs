//! Shared config-dir helpers for pilot / onboarding commands.
//!
//! Never print device tokens or other secrets. Redact as `[SET]` / `[EMPTY]`.

use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};

/// Serializes tests that mutate process-global env (`HOME`, policy path, etc.).
#[cfg(test)]
pub fn test_env_lock() -> std::sync::MutexGuard<'static, ()> {
    use std::sync::{Mutex, OnceLock};
    static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| Mutex::new(()))
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

/// Config directory: `~/.config/mcp-proxy` (or `$XDG_CONFIG_HOME/mcp-proxy`).
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

/// Path to the shell env file seeded by install / enroll.
pub fn env_file_path() -> PathBuf {
    config_dir().join("env")
}

/// Ensures the config directory exists with restrictive permissions when possible.
pub fn ensure_config_dir() -> Result<PathBuf> {
    let dir = config_dir();
    fs::create_dir_all(&dir).with_context(|| format!("failed to create {}", dir.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = fs::set_permissions(&dir, fs::Permissions::from_mode(0o700));
    }
    Ok(dir)
}

/// Secret-ish env key names — values must never be printed.
pub fn is_secret_env_key(key: &str) -> bool {
    let upper = key.to_ascii_uppercase();
    upper.contains("TOKEN")
        || upper.contains("SECRET")
        || upper.contains("PASSWORD")
        || upper.contains("PRIVATE_KEY")
        || upper.contains("API_KEY")
        || upper == "AUTHORIZATION"
}

/// Returns `[SET]` or `[EMPTY]` for secret values; otherwise the trimmed value.
pub fn redact_env_value(key: &str, value: &str) -> String {
    if is_secret_env_key(key) {
        if value.trim().is_empty() {
            "[EMPTY]".to_string()
        } else {
            "[SET]".to_string()
        }
    } else if value.trim().is_empty() {
        "[EMPTY]".to_string()
    } else {
        value.trim().to_string()
    }
}

/// Reads `KEY=VALUE` lines from an env-style file (no shell expansion).
pub fn read_env_file(path: &Path) -> Result<Vec<(String, String)>> {
    if !path.exists() {
        return Ok(Vec::new());
    }
    let text = fs::read_to_string(path)
        .with_context(|| format!("failed to read {}", path.display()))?;
    Ok(parse_env_lines(&text))
}

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
        if (value.starts_with('"') && value.ends_with('"'))
            || (value.starts_with('\'') && value.ends_with('\''))
        {
            value = value[1..value.len() - 1].to_string();
        }
        if !key.is_empty() {
            out.push((key, value));
        }
    }
    out
}

/// Upserts keys into `~/.config/mcp-proxy/env` and sets mode 0600.
///
/// Never echoes secret values. Existing non-touched keys are preserved.
pub fn upsert_env_file(updates: &[(&str, &str)]) -> Result<PathBuf> {
    let dir = ensure_config_dir()?;
    let path = dir.join("env");
    let mut map: std::collections::BTreeMap<String, String> = read_env_file(&path)?
        .into_iter()
        .collect();

    for (key, value) in updates {
        if key.trim().is_empty() {
            bail!("env key must not be empty");
        }
        map.insert((*key).to_string(), (*value).to_string());
    }

    let mut body = String::from("# mcp-proxy / Sqreen Core local env — do not commit\n");
    for (key, value) in &map {
        let needs_quote = value
            .chars()
            .any(|c| c.is_whitespace() || "#$\"'\\".contains(c));
        if needs_quote {
            let escaped = value.replace('\\', "\\\\").replace('"', "\\\"");
            body.push_str(&format!("export {key}=\"{escaped}\"\n"));
        } else {
            body.push_str(&format!("export {key}={value}\n"));
        }
    }

    fs::write(&path, body).with_context(|| format!("failed to write {}", path.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600))
            .with_context(|| format!("failed to chmod 0600 {}", path.display()))?;
    }
    Ok(path)
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

/// Non-secret org id from env (may be empty).
pub fn org_id_from_env() -> Option<String> {
    std::env::var(crate::policy::ORG_ID_ENV)
        .ok()
        .or_else(|| std::env::var(crate::policy::ORG_ID_ENV_ALT).ok())
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
}

/// Non-secret device id from env (may be empty).
pub fn device_id_from_env() -> Option<String> {
    std::env::var(crate::cloud_client::DEVICE_ID_ENV)
        .ok()
        .or_else(|| std::env::var(crate::cloud_client::DEVICE_ID_ENV_LEGACY).ok())
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn redacts_tokens() {
        assert_eq!(redact_env_value("MCP_DEVICE_TOKEN", "secret-value"), "[SET]");
        assert_eq!(redact_env_value("MCP_DEVICE_TOKEN", ""), "[EMPTY]");
        assert_eq!(
            redact_env_value("MCP_CONTROL_PLANE_URL", "http://localhost:8080"),
            "http://localhost:8080"
        );
    }

    #[test]
    fn parses_export_lines() {
        let lines = parse_env_lines(
            "# comment\nexport FOO=bar\nBAZ=\"hello world\"\nexport MCP_DEVICE_TOKEN=sekret\n",
        );
        assert_eq!(lines.len(), 3);
        assert_eq!(lines[0], ("FOO".into(), "bar".into()));
        assert_eq!(lines[1], ("BAZ".into(), "hello world".into()));
        assert_eq!(lines[2].0, "MCP_DEVICE_TOKEN");
    }

    #[test]
    fn upsert_preserves_and_redacts() {
        let _guard = test_env_lock();
        let tmp = std::env::temp_dir().join(format!("sqreen-pilot-env-{}", std::process::id()));
        let _ = fs::remove_dir_all(&tmp);
        fs::create_dir_all(&tmp).unwrap();
        // SAFETY: test-only HOME override for isolation.
        unsafe {
            std::env::set_var("HOME", &tmp);
            std::env::remove_var("XDG_CONFIG_HOME");
        }
        let path = upsert_env_file(&[
            ("MCP_CONTROL_PLANE_URL", "http://127.0.0.1:8080"),
            ("MCP_DEVICE_TOKEN", "tok-abc"),
        ])
        .unwrap();
        assert!(path.exists());
        let pairs = read_env_file(&path).unwrap();
        let map: std::collections::BTreeMap<_, _> = pairs.into_iter().collect();
        assert_eq!(
            map.get("MCP_CONTROL_PLANE_URL").map(String::as_str),
            Some("http://127.0.0.1:8080")
        );
        assert_eq!(
            map.get("MCP_DEVICE_TOKEN").map(String::as_str),
            Some("tok-abc")
        );
        assert_eq!(redact_env_value("MCP_DEVICE_TOKEN", "tok-abc"), "[SET]");
        let _ = fs::remove_dir_all(&tmp);
    }
}
