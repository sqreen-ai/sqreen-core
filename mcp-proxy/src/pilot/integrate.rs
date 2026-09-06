//! `mcp-proxy integrate cursor` — wrap Cursor MCP config for Day-1.

use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::{bail, Context, Result};
use serde_json::{json, Value};

use super::config::config_dir;
use super::day1::{self, INTEGRATE_COMMAND, PRIMARY_RUNTIME, PROVE_COMMAND};
use crate::policy::resolve_policy_path_for_load;

/// Runs `mcp-proxy integrate <target>`.
pub fn run_integrate(target: &str) -> Result<()> {
    match target.trim().to_ascii_lowercase().as_str() {
        "cursor" => integrate_cursor(),
        other => bail!(
            "unknown integrate target `{other}`\n\
             Usage: {INTEGRATE_COMMAND}\n\
             Primary Day-1 path: {PRIMARY_RUNTIME}"
        ),
    }
}

fn integrate_cursor() -> Result<()> {
    let proxy_bin = current_proxy_bin()?;
    let policy = resolve_policy_path_for_load()
        .filter(|p| p.exists())
        .unwrap_or_else(|| config_dir().join("mcp-policy.yaml"));
    let threat = config_dir().join("threat-intel.txt");

    let path = cursor_mcp_path();
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("failed to create {}", parent.display()))?;
    }

    let (action, servers_wrapped) = if path.exists() {
        backup_file(&path)?;
        let wrapped = wrap_existing_mcp_json(&path, &proxy_bin, &policy, &threat)?;
        ("updated", wrapped)
    } else {
        write_seed_mcp_json(&path, &proxy_bin, &policy, &threat)?;
        ("created", 1usize)
    };

    println!();
    println!("Sqreen Core · integrate cursor");
    println!("──────────────────────────────");
    println!("  Primary path:   {PRIMARY_RUNTIME}");
    println!("  mcp.json:       {} ({action})", path.display());
    println!("  Proxy binary:   {}", proxy_bin.display());
    println!("  Policy:         {}", policy.display());
    println!("  Servers wrapped:{servers_wrapped}");
    println!();
    println!("IMPORTANT");
    println!("  Config alone is NOT protection.");
    println!("  Runtime coverage is CONFIGURED until Cursor reloads MCP and one");
    println!("  real tools/call passes through mcp-proxy.");
    println!();
    println!("Next:");
    println!("  1. Restart Cursor (or Command Palette → MCP: Restart Servers)");
    println!("  2. Ask Cursor to read {}", day1::DAY1_ALLOW_PATH);
    println!(
        "     (`{}` = gateway self-check only — does not mint VERIFIED_ACTIVE)",
        PROVE_COMMAND
    );
    println!("  3. `mcp-proxy status`  → Runtime coverage: VERIFIED_ACTIVE");
    println!("  4. Ask Cursor to read {} (safe DENY)", day1::DAY1_DENY_PATH);
    println!();
    Ok(())
}

fn current_proxy_bin() -> Result<PathBuf> {
    if let Ok(exe) = env::current_exe() {
        if exe.exists() {
            return Ok(exe);
        }
    }
    // Fallbacks when tests invoke via cargo.
    for candidate in [
        dirs_home_local_bin(),
        Some(PathBuf::from("mcp-proxy")),
    ]
    .into_iter()
    .flatten()
    {
        if which_exists(&candidate) {
            return Ok(candidate);
        }
    }
    bail!("could not locate mcp-proxy binary for wrap command")
}

fn dirs_home_local_bin() -> Option<PathBuf> {
    let home = env::var_os("HOME")?;
    Some(PathBuf::from(home).join(".local/bin/mcp-proxy"))
}

fn which_exists(path: &Path) -> bool {
    if path.is_absolute() {
        return path.exists();
    }
    Command::new("which")
        .arg(path)
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

fn cursor_mcp_path() -> PathBuf {
    let home = env::var_os("HOME").unwrap_or_else(|| "/tmp".into());
    PathBuf::from(home).join(".cursor/mcp.json")
}

fn backup_file(path: &Path) -> Result<()> {
    let stamp = chrono::Utc::now().format("%Y%m%d%H%M%S");
    let backup = path.with_extension(format!("json.bak.{stamp}"));
    fs::copy(path, &backup)
        .with_context(|| format!("failed to backup {}", path.display()))?;
    println!("  Backup:         {}", backup.display());
    Ok(())
}

fn write_seed_mcp_json(
    path: &Path,
    proxy: &Path,
    policy: &Path,
    threat: &Path,
) -> Result<()> {
    let mut env_map = serde_json::Map::new();
    env_map.insert(
        "MCP_POLICY_PATH".into(),
        Value::String(policy.display().to_string()),
    );
    if threat.exists() {
        env_map.insert(
            "MCP_THREAT_INTEL_PATH".into(),
            Value::String(threat.display().to_string()),
        );
    }
    let doc = json!({
        "mcpServers": {
            "filesystem": {
                "command": proxy.display().to_string(),
                "args": [
                    "--",
                    "run",
                    "npx",
                    "-y",
                    "@modelcontextprotocol/server-filesystem",
                    "."
                ],
                "env": env_map
            }
        }
    });
    fs::write(path, format!("{}\n", serde_json::to_string_pretty(&doc)?))
        .with_context(|| format!("failed to write {}", path.display()))?;
    Ok(())
}

fn wrap_existing_mcp_json(
    path: &Path,
    proxy: &Path,
    policy: &Path,
    threat: &Path,
) -> Result<usize> {
    let text = fs::read_to_string(path)
        .with_context(|| format!("failed to read {}", path.display()))?;
    let mut data: Value =
        serde_json::from_str(&text).with_context(|| format!("invalid JSON in {}", path.display()))?;
    let servers = data
        .get_mut("mcpServers")
        .and_then(|v| v.as_object_mut())
        .ok_or_else(|| {
            anyhow::anyhow!(
                "{} has no mcpServers object — re-run after adding an MCP server, or delete the file to seed a filesystem wrap",
                path.display()
            )
        })?;

    let mut wrapped = 0usize;
    let proxy_s = proxy.display().to_string();
    let policy_s = policy.display().to_string();
    let threat_s = threat.display().to_string();

    for (_name, cfg) in servers.iter_mut() {
        let Some(obj) = cfg.as_object_mut() else {
            continue;
        };
        let command = obj
            .get("command")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        if command.contains("mcp-proxy") || command.contains("sqreen") {
            // Ensure policy env is present on already-wrapped entries.
            let env = obj.entry("env").or_insert_with(|| json!({}));
            if let Some(env_obj) = env.as_object_mut() {
                env_obj
                    .entry("MCP_POLICY_PATH")
                    .or_insert_with(|| Value::String(policy_s.clone()));
                if Path::new(&threat_s).exists() {
                    env_obj
                        .entry("MCP_THREAT_INTEL_PATH")
                        .or_insert_with(|| Value::String(threat_s.clone()));
                }
            }
            wrapped += 1;
            continue;
        }
        let args = obj
            .get("args")
            .and_then(|v| v.as_array())
            .cloned()
            .unwrap_or_default();
        let mut new_args = vec![
            Value::String("--".into()),
            Value::String("run".into()),
            Value::String(command),
        ];
        new_args.extend(args);

        let mut env = obj
            .get("env")
            .and_then(|v| v.as_object())
            .cloned()
            .unwrap_or_default();
        env.insert("MCP_POLICY_PATH".into(), Value::String(policy_s.clone()));
        if Path::new(&threat_s).exists() {
            env.entry("MCP_THREAT_INTEL_PATH".to_string())
                .or_insert_with(|| Value::String(threat_s.clone()));
        }

        obj.clear();
        obj.insert("command".into(), Value::String(proxy_s.clone()));
        obj.insert("args".into(), Value::Array(new_args));
        obj.insert("env".into(), Value::Object(env));
        wrapped += 1;
    }

    if wrapped == 0 {
        // Empty mcpServers — seed filesystem.
        write_seed_mcp_json(path, proxy, policy, threat)?;
        return Ok(1);
    }

    fs::write(path, format!("{}\n", serde_json::to_string_pretty(&data)?))
        .with_context(|| format!("failed to write {}", path.display()))?;
    Ok(wrapped)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pilot::config::test_env_lock;

    #[test]
    fn seeds_cursor_mcp_when_missing() {
        let _guard = test_env_lock();
        let tmp = std::env::temp_dir().join(format!("sqreen-integ-{}", std::process::id()));
        let _ = fs::remove_dir_all(&tmp);
        fs::create_dir_all(tmp.join(".config/mcp-proxy")).unwrap();
        let policy = tmp.join(".config/mcp-proxy/mcp-policy.yaml");
        fs::write(&policy, "version: \"1\"\nglobal:\n  block_patterns: []\ntools: []\n").unwrap();
        unsafe {
            std::env::set_var("HOME", &tmp);
            std::env::remove_var("XDG_CONFIG_HOME");
            std::env::set_var("MCP_POLICY_PATH", &policy);
        }
        integrate_cursor().unwrap();
        let mcp = tmp.join(".cursor/mcp.json");
        let text = fs::read_to_string(&mcp).unwrap();
        assert!(text.contains("mcp-proxy") || text.contains("run"));
        assert!(text.contains("MCP_POLICY_PATH"));
        let _ = fs::remove_dir_all(&tmp);
    }

    #[test]
    fn wraps_existing_unwrapped_server() {
        let _guard = test_env_lock();
        let tmp = std::env::temp_dir().join(format!("sqreen-integ2-{}", std::process::id()));
        let _ = fs::remove_dir_all(&tmp);
        fs::create_dir_all(tmp.join(".cursor")).unwrap();
        fs::create_dir_all(tmp.join(".config/mcp-proxy")).unwrap();
        let policy = tmp.join(".config/mcp-proxy/mcp-policy.yaml");
        fs::write(&policy, "version: \"1\"\nglobal:\n  block_patterns: []\ntools: []\n").unwrap();
        fs::write(
            tmp.join(".cursor/mcp.json"),
            r#"{"mcpServers":{"fs":{"command":"npx","args":["-y","@modelcontextprotocol/server-filesystem","."]}}}"#,
        )
        .unwrap();
        unsafe {
            std::env::set_var("HOME", &tmp);
            std::env::remove_var("XDG_CONFIG_HOME");
            std::env::set_var("MCP_POLICY_PATH", &policy);
        }
        integrate_cursor().unwrap();
        let text = fs::read_to_string(tmp.join(".cursor/mcp.json")).unwrap();
        assert!(text.contains("\"--\""));
        assert!(text.contains("run"));
        let _ = fs::remove_dir_all(&tmp);
    }
}
