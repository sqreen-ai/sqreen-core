//! `mcp-proxy support-bundle` — redacted diagnostics directory for pilot support.

use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use chrono::Utc;

use super::config::{
    config_dir, env_file_path, file_mode, read_env_file, redact_env_value,
};
use super::doctor::{format_doctor_report, run_doctor_checks};
use super::integrations::detect_integrations;
use super::status::collect_status;
use crate::policy::{resolve_policy_path_for_load, PolicyEngine};

/// Writes a support bundle under `/tmp` (or `out_dir` if provided) and prints the path.
pub async fn run_support_bundle(out_dir: Option<PathBuf>) -> Result<PathBuf> {
    let stamp = Utc::now().format("%Y%m%dT%H%M%SZ");
    let base = out_dir.unwrap_or_else(|| {
        std::env::temp_dir().join(format!("sqreen-support-bundle-{stamp}"))
    });
    fs::create_dir_all(&base)
        .with_context(|| format!("failed to create {}", base.display()))?;

    write_version(&base)?;
    write_os_info(&base)?;
    write_redacted_env(&base)?;
    write_status(&base)?;
    write_integrations(&base)?;
    write_policy_meta(&base)?;
    write_doctor(&base).await?;

    println!();
    println!("Sqreen Core · support bundle");
    println!("────────────────────────────");
    println!("  Path: {}", base.display());
    println!("  Contents are redacted — inspect before sharing.");
    println!("  Secrets appear as [SET]/[EMPTY] only.");
    println!();
    Ok(base)
}

fn write_version(base: &Path) -> Result<()> {
    let body = format!(
        "product: Sqreen Core (mcp-proxy)\nversion: {}\n",
        env!("CARGO_PKG_VERSION")
    );
    fs::write(base.join("version.txt"), body)?;
    Ok(())
}

fn write_os_info(base: &Path) -> Result<()> {
    let body = format!(
        "os: {}\narch: {}\nfamily: {}\n",
        std::env::consts::OS,
        std::env::consts::ARCH,
        std::env::consts::FAMILY
    );
    fs::write(base.join("os.txt"), body)?;
    Ok(())
}

fn write_redacted_env(base: &Path) -> Result<()> {
    let mut body = String::from("# Redacted env (process + config file)\n");

    let interesting = [
        "MCP_POLICY_PATH",
        "MCP_CONTROL_PLANE_URL",
        "MCP_DEVICE_TOKEN",
        "SQREEN_DEVICE_ID",
        "MCP_DEVICE_ID",
        "SQREEN_ORG_ID",
        "MCP_ORGANIZATION_ID",
        "SQREEN_APPROVAL_MODE",
        "SQREEN_ENFORCEMENT_POSTURE",
        "OPENAI_BASE_URL",
        "MCP_PROXY_LOG",
    ];
    body.push_str("\n## process env\n");
    for key in interesting {
        let raw = std::env::var(key).unwrap_or_default();
        body.push_str(&format!("{key}={}\n", redact_env_value(key, &raw)));
    }

    let env_path = env_file_path();
    body.push_str(&format!("\n## config file ({})\n", env_path.display()));
    if env_path.exists() {
        if let Some(mode) = file_mode(&env_path) {
            body.push_str(&format!("mode: {mode:04o}\n"));
        }
        for (k, v) in read_env_file(&env_path)? {
            body.push_str(&format!("{k}={}\n", redact_env_value(&k, &v)));
        }
    } else {
        body.push_str("(missing)\n");
    }

    body.push_str(&format!("\n## config_dir\n{}\n", config_dir().display()));
    fs::write(base.join("env.redacted.txt"), body)?;
    Ok(())
}

fn write_status(base: &Path) -> Result<()> {
    let s = collect_status();
    let body = format!(
        "protection: {}\npolicy_path: {}\npolicy_version: {}\ntool_rules: {}\nposture: {}\norg_id: {}\ndevice_id: {}\ncloud_configured: {}\ncloud_url: {}\ndevice_token: {}\napproval_mode: {}\n",
        s.protection.as_str(),
        s.policy_path
            .as_ref()
            .map(|p| p.display().to_string())
            .unwrap_or_else(|| "(none)".into()),
        s.policy_version.as_deref().unwrap_or("(none)"),
        s.tool_rules
            .map(|n| n.to_string())
            .unwrap_or_else(|| "(none)".into()),
        s.posture,
        s.org_id.as_deref().unwrap_or("(unset)"),
        s.device_id.as_deref().unwrap_or("(unset)"),
        s.cloud_configured,
        s.cloud_url.as_deref().unwrap_or("(unset)"),
        if s.device_token_present {
            "[SET]"
        } else {
            "[EMPTY]"
        },
        s.approval_mode,
    );
    fs::write(base.join("status.txt"), body)?;
    Ok(())
}

fn write_integrations(base: &Path) -> Result<()> {
    let mut body = String::new();
    for report in detect_integrations() {
        body.push_str(&format!(
            "{} | {} | {}\n",
            report.name,
            report.state.as_str(),
            report.detail
        ));
    }
    fs::write(base.join("integrations.txt"), body)?;
    Ok(())
}

fn write_policy_meta(base: &Path) -> Result<()> {
    let mut body = String::from("# Policy metadata only — full policy not included\n");
    match resolve_policy_path_for_load() {
        Some(path) => {
            body.push_str(&format!("path: {}\n", path.display()));
            if path.exists() {
                match PolicyEngine::load(&path) {
                    Ok(engine) => {
                        body.push_str(&format!("version: {}\n", engine.version()));
                        body.push_str(&format!("tool_rules: {}\n", engine.tool_count()));
                        body.push_str("loads: yes\n");
                    }
                    Err(err) => {
                        body.push_str(&format!("loads: no\nerror: {err}\n"));
                    }
                }
            } else {
                body.push_str("exists: no\n");
            }
        }
        None => body.push_str("path: (none)\n"),
    }
    fs::write(base.join("policy-meta.txt"), body)?;
    Ok(())
}

async fn write_doctor(base: &Path) -> Result<()> {
    let checks = run_doctor_checks(true).await;
    fs::write(base.join("doctor.txt"), format_doctor_report(&checks))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn support_bundle_writes_redacted_files() {
        let _guard = crate::pilot::config::test_env_lock();
        let tmp = std::env::temp_dir().join(format!("sqreen-bundle-home-{}", std::process::id()));
        let out = std::env::temp_dir().join(format!("sqreen-bundle-out-{}", std::process::id()));
        let _ = fs::remove_dir_all(&tmp);
        let _ = fs::remove_dir_all(&out);
        fs::create_dir_all(tmp.join(".config/mcp-proxy")).unwrap();
        unsafe {
            std::env::set_var("HOME", &tmp);
            std::env::remove_var("XDG_CONFIG_HOME");
            std::env::set_var("MCP_DEVICE_TOKEN", "secret-should-not-leak");
            std::env::remove_var("MCP_CONTROL_PLANE_URL");
        }
        let path = run_support_bundle(Some(out.clone())).await.unwrap();
        assert!(path.join("version.txt").exists());
        assert!(path.join("doctor.txt").exists());
        let env_txt = fs::read_to_string(path.join("env.redacted.txt")).unwrap();
        assert!(env_txt.contains("[SET]"));
        assert!(!env_txt.contains("secret-should-not-leak"));
        let _ = fs::remove_dir_all(&tmp);
        let _ = fs::remove_dir_all(&out);
        unsafe {
            std::env::remove_var("MCP_DEVICE_TOKEN");
        }
    }
}
