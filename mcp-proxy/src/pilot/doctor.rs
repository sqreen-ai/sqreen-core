//! `mcp-proxy doctor` — PASS / WARN / FAIL health checks with remediation (no secrets).

use std::time::Duration;

use anyhow::Result;

use super::config::{config_dir, env_file_path, file_mode};
use super::integrations::{detect_integrations, IntegrationState};
use crate::cloud_client::{CONTROL_PLANE_URL_ENV, DEVICE_TOKEN_ENV};
use crate::gateway::{ApprovalMode, EnforcementPosture};
use crate::policy::{resolve_policy_path_for_load, PolicyEngine, POLICY_PATH_ENV};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CheckLevel {
    Pass,
    Warn,
    Fail,
}

impl CheckLevel {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Pass => "PASS",
            Self::Warn => "WARN",
            Self::Fail => "FAIL",
        }
    }
}

#[derive(Debug, Clone)]
pub struct DoctorCheck {
    pub name: String,
    pub level: CheckLevel,
    pub detail: String,
    pub remediation: Option<String>,
}

/// Runs all doctor checks. `probe_cloud` performs an optional HTTP reachability probe.
pub async fn run_doctor_checks(probe_cloud: bool) -> Vec<DoctorCheck> {
    let mut checks = Vec::new();
    checks.push(check_binary_version());
    checks.push(check_config_dir());
    checks.push(check_policy());
    checks.push(check_posture());
    checks.push(check_approval_mode());
    checks.push(check_device_token());
    checks.push(check_env_permissions());
    checks.push(check_clock_sanity());
    checks.push(check_integrations_summary());
    if probe_cloud {
        checks.push(probe_cloud_reachability().await);
    } else {
        checks.push(check_cloud_configured_only());
    }
    checks
}

/// Prints doctor output and returns process-oriented success (false if any FAIL).
pub async fn run_doctor() -> Result<bool> {
    let checks = run_doctor_checks(true).await;
    let version = env!("CARGO_PKG_VERSION");

    println!();
    println!("Sqreen Core (mcp-proxy) · doctor");
    println!("────────────────────────────────");
    println!("  Version: {version}");
    println!();

    let mut fails = 0usize;
    let mut warns = 0usize;
    for check in &checks {
        match check.level {
            CheckLevel::Fail => fails += 1,
            CheckLevel::Warn => warns += 1,
            CheckLevel::Pass => {}
        }
        println!(
            "  [{:>4}] {:<22} {}",
            check.level.as_str(),
            check.name,
            check.detail
        );
        if let Some(rem) = &check.remediation {
            println!("         → {rem}");
        }
    }

    println!();
    if fails > 0 {
        println!("Result: FAIL ({fails} failed, {warns} warnings)");
        println!("Fix FAIL items above, then re-run `mcp-proxy doctor`.");
    } else if warns > 0 {
        println!("Result: PASS with warnings ({warns})");
        println!("Optional: address WARN items for a cleaner pilot.");
    } else {
        println!("Result: PASS");
    }
    println!();
    Ok(fails == 0)
}

/// Formats doctor checks as plain text (support bundle).
pub fn format_doctor_report(checks: &[DoctorCheck]) -> String {
    let mut out = String::new();
    out.push_str(&format!(
        "mcp-proxy doctor report · {}\n",
        env!("CARGO_PKG_VERSION")
    ));
    for check in checks {
        out.push_str(&format!(
            "[{}] {} — {}\n",
            check.level.as_str(),
            check.name,
            check.detail
        ));
        if let Some(rem) = &check.remediation {
            out.push_str(&format!("  remediation: {rem}\n"));
        }
    }
    out
}

fn check_binary_version() -> DoctorCheck {
    DoctorCheck {
        name: "binary".into(),
        level: CheckLevel::Pass,
        detail: format!("mcp-proxy {}", env!("CARGO_PKG_VERSION")),
        remediation: None,
    }
}

fn check_config_dir() -> DoctorCheck {
    let dir = config_dir();
    if dir.is_dir() {
        DoctorCheck {
            name: "config_dir".into(),
            level: CheckLevel::Pass,
            detail: dir.display().to_string(),
            remediation: None,
        }
    } else {
        DoctorCheck {
            name: "config_dir".into(),
            level: CheckLevel::Warn,
            detail: format!("{} missing", dir.display()),
            remediation: Some(
                "Run installer or `mkdir -p ~/.config/mcp-proxy` then re-install policy".into(),
            ),
        }
    }
}

fn check_policy() -> DoctorCheck {
    let Some(path) = resolve_policy_path_for_load() else {
        return DoctorCheck {
            name: "policy".into(),
            level: CheckLevel::Fail,
            detail: "no policy file found".into(),
            remediation: Some(format!(
                "Install policy or set {POLICY_PATH_ENV} to a valid mcp-policy.yaml"
            )),
        };
    };
    if !path.exists() {
        return DoctorCheck {
            name: "policy".into(),
            level: CheckLevel::Fail,
            detail: format!("missing at {}", path.display()),
            remediation: Some(format!(
                "Create the file or fix {POLICY_PATH_ENV}; installer seeds ~/.config/mcp-proxy/"
            )),
        };
    }
    match PolicyEngine::load(&path) {
        Ok(engine) => DoctorCheck {
            name: "policy".into(),
            level: CheckLevel::Pass,
            detail: format!(
                "{} · version {} · {} tool rules",
                path.display(),
                engine.version(),
                engine.tool_count()
            ),
            remediation: None,
        },
        Err(err) => DoctorCheck {
            name: "policy".into(),
            level: CheckLevel::Fail,
            detail: format!("load error at {}", path.display()),
            remediation: Some(format!(
                "Fix YAML/JSON syntax or restore defaults from installer ({err})"
            )),
        },
    }
}

fn check_posture() -> DoctorCheck {
    let posture = EnforcementPosture::from_env();
    if posture.allows_missing_policy_passthrough() {
        DoctorCheck {
            name: "posture".into(),
            level: CheckLevel::Warn,
            detail: format!(
                "{} — missing policy may FAIL_OPEN",
                posture.as_str()
            ),
            remediation: Some(
                "For pilots use default enforcing posture (unset SQREEN_ENFORCEMENT_POSTURE)"
                    .into(),
            ),
        }
    } else {
        DoctorCheck {
            name: "posture".into(),
            level: CheckLevel::Pass,
            detail: posture.as_str().to_string(),
            remediation: None,
        }
    }
}

fn check_approval_mode() -> DoctorCheck {
    let mode = ApprovalMode::from_env();
    let cloud = std::env::var(CONTROL_PLANE_URL_ENV)
        .ok()
        .filter(|s| !s.trim().is_empty())
        .is_some()
        && std::env::var(DEVICE_TOKEN_ENV)
            .ok()
            .filter(|s| !s.trim().is_empty())
            .is_some();
    match mode {
        ApprovalMode::Remote if !cloud => DoctorCheck {
            name: "approval_mode".into(),
            level: CheckLevel::Fail,
            detail: "remote selected but cloud client not configured".into(),
            remediation: Some(
                "Run `mcp-proxy enroll --control-plane URL --device-token TOKEN` or set mode=local"
                    .into(),
            ),
        },
        ApprovalMode::Auto if !cloud => DoctorCheck {
            name: "approval_mode".into(),
            level: CheckLevel::Warn,
            detail: "auto — will use local TTY until cloud is enrolled".into(),
            remediation: Some("Enroll device for remote SOC approvals".into()),
        },
        _ => DoctorCheck {
            name: "approval_mode".into(),
            level: CheckLevel::Pass,
            detail: mode.as_str().to_string(),
            remediation: None,
        },
    }
}

fn check_device_token() -> DoctorCheck {
    let file_pairs = super::config::read_env_file(&env_file_path()).unwrap_or_default();
    let url_set = std::env::var(CONTROL_PLANE_URL_ENV)
        .ok()
        .filter(|s| !s.trim().is_empty())
        .is_some()
        || file_pairs.iter().any(|(k, v)| {
            k == CONTROL_PLANE_URL_ENV && !v.trim().is_empty()
        });
    let token_set = std::env::var(DEVICE_TOKEN_ENV)
        .ok()
        .filter(|s| !s.trim().is_empty())
        .is_some()
        || file_pairs
            .iter()
            .any(|(k, v)| k == DEVICE_TOKEN_ENV && !v.trim().is_empty());
    match (url_set, token_set) {
        (true, true) => DoctorCheck {
            name: "device_token".into(),
            level: CheckLevel::Pass,
            detail: "present [SET]".into(),
            remediation: None,
        },
        (false, false) => DoctorCheck {
            name: "device_token".into(),
            level: CheckLevel::Warn,
            detail: "not configured (local-only OK)".into(),
            remediation: Some(
                "Optional: `mcp-proxy enroll --control-plane URL --device-token TOKEN`".into(),
            ),
        },
        (true, false) => DoctorCheck {
            name: "device_token".into(),
            level: CheckLevel::Fail,
            detail: "URL set but token [EMPTY]".into(),
            remediation: Some(
                "Mint token in Cloud SOC → Agent Identities, then enroll (token never printed)"
                    .into(),
            ),
        },
        (false, true) => DoctorCheck {
            name: "device_token".into(),
            level: CheckLevel::Warn,
            detail: "token [SET] but MCP_CONTROL_PLANE_URL missing".into(),
            remediation: Some("Set MCP_CONTROL_PLANE_URL or re-run enroll with --control-plane".into()),
        },
    }
}

fn check_env_permissions() -> DoctorCheck {
    let path = env_file_path();
    if !path.exists() {
        return DoctorCheck {
            name: "env_permissions".into(),
            level: CheckLevel::Warn,
            detail: format!("{} missing", path.display()),
            remediation: Some("Created by installer or `mcp-proxy enroll`".into()),
        };
    }
    match file_mode(&path) {
        Some(mode) if mode == 0o600 => DoctorCheck {
            name: "env_permissions".into(),
            level: CheckLevel::Pass,
            detail: format!("{} mode 0600", path.display()),
            remediation: None,
        },
        Some(mode) => DoctorCheck {
            name: "env_permissions".into(),
            level: CheckLevel::Warn,
            detail: format!("{} mode {:04o} (prefer 0600)", path.display(), mode),
            remediation: Some(format!("chmod 600 {}", path.display())),
        },
        None => DoctorCheck {
            name: "env_permissions".into(),
            level: CheckLevel::Pass,
            detail: format!("{} present", path.display()),
            remediation: None,
        },
    }
}

fn check_clock_sanity() -> DoctorCheck {
    // Rough sanity: chrono Utc::now should be after a fixed epoch and before a far future.
    let now = chrono::Utc::now();
    let year = now.format("%Y").to_string();
    let y: i32 = year.parse().unwrap_or(0);
    if (2024..=2100).contains(&y) {
        DoctorCheck {
            name: "clock".into(),
            level: CheckLevel::Pass,
            detail: format!("UTC {}", now.format("%Y-%m-%d %H:%M:%S")),
            remediation: None,
        }
    } else {
        DoctorCheck {
            name: "clock".into(),
            level: CheckLevel::Warn,
            detail: format!("unusual system time: {now}"),
            remediation: Some(
                "Fix system clock — TLS and remote approval expiry depend on it".into(),
            ),
        }
    }
}

fn check_integrations_summary() -> DoctorCheck {
    let reports = detect_integrations();
    let active = reports
        .iter()
        .filter(|r| r.state == IntegrationState::Active)
        .count();
    if active > 0 {
        DoctorCheck {
            name: "integrations".into(),
            level: CheckLevel::Pass,
            detail: format!("{active} active integration(s)"),
            remediation: None,
        }
    } else {
        DoctorCheck {
            name: "integrations".into(),
            level: CheckLevel::Warn,
            detail: "no IDE wrap / HTTP base URL / cloud detected in this environment".into(),
            remediation: Some(
                "Wrap MCP (`mcp-proxy -- run …`) or run `mcp-proxy serve` + OPENAI_BASE_URL".into(),
            ),
        }
    }
}

fn check_cloud_configured_only() -> DoctorCheck {
    let url = std::env::var(CONTROL_PLANE_URL_ENV).unwrap_or_default();
    if url.trim().is_empty() {
        DoctorCheck {
            name: "cloud_reachability".into(),
            level: CheckLevel::Warn,
            detail: "not configured".into(),
            remediation: Some("Optional for local-only pilots".into()),
        }
    } else {
        DoctorCheck {
            name: "cloud_reachability".into(),
            level: CheckLevel::Warn,
            detail: "configured (probe skipped)".into(),
            remediation: None,
        }
    }
}

async fn probe_cloud_reachability() -> DoctorCheck {
    let file_pairs = super::config::read_env_file(&env_file_path()).unwrap_or_default();
    let url = std::env::var(CONTROL_PLANE_URL_ENV)
        .ok()
        .filter(|s| !s.trim().is_empty())
        .or_else(|| {
            file_pairs.iter().find_map(|(k, v)| {
                (k == CONTROL_PLANE_URL_ENV && !v.trim().is_empty()).then(|| v.clone())
            })
        });
    let Some(url) = url.map(|u| u.trim().trim_end_matches('/').to_string()) else {
        return DoctorCheck {
            name: "cloud_reachability".into(),
            level: CheckLevel::Warn,
            detail: "not configured".into(),
            remediation: Some(
                "Local-only OK. To enroll: `mcp-proxy enroll --control-plane URL --device-token TOKEN`"
                    .into(),
            ),
        };
    };

    let client = match reqwest::Client::builder()
        .timeout(Duration::from_secs(3))
        .build()
    {
        Ok(c) => c,
        Err(err) => {
            return DoctorCheck {
                name: "cloud_reachability".into(),
                level: CheckLevel::Warn,
                detail: format!("could not build HTTP client: {err}"),
                remediation: Some("Retry; if persistent, check TLS / CA store".into()),
            };
        }
    };

    // Prefer a cheap GET on API root / health-ish paths; any HTTP response = reachable.
    let candidates = [
        format!("{url}/api/v1/health"),
        format!("{url}/health"),
        format!("{url}/"),
    ];

    for candidate in &candidates {
        match client.get(candidate).send().await {
            Ok(resp) => {
                return DoctorCheck {
                    name: "cloud_reachability".into(),
                    level: CheckLevel::Pass,
                    detail: format!("reachable ({candidate} → HTTP {})", resp.status()),
                    remediation: None,
                };
            }
            Err(_) => continue,
        }
    }

    DoctorCheck {
        name: "cloud_reachability".into(),
        level: CheckLevel::Fail,
        detail: format!("configured but unreachable: {url}"),
        remediation: Some(
            "Checklist: DNS / VPN / firewall, correct URL, TLS certs, control plane up; then `mcp-proxy doctor`"
                .into(),
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::path::PathBuf;

    #[tokio::test]
    async fn doctor_runs_without_panic() {
        let _guard = crate::pilot::config::test_env_lock();
        let tmp = std::env::temp_dir().join(format!("sqreen-doctor-{}", std::process::id()));
        let _ = fs::remove_dir_all(&tmp);
        let cfg = tmp.join(".config/mcp-proxy");
        fs::create_dir_all(&cfg).unwrap();
        let policy = cfg.join("mcp-policy.yaml");
        // Use repo baseline-shaped policy so PolicyEngine::load accepts it.
        let repo_policy = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("mcp-policy.yaml");
        if repo_policy.exists() {
            fs::copy(&repo_policy, &policy).unwrap();
        } else {
            fs::write(
                &policy,
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
"#,
            )
            .unwrap();
        }
        unsafe {
            std::env::set_var("HOME", &tmp);
            std::env::remove_var("XDG_CONFIG_HOME");
            std::env::set_var("MCP_POLICY_PATH", &policy);
            std::env::remove_var("MCP_CONTROL_PLANE_URL");
            std::env::remove_var("MCP_DEVICE_TOKEN");
            std::env::remove_var("SQREEN_APPROVAL_MODE");
            std::env::remove_var("SQREEN_ENFORCEMENT_POSTURE");
        }
        let checks = run_doctor_checks(false).await;
        assert!(!checks.is_empty());
        assert!(checks.iter().any(|c| c.name == "binary"));
        let policy_check = checks.iter().find(|c| c.name == "policy").expect("policy");
        assert_eq!(
            policy_check.level,
            CheckLevel::Pass,
            "policy detail: {}",
            policy_check.detail
        );
        for c in &checks {
            assert!(!c.detail.contains("sk-"));
            assert!(!c.detail.to_ascii_lowercase().contains("bearer "));
        }
        let _ = fs::remove_dir_all(&tmp);
    }
}
