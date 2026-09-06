//! `mcp-proxy status` — truthful posture (policy ≠ traffic protected).

use std::path::PathBuf;

use anyhow::Result;
use chrono::Utc;

use super::activity::{self, ActivitySnapshot, CLOUD_VERIFY_WINDOW};
use super::config::{config_dir, device_id_from_env, env_file_path, org_id_from_env};
use super::integrations::{
    detect_integrations, has_core_wrap_configured, IntegrationState,
};
use crate::cloud_client::{CONTROL_PLANE_URL_ENV, DEVICE_TOKEN_ENV};
use crate::gateway::{ApprovalMode, EnforcementPosture};
use crate::policy::{resolve_policy_path_for_load, PolicyEngine, POLICY_PATH_ENV};

/// Snapshot used by status and support-bundle.
#[derive(Debug, Clone)]
pub struct StatusReport {
    pub policy: PolicyState,
    pub policy_path: Option<PathBuf>,
    pub policy_version: Option<String>,
    pub tool_rules: Option<usize>,
    pub policy_signed: PolicySignedHint,
    pub runtime_coverage: RuntimeCoverageState,
    pub protected_traffic_verified: bool,
    pub last_protected_age: Option<String>,
    pub last_protected_tool: Option<String>,
    pub last_protected_runtime: Option<String>,
    pub cloud_enrollment: CloudEnrollmentState,
    pub cloud_connection: CloudConnectionState,
    pub last_cloud_age: Option<String>,
    pub posture: String,
    pub org_id: Option<String>,
    pub device_id: Option<String>,
    /// Credentials present on disk/process (enrollment), not live connectivity.
    pub cloud_enrollment_configured: bool,
    pub cloud_url: Option<String>,
    pub device_token_present: bool,
    pub approval_mode: String,
    pub config_dir: PathBuf,
    pub env_file: PathBuf,
    pub integrations: Vec<super::integrations::IntegrationReport>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PolicyState {
    Loaded,
    Missing,
    Invalid,
}

impl PolicyState {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Loaded => "LOADED",
            Self::Missing => "MISSING",
            Self::Invalid => "INVALID",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PolicySignedHint {
    /// Cloud-signed envelope present on disk.
    Yes,
    /// Local policy file only (Core default).
    LocalUnsigned,
    Unknown,
}

impl PolicySignedHint {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Yes => "yes",
            Self::LocalUnsigned => "no (local file)",
            Self::Unknown => "unknown",
        }
    }
}

/// Aggregate Core wrap / serve coverage (never equals “policy loaded”).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RuntimeCoverageState {
    NotConfigured,
    /// Wrap or local `serve` target present; no recent protected evaluation.
    Configured,
    /// Recent protected evaluation observed through a **configured** Core wrap/serve path.
    VerifiedActive,
    Unknown,
}

impl RuntimeCoverageState {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::NotConfigured => "NOT_CONFIGURED",
            Self::Configured => "CONFIGURED",
            Self::VerifiedActive => "VERIFIED_ACTIVE",
            Self::Unknown => "UNKNOWN",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CloudEnrollmentState {
    NotConfigured,
    Configured,
}

impl CloudEnrollmentState {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::NotConfigured => "NOT_CONFIGURED",
            Self::Configured => "CONFIGURED",
        }
    }
}

/// Live Cloud reachability — never green from credentials alone.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CloudConnectionState {
    NotConfigured,
    NotYetSeen,
    Verified,
    Stale,
    Unreachable,
}

impl CloudConnectionState {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::NotConfigured => "NOT_CONFIGURED",
            Self::NotYetSeen => "NOT_YET_SEEN",
            Self::Verified => "VERIFIED",
            Self::Stale => "STALE",
            Self::Unreachable => "UNREACHABLE",
        }
    }
}

fn policy_signed_hint(cfg: &std::path::Path) -> PolicySignedHint {
    let signed = cfg.join("mcp-policy.cloud.signed.json");
    if signed.exists() {
        PolicySignedHint::Yes
    } else {
        PolicySignedHint::LocalUnsigned
    }
}

fn cloud_connection_from_activity(
    enrolled: bool,
    activity: &ActivitySnapshot,
    now: chrono::DateTime<Utc>,
) -> (CloudConnectionState, Option<String>) {
    if !enrolled {
        return (CloudConnectionState::NotConfigured, None);
    }
    let age = activity
        .last_cloud_ok_at
        .map(|at| activity::format_age(at, now));

    match (activity.last_cloud_ok_at, activity.last_cloud_err_at) {
        (None, None) => (CloudConnectionState::NotYetSeen, None),
        (None, Some(_)) => (CloudConnectionState::Unreachable, None),
        (Some(ok), err) => {
            let err_newer = err.is_some_and(|e| e > ok);
            if err_newer {
                (CloudConnectionState::Unreachable, age)
            } else if now.signed_duration_since(ok) <= CLOUD_VERIFY_WINDOW {
                (CloudConnectionState::Verified, age)
            } else {
                (CloudConnectionState::Stale, age)
            }
        }
    }
}

/// Aggregate runtime coverage.
///
/// `VERIFIED_ACTIVE` requires **both** a configured Core wrap path and a recent
/// protected evaluation recorded from real MCP stdio enforcement. In-process self-checks
/// (`mcp-proxy prove`) must not set activity markers, and orphan markers without a wrap
/// never yield `VERIFIED_ACTIVE`. (OpenAI HTTP `serve` does not currently mint coverage.)
fn compute_runtime_coverage(
    wrap_configured: bool,
    traffic_verified: bool,
) -> RuntimeCoverageState {
    match (wrap_configured, traffic_verified) {
        (true, true) => RuntimeCoverageState::VerifiedActive,
        (true, false) => RuntimeCoverageState::Configured,
        (false, _) => RuntimeCoverageState::NotConfigured,
    }
}

/// Collects current status without printing secrets.
pub fn collect_status() -> StatusReport {
    let now = Utc::now();
    let activity = activity::load();
    let policy_path = resolve_policy_path_for_load();
    let mut policy_version = None;
    let mut tool_rules = None;
    let mut policy = PolicyState::Missing;

    if let Some(ref path) = policy_path {
        if path.exists() {
            match PolicyEngine::load(path) {
                Ok(engine) => {
                    policy_version = Some(engine.version().to_string());
                    tool_rules = Some(engine.tool_count());
                    policy = PolicyState::Loaded;
                }
                Err(_) => {
                    policy = PolicyState::Invalid;
                }
            }
        } else {
            policy = PolicyState::Missing;
        }
    }

    let cfg = config_dir();
    let policy_signed = if policy == PolicyState::Loaded {
        policy_signed_hint(&cfg)
    } else {
        PolicySignedHint::Unknown
    };

    let cloud_url = crate::local_env::lookup(CONTROL_PLANE_URL_ENV);
    let device_token_present = crate::local_env::lookup(DEVICE_TOKEN_ENV).is_some();
    let cloud_enrollment_configured = cloud_url.is_some() && device_token_present;
    let cloud_enrollment = if cloud_enrollment_configured {
        CloudEnrollmentState::Configured
    } else {
        CloudEnrollmentState::NotConfigured
    };
    let (cloud_connection, last_cloud_age) =
        cloud_connection_from_activity(cloud_enrollment_configured, &activity, now);

    let integrations = detect_integrations();
    let wrap_configured = has_core_wrap_configured(&integrations);
    // Activity alone is insufficient: markers without a configured wrap/serve path do not
    // count as verified runtime protection (e.g. stale files or misuse of evaluate APIs).
    let activity_recent = activity::protected_traffic_verified(now);
    let protected_traffic_verified = wrap_configured && activity_recent;
    let last_protected_age = if protected_traffic_verified {
        activity
            .last_protected_at
            .map(|at| activity::format_age(at, now))
    } else {
        None
    };
    let runtime_coverage = compute_runtime_coverage(wrap_configured, activity_recent);

    let (last_protected_tool, last_protected_runtime) = if protected_traffic_verified {
        (
            activity.last_protected_tool.clone(),
            activity.last_protected_runtime.clone(),
        )
    } else {
        (None, None)
    };

    StatusReport {
        policy,
        policy_path,
        policy_version,
        tool_rules,
        policy_signed,
        runtime_coverage,
        protected_traffic_verified,
        last_protected_age,
        last_protected_tool,
        last_protected_runtime,
        cloud_enrollment,
        cloud_connection,
        last_cloud_age,
        posture: EnforcementPosture::from_env().as_str().to_string(),
        org_id: org_id_from_env(),
        device_id: device_id_from_env(),
        cloud_enrollment_configured,
        cloud_url,
        device_token_present,
        approval_mode: ApprovalMode::from_env().as_str().to_string(),
        config_dir: cfg,
        env_file: env_file_path(),
        integrations,
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
    println!();
    println!("Policy");
    println!("  State:            {}", s.policy.as_str());
    println!("  Signed:           {}", s.policy_signed.as_str());
    match (&s.policy_path, &s.policy_version, s.tool_rules) {
        (Some(path), Some(ver), Some(n)) => {
            println!("  Path:             {}", path.display());
            println!("  Version:          {ver} · {n} tool rules");
        }
        (Some(path), _, _) if s.policy == PolicyState::Invalid => {
            println!("  Path:             {} (failed to load)", path.display());
        }
        (Some(path), _, _) => {
            println!("  Path:             {} (missing file)", path.display());
        }
        _ => {
            println!(
                "  Path:             (none — set {POLICY_PATH_ENV} or install policy)"
            );
        }
    }

    println!();
    println!("Runtime coverage");
    println!("  Aggregate:        {}", s.runtime_coverage.as_str());
    if s.runtime_coverage == RuntimeCoverageState::Configured {
        println!("                    (wrap present — traffic not yet verified)");
    }
    println!(
        "  Protected traffic: {}",
        if s.protected_traffic_verified {
            "VERIFIED"
        } else {
            "NOT_YET_VERIFIED"
        }
    );
    if let Some(age) = &s.last_protected_age {
        let tool = s.last_protected_tool.as_deref().unwrap_or("?");
        let rt = s.last_protected_runtime.as_deref().unwrap_or("?");
        println!("  Last evaluation:  {age} ({rt} / {tool})");
    }

    #[cfg(feature = "enterprise")]
    {
        println!();
        println!("Cloud");
        println!("  Enrollment:       {}", s.cloud_enrollment.as_str());
        println!("  Connection:       {}", s.cloud_connection.as_str());
        if let Some(age) = &s.last_cloud_age {
            println!("  Last connection:  {age}");
        }
        if let Some(url) = &s.cloud_url {
            println!("  URL:              {url}");
        }
        println!(
            "  Device token:     {}",
            if s.device_token_present {
                "[SET]"
            } else {
                "[EMPTY]"
            }
        );
    }
    #[cfg(not(feature = "enterprise"))]
    {
        println!();
        println!("Enterprise");
        println!("  Features:         not included in this build");
    }

    println!();
    println!("Approval");
    println!("  Mode:             {}", s.approval_mode);
    println!("  Posture:          {}", s.posture);
    #[cfg(feature = "enterprise")]
    {
        println!(
            "  Org ID:           {}",
            s.org_id.as_deref().unwrap_or("(unset)")
        );
        println!(
            "  Device ID:        {}",
            s.device_id.as_deref().unwrap_or("(unset)")
        );
    }
    println!("  Config dir:       {}", s.config_dir.display());

    println!();
    println!("Integrations");
    for report in &s.integrations {
        #[cfg(not(feature = "enterprise"))]
        if report.name.to_ascii_lowercase().contains("control plane")
            || report.name.to_ascii_lowercase().contains("cloud")
        {
            continue;
        }
        let mark = match report.state {
            IntegrationState::VerifiedActive => "●",
            IntegrationState::Configured | IntegrationState::Installed => "◐",
            IntegrationState::NotConfigured => "○",
            IntegrationState::Unknown => "?",
        };
        println!(
            "  {mark} {:<28} {}",
            report.name,
            report.state.as_str()
        );
    }

    println!();
    println!("Protection boundary");
    println!("  Protected:  MCP tools/call (stdio wrap) — PRODUCTION_SUPPORTED.");
    println!("              Cursor via Core MCP wrap — PILOT_SUPPORTED (same engine).");
    println!("              OpenAI-compatible Chat Completions via `serve` —");
    println!("              PILOT_SUPPORTED_LIMITED (non-stream response tool_calls only;");
    println!("              not equivalent to MCP pre-tool-call blocking).");
    println!("  Experimental: AnthropicAdapter (Messages HTTP via serve not wired);");
    println!("              Cursor IDE hooks (secondary — not Core wrap verification).");
    println!("  Not covered: model prompts, IDE chat without MCP/HTTP wrap,");
    println!("               OS processes, IAM, or network firewalls.");
    println!("  Note:       Policy LOADED does not mean traffic is protected.");
    println!();

    print_next_step(&s);
    println!();
    Ok(())
}

fn print_next_step(s: &StatusReport) {
    use super::day1;

    println!("Next step");
    if s.policy != PolicyState::Loaded {
        println!("  Install policy (`curl -fsSL https://sqreen.ai/install.sh | bash`)");
        println!("  then `source ~/.config/mcp-proxy/env && mcp-proxy demo`");
        return;
    }
    if s.runtime_coverage == RuntimeCoverageState::NotConfigured {
        println!("  Protect a real MCP runtime ({})", day1::PRIMARY_RUNTIME);
        day1::print_integrate_next();
        return;
    }
    if !s.protected_traffic_verified {
        day1::print_verify_traffic_next();
        return;
    }
    #[cfg(feature = "enterprise")]
    {
        if s.cloud_enrollment == CloudEnrollmentState::Configured
            && matches!(
                s.cloud_connection,
                CloudConnectionState::NotYetSeen | CloudConnectionState::Unreachable
            )
        {
            println!("  Enrollment saved — Cloud connection not verified yet.");
            println!("  Restart Cursor / reload MCP so the wrap process loads credentials.");
            println!("  Then `{}` and `mcp-proxy status`", day1::PROVE_COMMAND);
            println!("  → expect Cloud Connection: VERIFIED (when the control plane is reachable).");
            return;
        }
        if s.cloud_enrollment == CloudEnrollmentState::NotConfigured {
            day1::print_optional_cloud_next();
            return;
        }
        println!("  `mcp-proxy doctor` · review Cloud SOC events if enrolled.");
    }
    #[cfg(not(feature = "enterprise"))]
    {
        println!("  Local Core looks healthy — `mcp-proxy doctor` for a local checklist.");
        day1::print_optional_cloud_next();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    fn isolated_home(label: &str) -> (std::sync::MutexGuard<'static, ()>, PathBuf) {
        let guard = crate::pilot::config::test_env_lock();
        let tmp = std::env::temp_dir().join(format!(
            "sqreen-status-{label}-{}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&tmp);
        fs::create_dir_all(tmp.join(".config/mcp-proxy")).unwrap();
        unsafe {
            std::env::set_var("HOME", &tmp);
            std::env::remove_var("XDG_CONFIG_HOME");
            std::env::remove_var("MCP_POLICY_PATH");
            std::env::remove_var("MCP_CONTROL_PLANE_URL");
            std::env::remove_var("MCP_DEVICE_TOKEN");
            std::env::remove_var("OPENAI_BASE_URL");
            std::env::remove_var("SQREEN_APPROVAL_MODE");
            std::env::remove_var("SQREEN_ENFORCEMENT_POSTURE");
        }
        (guard, tmp)
    }

    fn write_policy(home: &std::path::Path) -> PathBuf {
        let policy = home.join(".config/mcp-proxy/mcp-policy.yaml");
        let repo = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("mcp-policy.yaml");
        if repo.exists() {
            fs::copy(&repo, &policy).unwrap();
        } else {
            fs::write(
                &policy,
                r#"
version: "1"
global:
  redact_keys: []
  risk_threshold: 70
  block_patterns: ["\\.ssh/"]
tools:
  - name: read_file
    action: Allow
    block_patterns: ["\\.ssh/"]
"#,
            )
            .unwrap();
        }
        unsafe {
            std::env::set_var("MCP_POLICY_PATH", &policy);
        }
        policy
    }

    fn write_cursor_wrap(home: &std::path::Path) {
        let dir = home.join(".cursor");
        fs::create_dir_all(&dir).unwrap();
        fs::write(
            dir.join("mcp.json"),
            r#"{
  "mcpServers": {
    "filesystem": {
      "command": "/tmp/mcp-proxy",
      "args": ["--", "run", "npx", "-y", "@modelcontextprotocol/server-filesystem", "."]
    }
  }
}"#,
        )
        .unwrap();
    }

    fn write_hooks_only(home: &std::path::Path) {
        let dir = home.join(".cursor");
        fs::create_dir_all(dir.join("hooks")).unwrap();
        fs::write(
            dir.join("hooks.json"),
            r#"{
  "version": 1,
  "hooks": {
    "beforeShellExecution": [{"command": "python3 .cursor/hooks/block-sensitive-paths.py"}]
  }
}"#,
        )
        .unwrap();
        fs::write(
            dir.join("hooks/block-sensitive-paths.py"),
            "print('hook')\n",
        )
        .unwrap();
    }

    fn rendered_status() -> String {
        let s = collect_status();
        // Mirror the invariant we care about for greps.
        let mut out = String::new();
        out.push_str(&format!("Policy {}\n", s.policy.as_str()));
        out.push_str(&format!(
            "Runtime coverage {}\n",
            s.runtime_coverage.as_str()
        ));
        out.push_str(&format!(
            "Cloud enrollment {} connection {}\n",
            s.cloud_enrollment.as_str(),
            s.cloud_connection.as_str()
        ));
        assert!(
            !out.contains("Protection: ACTIVE") && !out.contains("Protection:ACTIVE"),
            "status must never emit Protection: ACTIVE"
        );
        out
    }

    #[test]
    fn policy_only_is_not_verified_active() {
        let (_g, tmp) = isolated_home("policy-only");
        write_policy(&tmp);
        let s = collect_status();
        assert_eq!(s.policy, PolicyState::Loaded);
        assert_eq!(s.runtime_coverage, RuntimeCoverageState::NotConfigured);
        assert!(!s.protected_traffic_verified);
        assert!(!rendered_status().contains("Protection: ACTIVE"));
        let _ = fs::remove_dir_all(&tmp);
    }

    #[test]
    fn no_policy_is_missing() {
        let (_g, tmp) = isolated_home("no-policy");
        // Avoid resolving the repo's ./mcp-policy.yaml when tests run from the crate root.
        let missing = tmp.join("definitely-missing-policy.yaml");
        unsafe {
            std::env::set_var("MCP_POLICY_PATH", &missing);
        }
        let s = collect_status();
        assert_eq!(s.policy, PolicyState::Missing);
        assert_eq!(s.runtime_coverage, RuntimeCoverageState::NotConfigured);
        let _ = fs::remove_dir_all(&tmp);
    }

    #[test]
    fn enrollment_only_is_configured_not_connected() {
        let (_g, tmp) = isolated_home("enroll-only");
        write_policy(&tmp);
        crate::pilot::config::upsert_env_file(&[
            ("MCP_CONTROL_PLANE_URL", "http://127.0.0.1:9"),
            ("MCP_DEVICE_TOKEN", "tok-test"),
        ])
        .unwrap();
        let s = collect_status();
        assert_eq!(s.cloud_enrollment, CloudEnrollmentState::Configured);
        assert_eq!(s.cloud_connection, CloudConnectionState::NotYetSeen);
        assert_ne!(s.cloud_connection.as_str(), "CONNECTED");
        assert_ne!(s.cloud_connection.as_str(), "VERIFIED");
        let _ = fs::remove_dir_all(&tmp);
    }

    #[test]
    fn recent_protected_action_is_verified_active() {
        let (_g, tmp) = isolated_home("traffic");
        write_policy(&tmp);
        write_cursor_wrap(&tmp);
        activity::record_protected_evaluation("mcp_stdio", "read_file", "DENY");
        let s = collect_status();
        assert!(s.protected_traffic_verified);
        assert_eq!(s.runtime_coverage, RuntimeCoverageState::VerifiedActive);
        let cursor = s
            .integrations
            .iter()
            .find(|r| r.name.contains("Cursor mcp"))
            .expect("cursor");
        assert_eq!(cursor.state, IntegrationState::VerifiedActive);
        let _ = fs::remove_dir_all(&tmp);
    }

    #[test]
    fn activity_without_wrap_is_not_verified_active() {
        let (_g, tmp) = isolated_home("orphan-activity");
        write_policy(&tmp);
        // No wrap — orphan / self-check-style markers must not mint VERIFIED_ACTIVE.
        activity::record_protected_evaluation("mcp_stdio", "read_file", "DENY");
        let s = collect_status();
        assert_eq!(s.runtime_coverage, RuntimeCoverageState::NotConfigured);
        assert!(!s.protected_traffic_verified);
        assert!(s.last_protected_age.is_none());
        let _ = fs::remove_dir_all(&tmp);
    }

    #[test]
    fn wrap_without_traffic_is_configured_not_verified() {
        let (_g, tmp) = isolated_home("wrap-no-traffic");
        write_policy(&tmp);
        write_cursor_wrap(&tmp);
        let s = collect_status();
        assert_eq!(s.runtime_coverage, RuntimeCoverageState::Configured);
        assert!(!s.protected_traffic_verified);
        let cursor = s
            .integrations
            .iter()
            .find(|r| r.name.contains("Cursor mcp"))
            .expect("cursor");
        assert_eq!(cursor.state, IntegrationState::Configured);
        let _ = fs::remove_dir_all(&tmp);
    }

    #[test]
    fn hooks_without_wrap_do_not_imply_runtime_enforcement() {
        let (_g, tmp) = isolated_home("hooks-only");
        write_policy(&tmp);
        write_hooks_only(&tmp);
        let s = collect_status();
        assert_eq!(s.runtime_coverage, RuntimeCoverageState::NotConfigured);
        let hooks = s
            .integrations
            .iter()
            .find(|r| r.name.contains("hooks"))
            .expect("hooks");
        assert_eq!(hooks.state, IntegrationState::Installed);
        assert_ne!(hooks.state, IntegrationState::VerifiedActive);
        assert_ne!(hooks.state, IntegrationState::Configured);
        let _ = fs::remove_dir_all(&tmp);
    }

    #[test]
    fn cloud_unreachable_when_err_without_ok() {
        let (_g, tmp) = isolated_home("cloud-err");
        write_policy(&tmp);
        crate::pilot::config::upsert_env_file(&[
            ("MCP_CONTROL_PLANE_URL", "http://127.0.0.1:9"),
            ("MCP_DEVICE_TOKEN", "tok"),
        ])
        .unwrap();
        activity::record_cloud_err();
        let s = collect_status();
        assert_eq!(s.cloud_connection, CloudConnectionState::Unreachable);
        let _ = fs::remove_dir_all(&tmp);
    }

    #[test]
    fn cloud_verified_after_ok() {
        let (_g, tmp) = isolated_home("cloud-ok");
        write_policy(&tmp);
        crate::pilot::config::upsert_env_file(&[
            ("MCP_CONTROL_PLANE_URL", "http://127.0.0.1:9"),
            ("MCP_DEVICE_TOKEN", "tok"),
        ])
        .unwrap();
        activity::record_cloud_ok();
        let s = collect_status();
        assert_eq!(s.cloud_connection, CloudConnectionState::Verified);
        let _ = fs::remove_dir_all(&tmp);
    }

    #[test]
    fn status_never_prints_protection_active_literal() {
        let (_g, tmp) = isolated_home("no-protection-active");
        write_policy(&tmp);
        let s = collect_status();
        let text = format!("{s:?}");
        assert!(!text.contains("Protection: ACTIVE"));
        assert_eq!(s.policy, PolicyState::Loaded);
        assert_ne!(s.runtime_coverage.as_str(), "ACTIVE");
        let _ = fs::remove_dir_all(&tmp);
    }
}
