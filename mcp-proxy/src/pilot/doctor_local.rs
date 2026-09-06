//! Local-only doctor for open-core builds (no Enterprise enrollment diagnostics).

use anyhow::Result;

use super::day1;
use super::integrations::IntegrationState;
use super::status::{collect_status, PolicyState, RuntimeCoverageState};

/// Runs local health checks suitable for standalone Core.
pub fn run_doctor() -> Result<()> {
    println!();
    println!("Sqreen Core · doctor (local)");
    println!("────────────────────────────");

    let s = collect_status();
    let mut fails = 0usize;
    let mut warns = 0usize;

    match s.policy {
        PolicyState::Loaded => {
            println!("PASS  policy loaded");
            if let (Some(path), Some(ver)) = (&s.policy_path, &s.policy_version) {
                println!("      {} · {}", path.display(), ver);
            }
        }
        PolicyState::Invalid => {
            fails += 1;
            println!("FAIL  policy invalid");
            println!("      Fix MCP_POLICY_PATH or reinstall policy, then `mcp-proxy demo`");
        }
        PolicyState::Missing => {
            fails += 1;
            println!("FAIL  policy missing");
            println!(
                "      Install (`curl -fsSL https://sqreen.ai/install.sh | bash`) or set MCP_POLICY_PATH"
            );
        }
    }

    if s.approval_mode.eq_ignore_ascii_case("local") {
        println!("PASS  approval mode local");
    } else {
        warns += 1;
        println!("WARN  approval mode `{}`", s.approval_mode);
        println!("      Standalone Core uses local TTY/stdin confirmation by default");
        println!("      Enterprise management and remote workflows are available separately");
    }

    match s.runtime_coverage {
        RuntimeCoverageState::VerifiedActive => {
            println!("PASS  runtime coverage VERIFIED_ACTIVE");
        }
        RuntimeCoverageState::Configured => {
            warns += 1;
            println!("WARN  wrap configured but traffic not yet verified");
            day1::print_verify_traffic_next();
        }
        RuntimeCoverageState::NotConfigured | RuntimeCoverageState::Unknown => {
            warns += 1;
            let wrap = s.integrations.iter().any(|r| {
                r.name.contains("mcp.json")
                    && matches!(
                        r.state,
                        IntegrationState::Configured
                            | IntegrationState::Installed
                            | IntegrationState::VerifiedActive
                    )
            });
            if wrap {
                println!("WARN  MCP wrap present but coverage not VERIFIED_ACTIVE");
                day1::print_verify_traffic_next();
            } else {
                println!("WARN  MCP wrap not configured");
                day1::print_integrate_next();
            }
        }
    }

    println!();
    println!("Enterprise features are not included in this build.");
    println!();
    if fails > 0 {
        anyhow::bail!("doctor reported {fails} FAIL check(s)");
    }
    if warns > 0 {
        println!("doctor: {warns} WARN (local checks otherwise OK)");
    } else {
        println!("doctor: all local checks PASS");
    }
    Ok(())
}
