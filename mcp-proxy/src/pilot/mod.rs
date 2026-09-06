//! Design-partner pilot / onboarding CLI surface.
//!
//! Commands: `status`, `doctor`, `integrations`, `support-bundle`, `enroll`, `update`.

pub mod activity;
pub mod approval_mode;
pub mod config;
pub mod day1;
pub mod integrate;
pub mod integrations;
pub mod prove;
pub mod status;
pub mod support_bundle;
pub mod update;

#[cfg(feature = "enterprise")]
pub use crate::enterprise::pilot::{run_enroll, EnrollArgs};

#[cfg(not(feature = "enterprise"))]
mod doctor_local;
#[cfg(not(feature = "enterprise"))]
mod enroll_stub;

#[cfg(not(feature = "enterprise"))]
pub use enroll_stub::{run_enroll, EnrollArgs};

pub use integrate::run_integrate;
pub use integrations::run_integrations;
pub use prove::run_prove;
pub use status::run_status;
pub use support_bundle::run_support_bundle;

use anyhow::Result;
use std::path::PathBuf;

/// Pilot subcommands parsed from argv.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PilotCommand {
    Status,
    Doctor,
    Integrations,
    Integrate {
        target: String,
    },
    Prove,
    SupportBundle {
        out: Option<PathBuf>,
    },
    Enroll(EnrollArgs),
    /// Signed release-channel check (no auto-install).
    Update {
        check_only: bool,
    },
    ApprovalMode {
        mode: String,
    },
    TestRemoteApproval,
}

/// Dispatches a pilot command.
pub async fn run_pilot(cmd: PilotCommand) -> Result<()> {
    match cmd {
        PilotCommand::Status => run_status(),
        PilotCommand::Doctor => {
            #[cfg(feature = "enterprise")]
            {
                let ok = crate::enterprise::pilot::doctor::run_doctor().await?;
                if !ok {
                    anyhow::bail!("doctor reported FAIL checks");
                }
                Ok(())
            }
            #[cfg(not(feature = "enterprise"))]
            {
                doctor_local::run_doctor()
            }
        }
        PilotCommand::Integrations => run_integrations(),
        PilotCommand::Integrate { target } => run_integrate(&target),
        PilotCommand::Prove => run_prove().await,
        PilotCommand::SupportBundle { out } => {
            run_support_bundle(out).await?;
            Ok(())
        }
        PilotCommand::Enroll(args) => run_enroll(args),
        PilotCommand::Update { check_only } => update::run_update(check_only).await,
        PilotCommand::ApprovalMode { mode } => approval_mode::run_approval_mode(&mode),
        PilotCommand::TestRemoteApproval => {
            #[cfg(feature = "enterprise")]
            {
                crate::enterprise::pilot::test_remote_approval::run_test_remote_approval().await
            }
            #[cfg(not(feature = "enterprise"))]
            {
                anyhow::bail!("test-remote-approval requires the enterprise build")
            }
        }
    }
}

/// Parses `status|doctor|integrations|support-bundle|enroll …` from argv after program name.
///
/// Returns `None` if the first arg is not a pilot command.
pub fn parse_pilot_command(argv: &[String]) -> Result<Option<PilotCommand>> {
    let args: Vec<&str> = argv.iter().skip(1).map(String::as_str).collect();
    let Some(first) = args.first().copied() else {
        return Ok(None);
    };
    match first {
        "status" => Ok(Some(PilotCommand::Status)),
        "doctor" => Ok(Some(PilotCommand::Doctor)),
        "integrations" => Ok(Some(PilotCommand::Integrations)),
        "integrate" => {
            let target = args
                .get(1)
                .copied()
                .unwrap_or("cursor")
                .to_string();
            if args.len() > 2 {
                anyhow::bail!(
                    "usage: mcp-proxy integrate [cursor]\n\
                     Primary Day-1 path: Cursor + MCP"
                );
            }
            Ok(Some(PilotCommand::Integrate { target }))
        }
        "prove" => Ok(Some(PilotCommand::Prove)),
        "support-bundle" | "support_bundle" => {
            let mut out = None;
            let mut rest = args.iter().skip(1);
            while let Some(arg) = rest.next() {
                match *arg {
                    "--out" | "-o" => {
                        let path = rest
                            .next()
                            .ok_or_else(|| anyhow::anyhow!("missing path after --out"))?;
                        out = Some(PathBuf::from(path));
                    }
                    other => anyhow::bail!("unknown support-bundle option `{other}`"),
                }
            }
            Ok(Some(PilotCommand::SupportBundle { out }))
        }
        "enroll" => {
            #[cfg(feature = "enterprise")]
            {
                Ok(Some(PilotCommand::Enroll(parse_enroll_args(&args[1..])?)))
            }
            #[cfg(not(feature = "enterprise"))]
            {
                let _ = &args;
                anyhow::bail!(
                    "unknown command `enroll`\n\
                     Enterprise management is available separately.\n\
                     Try: mcp-proxy --help"
                )
            }
        }
        "approval-mode" | "approval_mode" => {
            #[cfg(feature = "enterprise")]
            {
                let mode = args
                    .get(1)
                    .copied()
                    .ok_or_else(|| {
                        anyhow::anyhow!(
                            "usage: mcp-proxy approval-mode <local|remote|auto>"
                        )
                    })?
                    .to_string();
                if args.len() > 2 {
                    anyhow::bail!("usage: mcp-proxy approval-mode <local|remote|auto>");
                }
                Ok(Some(PilotCommand::ApprovalMode { mode }))
            }
            #[cfg(not(feature = "enterprise"))]
            {
                let _ = &args;
                anyhow::bail!(
                    "unknown command `approval-mode`\n\
                     Standalone Core uses local approval by default.\n\
                     Try: mcp-proxy --help"
                )
            }
        }
        "test-remote-approval" | "test_remote_approval" => {
            #[cfg(feature = "enterprise")]
            {
                if args.len() > 1 {
                    anyhow::bail!("usage: mcp-proxy test-remote-approval");
                }
                Ok(Some(PilotCommand::TestRemoteApproval))
            }
            #[cfg(not(feature = "enterprise"))]
            {
                let _ = &args;
                anyhow::bail!(
                    "unknown command `test-remote-approval`\n\
                     Enterprise management is available separately.\n\
                     Try: mcp-proxy --help"
                )
            }
        }
        "update" => {
            let check_only = args.iter().any(|a| *a == "--check" || *a == "-c");
            for arg in args.iter().skip(1) {
                if *arg == "--check" || *arg == "-c" {
                    continue;
                }
                anyhow::bail!(
                    "unknown update option `{arg}`\n\
                     Usage: mcp-proxy update [--check]\n\
                     Auto-install is disabled; use the signed installer to upgrade."
                );
            }
            Ok(Some(PilotCommand::Update { check_only }))
        }
        _ => Ok(None),
    }
}

#[cfg(feature = "enterprise")]
fn parse_enroll_args(args: &[&str]) -> Result<EnrollArgs> {
    let mut control_plane = None;
    let mut device_token = None;
    let mut device_id = None;
    let mut org_id = None;
    let mut iter = args.iter();
    while let Some(arg) = iter.next() {
        match *arg {
            "--control-plane" | "--url" => {
                control_plane = Some(
                    (*iter
                        .next()
                        .ok_or_else(|| anyhow::anyhow!("missing value after --control-plane"))?)
                    .to_string(),
                );
            }
            "--device-token" | "--token" => {
                device_token = Some(
                    (*iter
                        .next()
                        .ok_or_else(|| anyhow::anyhow!("missing value after --device-token"))?)
                    .to_string(),
                );
            }
            "--device-id" => {
                device_id = Some(
                    (*iter
                        .next()
                        .ok_or_else(|| anyhow::anyhow!("missing value after --device-id"))?)
                    .to_string(),
                );
            }
            "--org-id" => {
                org_id = Some(
                    (*iter
                        .next()
                        .ok_or_else(|| anyhow::anyhow!("missing value after --org-id"))?)
                    .to_string(),
                );
            }
            other => anyhow::bail!(
                "unknown enroll option `{other}`\n\
                 Usage: mcp-proxy enroll --control-plane URL --device-token TOKEN [--device-id ID] [--org-id ORG]"
            ),
        }
    }
    Ok(EnrollArgs {
        control_plane: control_plane.unwrap_or_default(),
        device_token: device_token.unwrap_or_default(),
        device_id,
        org_id,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_pilot_verbs() {
        let status = parse_pilot_command(&["mcp-proxy".into(), "status".into()])
            .unwrap()
            .unwrap();
        assert!(matches!(status, PilotCommand::Status));

        let doctor = parse_pilot_command(&["mcp-proxy".into(), "doctor".into()])
            .unwrap()
            .unwrap();
        assert!(matches!(doctor, PilotCommand::Doctor));

        let update = parse_pilot_command(&[
            "mcp-proxy".into(),
            "update".into(),
            "--check".into(),
        ])
        .unwrap()
        .unwrap();
        assert!(matches!(
            update,
            PilotCommand::Update { check_only: true }
        ));

        let enroll = parse_pilot_command(&[
            "mcp-proxy".into(),
            "enroll".into(),
            "--control-plane".into(),
            "https://cp.example".into(),
            "--device-token".into(),
            "tok".into(),
            "--device-id".into(),
            "d1".into(),
        ]);
        #[cfg(feature = "enterprise")]
        {
            match enroll.unwrap().unwrap() {
                PilotCommand::Enroll(args) => {
                    assert_eq!(args.control_plane, "https://cp.example");
                    assert_eq!(args.device_token, "tok");
                    assert_eq!(args.device_id.as_deref(), Some("d1"));
                }
                _ => panic!("expected enroll"),
            }
        }
        #[cfg(not(feature = "enterprise"))]
        {
            assert!(enroll.is_err());
        }
    }

    #[test]
    fn parses_integrate_and_prove() {
        let integrate = parse_pilot_command(&[
            "mcp-proxy".into(),
            "integrate".into(),
            "cursor".into(),
        ])
        .unwrap()
        .unwrap();
        assert!(matches!(
            integrate,
            PilotCommand::Integrate { target } if target == "cursor"
        ));

        let prove = parse_pilot_command(&["mcp-proxy".into(), "prove".into()])
            .unwrap()
            .unwrap();
        assert!(matches!(prove, PilotCommand::Prove));

        let mode = parse_pilot_command(&[
            "mcp-proxy".into(),
            "approval-mode".into(),
            "remote".into(),
        ]);
        let test = parse_pilot_command(&[
            "mcp-proxy".into(),
            "test-remote-approval".into(),
        ]);
        #[cfg(feature = "enterprise")]
        {
            assert!(matches!(
                mode.unwrap().unwrap(),
                PilotCommand::ApprovalMode { mode } if mode == "remote"
            ));
            assert!(matches!(
                test.unwrap().unwrap(),
                PilotCommand::TestRemoteApproval
            ));
        }
        #[cfg(not(feature = "enterprise"))]
        {
            assert!(mode.is_err());
            assert!(test.is_err());
        }
    }

    #[test]
    fn non_pilot_returns_none() {
        let mode = parse_pilot_command(&["mcp-proxy".into(), "demo".into()]).unwrap();
        assert!(mode.is_none());
    }
}
