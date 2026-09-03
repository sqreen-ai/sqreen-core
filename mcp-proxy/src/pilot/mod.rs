//! Design-partner pilot / onboarding CLI surface.
//!
//! Commands: `status`, `doctor`, `integrations`, `support-bundle`, `enroll`, `update`.

pub mod config;
pub mod doctor;
pub mod enroll;
pub mod integrations;
pub mod status;
pub mod support_bundle;
pub mod update;

pub use enroll::{run_enroll, EnrollArgs};
pub use integrations::run_integrations;
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
    SupportBundle {
        out: Option<PathBuf>,
    },
    Enroll(EnrollArgs),
    /// Signed release-channel check (no auto-install).
    Update {
        check_only: bool,
    },
}

/// Dispatches a pilot command.
pub async fn run_pilot(cmd: PilotCommand) -> Result<()> {
    match cmd {
        PilotCommand::Status => run_status(),
        PilotCommand::Doctor => {
            let ok = doctor::run_doctor().await?;
            if !ok {
                // Non-zero exit is handled by main via Err — keep stdout complete.
                anyhow::bail!("doctor reported FAIL checks");
            }
            Ok(())
        }
        PilotCommand::Integrations => run_integrations(),
        PilotCommand::SupportBundle { out } => {
            run_support_bundle(out).await?;
            Ok(())
        }
        PilotCommand::Enroll(args) => run_enroll(args),
        PilotCommand::Update { check_only } => update::run_update(check_only).await,
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
        "enroll" => Ok(Some(PilotCommand::Enroll(parse_enroll_args(&args[1..])?))),
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
        ])
        .unwrap()
        .unwrap();
        match enroll {
            PilotCommand::Enroll(args) => {
                assert_eq!(args.control_plane, "https://cp.example");
                assert_eq!(args.device_token, "tok");
                assert_eq!(args.device_id.as_deref(), Some("d1"));
            }
            _ => panic!("expected enroll"),
        }
    }

    #[test]
    fn non_pilot_returns_none() {
        let mode = parse_pilot_command(&["mcp-proxy".into(), "demo".into()]).unwrap();
        assert!(mode.is_none());
    }
}
