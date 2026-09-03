//! `mcp-proxy enroll` — write control-plane URL + device token to local env (0600).

use anyhow::{bail, Context, Result};

use super::config::{env_file_path, upsert_env_file};
use crate::cloud_client::{CONTROL_PLANE_URL_ENV, DEVICE_ID_ENV, DEVICE_TOKEN_ENV};

/// Flag-based enrollment arguments (no interactive secret prompts).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EnrollArgs {
    pub control_plane: String,
    pub device_token: String,
    pub device_id: Option<String>,
    pub org_id: Option<String>,
}

/// Writes enrollment env without echoing the device token.
pub fn run_enroll(args: EnrollArgs) -> Result<()> {
    let url = args.control_plane.trim().to_string();
    let token = args.device_token.trim().to_string();
    if url.is_empty() {
        bail!(enroll_error_checklist(
            "missing --control-plane URL",
            "Provide the Cloud SOC / control-plane base URL (e.g. https://api.example.com)."
        ));
    }
    if token.is_empty() {
        bail!(enroll_error_checklist(
            "missing --device-token",
            "Mint a device token in Cloud SOC → Agent Identities, then pass --device-token."
        ));
    }
    if !(url.starts_with("http://") || url.starts_with("https://")) {
        bail!(enroll_error_checklist(
            "invalid --control-plane URL",
            "URL must start with http:// or https://."
        ));
    }

    let device_id = args
        .device_id
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(|s| s.to_string());
    let org_id = args
        .org_id
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(|s| s.to_string());

    let mut owned: Vec<(String, String)> = vec![
        (CONTROL_PLANE_URL_ENV.to_string(), url.clone()),
        (DEVICE_TOKEN_ENV.to_string(), token),
    ];
    if let Some(ref id) = device_id {
        owned.push((DEVICE_ID_ENV.to_string(), id.clone()));
    }
    if let Some(ref org) = org_id {
        owned.push((crate::policy::ORG_ID_ENV.to_string(), org.clone()));
    }

    let refs: Vec<(&str, &str)> = owned
        .iter()
        .map(|(k, v)| (k.as_str(), v.as_str()))
        .collect();
    let path = upsert_env_file(&refs).context("failed to write enrollment env")?;

    println!();
    println!("Sqreen Core · enroll");
    println!("────────────────────");
    println!("  Wrote:              {}", path.display());
    println!("  Control plane URL:  {url}");
    println!("  Device token:       [SET] (not printed)");
    if let Some(ref id) = device_id {
        println!("  Device ID:          {id}");
    }
    if let Some(ref org) = org_id {
        println!("  Org ID:             {org}");
    }
    println!();
    println!("Next:");
    println!("  source {}", env_file_path().display());
    println!("  mcp-proxy doctor");
    println!("  mcp-proxy status");
    println!();
    println!("If cloud sync fails, check:");
    println!("  • URL reachable from this machine (TLS / firewall / VPN)");
    println!("  • Device token still active (not revoked) in Cloud SOC");
    println!("  • Clock roughly in sync (TLS + approval expiry)");
    println!();
    Ok(())
}

fn enroll_error_checklist(summary: &str, hint: &str) -> String {
    format!(
        "{summary}\n\
         \n\
         Checklist:\n\
           • {hint}\n\
           • Example:\n\
               mcp-proxy enroll --control-plane https://api.example.com \\\n\
                 --device-token <TOKEN> [--device-id <ID>] [--org-id <ORG>]\n\
           • Never paste tokens into chat logs or commit ~/.config/mcp-proxy/env\n\
           • After enroll: source ~/.config/mcp-proxy/env && mcp-proxy doctor"
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pilot::config::{read_env_file, redact_env_value};
    use std::fs;

    #[test]
    fn enroll_writes_without_echoing_token_in_helpers() {
        let _guard = crate::pilot::config::test_env_lock();
        let tmp = std::env::temp_dir().join(format!("sqreen-enroll-{}", std::process::id()));
        let _ = fs::remove_dir_all(&tmp);
        fs::create_dir_all(&tmp).unwrap();
        unsafe {
            std::env::set_var("HOME", &tmp);
            std::env::remove_var("XDG_CONFIG_HOME");
        }
        run_enroll(EnrollArgs {
            control_plane: "https://cp.example.com".into(),
            device_token: "super-secret-token".into(),
            device_id: Some("dev-1".into()),
            org_id: Some("acme".into()),
        })
        .unwrap();
        let path = tmp.join(".config/mcp-proxy/env");
        let pairs = read_env_file(&path).unwrap();
        let map: std::collections::BTreeMap<_, _> = pairs.into_iter().collect();
        assert_eq!(
            map.get("MCP_CONTROL_PLANE_URL").map(String::as_str),
            Some("https://cp.example.com")
        );
        assert_eq!(
            map.get("MCP_DEVICE_TOKEN").map(String::as_str),
            Some("super-secret-token")
        );
        assert_eq!(
            redact_env_value("MCP_DEVICE_TOKEN", "super-secret-token"),
            "[SET]"
        );
        let _ = fs::remove_dir_all(&tmp);
    }

    #[test]
    fn rejects_empty_url() {
        let err = run_enroll(EnrollArgs {
            control_plane: "  ".into(),
            device_token: "tok".into(),
            device_id: None,
            org_id: None,
        })
        .unwrap_err();
        assert!(err.to_string().contains("missing --control-plane"));
    }
}
