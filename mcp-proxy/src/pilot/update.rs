//! Safe update check against the signed release channel.
//!
//! `mcp-proxy update --check` fetches `release-manifest.json` and compares
//! versions. It does **not** auto-install. Upgrades go through `install.sh`,
//! which verifies the Ed25519-signed manifest + artifact digests.

use anyhow::{bail, Context, Result};
use serde::Deserialize;

const CURRENT: &str = env!("CARGO_PKG_VERSION");

/// Default public release base (override with `SQREEN_RELEASE_BASE`).
const DEFAULT_RELEASE_BASE: &str = "https://sqreen.ai/releases";

#[derive(Debug, Deserialize)]
struct ReleaseManifest {
    version: String,
    #[serde(default)]
    product: Option<String>,
}

/// Runs `update` (with optional `--check`).
pub async fn run_update(check_only: bool) -> Result<()> {
    println!("Sqreen Core · update");
    println!("────────────────────");
    println!("  Current:  mcp-proxy {CURRENT}");

    let base = std::env::var("SQREEN_RELEASE_BASE")
        .unwrap_or_else(|_| DEFAULT_RELEASE_BASE.to_string())
        .trim_end_matches('/')
        .to_string();
    let url = format!("{base}/latest/release-manifest.json");

    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(15))
        .user_agent(format!("mcp-proxy/{CURRENT} update-check"))
        .build()
        .context("failed to build HTTP client for update check")?;

    let response = match client.get(&url).send().await {
        Ok(resp) => resp,
        Err(err) => {
            println!("  Latest:   (unreachable)");
            println!();
            println!("Cannot reach release channel at {url}");
            println!("Check:");
            println!("  1. network / DNS / TLS");
            println!("  2. SQREEN_RELEASE_BASE (currently {base})");
            println!("  3. corporate proxy settings");
            bail!("update check failed: {err}");
        }
    };

    if !response.status().is_success() {
        println!("  Latest:   (HTTP {})", response.status());
        bail!(
            "Cannot fetch release manifest from {url} (HTTP {}). \
             Check SQREEN_RELEASE_BASE and that the release channel is published.",
            response.status()
        );
    }

    let body = response
        .text()
        .await
        .context("failed to read release-manifest.json body")?;
    let manifest: ReleaseManifest = serde_json::from_str(&body).with_context(|| {
        format!("malformed release-manifest.json from {url} (expected JSON with version)")
    })?;

    let latest = normalize_version(&manifest.version);
    let current = normalize_version(CURRENT);
    println!("  Latest:   {}", manifest.version);
    if let Some(product) = manifest.product.as_deref() {
        println!("  Product:  {product}");
    }
    println!("  Manifest: {url}");
    println!();

    match compare_semver_ish(&current, &latest) {
        OrderingResult::Equal => {
            println!("You are on the latest published version.");
            println!("Integrity: upgrades still require a signed release-manifest.json");
            println!("          (see docs/RELEASE_INTEGRITY.md).");
        }
        OrderingResult::Behind => {
            println!("An update is available: {CURRENT} → {}", manifest.version);
            println!();
            println!("Safe upgrade (verifies Ed25519 signature + SHA-256 digests):");
            println!("  curl -fsSL https://sqreen.ai/install.sh | bash");
            println!("  # or pin: bash -s -- --version {}", manifest.version);
            println!();
            println!("This command does not auto-install — re-run the installer.");
        }
        OrderingResult::Ahead => {
            println!("Local build ({CURRENT}) is newer than published latest ({latest}).");
            println!("Typical for development builds.");
        }
        OrderingResult::Unknown => {
            println!("Could not compare versions ({CURRENT} vs {}).", manifest.version);
            println!("If you need an upgrade, re-run the signed installer.");
        }
    }

    if !check_only {
        println!();
        println!("Tip: `mcp-proxy update --check` is the supported check-only form.");
        println!("Auto-update is intentionally disabled; use install.sh for upgrades.");
    }

    Ok(())
}

fn normalize_version(raw: &str) -> String {
    raw.trim().trim_start_matches('v').to_string()
}

enum OrderingResult {
    Equal,
    Behind,
    Ahead,
    Unknown,
}

/// Best-effort numeric compare for `MAJOR.MINOR.PATCH` (+ optional suffix ignored).
fn compare_semver_ish(current: &str, latest: &str) -> OrderingResult {
    let current = normalize_version(current);
    let latest = normalize_version(latest);
    let parse = |s: &str| -> Option<(u64, u64, u64)> {
        let core = s.split(['-', '+']).next().unwrap_or(s);
        let mut parts = core.split('.');
        let major = parts.next()?.parse().ok()?;
        let minor = parts.next()?.parse().ok()?;
        let patch = parts.next().unwrap_or("0").parse().ok()?;
        Some((major, minor, patch))
    };
    match (parse(&current), parse(&latest)) {
        (Some(c), Some(l)) => {
            if c == l {
                OrderingResult::Equal
            } else if c < l {
                OrderingResult::Behind
            } else {
                OrderingResult::Ahead
            }
        }
        _ => OrderingResult::Unknown,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn compares_versions() {
        assert!(matches!(
            compare_semver_ish("0.1.9", "0.1.10"),
            OrderingResult::Behind
        ));
        assert!(matches!(
            compare_semver_ish("0.2.0", "0.1.9"),
            OrderingResult::Ahead
        ));
        assert!(matches!(
            compare_semver_ish("0.1.9", "v0.1.9"),
            OrderingResult::Equal
        ));
    }

    #[test]
    fn normalizes_v_prefix() {
        assert_eq!(normalize_version("v0.1.9"), "0.1.9");
    }
}
