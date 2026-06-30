//! Hot-reloadable policy handle shared across relay tasks.
//!
//! Policy is refreshed from the control plane (or local file) every
//! [`POLICY_REFRESH_INTERVAL`] when a `tools/call` is evaluated, so IDE
//! MCP processes pick up dashboard policy changes without a manual restart.

use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant};

use anyhow::Result;

use crate::cloud_client::{CloudClient, PolicySyncSource};
use crate::policy::{build_engine, load_config_optional, PolicyEngine};

/// Minimum interval between control-plane policy sync attempts.
pub const POLICY_REFRESH_INTERVAL: Duration = Duration::from_secs(5);

/// Thread-safe, periodically refreshed policy snapshot.
#[derive(Debug)]
pub struct PolicyStore {
    engine: RwLock<Option<Arc<PolicyEngine>>>,
    last_refresh: RwLock<Instant>,
}

impl PolicyStore {
    /// Creates a store seeded with the policy loaded at process startup.
    pub fn new(engine: Option<PolicyEngine>) -> Self {
        Self {
            engine: RwLock::new(engine.map(Arc::new)),
            last_refresh: RwLock::new(Instant::now()),
        }
    }

    /// Returns the current compiled policy, if any.
    pub fn snapshot(&self) -> Option<Arc<PolicyEngine>> {
        self.engine.read().ok()?.clone()
    }

    /// Reloads policy when the refresh interval has elapsed.
    pub async fn refresh_if_stale(&self, cloud_client: Option<&CloudClient>) {
        let stale = self
            .last_refresh
            .read()
            .map(|instant| instant.elapsed() >= POLICY_REFRESH_INTERVAL)
            .unwrap_or(true);

        if !stale {
            return;
        }

        if let Ok(engine) = load_policy_engine(cloud_client).await {
            if let Ok(mut guard) = self.engine.write() {
                *guard = engine.map(Arc::new);
            }
            if let Ok(mut guard) = self.last_refresh.write() {
                *guard = Instant::now();
            }
        }
    }
}

/// Loads policy from the control plane when configured, otherwise from local YAML.
pub async fn load_policy_engine(
    cloud_client: Option<&CloudClient>,
) -> Result<Option<PolicyEngine>> {
    let local_config = load_config_optional()?;

    if let Some(client) = cloud_client {
        match client.fetch_latest_policy().await {
            Ok((remote_config, source)) => {
                let label = match source {
                    PolicySyncSource::ControlPlane => "control plane",
                    PolicySyncSource::Cache => "cache",
                    PolicySyncSource::LocalYaml => "local yaml",
                };
                eprintln!(
                    "mcp-proxy: loaded policy v{} from {label} ({} remote tool rules)",
                    remote_config.version,
                    remote_config.tools.len()
                );
                return build_engine(Some(remote_config), local_config);
            }
            Err(error) => {
                eprintln!("mcp-proxy: cloud policy sync unavailable: {error:#}");
            }
        }
    }

    build_engine(None, local_config)
}
