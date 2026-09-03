//! Hot-reloadable policy handle shared across relay tasks.
//!
//! Policy is refreshed from the control plane (or local file) every
//! [`POLICY_REFRESH_INTERVAL`] when a `tools/call` is evaluated, so IDE
//! MCP processes pick up dashboard policy changes without a manual restart.

use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant};

use anyhow::Result;

use crate::cloud_client::{CloudClient, PolicySyncSource};
use crate::gateway::PolicyAvailability;
use crate::policy::{build_engine_composed, load_config_optional, PolicyEngine};

/// Minimum interval between control-plane policy sync attempts.
pub const POLICY_REFRESH_INTERVAL: Duration = Duration::from_secs(5);

/// Thread-safe, periodically refreshed policy snapshot.
#[derive(Debug)]
pub struct PolicyStore {
    engine: RwLock<Option<Arc<PolicyEngine>>>,
    availability: RwLock<PolicyAvailability>,
    last_refresh: RwLock<Instant>,
}

impl PolicyStore {
    /// Creates a store seeded with the policy loaded at process startup.
    pub fn new(engine: Option<PolicyEngine>) -> Self {
        let availability = if engine.is_some() {
            PolicyAvailability::Available
        } else {
            PolicyAvailability::Missing
        };
        Self {
            engine: RwLock::new(engine.map(Arc::new)),
            availability: RwLock::new(availability),
            last_refresh: RwLock::new(Instant::now()),
        }
    }

    /// Creates a store with an explicit availability state (tests / managed bootstrap).
    pub fn with_availability(
        engine: Option<PolicyEngine>,
        availability: PolicyAvailability,
    ) -> Self {
        Self {
            engine: RwLock::new(engine.map(Arc::new)),
            availability: RwLock::new(availability),
            last_refresh: RwLock::new(Instant::now()),
        }
    }

    /// Returns the current compiled policy, if any.
    ///
    /// Recovers a poisoned lock rather than reporting "no policy". A panic in an unrelated
    /// task poisons the lock; treating that as an absent policy would disable enforcement
    /// process-wide, silently and permanently, which is the most consequential possible
    /// reading of `.ok()?`. The guarded value is an immutable snapshot, so a writer that
    /// panicked cannot have left it half-updated.
    pub fn snapshot(&self) -> Option<Arc<PolicyEngine>> {
        self.engine
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clone()
    }

    /// Machine-readable availability of the declarative policy source.
    pub fn availability(&self) -> PolicyAvailability {
        *self
            .availability
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    /// Reloads policy when the refresh interval has elapsed.
    ///
    /// # Never downgrades to unprotected
    ///
    /// A refresh that yields no policy — the file was deleted, renamed, or moved out from
    /// under a running proxy — leaves the previous snapshot in place instead of clearing
    /// it. Clearing it would silently drop the process into passthrough mode within one
    /// refresh interval, which makes "delete the policy file" a complete bypass available
    /// to anything that can write to the config directory.
    ///
    /// Startup is the only point at which "no policy" is accepted, and it is reported on
    /// stderr when it happens. Runtime keep-previous is reported as
    /// [`PolicyAvailability::Stale`].
    pub async fn refresh_if_stale(&self, cloud_client: Option<&CloudClient>) {
        let stale = self
            .last_refresh
            .read()
            .map(|instant| instant.elapsed() >= POLICY_REFRESH_INTERVAL)
            .unwrap_or(true);

        if !stale {
            return;
        }

        // Marked before the outcome is known so a persistently failing source is retried
        // on the interval rather than on every single tool call.
        *self
            .last_refresh
            .write()
            .unwrap_or_else(|poisoned| poisoned.into_inner()) = Instant::now();

        let load_result = load_policy_engine_with_status(cloud_client).await;

        let mut guard = self
            .engine
            .write()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let mut availability = self
            .availability
            .write()
            .unwrap_or_else(|poisoned| poisoned.into_inner());

        match load_result {
            Ok(LoadOutcome::Loaded { engine, source }) => {
                *guard = Some(Arc::new(engine));
                *availability = match source {
                    PolicyLoadSource::ControlPlane | PolicyLoadSource::LocalYaml => {
                        PolicyAvailability::Available
                    }
                    PolicyLoadSource::Cache => PolicyAvailability::Stale,
                };
            }
            Ok(LoadOutcome::Absent) => {
                if guard.is_some() {
                    eprintln!(
                        "mcp-proxy: policy source returned no policy; \
                         keeping the previously loaded one rather than dropping enforcement"
                    );
                    *availability = PolicyAvailability::Stale;
                } else {
                    *availability = PolicyAvailability::Missing;
                }
            }
            Err(LoadError::Unreadable(error)) => {
                eprintln!(
                    "mcp-proxy: policy refresh failed ({error:#}); \
                     keeping the previously loaded policy"
                );
                if guard.is_some() {
                    *availability = PolicyAvailability::Stale;
                } else {
                    *availability = PolicyAvailability::Unreadable;
                }
            }
            Err(LoadError::Invalid(error)) => {
                eprintln!(
                    "mcp-proxy: policy refresh failed ({error:#}); \
                     keeping the previously loaded policy"
                );
                if guard.is_some() {
                    *availability = PolicyAvailability::Stale;
                } else {
                    *availability = PolicyAvailability::Invalid;
                }
            }
            Err(LoadError::RemoteUnavailable(error)) => {
                eprintln!(
                    "mcp-proxy: managed policy unavailable ({error:#}); \
                     keeping the previously loaded policy when present"
                );
                if guard.is_some() {
                    *availability = PolicyAvailability::Stale;
                } else {
                    *availability = PolicyAvailability::RemoteUnavailable;
                }
            }
        }
    }
}

/// Where a successful load came from (for availability tagging).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PolicyLoadSource {
    ControlPlane,
    Cache,
    LocalYaml,
}

enum LoadOutcome {
    Loaded {
        engine: PolicyEngine,
        source: PolicyLoadSource,
    },
    Absent,
}

enum LoadError {
    Unreadable(anyhow::Error),
    Invalid(anyhow::Error),
    RemoteUnavailable(anyhow::Error),
}

/// Loads policy from the control plane when configured, otherwise from local YAML.
pub async fn load_policy_engine(
    cloud_client: Option<&CloudClient>,
) -> Result<Option<PolicyEngine>> {
    match load_policy_engine_with_status(cloud_client).await {
        Ok(LoadOutcome::Loaded { engine, .. }) => Ok(Some(engine)),
        Ok(LoadOutcome::Absent) => Ok(None),
        Err(LoadError::Unreadable(e) | LoadError::Invalid(e) | LoadError::RemoteUnavailable(e)) => {
            Err(e)
        }
    }
}

async fn load_policy_engine_with_status(
    cloud_client: Option<&CloudClient>,
) -> Result<LoadOutcome, LoadError> {
    let local_config = match load_config_optional() {
        Ok(config) => config,
        Err(error) => {
            let message = format!("{error:#}").to_ascii_lowercase();
            if message.contains("empty") || message.contains("parse") || message.contains("yaml") {
                return Err(LoadError::Invalid(error));
            }
            return Err(LoadError::Unreadable(error));
        }
    };

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
                let load_source = match source {
                    PolicySyncSource::ControlPlane => PolicyLoadSource::ControlPlane,
                    PolicySyncSource::Cache => PolicyLoadSource::Cache,
                    PolicySyncSource::LocalYaml => PolicyLoadSource::LocalYaml,
                };
                return match build_engine_composed(Some(remote_config), local_config) {
                    Ok(Some(engine)) => Ok(LoadOutcome::Loaded {
                        engine,
                        source: load_source,
                    }),
                    Ok(None) => Ok(LoadOutcome::Absent),
                    Err(error) => Err(LoadError::Invalid(error)),
                };
            }
            Err(error) => {
                eprintln!("mcp-proxy: cloud policy sync unavailable: {error:#}");
                // When signed managed policy is required, do not silently fall back to
                // weaker unsigned local YAML after a failed/rejected remote sync.
                if crate::policy::require_signed_policy() {
                    return Err(LoadError::RemoteUnavailable(error));
                }
                if local_config.is_none() {
                    return Err(LoadError::RemoteUnavailable(error));
                }
                // Unsigned explicitly allowed: local YAML may be used.
            }
        }
    }

    match build_engine_composed(None, local_config) {
        Ok(Some(engine)) => Ok(LoadOutcome::Loaded {
            engine,
            source: PolicyLoadSource::LocalYaml,
        }),
        Ok(None) => Ok(LoadOutcome::Absent),
        Err(error) => Err(LoadError::Invalid(error)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_store_marks_missing_when_empty() {
        let store = PolicyStore::new(None);
        assert!(store.snapshot().is_none());
        assert_eq!(store.availability(), PolicyAvailability::Missing);
    }

    #[test]
    fn new_store_marks_available_when_seeded() {
        let engine = PolicyEngine::from_yaml(
            r#"
version: "1"
global:
  redact_keys: []
  risk_threshold: 70
  block_patterns: []
tools: []
"#,
        )
        .expect("policy");
        let store = PolicyStore::new(Some(engine));
        assert!(store.snapshot().is_some());
        assert_eq!(store.availability(), PolicyAvailability::Available);
    }
}
