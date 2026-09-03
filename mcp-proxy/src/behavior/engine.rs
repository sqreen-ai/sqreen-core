//! Behavioral detection engine — profiles actions and emits findings.
//!
//! # Enforcement model
//!
//! Detectors **signal**; they do not block. Callers (typically the gateway) feed
//! [`BehaviorFinding`] into policy match context so operators decide
//! `ALLOW` / `DENY` / `REQUIRE_APPROVAL` per signal via declarative rules.
//!
//! # Evaluate then record
//!
//! [`BehaviorEngine::evaluate`] must run **before** [`BehaviorEngine::record`] so
//! "never seen before" detectors observe the prior baseline.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use chrono::Utc;

use crate::action::AgentAction;

use super::detectors::{default_detectors, BehaviorDetector, DetectionContext};
use super::features::profile_record_from_action;
use super::session::SessionTracker;
use super::types::{BehaviorFinding, BehaviorProfile, BehaviorSignal};

/// Tunables for deterministic detectors.
#[derive(Debug, Clone)]
pub struct BehaviorConfig {
    /// Minimum historical actions before novel-* detectors fire.
    pub min_profile_actions: u64,
    /// Sliding window for high-volume reads.
    pub read_volume_window: Duration,
    /// Read count inside the window that raises [`BehaviorSignalKind::HighVolumeReads`].
    pub read_volume_threshold: usize,
    /// Window for destructive-after-reads sequences.
    pub sequence_window: Duration,
    /// Minimum prior reads required for destructive-after-reads.
    pub min_reads_before_destructive: usize,
    /// Current rate must exceed baseline × this multiplier.
    pub frequency_multiplier: f64,
    /// Max timestamps retained per profile.
    pub max_timestamps: usize,
    /// Max recent action records retained per profile.
    pub max_recent_actions: usize,
    /// Max profiles retained (LRU-ish by eviction of arbitrary key when exceeded).
    pub max_profiles: usize,
}

impl Default for BehaviorConfig {
    fn default() -> Self {
        Self {
            min_profile_actions: 5,
            read_volume_window: Duration::from_secs(60),
            read_volume_threshold: 10,
            sequence_window: Duration::from_secs(120),
            min_reads_before_destructive: 3,
            frequency_multiplier: 3.0,
            max_timestamps: 256,
            max_recent_actions: 64,
            max_profiles: 1_024,
        }
    }
}

/// Deterministic/statistical behavioral detection over per-agent profiles.
pub struct BehaviorEngine {
    config: BehaviorConfig,
    detectors: Vec<Arc<dyn BehaviorDetector>>,
    profiles: Mutex<HashMap<String, BehaviorProfile>>,
    session: Option<Arc<SessionTracker>>,
}

impl Default for BehaviorEngine {
    fn default() -> Self {
        Self::new(BehaviorConfig::default(), None)
    }
}

impl BehaviorEngine {
    /// Builds an engine with the default detector set.
    pub fn new(config: BehaviorConfig, session: Option<Arc<SessionTracker>>) -> Self {
        Self {
            config,
            detectors: default_detectors(),
            profiles: Mutex::new(HashMap::new()),
            session,
        }
    }

    /// Builds an engine with a custom detector list (for tests / future detectors).
    pub fn with_detectors(
        config: BehaviorConfig,
        session: Option<Arc<SessionTracker>>,
        detectors: Vec<Arc<dyn BehaviorDetector>>,
    ) -> Self {
        Self {
            config,
            detectors,
            profiles: Mutex::new(HashMap::new()),
            session,
        }
    }

    /// Returns the config in force.
    pub fn config(&self) -> &BehaviorConfig {
        &self.config
    }

    /// Stable profile key for an action.
    pub fn profile_key(action: &AgentAction) -> String {
        let agent = action.identity.effective_agent_id();
        match action.identity.workspace_id.as_ref() {
            Some(workspace) => format!("{agent}|{}", workspace.as_str()),
            None => agent.to_string(),
        }
    }

    /// Runs all detectors against the current profile **without** mutating it.
    pub fn evaluate(&self, action: &AgentAction) -> BehaviorFinding {
        let key = Self::profile_key(action);
        let now = Utc::now();

        let profiles = self
            .profiles
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let empty = BehaviorProfile::new(&key, now);
        let profile = profiles.get(&key).unwrap_or(&empty);

        let ctx = DetectionContext {
            action,
            profile,
            session: self.session.as_deref(),
            now,
            config: &self.config,
        };

        let mut signals: Vec<BehaviorSignal> = self
            .detectors
            .iter()
            .flat_map(|detector| detector.observe(&ctx))
            .collect();

        // Deterministic order for stable tests / audit.
        signals.sort_by(|left, right| {
            right
                .severity
                .cmp(&left.severity)
                .then_with(|| left.kind.as_str().cmp(right.kind.as_str()))
                .then_with(|| left.detector_id.cmp(&right.detector_id))
        });

        BehaviorFinding::from_signals(key, signals)
    }

    /// Updates the agent profile after an evaluation is settled.
    pub fn record(&self, action: &AgentAction) {
        let key = Self::profile_key(action);
        let now = Utc::now();
        let record = profile_record_from_action(action, now);

        let mut profiles = self
            .profiles
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());

        if profiles.len() >= self.config.max_profiles && !profiles.contains_key(&key) {
            // Evict an arbitrary entry to bound memory.
            if let Some(evict) = profiles.keys().next().cloned() {
                profiles.remove(&evict);
            }
        }

        let profile = profiles
            .entry(key.clone())
            .or_insert_with(|| BehaviorProfile::new(key, now));

        profile.last_seen = now;
        profile.total_actions = profile.total_actions.saturating_add(1);
        profile
            .seen_tools
            .insert(action.tool_name().to_ascii_lowercase());

        if let Some(dir) = &record.directory_key {
            profile.seen_directories.insert(dir.clone());
        }
        if let Some(domain) = &record.domain {
            profile.seen_domains.insert(domain.clone());
        }
        profile
            .seen_environment_tiers
            .insert(action.identity.environment.tier);

        profile.recent_timestamps.push_back(now);
        while profile.recent_timestamps.len() > self.config.max_timestamps {
            profile.recent_timestamps.pop_front();
        }

        profile.recent_actions.push_back(record);
        while profile.recent_actions.len() > self.config.max_recent_actions {
            profile.recent_actions.pop_front();
        }
    }

    /// Snapshot of a profile for tests.
    pub fn profile_snapshot(&self, key: &str) -> Option<BehaviorProfile> {
        self.profiles
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .get(key)
            .cloned()
    }

    /// Number of retained profiles.
    pub fn profile_count(&self) -> usize {
        self.profiles
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .len()
    }

    /// Seeds a profile with synthetic history (tests).
    pub fn seed_profile(&self, profile: BehaviorProfile) {
        let mut profiles = self
            .profiles
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        profiles.insert(profile.profile_key.clone(), profile);
    }
}

/// Helper to build a warmed profile from a sequence of historical actions (tests).
pub fn build_profile_from_history(
    profile_key: &str,
    history: &[AgentAction],
    config: &BehaviorConfig,
) -> BehaviorProfile {
    let now = Utc::now();
    let mut profile = BehaviorProfile::new(profile_key, now);
    for action in history {
        let record = profile_record_from_action(action, now);
        profile.total_actions = profile.total_actions.saturating_add(1);
        profile.last_seen = now;
        profile
            .seen_tools
            .insert(action.tool_name().to_ascii_lowercase());
        if let Some(dir) = &record.directory_key {
            profile.seen_directories.insert(dir.clone());
        }
        if let Some(domain) = &record.domain {
            profile.seen_domains.insert(domain.clone());
        }
        profile
            .seen_environment_tiers
            .insert(action.identity.environment.tier);
        profile.recent_timestamps.push_back(now);
        profile.recent_actions.push_back(record);
    }

    while profile.recent_timestamps.len() > config.max_timestamps {
        profile.recent_timestamps.pop_front();
    }
    while profile.recent_actions.len() > config.max_recent_actions {
        profile.recent_actions.pop_front();
    }

    profile
}
