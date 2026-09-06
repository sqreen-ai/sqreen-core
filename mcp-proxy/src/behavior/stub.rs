//! Open-core stub for the advanced behavior profile engine.

use std::sync::Arc;
use std::time::Duration;

use crate::action::AgentAction;

use super::session::SessionTracker;
use super::types::{BehaviorFinding, BehaviorProfile, BehaviorSignal};

#[derive(Debug, Clone)]
pub struct BehaviorConfig {
    pub min_profile_actions: u64,
    pub read_volume_window: Duration,
    pub read_volume_threshold: usize,
    pub sequence_window: Duration,
    pub min_reads_before_destructive: usize,
    pub frequency_multiplier: f64,
    pub max_timestamps: usize,
    pub max_recent_actions: usize,
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

pub struct DetectionContext<'a> {
    pub action: &'a AgentAction,
    pub profile: &'a BehaviorProfile,
    pub session: Option<&'a SessionTracker>,
    pub now: chrono::DateTime<chrono::Utc>,
    pub config: &'a BehaviorConfig,
}

pub trait BehaviorDetector: Send + Sync {
    fn id(&self) -> &'static str;
    fn observe(&self, ctx: &DetectionContext<'_>) -> Vec<BehaviorSignal>;
}

pub fn default_detectors() -> Vec<Arc<dyn BehaviorDetector>> {
    Vec::new()
}

pub fn build_profile_from_history(
    profile_key: &str,
    _history: &[AgentAction],
    _config: &BehaviorConfig,
) -> BehaviorProfile {
    BehaviorProfile::new(profile_key, chrono::Utc::now())
}

#[derive(Debug, Default)]
pub struct BehaviorEngine {
    config: BehaviorConfig,
}

impl BehaviorEngine {
    pub fn new(config: BehaviorConfig, _session: Option<Arc<SessionTracker>>) -> Self {
        Self { config }
    }

    pub fn with_detectors(
        config: BehaviorConfig,
        session: Option<Arc<SessionTracker>>,
        _detectors: Vec<Arc<dyn BehaviorDetector>>,
    ) -> Self {
        Self::new(config, session)
    }

    pub fn profile_key(action: &AgentAction) -> String {
        action.tool_name().to_string()
    }

    pub fn evaluate(&self, action: &AgentAction) -> BehaviorFinding {
        BehaviorFinding::empty(Self::profile_key(action))
    }

    pub fn record(&self, _action: &AgentAction) {}

    pub fn seed_profile(&self, _profile: BehaviorProfile) {}

    pub fn config(&self) -> &BehaviorConfig {
        &self.config
    }
}
