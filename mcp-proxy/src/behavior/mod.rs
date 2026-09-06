//! Behavioral Detection Engine for AI agents.
//!
//! Open-core keeps session chain tracking and signal types. The advanced profile
//! engine and detector set live under `enterprise` and are compiled only with that
//! feature.

pub mod session;
mod types;

#[cfg(feature = "enterprise")]
pub use crate::enterprise::behavior::{
    build_profile_from_history, default_detectors, BehaviorConfig, BehaviorDetector,
    BehaviorEngine, DetectionContext,
};

#[cfg(not(feature = "enterprise"))]
mod stub;

#[cfg(not(feature = "enterprise"))]
pub use stub::{
    build_profile_from_history, default_detectors, BehaviorConfig, BehaviorDetector,
    BehaviorEngine, DetectionContext,
};

pub use session::{
    SessionTracker, DEFAULT_SESSION_CAPACITY, FILESYSTEM_TOOLS, MIN_FILESYSTEM_PROBES,
    NETWORK_TOOLS, SHELL_TOOLS, TELEMETRY_BEHAVIORAL_CHAIN,
};
pub use types::{
    BehaviorFinding, BehaviorProfile, BehaviorSeverity, BehaviorSignal, BehaviorSignalKind,
    ProfileActionRecord,
};
