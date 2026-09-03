//! Behavioral Detection Engine for AI agents.
//!
//! Deterministic and statistical signals over per-agent [`BehaviorProfile`]s.
//! No LLM and no machine learning — detectors are small, auditable rules that
//! emit [`BehaviorSignal`]s aggregated into a [`BehaviorFinding`].
//!
//! # Policy integration
//!
//! Findings **augment** policy; they do not auto-block. Policy rules may match:
//!
//! - `behavior.signal` — signal kind slug (e.g. `novel_sensitive_directory`)
//! - `behavior.severity` — exact max severity (`LOW`…`CRITICAL`)
//! - `behavior.severity_at_least` — minimum severity floor
//!
//! Effects remain the ordinary `allow` / `deny` / `require_approval`.

mod detectors;
mod engine;
mod features;
mod session;
mod types;

#[cfg(test)]
mod tests;

pub use detectors::{default_detectors, BehaviorDetector, DetectionContext};
pub use engine::{build_profile_from_history, BehaviorConfig, BehaviorEngine};
pub use session::{
    SessionTracker, DEFAULT_SESSION_CAPACITY, FILESYSTEM_TOOLS, MIN_FILESYSTEM_PROBES,
    NETWORK_TOOLS, SHELL_TOOLS, TELEMETRY_BEHAVIORAL_CHAIN,
};
pub use types::{
    BehaviorFinding, BehaviorProfile, BehaviorSeverity, BehaviorSignal, BehaviorSignalKind,
    ProfileActionRecord,
};
