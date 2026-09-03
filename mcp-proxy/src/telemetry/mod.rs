//! Privacy-conscious behavioral telemetry for evaluated agent actions.
//!
//! # Purpose
//!
//! Build **security-relevant behavioral signals** — not a cloud dump of prompts, secrets,
//! or file contents. Each evaluation can produce an [`AgentSecurityEvent`] that records
//! who (hashed), what kind of action, which policies matched, risk flags, and the decision.
//!
//! # Local-first
//!
//! [`TelemetryMode::Disabled`] and [`TelemetryMode::LocalOnly`] need no control plane.
//! Cloud export is opt-in via [`CloudTelemetryExporter`] and reuses the existing
//! [`crate::cloud_client::CloudClient`] fire-and-forget path for legacy records.
//!
//! # Enforcement isolation
//!
//! [`TelemetryPipeline::emit`] never blocks and never returns an error to the gateway.
//! Queue overflow and export failures increment counters and drop events.

mod event;
mod generate;
mod pipeline;
mod privacy;
mod sink;

pub use event::{
    ActionSignal, AgentIdentitySignal, AgentSecurityEvent, ApprovalSignal, ArgumentSummary,
    DestinationSignal, EnvironmentSignal, PipelineOutcome, PolicyMatchSignal, RiskSignal,
    SessionSignal, EVENT_SCHEMA_VERSION,
};
pub use generate::build_security_event;
pub use pipeline::{
    TelemetryConfig, TelemetryMode, TelemetryPipeline, TelemetryStats, TelemetryStatsSnapshot,
};
pub use privacy::{
    destination_category, extract_domain, hash_identifier, is_sensitive_value_key, PathSummary,
    PrivacyPolicy, DEFAULT_HASH_SALT,
};
pub use sink::{
    CloudTelemetryExporter, CompositeExporter, ExportError, FailingExporter, NullExporter,
    RecordingExporter, TelemetryExporter,
};

use std::sync::Arc;

use crate::action::AgentAction;
use crate::cloud_client::CloudClient;
use crate::gateway::EvaluationOutcome;

/// Builds an event and hands it to the pipeline. Failures are swallowed by design.
pub fn emit_evaluation(
    pipeline: &TelemetryPipeline,
    action: &AgentAction,
    outcome: &EvaluationOutcome,
) {
    if pipeline.is_disabled() {
        return;
    }

    let event = build_security_event(action, outcome, pipeline.privacy());
    pipeline.emit(event);
}

/// Constructs a local-only pipeline with a recording exporter (tests / dry-run).
pub fn local_recording_pipeline(salt: &str) -> (TelemetryPipeline, Arc<RecordingExporter>) {
    let recorder = Arc::new(RecordingExporter::new());
    let pipeline = TelemetryPipeline::start(TelemetryConfig::local(salt), recorder.clone());
    (pipeline, recorder)
}

/// Constructs a cloud-backed pipeline when a control-plane client is available.
pub fn cloud_pipeline(client: Arc<CloudClient>) -> TelemetryPipeline {
    TelemetryPipeline::start(
        TelemetryConfig::cloud(),
        Arc::new(CloudTelemetryExporter::new(client)),
    )
}
