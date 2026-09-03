//! Telemetry export destinations.
//!
//! Exporters must never influence security decisions. Failures are returned as
//! [`ExportError`] for the pipeline to retry or drop.

use std::fmt;
use std::sync::{Arc, Mutex};

use super::event::AgentSecurityEvent;
use crate::cloud_client::{CloudClient, TelemetryRecord, UserDecision};
use crate::gateway::Decision;

/// An exporter failed to deliver a batch.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExportError {
    /// Exporter name.
    pub exporter: &'static str,
    /// Sanitized failure detail.
    pub detail: String,
    /// When true, retrying is unlikely to help (e.g. schema rejection).
    pub permanent: bool,
}

impl ExportError {
    pub fn new(exporter: &'static str, detail: impl Into<String>) -> Self {
        Self {
            exporter,
            detail: detail.into(),
            permanent: false,
        }
    }

    pub fn permanent(exporter: &'static str, detail: impl Into<String>) -> Self {
        Self {
            exporter,
            detail: detail.into(),
            permanent: true,
        }
    }
}

impl fmt::Display for ExportError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}: {}", self.exporter, self.detail)
    }
}

impl std::error::Error for ExportError {}

/// Destination for batched [`AgentSecurityEvent`]s.
pub trait TelemetryExporter: Send + Sync {
    /// Exports a non-empty batch. Must not panic; may fail with [`ExportError`].
    fn export(&self, batch: &[AgentSecurityEvent]) -> Result<(), ExportError>;

    /// Stable name for diagnostics.
    fn name(&self) -> &'static str;
}

/// Discards every batch — local-only / telemetry-disabled deployments.
#[derive(Debug, Clone, Copy, Default)]
pub struct NullExporter;

impl TelemetryExporter for NullExporter {
    fn export(&self, _batch: &[AgentSecurityEvent]) -> Result<(), ExportError> {
        Ok(())
    }

    fn name(&self) -> &'static str {
        "null"
    }
}

/// Records batches in memory for tests.
#[derive(Debug, Clone, Default)]
pub struct RecordingExporter {
    batches: Arc<Mutex<Vec<Vec<AgentSecurityEvent>>>>,
}

impl RecordingExporter {
    pub fn new() -> Self {
        Self::default()
    }

    /// Flattens all recorded events, oldest first.
    pub fn events(&self) -> Vec<AgentSecurityEvent> {
        self.batches
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .iter()
            .flatten()
            .cloned()
            .collect()
    }

    /// Number of export calls.
    pub fn batch_count(&self) -> usize {
        self.batches
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .len()
    }

    pub fn clear(&self) {
        self.batches
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clear();
    }
}

impl TelemetryExporter for RecordingExporter {
    fn export(&self, batch: &[AgentSecurityEvent]) -> Result<(), ExportError> {
        self.batches
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .push(batch.to_vec());
        Ok(())
    }

    fn name(&self) -> &'static str {
        "recording"
    }
}

/// Always fails — for resilience tests.
#[derive(Debug, Clone, Copy)]
pub struct FailingExporter {
    pub permanent: bool,
}

impl TelemetryExporter for FailingExporter {
    fn export(&self, _batch: &[AgentSecurityEvent]) -> Result<(), ExportError> {
        if self.permanent {
            Err(ExportError::permanent(
                "failing",
                "configured permanent failure",
            ))
        } else {
            Err(ExportError::new("failing", "configured transient failure"))
        }
    }

    fn name(&self) -> &'static str {
        "failing"
    }
}

/// Forwards each event as a legacy [`TelemetryRecord`] to the control plane.
///
/// Preserves the existing `/api/v1/telemetry/log` contract while the richer
/// [`AgentSecurityEvent`] shape is used locally and in tests. Delivery is still
/// asynchronous via [`CloudClient::dispatch_telemetry`].
#[derive(Clone)]
pub struct CloudTelemetryExporter {
    client: Arc<CloudClient>,
}

impl CloudTelemetryExporter {
    pub fn new(client: Arc<CloudClient>) -> Self {
        Self { client }
    }
}

impl TelemetryExporter for CloudTelemetryExporter {
    fn export(&self, batch: &[AgentSecurityEvent]) -> Result<(), ExportError> {
        for event in batch {
            let record = TelemetryRecord::new(
                self.client.device_id(),
                event.action.tool.clone(),
                event.risk.score.unwrap_or(0),
                primary_pattern(event),
                user_decision_from(event),
            )
            .with_identity_from_event(event);
            self.client.dispatch_telemetry(record);
        }
        Ok(())
    }

    fn name(&self) -> &'static str {
        "cloud"
    }
}

fn primary_pattern(event: &AgentSecurityEvent) -> String {
    event
        .policies_matched
        .first()
        .map(|policy| policy.rule_id.clone())
        .or_else(|| event.risk.reason_codes.first().cloned())
        .unwrap_or_else(|| match event.decision {
            Decision::Allow => "allowed".to_string(),
            Decision::Deny => "denied".to_string(),
            Decision::RequireApproval => "require_approval".to_string(),
        })
}

fn user_decision_from(event: &AgentSecurityEvent) -> UserDecision {
    if let Some(approval) = &event.approval {
        return match approval.outcome.as_str() {
            "approved" => UserDecision::Approved,
            "denied" => UserDecision::Denied,
            _ => UserDecision::Skipped,
        };
    }

    match event.decision {
        Decision::Deny => UserDecision::Denied,
        Decision::Allow | Decision::RequireApproval => UserDecision::Skipped,
    }
}

/// Fans batches out to several exporters.
#[derive(Clone, Default)]
pub struct CompositeExporter {
    exporters: Vec<Arc<dyn TelemetryExporter>>,
}

impl CompositeExporter {
    pub fn new(exporters: Vec<Arc<dyn TelemetryExporter>>) -> Self {
        Self { exporters }
    }

    pub fn with(mut self, exporter: Arc<dyn TelemetryExporter>) -> Self {
        self.exporters.push(exporter);
        self
    }
}

impl TelemetryExporter for CompositeExporter {
    fn export(&self, batch: &[AgentSecurityEvent]) -> Result<(), ExportError> {
        let mut first_error = None;
        for exporter in &self.exporters {
            if let Err(error) = exporter.export(batch) {
                first_error.get_or_insert(error);
            }
        }
        match first_error {
            Some(error) => Err(error),
            None => Ok(()),
        }
    }

    fn name(&self) -> &'static str {
        "composite"
    }
}
