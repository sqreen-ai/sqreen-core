//! Bounded, non-blocking telemetry delivery pipeline.
//!
//! # Invariants
//!
//! 1. **`emit` never blocks** the evaluation path — a full queue drops the newest event.
//! 2. **Export failures never change security decisions** — retries happen in a background
//!    worker; exhausted retries increment drop counters and move on.
//! 3. **Local-only mode works** — a [`super::sink::NullExporter`] or recording sink needs
//!    no network.

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use tokio::sync::mpsc;
use tokio::time::{sleep, timeout, Instant};

use super::event::AgentSecurityEvent;
use super::privacy::PrivacyPolicy;
use super::sink::{NullExporter, TelemetryExporter};

/// How telemetry is routed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum TelemetryMode {
    /// Do not emit events.
    Disabled,
    /// Emit to a local exporter only (stderr, recording, null).
    #[default]
    LocalOnly,
    /// Emit through whatever exporter the pipeline was built with (may include cloud).
    Cloud,
}

/// Tunables for the background delivery worker.
#[derive(Debug, Clone)]
pub struct TelemetryConfig {
    pub mode: TelemetryMode,
    /// Maximum queued events before backpressure drops new ones.
    pub queue_capacity: usize,
    /// Flush when this many events accumulate.
    pub batch_size: usize,
    /// Flush after this idle period even if the batch is not full.
    pub batch_interval: Duration,
    /// Maximum delivery attempts per batch (including the first).
    pub max_retries: u32,
    /// Initial backoff between retries.
    pub initial_backoff: Duration,
    /// Cap on retry backoff.
    pub max_backoff: Duration,
    /// Privacy transforms applied when generating events.
    pub privacy: PrivacyPolicy,
}

impl Default for TelemetryConfig {
    fn default() -> Self {
        Self {
            mode: TelemetryMode::LocalOnly,
            queue_capacity: 1_024,
            batch_size: 32,
            batch_interval: Duration::from_secs(1),
            max_retries: 3,
            initial_backoff: Duration::from_millis(100),
            max_backoff: Duration::from_secs(5),
            privacy: PrivacyPolicy::default(),
        }
    }
}

impl TelemetryConfig {
    /// Disabled pipeline — `emit` is a no-op.
    pub fn disabled() -> Self {
        Self {
            mode: TelemetryMode::Disabled,
            ..Self::default()
        }
    }

    /// Local-only with an explicit privacy salt.
    pub fn local(salt: impl Into<String>) -> Self {
        Self {
            mode: TelemetryMode::LocalOnly,
            privacy: PrivacyPolicy::with_salt(salt),
            ..Self::default()
        }
    }

    /// Cloud-oriented defaults.
    pub fn cloud() -> Self {
        Self {
            mode: TelemetryMode::Cloud,
            ..Self::default()
        }
    }
}

/// Counters for operators and tests.
#[derive(Debug, Default)]
pub struct TelemetryStats {
    pub emitted: AtomicU64,
    pub queued: AtomicU64,
    pub dropped_backpressure: AtomicU64,
    pub dropped_retry_exhausted: AtomicU64,
    pub exported: AtomicU64,
    pub export_failures: AtomicU64,
}

impl TelemetryStats {
    pub fn snapshot(&self) -> TelemetryStatsSnapshot {
        TelemetryStatsSnapshot {
            emitted: self.emitted.load(Ordering::Relaxed),
            queued: self.queued.load(Ordering::Relaxed),
            dropped_backpressure: self.dropped_backpressure.load(Ordering::Relaxed),
            dropped_retry_exhausted: self.dropped_retry_exhausted.load(Ordering::Relaxed),
            exported: self.exported.load(Ordering::Relaxed),
            export_failures: self.export_failures.load(Ordering::Relaxed),
        }
    }
}

/// Point-in-time view of [`TelemetryStats`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct TelemetryStatsSnapshot {
    pub emitted: u64,
    pub queued: u64,
    pub dropped_backpressure: u64,
    pub dropped_retry_exhausted: u64,
    pub exported: u64,
    pub export_failures: u64,
}

/// Non-blocking enqueue + background batch/retry worker.
pub struct TelemetryPipeline {
    config: TelemetryConfig,
    tx: Mutex<Option<mpsc::Sender<AgentSecurityEvent>>>,
    stats: Arc<TelemetryStats>,
    shutdown: Arc<AtomicBool>,
}

impl TelemetryPipeline {
    /// Starts a pipeline with the given exporter.
    ///
    /// When `mode` is [`TelemetryMode::Disabled`], no worker is spawned.
    pub fn start(config: TelemetryConfig, exporter: Arc<dyn TelemetryExporter>) -> Self {
        let stats = Arc::new(TelemetryStats::default());
        let shutdown = Arc::new(AtomicBool::new(false));

        if config.mode == TelemetryMode::Disabled {
            return Self {
                config,
                tx: Mutex::new(None),
                stats,
                shutdown,
            };
        }

        let (tx, rx) = mpsc::channel(config.queue_capacity.max(1));
        let worker_stats = Arc::clone(&stats);
        let worker_shutdown = Arc::clone(&shutdown);
        let worker_config = config.clone();

        spawn_worker(worker_config, exporter, rx, worker_stats, worker_shutdown);

        Self {
            config,
            tx: Mutex::new(Some(tx)),
            stats,
            shutdown,
        }
    }

    /// Starts a disabled pipeline (emit is a no-op).
    pub fn disabled() -> Self {
        Self::start(TelemetryConfig::disabled(), Arc::new(NullExporter))
    }

    /// Returns the privacy policy used when generating events.
    pub fn privacy(&self) -> &PrivacyPolicy {
        &self.config.privacy
    }

    /// Returns the configured mode.
    pub fn mode(&self) -> TelemetryMode {
        self.config.mode
    }

    /// Returns `true` when events are discarded without queuing.
    pub fn is_disabled(&self) -> bool {
        self.config.mode == TelemetryMode::Disabled
            || self
                .tx
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .is_none()
    }

    /// Enqueues an event without blocking.
    ///
    /// On a full queue the event is dropped and `dropped_backpressure` increments.
    /// Never returns an error to the caller — telemetry must not fail evaluation.
    pub fn emit(&self, event: AgentSecurityEvent) {
        self.stats.emitted.fetch_add(1, Ordering::Relaxed);

        let guard = self
            .tx
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let Some(tx) = guard.as_ref() else {
            return;
        };

        match tx.try_send(event) {
            Ok(()) => {
                self.stats.queued.fetch_add(1, Ordering::Relaxed);
            }
            Err(mpsc::error::TrySendError::Full(_)) | Err(mpsc::error::TrySendError::Closed(_)) => {
                self.stats
                    .dropped_backpressure
                    .fetch_add(1, Ordering::Relaxed);
            }
        }
    }

    /// Snapshot of delivery counters.
    pub fn stats(&self) -> TelemetryStatsSnapshot {
        self.stats.snapshot()
    }

    /// Signals the worker to stop and closes the queue so pending batches flush.
    pub fn request_shutdown(&self) {
        self.shutdown.store(true, Ordering::Relaxed);
        // Dropping the sender wakes `recv` with `None`, which flushes any partial batch.
        *self
            .tx
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner()) = None;
    }
}

impl Drop for TelemetryPipeline {
    fn drop(&mut self) {
        self.request_shutdown();
    }
}

fn spawn_worker(
    config: TelemetryConfig,
    exporter: Arc<dyn TelemetryExporter>,
    mut rx: mpsc::Receiver<AgentSecurityEvent>,
    stats: Arc<TelemetryStats>,
    shutdown: Arc<AtomicBool>,
) {
    let Ok(handle) = tokio::runtime::Handle::try_current() else {
        // No runtime — fall back to sync drain on each emit is impossible without
        // blocking; discard and leave counters reflecting emitted-but-unexported.
        eprintln!(
            "mcp-proxy telemetry: no async runtime for delivery worker; events will be dropped"
        );
        return;
    };

    handle.spawn(async move {
        let mut batch = Vec::with_capacity(config.batch_size);
        let mut deadline = Instant::now() + config.batch_interval;

        loop {
            if shutdown.load(Ordering::Relaxed) && batch.is_empty() {
                // Drain any remaining queued events once.
                while let Ok(event) = rx.try_recv() {
                    batch.push(event);
                    if batch.len() >= config.batch_size {
                        flush_batch(&exporter, &mut batch, &config, &stats).await;
                    }
                }
                if !batch.is_empty() {
                    flush_batch(&exporter, &mut batch, &config, &stats).await;
                }
                break;
            }

            let wait = deadline.saturating_duration_since(Instant::now());
            match timeout(wait, rx.recv()).await {
                Ok(Some(event)) => {
                    batch.push(event);
                    if batch.len() >= config.batch_size {
                        flush_batch(&exporter, &mut batch, &config, &stats).await;
                        deadline = Instant::now() + config.batch_interval;
                    }
                }
                Ok(None) => {
                    if !batch.is_empty() {
                        flush_batch(&exporter, &mut batch, &config, &stats).await;
                    }
                    break;
                }
                Err(_) => {
                    // Interval elapsed.
                    if !batch.is_empty() {
                        flush_batch(&exporter, &mut batch, &config, &stats).await;
                    }
                    deadline = Instant::now() + config.batch_interval;
                    if shutdown.load(Ordering::Relaxed) {
                        continue;
                    }
                }
            }
        }
    });
}

async fn flush_batch(
    exporter: &Arc<dyn TelemetryExporter>,
    batch: &mut Vec<AgentSecurityEvent>,
    config: &TelemetryConfig,
    stats: &TelemetryStats,
) {
    if batch.is_empty() {
        return;
    }

    let payload = std::mem::take(batch);
    let mut attempt = 0u32;
    let mut backoff = config.initial_backoff;

    loop {
        attempt += 1;
        match exporter.export(&payload) {
            Ok(()) => {
                stats
                    .exported
                    .fetch_add(payload.len() as u64, Ordering::Relaxed);
                return;
            }
            Err(error) => {
                stats.export_failures.fetch_add(1, Ordering::Relaxed);
                if error.permanent || attempt >= config.max_retries {
                    stats
                        .dropped_retry_exhausted
                        .fetch_add(payload.len() as u64, Ordering::Relaxed);
                    eprintln!(
                        "mcp-proxy telemetry: dropping {} event(s) after export failure \
                         ({}): {}; local enforcement is unaffected",
                        payload.len(),
                        exporter.name(),
                        error.detail
                    );
                    return;
                }

                sleep(backoff).await;
                backoff = (backoff * 2).min(config.max_backoff);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::gateway::Decision;
    use crate::taxonomy::{ActionCategory, RiskProfile};
    use crate::telemetry::event::{
        ActionSignal, AgentIdentitySignal, EnvironmentSignal, PipelineOutcome, RiskSignal,
        SessionSignal,
    };
    use crate::telemetry::sink::{FailingExporter, RecordingExporter};
    use chrono::Utc;

    fn sample_event(tool: &str) -> AgentSecurityEvent {
        AgentSecurityEvent {
            schema_version: "2026.3".to_string(),
            timestamp: Utc::now(),
            organization_id: None,
            agent: AgentIdentitySignal {
                agent_id: "h_abc".to_string(),
                agent_type: "coding".to_string(),
                anonymous: true,
                agent_trust: "self_asserted".to_string(),
                agent_identity_source: None,
                agent_bound_id: None,
                user_id: None,
                user_trust: "self_asserted".to_string(),
                workspace_id: None,
                labels: Default::default(),
            },
            session: SessionSignal {
                session_id: None,
                trace_id: None,
                action_id: "h_act".to_string(),
                runtime: "mcp_stdio".to_string(),
            },
            action: ActionSignal {
                action_type: ActionCategory::Read,
                resource_types: Vec::new(),
                tool: tool.to_string(),
                operation: None,
            },
            destination: None,
            environment: EnvironmentSignal {
                tier: "unknown".to_string(),
                os: None,
            },
            decision: Decision::Allow,
            simulated_decision: None,
            policies_matched: Vec::new(),
            risk: RiskSignal {
                score: Some(1),
                level: None,
                factors: Vec::new(),
                semantics: None,
                profile: RiskProfile::default(),
                reason_codes: Vec::new(),
            },
            approval: None,
            latency_micros: 10,
            outcome: PipelineOutcome::Success,
            arguments: None,
            metadata: Default::default(),
        }
    }

    #[tokio::test]
    async fn batches_and_exports_events() {
        let recorder = Arc::new(RecordingExporter::new());
        let pipeline = TelemetryPipeline::start(
            TelemetryConfig {
                batch_size: 2,
                batch_interval: Duration::from_millis(50),
                ..TelemetryConfig::local("test")
            },
            recorder.clone(),
        );

        pipeline.emit(sample_event("a"));
        pipeline.emit(sample_event("b"));

        sleep(Duration::from_millis(150)).await;

        assert_eq!(pipeline.stats().exported, 2);
        assert_eq!(recorder.events().len(), 2);
    }

    #[tokio::test]
    async fn backpressure_drops_without_blocking() {
        let recorder = Arc::new(RecordingExporter::new());
        let pipeline = TelemetryPipeline::start(
            TelemetryConfig {
                queue_capacity: 1,
                batch_size: 100,
                batch_interval: Duration::from_secs(60),
                ..TelemetryConfig::local("test")
            },
            recorder.clone(),
        );

        // Fill the channel; further emits must not block.
        for i in 0..20 {
            pipeline.emit(sample_event(&format!("tool-{i}")));
        }

        let stats = pipeline.stats();
        assert!(stats.dropped_backpressure > 0);
        assert_eq!(stats.emitted, 20);
    }

    #[tokio::test]
    async fn exhausted_retries_drop_without_panicking() {
        let pipeline = TelemetryPipeline::start(
            TelemetryConfig {
                batch_size: 1,
                batch_interval: Duration::from_millis(20),
                max_retries: 2,
                initial_backoff: Duration::from_millis(5),
                max_backoff: Duration::from_millis(10),
                ..TelemetryConfig::local("test")
            },
            Arc::new(FailingExporter { permanent: false }),
        );

        pipeline.emit(sample_event("fail"));
        sleep(Duration::from_millis(200)).await;

        let stats = pipeline.stats();
        assert!(stats.dropped_retry_exhausted >= 1);
        assert!(stats.export_failures >= 1);
    }

    #[test]
    fn disabled_pipeline_emits_nowhere() {
        let pipeline = TelemetryPipeline::disabled();
        pipeline.emit(sample_event("x"));
        assert_eq!(pipeline.stats().queued, 0);
        assert!(pipeline.is_disabled());
    }
}
