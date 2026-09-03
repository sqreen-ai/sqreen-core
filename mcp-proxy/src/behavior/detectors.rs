//! Pluggable deterministic detectors.
//!
//! Each detector observes an action against a [`BehaviorProfile`] and may emit
//! zero or more [`BehaviorSignal`]s. Detectors never enforce — they only signal.

use std::sync::Arc;
use std::time::Duration;

use chrono::{DateTime, Utc};

use crate::action::{AgentAction, EnvironmentTier};
use crate::taxonomy::ActionCategory;

use super::features::{
    action_domains, action_paths, directory_key, environment_tier_slug, is_sensitive_directory,
};
use super::session::SessionTracker;
use super::types::{BehaviorProfile, BehaviorSeverity, BehaviorSignal, BehaviorSignalKind};

/// Shared view detectors receive for one evaluation.
pub struct DetectionContext<'a> {
    pub action: &'a AgentAction,
    pub profile: &'a BehaviorProfile,
    pub session: Option<&'a SessionTracker>,
    pub now: DateTime<Utc>,
    pub config: &'a super::engine::BehaviorConfig,
}

/// Extension point for future detectors (statistical, graph-based, etc.).
pub trait BehaviorDetector: Send + Sync {
    fn id(&self) -> &'static str;
    fn observe(&self, ctx: &DetectionContext<'_>) -> Vec<BehaviorSignal>;
}

/// Returns the default built-in detector set.
pub fn default_detectors() -> Vec<Arc<dyn BehaviorDetector>> {
    vec![
        Arc::new(NovelSensitiveDirectoryDetector),
        Arc::new(UnknownToolDetector),
        Arc::new(NovelExternalDomainDetector),
        Arc::new(HighVolumeReadsDetector),
        Arc::new(CredentialAccessDetector),
        Arc::new(DestructiveAfterReadsDetector),
        Arc::new(ActionFrequencyDeviationDetector),
        Arc::new(ProductionFromDevAgentDetector),
        Arc::new(ExfiltrationChainDetector),
    ]
}

/* ---- Detectors ---- */

pub struct NovelSensitiveDirectoryDetector;

impl BehaviorDetector for NovelSensitiveDirectoryDetector {
    fn id(&self) -> &'static str {
        "novel_sensitive_directory"
    }

    fn observe(&self, ctx: &DetectionContext<'_>) -> Vec<BehaviorSignal> {
        if !ctx.profile.is_warmed_up(ctx.config.min_profile_actions) {
            return Vec::new();
        }

        let mut signals = Vec::new();
        for path in action_paths(ctx.action) {
            let key = directory_key(&path);
            if !is_sensitive_directory(&key) {
                continue;
            }
            if ctx.profile.seen_directories.contains(&key) {
                continue;
            }

            signals.push(
                BehaviorSignal::new(
                    self.id(),
                    BehaviorSignalKind::NovelSensitiveDirectory,
                    BehaviorSeverity::High,
                    format!(
                        "agent accessed sensitive directory it has never accessed before via tool `{}`",
                        ctx.action.tool_name()
                    ),
                )
                .with_evidence("directory_kind", "sensitive")
                .with_evidence("tool", ctx.action.tool_name()),
            );
        }
        signals
    }
}

pub struct UnknownToolDetector;

impl BehaviorDetector for UnknownToolDetector {
    fn id(&self) -> &'static str {
        "unknown_tool"
    }

    fn observe(&self, ctx: &DetectionContext<'_>) -> Vec<BehaviorSignal> {
        if !ctx.profile.is_warmed_up(ctx.config.min_profile_actions) {
            return Vec::new();
        }

        let tool = ctx.action.tool_name().to_ascii_lowercase();
        if ctx.profile.seen_tools.contains(&tool) {
            return Vec::new();
        }

        vec![BehaviorSignal::new(
            self.id(),
            BehaviorSignalKind::UnknownTool,
            BehaviorSeverity::Medium,
            format!("agent suddenly invoked unknown tool `{tool}`"),
        )
        .with_evidence("tool", tool)]
    }
}

pub struct NovelExternalDomainDetector;

impl BehaviorDetector for NovelExternalDomainDetector {
    fn id(&self) -> &'static str {
        "novel_external_domain"
    }

    fn observe(&self, ctx: &DetectionContext<'_>) -> Vec<BehaviorSignal> {
        if !ctx.profile.is_warmed_up(ctx.config.min_profile_actions) {
            return Vec::new();
        }

        let mut signals = Vec::new();
        for domain in action_domains(ctx.action) {
            let category = crate::telemetry::destination_category(&domain);
            if category != "external" {
                continue;
            }
            if ctx.profile.seen_domains.contains(&domain) {
                continue;
            }

            signals.push(
                BehaviorSignal::new(
                    self.id(),
                    BehaviorSignalKind::NovelExternalDomain,
                    BehaviorSeverity::High,
                    format!(
                        "agent sent data to previously unseen external domain `{domain}` via tool `{}`",
                        ctx.action.tool_name()
                    ),
                )
                .with_evidence("domain", domain)
                .with_evidence("category", category),
            );
        }
        signals
    }
}

pub struct HighVolumeReadsDetector;

impl BehaviorDetector for HighVolumeReadsDetector {
    fn id(&self) -> &'static str {
        "high_volume_reads"
    }

    fn observe(&self, ctx: &DetectionContext<'_>) -> Vec<BehaviorSignal> {
        let is_read = matches!(
            ctx.action.security.action,
            ActionCategory::Read | ActionCategory::Query
        );
        if !is_read {
            return Vec::new();
        }

        let prior = ctx
            .profile
            .reads_in_window(ctx.now, ctx.config.read_volume_window);
        // +1 for the current action not yet recorded.
        let total = prior + 1;
        if total < ctx.config.read_volume_threshold {
            return Vec::new();
        }

        let severity = if total >= ctx.config.read_volume_threshold.saturating_mul(2) {
            BehaviorSeverity::High
        } else {
            BehaviorSeverity::Medium
        };

        vec![BehaviorSignal::new(
            self.id(),
            BehaviorSignalKind::HighVolumeReads,
            severity,
            format!(
                "agent performed {total} reads within {}s (threshold {})",
                ctx.config.read_volume_window.as_secs(),
                ctx.config.read_volume_threshold
            ),
        )
        .with_evidence("read_count", total.to_string())]
    }
}

pub struct CredentialAccessDetector;

impl BehaviorDetector for CredentialAccessDetector {
    fn id(&self) -> &'static str {
        "credential_access"
    }

    fn observe(&self, ctx: &DetectionContext<'_>) -> Vec<BehaviorSignal> {
        if !ctx.action.security.risk.credential_access {
            return Vec::new();
        }

        let novel = action_paths(ctx.action).into_iter().any(|path| {
            let key = directory_key(&path);
            !ctx.profile.seen_directories.contains(&key)
        });

        let severity = if novel {
            BehaviorSeverity::Critical
        } else {
            BehaviorSeverity::High
        };

        vec![BehaviorSignal::new(
            self.id(),
            BehaviorSignalKind::CredentialAccess,
            severity,
            format!(
                "agent attempted credential/secret access via tool `{}`",
                ctx.action.tool_name()
            ),
        )
        .with_evidence("novel_location", novel.to_string())]
    }
}

pub struct DestructiveAfterReadsDetector;

impl BehaviorDetector for DestructiveAfterReadsDetector {
    fn id(&self) -> &'static str {
        "destructive_after_reads"
    }

    fn observe(&self, ctx: &DetectionContext<'_>) -> Vec<BehaviorSignal> {
        if !ctx.action.security.risk.destructive
            && !matches!(
                ctx.action.security.action,
                ActionCategory::Delete | ActionCategory::Deploy | ActionCategory::Escalate
            )
        {
            return Vec::new();
        }

        let window = ctx.config.sequence_window;
        let cutoff = ctx.now
            - chrono::Duration::from_std(window).unwrap_or_else(|_| chrono::Duration::seconds(120));

        let recent_reads: Vec<_> = ctx
            .profile
            .recent_actions
            .iter()
            .filter(|record| {
                record.timestamp >= cutoff
                    && matches!(record.action, ActionCategory::Read | ActionCategory::Query)
            })
            .collect();

        if recent_reads.len() < ctx.config.min_reads_before_destructive {
            return Vec::new();
        }

        let distinct_dirs: std::collections::HashSet<_> = recent_reads
            .iter()
            .filter_map(|record| record.directory_key.as_deref())
            .collect();

        // "Unrelated" = multiple distinct directories, or no shared dir with the destructive target.
        let destructive_dir = action_paths(ctx.action)
            .into_iter()
            .next()
            .map(|path| directory_key(&path));
        let unrelated = distinct_dirs.len() >= 2
            || destructive_dir
                .as_deref()
                .is_some_and(|dir| !distinct_dirs.contains(dir));

        if !unrelated && distinct_dirs.len() < 2 {
            return Vec::new();
        }

        vec![BehaviorSignal::new(
            self.id(),
            BehaviorSignalKind::DestructiveAfterReads,
            BehaviorSeverity::Critical,
            format!(
                "agent executed destructive action `{}` after {} unrelated reads",
                ctx.action.tool_name(),
                recent_reads.len()
            ),
        )
        .with_evidence("prior_reads", recent_reads.len().to_string())
        .with_evidence("distinct_directories", distinct_dirs.len().to_string())]
    }
}

pub struct ActionFrequencyDeviationDetector;

impl BehaviorDetector for ActionFrequencyDeviationDetector {
    fn id(&self) -> &'static str {
        "action_frequency_deviation"
    }

    fn observe(&self, ctx: &DetectionContext<'_>) -> Vec<BehaviorSignal> {
        if !ctx.profile.is_warmed_up(ctx.config.min_profile_actions) {
            return Vec::new();
        }

        let Some(baseline) = ctx.profile.mean_actions_per_minute() else {
            return Vec::new();
        };
        if baseline <= 0.0 {
            return Vec::new();
        }

        let recent = ctx
            .profile
            .actions_in_window(ctx.now, Duration::from_secs(60))
            + 1; // include current
        let current_rate = recent as f64; // per minute window

        if current_rate < baseline * ctx.config.frequency_multiplier {
            return Vec::new();
        }

        let severity = if current_rate >= baseline * ctx.config.frequency_multiplier * 2.0 {
            BehaviorSeverity::High
        } else {
            BehaviorSeverity::Medium
        };

        vec![BehaviorSignal::new(
            self.id(),
            BehaviorSignalKind::ActionFrequencyDeviation,
            severity,
            format!(
                "action frequency {current_rate:.1}/min is {:.1}× the agent baseline {baseline:.1}/min",
                current_rate / baseline
            ),
        )
        .with_evidence("baseline_per_min", format!("{baseline:.2}"))
        .with_evidence("current_per_min", format!("{current_rate:.2}"))]
    }
}

pub struct ProductionFromDevAgentDetector;

impl BehaviorDetector for ProductionFromDevAgentDetector {
    fn id(&self) -> &'static str {
        "production_from_dev_agent"
    }

    fn observe(&self, ctx: &DetectionContext<'_>) -> Vec<BehaviorSignal> {
        if ctx.action.identity.environment.tier != EnvironmentTier::Production {
            return Vec::new();
        }
        if !ctx.profile.is_warmed_up(ctx.config.min_profile_actions) {
            return Vec::new();
        }

        let historically_prod = ctx
            .profile
            .seen_environment_tiers
            .contains(&EnvironmentTier::Production);
        if historically_prod {
            return Vec::new();
        }

        let only_lower = ctx.profile.seen_environment_tiers.iter().all(|tier| {
            matches!(
                tier,
                EnvironmentTier::Development | EnvironmentTier::Staging | EnvironmentTier::Unknown
            )
        });
        if !only_lower || ctx.profile.seen_environment_tiers.is_empty() {
            return Vec::new();
        }

        let prior: Vec<_> = ctx
            .profile
            .seen_environment_tiers
            .iter()
            .map(|tier| environment_tier_slug(*tier))
            .collect();

        vec![BehaviorSignal::new(
            self.id(),
            BehaviorSignalKind::ProductionFromDevAgent,
            BehaviorSeverity::Critical,
            format!(
                "production access from agent historically only seen in {}",
                prior.join(",")
            ),
        )
        .with_evidence("prior_tiers", prior.join(","))]
    }
}

pub struct ExfiltrationChainDetector;

impl BehaviorDetector for ExfiltrationChainDetector {
    fn id(&self) -> &'static str {
        "exfiltration_chain"
    }

    fn observe(&self, ctx: &DetectionContext<'_>) -> Vec<BehaviorSignal> {
        let Some(session) = ctx.session else {
            return Vec::new();
        };
        if !session.verify_action_chain(ctx.action) {
            return Vec::new();
        }

        vec![BehaviorSignal::new(
            self.id(),
            BehaviorSignalKind::ExfiltrationChain,
            BehaviorSeverity::Critical,
            format!(
                "tool `{}` completes an exfiltration-risk chain in this session",
                ctx.action.tool_name()
            ),
        )]
    }
}
