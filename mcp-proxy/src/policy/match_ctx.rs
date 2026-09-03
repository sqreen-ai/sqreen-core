//! Unified match surface for normalized policy predicates.

use std::borrow::Cow;

use regex::Regex;

use crate::action::{AgentAction, Arguments, Resource};
use crate::behavior::{BehaviorFinding, BehaviorSeverity, BehaviorSignalKind};
use crate::classify;
use crate::identity::{IdentityMatchContext, LOCAL_ANONYMOUS_AGENT_ID};
use crate::scoring::{ExplainableRiskScore, RiskFactorKind, RiskLevel};
use crate::taxonomy::{self, TaxonomyMatchContext};

const PATH_KEYS: &[&str] = &[
    "path",
    "file_path",
    "filepath",
    "filename",
    "absolute_path",
    "directory",
    "dir",
    "folder",
    "root",
    "base_path",
];

pub const DOCUMENTED_MATCH_FIELDS: &[&str] = &[
    "action",
    "agent.anonymous",
    "agent_id",
    "agent.label",
    "agent.trust",
    "agent.bound_id",
    "agent.id",
    "agent_type",
    "behavior.severity",
    "behavior.severity_at_least",
    "behavior.signal",
    "environment",
    "labels.team",
    "operation",
    "path",
    "path_not_prefix",
    "path_pattern",
    "path_prefix",
    "resource.filesystem",
    "risk.destructive",
    "risk.factor",
    "risk.level",
    "risk.level_at_least",
    "risk.score_at_least",
    "runtime",
    "tool_name",
    "workspace_id",
];

#[derive(Debug)]
pub struct PolicyMatchContext<'a> {
    action: &'a AgentAction,
    identity: IdentityMatchContext<'a>,
    taxonomy: taxonomy::SecurityClassification,
    paths: Vec<String>,
    behavior: Option<&'a BehaviorFinding>,
    risk_score: Option<&'a ExplainableRiskScore>,
}

impl<'a> PolicyMatchContext<'a> {
    pub fn build(action: &'a AgentAction) -> Self {
        Self::build_with_context(action, None, None)
    }

    pub fn build_with_behavior(
        action: &'a AgentAction,
        behavior: Option<&'a BehaviorFinding>,
    ) -> Self {
        Self::build_with_context(action, behavior, None)
    }

    pub fn build_with_context(
        action: &'a AgentAction,
        behavior: Option<&'a BehaviorFinding>,
        risk_score: Option<&'a ExplainableRiskScore>,
    ) -> Self {
        Self {
            action,
            identity: IdentityMatchContext::from_action(action),
            taxonomy: taxonomy::classify_action(action),
            paths: extract_paths(action),
            behavior,
            risk_score,
        }
    }

    pub fn paths(&self) -> &[String] {
        &self.paths
    }

    pub fn tool_name(&self) -> &str {
        self.action.tool_name()
    }

    /// Returns true when the action's agent claim may grant privilege-sensitive Allows.
    pub fn agent_trust_can_grant_privilege(&self) -> bool {
        self.action.identity.agent_trust.can_grant_privilege()
            || self.action.identity.agent_bound_id.is_some()
    }

    pub fn canonical_arguments(&self) -> &str {
        self.action.canonical_params_json()
    }

    pub fn field(&self, name: &str) -> Option<String> {
        let key = name.trim();
        if key.is_empty() {
            return None;
        }

        if key == "tool_name" {
            return Some(self.action.tool_name().to_string());
        }

        if key == "path" {
            return self.paths.first().cloned();
        }

        if key == "agent.anonymous" {
            let anonymous = self.action.identity.is_anonymous()
                || self
                    .identity
                    .agent_id
                    .is_some_and(|id| id == LOCAL_ANONYMOUS_AGENT_ID);
            return Some(anonymous.to_string());
        }

        if let Some(value) = self.identity.field(key) {
            return Some(value);
        }

        let tax = TaxonomyMatchContext {
            action: self.taxonomy.action,
            resources: &self.taxonomy.resources,
            risk: &self.taxonomy.risk,
        };

        if let Some(value) = tax.field(key) {
            return Some(value);
        }

        if key == "action" {
            return Some(self.taxonomy.action.as_str().to_string());
        }

        if let Some(value) = self.scored_risk_field(key) {
            return Some(value);
        }

        if let Some(value) = self.behavior_field(key) {
            return Some(value);
        }

        None
    }

    fn scored_risk_field(&self, key: &str) -> Option<String> {
        let scored = self.risk_score?;

        match key {
            "risk.level" => Some(scored.level.as_str().to_string()),
            "risk.level_at_least" => Some(scored.level.as_str().to_string()),
            "risk.score_at_least" => Some(scored.score.to_string()),
            "risk.factor" => scored
                .factors
                .first()
                .map(|factor| factor.kind.as_str().to_string()),
            _ => {
                if let Some(kind_name) = key.strip_prefix("risk.factor.") {
                    let present = RiskFactorKind::parse(kind_name)
                        .is_some_and(|kind| scored.has_factor(kind));
                    return Some(present.to_string());
                }
                None
            }
        }
    }

    fn behavior_field(&self, key: &str) -> Option<String> {
        let finding = self.behavior?;

        if key == "behavior.signal" {
            // Multi-value: callers use matches_field_equals which checks membership.
            return finding
                .signals
                .first()
                .map(|signal| signal.kind.as_str().to_string());
        }

        if key == "behavior.severity" {
            if finding.is_empty() {
                return None;
            }
            return Some(finding.max_severity.as_str().to_string());
        }

        if key == "behavior.severity_at_least" {
            if finding.is_empty() {
                return None;
            }
            return Some(finding.max_severity.as_str().to_string());
        }

        if let Some(kind_name) = key.strip_prefix("behavior.signal.") {
            let present =
                BehaviorSignalKind::parse(kind_name).is_some_and(|kind| finding.has_kind(kind));
            return Some(present.to_string());
        }

        None
    }

    pub fn matches_field_equals(&self, field: &str, expected: &str) -> bool {
        let field = field.trim();
        let expected = expected.trim();

        if field == "behavior.signal" {
            return self.behavior.is_some_and(|finding| {
                BehaviorSignalKind::parse(expected).is_some_and(|kind| finding.has_kind(kind))
            });
        }

        if field == "behavior.severity_at_least" {
            return self.behavior.is_some_and(|finding| {
                BehaviorSeverity::from_str_lossy(expected)
                    .is_some_and(|floor| finding.severity_at_least(floor))
            });
        }

        if field == "behavior.severity" {
            return self.behavior.is_some_and(|finding| {
                !finding.is_empty()
                    && BehaviorSeverity::from_str_lossy(expected)
                        .is_some_and(|severity| finding.max_severity == severity)
            });
        }

        if field == "risk.factor" {
            return self.risk_score.is_some_and(|scored| {
                RiskFactorKind::parse(expected).is_some_and(|kind| scored.has_factor(kind))
            });
        }

        if field == "risk.level" {
            return self.risk_score.is_some_and(|scored| {
                RiskLevel::parse(expected).is_some_and(|level| scored.level == level)
            });
        }

        if field == "risk.level_at_least" {
            return self.risk_score.is_some_and(|scored| {
                RiskLevel::parse(expected).is_some_and(|floor| scored.level.rank() >= floor.rank())
            });
        }

        if field == "risk.score_at_least" {
            return self.risk_score.is_some_and(|scored| {
                expected
                    .parse::<u8>()
                    .is_ok_and(|floor| scored.score >= floor)
            });
        }

        self.field(field)
            .is_some_and(|actual| values_equal(&actual, expected))
    }

    pub fn matches_path_regex(&self, pattern: &Regex) -> bool {
        self.paths
            .iter()
            .any(|path| pattern.is_match(path) || pattern.is_match(&expand_home(path)))
    }

    pub fn matches_path_prefix(&self, prefix: &str) -> bool {
        self.paths
            .iter()
            .any(|path| path.starts_with(prefix) || expand_home(path).starts_with(prefix))
    }

    pub fn matches_path_not_prefix(&self, prefix: &str) -> bool {
        !self.paths.is_empty()
            && self
                .paths
                .iter()
                .all(|path| !path.starts_with(prefix) && !expand_home(path).starts_with(prefix))
    }
}

pub fn extract_paths(action: &AgentAction) -> Vec<String> {
    let mut paths = Vec::new();

    match &action.target_resource {
        Some(Resource::File { path }) | Some(Resource::Directory { path }) => {
            paths.push(path.clone());
        }
        Some(Resource::Command { raw, .. }) => paths.push(raw.clone()),
        _ => {}
    }

    let inferred = classify::classify(&action.tool_name, &action.arguments);
    if let Some(Resource::File { path }) | Some(Resource::Directory { path }) =
        inferred.target_resource
    {
        if !paths.iter().any(|existing| existing == &path) {
            paths.push(path);
        }
    }

    collect_path_arguments(&action.arguments, &mut paths);

    // Normalize for policy matching (percent-decode + collapse dot segments).
    // Original forms are retained alongside normalized forms so both can match.
    let mut normalized = Vec::new();
    for path in &paths {
        let norm = crate::security_baseline::normalize_path_for_policy(path);
        if norm.normalized != *path && !paths.iter().any(|p| p == &norm.normalized) {
            normalized.push(norm.normalized);
        }
    }
    paths.extend(normalized);
    paths
}

fn collect_path_arguments(arguments: &Arguments, paths: &mut Vec<String>) {
    if let Some((_, value)) = arguments.first_string_field(PATH_KEYS.iter().copied()) {
        if !paths.iter().any(|path| path == value) {
            paths.push(value.to_string());
        }
    }
}

pub fn expand_home(path: &str) -> Cow<'_, str> {
    if path.starts_with('~') {
        if let Ok(home) = std::env::var("HOME") {
            if path.len() == 1 {
                return Cow::Owned(home);
            }
            if path.as_bytes().get(1) == Some(&b'/') {
                return Cow::Owned(format!("{home}{}", &path[1..]));
            }
        }
    }
    Cow::Borrowed(path)
}

pub fn values_equal(actual: &str, expected: &str) -> bool {
    actual.eq_ignore_ascii_case(expected.trim())
        || actual
            .replace('_', "-")
            .eq_ignore_ascii_case(&expected.trim().replace('_', "-"))
}

pub fn inspection_surface(tool_name: &str, arguments: &str) -> String {
    const JSON_NULL: &str = "null";
    if arguments.trim() == JSON_NULL {
        tool_name.to_string()
    } else {
        arguments.to_string()
    }
}
