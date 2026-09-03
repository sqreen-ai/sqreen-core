//! Shared feature extraction for behavioral detectors (privacy-safe keys only).

use std::borrow::Cow;

use chrono::{DateTime, Utc};

use crate::action::{AgentAction, Destination, EnvironmentTier, Resource};
use crate::taxonomy::{ActionCategory, ResourceCategory};
use crate::telemetry::{destination_category, extract_domain};

use super::types::ProfileActionRecord;

/// Directory prefixes treated as sensitive for novel-access detection.
pub const SENSITIVE_DIRECTORY_MARKERS: &[&str] = &[
    "/.ssh",
    "/.aws",
    "/.gnupg",
    "/.env",
    "/credentials",
    "/secrets",
    "/etc/",
    "/root/",
];

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

fn expand_home(path: &str) -> Cow<'_, str> {
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

/// Builds a stable directory key from a path (parent of file, or path itself).
pub fn directory_key(path: &str) -> String {
    let expanded = expand_home(path);
    let normalized = expanded.trim_end_matches('/');
    if let Some((parent, _)) = normalized.rsplit_once('/') {
        if parent.is_empty() {
            "/".to_string()
        } else {
            parent.to_string()
        }
    } else {
        normalized.to_string()
    }
}

pub fn is_sensitive_directory(directory: &str) -> bool {
    let lowered = directory.to_ascii_lowercase();
    SENSITIVE_DIRECTORY_MARKERS
        .iter()
        .any(|marker| lowered.contains(&marker.to_ascii_lowercase()))
}

pub fn action_paths(action: &AgentAction) -> Vec<String> {
    let mut paths = Vec::new();

    match &action.target_resource {
        Some(Resource::File { path }) | Some(Resource::Directory { path }) => {
            paths.push(path.clone());
        }
        Some(Resource::Command { raw, .. }) => paths.push(raw.clone()),
        _ => {}
    }

    if let Some((_, value)) = action
        .arguments
        .first_string_field(PATH_KEYS.iter().copied())
    {
        if !paths.iter().any(|path| path == value) {
            paths.push(value.to_string());
        }
    }

    paths
}

pub fn action_domains(action: &AgentAction) -> Vec<String> {
    let mut domains = Vec::new();

    match &action.destination {
        Some(Destination::Host { host, .. }) => {
            if let Some(domain) = extract_domain(host) {
                domains.push(domain);
            }
        }
        Some(Destination::Url { url, host }) => {
            if let Some(domain) = host
                .as_deref()
                .and_then(extract_domain)
                .or_else(|| extract_domain(url))
            {
                domains.push(domain);
            }
        }
        _ => {}
    }

    if let Some((_, raw)) = action
        .arguments
        .first_string_field(["url", "uri", "endpoint", "host"].iter().copied())
    {
        if let Some(domain) = extract_domain(raw) {
            if !domains.iter().any(|existing| existing == &domain) {
                domains.push(domain);
            }
        }
    }

    domains
}

pub fn profile_record_from_action(action: &AgentAction, now: DateTime<Utc>) -> ProfileActionRecord {
    let directory = action_paths(action)
        .into_iter()
        .next()
        .map(|path| directory_key(&path));
    let domain = action_domains(action).into_iter().next();

    ProfileActionRecord {
        timestamp: now,
        tool_name: action.tool_name().to_ascii_lowercase(),
        action: action.security.action,
        operation: action.operation,
        directory_key: directory,
        domain,
        credential_access: action.security.risk.credential_access
            || action
                .security
                .touches_resource(ResourceCategory::Credential)
            || action.security.touches_resource(ResourceCategory::Secret),
        destructive: action.security.risk.destructive
            || matches!(
                action.security.action,
                ActionCategory::Delete | ActionCategory::Deploy | ActionCategory::Escalate
            ),
        environment_tier: action.identity.environment.tier,
    }
}

pub fn environment_tier_slug(tier: EnvironmentTier) -> &'static str {
    match tier {
        EnvironmentTier::Development => "development",
        EnvironmentTier::Staging => "staging",
        EnvironmentTier::Production => "production",
        EnvironmentTier::Unknown => "unknown",
    }
}
