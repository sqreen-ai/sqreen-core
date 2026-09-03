//! Compile-time validation for policy documents.

use std::collections::HashSet;

use anyhow::{bail, Result};

use super::match_ctx::DOCUMENTED_MATCH_FIELDS;
use super::schema::{
    PolicyConfig, PolicyRule, RuleEffect, SCHEMA_2026_3, SCHEMA_LEGACY, SUPPORTED_SCHEMA_VERSIONS,
};

/// Validates a parsed policy document before it is activated.
pub fn validate_config(config: &PolicyConfig) -> Result<()> {
    if !SUPPORTED_SCHEMA_VERSIONS.contains(&config.schema_version.as_str()) {
        bail!(
            "unsupported schema_version `{}`; supported: {}",
            config.schema_version,
            SUPPORTED_SCHEMA_VERSIONS.join(", ")
        );
    }

    if config.version.trim().is_empty() {
        bail!("policy `version` must not be empty");
    }

    validate_unique_names(config)?;
    validate_rules(&config.rules)?;

    for (index, rule) in config.identity_rules.iter().enumerate() {
        if rule.name.trim().is_empty() {
            bail!("identity_rules[{index}].name must not be empty");
        }
    }

    for (index, rule) in config.taxonomy_rules.iter().enumerate() {
        if rule.name.trim().is_empty() {
            bail!("taxonomy_rules[{index}].name must not be empty");
        }
    }

    for (index, tool) in config.tools.iter().enumerate() {
        if tool.name.trim().is_empty() {
            bail!("tools[{index}].name must not be empty");
        }
    }

    if config.schema_version == SCHEMA_2026_3 && config.rules.is_empty() {
        bail!("schema_version `2026.3` requires at least one entry in `rules`");
    }

    Ok(())
}

fn validate_unique_names(config: &PolicyConfig) -> Result<()> {
    let mut seen = HashSet::new();

    for rule in &config.rules {
        if !seen.insert(format!("rules:{}", rule.name)) {
            bail!("duplicate policy rule name `{}`", rule.name);
        }
    }
    for rule in &config.identity_rules {
        if !seen.insert(format!("identity:{}", rule.name)) {
            bail!("duplicate identity rule name `{}`", rule.name);
        }
    }
    for rule in &config.taxonomy_rules {
        if !seen.insert(format!("taxonomy:{}", rule.name)) {
            bail!("duplicate taxonomy rule name `{}`", rule.name);
        }
    }
    for tool in &config.tools {
        if !seen.insert(format!("tool:{}", tool.name)) {
            bail!("duplicate tool policy name `{}`", tool.name);
        }
    }

    Ok(())
}

fn validate_rules(rules: &[PolicyRule]) -> Result<()> {
    for (index, rule) in rules.iter().enumerate() {
        if rule.name.trim().is_empty() {
            bail!("rules[{index}].name must not be empty");
        }

        match rule.effect {
            RuleEffect::Allow
            | RuleEffect::Deny
            | RuleEffect::RequireApproval
            | RuleEffect::Redact => {}
        }

        for key in rule.when.keys() {
            validate_match_key(key, &format!("rules[{index}]"))?;
        }
    }

    Ok(())
}

fn validate_match_key(key: &str, scope: &str) -> Result<()> {
    let trimmed = key.trim();
    if trimmed.is_empty() {
        bail!("{scope}: match key must not be empty");
    }

    if DOCUMENTED_MATCH_FIELDS.contains(&trimmed) {
        return Ok(());
    }

    if trimmed.starts_with("labels.") || trimmed.starts_with("action.") {
        return Ok(());
    }
    if trimmed.starts_with("resource.") || trimmed.starts_with("risk.") {
        return Ok(());
    }
    if trimmed.starts_with("behavior.signal.") || trimmed.starts_with("risk.factor.") {
        return Ok(());
    }
    if matches!(trimmed, "path_pattern" | "path_prefix" | "path_not_prefix") {
        return Ok(());
    }

    bail!("{scope}: unknown match key `{trimmed}`");
}

/// Returns `true` when the document is legacy-only (no normalized rules section).
pub fn is_legacy_only(config: &PolicyConfig) -> bool {
    config.schema_version == SCHEMA_LEGACY && config.rules.is_empty()
}
