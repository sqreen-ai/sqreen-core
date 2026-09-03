//! Policy composition: mandatory baseline cannot be weakened by remote/local layers.
//!
//! Effective **tools / globals / risk / redact keys** =
//!   mandatory_security_baseline
//!   + organization (managed) policy  (may only tighten overlapping controls)
//!   + optional local restrictions    (may only tighten)
//!
//! Normalized `rules[]` are **not** flattened for enforcement. Use
//! [`crate::policy::compile::compile_layered`] so each rule keeps trust-layer provenance.
//! Evaluation merges per-layer winners with tighten-only effect severity
//! (`Deny` > `Confirm` > `Redact` > `Allow`). Priority is within-layer only.
//!
//! Risk threshold: minimum wins (lower = stricter).
//! Block patterns and redact keys: union (never remove baseline entries).

use std::collections::{HashMap, HashSet};

use super::schema::{
    GlobalPolicy, PolicyAction, PolicyConfig, PolicyMode, ToolPolicy, SCHEMA_LEGACY,
};

/// Severity for composition (higher = stricter).
fn action_severity(action: PolicyAction) -> u8 {
    match action {
        PolicyAction::Block => 3,
        PolicyAction::Confirm => 2,
        PolicyAction::Redact => 1,
        PolicyAction::Allow => 0,
    }
}

fn stricter_action(a: PolicyAction, b: PolicyAction) -> PolicyAction {
    if action_severity(a) >= action_severity(b) {
        a
    } else {
        b
    }
}

/// Immutable Sqreen safety baseline embedded in the binary.
///
/// Sourced from [`crate::security_baseline`] — the single SoT for defaults.
pub fn mandatory_security_baseline() -> PolicyConfig {
    crate::security_baseline::mandatory_policy_config()
}

fn merge_tool(a: ToolPolicy, b: ToolPolicy) -> ToolPolicy {
    let mut patterns: HashSet<String> = a.block_patterns.into_iter().collect();
    patterns.extend(b.block_patterns);
    ToolPolicy {
        name: a.name,
        action: stricter_action(a.action, b.action),
        block_patterns: patterns.into_iter().collect(),
    }
}

/// Merge tools, globals, mode, and legacy identity/taxonomy with tighten-only semantics.
///
/// Normalized `rules[]` are **not** flattened here — they keep trust-layer provenance
/// via [`crate::policy::compile::compile_layered`]. Appending overlay rules into one
/// priority-ordered list is unsafe across trust boundaries.
pub fn overlay_globals_and_tools(
    baseline: &PolicyConfig,
    organization: &PolicyConfig,
    local: Option<&PolicyConfig>,
) -> PolicyConfig {
    let mut merged = overlay_globals_tools_legacy(baseline.clone(), organization);
    if let Some(local_cfg) = local {
        merged = overlay_globals_tools_legacy(merged, local_cfg);
    }
    // Surface metadata from the highest authoring layer; rules stay empty here.
    merged.rules = Vec::new();
    if let Some(local_cfg) = local {
        merged.version = local_cfg.version.clone();
        if local_cfg.schema_version != SCHEMA_LEGACY {
            merged.schema_version = local_cfg.schema_version.clone();
        } else if organization.schema_version != SCHEMA_LEGACY {
            merged.schema_version = organization.schema_version.clone();
        }
    } else {
        merged.version = organization.version.clone();
        if organization.schema_version != SCHEMA_LEGACY {
            merged.schema_version = organization.schema_version.clone();
        }
    }
    merged
}

fn overlay_globals_tools_legacy(base: PolicyConfig, overlay: &PolicyConfig) -> PolicyConfig {
    let mut tools: HashMap<String, ToolPolicy> = base
        .tools
        .into_iter()
        .map(|t| (t.name.clone(), t))
        .collect();

    for tool in &overlay.tools {
        tools
            .entry(tool.name.clone())
            .and_modify(|existing| *existing = merge_tool(existing.clone(), tool.clone()))
            .or_insert_with(|| tool.clone());
    }

    let mut redact: HashSet<String> = base.global.redact_keys.into_iter().collect();
    redact.extend(overlay.global.redact_keys.iter().cloned());

    let mut blocks: HashSet<String> = base.global.block_patterns.into_iter().collect();
    blocks.extend(overlay.global.block_patterns.iter().cloned());

    // Lower risk threshold is stricter.
    let risk_threshold = base
        .global
        .risk_threshold
        .min(overlay.global.risk_threshold);

    // Mode: Enforce wins over Audit (cannot weaken to audit-only via overlay alone
    // when baseline is Enforce).
    let mode = match (base.mode, overlay.mode) {
        (PolicyMode::Enforce, _) | (_, PolicyMode::Enforce) => PolicyMode::Enforce,
        _ => overlay.mode,
    };

    let mut identity_rules = base.identity_rules;
    for rule in &overlay.identity_rules {
        if !identity_rules.iter().any(|e| e.name == rule.name) {
            identity_rules.push(rule.clone());
        }
    }
    let mut taxonomy_rules = base.taxonomy_rules;
    for rule in &overlay.taxonomy_rules {
        if !taxonomy_rules.iter().any(|e| e.name == rule.name) {
            taxonomy_rules.push(rule.clone());
        }
    }

    // Preserve base.rules for compose_effective_policy display merge only.
    let mut rules = base.rules;
    for rule in &overlay.rules {
        if !rules.iter().any(|e| e.name == rule.name) {
            rules.push(rule.clone());
        }
    }

    PolicyConfig {
        version: overlay.version.clone(),
        schema_version: if overlay.schema_version != SCHEMA_LEGACY {
            overlay.schema_version.clone()
        } else {
            base.schema_version
        },
        mode,
        rules,
        global: GlobalPolicy {
            redact_keys: redact.into_iter().collect(),
            risk_threshold,
            block_patterns: blocks.into_iter().collect(),
        },
        identity_rules,
        taxonomy_rules,
        tools: tools.into_values().collect(),
    }
}

/// Compose effective policy document for inspection / SIEM (tools & globals).
///
/// **Enforcement** must use [`crate::policy::compile::compile_layered`] so normalized
/// `rules[]` retain trust-layer provenance. This helper still merges rule *names* for
/// a flattened view and must not be treated as the evaluation authority.
pub fn compose_effective_policy(
    organization: &PolicyConfig,
    local: Option<&PolicyConfig>,
) -> PolicyConfig {
    let mut effective = overlay_globals_tools_legacy(mandatory_security_baseline(), organization);
    if let Some(local) = local {
        effective = overlay_globals_tools_legacy(effective, local);
    }
    effective
}

/// True when `candidate` does not drop any mandatory baseline block pattern
/// and does not weaken a baseline tool action.
pub fn respects_mandatory_baseline(candidate: &PolicyConfig) -> bool {
    let baseline = mandatory_security_baseline();
    let cand_blocks: HashSet<&str> = candidate
        .global
        .block_patterns
        .iter()
        .map(String::as_str)
        .collect();
    for p in &baseline.global.block_patterns {
        if !cand_blocks.contains(p.as_str()) {
            return false;
        }
    }
    let cand_tools: HashMap<&str, &ToolPolicy> = candidate
        .tools
        .iter()
        .map(|t| (t.name.as_str(), t))
        .collect();
    for bt in &baseline.tools {
        if let Some(ct) = cand_tools.get(bt.name.as_str()) {
            if action_severity(ct.action) < action_severity(bt.action) {
                return false;
            }
        }
    }
    if candidate.global.risk_threshold > baseline.global.risk_threshold {
        return false;
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn remote_cannot_remove_baseline_patterns() {
        let mut remote = mandatory_security_baseline();
        remote.global.block_patterns.clear();
        remote.global.risk_threshold = 99;
        for t in &mut remote.tools {
            t.action = PolicyAction::Allow;
            t.block_patterns.clear();
        }
        let effective = compose_effective_policy(&remote, None);
        assert!(respects_mandatory_baseline(&effective));
        assert!(!effective.global.block_patterns.is_empty());
        let bash = effective
            .tools
            .iter()
            .find(|t| t.name == "execute_bash")
            .expect("bash");
        assert_eq!(bash.action, PolicyAction::Confirm);
    }

    #[test]
    fn remote_can_add_stricter_restrictions() {
        let remote = PolicyConfig {
            version: "org-2".into(),
            schema_version: SCHEMA_LEGACY.into(),
            mode: PolicyMode::Enforce,
            rules: vec![],
            global: GlobalPolicy {
                redact_keys: vec!["CUSTOM_SECRET".into()],
                risk_threshold: 40,
                block_patterns: vec!["evil-corp\\.example".into()],
            },
            identity_rules: vec![],
            taxonomy_rules: vec![],
            tools: vec![ToolPolicy {
                name: "execute_bash".into(),
                action: PolicyAction::Block,
                block_patterns: vec!["nc\\s+".into()],
            }],
        };
        let effective = compose_effective_policy(&remote, None);
        assert!(effective.global.risk_threshold <= 40);
        assert!(effective
            .global
            .redact_keys
            .iter()
            .any(|k| k == "CUSTOM_SECRET"));
        let bash = effective
            .tools
            .iter()
            .find(|t| t.name == "execute_bash")
            .unwrap();
        assert_eq!(bash.action, PolicyAction::Block);
    }
}
