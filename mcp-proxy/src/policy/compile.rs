//! Compiles declarative policy documents into runtime rules.

use std::collections::{HashMap, HashSet};

use anyhow::{bail, Context, Result};
use regex::Regex;

use super::compose::{mandatory_security_baseline, overlay_globals_and_tools};
use super::schema::{
    IdentityRule, PolicyAction, PolicyConfig, PolicyRule, RuleEffect, TaxonomyRule, ToolPolicy,
};
use super::validate::validate_config;

/// Legacy identity rules — evaluated before taxonomy in the old pipeline.
pub const LEGACY_IDENTITY_PRIORITY_BASE: i32 = 7_000;
/// Legacy taxonomy rules.
pub const LEGACY_TAXONOMY_PRIORITY_BASE: i32 = 6_000;
/// Legacy global payload block patterns.
pub const LEGACY_GLOBAL_BLOCK_PRIORITY: i32 = 5_000;
/// Legacy per-tool payload block patterns.
pub const LEGACY_TOOL_BLOCK_PRIORITY: i32 = 4_500;
/// Legacy whole-tool deny.
pub const LEGACY_TOOL_DENY_PRIORITY: i32 = 4_000;
/// Legacy whole-tool approval.
pub const LEGACY_TOOL_APPROVAL_PRIORITY: i32 = 3_500;

/// Trust / provenance layer for a compiled rule.
///
/// Priority is meaningful **within** a layer. Cross-layer authority uses tighten-only
/// effect merge (Deny > Confirm > Redact > Allow), never raw priority across layers.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum PolicyTrustLayer {
    /// Optional local restrictions (may only tighten).
    Local = 0,
    /// Authenticated organization / managed policy.
    Organization = 1,
    /// Immutable Sqreen mandatory security baseline.
    MandatoryBaseline = 2,
}

impl PolicyTrustLayer {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::MandatoryBaseline => "mandatory_baseline",
            Self::Organization => "organization",
            Self::Local => "local",
        }
    }

    pub fn rank(self) -> u8 {
        self as u8
    }
}

/// Where a compiled rule originated.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RuleSource {
    Normalized,
    LegacyIdentity,
    LegacyTaxonomy,
    LegacyGlobalBlock,
    LegacyToolBlock,
    LegacyToolAction,
}

/// One predicate evaluated against [`super::match_ctx::PolicyMatchContext`].
#[derive(Debug)]
pub enum Predicate {
    FieldEquals { field: String, expected: String },
    PathRegex(Regex),
    PathPrefix(String),
    PathNotPrefix(String),
    PayloadRegex(Regex),
}

/// Runtime-ready rule sorted deterministically at evaluation time.
#[derive(Debug)]
pub struct CompiledRule {
    pub id: String,
    pub name: String,
    pub priority: i32,
    pub order: u32,
    pub effect: RuleEffect,
    pub description: Option<String>,
    pub tools: HashSet<String>,
    pub predicates: Vec<Predicate>,
    pub source: RuleSource,
    pub trust_layer: PolicyTrustLayer,
}

/// Output of compiling a [`PolicyConfig`].
#[derive(Debug)]
pub struct CompiledPolicy {
    pub version: String,
    pub schema_version: String,
    pub mode: super::schema::PolicyMode,
    pub rules: Vec<CompiledRule>,
    pub redact_keys: HashSet<String>,
    pub risk_threshold: u8,
}

pub fn compile_config(config: PolicyConfig) -> Result<CompiledPolicy> {
    compile_config_with_layer(config, PolicyTrustLayer::Organization)
}

pub fn compile_config_with_layer(
    config: PolicyConfig,
    layer: PolicyTrustLayer,
) -> Result<CompiledPolicy> {
    validate_config(&config)?;

    let mut rules = Vec::new();
    let mut order = 0u32;
    append_all_rules(&mut rules, &mut order, &config, layer)?;

    Ok(CompiledPolicy {
        version: config.version,
        schema_version: config.schema_version,
        mode: config.mode,
        rules,
        redact_keys: config.global.redact_keys.into_iter().collect(),
        risk_threshold: config.global.risk_threshold,
    })
}

/// Compile mandatory + organization + optional local with explicit trust layers.
pub fn compile_layered(
    organization: &PolicyConfig,
    local: Option<&PolicyConfig>,
) -> Result<CompiledPolicy> {
    let baseline = mandatory_security_baseline();
    let merged = overlay_globals_and_tools(&baseline, organization, local);

    // `merged` carries tighten-only tools/globals with `rules` cleared intentionally.
    // Validate authoring documents, not the intermediate carrier.
    validate_config(organization)?;
    if let Some(local_cfg) = local {
        validate_config(local_cfg)?;
    }

    let mut rules = Vec::new();
    let mut order = 0u32;

    for rule in &baseline.rules {
        rules.push(compile_normalized_rule(
            rule,
            &mut order,
            PolicyTrustLayer::MandatoryBaseline,
        )?);
    }
    for rule in &organization.rules {
        rules.push(compile_normalized_rule(
            rule,
            &mut order,
            PolicyTrustLayer::Organization,
        )?);
    }
    if let Some(local_cfg) = local {
        for rule in &local_cfg.rules {
            rules.push(compile_normalized_rule(
                rule,
                &mut order,
                PolicyTrustLayer::Local,
            )?);
        }
    }

    // Merged tools / block patterns / legacy rules are already tighten-only.
    append_legacy_rules(
        &mut rules,
        &mut order,
        &merged,
        PolicyTrustLayer::Organization,
    )?;

    Ok(CompiledPolicy {
        version: merged.version,
        schema_version: merged.schema_version,
        mode: merged.mode,
        rules,
        redact_keys: merged.global.redact_keys.into_iter().collect(),
        risk_threshold: merged.global.risk_threshold,
    })
}

fn append_all_rules(
    rules: &mut Vec<CompiledRule>,
    order: &mut u32,
    config: &PolicyConfig,
    layer: PolicyTrustLayer,
) -> Result<()> {
    for rule in &config.rules {
        rules.push(compile_normalized_rule(rule, order, layer)?);
    }
    append_legacy_rules(rules, order, config, layer)
}

fn append_legacy_rules(
    rules: &mut Vec<CompiledRule>,
    order: &mut u32,
    config: &PolicyConfig,
    layer: PolicyTrustLayer,
) -> Result<()> {
    for (index, rule) in config.identity_rules.iter().enumerate() {
        rules.push(compile_identity_rule(rule, index, order, layer)?);
    }
    for (index, rule) in config.taxonomy_rules.iter().enumerate() {
        rules.push(compile_taxonomy_rule(rule, index, order, layer)?);
    }
    for pattern in &config.global.block_patterns {
        rules.push(compile_global_block(pattern, order, layer)?);
    }

    let mut tools = HashMap::new();
    for tool in &config.tools {
        if tools.contains_key(&tool.name) {
            bail!("duplicate tool policy for `{}`", tool.name);
        }
        tools.insert(tool.name.clone(), tool.clone());
    }
    for tool in tools.into_values() {
        rules.extend(compile_tool_policy(tool, order, layer)?);
    }
    Ok(())
}

fn compile_normalized_rule(
    rule: &PolicyRule,
    order: &mut u32,
    layer: PolicyTrustLayer,
) -> Result<CompiledRule> {
    let mut predicates = Vec::new();

    for (field, expected) in &rule.when {
        match field.as_str() {
            "path_pattern" => {
                predicates.push(Predicate::PathRegex(Regex::new(expected).with_context(
                    || format!("rules[{}]: invalid path_pattern `{expected}`", rule.name),
                )?));
            }
            "path_prefix" => predicates.push(Predicate::PathPrefix(expected.clone())),
            "path_not_prefix" => predicates.push(Predicate::PathNotPrefix(expected.clone())),
            _ => predicates.push(Predicate::FieldEquals {
                field: field.clone(),
                expected: expected.clone(),
            }),
        }
    }

    Ok(CompiledRule {
        id: format!("{}.rules[{}]", layer.as_str(), rule.name),
        name: rule.name.clone(),
        priority: rule.priority,
        order: next_order(order),
        effect: rule.effect,
        description: rule.description.clone(),
        tools: rule.tools.iter().cloned().collect(),
        predicates,
        source: RuleSource::Normalized,
        trust_layer: layer,
    })
}

fn compile_identity_rule(
    rule: &IdentityRule,
    index: usize,
    order: &mut u32,
    layer: PolicyTrustLayer,
) -> Result<CompiledRule> {
    Ok(CompiledRule {
        id: format!("{}.identity_rules[{}]", layer.as_str(), rule.name),
        name: rule.name.clone(),
        priority: LEGACY_IDENTITY_PRIORITY_BASE - index as i32,
        order: next_order(order),
        effect: rule.action.into(),
        description: None,
        tools: rule.tools.iter().cloned().collect(),
        predicates: rule
            .when
            .iter()
            .map(|(field, expected)| Predicate::FieldEquals {
                field: field.clone(),
                expected: expected.clone(),
            })
            .collect(),
        source: RuleSource::LegacyIdentity,
        trust_layer: layer,
    })
}

fn compile_taxonomy_rule(
    rule: &TaxonomyRule,
    index: usize,
    order: &mut u32,
    layer: PolicyTrustLayer,
) -> Result<CompiledRule> {
    Ok(CompiledRule {
        id: format!("{}.taxonomy_rules[{}]", layer.as_str(), rule.name),
        name: rule.name.clone(),
        priority: LEGACY_TAXONOMY_PRIORITY_BASE - index as i32,
        order: next_order(order),
        effect: rule.action.into(),
        description: None,
        tools: rule.tools.iter().cloned().collect(),
        predicates: rule
            .when
            .iter()
            .map(|(field, expected)| Predicate::FieldEquals {
                field: field.clone(),
                expected: expected.clone(),
            })
            .collect(),
        source: RuleSource::LegacyTaxonomy,
        trust_layer: layer,
    })
}

fn compile_global_block(
    pattern: &str,
    order: &mut u32,
    layer: PolicyTrustLayer,
) -> Result<CompiledRule> {
    Ok(CompiledRule {
        id: format!("{}.global.block_patterns[{pattern}]", layer.as_str()),
        name: format!("global-block-{pattern}"),
        priority: LEGACY_GLOBAL_BLOCK_PRIORITY,
        order: next_order(order),
        effect: RuleEffect::Deny,
        description: None,
        tools: HashSet::new(),
        predicates: vec![Predicate::PayloadRegex(
            Regex::new(pattern)
                .with_context(|| format!("invalid global block_pattern `{pattern}`"))?,
        )],
        source: RuleSource::LegacyGlobalBlock,
        trust_layer: layer,
    })
}

fn compile_tool_policy(
    tool: ToolPolicy,
    order: &mut u32,
    layer: PolicyTrustLayer,
) -> Result<Vec<CompiledRule>> {
    let mut rules = Vec::new();

    for pattern in &tool.block_patterns {
        rules.push(CompiledRule {
            id: format!(
                "{}.tools[{}].block_patterns[{pattern}]",
                layer.as_str(),
                tool.name
            ),
            name: format!("{}-block-{pattern}", tool.name),
            priority: LEGACY_TOOL_BLOCK_PRIORITY,
            order: next_order(order),
            effect: RuleEffect::Deny,
            description: None,
            tools: HashSet::from([tool.name.clone()]),
            predicates: vec![Predicate::PayloadRegex(Regex::new(pattern).with_context(
                || format!("invalid tools[{}] block_pattern `{pattern}`", tool.name),
            )?)],
            source: RuleSource::LegacyToolBlock,
            trust_layer: layer,
        });
    }

    let (priority, effect, source) = match tool.action {
        PolicyAction::Block => (
            LEGACY_TOOL_DENY_PRIORITY,
            RuleEffect::Deny,
            RuleSource::LegacyToolAction,
        ),
        PolicyAction::Confirm => (
            LEGACY_TOOL_APPROVAL_PRIORITY,
            RuleEffect::RequireApproval,
            RuleSource::LegacyToolAction,
        ),
        PolicyAction::Allow => return Ok(rules),
        PolicyAction::Redact => (
            LEGACY_TOOL_APPROVAL_PRIORITY,
            RuleEffect::Redact,
            RuleSource::LegacyToolAction,
        ),
    };

    rules.push(CompiledRule {
        id: format!("{}.tools[{}].action", layer.as_str(), tool.name),
        name: format!("{}-action", tool.name),
        priority,
        order: next_order(order),
        effect,
        description: Some(format!(
            "tool `{}` configured with action {:?}",
            tool.name, tool.action
        )),
        tools: HashSet::from([tool.name.clone()]),
        predicates: Vec::new(),
        source,
        trust_layer: layer,
    });

    Ok(rules)
}

fn next_order(order: &mut u32) -> u32 {
    let current = *order;
    *order += 1;
    current
}

impl CompiledRule {
    pub fn matches(&self, ctx: &super::match_ctx::PolicyMatchContext<'_>) -> bool {
        if !self.tools.is_empty() && !self.tools.contains(ctx.tool_name()) {
            return false;
        }

        let predicates_match = self.predicates.iter().all(|predicate| match predicate {
            Predicate::FieldEquals { field, expected } => ctx.matches_field_equals(field, expected),
            Predicate::PathRegex(pattern) => ctx.matches_path_regex(pattern),
            Predicate::PathPrefix(prefix) => ctx.matches_path_prefix(prefix),
            Predicate::PathNotPrefix(prefix) => ctx.matches_path_not_prefix(prefix),
            Predicate::PayloadRegex(pattern) => {
                let surface = super::match_ctx::inspection_surface(
                    ctx.tool_name(),
                    ctx.canonical_arguments(),
                );
                pattern.is_match(&surface)
            }
        });
        if !predicates_match {
            return false;
        }

        // SELF-ASSERTED IDENTITY MUST NEVER GRANT ADDITIONAL PRIVILEGE.
        // Allow (and Redact-as-allow-path) effects that depend on spoofable identity
        // fields require Bound/Authenticated agent trust — unless the rule explicitly
        // matches agent.bound_id / agent.trust=bound|authenticated.
        if matches!(self.effect, RuleEffect::Allow | RuleEffect::Redact)
            && self.uses_privilege_sensitive_identity()
            && !self.requires_bound_agent_predicate()
            && !ctx.agent_trust_can_grant_privilege()
        {
            return false;
        }

        true
    }

    /// Predicates that would grant privilege if matched solely on labels.
    fn uses_privilege_sensitive_identity(&self) -> bool {
        self.predicates.iter().any(|predicate| {
            let Predicate::FieldEquals { field, .. } = predicate else {
                return false;
            };
            let key = field.trim();
            matches!(
                key,
                "agent_id"
                    | "agent.label"
                    | "user_id"
                    | "user.label"
                    | "session_id"
                    | "session.label"
                    | "organization_id"
                    | "device_id"
            )
        })
    }

    fn requires_bound_agent_predicate(&self) -> bool {
        self.predicates.iter().any(|predicate| {
            let Predicate::FieldEquals { field, expected } = predicate else {
                return false;
            };
            let key = field.trim();
            if matches!(key, "agent.bound_id" | "agent.id" | "agent_bound_id") {
                return !expected.trim().is_empty();
            }
            if matches!(key, "agent.trust" | "agent_trust") {
                let exp = expected.trim().to_ascii_lowercase();
                return exp == "bound" || exp == "authenticated";
            }
            false
        })
    }
}
