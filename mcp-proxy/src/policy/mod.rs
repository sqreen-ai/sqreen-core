//! Declarative policy engine for agent actions.
//!
//! Policies are authored as versioned YAML/JSON, validated at load time, and compiled into
//! trust-layered rules. Priority orders matches **within** a layer; cross-layer conflicts use
//! tighten-only effect severity (`Deny` > `Confirm` > `Redact` > `Allow`). Evaluation operates
//! on normalized [`crate::action::AgentAction`] semantics — identity, taxonomy, and resource
//! paths — while legacy tool-centric rules remain supported for backwards compatibility.

mod canonical;
mod compile;
mod compose;
mod evaluation;
mod match_ctx;
mod redact;
mod schema;
mod signed;
mod validate;

#[cfg(test)]
mod integrity_tests;
#[cfg(test)]
mod trust_layer_tests;

pub use compile::{compile_config, compile_layered, CompiledPolicy, PolicyTrustLayer, RuleSource};
pub use compose::{
    compose_effective_policy, mandatory_security_baseline, overlay_globals_and_tools,
    respects_mandatory_baseline,
};
pub use evaluation::{
    evaluate_policy, evaluate_policy_with_behavior, evaluate_policy_with_context, BlockedRule,
    MatchedRuleSummary, PolicyEvaluation, PolicyVerdict,
};
pub use match_ctx::{PolicyMatchContext, DOCUMENTED_MATCH_FIELDS};
pub use schema::{
    GlobalPolicy, IdentityRule, PolicyAction, PolicyConfig, PolicyMode, PolicyRule, RuleEffect,
    TaxonomyRule, ToolPolicy, SCHEMA_2026_3, SCHEMA_LEGACY, SUPPORTED_SCHEMA_VERSIONS,
};
pub use signed::{
    acceptance_from_envelope, acceptance_path_beside_cache, activate_signed_policy,
    emit_policy_event, load_acceptance, load_signed_envelope, parse_sync_response,
    persist_acceptance, persist_signed_envelope, policy_digest, reject_err, require_signed_policy,
    verify_signature, PolicyAcceptanceState, PolicyRejectReason, SignedPolicyEnvelope,
    VerifiedPolicyActivation, ALLOW_TEST_KEYS_ENV, ALLOW_UNSIGNED_ENV, ENVELOPE_SCHEMA_VERSION,
    ORG_ID_ENV, PRIMARY_POLICY_KEY_ID, TEST_POLICY_KEY_ID,
};
pub use validate::{is_legacy_only, validate_config};

use std::collections::{HashMap, HashSet};
use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use serde::Deserialize;
use serde_json::Value;

use crate::action::{AgentAction, Arguments};
use crate::behavior::BehaviorFinding;
use crate::scoring::ExplainableRiskScore;

use redact::redact_value;

/// Default policy file name in the working directory.
pub const DEFAULT_POLICY_FILE: &str = "mcp-policy.yaml";

/// Environment variable used to override the policy file path.
pub const POLICY_PATH_ENV: &str = "MCP_POLICY_PATH";

/// Compiled, runtime-ready policy loaded at startup.
#[derive(Debug)]
pub struct PolicyEngine {
    compiled: CompiledPolicy,
}

impl PolicyEngine {
    pub fn from_compiled(compiled: CompiledPolicy) -> Self {
        Self { compiled }
    }

    pub fn from_config(config: PolicyConfig) -> Result<Self> {
        Ok(Self {
            compiled: compile_config(config)?,
        })
    }

    /// Compose mandatory baseline + organization + optional local with trust layers.
    pub fn from_layered(organization: &PolicyConfig, local: Option<&PolicyConfig>) -> Result<Self> {
        Ok(Self {
            compiled: compile_layered(organization, local)?,
        })
    }

    pub fn from_yaml(source: &str) -> Result<Self> {
        Self::from_config(PolicyConfig::from_yaml(source).context("failed to parse policy yaml")?)
    }

    pub fn load(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref();
        let source = fs::read_to_string(path)
            .with_context(|| format!("failed to read policy file at {}", path.display()))?;
        Self::from_yaml(&source)
    }

    pub fn load_optional() -> Result<Option<Self>> {
        let path = resolve_policy_path();
        if !path.exists() {
            return Ok(None);
        }
        Ok(Some(Self::load(path)?))
    }

    pub fn version(&self) -> &str {
        &self.compiled.version
    }

    pub fn schema_version(&self) -> &str {
        &self.compiled.schema_version
    }

    pub fn mode(&self) -> PolicyMode {
        self.compiled.mode
    }

    pub fn tool_count(&self) -> usize {
        self.compiled
            .rules
            .iter()
            .filter(|rule| {
                matches!(
                    rule.source,
                    RuleSource::LegacyToolBlock | RuleSource::LegacyToolAction
                )
            })
            .count()
    }

    pub fn risk_threshold(&self) -> u8 {
        self.compiled.risk_threshold
    }

    pub fn evaluate_detailed(&self, action: &AgentAction) -> PolicyEvaluation {
        self.evaluate_detailed_with_context(action, None, None)
    }

    pub fn evaluate_detailed_with_behavior(
        &self,
        action: &AgentAction,
        behavior: Option<&BehaviorFinding>,
    ) -> PolicyEvaluation {
        self.evaluate_detailed_with_context(action, behavior, None)
    }

    pub fn evaluate_detailed_with_context(
        &self,
        action: &AgentAction,
        behavior: Option<&BehaviorFinding>,
        risk_score: Option<&ExplainableRiskScore>,
    ) -> PolicyEvaluation {
        evaluate_policy_with_context(&self.compiled, action, behavior, risk_score)
    }

    pub fn evaluate_action(&self, action: &AgentAction) -> PolicyVerdict {
        self.evaluate_detailed(action).verdict_for_enforcement()
    }

    pub fn evaluate_action_with_behavior(
        &self,
        action: &AgentAction,
        behavior: Option<&BehaviorFinding>,
    ) -> PolicyVerdict {
        self.evaluate_detailed_with_behavior(action, behavior)
            .verdict_for_enforcement()
    }

    pub fn evaluate_action_with_context(
        &self,
        action: &AgentAction,
        behavior: Option<&BehaviorFinding>,
        risk_score: Option<&ExplainableRiskScore>,
    ) -> PolicyVerdict {
        self.evaluate_detailed_with_context(action, behavior, risk_score)
            .verdict_for_enforcement()
    }

    pub fn evaluate_tools_call(&self, params_json: &str) -> PolicyVerdict {
        let params = match serde_json::from_str::<ToolsCallParams>(params_json) {
            Ok(params) => params,
            Err(error) => {
                return PolicyVerdict::Unevaluable {
                    detail: format!("tools/call params are not readable: {error}"),
                };
            }
        };

        if params.name.trim().is_empty() {
            return PolicyVerdict::Unevaluable {
                detail: "tools/call params are missing tool name".to_string(),
            };
        }

        let name = params.name;
        let action = AgentAction::builder(
            name.clone(),
            Arguments::from_name_and_arguments(&name, &params.arguments),
        )
        .build_unvalidated();

        self.evaluate_action(&action)
    }

    pub fn redact_global_secrets(&self, frame: &[u8]) -> Vec<u8> {
        match self.try_redact_global_secrets(frame) {
            Ok(redacted) => redacted,
            Err(failure) => failure.best_effort,
        }
    }

    pub fn try_redact_global_secrets(&self, frame: &[u8]) -> Result<Vec<u8>, RedactionFailure> {
        if self.compiled.redact_keys.is_empty() {
            return Ok(frame.to_vec());
        }

        let text = std::str::from_utf8(frame).map_err(|error| RedactionFailure {
            detail: format!("frame is not valid utf-8: {error}"),
            best_effort: frame.to_vec(),
        })?;

        let mut value: Value = serde_json::from_str(text).map_err(|error| RedactionFailure {
            detail: format!("frame is not valid json: {error}"),
            best_effort: frame.to_vec(),
        })?;

        redact_value(&mut value, &self.compiled.redact_keys);
        Ok(value.to_string().into_bytes())
    }
}

/// Global redaction could not be applied to a frame.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RedactionFailure {
    pub detail: String,
    pub best_effort: Vec<u8>,
}

#[derive(Debug, Deserialize)]
struct ToolsCallParams {
    name: String,
    #[serde(default)]
    arguments: Value,
}

impl PolicyConfig {
    pub fn from_yaml(source: &str) -> Result<Self> {
        serde_yaml::from_str(source).context("failed to parse policy yaml")
    }

    pub fn from_json(source: &str) -> Result<Self> {
        serde_json::from_str(source).context("failed to parse policy json")
    }
}

pub fn load_config_optional() -> Result<Option<PolicyConfig>> {
    let path = resolve_policy_path();
    if !path.exists() {
        return Ok(None);
    }

    let source = fs::read_to_string(&path)
        .with_context(|| format!("failed to read policy file at {}", path.display()))?;
    if source.trim().is_empty() {
        anyhow::bail!(
            "policy file at {} is empty — refusing to treat as an empty allow-all policy",
            path.display()
        );
    }
    Ok(Some(PolicyConfig::from_yaml(&source)?))
}

pub fn persist_config_cache(config: &PolicyConfig, path: &Path) -> Result<()> {
    let serialized =
        serde_json::to_string_pretty(config).context("failed to serialize policy cache")?;
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("failed to create policy cache dir {}", parent.display()))?;
    }
    fs::write(path, serialized)
        .with_context(|| format!("failed to write policy cache to {}", path.display()))?;
    Ok(())
}

pub fn load_config_cache(path: &Path) -> Result<Option<PolicyConfig>> {
    if !path.exists() {
        return Ok(None);
    }

    let source = fs::read_to_string(path)
        .with_context(|| format!("failed to read policy cache at {}", path.display()))?;
    Ok(Some(PolicyConfig::from_json(&source)?))
}

pub fn merge_configs(remote: PolicyConfig, local: PolicyConfig) -> PolicyConfig {
    let mut tools_by_name: HashMap<String, ToolPolicy> = remote
        .tools
        .into_iter()
        .map(|tool| (tool.name.clone(), tool))
        .collect();

    for tool in local.tools {
        tools_by_name.entry(tool.name.clone()).or_insert(tool);
    }

    let mut redact_keys: HashSet<String> = remote.global.redact_keys.into_iter().collect();
    redact_keys.extend(local.global.redact_keys);

    let mut block_patterns: HashSet<String> = remote.global.block_patterns.into_iter().collect();
    block_patterns.extend(local.global.block_patterns);

    let mut identity_rules = remote.identity_rules;
    for rule in local.identity_rules {
        if !identity_rules
            .iter()
            .any(|existing| existing.name == rule.name)
        {
            identity_rules.push(rule);
        }
    }

    let mut taxonomy_rules = remote.taxonomy_rules;
    for rule in local.taxonomy_rules {
        if !taxonomy_rules
            .iter()
            .any(|existing| existing.name == rule.name)
        {
            taxonomy_rules.push(rule);
        }
    }

    let mut rules = remote.rules;
    for rule in local.rules {
        if !rules.iter().any(|existing| existing.name == rule.name) {
            rules.push(rule);
        }
    }

    PolicyConfig {
        version: remote.version,
        schema_version: if remote.schema_version != SCHEMA_LEGACY {
            remote.schema_version
        } else {
            local.schema_version
        },
        mode: remote.mode,
        rules,
        global: GlobalPolicy {
            redact_keys: redact_keys.into_iter().collect(),
            risk_threshold: remote.global.risk_threshold,
            block_patterns: block_patterns.into_iter().collect(),
        },
        identity_rules,
        taxonomy_rules,
        tools: tools_by_name.into_values().collect(),
    }
}

/// Compose mandatory baseline + remote org policy + optional local (stricter-only overlays).
pub fn build_engine_composed(
    remote_config: Option<PolicyConfig>,
    local_config: Option<PolicyConfig>,
) -> Result<Option<PolicyEngine>> {
    match (remote_config, local_config) {
        (Some(remote), local) => Ok(Some(PolicyEngine::from_layered(&remote, local.as_ref())?)),
        // Local-only YAML is treated as the organization authoring layer atop the baseline.
        (None, Some(local)) => Ok(Some(PolicyEngine::from_layered(&local, None)?)),
        (None, None) => Ok(None),
    }
}

/// Legacy merge helper that does **not** apply the mandatory security baseline.
///
/// Production / fleet activation must use [`build_engine_composed`] or
/// [`PolicyEngine::from_layered`] / [`activate_signed_policy`] instead.
/// Kept only for narrow unit-test and demo call sites that intentionally
/// compile a single authored document.
#[doc(hidden)]
pub fn build_engine_without_baseline_for_tests(
    remote_config: Option<PolicyConfig>,
    local_config: Option<PolicyConfig>,
) -> Result<Option<PolicyEngine>> {
    let config = match (remote_config, local_config) {
        (Some(remote), Some(local)) => Some(merge_configs(remote, local)),
        (Some(remote), None) => Some(remote),
        (None, Some(local)) => Some(local),
        (None, None) => None,
    };

    config.map(PolicyEngine::from_config).transpose()
}

#[deprecated(
    note = "use build_engine_composed / from_layered — this helper skips the mandatory baseline"
)]
pub fn build_engine(
    remote_config: Option<PolicyConfig>,
    local_config: Option<PolicyConfig>,
) -> Result<Option<PolicyEngine>> {
    build_engine_without_baseline_for_tests(remote_config, local_config)
}

pub fn blocked_response(id: &Value, reason: &str) -> Vec<u8> {
    let response = serde_json::json!({
        "jsonrpc": "2.0",
        "id": id,
        "error": {
            "code": -32_000,
            "message": format!("blocked by mcp-proxy policy: {reason}"),
        }
    });

    response.to_string().into_bytes()
}

pub fn access_denied_response(id: &Value, reason: &str) -> Vec<u8> {
    let response = serde_json::json!({
        "jsonrpc": "2.0",
        "id": id,
        "error": {
            "code": -32_003,
            "message": format!("access denied: {reason}"),
        }
    });

    response.to_string().into_bytes()
}

pub fn rewrite_tools_call_frame(original_frame: &[u8], redacted_params: &[u8]) -> Result<Vec<u8>> {
    let mut value: Value =
        serde_json::from_slice(original_frame).context("failed to parse request frame")?;
    let params_value: Value =
        serde_json::from_slice(redacted_params).context("failed to parse redacted params")?;

    if let Some(object) = value.as_object_mut() {
        object.insert("params".to_string(), params_value);
    }

    Ok(value.to_string().into_bytes())
}

fn resolve_policy_path() -> PathBuf {
    resolve_policy_path_for_load().unwrap_or_else(|| PathBuf::from(DEFAULT_POLICY_FILE))
}

/// Resolves the policy file used at startup / demos.
///
/// Order: `MCP_POLICY_PATH` → `./mcp-policy.yaml` if present → `~/.config/mcp-proxy/mcp-policy.yaml`.
pub fn resolve_policy_path_for_load() -> Option<PathBuf> {
    if let Ok(path) = std::env::var(POLICY_PATH_ENV) {
        let path = PathBuf::from(path);
        if path.exists() {
            return Some(path);
        }
        // Explicit override that does not exist — still return it so load errors are clear.
        return Some(path);
    }

    let cwd = PathBuf::from(DEFAULT_POLICY_FILE);
    if cwd.exists() {
        return Some(cwd);
    }

    let home = std::env::var_os("HOME")?;
    let installed = PathBuf::from(home).join(".config/mcp-proxy/mcp-policy.yaml");
    if installed.exists() {
        return Some(installed);
    }

    None
}

#[cfg(test)]
mod tests;
