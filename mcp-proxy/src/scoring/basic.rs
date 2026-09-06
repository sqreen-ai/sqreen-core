//! Open-core basic risk scorer — coarse, transparent, no proprietary weights.
//!
//! Uses max-of-signals severity buckets (LOW/MEDIUM/HIGH/CRITICAL), not tuned
//! weighted combinations. Advanced weighting lives under `enterprise`.

use crate::action::AgentAction;
use crate::taxonomy::{ActionCategory, ResourceCategory};

use super::types::{
    ExplainableRiskScore, RiskFactor, RiskFactorKind, RiskLevelThresholds, RiskScoreInput,
    SCORE_SEMANTICS,
};

/// Placeholder kept for API stability; open-core does not expose tuned weights.
#[derive(Debug, Clone, PartialEq, Eq, Default, serde::Serialize, serde::Deserialize)]
pub struct RiskScoreWeights;

/// Placeholder kept for API stability; open-core does not expose diminishing-return caps.
#[derive(Debug, Clone, PartialEq, Eq, Default, serde::Serialize, serde::Deserialize)]
pub struct RiskScoreCaps;

/// Basic open-core scorer configuration (level bands only).
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize, Default)]
pub struct RiskScoreConfig {
    pub weights: RiskScoreWeights,
    pub levels: RiskLevelThresholds,
    pub caps: RiskScoreCaps,
}

/// Coarse local risk scorer for standalone Core.
#[derive(Debug, Clone, Default)]
pub struct RiskScoreEngine {
    config: RiskScoreConfig,
}

impl RiskScoreEngine {
    pub fn new(config: RiskScoreConfig) -> Self {
        Self { config }
    }

    pub fn config(&self) -> &RiskScoreConfig {
        &self.config
    }

    /// Scores an action with transparent coarse buckets (max of fired signals).
    pub fn score(&self, action: &AgentAction, input: RiskScoreInput<'_>) -> ExplainableRiskScore {
        let mut factors: Vec<RiskFactor> = Vec::new();

        let security = &action.security;
        let tool = action.tool_name();

        if security.risk.credential_access
            || security.touches_resource(ResourceCategory::Secret)
            || security.touches_resource(ResourceCategory::Credential)
        {
            factors.push(bucket(
                RiskFactorKind::SecretAccess,
                80,
                format!("credential/secret material via `{tool}`"),
            ));
        }

        if security.risk.destructive
            || matches!(
                security.action,
                ActionCategory::Delete | ActionCategory::Deploy | ActionCategory::Escalate
            )
        {
            factors.push(bucket(
                RiskFactorKind::DestructiveAction,
                70,
                format!("destructive action category `{}`", security.action.as_str()),
            ));
        }

        // Coarse shell / high-impact tool bucket (fixed severity, not weighted).
        if is_policy_sensitive_tool(tool) {
            factors.push(bucket(
                RiskFactorKind::PolicySensitiveOperation,
                75,
                format!("tool `{tool}` is a high-impact policy-sensitive operation"),
            ));
        }

        // Unknown / partially classified tools get a transparent unusual-tool flag.
        let knowledge = crate::classify::classify(tool, &action.arguments).tool_knowledge;
        match knowledge {
            crate::security_baseline::ToolKnowledge::Unknown => {
                factors.push(bucket(
                    RiskFactorKind::UnusualTool,
                    40,
                    format!("tool `{tool}` is unknown to the classifier"),
                ));
            }
            crate::security_baseline::ToolKnowledge::PartiallyClassified => {
                factors.push(bucket(
                    RiskFactorKind::UnusualTool,
                    35,
                    format!("tool `{tool}` is only partially classified from arguments"),
                ));
            }
            crate::security_baseline::ToolKnowledge::Known => {}
        }

        if let Some(content) = input.content {
            if content.score >= 50 {
                factors.push(bucket(
                    RiskFactorKind::ContentSecret,
                    content.score.min(85),
                    "content scanner flagged sensitive material".into(),
                ));
            }
        }

        if input.ioc_match {
            factors.push(bucket(
                RiskFactorKind::ThreatIntel,
                85,
                "threat-intel indicator matched".into(),
            ));
        }

        // Behavior findings may exist but open-core does not score advanced profiles.
        let _ = input.behavior;

        let score = factors
            .iter()
            .map(|factor| factor.contribution)
            .max()
            .unwrap_or(0)
            .min(100);

        ExplainableRiskScore {
            score,
            level: self.config.levels.level_for(score),
            factors,
            semantics: SCORE_SEMANTICS,
        }
    }
}

fn bucket(kind: RiskFactorKind, contribution: u8, detail: String) -> RiskFactor {
    RiskFactor {
        kind,
        weight: contribution,
        contribution,
        detail,
    }
}

/// Transparent allowlist of high-impact tools — not a proprietary weight table.
fn is_policy_sensitive_tool(tool_name: &str) -> bool {
    let name = tool_name.to_ascii_lowercase();
    matches!(
        name.as_str(),
        "execute_bash"
            | "run_terminal_cmd"
            | "shell"
            | "bash"
            | "write_file"
            | "edit_file"
            | "apply_patch"
            | "delete_file"
            | "remove_file"
            | "deploy_release"
            | "kubectl"
    ) || name.contains("deploy")
        || name.contains("sudo")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::action::{Arguments, Runtime, SourceRef};

    fn action(tool: &str, args: serde_json::Value) -> AgentAction {
        let mut built = AgentAction::builder(tool, Arguments::from_name_and_arguments(tool, &args))
            .source(SourceRef::new(Runtime::MCP_STDIO, "test"))
            .build_unvalidated();
        built.refresh_security_classification();
        built
    }

    #[test]
    fn credential_path_is_high_or_critical() {
        let engine = RiskScoreEngine::default();
        let scored = engine.score(
            &action(
                "read_file",
                serde_json::json!({"path": "/tmp/sqreen-demo.ssh/id_rsa"}),
            ),
            RiskScoreInput::default(),
        );
        assert!(scored.score >= 50);
        assert!(scored.has_factor(RiskFactorKind::SecretAccess));
    }

    #[test]
    fn benign_tmp_read_is_low() {
        let engine = RiskScoreEngine::default();
        let scored = engine.score(
            &action(
                "read_file",
                serde_json::json!({"path": "/tmp/sqreen-demo-ok.txt"}),
            ),
            RiskScoreInput::default(),
        );
        assert!(scored.score < 50);
    }
}
