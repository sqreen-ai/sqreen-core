//! Open-core stub: no remote control-plane connectivity.
//!
//! Shared wire-shaped types remain so local audit/telemetry code compiles; every
//! network method is a no-op or returns an explicit error.

use anyhow::{bail, Result};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::policy::PolicyConfig;
use crate::threat_intel::ThreatIntelFeed;

pub const CONTROL_PLANE_URL_ENV: &str = "MCP_CONTROL_PLANE_URL";
pub const DEVICE_TOKEN_ENV: &str = "MCP_DEVICE_TOKEN";
pub const DEVICE_ID_ENV: &str = "SQREEN_DEVICE_ID";
pub const DEVICE_ID_ENV_LEGACY: &str = "MCP_DEVICE_ID";
pub const DEVICE_TOKEN_HEADER: &str = "X-Device-Token";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PolicySyncSource {
    ControlPlane,
    Cache,
    LocalYaml,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ThreatIntelSyncSource {
    ControlPlane,
    Cache,
    LocalFile,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum UserDecision {
    Approved,
    Denied,
    Skipped,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RemoteApprovalStatus {
    pub id: String,
    pub status: String,
    #[serde(default)]
    pub action_digest: String,
    #[serde(default)]
    pub expires_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateRemoteApprovalBody {
    pub action_digest: String,
    pub tool_name: String,
    pub sanitized_arguments: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub agent_bound_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub agent_label: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub agent_trust: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub execution_session_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub action_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub action_category: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub target_resource: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub environment: Option<String>,
    pub risk_score: u8,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub risk_level: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub risk_factors: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub matched_policies: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub idempotency_key: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TelemetryRecord {
    pub timestamp: DateTime<Utc>,
    pub device_id: String,
    pub tool_name: String,
    pub risk_score: u8,
    pub pattern_matched: String,
    pub user_decision: UserDecision,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub agent_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub agent_label: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub agent_trust: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub agent_identity_source: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub agent_bound_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub user_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub user_label: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub user_trust: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session_label: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session_trust: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub runtime: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub model_provider: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub risk_factors: Vec<String>,
}

impl TelemetryRecord {
    pub fn new(
        device_id: impl Into<String>,
        tool_name: impl Into<String>,
        risk_score: u8,
        pattern_matched: impl Into<String>,
        user_decision: UserDecision,
    ) -> Self {
        Self {
            timestamp: Utc::now(),
            device_id: device_id.into(),
            tool_name: tool_name.into(),
            risk_score,
            pattern_matched: pattern_matched.into(),
            user_decision,
            agent_id: None,
            agent_label: None,
            agent_trust: None,
            agent_identity_source: None,
            agent_bound_id: None,
            user_id: None,
            user_label: None,
            user_trust: None,
            session_id: None,
            session_label: None,
            session_trust: None,
            runtime: None,
            model_provider: None,
            risk_factors: Vec::new(),
        }
    }

    pub fn with_execution_identity(mut self, action: &crate::action::AgentAction) -> Self {
        let principal = action.identity.execution_principal(
            action.execution.session_id.as_ref(),
            &action.execution.runtime,
            &action.model,
            Some(action.source.adapter.as_str()),
        );
        if let Some(agent) = principal.agent {
            self.agent_label = Some(agent.value.clone());
            self.agent_id = Some(agent.value);
            self.agent_trust = Some(agent.trust.as_str().to_string());
            self.agent_identity_source = Some(agent.source);
        }
        self.agent_bound_id = principal.agent_bound_id;
        if let Some(user) = principal.user {
            self.user_label = Some(user.value.clone());
            self.user_id = Some(user.value);
            self.user_trust = Some(user.trust.as_str().to_string());
        }
        if let Some(session) = principal.session {
            self.session_label = Some(session.value.clone());
            self.session_id = Some(session.value);
            self.session_trust = Some(session.trust.as_str().to_string());
        }
        self.runtime = Some(principal.runtime);
        self.model_provider = principal.provider;
        self
    }

    pub fn with_identity_from_event(mut self, event: &crate::telemetry::AgentSecurityEvent) -> Self {
        self.agent_id = Some(event.agent.agent_id.clone());
        self.agent_label = Some(event.agent.agent_id.clone());
        self.agent_trust = Some(event.agent.agent_trust.clone());
        self.agent_identity_source = event.agent.agent_identity_source.clone();
        self.agent_bound_id = event.agent.agent_bound_id.clone();
        self.user_id = event.agent.user_id.clone();
        self.user_label = event.agent.user_id.clone();
        self.user_trust = Some(event.agent.user_trust.clone());
        self.session_id = event.session.session_id.clone();
        self.session_label = event.session.session_id.clone();
        self.session_trust = Some("self_asserted".to_string());
        self.runtime = Some(event.session.runtime.clone());
        self.risk_factors = event.risk.factors.clone();
        self
    }
}

/// Stub client — never constructed in open-core (`load_optional` is always `None`).
#[derive(Clone)]
pub struct CloudClient {
    device_id: String,
}

impl CloudClient {
    pub fn new(_base_url: &str, _device_token: &str) -> Self {
        Self {
            device_id: "open-core-stub".into(),
        }
    }

    pub fn new_with_device_id(
        _base_url: &str,
        _device_token: &str,
        device_id: impl Into<String>,
    ) -> Self {
        Self {
            device_id: device_id.into(),
        }
    }

    pub fn load_optional() -> Option<Self> {
        None
    }

    pub fn device_id(&self) -> &str {
        &self.device_id
    }

    pub async fn fetch_latest_policy(&self) -> Result<(PolicyConfig, PolicySyncSource)> {
        bail!("enterprise cloud client is not available in open-core builds")
    }

    pub async fn fetch_latest_threat_intel(
        &self,
    ) -> Result<(ThreatIntelFeed, ThreatIntelSyncSource)> {
        bail!("enterprise cloud client is not available in open-core builds")
    }

    pub fn dispatch_telemetry(&self, _record: TelemetryRecord) {
        // No-op: open-core has no control-plane sink.
    }

    pub async fn create_approval_request(
        &self,
        _body: CreateRemoteApprovalBody,
    ) -> Result<RemoteApprovalStatus> {
        bail!("remote approvals require the enterprise feature")
    }

    pub async fn get_approval_status(&self, _id: &str) -> Result<RemoteApprovalStatus> {
        bail!("remote approvals require the enterprise feature")
    }

    pub async fn consume_approval(
        &self,
        _id: &str,
        _action_digest: &str,
    ) -> Result<RemoteApprovalStatus> {
        bail!("remote approvals require the enterprise feature")
    }
}
