//! Open-core approval mode selection (local / unavailable only).

use std::sync::Arc;

use serde::{Deserialize, Serialize};

use super::super::{
    ApprovalEngine, ApprovalFuture, ApprovalOutcome, ApprovalRequest, TerminalApprovalEngine,
    UnavailableApprovalEngine,
};
use crate::cloud_client::CloudClient;

pub const APPROVAL_MODE_ENV: &str = "SQREEN_APPROVAL_MODE";
pub const DEFAULT_REMOTE_POLL_INTERVAL: std::time::Duration =
    std::time::Duration::from_millis(750);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ApprovalMode {
    Local,
    Remote,
    Auto,
}

impl ApprovalMode {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Local => "local",
            Self::Remote => "remote",
            Self::Auto => "auto",
        }
    }

    pub fn from_env() -> Self {
        match crate::local_env::lookup(APPROVAL_MODE_ENV)
            .unwrap_or_default()
            .trim()
            .to_ascii_lowercase()
            .as_str()
        {
            "remote" => Self::Remote,
            "auto" => Self::Auto,
            _ => Self::Local,
        }
    }
}

/// Open-core: remote mode is unavailable; auto falls back to terminal.
pub fn select_approval_engine(_cloud: Option<&Arc<CloudClient>>) -> Arc<dyn ApprovalEngine> {
    match ApprovalMode::from_env() {
        ApprovalMode::Local | ApprovalMode::Auto => Arc::new(TerminalApprovalEngine),
        ApprovalMode::Remote => {
            eprintln!(
                "mcp-proxy: SQREEN_APPROVAL_MODE=remote requires the enterprise build; \
                 approvals unavailable (fail closed)"
            );
            Arc::new(UnavailableApprovalEngine)
        }
    }
}

/// Placeholder type so public re-exports stay stable; not constructible in open-core.
#[derive(Debug)]
pub struct RemoteApprovalEngine;

impl RemoteApprovalEngine {
    pub fn new(_client: Arc<CloudClient>) -> Self {
        Self
    }
}

impl ApprovalEngine for RemoteApprovalEngine {
    fn request<'a>(&'a self, _request: ApprovalRequest<'a>) -> ApprovalFuture<'a> {
        Box::pin(async { ApprovalOutcome::Unavailable })
    }

    fn name(&self) -> &'static str {
        "remote_unavailable_open_core"
    }
}
