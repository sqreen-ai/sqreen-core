//! Remote (control-plane) approval engine — enterprise SOC human gate.
//!
//! # Modes ([`ApprovalMode`] / `SQREEN_APPROVAL_MODE`)
//!
//! | Mode | Behavior |
//! |------|----------|
//! | `local` (default) | [`super::TerminalApprovalEngine`] — TTY / stdin |
//! | `remote` | [`RemoteApprovalEngine`] only; unavailable → Deny/Unavailable; **never** falls back to TTY |
//! | `auto` | Remote when a [`CloudClient`] is configured at **engine selection** time; otherwise Local |
//!
//! Mid-flight fallback from Remote → Local is forbidden. Only `auto` chooses Local when
//! cloud is absent before the first request.
//!
//! Remote approvals are **APPROVE_ONCE** only — no session / timed grants on the wire.

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;

use serde::{Deserialize, Serialize};

use super::{
    ApprovalEngine, ApprovalFuture, ApprovalOutcome, ApprovalRequest, ApprovalVerdict,
    TerminalApprovalEngine,
};
use crate::cloud_client::{CloudClient, CreateRemoteApprovalBody, RemoteApprovalStatus};

/// Env var selecting the approval channel (`local` \| `remote` \| `auto`).
pub const APPROVAL_MODE_ENV: &str = "SQREEN_APPROVAL_MODE";

/// Default remote poll interval while waiting for a human decision.
pub const DEFAULT_REMOTE_POLL_INTERVAL: Duration = Duration::from_millis(750);

/// How the gateway obtains human approval.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ApprovalMode {
    /// Local terminal / stdin engine.
    Local,
    /// Control-plane remote approvals only (fail closed).
    Remote,
    /// Prefer remote when cloud is configured; otherwise local. Selection-time only.
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

    /// Parses `SQREEN_APPROVAL_MODE` (default `local`).
    pub fn from_env() -> Self {
        match std::env::var(APPROVAL_MODE_ENV)
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

/// Builds the approval engine for the configured mode.
///
/// - `Local` → terminal
/// - `Remote` → remote when cloud present; otherwise [`super::UnavailableApprovalEngine`]
/// - `Auto` → remote when cloud present; otherwise terminal
pub fn select_approval_engine(cloud: Option<&Arc<CloudClient>>) -> Arc<dyn ApprovalEngine> {
    match ApprovalMode::from_env() {
        ApprovalMode::Local => Arc::new(TerminalApprovalEngine),
        ApprovalMode::Remote => match cloud {
            Some(client) => Arc::new(RemoteApprovalEngine::new(client.clone())),
            None => {
                eprintln!(
                    "mcp-proxy: SQREEN_APPROVAL_MODE=remote but no cloud client; \
                     approvals unavailable (fail closed — never falling back to TTY)"
                );
                Arc::new(super::UnavailableApprovalEngine)
            }
        },
        ApprovalMode::Auto => match cloud {
            Some(client) => Arc::new(RemoteApprovalEngine::new(client.clone())),
            None => Arc::new(TerminalApprovalEngine),
        },
    }
}

/// Transport used by [`RemoteApprovalEngine`] (real [`CloudClient`] or test mock).
pub trait RemoteApprovalTransport: Send + Sync {
    fn create_approval_request(
        &self,
        body: CreateRemoteApprovalBody,
    ) -> Pin<Box<dyn Future<Output = anyhow::Result<RemoteApprovalStatus>> + Send + '_>>;

    fn get_approval_status(
        &self,
        id: &str,
    ) -> Pin<Box<dyn Future<Output = anyhow::Result<RemoteApprovalStatus>> + Send + '_>>;

    fn consume_approval(
        &self,
        id: &str,
        action_digest: &str,
    ) -> Pin<Box<dyn Future<Output = anyhow::Result<RemoteApprovalStatus>> + Send + '_>>;
}

impl RemoteApprovalTransport for CloudClient {
    fn create_approval_request(
        &self,
        body: CreateRemoteApprovalBody,
    ) -> Pin<Box<dyn Future<Output = anyhow::Result<RemoteApprovalStatus>> + Send + '_>> {
        Box::pin(async move { self.create_approval_request(body).await })
    }

    fn get_approval_status(
        &self,
        id: &str,
    ) -> Pin<Box<dyn Future<Output = anyhow::Result<RemoteApprovalStatus>> + Send + '_>> {
        let id = id.to_string();
        Box::pin(async move { self.get_approval_status(&id).await })
    }

    fn consume_approval(
        &self,
        id: &str,
        action_digest: &str,
    ) -> Pin<Box<dyn Future<Output = anyhow::Result<RemoteApprovalStatus>> + Send + '_>> {
        let id = id.to_string();
        let digest = action_digest.to_string();
        Box::pin(async move { self.consume_approval(&id, &digest).await })
    }
}

/// Polls the control plane until APPROVED / DENIED / EXPIRED, then consumes once.
pub struct RemoteApprovalEngine {
    transport: Arc<dyn RemoteApprovalTransport>,
    poll_interval: Duration,
}

impl RemoteApprovalEngine {
    pub fn new(client: Arc<CloudClient>) -> Self {
        Self {
            transport: client,
            poll_interval: DEFAULT_REMOTE_POLL_INTERVAL,
        }
    }

    pub fn with_transport(
        transport: Arc<dyn RemoteApprovalTransport>,
        poll_interval: Duration,
    ) -> Self {
        Self {
            transport,
            poll_interval,
        }
    }
}

impl ApprovalEngine for RemoteApprovalEngine {
    fn request<'a>(&'a self, request: ApprovalRequest<'a>) -> ApprovalFuture<'a> {
        Box::pin(async move {
            let ctx = request.context;
            let digest = ctx.binding.fingerprint.clone();

            let body = CreateRemoteApprovalBody {
                action_digest: digest.clone(),
                tool_name: ctx.action.clone(),
                sanitized_arguments: ctx.sanitized_arguments.clone(),
                agent_bound_id: non_empty(&ctx.binding.agent_bound_id),
                agent_label: non_empty(&ctx.requesting_agent),
                agent_trust: non_empty(&ctx.binding.agent_trust),
                execution_session_id: non_empty(&ctx.binding.session_id),
                action_id: None,
                action_category: non_empty(&ctx.action_category),
                target_resource: ctx.target_resource.clone(),
                environment: non_empty(&ctx.environment),
                risk_score: ctx.risk_score,
                risk_level: Some(ctx.risk_level.as_str().to_string()),
                risk_factors: ctx.risk_reasons.clone(),
                matched_policies: ctx.matched_policies.clone(),
                idempotency_key: Some(digest.clone()),
            };

            let created = match self.transport.create_approval_request(body).await {
                Ok(status) => status,
                Err(error) => {
                    eprintln!(
                        "mcp-proxy: remote approval create failed: {error:#}; denying (fail closed)"
                    );
                    return ApprovalOutcome::Unavailable;
                }
            };

            // Never execute while PENDING — poll until terminal.
            let status =
                match poll_until_terminal(self.transport.as_ref(), &created.id, self.poll_interval)
                    .await
                {
                    Ok(status) => status,
                    Err(error) => {
                        eprintln!(
                            "mcp-proxy: remote approval poll failed: {error:#}; denying (fail closed)"
                        );
                        return ApprovalOutcome::Unavailable;
                    }
                };

            match status.status.to_ascii_uppercase().as_str() {
                "APPROVED" => {
                    // Recompute digest at consume time (tamper / drift check).
                    let live_digest = request.context.binding.fingerprint.clone();
                    match self
                        .transport
                        .consume_approval(&status.id, &live_digest)
                        .await
                    {
                        Ok(_) => ApprovalOutcome::Approved {
                            verdict: ApprovalVerdict::ApproveOnce,
                        },
                        Err(error) => {
                            eprintln!(
                                "mcp-proxy: remote approval consume failed: {error:#}; denying"
                            );
                            ApprovalOutcome::Unavailable
                        }
                    }
                }
                "DENIED" => ApprovalOutcome::Denied,
                "EXPIRED" | "CANCELLED" => ApprovalOutcome::Denied,
                other => {
                    eprintln!("mcp-proxy: remote approval unexpected status {other}; denying");
                    ApprovalOutcome::Unavailable
                }
            }
        })
    }

    fn name(&self) -> &'static str {
        "remote"
    }
}

async fn poll_until_terminal(
    transport: &dyn RemoteApprovalTransport,
    id: &str,
    interval: Duration,
) -> anyhow::Result<RemoteApprovalStatus> {
    loop {
        let status = transport.get_approval_status(id).await?;
        match status.status.to_ascii_uppercase().as_str() {
            "PENDING" => {
                tokio::time::sleep(interval).await;
            }
            _ => return Ok(status),
        }
    }
}

fn non_empty(value: &str) -> Option<String> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        None
    } else {
        Some(trimmed.to_string())
    }
}

#[cfg(test)]
mod remote_approval_tests {
    use super::*;
    use crate::action::{Arguments, Runtime, SourceRef};
    use crate::gateway::approval::ApprovalContext;
    use std::sync::Mutex;

    struct MockTransport {
        create: Mutex<Option<RemoteApprovalStatus>>,
        poll: Mutex<Vec<RemoteApprovalStatus>>,
        consume_err: Mutex<Option<String>>,
        consume_digest: Mutex<Option<String>>,
        create_err: Mutex<Option<String>>,
    }

    impl RemoteApprovalTransport for MockTransport {
        fn create_approval_request(
            &self,
            body: CreateRemoteApprovalBody,
        ) -> Pin<Box<dyn Future<Output = anyhow::Result<RemoteApprovalStatus>> + Send + '_>>
        {
            Box::pin(async move {
                if let Some(err) = self.create_err.lock().unwrap().clone() {
                    anyhow::bail!("{err}");
                }
                let mut status = self
                    .create
                    .lock()
                    .unwrap()
                    .clone()
                    .unwrap_or(RemoteApprovalStatus {
                        id: "aprq_test".into(),
                        status: "PENDING".into(),
                        action_digest: body.action_digest.clone(),
                        expires_at: None,
                    });
                status.action_digest = body.action_digest;
                Ok(status)
            })
        }

        fn get_approval_status(
            &self,
            _id: &str,
        ) -> Pin<Box<dyn Future<Output = anyhow::Result<RemoteApprovalStatus>> + Send + '_>>
        {
            Box::pin(async move {
                let mut q = self.poll.lock().unwrap();
                if q.is_empty() {
                    anyhow::bail!("empty poll queue");
                }
                Ok(q.remove(0))
            })
        }

        fn consume_approval(
            &self,
            _id: &str,
            action_digest: &str,
        ) -> Pin<Box<dyn Future<Output = anyhow::Result<RemoteApprovalStatus>> + Send + '_>>
        {
            let digest = action_digest.to_string();
            Box::pin(async move {
                *self.consume_digest.lock().unwrap() = Some(digest.clone());
                if let Some(err) = self.consume_err.lock().unwrap().clone() {
                    anyhow::bail!("{err}");
                }
                Ok(RemoteApprovalStatus {
                    id: "aprq_test".into(),
                    status: "CONSUMED".into(),
                    action_digest: digest,
                    expires_at: None,
                })
            })
        }
    }

    fn sample_action() -> crate::action::AgentAction {
        crate::action::AgentAction::builder(
            "execute_bash",
            Arguments::from_name_and_arguments(
                "execute_bash",
                &serde_json::json!({"cmd": "ls"}),
            ),
        )
        .source(SourceRef::new(Runtime::MCP_STDIO, "test"))
        .build_unvalidated()
    }

    fn sample_request<'a>(
        action: &'a crate::action::AgentAction,
        context: &'a ApprovalContext,
    ) -> ApprovalRequest<'a> {
        ApprovalRequest {
            action,
            risk_score: context.risk_score,
            payload: action.canonical_params_json(),
            justification: "test",
            context,
        }
    }

    #[tokio::test]
    async fn remote_unavailable_is_not_allow() {
        let transport = Arc::new(MockTransport {
            create: Mutex::new(None),
            poll: Mutex::new(vec![]),
            consume_err: Mutex::new(None),
            consume_digest: Mutex::new(None),
            create_err: Mutex::new(Some("network down".into())),
        });
        let engine = RemoteApprovalEngine::with_transport(transport, Duration::from_millis(1));
        let action = sample_action();
        let context =
            ApprovalContext::build(&action, action.canonical_params_json(), 90, None, &[], &[]);
        let outcome = engine.request(sample_request(&action, &context)).await;
        assert_eq!(outcome, ApprovalOutcome::Unavailable);
        assert!(!outcome.is_approved());
    }

    #[tokio::test]
    async fn digest_change_invalidates_consume() {
        let action = sample_action();
        let context =
            ApprovalContext::build(&action, action.canonical_params_json(), 90, None, &[], &[]);
        let digest = context.binding.fingerprint.clone();

        let transport = Arc::new(MockTransport {
            create: Mutex::new(Some(RemoteApprovalStatus {
                id: "aprq_1".into(),
                status: "PENDING".into(),
                action_digest: digest.clone(),
                expires_at: None,
            })),
            poll: Mutex::new(vec![RemoteApprovalStatus {
                id: "aprq_1".into(),
                status: "APPROVED".into(),
                action_digest: digest,
                expires_at: None,
            }]),
            consume_err: Mutex::new(Some("action digest mismatch".into())),
            consume_digest: Mutex::new(None),
            create_err: Mutex::new(None),
        });
        let engine = RemoteApprovalEngine::with_transport(transport, Duration::from_millis(1));
        let outcome = engine.request(sample_request(&action, &context)).await;
        assert_eq!(outcome, ApprovalOutcome::Unavailable);
    }

    #[tokio::test]
    async fn approved_path_returns_approve_once() {
        let action = sample_action();
        let context =
            ApprovalContext::build(&action, action.canonical_params_json(), 90, None, &[], &[]);
        let digest = context.binding.fingerprint.clone();

        let transport = Arc::new(MockTransport {
            create: Mutex::new(Some(RemoteApprovalStatus {
                id: "aprq_ok".into(),
                status: "PENDING".into(),
                action_digest: digest.clone(),
                expires_at: None,
            })),
            poll: Mutex::new(vec![
                RemoteApprovalStatus {
                    id: "aprq_ok".into(),
                    status: "PENDING".into(),
                    action_digest: digest.clone(),
                    expires_at: None,
                },
                RemoteApprovalStatus {
                    id: "aprq_ok".into(),
                    status: "APPROVED".into(),
                    action_digest: digest.clone(),
                    expires_at: None,
                },
            ]),
            consume_err: Mutex::new(None),
            consume_digest: Mutex::new(None),
            create_err: Mutex::new(None),
        });
        let engine =
            RemoteApprovalEngine::with_transport(transport.clone(), Duration::from_millis(1));
        let outcome = engine.request(sample_request(&action, &context)).await;
        assert_eq!(outcome, ApprovalOutcome::approve_once());
        assert_eq!(
            transport.consume_digest.lock().unwrap().as_deref(),
            Some(digest.as_str())
        );
    }

    #[test]
    fn remote_mode_without_cloud_is_unavailable_not_terminal() {
        std::env::set_var(APPROVAL_MODE_ENV, "remote");
        let engine = select_approval_engine(None);
        assert_eq!(engine.name(), "unavailable");
        std::env::set_var(APPROVAL_MODE_ENV, "local");
        let local = select_approval_engine(None);
        assert_eq!(local.name(), "terminal");
        std::env::remove_var(APPROVAL_MODE_ENV);
    }
}
