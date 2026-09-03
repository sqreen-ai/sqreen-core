//! Approval resolution — a first-class security control, not just a UI prompt.
//!
//! When policy or risk concludes that an action needs a human, the gateway hands a rich
//! [`ApprovalContext`] to an [`ApprovalEngine`]. Engines return an [`ApprovalOutcome`] that
//! may carry an [`ApprovalVerdict`] (`APPROVE_ONCE`, `DENY`, `APPROVE_FOR_SESSION`,
//! time-limited approve). The gateway consults [`ApprovalGrantStore`] before prompting so
//! scoped, non-expired grants can authorize without re-asking — and records every judgment
//! in the store's audit history.
//!
//! # Fail-closed invariant
//!
//! Every outcome other than an explicit approved judgment stops the action. An engine that
//! errors or panics reports [`ApprovalOutcome::Unavailable`] and one that runs out of time
//! reports [`ApprovalOutcome::TimedOut`]; the gateway applies
//! [`crate::gateway::FailurePolicy::approval_unavailable`] to both.
//!
//! An unavailable approver never resolves to a plain allow *even when the deployment
//! configured approval to fail open*: the strongest thing an open posture can produce is
//! [`Decision::RequireApproval`], which [`Decision::stops_execution`] still treats as
//! stopping.

mod context;
mod grant;
mod remote;

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;

use chrono::{DateTime, Utc};

pub use context::{ApprovalContext, DEFAULT_TIMED_APPROVAL};
pub use grant::{
    session_approval_safe, ActionBinding, ApprovalGrant, ApprovalGrantStore, ApprovalHistoryEntry,
    ApprovalHistoryEvent, ApprovalScope, ApprovalVerdict, GrantAuthorization, GrantRejectReason,
    DEFAULT_ONCE_TTL, DEFAULT_SESSION_TTL,
};
pub use remote::{
    select_approval_engine, ApprovalMode, RemoteApprovalEngine, APPROVAL_MODE_ENV,
    DEFAULT_REMOTE_POLL_INTERVAL,
};

use super::decision::Decision;
use super::failure::FailureMode;
use crate::action::AgentAction;

/// Boxed future returned by [`ApprovalEngine::request`].
pub type ApprovalFuture<'a> = Pin<Box<dyn Future<Output = ApprovalOutcome> + Send + 'a>>;

/// The result of asking for approval.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ApprovalOutcome {
    /// An approver allowed the action under a specific verdict.
    Approved { verdict: ApprovalVerdict },
    /// An approver refused the action.
    Denied,
    /// No approver could be reached.
    Unavailable,
    /// An approver was asked and did not answer within the deadline.
    TimedOut,
}

impl ApprovalOutcome {
    /// Convenience constructor for a one-shot approval.
    pub fn approve_once() -> Self {
        Self::Approved {
            verdict: ApprovalVerdict::ApproveOnce,
        }
    }

    /// Returns `true` when the outcome is a human judgment rather than a failure.
    pub fn is_judgment(&self) -> bool {
        matches!(self, Self::Approved { .. } | Self::Denied)
    }

    /// Returns `true` when the action may proceed.
    pub fn is_approved(&self) -> bool {
        matches!(self, Self::Approved { .. })
    }

    /// Maps the outcome onto a decision under the deployment's approval failure mode.
    pub fn as_decision(&self, unavailable: FailureMode) -> Decision {
        match self {
            Self::Approved { .. } => Decision::Allow,
            Self::Denied => Decision::Deny,
            Self::Unavailable | Self::TimedOut => match unavailable {
                FailureMode::FailClosed => Decision::Deny,
                FailureMode::DegradeSafely | FailureMode::FailOpen => Decision::RequireApproval,
            },
        }
    }

    /// Verdict when approved; `None` otherwise.
    pub fn verdict(&self) -> Option<&ApprovalVerdict> {
        match self {
            Self::Approved { verdict } => Some(verdict),
            _ => None,
        }
    }
}

/// Everything an approver needs in order to judge an action.
#[derive(Debug, Clone, Copy)]
pub struct ApprovalRequest<'a> {
    /// The action awaiting approval.
    pub action: &'a AgentAction,
    /// Effective risk score.
    pub risk_score: u8,
    /// Payload to display — the sanitized one when DLP masked anything.
    pub payload: &'a str,
    /// Operator-facing summary of why approval is required.
    pub justification: &'a str,
    /// Full sanitized reviewer brief.
    pub context: &'a ApprovalContext,
}

/// Obtains a human decision on an action.
pub trait ApprovalEngine: Send + Sync {
    /// Requests approval, resolving when a decision is reached or unavailability is
    /// determined.
    fn request<'a>(&'a self, request: ApprovalRequest<'a>) -> ApprovalFuture<'a>;

    /// Stable name for audit records and diagnostics.
    fn name(&self) -> &'static str;
}

/// Prompts the local operator over `/dev/tty`, falling back to stderr and stdin.
///
/// Supports `y` (APPROVE_ONCE), `n` (DENY), `s` (APPROVE_FOR_SESSION when eligible), and
/// `t` (time-limited APPROVE_UNTIL when eligible).
#[derive(Debug, Clone, Copy, Default)]
pub struct TerminalApprovalEngine;

impl ApprovalEngine for TerminalApprovalEngine {
    fn request<'a>(&'a self, request: ApprovalRequest<'a>) -> ApprovalFuture<'a> {
        Box::pin(async move {
            let brief = request.context.render_brief();
            let session_ok = request.context.session_approval_eligible;
            let timed_ok = request.context.timed_approval_eligible;
            let ttl_secs = request.context.timed_approval_ttl_secs;

            let verdict = prompt_approval_verdict(&brief, session_ok, timed_ok, ttl_secs).await;
            match verdict {
                Some(ApprovalVerdict::Deny) => ApprovalOutcome::Denied,
                Some(verdict) => ApprovalOutcome::Approved { verdict },
                None => ApprovalOutcome::Unavailable,
            }
        })
    }

    fn name(&self) -> &'static str {
        "terminal"
    }
}

async fn prompt_approval_verdict(
    brief: &str,
    session_ok: bool,
    timed_ok: bool,
    ttl_secs: u64,
) -> Option<ApprovalVerdict> {
    let owned = brief.to_string();
    let prompt = tokio::task::spawn_blocking(move || prompt_approval_verdict_sync(&owned));

    let settled = match crate::risk::resolve_approval_timeout_public() {
        Some(deadline) => match tokio::time::timeout(deadline, prompt).await {
            Ok(settled) => settled,
            Err(_) => {
                eprintln!(
                    "mcp-proxy: approval prompt timed out after {}s; defaulting to deny",
                    deadline.as_secs()
                );
                return Some(ApprovalVerdict::Deny);
            }
        },
        None => prompt.await,
    };

    match settled {
        Ok(Ok(raw)) => Some(parse_verdict_input(&raw, session_ok, timed_ok, ttl_secs)),
        Ok(Err(error)) => {
            eprintln!("mcp-proxy: approval prompt failed ({error:#}); defaulting to deny");
            None
        }
        Err(_) => {
            eprintln!("mcp-proxy: approval prompt task panicked; defaulting to deny");
            None
        }
    }
}

fn parse_verdict_input(
    raw: &str,
    session_ok: bool,
    timed_ok: bool,
    ttl_secs: u64,
) -> ApprovalVerdict {
    let trimmed = raw.trim().to_ascii_lowercase();
    match trimmed.as_str() {
        "y" | "yes" => ApprovalVerdict::ApproveOnce,
        "s" | "session" if session_ok => ApprovalVerdict::ApproveForSession,
        "t" | "timed" | "time" if timed_ok => {
            let expires_at = Utc::now() + chrono::Duration::seconds(ttl_secs as i64);
            ApprovalVerdict::ApproveUntil { expires_at }
        }
        _ => ApprovalVerdict::Deny,
    }
}

fn prompt_approval_verdict_sync(brief: &str) -> anyhow::Result<String> {
    use std::io::{Read, Write};

    #[cfg(unix)]
    {
        if let Ok(mut tty) = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open("/dev/tty")
        {
            tty.write_all(brief.as_bytes())?;
            tty.write_all(b"\n> ")?;
            tty.flush()?;
            let mut buf = String::new();
            // Read one line.
            let mut byte = [0u8; 1];
            while tty.read(&mut byte)? == 1 {
                if byte[0] == b'\n' {
                    break;
                }
                if byte[0] != b'\r' {
                    buf.push(byte[0] as char);
                }
            }
            return Ok(buf);
        }
    }

    let mut stderr = std::io::stderr();
    stderr.write_all(brief.as_bytes())?;
    stderr.write_all(b"\n> ")?;
    stderr.flush()?;
    let mut buf = String::new();
    std::io::stdin().read_line(&mut buf)?;
    Ok(buf)
}

/// Refuses every action that reaches approval.
#[derive(Debug, Clone, Copy, Default)]
pub struct DenyAllApprovalEngine;

impl ApprovalEngine for DenyAllApprovalEngine {
    fn request<'a>(&'a self, _request: ApprovalRequest<'a>) -> ApprovalFuture<'a> {
        Box::pin(async { ApprovalOutcome::Denied })
    }

    fn name(&self) -> &'static str {
        "deny_all"
    }
}

/// Approves every action that reaches approval with [`ApprovalVerdict::ApproveOnce`].
///
/// **Not a security posture.** Tests and observation-mode rollouts only.
#[derive(Debug, Clone, Copy, Default)]
pub struct AllowAllApprovalEngine;

impl ApprovalEngine for AllowAllApprovalEngine {
    fn request<'a>(&'a self, _request: ApprovalRequest<'a>) -> ApprovalFuture<'a> {
        Box::pin(async { ApprovalOutcome::approve_once() })
    }

    fn name(&self) -> &'static str {
        "allow_all"
    }
}

/// Reports that no approver could be reached.
#[derive(Debug, Clone, Copy, Default)]
pub struct UnavailableApprovalEngine;

impl ApprovalEngine for UnavailableApprovalEngine {
    fn request<'a>(&'a self, _request: ApprovalRequest<'a>) -> ApprovalFuture<'a> {
        Box::pin(async { ApprovalOutcome::Unavailable })
    }

    fn name(&self) -> &'static str {
        "unavailable"
    }
}

/// Bounds any approval engine with a deadline.
pub struct TimeoutApprovalEngine {
    inner: Arc<dyn ApprovalEngine>,
    deadline: Duration,
}

impl TimeoutApprovalEngine {
    pub fn new(inner: Arc<dyn ApprovalEngine>, deadline: Duration) -> Self {
        Self { inner, deadline }
    }

    pub fn with_default_deadline(inner: Arc<dyn ApprovalEngine>) -> Self {
        Self::new(inner, crate::risk::DEFAULT_APPROVAL_TIMEOUT)
    }

    pub fn deadline(&self) -> Duration {
        self.deadline
    }
}

impl ApprovalEngine for TimeoutApprovalEngine {
    fn request<'a>(&'a self, request: ApprovalRequest<'a>) -> ApprovalFuture<'a> {
        Box::pin(async move {
            match tokio::time::timeout(self.deadline, self.inner.request(request)).await {
                Ok(outcome) => outcome,
                Err(_) => {
                    eprintln!(
                        "mcp-proxy: approval via {} timed out after {}s; denying",
                        self.inner.name(),
                        self.deadline.as_secs()
                    );
                    ApprovalOutcome::TimedOut
                }
            }
        })
    }

    fn name(&self) -> &'static str {
        self.inner.name()
    }
}

/// Applies an approved verdict to the grant store (session / timed reuse).
pub fn mint_grants_for_verdict(
    store: &ApprovalGrantStore,
    context: &ApprovalContext,
    verdict: &ApprovalVerdict,
) -> Option<ApprovalGrant> {
    match verdict {
        ApprovalVerdict::ApproveOnce => {
            // One-shot in-band approval does not mint a reusable grant. Out-of-band
            // callers that need a redeemable token should call `issue_once` explicitly.
            None
        }
        ApprovalVerdict::Deny => None,
        ApprovalVerdict::ApproveForSession => {
            if !context.session_approval_eligible {
                return None;
            }
            store
                .issue_session(
                    &context.request_id,
                    context.binding.clone(),
                    DEFAULT_SESSION_TTL,
                )
                .ok()
        }
        ApprovalVerdict::ApproveUntil { expires_at } => {
            if !context.timed_approval_eligible {
                return None;
            }
            Some(store.issue_until(&context.request_id, context.binding.clone(), *expires_at))
        }
    }
}

/// Formats an expiry for audit detail strings.
pub fn format_expiry(expires_at: DateTime<Utc>) -> String {
    expires_at.to_rfc3339()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::action::{Arguments, Runtime, SourceRef};

    fn action() -> AgentAction {
        AgentAction::builder(
            "execute_bash",
            Arguments::from_name_and_arguments("execute_bash", &serde_json::json!({"cmd": "ls"})),
        )
        .source(SourceRef::new(Runtime::MCP_STDIO, "test"))
        .build_unvalidated()
    }

    fn context_for(action: &AgentAction) -> ApprovalContext {
        ApprovalContext::build(action, action.canonical_params_json(), 90, None, &[], &[])
    }

    fn request<'a>(action: &'a AgentAction, context: &'a ApprovalContext) -> ApprovalRequest<'a> {
        ApprovalRequest {
            action,
            risk_score: 90,
            payload: action.canonical_params_json(),
            justification: "test",
            context,
        }
    }

    #[tokio::test]
    async fn deny_all_refuses() {
        let action = action();
        let context = context_for(&action);
        assert_eq!(
            DenyAllApprovalEngine
                .request(request(&action, &context))
                .await,
            ApprovalOutcome::Denied
        );
    }

    #[tokio::test]
    async fn allow_all_approves_once() {
        let action = action();
        let context = context_for(&action);
        assert_eq!(
            AllowAllApprovalEngine
                .request(request(&action, &context))
                .await,
            ApprovalOutcome::approve_once()
        );
    }

    #[test]
    fn unavailability_denies_when_configured_closed() {
        for outcome in [ApprovalOutcome::Unavailable, ApprovalOutcome::TimedOut] {
            assert_eq!(outcome.as_decision(FailureMode::FailClosed), Decision::Deny);
        }
    }

    #[test]
    fn an_absent_approver_never_produces_an_allow() {
        for outcome in [ApprovalOutcome::Unavailable, ApprovalOutcome::TimedOut] {
            for mode in [
                FailureMode::FailOpen,
                FailureMode::DegradeSafely,
                FailureMode::FailClosed,
            ] {
                let decision = outcome.as_decision(mode);
                assert!(
                    decision.stops_execution(),
                    "{outcome:?} under {mode} must not allow the action"
                );
                assert!(!outcome.is_judgment());
            }
        }
    }

    #[test]
    fn a_judgment_is_independent_of_the_failure_mode() {
        for mode in [
            FailureMode::FailOpen,
            FailureMode::DegradeSafely,
            FailureMode::FailClosed,
        ] {
            assert_eq!(ApprovalOutcome::Denied.as_decision(mode), Decision::Deny);
            assert_eq!(
                ApprovalOutcome::approve_once().as_decision(mode),
                Decision::Allow
            );
        }

        assert!(ApprovalOutcome::approve_once().is_judgment());
        assert!(ApprovalOutcome::Denied.is_judgment());
    }

    #[tokio::test]
    async fn a_slow_approver_times_out_rather_than_hanging() {
        struct NeverAnswers;

        impl ApprovalEngine for NeverAnswers {
            fn request<'a>(&'a self, _request: ApprovalRequest<'a>) -> ApprovalFuture<'a> {
                Box::pin(async {
                    std::future::pending::<()>().await;
                    ApprovalOutcome::approve_once()
                })
            }

            fn name(&self) -> &'static str {
                "never_answers"
            }
        }

        let engine = TimeoutApprovalEngine::new(Arc::new(NeverAnswers), Duration::from_millis(20));
        let action = action();
        let context = context_for(&action);

        assert_eq!(
            engine.request(request(&action, &context)).await,
            ApprovalOutcome::TimedOut
        );
        assert_eq!(engine.deadline(), Duration::from_millis(20));
    }

    #[tokio::test]
    async fn a_prompt_answered_in_time_passes_through_the_timeout_wrapper() {
        let engine =
            TimeoutApprovalEngine::new(Arc::new(AllowAllApprovalEngine), Duration::from_secs(30));
        let action = action();
        let context = context_for(&action);

        assert_eq!(
            engine.request(request(&action, &context)).await,
            ApprovalOutcome::approve_once()
        );
    }

    #[tokio::test]
    async fn the_unavailable_engine_reports_unavailability() {
        let action = action();
        let context = context_for(&action);
        assert_eq!(
            UnavailableApprovalEngine
                .request(request(&action, &context))
                .await,
            ApprovalOutcome::Unavailable
        );
    }

    #[test]
    fn engines_are_object_safe() {
        let engines: Vec<Box<dyn ApprovalEngine>> = vec![
            Box::new(TerminalApprovalEngine),
            Box::new(DenyAllApprovalEngine),
            Box::new(AllowAllApprovalEngine),
            Box::new(UnavailableApprovalEngine),
            Box::new(TimeoutApprovalEngine::with_default_deadline(Arc::new(
                DenyAllApprovalEngine,
            ))),
        ];

        let names: Vec<_> = engines.iter().map(|engine| engine.name()).collect();
        assert_eq!(
            names,
            [
                "terminal",
                "deny_all",
                "allow_all",
                "unavailable",
                "deny_all"
            ]
        );
    }

    #[test]
    fn parse_verdict_respects_eligibility() {
        assert_eq!(
            parse_verdict_input("s", false, false, 60),
            ApprovalVerdict::Deny
        );
        assert_eq!(
            parse_verdict_input("s", true, false, 60),
            ApprovalVerdict::ApproveForSession
        );
        match parse_verdict_input("t", false, true, 120) {
            ApprovalVerdict::ApproveUntil { .. } => {}
            other => panic!("expected ApproveUntil, got {other:?}"),
        }
    }
}
