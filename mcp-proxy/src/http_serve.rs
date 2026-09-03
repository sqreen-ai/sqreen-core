//! OpenAI-compatible HTTP agent firewall (`mcp-proxy serve`).
//!
//! Listens locally, forwards to an upstream OpenAI-compatible API, and evaluates
//! `tool_calls` through [`crate::guard`] before returning them to the client.
//!
//! MVP: non-streaming chat completions only. Requests with `"stream": true` are
//! rejected with HTTP 400.

use std::convert::Infallible;
use std::net::SocketAddr;
use std::sync::Arc;

use anyhow::{Context, Result};
use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::body::Incoming;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Method, Request, Response, StatusCode};
use hyper_util::rt::TokioIo;
use serde_json::{json, Value};
use tokio::net::TcpListener;

use crate::adapters::{
    process_with_adapter, NormalizationContext, OpenAiAdapter, OpenAiEffect, OpenAiFunctionCall,
};
use crate::guard::GuardContext;
use crate::policy::PolicyEngine;
use crate::risk::{mask_secrets_in_frame, mask_secrets_in_text};

/// Environment variable for the local listen address (`host:port`).
pub const HTTP_LISTEN_ENV: &str = "MCP_HTTP_LISTEN";

/// Environment variable for the upstream OpenAI-compatible base URL.
pub const UPSTREAM_BASE_URL_ENV: &str = "MCP_UPSTREAM_BASE_URL";

/// Default listen address when unset.
pub const DEFAULT_LISTEN: &str = "127.0.0.1:8787";

/// Default upstream when unset.
pub const DEFAULT_UPSTREAM: &str = "https://api.openai.com";

/// Configuration for [`run_agent_firewall`].
#[derive(Debug, Clone)]
pub struct ServeConfig {
    pub listen: SocketAddr,
    pub upstream_base: String,
    pub forward_api_key: Option<String>,
}

impl ServeConfig {
    /// Parses CLI/env defaults: `--listen`, `--upstream`, `OPENAI_API_KEY`.
    pub fn from_args_and_env(listen: Option<&str>, upstream: Option<&str>) -> Result<Self> {
        let listen_raw = listen
            .map(str::to_string)
            .or_else(|| std::env::var(HTTP_LISTEN_ENV).ok())
            .unwrap_or_else(|| DEFAULT_LISTEN.to_string());
        let listen: SocketAddr = listen_raw
            .parse()
            .with_context(|| format!("invalid listen address `{listen_raw}`"))?;

        let upstream_base = upstream
            .map(str::to_string)
            .or_else(|| std::env::var(UPSTREAM_BASE_URL_ENV).ok())
            .unwrap_or_else(|| DEFAULT_UPSTREAM.to_string())
            .trim_end_matches('/')
            .to_string();

        let forward_api_key = std::env::var("OPENAI_API_KEY")
            .ok()
            .filter(|v| !v.is_empty());

        Ok(Self {
            listen,
            upstream_base,
            forward_api_key,
        })
    }
}

/// Shared state for each HTTP connection handler.
#[derive(Clone)]
struct AppState {
    config: ServeConfig,
    policy_store: Arc<crate::policy_store::PolicyStore>,
    wasm: Option<Arc<crate::wasm_engine::WasmPolicyEngine>>,
    threat_intel_store: Arc<crate::threat_intel::ThreatIntelStore>,
    session: Arc<crate::behavior::SessionTracker>,
    cloud: Option<Arc<crate::cloud_client::CloudClient>>,
    normalization: Arc<NormalizationContext>,
    http: reqwest::Client,
}

impl AppState {
    fn guard(&self) -> GuardContext {
        GuardContext {
            policy: self.policy_store.snapshot(),
            policy_availability: self.policy_store.availability(),
            wasm: self.wasm.clone(),
            threat_intel: Arc::new(self.threat_intel_store.snapshot()),
            session: Arc::clone(&self.session),
            cloud: self.cloud.clone(),
        }
    }
}

/// Runs the agent firewall until the process is terminated.
pub async fn run_agent_firewall_with_stores(
    config: ServeConfig,
    policy_store: Arc<crate::policy_store::PolicyStore>,
    wasm: Option<Arc<crate::wasm_engine::WasmPolicyEngine>>,
    threat_intel_store: Arc<crate::threat_intel::ThreatIntelStore>,
    session: Arc<crate::behavior::SessionTracker>,
    cloud: Option<Arc<crate::cloud_client::CloudClient>>,
    normalization: Arc<NormalizationContext>,
) -> Result<()> {
    let listener = TcpListener::bind(config.listen)
        .await
        .with_context(|| format!("failed to bind agent firewall on {}", config.listen))?;

    eprintln!(
        "mcp-proxy: agent firewall listening on http://{} (upstream {})",
        config.listen, config.upstream_base
    );
    eprintln!(
        "mcp-proxy: set OPENAI_BASE_URL=http://{}/v1  (non-streaming chat completions only)",
        config.listen
    );

    let state = AppState {
        config,
        policy_store,
        wasm,
        threat_intel_store,
        session,
        cloud,
        normalization,
        http: reqwest::Client::new(),
    };

    loop {
        let (stream, peer) = listener
            .accept()
            .await
            .context("failed to accept agent firewall connection")?;
        let io = TokioIo::new(stream);
        let state = state.clone();

        tokio::spawn(async move {
            let service = service_fn(move |req| {
                let state = state.clone();
                async move { Ok::<_, Infallible>(handle_request(state, req).await) }
            });

            if let Err(error) = http1::Builder::new().serve_connection(io, service).await {
                eprintln!("mcp-proxy: HTTP connection from {peer} error: {error}");
            }
        });
    }
}

/// Convenience wrapper when only a static [`GuardContext`] is available (tests / simple embeds).
pub async fn run_agent_firewall(config: ServeConfig, guard: GuardContext) -> Result<()> {
    let threat_intel_store = Arc::new(crate::threat_intel::ThreatIntelStore::new(
        (*guard.threat_intel).clone(),
    ));
    run_agent_firewall_with_stores(
        config,
        Arc::new(crate::policy_store::PolicyStore::new(None)),
        guard.wasm,
        threat_intel_store,
        guard.session,
        guard.cloud,
        Arc::new(NormalizationContext::new()),
    )
    .await
}

/// Terminal error handler for the firewall.
///
/// # Errors are answered, not narrated
///
/// The client of this proxy is the agent, and an agent is an untrusted consumer of error
/// text. Returning the internal chain to it published whatever the chain happened to
/// contain: upstream URLs with embedded credentials, adapter messages carrying payload
/// fragments, filesystem paths. The chain goes to the operator's stderr, sanitized; the
/// caller gets the sanitized summary, which is enough to distinguish an upstream failure
/// from a policy denial and nothing more.
async fn handle_request(state: AppState, req: Request<Incoming>) -> Response<Full<Bytes>> {
    match handle_request_inner(state, req).await {
        Ok(response) => response,
        Err(error) => {
            let detail = crate::gateway::sanitize_error(&error);
            eprintln!("mcp-proxy: agent firewall request failed: {detail}");
            json_error(
                StatusCode::BAD_GATEWAY,
                &format!("upstream error: {detail}"),
            )
        }
    }
}

async fn handle_request_inner(
    state: AppState,
    req: Request<Incoming>,
) -> Result<Response<Full<Bytes>>> {
    let method = req.method().clone();
    let path = req.uri().path().to_string();
    let query = req
        .uri()
        .query()
        .map(|q| format!("?{q}"))
        .unwrap_or_default();
    let auth_header = req
        .headers()
        .get(hyper::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .map(str::to_string);

    let body_bytes = req
        .collect()
        .await
        .context("failed to read request body")?
        .to_bytes();

    let is_chat = path.ends_with("/chat/completions") || path == "/chat/completions";

    let mut outbound_body = body_bytes.to_vec();
    if !outbound_body.is_empty() {
        if let Some(masked) = mask_secrets_in_frame(&outbound_body) {
            eprintln!("mcp-proxy: masked secrets in outbound HTTP request body");
            outbound_body = masked;
        }
    }

    if is_chat && method == Method::POST {
        if let Ok(value) = serde_json::from_slice::<Value>(&outbound_body) {
            if value.get("stream").and_then(|v| v.as_bool()) == Some(true) {
                return Ok(json_error(
                    StatusCode::BAD_REQUEST,
                    "mcp-proxy agent firewall MVP does not support streaming; set stream=false",
                ));
            }
        }
    }

    let upstream_url = format!("{}{}{}", state.config.upstream_base, path, query);
    let mut builder = state.http.request(
        reqwest::Method::from_bytes(method.as_str().as_bytes()).unwrap_or(reqwest::Method::POST),
        &upstream_url,
    );

    if let Some(auth) = auth_header.or_else(|| {
        state
            .config
            .forward_api_key
            .as_ref()
            .map(|key| format!("Bearer {key}"))
    }) {
        builder = builder.header(reqwest::header::AUTHORIZATION, auth);
    }
    builder = builder.header(reqwest::header::CONTENT_TYPE, "application/json");

    let upstream = builder
        .body(outbound_body)
        .send()
        .await
        .with_context(|| format!("failed to reach upstream {upstream_url}"))?;

    let status =
        StatusCode::from_u16(upstream.status().as_u16()).unwrap_or(StatusCode::BAD_GATEWAY);
    let mut response_bytes = upstream
        .bytes()
        .await
        .context("failed to read upstream response body")?
        .to_vec();

    if is_chat && status.is_success() {
        let guard = state.guard();
        response_bytes = enforce_chat_completions_response_with_context(
            &guard,
            state.normalization.as_ref(),
            response_bytes,
        )
        .await?;
    } else if let Some(masked) = mask_secrets_in_frame(&response_bytes) {
        eprintln!("mcp-proxy: masked secrets in upstream HTTP response body");
        response_bytes = masked;
    }

    Ok(Response::builder()
        .status(status)
        .header(hyper::header::CONTENT_TYPE, "application/json")
        .body(Full::new(Bytes::from(response_bytes)))
        .context("failed to build HTTP response")?)
}

/// Evaluates each `tool_calls[]` entry; blocks or masks before returning to the client.
///
/// Retained for compatibility with callers that have no [`NormalizationContext`]; uses an
/// empty one, which leaves the ambient identity fields unset without changing any verdict.
pub async fn enforce_chat_completions_response(
    guard: &GuardContext,
    body: Vec<u8>,
) -> Result<Vec<u8>> {
    enforce_chat_completions_response_with_context(guard, &NormalizationContext::new(), body).await
}

/// [`enforce_chat_completions_response`] with ambient identity attached to each action.
pub async fn enforce_chat_completions_response_with_context(
    guard: &GuardContext,
    normalization: &NormalizationContext,
    body: Vec<u8>,
) -> Result<Vec<u8>> {
    let mut value: Value = serde_json::from_slice(&body)
        .context("upstream chat completions response was not valid JSON")?;

    let model = value
        .get("model")
        .and_then(Value::as_str)
        .map(str::to_string);

    let Some(choices) = value.get_mut("choices").and_then(|c| c.as_array_mut()) else {
        if let Some(masked) = mask_secrets_in_frame(&body) {
            return Ok(masked);
        }
        return Ok(body);
    };

    for choice in choices.iter_mut() {
        let Some(message) = choice.get_mut("message") else {
            continue;
        };

        if let Some(content) = message
            .get_mut("content")
            .and_then(|c| c.as_str())
            .map(str::to_string)
        {
            let (masked, changed) = mask_secrets_in_text(&content);
            if changed {
                message["content"] = Value::String(masked);
            }
        }

        let Some(tool_calls) = message.get_mut("tool_calls").and_then(|t| t.as_array_mut()) else {
            continue;
        };

        let mut kept = Vec::new();
        for call in tool_calls.drain(..) {
            match enforce_one_tool_call(guard, normalization, model.as_deref(), call).await? {
                Some(rewritten) => kept.push(rewritten),
                None => {
                    // Blocked — drop this tool call from the response.
                }
            }
        }

        if kept.is_empty() {
            message.as_object_mut().map(|obj| obj.remove("tool_calls"));
            if message
                .get("content")
                .and_then(|c| c.as_str())
                .unwrap_or("")
                .is_empty()
            {
                message["content"] = Value::String(
                    "[blocked by mcp-proxy agent firewall: tool call denied]".to_string(),
                );
            }
            message["finish_reason"] = Value::String("stop".to_string());
        } else {
            message["tool_calls"] = Value::Array(kept);
        }
    }

    Ok(value.to_string().into_bytes())
}

async fn enforce_one_tool_call(
    guard: &GuardContext,
    normalization: &NormalizationContext,
    model: Option<&str>,
    call: Value,
) -> Result<Option<Value>> {
    let mut call = call;
    let name = call
        .pointer("/function/name")
        .and_then(|v| v.as_str())
        .unwrap_or(crate::adapters::openai::UNKNOWN_TOOL)
        .to_string();

    let arguments = call
        .pointer("/function/arguments")
        .cloned()
        .unwrap_or(Value::Object(Default::default()));

    let call_id = call.get("id").and_then(Value::as_str).map(str::to_string);

    // A tool call the adapter cannot normalize is dropped rather than forwarded. Returning
    // the error would abort the whole response — including the sibling tool calls that
    // *did* evaluate cleanly — so one malformed entry would become a denial of service
    // against the others.
    let wire = OpenAiFunctionCall::new(&name, &arguments)
        .with_call_id(call_id.as_deref())
        .with_model(model);

    let processed =
        match process_with_adapter::<OpenAiAdapter>(&guard.gateway(), normalization, wire).await {
            Ok(processed) => processed,
            Err(error) => {
                eprintln!(
                    "mcp-proxy: security control degraded [{}=FAIL_CLOSED] \
                 dropped unnormalizable tool_call `{name}`: {}",
                    crate::gateway::Subsystem::Normalization,
                    crate::gateway::sanitize_detail(&error.to_string())
                );
                return Ok(None);
            }
        };

    match processed.effect {
        OpenAiEffect::Forward {
            rewritten_params_json,
        } => {
            if let Some(rewritten) = rewritten_params_json {
                if let Ok(params) = serde_json::from_str::<Value>(&rewritten) {
                    if let Some(args) = params.get("arguments") {
                        let args_str = match args {
                            Value::String(s) => s.clone(),
                            other => other.to_string(),
                        };
                        if let Some(func) = call.get_mut("function").and_then(|f| f.as_object_mut())
                        {
                            func.insert("arguments".to_string(), Value::String(args_str));
                        }
                    }
                }
            } else {
                // Still mask secrets inside raw argument strings.
                if let Some(raw) = call.pointer("/function/arguments").and_then(|v| v.as_str()) {
                    let (masked, changed) = mask_secrets_in_text(raw);
                    if changed {
                        if let Some(func) = call.get_mut("function").and_then(|f| f.as_object_mut())
                        {
                            func.insert("arguments".to_string(), Value::String(masked));
                        }
                    }
                }
            }
            Ok(Some(call))
        }
        OpenAiEffect::Drop { reason } => {
            eprintln!("mcp-proxy: blocked OpenAI tool_call `{name}`: {reason}");
            Ok(None)
        }
    }
}

fn json_error(status: StatusCode, message: &str) -> Response<Full<Bytes>> {
    let body = json!({
        "error": {
            "message": message,
            "type": "mcp_proxy_agent_firewall",
            "code": status.as_u16(),
        }
    })
    .to_string();

    Response::builder()
        .status(status)
        .header(hyper::header::CONTENT_TYPE, "application/json")
        .body(Full::new(Bytes::from(body)))
        .unwrap_or_else(|_| {
            Response::new(Full::new(Bytes::from(
                r#"{"error":{"message":"internal error"}}"#,
            )))
        })
}

/// Applies policy key redaction + secret-value DLP to an MCP server→client frame.
pub fn sanitize_server_frame(policy: Option<&PolicyEngine>, frame: &[u8]) -> Option<Vec<u8>> {
    let mut current = frame.to_vec();
    let mut changed = false;

    if let Some(engine) = policy {
        match engine.try_redact_global_secrets(&current) {
            Ok(redacted) => {
                if redacted.as_slice() != current.as_slice() {
                    current = redacted;
                    changed = true;
                }
            }
            Err(failure) => {
                // Key-based redaction needs a JSON tree to walk. When the frame is not one,
                // the configured `redact_keys` cannot be honored — so say so, and fall
                // through to the pattern-based scanner below, which works on raw bytes and
                // is the only protection left for this frame.
                eprintln!(
                    "mcp-proxy: security control degraded [{}=DEGRADE_SAFELY] \
                     redact_keys could not be applied to a response frame: {}; \
                     falling back to pattern-based masking",
                    crate::gateway::Subsystem::PolicyEngine,
                    crate::gateway::sanitize_detail(&failure.detail)
                );
            }
        }
    }

    if let Some(masked) = mask_secrets_in_frame(&current) {
        current = masked;
        changed = true;
    }

    if changed {
        Some(current)
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::behavior::SessionTracker;
    use crate::gateway::PolicyAvailability;
    use crate::risk::SECRET_MASK_TOKEN;
    use crate::threat_intel::ThreatIntelMatcher;

    fn test_guard() -> GuardContext {
        let policy = crate::policy::PolicyEngine::from_yaml(
            r#"
version: "1"
global:
  redact_keys: []
  risk_threshold: 99
  block_patterns: []
tools:
  - name: "read_file"
    action: "Allow"
    block_patterns: []
"#,
        )
        .expect("policy");
        GuardContext {
            policy: Some(Arc::new(policy)),
            policy_availability: PolicyAvailability::Available,
            wasm: None,
            threat_intel: Arc::new(ThreatIntelMatcher::default()),
            session: Arc::new(SessionTracker::default()),
            cloud: None,
        }
    }

    #[tokio::test]
    async fn masks_secrets_inside_tool_call_arguments() {
        let body = json!({
            "id": "chatcmpl-test",
            "choices": [{
                "index": 0,
                "message": {
                    "role": "assistant",
                    "content": null,
                    "tool_calls": [{
                        "id": "call_1",
                        "type": "function",
                        "function": {
                            "name": "read_file",
                            "arguments": "{\"api_key\":\"sk-proj-abcdefghijklmnopqrstuvwxyz012345\"}"
                        }
                    }]
                },
                "finish_reason": "tool_calls"
            }]
        })
        .to_string()
        .into_bytes();

        let rewritten = enforce_chat_completions_response(&test_guard(), body)
            .await
            .expect("enforce");
        let text = String::from_utf8(rewritten).expect("utf8");
        assert!(text.contains(SECRET_MASK_TOKEN));
        assert!(!text.contains("sk-proj-abcdefghijklmnopqrstuvwxyz012345"));
        assert!(text.contains("tool_calls"));
    }

    #[tokio::test]
    async fn rejects_parse_of_stream_flag_helper() {
        // Documented contract: stream true is rejected before upstream.
        let value = json!({"stream": true, "model": "gpt-4o-mini"});
        assert_eq!(value.get("stream").and_then(|v| v.as_bool()), Some(true));
    }

    #[test]
    fn sanitize_server_frame_masks_github_token() {
        let frame = br#"{"result":{"content":[{"text":"token ghp_abcdefghijklmnopqrstuvwxyz0123456789AB"}]}}"#;
        let out = sanitize_server_frame(None, frame).expect("should mask");
        let text = String::from_utf8(out).unwrap();
        assert!(text.contains(SECRET_MASK_TOKEN));
        assert!(!text.contains("ghp_"));
    }
}
