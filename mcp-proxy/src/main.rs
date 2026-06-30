//! # mcp-proxy
//!
//! A local-first, transparent stdio proxy for MCP (Model Context Protocol) traffic.
//!
//! ## Architecture
//!
//! ```text
//! Client (IDE) ──stdin/stdout──► mcp-proxy ──stdin/stdout──► MCP server
//!                                    │
//!                                    ├─ peeker (zero-copy classify)
//!                                    ├─ YAML policy engine
//!                                    ├─ Wasm sandbox extension
//!                                    ├─ DLP / risk gate (/dev/tty)
//!                                    └─ optional cloud sync + telemetry
//! ```
//!
//! ## Concurrency and thread safety
//!
//! - Two independent Tokio tasks relay client→server and server→client.
//! - A [`Mutex`] serializes writes to the debug log file across both directions.
//! - Policy engines are immutable after startup (`Arc<PolicyEngine>`); cloud policy refresh
//!   occurs at boot (future: background sync).
//! - Telemetry dispatch uses `tokio::spawn` — **never blocks** the active relay task.
//!
//! ## Fail-closed invariants
//!
//! 1. Policy **Block** returns a JSON-RPC error to the client without forwarding.
//! 2. Risk gate denial returns `-32003` access denied when the operator rejects a call.
//! 3. Risk prompt or cloud failures default to deny or local fallback — never silent allow.
//! 4. Invalid JSON-RPC peek failures still forward (passthrough) to avoid breaking unknown
//!    extensions; policy hooks only run on successfully classified `tools/call` requests.
//!
//! ## Zero-copy lifetime boundaries
//!
//! [`peeker::peek_envelope`] borrows `params` from the in-memory frame buffer. Policy
//! inspection must finish before the frame is rewritten or forwarded. See `peeker.rs`.
//!
//! ## Usage
//!
//! ```text
//! mcp-proxy -- run <command> [args...]
//!
//! # Example
//! mcp-proxy -- run node /path/to/mcp-server.js
//! ```
//!
//! ## Environment
//!
//! - `MCP_PROXY_LOG`: Optional path to the debug log file. Defaults to `mcp-proxy.log`
//!   in the current working directory.
//! - `MCP_POLICY_PATH`: Declarative YAML policy file path.
//! - `MCP_WASM_POLICY`: Optional `.wasm` policy extension module.
//! - `MCP_CONTROL_PLANE_URL` / `MCP_DEVICE_TOKEN`: Optional cloud policy + telemetry sync.

mod peeker;
mod risk;
mod policy;
mod policy_store;
mod wasm_engine;
mod cloud_client;
mod threat_intel;
mod behavior;

use std::env;
use std::path::PathBuf;
use std::process::Stdio;
use std::sync::Arc;

use anyhow::{bail, Context, Result};
use behavior::SessionTracker;
use cloud_client::{CloudClient, TelemetryRecord, UserDecision};
use peeker::{format_peek_summary, peek_envelope, McpMessageType};
use policy::{
    access_denied_response, blocked_response,
    rewrite_tools_call_frame, PolicyEngine, PolicyVerdict,
};
use policy_store::{load_policy_engine, PolicyStore};
use risk::{
    analyze_params, apply_security_layers, calculate_risk_score, prompt_user_confirmation,
    resolve_risk_threshold,
};
use threat_intel::{load_threat_intel_matcher, ThreatIntelMatcher, ThreatIntelStore};
use serde_json::Value;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::process::{Child, Command};
use tokio::sync::Mutex;
use tokio::task::JoinHandle;
use wasm_engine::{parse_tool_name, WasmDecision, WasmPolicyEngine, WASM_POLICY_ENV};

/// Default filename for the local debug trace log.
const DEFAULT_LOG_FILE: &str = "mcp-proxy.log";

/// Environment variable used to override the debug log path.
const LOG_PATH_ENV: &str = "MCP_PROXY_LOG";

/// Parsed CLI invocation describing the downstream MCP server command.
#[derive(Debug, Clone, PartialEq, Eq)]
struct RunCommand {
    program: String,
    args: Vec<String>,
}

/// Thread-safe append-only debug logger shared by both relay tasks.
struct DebugLogger {
    file: Mutex<tokio::fs::File>,
}

impl DebugLogger {
    /// Opens (or creates) the debug log file for append-only writes.
    async fn open(path: PathBuf) -> Result<Self> {
        let file = tokio::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&path)
            .await
            .with_context(|| format!("failed to open debug log file at {}", path.display()))?;

        Ok(Self {
            file: Mutex::new(file),
        })
    }

    /// Writes a direction-tagged UTF-8 frame to the debug log.
    async fn log_bytes(&self, direction: &str, frame: &[u8]) -> Result<()> {
        let mut file = self.file.lock().await;
        file.write_all(format!("[{direction}] ").as_bytes())
            .await
            .context("failed to write debug log prefix")?;
        file.write_all(frame)
            .await
            .context("failed to write debug log frame")?;
        file.write_all(b"\n")
            .await
            .context("failed to write debug log newline")?;
        file.flush().await.context("failed to flush debug log")?;
        Ok(())
    }

    /// Writes a structured envelope inspection summary to the debug log.
    async fn log_inspection(&self, direction: &str, summary: &str) -> Result<()> {
        let mut file = self.file.lock().await;
        file.write_all(format!("[{direction}] {summary}\n").as_bytes())
            .await
            .context("failed to write envelope inspection log entry")?;
        file.flush().await.context("failed to flush debug log")?;
        Ok(())
    }
}

/// Strips trailing `\n` / `\r` delimiters from a `read_until` buffer in place.
fn strip_line_delimiter(buffer: &mut Vec<u8>) {
    while matches!(buffer.last(), Some(b'\n') | Some(b'\r')) {
        buffer.pop();
    }
}

/// Forwards a raw frame slice to a stream without converting to `String`.
async fn forward_frame(
    writer: &mut (impl AsyncWriteExt + Unpin),
    frame: &[u8],
) -> Result<()> {
    writer
        .write_all(frame)
        .await
        .context("failed to write frame body")?;
    writer
        .write_all(b"\n")
        .await
        .context("failed to write frame delimiter")?;
    writer.flush().await.context("failed to flush relay stream")?;
    Ok(())
}

/// Snapshot of client-side policy inputs extracted before frame mutation.
struct ClientPolicyInput {
    request_id: Value,
    tools_call_params: String,
}

/// Peeks at a frame, logs classification metadata, and forwards the original bytes.
async fn inspect_and_relay(
    logger: &DebugLogger,
    direction: &str,
    frame: &mut Vec<u8>,
    downstream_writer: &mut (impl AsyncWriteExt + Unpin),
    client_writer: Option<&mut (impl AsyncWriteExt + Unpin)>,
    policy_store: &PolicyStore,
    wasm_policy: Option<&WasmPolicyEngine>,
    cloud_client: Option<&CloudClient>,
    threat_intel_store: &ThreatIntelStore,
    session_tracker: &SessionTracker,
) -> Result<()> {
    logger
        .log_bytes(direction, frame)
        .await
        .context("failed to record relay debug log entry")?;

    let (summary, client_policy_input, peek_failed) = {
        let classification = peek_envelope(frame);
        let summary = classification
            .as_ref()
            .map(format_peek_summary)
            .unwrap_or_else(|error| format!("peek error: {error:#}"));

        let client_policy_input = match (&classification, direction) {
            (
                Ok(McpMessageType::Request {
                    id,
                    method,
                    params: Some(raw_params),
                    ..
                }),
                "Client -> Server",
            ) if method == "tools/call" => Some(ClientPolicyInput {
                request_id: id.clone(),
                tools_call_params: raw_params.get().to_string(),
            }),
            _ => None,
        };

        let _use_fast_path = classification
            .as_ref()
            .map(|value| value.is_fast_path())
            .unwrap_or(false);
        let peek_failed = classification.is_err();

        (summary, client_policy_input, peek_failed)
    };

    logger
        .log_inspection(direction, &summary)
        .await
        .context("failed to record envelope inspection log entry")?;

    if let Some(input) = client_policy_input {
        policy_store
            .refresh_if_stale(cloud_client)
            .await;
        threat_intel_store
            .refresh_if_stale(cloud_client)
            .await;
        let policy = policy_store.snapshot();
        let threat_intel = threat_intel_store.snapshot();

        if let Some(outcome) = apply_yaml_policy(
            policy.as_deref(),
            cloud_client,
            &input,
            frame,
            logger,
            direction,
        )
        .await?
        {
            return finish_policy_outcome(
                outcome,
                downstream_writer,
                client_writer,
            )
            .await;
        }

        if let Some(outcome) =
            apply_wasm_policy(wasm_policy, cloud_client, &input, frame, logger, direction).await?
        {
            return finish_policy_outcome(
                outcome,
                downstream_writer,
                client_writer,
            )
            .await;
        }

        if let Some(outcome) = apply_risk_pipeline(
            policy.as_deref(),
            cloud_client,
            &threat_intel,
            session_tracker,
            &input,
            frame,
            logger,
            direction,
        )
        .await?
        {
            return finish_risk_outcome(outcome, frame, downstream_writer, client_writer).await;
        }
    }

    if direction == "Server -> Client" {
        if let Some(policy) = policy_store.snapshot() {
            if let Some(bytes) = apply_server_policy(Some(policy.as_ref()), frame) {
                forward_frame(downstream_writer, &bytes).await?;
                return Ok(());
            }
        }
    }

    if peek_failed {
        forward_frame(downstream_writer, frame).await?;
        return Ok(());
    }

    forward_frame(downstream_writer, frame).await?;
    Ok(())
}

enum PolicyOutcome {
    Blocked { id: Value, reason: String },
    Forward(Vec<u8>),
}

enum RiskOutcome {
    Denied { id: Value, reason: String },
    Approved,
}

async fn finish_policy_outcome(
    outcome: PolicyOutcome,
    downstream_writer: &mut (impl AsyncWriteExt + Unpin),
    client_writer: Option<&mut (impl AsyncWriteExt + Unpin)>,
) -> Result<()> {
    match outcome {
        PolicyOutcome::Blocked { id, reason } => {
            let response_writer =
                client_writer.context("client writer unavailable for blocked response")?;
            let response = blocked_response(&id, &reason);
            forward_frame(response_writer, &response).await?;
        }
        PolicyOutcome::Forward(bytes) => {
            forward_frame(downstream_writer, &bytes).await?;
        }
    }
    Ok(())
}

async fn finish_risk_outcome(
    outcome: RiskOutcome,
    frame: &mut Vec<u8>,
    downstream_writer: &mut (impl AsyncWriteExt + Unpin),
    client_writer: Option<&mut (impl AsyncWriteExt + Unpin)>,
) -> Result<()> {
    match outcome {
        RiskOutcome::Denied { id, reason } => {
            let response_writer =
                client_writer.context("client writer unavailable for denied response")?;
            let response = access_denied_response(&id, &reason);
            forward_frame(response_writer, &response).await?;
        }
        RiskOutcome::Approved => {
            forward_frame(downstream_writer, frame).await?;
        }
    }
    Ok(())
}

async fn apply_risk_pipeline(
    policy: Option<&PolicyEngine>,
    cloud_client: Option<&CloudClient>,
    threat_intel: &ThreatIntelMatcher,
    session_tracker: &SessionTracker,
    input: &ClientPolicyInput,
    frame: &mut Vec<u8>,
    logger: &DebugLogger,
    direction: &str,
) -> Result<Option<RiskOutcome>> {
    let tool_name = parse_tool_name(&input.tools_call_params)?;
    let ioc_match = threat_intel.matches_payload(&input.tools_call_params);
    let behavioral_anomaly =
        session_tracker.verify_behavioral_chain(&tool_name, &input.tools_call_params);
    let analysis = analyze_params(&tool_name, &input.tools_call_params);
    let security = apply_security_layers(analysis.score, ioc_match, behavioral_anomaly);
    let effective_score = security.effective_score;
    let threshold = resolve_risk_threshold(policy.map(PolicyEngine::risk_threshold));
    let force_gate = security.force_confirmation_gate || effective_score >= threshold;
    let security_marker = security.telemetry_marker;

    if ioc_match {
        logger
            .log_inspection(direction, "threat intel: IOC match in tool payload")
            .await?;
    }
    if behavioral_anomaly {
        logger
            .log_inspection(
                direction,
                "behavior: BEHAVIORAL_CHAIN_ANOMALY (filesystem probes -> network tool)",
            )
            .await?;
    }

    if let Some(sanitized) = analysis.sanitized_params {
        let rewritten = rewrite_tools_call_frame(frame, sanitized.as_bytes())
            .context("failed to rewrite risk-sanitized tools/call frame")?;
        *frame = rewritten;
        logger
            .log_inspection(direction, "risk dlp: masked sensitive segments in params")
            .await?;
        emit_telemetry(
            cloud_client,
            &tool_name,
            effective_score,
            "risk_dlp_mask",
            UserDecision::Skipped,
        );
    }

    logger
        .log_inspection(
            direction,
            &format!(
                "risk score={} effective={} threshold={} tool={tool_name} force_gate={force_gate}",
                analysis.score, effective_score, threshold
            ),
        )
        .await?;

    if !force_gate {
        session_tracker.record(&tool_name);
        return Ok(None);
    }

    logger
        .log_inspection(
            direction,
            &format!("risk gate: awaiting operator confirmation for `{tool_name}`"),
        )
        .await?;

    let preview = std::str::from_utf8(frame).unwrap_or(&input.tools_call_params);
    let approved = prompt_user_confirmation(&tool_name, effective_score, preview).await;
    let pattern = security_marker.unwrap_or("risk_threshold_exceeded");

    session_tracker.record(&tool_name);

    if approved {
        logger
            .log_inspection(direction, "risk gate: operator approved")
            .await?;
        emit_telemetry(
            cloud_client,
            &tool_name,
            effective_score,
            pattern,
            UserDecision::Approved,
        );
        Ok(Some(RiskOutcome::Approved))
    } else {
        logger
            .log_inspection(direction, "risk gate: operator denied")
            .await?;
        emit_telemetry(
            cloud_client,
            &tool_name,
            effective_score,
            pattern,
            UserDecision::Denied,
        );
        Ok(Some(RiskOutcome::Denied {
            id: input.request_id.clone(),
            reason: if behavioral_anomaly {
                "BEHAVIORAL_CHAIN_ANOMALY: operator denied exfiltration-risk tool chain"
                    .to_string()
            } else if ioc_match {
                "THREAT_INTEL_IOC_MATCH: operator denied IOC-tainted tool call".to_string()
            } else {
                "user denied high-risk tool call".to_string()
            },
        }))
    }
}

fn emit_telemetry(
    cloud_client: Option<&CloudClient>,
    tool_name: &str,
    risk_score: u8,
    pattern_matched: &str,
    user_decision: UserDecision,
) {
    let Some(client) = cloud_client else {
        return;
    };

    let record = TelemetryRecord::new(
        client.device_id(),
        tool_name,
        risk_score,
        pattern_matched,
        user_decision,
    );
    client.dispatch_telemetry(record);
}

async fn apply_yaml_policy(
    policy: Option<&PolicyEngine>,
    cloud_client: Option<&CloudClient>,
    input: &ClientPolicyInput,
    frame: &mut Vec<u8>,
    logger: &DebugLogger,
    direction: &str,
) -> Result<Option<PolicyOutcome>> {
    let Some(engine) = policy else {
        return Ok(None);
    };

    let tool_name = parse_tool_name(&input.tools_call_params)?;
    let risk_score = calculate_risk_score(&tool_name, &input.tools_call_params);

    match engine.evaluate_tools_call(&input.tools_call_params) {
        PolicyVerdict::Allow => Ok(None),
        PolicyVerdict::Block { reason } => {
            logger
                .log_inspection(direction, &format!("policy block: {reason}"))
                .await?;
            emit_telemetry(
                cloud_client,
                &tool_name,
                risk_score,
                &reason,
                UserDecision::Denied,
            );
            Ok(Some(PolicyOutcome::Blocked {
                id: input.request_id.clone(),
                reason,
            }))
        }
        PolicyVerdict::Confirm { message } => {
            logger
                .log_inspection(direction, &format!("policy confirm: {message}"))
                .await?;
            eprintln!("mcp-proxy: {message}");
            emit_telemetry(
                cloud_client,
                &tool_name,
                risk_score,
                &message,
                UserDecision::Skipped,
            );
            Ok(None)
        }
        PolicyVerdict::Redact { frame: redacted_params } => {
            let rewritten = rewrite_tools_call_frame(frame, &redacted_params)
                .context("failed to rewrite redacted tools/call frame")?;
            logger
                .log_inspection(direction, "policy redact: applied global redact_keys")
                .await?;
            emit_telemetry(
                cloud_client,
                &tool_name,
                risk_score,
                "global_redact_keys",
                UserDecision::Skipped,
            );
            Ok(Some(PolicyOutcome::Forward(rewritten)))
        }
    }
}

async fn apply_wasm_policy(
    wasm_policy: Option<&WasmPolicyEngine>,
    cloud_client: Option<&CloudClient>,
    input: &ClientPolicyInput,
    frame: &mut Vec<u8>,
    logger: &DebugLogger,
    direction: &str,
) -> Result<Option<PolicyOutcome>> {
    let Some(engine) = wasm_policy else {
        return Ok(None);
    };

    let tool_name = parse_tool_name(&input.tools_call_params)?;
    let risk_score = calculate_risk_score(&tool_name, &input.tools_call_params);
    let decision = engine.evaluate_tool_call(&tool_name, &input.tools_call_params)?;

    match decision {
        WasmDecision::Allow => Ok(None),
        WasmDecision::Block { reason } => {
            logger
                .log_inspection(direction, &format!("wasm block: {reason}"))
                .await?;
            emit_telemetry(
                cloud_client,
                &tool_name,
                risk_score,
                &reason,
                UserDecision::Denied,
            );
            Ok(Some(PolicyOutcome::Blocked {
                id: input.request_id.clone(),
                reason: format!("wasm: {reason}"),
            }))
        }
        WasmDecision::Rewrite { modified_params } => {
            let rewritten = rewrite_tools_call_frame(frame, modified_params.as_bytes())
                .context("failed to rewrite wasm-modified tools/call frame")?;
            logger
                .log_inspection(direction, "wasm rewrite: modified tools/call params")
                .await?;
            emit_telemetry(
                cloud_client,
                &tool_name,
                risk_score,
                "wasm_rewrite",
                UserDecision::Skipped,
            );
            Ok(Some(PolicyOutcome::Forward(rewritten)))
        }
    }
}

fn apply_server_policy(policy: Option<&PolicyEngine>, frame: &mut Vec<u8>) -> Option<Vec<u8>> {
    let engine = policy?;
    let redacted = engine.redact_global_secrets(frame);
    if redacted.as_slice() != frame.as_slice() {
        Some(redacted)
    } else {
        None
    }
}

/// Parses `mcp-proxy -- run <command> [args...]` from process arguments.
fn parse_run_command(argv: &[String]) -> Result<RunCommand> {
    let separator = argv
        .iter()
        .position(|arg| arg == "--")
        .context("missing `--` separator; usage: mcp-proxy -- run <command> [args...]")?;

    let mut tail = argv[separator + 1..].iter();
    match tail.next() {
        Some(keyword) if keyword == "run" => {}
        Some(other) => bail!(
            "expected `run` after `--`, found `{other}`; usage: mcp-proxy -- run <command> [args...]"
        ),
        None => bail!("missing `run` subcommand after `--`"),
    }

    let program = tail
        .next()
        .context("missing downstream command after `run`")?
        .clone();

    let args = tail.cloned().collect();

    Ok(RunCommand { program, args })
}

/// Resolves the debug log destination from the environment or a default file name.
fn resolve_log_path() -> PathBuf {
    env::var(LOG_PATH_ENV)
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from(DEFAULT_LOG_FILE))
}

/// Spawns the downstream MCP server with piped stdin/stdout and inherited stderr.
async fn spawn_downstream(command: &RunCommand) -> Result<Child> {
    Command::new(&command.program)
        .args(&command.args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()
        .with_context(|| {
            format!(
                "failed to spawn downstream MCP server: {} {}",
                command.program,
                command.args.join(" ")
            )
        })
}

/// Relays newline-delimited byte frames from the AI client to the downstream MCP server.
async fn relay_client_to_server(
    logger: Arc<DebugLogger>,
    policy_store: Arc<PolicyStore>,
    wasm_policy: Arc<Option<WasmPolicyEngine>>,
    cloud_client: Arc<Option<CloudClient>>,
    threat_intel_store: Arc<ThreatIntelStore>,
    session_tracker: Arc<SessionTracker>,
    mut child_stdin: tokio::process::ChildStdin,
) -> Result<()> {
    let mut client_reader = BufReader::new(tokio::io::stdin());
    let mut client_writer = tokio::io::stdout();
    let mut frame_buffer = Vec::with_capacity(4096);

    loop {
        frame_buffer.clear();
        let bytes_read = client_reader
            .read_until(b'\n', &mut frame_buffer)
            .await
            .context("failed to read frame from client stdin")?;

        if bytes_read == 0 {
            break;
        }

        strip_line_delimiter(&mut frame_buffer);
        inspect_and_relay(
            &logger,
            "Client -> Server",
            &mut frame_buffer,
            &mut child_stdin,
            Some(&mut client_writer),
            policy_store.as_ref(),
            wasm_policy.as_ref().as_ref(),
            cloud_client.as_ref().as_ref(),
            threat_intel_store.as_ref(),
            session_tracker.as_ref(),
        )
        .await
        .context("failed to relay client-to-server frame")?;
    }

    drop(child_stdin);
    Ok(())
}

/// Relays newline-delimited byte frames from the downstream MCP server to the AI client.
async fn relay_server_to_client(
    logger: Arc<DebugLogger>,
    policy_store: Arc<PolicyStore>,
    threat_intel_store: Arc<ThreatIntelStore>,
    session_tracker: Arc<SessionTracker>,
    child_stdout: tokio::process::ChildStdout,
) -> Result<()> {
    let mut server_reader = BufReader::new(child_stdout);
    let mut client_writer = tokio::io::stdout();
    let mut frame_buffer = Vec::with_capacity(4096);

    loop {
        frame_buffer.clear();
        let bytes_read = server_reader
            .read_until(b'\n', &mut frame_buffer)
            .await
            .context("failed to read frame from downstream server stdout")?;

        if bytes_read == 0 {
            break;
        }

        strip_line_delimiter(&mut frame_buffer);
        inspect_and_relay(
            &logger,
            "Server -> Client",
            &mut frame_buffer,
            &mut client_writer,
            None::<&mut tokio::io::Stdout>,
            policy_store.as_ref(),
            None,
            None,
            threat_intel_store.as_ref(),
            session_tracker.as_ref(),
        )
        .await
        .context("failed to relay server-to-client frame")?;
    }

    Ok(())
}

/// Waits for both relay tasks and returns the first error, if any.
async fn join_relays(
    client_to_server: JoinHandle<Result<()>>,
    server_to_client: JoinHandle<Result<()>>,
) -> Result<()> {
    let (client_result, server_result) = tokio::join!(client_to_server, server_to_client);

    let client_relay = client_result.context("client-to-server relay task panicked")??;
    let server_relay = server_result.context("server-to-client relay task panicked")??;

    let _ = (client_relay, server_relay);
    Ok(())
}

/// Ensures the child process is reaped after relay shutdown.
async fn shutdown_child(mut child: Child) -> Result<()> {
    match child.wait().await {
        Ok(status) if status.success() => Ok(()),
        Ok(status) => bail!("downstream MCP server exited with status: {status}"),
        Err(error) if error.kind() == std::io::ErrorKind::InvalidInput => Ok(()),
        Err(error) => Err(error).context("failed while waiting for downstream MCP server"),
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    let argv: Vec<String> = env::args().collect();
    let run_command = parse_run_command(&argv)?;

    let cloud_client = Arc::new(CloudClient::load_optional());

    let policy_store = Arc::new(PolicyStore::new(
        load_policy_engine(cloud_client.as_ref().as_ref()).await
            .with_context(|| "failed to load mcp-proxy policy")?,
    ));

    let mut wasm_policy = WasmPolicyEngine::load_optional()?;
    if let Some(engine) = wasm_policy.as_mut() {
        engine.set_violation_log_path(resolve_log_path());
        eprintln!(
            "mcp-proxy: loaded wasm policy extension from {}",
            env::var(WASM_POLICY_ENV).unwrap_or_default()
        );
    }

    let wasm_policy = Arc::new(wasm_policy);

    let threat_intel_store = Arc::new(ThreatIntelStore::new(
        load_threat_intel_matcher(cloud_client.as_ref().as_ref()).await,
    ));
    let session_tracker = Arc::new(SessionTracker::default());

    if let Some(engine) = policy_store.snapshot() {
        eprintln!(
            "mcp-proxy: active policy version {} ({} tool rules)",
            engine.version(),
            engine.tool_count()
        );
    } else {
        eprintln!("mcp-proxy: no policy loaded; running in passthrough mode");
    }

    if cloud_client.as_ref().is_some() {
        eprintln!(
            "mcp-proxy: cloud control plane enabled (policy + threat-intel hot reload every 5s)"
        );
    }

    if threat_intel_store.snapshot().indicator_count() > 0 {
        eprintln!(
            "mcp-proxy: loaded {} local threat-intel indicators",
            threat_intel_store.snapshot().indicator_count()
        );
    }

    let logger = Arc::new(DebugLogger::open(resolve_log_path()).await?);
    let mut child = spawn_downstream(&run_command)
        .await
        .with_context(|| {
            format!(
                "failed to start downstream MCP server `{}` — check that the command exists and is executable",
                run_command.program
            )
        })?;

    let child_stdin = child
        .stdin
        .take()
        .context("downstream MCP server stdin was not available for piping")?;
    let child_stdout = child
        .stdout
        .take()
        .context("downstream MCP server stdout was not available for piping")?;

    let logger_for_client = Arc::clone(&logger);
    let policy_for_client = Arc::clone(&policy_store);
    let wasm_for_client = Arc::clone(&wasm_policy);
    let cloud_for_client = Arc::clone(&cloud_client);
    let threat_intel_for_client = Arc::clone(&threat_intel_store);
    let session_tracker_for_client = Arc::clone(&session_tracker);
    let client_to_server = tokio::spawn(async move {
        relay_client_to_server(
            logger_for_client,
            policy_for_client,
            wasm_for_client,
            cloud_for_client,
            threat_intel_for_client,
            session_tracker_for_client,
            child_stdin,
        )
        .await
    });

    let logger_for_server = Arc::clone(&logger);
    let policy_for_server = Arc::clone(&policy_store);
    let threat_intel_for_server = Arc::clone(&threat_intel_store);
    let session_tracker_for_server = Arc::clone(&session_tracker);
    let server_to_client = tokio::spawn(async move {
        relay_server_to_client(
            logger_for_server,
            policy_for_server,
            threat_intel_for_server,
            session_tracker_for_server,
            child_stdout,
        )
        .await
    });

    let relay_result = join_relays(client_to_server, server_to_client).await;

    if let Err(error) = shutdown_child(child).await {
        eprintln!("mcp-proxy: warning during child shutdown: {error:#}");
    }

    relay_result
}

#[cfg(test)]
mod tests {
    use super::parse_run_command;

    #[test]
    fn parses_run_command_after_separator() {
        let argv = vec![
            "mcp-proxy".to_string(),
            "--".to_string(),
            "run".to_string(),
            "node".to_string(),
            "/tmp/server.js".to_string(),
            "--port".to_string(),
            "8080".to_string(),
        ];

        let command = parse_run_command(&argv).expect("command should parse");
        assert_eq!(command.program, "node");
        assert_eq!(
            command.args,
            vec![
                "/tmp/server.js".to_string(),
                "--port".to_string(),
                "8080".to_string(),
            ]
        );
    }

    #[test]
    fn rejects_missing_run_keyword() {
        let argv = vec![
            "mcp-proxy".to_string(),
            "--".to_string(),
            "start".to_string(),
            "node".to_string(),
        ];

        let error = parse_run_command(&argv).expect_err("parser should reject invalid keyword");
        assert!(error.to_string().contains("expected `run`"));
    }
}
