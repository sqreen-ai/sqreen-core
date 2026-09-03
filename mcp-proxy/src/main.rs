//! # mcp-proxy / Sqreen Core
//!
//! Local-first runtime security for MCP stdio and OpenAI-compatible HTTP agent traffic.
//!
//! ## Usage
//!
//! ```text
//! mcp-proxy demo
//! mcp-proxy status
//! mcp-proxy doctor
//! mcp-proxy --help
//! mcp-proxy --version
//! mcp-proxy -- run <command> [args...]
//! mcp-proxy serve [--listen 127.0.0.1:8787] [--upstream https://api.openai.com]
//! ```

use std::env;
use std::path::PathBuf;
use std::process::Stdio;
use std::sync::Arc;

use anyhow::{bail, Context, Result};
use mcp_proxy::adapters::{
    McpAdapter, McpDenyStyle, McpEffect, McpToolsCall, NormalizationContext, RuntimeAdapter,
    ToolCallAdapter,
};
use mcp_proxy::behavior::SessionTracker;
use mcp_proxy::cloud_client::CloudClient;
use mcp_proxy::demo::run_first_block_demo;
use mcp_proxy::gateway::{sanitize_detail, sanitize_error, FailurePolicy, Subsystem};
use mcp_proxy::guard::{evaluate_outcome, GuardContext};
use mcp_proxy::http_serve::{run_agent_firewall_with_stores, sanitize_server_frame, ServeConfig};
use mcp_proxy::peeker::{format_peek_summary, peek_envelope, McpMessageType};
use mcp_proxy::pilot::{parse_pilot_command, run_pilot, PilotCommand};
use mcp_proxy::policy::{access_denied_response, blocked_response, rewrite_tools_call_frame};
use mcp_proxy::policy_store::{load_policy_engine, PolicyStore};
use mcp_proxy::risk::mask_secrets_in_frame;
use mcp_proxy::threat_intel::{load_threat_intel_matcher, ThreatIntelStore};
use mcp_proxy::wasm_engine::{WasmPolicyEngine, WASM_POLICY_ENV};
use serde_json::Value;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::process::{Child, Command};
use tokio::sync::Mutex;
use tokio::task::JoinHandle;

/// Default filename for the local debug trace log.
const DEFAULT_LOG_FILE: &str = "mcp-proxy.log";

/// Environment variable used to override the debug log path.
const LOG_PATH_ENV: &str = "MCP_PROXY_LOG";

const VERSION: &str = env!("CARGO_PKG_VERSION");

fn print_help() {
    println!(
        "\
Sqreen Core (mcp-proxy) {VERSION} — security layer for AI agent tool calls

Usage:
  mcp-proxy demo
  mcp-proxy status
  mcp-proxy doctor
  mcp-proxy integrations
  mcp-proxy support-bundle [--out DIR]
  mcp-proxy enroll --control-plane URL --device-token TOKEN [--device-id ID]
  mcp-proxy update --check
  mcp-proxy -- run <command> [args...]
  mcp-proxy serve [--listen ADDR] [--upstream URL]
  mcp-proxy --help
  mcp-proxy --version

  (alias) sqreen …   same commands as mcp-proxy

Commands:
  demo            Safe first-run demo: allow, block, confirm/approval, explain
  status          Protection ACTIVE/INACTIVE, policy, posture, cloud, integrations
  doctor          PASS/WARN/FAIL health checks with remediation
  integrations    Detect Cursor/Claude wrap, control plane, OPENAI_BASE_URL
  support-bundle  Write a redacted diagnostics folder (inspect before sharing)
  enroll          Write control-plane URL + device token to ~/.config/mcp-proxy/env
  update          Compare local version to signed release channel (--check; no auto-install)
  serve           HTTP proxy for OpenAI-compatible (and Anthropic-shaped) agent tool traffic
  -- run          Wrap an MCP stdio server (used by Cursor / Claude Desktop)

Examples:
  source ~/.config/mcp-proxy/env
  mcp-proxy demo
  mcp-proxy status && mcp-proxy doctor

  mcp-proxy -- run npx -y @modelcontextprotocol/server-filesystem .

  mcp-proxy serve --listen 127.0.0.1:8787 --upstream https://api.openai.com
  export OPENAI_BASE_URL=http://127.0.0.1:8787/v1

Policy:
  MCP_POLICY_PATH   Override policy file (default: ./mcp-policy.yaml or ~/.config/mcp-proxy/mcp-policy.yaml)

Docs:
  docs/QUICKSTART.md · docs/PRIVACY.md · docs/DESIGN_PARTNER.md

Uninstall:
  See README — restore IDE mcp.json from .bak.* and remove ~/.local/bin/mcp-proxy
"
    );
}

/// Parsed CLI invocation describing the downstream MCP server command.
#[derive(Debug, Clone, PartialEq, Eq)]
struct RunCommand {
    program: String,
    args: Vec<String>,
}

/// Top-level CLI mode.
#[derive(Debug, Clone, PartialEq, Eq)]
enum CliMode {
    Help,
    Version,
    Demo,
    Pilot(PilotCommand),
    Run(RunCommand),
    Serve {
        listen: Option<String>,
        upstream: Option<String>,
    },
}

/// Thread-safe append-only debug logger shared by both relay tasks.
struct DebugLogger {
    file: Mutex<tokio::fs::File>,
}

impl DebugLogger {
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

    /// Appends a relay frame, with secret values masked.
    ///
    /// The debug log is on by default and holds every frame in both directions, which
    /// makes it the largest secret sink in the process: a proxy whose purpose is stopping
    /// credential egress was writing every credential it saw to a world-readable file next
    /// to the policy. Frames go through the same DLP scanner that protects payloads, so
    /// the log keeps its diagnostic value — shapes, sizes, tool names, structure — without
    /// keeping the secrets.
    async fn log_bytes(&self, direction: &str, frame: &[u8]) -> Result<()> {
        let masked = mask_secrets_in_frame(frame);
        let body = masked.as_deref().unwrap_or(frame);

        let mut file = self.file.lock().await;
        file.write_all(format!("[{direction}] ").as_bytes())
            .await
            .context("failed to write debug log prefix")?;
        file.write_all(body)
            .await
            .context("failed to write debug log frame")?;
        file.write_all(b"\n")
            .await
            .context("failed to write debug log newline")?;
        file.flush().await.context("failed to flush debug log")?;
        Ok(())
    }

    async fn log_inspection(&self, direction: &str, summary: &str) -> Result<()> {
        let mut file = self.file.lock().await;
        file.write_all(format!("[{direction}] {summary}\n").as_bytes())
            .await
            .context("failed to write envelope inspection log entry")?;
        file.flush().await.context("failed to flush debug log")?;
        Ok(())
    }

    /// Records to the debug log without letting a logging failure reach the caller.
    ///
    /// Diagnostics must not be able to stop traffic. A full disk, a rotated-away file, or
    /// a permissions change used to propagate out of the relay loop and terminate the
    /// connection — turning a logging problem into an agent outage, which is both worse
    /// than the problem and the kind of failure operators resolve by uninstalling the
    /// proxy. Enforcement does not read this log, so losing it costs forensics, not
    /// protection.
    async fn record(&self, direction: &str, frame: &[u8], summary: &str) {
        if let Err(error) = self.log_bytes(direction, frame).await {
            warn_once_per_kind("debug log frame", &error);
        }

        if let Err(error) = self.log_inspection(direction, summary).await {
            warn_once_per_kind("debug log inspection", &error);
        }
    }
}

/// Reports a degraded-diagnostics condition at most once, to avoid a log-failure loop
/// filling stderr at the rate of the traffic it failed to record.
fn warn_once_per_kind(what: &str, error: &anyhow::Error) {
    use std::sync::atomic::{AtomicBool, Ordering};
    static WARNED: AtomicBool = AtomicBool::new(false);

    if !WARNED.swap(true, Ordering::Relaxed) {
        eprintln!(
            "mcp-proxy: {what} unavailable ({}); continuing to enforce without it",
            mcp_proxy::gateway::sanitize_error(error)
        );
    }
}

fn strip_line_delimiter(buffer: &mut Vec<u8>) {
    while matches!(buffer.last(), Some(b'\n') | Some(b'\r')) {
        buffer.pop();
    }
}

async fn forward_frame(writer: &mut (impl AsyncWriteExt + Unpin), frame: &[u8]) -> Result<()> {
    writer
        .write_all(frame)
        .await
        .context("failed to write frame body")?;
    writer
        .write_all(b"\n")
        .await
        .context("failed to write frame delimiter")?;
    writer
        .flush()
        .await
        .context("failed to flush relay stream")?;
    Ok(())
}

struct ClientPolicyInput {
    request_id: Value,
    tools_call_params: String,
}

async fn inspect_and_relay(
    logger: &DebugLogger,
    direction: &str,
    frame: &mut Vec<u8>,
    downstream_writer: &mut (impl AsyncWriteExt + Unpin),
    client_writer: Option<&mut (impl AsyncWriteExt + Unpin)>,
    policy_store: &PolicyStore,
    guard_base: &GuardContext,
    cloud_client: Option<&CloudClient>,
    threat_intel_store: &ThreatIntelStore,
    normalization: &NormalizationContext,
) -> Result<()> {
    let (summary, client_policy_input, peek_error) = {
        let classification = peek_envelope(frame);
        let summary = classification
            .as_ref()
            .map(format_peek_summary)
            .unwrap_or_else(|error| format!("peek error: {}", sanitize_error(error)));

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

        let peek_error = classification.as_ref().err().map(sanitize_error);

        (summary, client_policy_input, peek_error)
    };

    logger.record(direction, frame, &summary).await;

    if let Some(input) = client_policy_input {
        policy_store.refresh_if_stale(cloud_client).await;
        threat_intel_store.refresh_if_stale(cloud_client).await;

        let policy = policy_store.snapshot();
        let threat_intel = Arc::new(threat_intel_store.snapshot());
        let ctx = GuardContext {
            policy: policy.clone(),
            policy_availability: policy_store.availability(),
            wasm: guard_base.wasm.clone(),
            threat_intel,
            session: Arc::clone(&guard_base.session),
            cloud: guard_base.cloud.clone(),
        };

        let request_id = match &input.request_id {
            Value::String(id) => Some(id.clone()),
            Value::Number(id) => Some(id.to_string()),
            _ => None,
        };

        // A `tools/call` the adapter cannot normalize is a malformed request, and the
        // failure matrix says a request nobody can parse is a request nobody can clear.
        // Previously this `?` aborted the relay task, which killed the agent's connection
        // rather than answering the one bad call — safe, but indistinguishable from a
        // crash. Now the caller gets a JSON-RPC error and the session survives.
        let wire =
            McpToolsCall::stdio(&input.tools_call_params).with_request_id(request_id.as_deref());
        let action = match McpAdapter::decode(normalization, wire) {
            Ok(action) => action,
            Err(error) => {
                let detail = sanitize_detail(&error.to_string());
                let mode = FailurePolicy::from_env().mode_for(Subsystem::Normalization);

                eprintln!(
                    "mcp-proxy: security control degraded [{}={mode}] {detail}",
                    Subsystem::Normalization
                );
                logger
                    .record(direction, frame, &format!("normalization failed: {detail}"))
                    .await;

                if mode.permits_allow() {
                    forward_frame(downstream_writer, frame).await?;
                    return Ok(());
                }

                let response_writer = client_writer
                    .context("client writer unavailable for malformed-request response")?;
                let response = blocked_response(
                    &input.request_id,
                    &format!("request could not be normalized for evaluation: {detail}"),
                );

                forward_frame(response_writer, &response).await?;
                return Ok(());
            }
        };

        let outcome = evaluate_outcome(&ctx, &action).await;
        let record = mcp_proxy::adapters::AdapterExecutionRecord::from_evaluation(
            McpAdapter::ADAPTER_ID,
            &action,
            &outcome,
        );
        let effect =
            McpAdapter::enforce(&wire, &action, &outcome).unwrap_or_else(|_| McpEffect::Block {
                reason: "adapter enforcement failed".to_string(),
                style: McpDenyStyle::AccessDenied,
            });
        McpAdapter::emit_outcome(&record);

        match effect {
            McpEffect::Block { reason, style } => {
                logger
                    .record(direction, frame, &format!("guard block: {reason}"))
                    .await;

                let response_writer =
                    client_writer.context("client writer unavailable for blocked response")?;

                let response = match style {
                    McpDenyStyle::RuleProhibition => blocked_response(&input.request_id, &reason),
                    McpDenyStyle::AccessDenied => {
                        access_denied_response(&input.request_id, &reason)
                    }
                };

                forward_frame(response_writer, &response).await?;
                return Ok(());
            }
            McpEffect::Forward {
                rewritten_params_json,
            } => {
                if let Some(rewritten) = rewritten_params_json {
                    // A rewrite that cannot be re-framed must not fall through to forwarding the
                    // original: the original is the payload the rewrite existed to replace.
                    match rewrite_tools_call_frame(frame, rewritten.as_bytes()) {
                        Ok(new_frame) => {
                            *frame = new_frame;
                            logger
                                .record(
                                    direction,
                                    frame,
                                    "guard: forwarded rewritten tools/call params",
                                )
                                .await;
                        }
                        Err(error) => {
                            let detail = sanitize_error(&error);
                            eprintln!(
                                "mcp-proxy: security control degraded [{}=FAIL_CLOSED] \
                                 could not apply rewritten arguments: {detail}",
                                Subsystem::PolicyEngine
                            );

                            let response_writer = client_writer.context(
                                "client writer unavailable for rewrite-failure response",
                            )?;
                            let response = blocked_response(
                                &input.request_id,
                                "sanitized arguments could not be applied to the request",
                            );

                            forward_frame(response_writer, &response).await?;
                            return Ok(());
                        }
                    }
                }

                forward_frame(downstream_writer, frame).await?;
                return Ok(());
            }
        }
    }

    if direction == "Server -> Client" {
        if let Some(bytes) = sanitize_server_frame(policy_store.snapshot().as_deref(), frame) {
            forward_frame(downstream_writer, &bytes).await?;
            return Ok(());
        }
    }

    // A frame the envelope parser could not read.
    //
    // Forwarding it — the previous behavior — is a parser-differential bypass: `mcp-proxy`
    // declines to inspect exactly the frames a downstream server may still accept, so
    // "make the proxy's parser fail" becomes a way to skip policy entirely.
    //
    // Only the client direction is gated. A server response is not an agent action, and
    // dropping it would break the client for a frame that carries no request to evaluate.
    if let Some(detail) = peek_error {
        if direction == "Client -> Server" {
            let mode = FailurePolicy::from_env().mode_for(Subsystem::Normalization);

            if !mode.permits_allow() {
                eprintln!(
                    "mcp-proxy: security control degraded [{}={mode}] \
                     unparseable client frame withheld: {detail}",
                    Subsystem::Normalization
                );

                if let Some(response_writer) = client_writer {
                    // `id: null` per JSON-RPC: the frame's id is exactly what could not be
                    // read, so there is nothing honest to correlate against.
                    let response = blocked_response(
                        &Value::Null,
                        "request could not be parsed for evaluation",
                    );
                    forward_frame(response_writer, &response).await?;
                }

                return Ok(());
            }
        }
    }

    forward_frame(downstream_writer, frame).await?;
    Ok(())
}

/// Parses CLI: `demo` | pilot cmds | `serve …` | `-- run …` | help/version.
fn parse_cli(argv: &[String]) -> Result<CliMode> {
    let args: Vec<&str> = argv.iter().skip(1).map(String::as_str).collect();

    if args.is_empty()
        || args
            .iter()
            .any(|a| *a == "--help" || *a == "-h" || *a == "help")
    {
        return Ok(CliMode::Help);
    }
    if args
        .iter()
        .any(|a| *a == "--version" || *a == "-V" || *a == "version")
    {
        return Ok(CliMode::Version);
    }
    if args.first().copied() == Some("demo") {
        return Ok(CliMode::Demo);
    }
    if let Some(pilot) = parse_pilot_command(argv)? {
        return Ok(CliMode::Pilot(pilot));
    }
    if args.iter().any(|a| *a == "serve") {
        return parse_serve_command(argv);
    }
    Ok(CliMode::Run(parse_run_command(argv)?))
}

fn parse_serve_command(argv: &[String]) -> Result<CliMode> {
    let serve_pos = argv
        .iter()
        .position(|arg| arg == "serve")
        .context("internal: serve token missing")?;

    let mut listen = None;
    let mut upstream = None;
    let mut rest = argv[serve_pos + 1..].iter();
    while let Some(arg) = rest.next() {
        match arg.as_str() {
            "--listen" => {
                listen = Some(rest.next().context("missing value after --listen")?.clone());
            }
            "--upstream" => {
                upstream = Some(
                    rest.next()
                        .context("missing value after --upstream")?
                        .clone(),
                );
            }
            other => bail!("unknown serve option `{other}`"),
        }
    }

    Ok(CliMode::Serve { listen, upstream })
}

fn parse_run_command(argv: &[String]) -> Result<RunCommand> {
    let separator = argv.iter().position(|arg| arg == "--").context(
        "missing `--` separator.\n\
         Try:  mcp-proxy --help\n\
         Or:   mcp-proxy demo\n\
         Or:   mcp-proxy -- run <command> [args...]\n\
         Or:   mcp-proxy serve --listen 127.0.0.1:8787 --upstream https://api.openai.com",
    )?;

    let mut tail = argv[separator + 1..].iter();
    match tail.next() {
        Some(keyword) if keyword == "run" => {}
        Some(other) => bail!(
            "expected `run` after `--`, found `{other}`.\n\
             Usage: mcp-proxy -- run <command> [args...]   (see mcp-proxy --help)"
        ),
        None => bail!("missing `run` subcommand after `--` (see mcp-proxy --help)"),
    }

    let program = tail
        .next()
        .context("missing downstream command after `run`")?
        .clone();
    let args = tail.cloned().collect();
    Ok(RunCommand { program, args })
}

fn resolve_log_path() -> PathBuf {
    env::var(LOG_PATH_ENV)
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from(DEFAULT_LOG_FILE))
}

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

async fn relay_client_to_server(
    logger: Arc<DebugLogger>,
    policy_store: Arc<PolicyStore>,
    guard_base: GuardContext,
    cloud_client: Arc<Option<CloudClient>>,
    threat_intel_store: Arc<ThreatIntelStore>,
    normalization: Arc<NormalizationContext>,
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
            &guard_base,
            cloud_client.as_ref().as_ref(),
            threat_intel_store.as_ref(),
            normalization.as_ref(),
        )
        .await
        .context("failed to relay client-to-server frame")?;
    }

    drop(child_stdin);
    Ok(())
}

async fn relay_server_to_client(
    logger: Arc<DebugLogger>,
    policy_store: Arc<PolicyStore>,
    guard_base: GuardContext,
    threat_intel_store: Arc<ThreatIntelStore>,
    normalization: Arc<NormalizationContext>,
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
            &guard_base,
            None,
            threat_intel_store.as_ref(),
            normalization.as_ref(),
        )
        .await
        .context("failed to relay server-to-client frame")?;
    }

    Ok(())
}

async fn join_relays(
    client_to_server: JoinHandle<Result<()>>,
    server_to_client: JoinHandle<Result<()>>,
) -> Result<()> {
    let (client_result, server_result) = tokio::join!(client_to_server, server_to_client);
    client_result.context("client-to-server relay task panicked")??;
    server_result.context("server-to-client relay task panicked")??;
    Ok(())
}

async fn shutdown_child(mut child: Child) -> Result<()> {
    match child.wait().await {
        Ok(status) if status.success() => Ok(()),
        Ok(status) => bail!("downstream MCP server exited with status: {status}"),
        Err(error) if error.kind() == std::io::ErrorKind::InvalidInput => Ok(()),
        Err(error) => Err(error).context("failed while waiting for downstream MCP server"),
    }
}

async fn bootstrap_shared_state() -> Result<(
    Arc<Option<CloudClient>>,
    Arc<PolicyStore>,
    Option<Arc<WasmPolicyEngine>>,
    Arc<ThreatIntelStore>,
    Arc<SessionTracker>,
    Arc<NormalizationContext>,
)> {
    let cloud_opt = CloudClient::load_optional();
    let cloud_client = Arc::new(cloud_opt);

    let policy_store = Arc::new(PolicyStore::new(
        load_policy_engine(cloud_client.as_ref().as_ref())
            .await
            .context("failed to load mcp-proxy policy")?,
    ));

    let mut wasm_policy = WasmPolicyEngine::load_optional()?;
    if let Some(engine) = wasm_policy.as_mut() {
        engine.set_violation_log_path(resolve_log_path());
        eprintln!(
            "mcp-proxy: loaded wasm policy extension from {}",
            env::var(WASM_POLICY_ENV).unwrap_or_default()
        );
    }
    let wasm_shared = wasm_policy.map(Arc::new);

    let threat_intel_store = Arc::new(ThreatIntelStore::new(
        load_threat_intel_matcher(cloud_client.as_ref().as_ref()).await,
    ));
    let session_tracker = Arc::new(SessionTracker::default());

    // Ambient identity for every action this process normalizes. Session scope matches
    // `session_tracker`: one process, one session, unless `SQREEN_SESSION_ID` overrides it.
    let normalization = Arc::new(NormalizationContext::from_env());

    if let Some(engine) = policy_store.snapshot() {
        eprintln!(
            "mcp-proxy: active policy version {} ({} tool rules)",
            engine.version(),
            engine.tool_count()
        );
        eprintln!(
            "mcp-proxy: {}",
            mcp_proxy::EnforcementPosture::from_env().enforcement_banner()
        );
    } else {
        let posture = mcp_proxy::EnforcementPosture::from_env();
        eprintln!("mcp-proxy: {}", posture.enforcement_banner());
        if posture.allows_missing_policy_passthrough() {
            eprintln!(
                "mcp-proxy: WARNING — no policy loaded; DEVELOPMENT posture FAIL_OPEN \
                 (tool calls are NOT protected by declarative policy)"
            );
        } else {
            eprintln!(
                "mcp-proxy: no policy loaded; {} posture will DENY tool execution \
                 until a valid policy is available (reason=policy_unavailable)",
                posture.as_str()
            );
        }
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

    Ok((
        cloud_client,
        policy_store,
        wasm_shared,
        threat_intel_store,
        session_tracker,
        normalization,
    ))
}

fn make_guard_base(
    policy_store: &PolicyStore,
    wasm: &Option<Arc<WasmPolicyEngine>>,
    threat_intel_store: &ThreatIntelStore,
    session: &Arc<SessionTracker>,
    cloud_client: &Arc<Option<CloudClient>>,
) -> GuardContext {
    GuardContext {
        policy: policy_store.snapshot(),
        policy_availability: policy_store.availability(),
        wasm: wasm.clone(),
        threat_intel: Arc::new(threat_intel_store.snapshot()),
        session: Arc::clone(session),
        cloud: cloud_client.as_ref().as_ref().map(|c| Arc::new(c.clone())),
    }
}

async fn run_stdio_mode(run_command: RunCommand) -> Result<()> {
    let (
        cloud_client,
        policy_store,
        wasm_shared,
        threat_intel_store,
        session_tracker,
        normalization,
    ) = bootstrap_shared_state().await?;

    let guard_base = make_guard_base(
        policy_store.as_ref(),
        &wasm_shared,
        threat_intel_store.as_ref(),
        &session_tracker,
        &cloud_client,
    );

    let logger = Arc::new(DebugLogger::open(resolve_log_path()).await?);
    let mut child = spawn_downstream(&run_command).await.with_context(|| {
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
    let guard_for_client = guard_base.clone();
    let cloud_for_client = Arc::clone(&cloud_client);
    let threat_intel_for_client = Arc::clone(&threat_intel_store);
    let normalization_for_client = Arc::clone(&normalization);
    let client_to_server = tokio::spawn(async move {
        relay_client_to_server(
            logger_for_client,
            policy_for_client,
            guard_for_client,
            cloud_for_client,
            threat_intel_for_client,
            normalization_for_client,
            child_stdin,
        )
        .await
    });

    let logger_for_server = Arc::clone(&logger);
    let policy_for_server = Arc::clone(&policy_store);
    let guard_for_server = guard_base.clone();
    let threat_intel_for_server = Arc::clone(&threat_intel_store);
    let normalization_for_server = Arc::clone(&normalization);
    let server_to_client = tokio::spawn(async move {
        relay_server_to_client(
            logger_for_server,
            policy_for_server,
            guard_for_server,
            threat_intel_for_server,
            normalization_for_server,
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

async fn run_serve_mode(listen: Option<String>, upstream: Option<String>) -> Result<()> {
    let (
        cloud_client,
        policy_store,
        wasm_shared,
        threat_intel_store,
        session_tracker,
        normalization,
    ) = bootstrap_shared_state().await?;

    let policy_bg = Arc::clone(&policy_store);
    let threat_bg = Arc::clone(&threat_intel_store);
    let cloud_bg = Arc::clone(&cloud_client);
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(std::time::Duration::from_secs(5));
        loop {
            interval.tick().await;
            policy_bg.refresh_if_stale(cloud_bg.as_ref().as_ref()).await;
            threat_bg.refresh_if_stale(cloud_bg.as_ref().as_ref()).await;
        }
    });

    let config = ServeConfig::from_args_and_env(listen.as_deref(), upstream.as_deref())?;
    run_agent_firewall_with_stores(
        config,
        policy_store,
        wasm_shared,
        threat_intel_store,
        session_tracker,
        cloud_client.as_ref().as_ref().map(|c| Arc::new(c.clone())),
        normalization,
    )
    .await
}

#[tokio::main]
async fn main() -> Result<()> {
    let argv: Vec<String> = env::args().collect();
    match parse_cli(&argv)? {
        CliMode::Help => {
            print_help();
            Ok(())
        }
        CliMode::Version => {
            println!("mcp-proxy {VERSION}");
            Ok(())
        }
        CliMode::Demo => run_first_block_demo(),
        CliMode::Pilot(cmd) => run_pilot(cmd).await,
        CliMode::Run(run_command) => run_stdio_mode(run_command).await,
        CliMode::Serve { listen, upstream } => run_serve_mode(listen, upstream).await,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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

        let mode = parse_cli(&argv).expect("command should parse");
        match mode {
            CliMode::Run(command) => {
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
            _ => panic!("expected run mode"),
        }
    }

    #[test]
    fn parses_serve_command() {
        let argv = vec![
            "mcp-proxy".to_string(),
            "serve".to_string(),
            "--listen".to_string(),
            "127.0.0.1:9999".to_string(),
            "--upstream".to_string(),
            "http://127.0.0.1:18080".to_string(),
        ];
        let mode = parse_cli(&argv).expect("serve should parse");
        match mode {
            CliMode::Serve { listen, upstream } => {
                assert_eq!(listen.as_deref(), Some("127.0.0.1:9999"));
                assert_eq!(upstream.as_deref(), Some("http://127.0.0.1:18080"));
            }
            _ => panic!("expected serve mode"),
        }
    }

    #[test]
    fn rejects_missing_run_keyword() {
        let argv = vec![
            "mcp-proxy".to_string(),
            "--".to_string(),
            "start".to_string(),
            "node".to_string(),
        ];

        let error = parse_cli(&argv).expect_err("parser should reject invalid keyword");
        assert!(error.to_string().contains("expected `run`"));
    }

    #[test]
    fn parses_help_and_demo() {
        let help = parse_cli(&["mcp-proxy".into(), "--help".into()]).unwrap();
        assert!(matches!(help, CliMode::Help));
        let demo = parse_cli(&["mcp-proxy".into(), "demo".into()]).unwrap();
        assert!(matches!(demo, CliMode::Demo));
        let ver = parse_cli(&["mcp-proxy".into(), "--version".into()]).unwrap();
        assert!(matches!(ver, CliMode::Version));
        let status = parse_cli(&["mcp-proxy".into(), "status".into()]).unwrap();
        assert!(matches!(status, CliMode::Pilot(PilotCommand::Status)));
        let doctor = parse_cli(&["sqreen".into(), "doctor".into()]).unwrap();
        assert!(matches!(doctor, CliMode::Pilot(PilotCommand::Doctor)));
    }
}
