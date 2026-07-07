//! Sandboxed WebAssembly policy extension runtime.
//!
//! # Memory boundary guarantees
//!
//! - The host writes inbound evaluation JSON into guest linear memory at `input_ptr`
//!   (default offset `0`). Maximum read/write span: [`MAX_GUEST_IO_LEN`] (1 MiB).
//! - All guest pointers passed to host imports (`log_violation`, `report_block`,
//!   `report_rewrite`) are bounds-checked against exported `memory` before UTF-8 decode.
//! - Negative pointer/length values are rejected; overflow on `ptr + len` is rejected.
//!
//! # Thread safety
//!
//! Each evaluation constructs an isolated [`Store<HostState>`] and module instance.
//! [`WasmPolicyEngine`] is `Send + Sync`; concurrent evaluations require separate calls
//! (no shared guest state across threads).
//!
//! # Fail-closed invariants
//!
//! - Unknown guest decision codes fail the evaluation with an error (caller may abort relay).
//! - Rewrite without `report_rewrite` payload is rejected.
//! - Guest strings that are not valid UTF-8 fail the import and bubble up as errors.

use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use anyhow::{bail, Context, Result};
use serde_json::Value;
use wasmtime::{Caller, Engine, Linker, Memory, Module, Store};

fn map_wasm_err(context: impl std::fmt::Display) -> impl Fn(wasmtime::Error) -> anyhow::Error {
    move |error| anyhow::anyhow!("{context}: {error}")
}

/// Environment variable pointing at a compiled policy extension module (`.wasm`).
pub const WASM_POLICY_ENV: &str = "MCP_WASM_POLICY";

/// Maximum bytes the host will read from guest linear memory in one call.
const MAX_GUEST_IO_LEN: usize = 1 << 20;

/// Default guest linear memory offset for inbound evaluation payloads.
const INPUT_BUFFER_OFFSET: u32 = 0;

/// Guest return codes from `evaluate_policy`.
const DECISION_ALLOW: i32 = 0;
const DECISION_BLOCK: i32 = 1;
const DECISION_REWRITE: i32 = 2;

/// Decision returned by a sandboxed policy module.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WasmDecision {
    Allow,
    Block { reason: String },
    Rewrite { modified_params: String },
}

/// Per-evaluation host state shared with Wasm import functions.
#[derive(Default)]
struct HostState {
    violations: Vec<String>,
    block_reason: Option<String>,
    rewrite_params: Option<String>,
    violation_log: Option<Arc<Mutex<std::fs::File>>>,
}

/// Pre-compiled Wasmtime embedding for a policy extension module.
pub struct WasmPolicyEngine {
    engine: Engine,
    module: Module,
    linker: Linker<HostState>,
    violation_log_path: Option<PathBuf>,
}

impl WasmPolicyEngine {
    /// Loads, compiles, and links a policy module from disk.
    pub fn new(wasm_file_path: &str) -> Result<Self> {
        let engine = Engine::default();
        let module = Module::from_file(&engine, wasm_file_path)
            .map_err(map_wasm_err(format!("failed to load wasm policy module from {wasm_file_path}")))?;

        let mut linker = Linker::new(&engine);
        linker.func_wrap("env", "log_violation", host_log_violation)?;
        linker.func_wrap("env", "report_block", host_report_block)?;
        linker.func_wrap("env", "report_rewrite", host_report_rewrite)?;

        Ok(Self {
            engine,
            module,
            linker,
            violation_log_path: None,
        })
    }

    /// Loads a module when [`WASM_POLICY_ENV`] is set and the file exists.
    pub fn load_optional() -> Result<Option<Self>> {
        let path = match std::env::var(WASM_POLICY_ENV) {
            Ok(value) if !value.is_empty() => value,
            _ => return Ok(None),
        };

        if !Path::new(&path).exists() {
            bail!("{WASM_POLICY_ENV} points to missing file: {path}");
        }

        Ok(Some(Self::new(&path)?))
    }

    /// Attaches a host-side violation log file for guest `log_violation` calls.
    pub fn set_violation_log_path(&mut self, log_path: PathBuf) {
        self.violation_log_path = Some(log_path);
    }

    /// Evaluates a `tools/call` invocation inside the sandbox.
    ///
    /// The guest receives a UTF-8 JSON payload shaped as:
    /// `{ "tool_name": "...", "params": { ... } }`
    ///
    /// Expected guest exports:
    /// - `memory`
    /// - `evaluate_policy(input_len: i32) -> i32`
    /// - optional `input_ptr() -> i32` (defaults to [`INPUT_BUFFER_OFFSET`])
    pub fn evaluate_tool_call(&self, tool_name: &str, params_json: &str) -> Result<WasmDecision> {
        let payload = build_evaluation_payload(tool_name, params_json)?;
        let payload_bytes = payload.as_bytes();

        if payload_bytes.len() > MAX_GUEST_IO_LEN {
            bail!("tool call payload exceeds wasm guest buffer limit");
        }

        let violation_log = self
            .violation_log_path
            .as_ref()
            .map(|path| -> Result<Arc<Mutex<std::fs::File>>> {
                Ok(Arc::new(Mutex::new(
                    std::fs::OpenOptions::new()
                        .create(true)
                        .append(true)
                        .open(path)
                        .with_context(|| {
                            format!("failed to open wasm violation log at {}", path.display())
                        })?,
                )))
            })
            .transpose()?;

        let mut store = Store::new(
            &self.engine,
            HostState {
                violation_log,
                ..HostState::default()
            },
        );

        let instance = self
            .linker
            .instantiate(&mut store, &self.module)
            .map_err(map_wasm_err("failed to instantiate wasm policy module"))?;

        let memory = instance
            .get_memory(&mut store, "memory")
            .context("wasm policy module must export `memory`")?;

        let input_ptr = if let Ok(input_ptr) =
            instance.get_typed_func::<(), i32>(&mut store, "input_ptr")
        {
            input_ptr
                .call(&mut store, ())
                .map_err(map_wasm_err("input_ptr call failed"))?
        } else {
            INPUT_BUFFER_OFFSET as i32
        };

        write_guest_bytes(
            &mut store,
            &memory,
            input_ptr,
            payload_bytes,
            "evaluation payload",
        )?;

        let evaluate = instance
            .get_typed_func::<i32, i32>(&mut store, "evaluate_policy")
            .map_err(map_wasm_err(
                "wasm policy module must export `evaluate_policy(i32) -> i32`",
            ))?;

        let decision_code = evaluate
            .call(&mut store, payload_bytes.len() as i32)
            .map_err(map_wasm_err("evaluate_policy call failed"))?;

        match decision_code {
            DECISION_ALLOW => Ok(WasmDecision::Allow),
            DECISION_BLOCK => Ok(WasmDecision::Block {
                reason: store
                    .data()
                    .block_reason
                    .clone()
                    .unwrap_or_else(|| "blocked by wasm policy extension".to_string()),
            }),
            DECISION_REWRITE => {
                let modified = store
                    .data()
                    .rewrite_params
                    .clone()
                    .context("guest returned rewrite without report_rewrite payload")?;
                Ok(WasmDecision::Rewrite {
                    modified_params: modified,
                })
            }
            other => bail!("wasm policy module returned unknown decision code: {other}"),
        }
    }
}

/// Builds the JSON evaluation context passed into guest linear memory.
fn build_evaluation_payload(tool_name: &str, params_json: &str) -> Result<String> {
    let params_value: Value =
        serde_json::from_str(params_json).context("failed to parse tools/call params json")?;

    let payload = serde_json::json!({
        "tool_name": tool_name,
        "params": params_value,
    });

    Ok(payload.to_string())
}

/// Reads a bounded, UTF-8 validated slice from guest linear memory.
fn read_guest_string(caller: &mut Caller<'_, HostState>, ptr: i32, len: i32) -> Result<String> {
    let bytes = read_guest_bytes(caller, ptr, len, "guest string")?;
    String::from_utf8(bytes).context("guest string was not valid utf-8")
}

/// Reads a bounded slice from guest linear memory with strict bounds checking.
fn read_guest_bytes(
    caller: &mut Caller<'_, HostState>,
    ptr: i32,
    len: i32,
    label: &str,
) -> Result<Vec<u8>> {
    if ptr < 0 || len < 0 {
        bail!("negative pointer/length for {label}");
    }

    let len = len as usize;
    if len > MAX_GUEST_IO_LEN {
        bail!("{label} length {len} exceeds host limit");
    }

    let ptr = ptr as usize;
    let memory = caller
        .get_export("memory")
        .and_then(|export| export.into_memory())
        .context("guest module must export memory")?;

    let end = ptr
        .checked_add(len)
        .context("guest memory offset overflow")?;

    memory
        .data(caller)
        .get(ptr..end)
        .map(|slice| slice.to_vec())
        .with_context(|| format!("guest {label} read out of bounds at {ptr} len {len}"))
}

/// Writes host bytes into guest linear memory with strict bounds checking.
fn write_guest_bytes(
    store: &mut Store<HostState>,
    memory: &Memory,
    ptr: i32,
    bytes: &[u8],
    label: &str,
) -> Result<()> {
    if ptr < 0 {
        bail!("negative pointer for {label}");
    }

    let ptr = ptr as usize;
    memory
        .write(store, ptr, bytes)
        .map_err(|error| anyhow::anyhow!("failed to write {label} into guest memory: {error}"))
}

fn append_violation_log(state: &mut HostState, message: &str) -> Result<()> {
    state.violations.push(message.to_string());

    if let Some(log) = &state.violation_log {
        use std::io::Write;
        let mut file = log
            .lock()
            .map_err(|_| anyhow::anyhow!("wasm violation log mutex poisoned"))?;
        writeln!(file, "[wasm] {message}").context("failed to write wasm violation log")?;
        file.flush().context("failed to flush wasm violation log")?;
    } else {
        eprintln!("mcp-proxy wasm: {message}");
    }

    Ok(())
}

fn host_log_violation(
    mut caller: Caller<'_, HostState>,
    ptr: i32,
    len: i32,
) -> Result<(), wasmtime::Error> {
    let message = read_guest_string(&mut caller, ptr, len)
        .map_err(|error| wasmtime::Error::msg(error.to_string()))?;
    append_violation_log(caller.data_mut(), &message)
        .map_err(|error| wasmtime::Error::msg(error.to_string()))
}

fn host_report_block(
    mut caller: Caller<'_, HostState>,
    ptr: i32,
    len: i32,
) -> Result<(), wasmtime::Error> {
    let reason = read_guest_string(&mut caller, ptr, len)
        .map_err(|error| wasmtime::Error::msg(error.to_string()))?;
    caller.data_mut().block_reason = Some(reason);
    Ok(())
}

fn host_report_rewrite(
    mut caller: Caller<'_, HostState>,
    ptr: i32,
    len: i32,
) -> Result<(), wasmtime::Error> {
    let modified = read_guest_string(&mut caller, ptr, len)
        .map_err(|error| wasmtime::Error::msg(error.to_string()))?;
    caller.data_mut().rewrite_params = Some(modified);
    Ok(())
}

/// Extracts the MCP tool name from a `tools/call` params JSON payload.
pub fn parse_tool_name(params_json: &str) -> Result<String> {
    #[derive(serde::Deserialize)]
    struct ToolsCallParams {
        name: String,
    }

    let params: ToolsCallParams =
        serde_json::from_str(params_json).context("failed to parse tool name from params")?;
    Ok(params.name)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Read;
    use std::sync::atomic::{AtomicUsize, Ordering};

    static LOG_COUNTER: AtomicUsize = AtomicUsize::new(0);

    fn unique_violation_log() -> PathBuf {
        let id = LOG_COUNTER.fetch_add(1, Ordering::SeqCst);
        std::env::temp_dir().join(format!("mcp-proxy-wasm-test-{id}.log"))
    }

    const ALLOW_POLICY_WAT: &str = r#"
(module
  (import "env" "log_violation" (func $log_violation (param i32 i32)))
  (import "env" "report_block" (func $report_block (param i32 i32)))
  (import "env" "report_rewrite" (func $report_rewrite (param i32 i32)))
  (memory (export "memory") 2)
  (func (export "input_ptr") (result i32) i32.const 0)
  (func (export "evaluate_policy") (param $len i32) (result i32)
    i32.const 0)
)
"#;

    const BLOCK_POLICY_WAT: &str = r#"
(module
  (import "env" "log_violation" (func $log_violation (param i32 i32)))
  (import "env" "report_block" (func $report_block (param i32 i32)))
  (import "env" "report_rewrite" (func $report_rewrite (param i32 i32)))
  (memory (export "memory") 2)
  (data (i32.const 1024) "blocked by wasm policy extension")
  (func (export "input_ptr") (result i32) i32.const 0)
  (func (export "evaluate_policy") (param $len i32) (result i32)
    i32.const 1024
    i32.const 32
    call $report_block
    i32.const 1024
    i32.const 32
    call $log_violation
    i32.const 1)
)
"#;

    const REWRITE_POLICY_WAT: &str = r#"
(module
  (import "env" "log_violation" (func $log_violation (param i32 i32)))
  (import "env" "report_block" (func $report_block (param i32 i32)))
  (import "env" "report_rewrite" (func $report_rewrite (param i32 i32)))
  (memory (export "memory") 2)
  (data (i32.const 1024) "{\"name\":\"sanitized\",\"arguments\":{}}")
  (func (export "input_ptr") (result i32) i32.const 0)
  (func (export "evaluate_policy") (param $len i32) (result i32)
    i32.const 1024
    i32.const 38
    call $report_rewrite
    i32.const 2)
)
"#;

    fn test_engine_with(wat: &str) -> WasmPolicyEngine {
        let engine = Engine::default();
        let module = Module::new(&engine, wat).expect("test module should compile");
        let mut linker = Linker::new(&engine);
        linker
            .func_wrap("env", "log_violation", host_log_violation)
            .expect("log import");
        linker
            .func_wrap("env", "report_block", host_report_block)
            .expect("block import");
        linker
            .func_wrap("env", "report_rewrite", host_report_rewrite)
            .expect("rewrite import");

        WasmPolicyEngine {
            engine,
            module,
            linker,
            violation_log_path: None,
        }
    }

    fn test_engine() -> WasmPolicyEngine {
        test_engine_with(ALLOW_POLICY_WAT)
    }

    #[test]
    fn allows_benign_tool_call() {
        let engine = test_engine();
        let params = r#"{"name":"read_file","arguments":{"path":"/tmp/a"}}"#;
        assert_eq!(
            engine.evaluate_tool_call("read_file", params).expect("evaluate"),
            WasmDecision::Allow
        );
    }

    #[test]
    fn blocks_when_guest_detects_marker() {
        let engine = test_engine_with(BLOCK_POLICY_WAT);
        let params = r#"{"name":"execute_bash","arguments":{"command":"wasm_block"}}"#;
        let decision = engine
            .evaluate_tool_call("execute_bash", params)
            .expect("evaluate");
        assert!(matches!(decision, WasmDecision::Block { .. }));
    }

    #[test]
    fn rewrites_when_guest_detects_marker() {
        let engine = test_engine_with(REWRITE_POLICY_WAT);
        let params = r#"{"name":"execute_bash","arguments":{"command":"wasm_rewrite"}}"#;
        let decision = engine
            .evaluate_tool_call("execute_bash", params)
            .expect("evaluate");
        assert!(matches!(decision, WasmDecision::Rewrite { .. }));
    }

    #[test]
    fn writes_violations_to_log_file() {
        let log_path = unique_violation_log();
        let mut engine = test_engine_with(BLOCK_POLICY_WAT);
        engine.set_violation_log_path(log_path.clone());

        let params = r#"{"name":"execute_bash","arguments":{"command":"wasm_block"}}"#;
        let _ = engine.evaluate_tool_call("execute_bash", params);

        let mut file = std::fs::File::open(&log_path).expect("log file");
        let mut contents = String::new();
        file.read_to_string(&mut contents).expect("read log");
        assert!(contents.contains("blocked by wasm policy extension"));
    }
}
