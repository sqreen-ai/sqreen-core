//! SDK for authoring custom security plugins that run inside the `mcp-proxy`
//! WebAssembly sandbox.
//!
//! # Guest ABI (must match the host)
//!
//! **Exports**
//! - `memory`
//! - `input_ptr() -> i32` — offset where the host writes inbound JSON
//! - `evaluate_policy(input_len: i32) -> i32` — returns `0` Allow, `1` Block, `2` Rewrite
//!
//! **Imports (`env`)**
//! - `log_violation(ptr, len)`
//! - `report_block(ptr, len)`
//! - `report_rewrite(ptr, len)`
//!
//! # Quick start
//!
//! ```no_run
//! use mcp_proxy_sdk::{export_policy_plugin, Decision, EvaluationContext, PolicyPlugin};
//!
//! struct DemoPlugin;
//!
//! impl PolicyPlugin for DemoPlugin {
//!     fn evaluate(ctx: &EvaluationContext) -> Decision {
//!         if ctx.tool_name() == "execute_bash" {
//!             Decision::block("shell execution denied by demo plugin")
//!         } else {
//!             Decision::allow()
//!         }
//!     }
//! }
//!
//! export_policy_plugin!(DemoPlugin);
//! ```
//!
//! Build for the sandbox target:
//!
//! ```text
//! rustup target add wasm32-unknown-unknown
//! cargo build --release --target wasm32-unknown-unknown
//! ```

#![cfg_attr(target_arch = "wasm32", no_std)]

extern crate alloc;

#[cfg(target_arch = "wasm32")]
#[global_allocator]
static ALLOC: wee_alloc::WeeAlloc = wee_alloc::WeeAlloc::INIT;

mod host;
mod memory;
mod runtime;

pub use host::{log_violation, report_block, report_rewrite};
pub use runtime::{dispatch_evaluate, SdkError};

use alloc::string::{String, ToString};
use serde::Deserialize;
use serde_json::Value;

/// Linear-memory offset where the host writes the inbound evaluation payload.
pub const INPUT_BUFFER_OFFSET: i32 = 0;

/// Guest return code: allow the tool call to proceed.
pub const DECISION_ALLOW: i32 = 0;

/// Guest return code: block the tool call.
pub const DECISION_BLOCK: i32 = 1;

/// Guest return code: rewrite params and forward the modified payload.
pub const DECISION_REWRITE: i32 = 2;

/// Maximum bytes read from the inbound evaluation buffer.
pub const MAX_INPUT_BYTES: usize = 65536;

/// Policy outcome returned by plugin authors.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Decision {
    Allow,
    Block { reason: String },
    Rewrite { modified_params: String },
}

impl Decision {
    pub fn allow() -> Self {
        Self::Allow
    }

    pub fn block(reason: impl Into<String>) -> Self {
        Self::Block {
            reason: reason.into(),
        }
    }

    /// `modified_params` must be a full JSON-RPC `tools/call` params object.
    pub fn rewrite(modified_params: impl Into<String>) -> Self {
        Self::Rewrite {
            modified_params: modified_params.into(),
        }
    }
}

/// Parsed evaluation context passed to guest plugins.
#[derive(Debug, Clone)]
pub struct EvaluationContext {
    tool_name: String,
    params: Value,
    raw_json: String,
}

impl EvaluationContext {
    /// Parses the host evaluation payload.
    ///
    /// Expected JSON shape:
    /// `{ "tool_name": "...", "params": { ... } }`
    pub fn from_json(raw: &str) -> Result<Self, runtime::SdkError> {
        let payload: HostPayload =
            serde_json::from_str(raw).map_err(|error| runtime::SdkError::InvalidJson(error.to_string()))?;

        Ok(Self {
            tool_name: payload.tool_name,
            params: payload.params,
            raw_json: raw.to_string(),
        })
    }

    pub fn tool_name(&self) -> &str {
        &self.tool_name
    }

    pub fn params(&self) -> &Value {
        &self.params
    }

    pub fn raw_json(&self) -> &str {
        &self.raw_json
    }

    /// Returns a string field from the nested `params` object when present.
    pub fn param_str(&self, key: &str) -> Option<&str> {
        self.params.get(key).and_then(Value::as_str)
    }
}

/// Plugin entry point implemented by external authors.
pub trait PolicyPlugin {
    fn evaluate(ctx: &EvaluationContext) -> Decision;
}

/// Writes a violation message to the host log without changing the decision.
pub fn log_violation_message(message: &str) -> Result<(), runtime::SdkError> {
    let (ptr, len) = memory::write_scratch(message)?;
    unsafe {
        log_violation(ptr, len);
    }
    Ok(())
}

/// Converts a [`Decision`] into host calls and the wasm return code.
pub fn apply_decision(decision: Decision) -> Result<i32, runtime::SdkError> {
    match decision {
        Decision::Allow => Ok(DECISION_ALLOW),
        Decision::Block { reason } => {
            let (block_ptr, block_len) = memory::write_scratch(&reason)?;
            unsafe {
                report_block(block_ptr, block_len);
            }

            let (log_ptr, log_len) = memory::write_scratch(&reason)?;
            unsafe {
                log_violation(log_ptr, log_len);
            }

            Ok(DECISION_BLOCK)
        }
        Decision::Rewrite { modified_params } => {
            let (ptr, len) = memory::write_scratch(&modified_params)?;
            unsafe {
                report_rewrite(ptr, len);
            }
            Ok(DECISION_REWRITE)
        }
    }
}

/// Generates the required wasm exports for a plugin type.
#[macro_export]
macro_rules! export_policy_plugin {
    ($plugin:ty) => {
        #[no_mangle]
        pub extern "C" fn input_ptr() -> i32 {
            $crate::INPUT_BUFFER_OFFSET
        }

        #[no_mangle]
        pub extern "C" fn evaluate_policy(input_len: i32) -> i32 {
            $crate::dispatch_evaluate::<$plugin>(input_len)
        }
    };
}

#[derive(Debug, Deserialize)]
struct HostPayload {
    tool_name: String,
    params: Value,
}

#[cfg(target_arch = "wasm32")]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_host_payload() {
        let raw = r#"{"tool_name":"read_file","params":{"name":"read_file","arguments":{"path":"/tmp/a"}}}"#;
        let ctx = EvaluationContext::from_json(raw).expect("parse");
        assert_eq!(ctx.tool_name(), "read_file");
        assert_eq!(ctx.param_str("name"), Some("read_file"));
    }

    #[test]
    fn decision_helpers_build_expected_variants() {
        assert_eq!(Decision::allow(), Decision::Allow);
        assert_eq!(
            Decision::block("nope"),
            Decision::Block {
                reason: "nope".to_string()
            }
        );
    }
}
