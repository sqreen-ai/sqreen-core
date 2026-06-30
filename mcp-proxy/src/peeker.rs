//! Zero-copy JSON-RPC envelope peeker for MCP stdio frames.
//!
//! # Design
//!
//! [`peek_envelope`] walks the top-level JSON object key-by-key using
//! `serde_json::Deserializer::from_slice`, materializing only the fields required
//! for classification (`jsonrpc`, `method`, `id`, `result`/`error`). Large or nested
//! payloads (for example `params` on unrelated methods) are skipped via
//! [`serde::de::IgnoredAny`] without building an intermediate DOM.
//!
//! # Lifetime boundaries
//!
//! The input `bytes` slice is the single owner of frame data for the duration of a
//! relay iteration. [`McpMessageType::Request::params`] is an optional
//! [`serde_json::value::RawValue`] view that borrows directly from `bytes` when
//! `method == "tools/call"`. Callers must:
//!
//! 1. Peek while `bytes` is valid and unmodified.
//! 2. Complete any policy inspection that reads `params` before reusing or clearing
//!    the buffer.
//! 3. Forward the same underlying `&[u8]` to the peer stream without cloning the
//!    frame body.
//!
//! This keeps heap churn to one small `Vec` per line in the relay loop plus
//! bounded allocations for `method`/`id` metadata only.

use std::borrow::Cow;
use std::fmt;

use anyhow::{bail, Context, Result};
use serde::de::{IgnoredAny, MapAccess, Visitor};
use serde::Deserializer;
use serde_json::value::RawValue;
use serde_json::{Deserializer as JsonDeserializer, Value};

/// JSON-RPC 2.0 protocol version string.
const JSONRPC_VERSION: &str = "2.0";

/// MCP method that triggers raw `params` capture for downstream policy hooks.
const TOOLS_CALL_METHOD: &str = "tools/call";

/// Classified MCP / JSON-RPC envelope with optional zero-copy parameter view.
#[derive(Debug)]
pub enum McpMessageType<'a> {
    /// A JSON-RPC request carrying an `id` and `method`.
    Request {
        id: Value,
        method: String,
        /// Borrowed `params` subtree when `method == "tools/call"`.
        params: Option<&'a RawValue>,
    },
    /// A JSON-RPC notification (no `id` field).
    Notification {
        method: String,
    },
    /// A JSON-RPC response (`result` or `error` present).
    Response {
        id: Value,
    },
    /// Non-JSON, empty, or structurally unrecognizable frame.
    Unknown,
}

/// Fields collected during a single lazy map walk.
struct PeekFields<'a> {
    jsonrpc: Option<Cow<'a, str>>,
    method: Option<String>,
    id: Option<Value>,
    params: Option<&'a RawValue>,
    has_result: bool,
    has_error: bool,
}

/// Map visitor that extracts envelope metadata without deserializing the full object.
struct EnvelopeMapVisitor;

impl<'de> Visitor<'de> for EnvelopeMapVisitor {
    type Value = PeekFields<'de>;

    fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        formatter.write_str("a JSON-RPC envelope object")
    }

    fn visit_map<M>(self, mut map: M) -> Result<Self::Value, M::Error>
    where
        M: MapAccess<'de>,
    {
        let mut fields = PeekFields {
            jsonrpc: None,
            method: None,
            id: None,
            params: None,
            has_result: false,
            has_error: false,
        };

        while let Some(key) = map.next_key::<Cow<'de, str>>()? {
            match key.as_ref() {
                "jsonrpc" => {
                    fields.jsonrpc = Some(map.next_value()?);
                }
                "method" => {
                    let method: Cow<'de, str> = map.next_value()?;
                    fields.method = Some(method.into_owned());
                }
                "id" => {
                    fields.id = Some(map.next_value()?);
                }
                "params" => {
                    // Retain a zero-copy view; only surfaced for tools/call after classification.
                    fields.params = Some(map.next_value()?);
                }
                "result" => {
                    fields.has_result = true;
                    let _: IgnoredAny = map.next_value()?;
                }
                "error" => {
                    fields.has_error = true;
                    let _: IgnoredAny = map.next_value()?;
                }
                _ => {
                    let _: IgnoredAny = map.next_value()?;
                }
            }
        }

        Ok(fields)
    }
}

impl McpMessageType<'_> {
    /// Returns `true` for notifications and responses that can be forwarded without
    /// retaining parsed metadata beyond logging.
    pub fn is_fast_path(&self) -> bool {
        matches!(
            self,
            McpMessageType::Notification { .. } | McpMessageType::Response { .. }
        )
    }
}

/// Peeks at a single newline-delimited frame and classifies the JSON-RPC envelope.
///
/// The returned [`McpMessageType`] may borrow from `bytes` (notably `params` on
/// `tools/call` requests). See module-level docs for lifetime rules.
pub fn peek_envelope(bytes: &[u8]) -> Result<McpMessageType<'_>> {
    let bytes = trim_ascii_whitespace(bytes);
    if bytes.is_empty() {
        return Ok(McpMessageType::Unknown);
    }

    let mut de = JsonDeserializer::from_slice(bytes);
    let fields = de
        .deserialize_map(EnvelopeMapVisitor)
        .map_err(|error| anyhow::Error::new(error))
        .context("failed to peek json-rpc envelope")?;

    classify_fields(fields)
}

/// Renders a compact inspection line for debug logging.
pub fn format_peek_summary(message: &McpMessageType<'_>) -> String {
    match message {
        McpMessageType::Request { id, method, params } => {
            let mut summary = format!("request method={method} id={id}");
            if method == TOOLS_CALL_METHOD {
                if let Some(raw) = params {
                    summary.push_str(&format!(" params_raw_len={}", raw.get().len()));
                } else {
                    summary.push_str(" params_raw_len=0");
                }
            }
            summary
        }
        McpMessageType::Notification { method } => format!("notification method={method}"),
        McpMessageType::Response { id } => format!("response id={id}"),
        McpMessageType::Unknown => "unknown".to_string(),
    }
}

/// Strips leading and trailing ASCII whitespace without allocating.
fn trim_ascii_whitespace(bytes: &[u8]) -> &[u8] {
    let start = bytes
        .iter()
        .position(|byte| !byte.is_ascii_whitespace())
        .unwrap_or(bytes.len());
    let end = bytes
        .iter()
        .rposition(|byte| !byte.is_ascii_whitespace())
        .map(|index| index + 1)
        .unwrap_or(start);
    &bytes[start..end]
}

/// Converts lazily collected fields into a classified message type.
fn classify_fields<'a>(fields: PeekFields<'a>) -> Result<McpMessageType<'a>> {
    let has_rpc_shape = fields.jsonrpc.is_some()
        || fields.method.is_some()
        || fields.has_result
        || fields.has_error;

    if !has_rpc_shape {
        return Ok(McpMessageType::Unknown);
    }

    if fields.jsonrpc.as_deref() != Some(JSONRPC_VERSION) {
        bail!("invalid or missing jsonrpc version");
    }

    if let Some(method) = fields.method {
        if fields.has_result || fields.has_error {
            bail!("json-rpc envelope mixes method with result/error");
        }

        if let Some(id) = fields.id {
            let params = if method == TOOLS_CALL_METHOD {
                fields.params
            } else {
                None
            };

            return Ok(McpMessageType::Request { id, method, params });
        }

        return Ok(McpMessageType::Notification { method });
    }

    if fields.has_result || fields.has_error {
        return Ok(McpMessageType::Response {
            id: fields.id.unwrap_or(Value::Null),
        });
    }

    Ok(McpMessageType::Unknown)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classifies_request_without_params_capture() {
        let frame = br#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}"#;
        let message = peek_envelope(frame).expect("valid request");

        let McpMessageType::Request { id, method, params } = message else {
            panic!("expected request");
        };
        assert_eq!(id, Value::from(1));
        assert_eq!(method, "initialize");
        assert!(params.is_none());
    }

    #[test]
    fn classifies_notification_on_fast_path() {
        let frame = br#"{"jsonrpc":"2.0","method":"notifications/initialized","params":{}}"#;
        let message = peek_envelope(frame).expect("valid notification");

        let McpMessageType::Notification { method } = message else {
            panic!("expected notification");
        };
        assert_eq!(method, "notifications/initialized");
    }

    #[test]
    fn classifies_response_on_fast_path() {
        let frame = br#"{"jsonrpc":"2.0","id":"abc","result":{"capabilities":{}}}"#;
        let message = peek_envelope(frame).expect("valid response");

        let McpMessageType::Response { id } = message else {
            panic!("expected response");
        };
        assert_eq!(id, Value::String("abc".to_string()));
    }

    #[test]
    fn captures_tools_call_params_as_raw_value() {
        let frame = br#"{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"read_file","arguments":{"path":"/etc/passwd"}}}"#;
        let message = peek_envelope(frame).expect("valid tools/call request");

        let McpMessageType::Request { method, params, .. } = message else {
            panic!("expected request");
        };

        assert_eq!(method, "tools/call");
        let raw = params.expect("params should be captured");
        assert!(raw.get().contains("read_file"));
        assert!(raw.get().contains("/etc/passwd"));
    }

    #[test]
    fn treats_empty_frame_as_unknown() {
        assert!(matches!(
            peek_envelope(b"   \n").expect("empty frame"),
            McpMessageType::Unknown
        ));
    }

    #[test]
    fn rejects_invalid_json() {
        assert!(peek_envelope(b"not-json").is_err());
    }

    #[test]
    fn rejects_invalid_jsonrpc_version() {
        let frame = br#"{"jsonrpc":"1.0","id":1,"method":"initialize"}"#;
        assert!(peek_envelope(frame).is_err());
    }
}
