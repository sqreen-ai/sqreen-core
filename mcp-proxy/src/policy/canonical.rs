//! Deterministic JSON canonicalization for policy signing.
//!
//! Algorithm (JCS-inspired, deterministic subset):
//! - Objects: keys sorted lexicographically (UTF-8 byte order), no whitespace
//! - Arrays: preserve order; each element canonicalized
//! - Strings/numbers/bools/null: compact JSON encoding via serde_json
//!
//! Both the control plane (Go) and the edge (Rust) MUST implement the same rules.

use serde_json::{Map, Value};

/// Emit canonical JSON bytes for an arbitrary JSON value.
pub fn canonicalize(value: &Value) -> Vec<u8> {
    let mut out = Vec::new();
    write_canonical(value, &mut out);
    out
}

fn write_canonical(value: &Value, out: &mut Vec<u8>) {
    match value {
        Value::Null => out.extend_from_slice(b"null"),
        Value::Bool(true) => out.extend_from_slice(b"true"),
        Value::Bool(false) => out.extend_from_slice(b"false"),
        Value::Number(n) => out.extend_from_slice(n.to_string().as_bytes()),
        Value::String(s) => {
            let encoded = Value::String(s.clone()).to_string();
            out.extend_from_slice(encoded.as_bytes());
        }
        Value::Array(items) => {
            out.push(b'[');
            for (i, item) in items.iter().enumerate() {
                if i > 0 {
                    out.push(b',');
                }
                write_canonical(item, out);
            }
            out.push(b']');
        }
        Value::Object(map) => write_object(map, out),
    }
}

fn write_object(map: &Map<String, Value>, out: &mut Vec<u8>) {
    out.push(b'{');
    let mut keys: Vec<&String> = map.keys().collect();
    keys.sort_unstable();
    for (i, key) in keys.iter().enumerate() {
        if i > 0 {
            out.push(b',');
        }
        let encoded_key = Value::String((*key).clone()).to_string();
        out.extend_from_slice(encoded_key.as_bytes());
        out.push(b':');
        write_canonical(&map[*key], out);
    }
    out.push(b'}');
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn sorts_object_keys() {
        let v = json!({"b": 1, "a": 2});
        assert_eq!(canonicalize(&v), br#"{"a":2,"b":1}"#);
    }

    #[test]
    fn nested_sort() {
        let v = json!({"z": {"b": 1, "a": 0}, "a": [3, 1]});
        assert_eq!(canonicalize(&v), br#"{"a":[3,1],"z":{"a":0,"b":1}}"#);
    }
}
