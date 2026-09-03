//! JSON redaction helpers shared by policy evaluation.

use std::collections::HashSet;

use serde_json::Value;

use crate::security_baseline::{canonicalize_key_name, policy_keys_to_canonical_set};

pub fn redact_json_text(source: &str, keys: &HashSet<String>) -> Vec<u8> {
    match serde_json::from_str::<Value>(source) {
        Ok(mut value) => {
            redact_value(&mut value, keys);
            value.to_string().into_bytes()
        }
        Err(_) => source.as_bytes().to_vec(),
    }
}

/// Redact object keys using case-insensitive / separator-normalized matching.
pub fn redact_value(value: &mut Value, keys: &HashSet<String>) {
    let canonical = policy_keys_to_canonical_set(keys);
    redact_value_ci(value, &canonical);
}

fn redact_value_ci(value: &mut Value, keys: &HashSet<String>) {
    match value {
        Value::Object(map) => {
            let owned_keys: Vec<String> = map.keys().cloned().collect();
            for key in owned_keys {
                if keys.contains(&canonicalize_key_name(&key)) {
                    if let Some(entry) = map.get_mut(&key) {
                        *entry = Value::String("[REDACTED]".to_string());
                    }
                } else if let Some(entry) = map.get_mut(&key) {
                    redact_value_ci(entry, keys);
                }
            }
        }
        Value::Array(items) => {
            for item in items {
                redact_value_ci(item, keys);
            }
        }
        _ => {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn redacts_case_insensitive_keys() {
        let keys: HashSet<String> = ["API_KEY".into()].into_iter().collect();
        let mut v = serde_json::json!({"api-key": "secret", "ok": 1});
        redact_value(&mut v, &keys);
        assert_eq!(v["api-key"], "[REDACTED]");
        assert_eq!(v["ok"], 1);
    }
}
