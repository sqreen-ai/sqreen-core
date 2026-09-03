//! Canonical sensitive key names for DLP / redaction / telemetry / approval sanitization.
//!
//! Subsystems may add keys, but MUST start from [`CANONICAL_REDACT_KEYS`] /
//! [`SENSITIVE_KEY_FRAGMENTS`]. Matching is case-insensitive after [`canonicalize_key_name`].

use std::collections::HashSet;

use serde_json::Value;

/// Exact key names shipped in default policy `redact_keys`.
pub const CANONICAL_REDACT_KEYS: &[&str] = &[
    "OPENAI_API_KEY",
    "ANTHROPIC_API_KEY",
    "STRIPE_SECRET_KEY",
    "AWS_SECRET_ACCESS_KEY",
    "AWS_SESSION_TOKEN",
    "AWS_ACCESS_KEY_ID",
    "GITHUB_TOKEN",
    "GH_TOKEN",
    "SLACK_BOT_TOKEN",
    "SLACK_TOKEN",
    "AUTHORIZATION",
    "PASSWORD",
    "PASSWD",
    "SECRET",
    "TOKEN",
    "ACCESS_TOKEN",
    "REFRESH_TOKEN",
    "API_KEY",
    "APIKEY",
    "PRIVATE_KEY",
    "CLIENT_SECRET",
    "COOKIE",
];

/// Lowercase fragments that mark a key as sensitive (substring match on canonical form).
pub const SENSITIVE_KEY_FRAGMENTS: &[&str] = &[
    "password",
    "passwd",
    "secret",
    "token",
    "access_token",
    "refresh_token",
    "api_key",
    "apikey",
    "authorization",
    "cookie",
    "private_key",
    "client_secret",
    "aws_secret_access_key",
    "session_token",
];

/// Normalize a JSON key for comparison: lowercase, `-`/` ` → `_`.
pub fn canonicalize_key_name(key: &str) -> String {
    key.trim()
        .chars()
        .map(|c| match c {
            '-' | ' ' => '_',
            other => other.to_ascii_lowercase(),
        })
        .collect()
}

/// True when `key` is sensitive per the canonical fragment list.
pub fn is_sensitive_key(key: &str) -> bool {
    let canon = canonicalize_key_name(key);
    if CANONICAL_REDACT_KEYS
        .iter()
        .any(|k| canonicalize_key_name(k) == canon)
    {
        return true;
    }
    SENSITIVE_KEY_FRAGMENTS
        .iter()
        .any(|frag| canon.contains(frag))
}

/// Build a [`HashSet`] of canonical names from policy redact_keys + baseline fragments.
pub fn redact_key_set(policy_keys: &[String]) -> HashSet<String> {
    let mut set = HashSet::new();
    for key in CANONICAL_REDACT_KEYS {
        set.insert(canonicalize_key_name(key));
    }
    for key in policy_keys {
        set.insert(canonicalize_key_name(key));
    }
    set
}

/// Convert a policy key list into a case-insensitive lookup set for [`redact_value`].
pub fn policy_keys_to_canonical_set(policy_keys: &HashSet<String>) -> HashSet<String> {
    policy_keys
        .iter()
        .map(|k| canonicalize_key_name(k))
        .collect()
}

/// Redact object keys case-insensitively using the canonical set.
pub fn redact_keys_case_insensitive(value: &mut Value, policy_keys: &[String]) {
    let keys = redact_key_set(policy_keys);
    redact_value_ci(value, &keys);
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
    fn case_and_separator_variants_match() {
        assert!(is_sensitive_key("api_key"));
        assert!(is_sensitive_key("API-KEY"));
        assert!(is_sensitive_key("ApiKey"));
        assert!(is_sensitive_key("authorization"));
        assert!(is_sensitive_key("Authorization"));
        assert!(!is_sensitive_key("user_name"));
    }

    #[test]
    fn redacts_mixed_case_keys() {
        let mut v = serde_json::json!({"Api-Key": "secret-value", "nested": {"PASSWORD": "x"}});
        redact_keys_case_insensitive(&mut v, &[]);
        assert_eq!(v["Api-Key"], "[REDACTED]");
        assert_eq!(v["nested"]["PASSWORD"], "[REDACTED]");
    }
}
