//! Privacy transforms for behavioral telemetry.
//!
//! Events are security signals, not forensic dumps. These helpers ensure identifiers are
//! tokenized and argument values never carry secrets, prompts, or file contents.

use sha2::{Digest, Sha256};

/// Default salt when none is configured — deployments should override via env.
pub const DEFAULT_HASH_SALT: &str = "sqreen-telemetry-v1";

/// Argument keys whose *values* are never emitted (prompts, bodies, secrets).
const SENSITIVE_VALUE_KEYS: &[&str] = &[
    "prompt",
    "content",
    "message",
    "messages",
    "body",
    "text",
    "input",
    "output",
    "file_contents",
    "file_content",
    "contents",
    "data",
    "payload",
    "raw",
    "api_key",
    "apikey",
    "token",
    "access_token",
    "refresh_token",
    "password",
    "passwd",
    "secret",
    "authorization",
    "auth",
    "credential",
    "credentials",
    "private_key",
    "ssh_key",
];

/// Path-like argument keys eligible for hashed path summaries.
const PATH_KEYS: &[&str] = &[
    "path",
    "file_path",
    "filepath",
    "filename",
    "absolute_path",
    "directory",
    "dir",
    "folder",
    "root",
    "base_path",
];

/// URL-like argument keys — only the host/domain is kept.
const URL_KEYS: &[&str] = &["url", "uri", "endpoint", "href", "host"];

/// Privacy policy applied when building [`super::event::AgentSecurityEvent`]s.
#[derive(Debug, Clone)]
pub struct PrivacyPolicy {
    /// Salt mixed into identifier hashes.
    pub hash_salt: String,
    /// When true, omit even hashed path summaries (signal-only).
    pub omit_path_summaries: bool,
}

impl Default for PrivacyPolicy {
    fn default() -> Self {
        Self {
            hash_salt: std::env::var("SQREEN_TELEMETRY_HASH_SALT")
                .unwrap_or_else(|_| DEFAULT_HASH_SALT.to_string()),
            omit_path_summaries: false,
        }
    }
}

impl PrivacyPolicy {
    /// Builds a policy with an explicit salt.
    pub fn with_salt(salt: impl Into<String>) -> Self {
        Self {
            hash_salt: salt.into(),
            omit_path_summaries: false,
        }
    }

    /// Hashes a durable identifier into a stable opaque token.
    pub fn hash_id(&self, value: &str) -> String {
        hash_identifier(value, &self.hash_salt)
    }

    /// Hashes when present.
    pub fn hash_optional(&self, value: Option<&str>) -> Option<String> {
        value
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(|value| self.hash_id(value))
    }
}

/// Opaque, stable hash of an identifier (`h_` + 16 hex chars).
pub fn hash_identifier(value: &str, salt: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(salt.as_bytes());
    hasher.update(b"|");
    hasher.update(value.as_bytes());
    let digest = hasher.finalize();
    let hex = digest
        .iter()
        .take(8)
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    format!("h_{hex}")
}

/// Returns `true` when an argument key's value must never leave the process.
pub fn is_sensitive_value_key(key: &str) -> bool {
    let lowered = key.to_ascii_lowercase();
    SENSITIVE_VALUE_KEYS
        .iter()
        .any(|blocked| lowered == *blocked || lowered.contains(blocked))
}

/// Returns `true` when the key looks like a filesystem path field.
pub fn is_path_key(key: &str) -> bool {
    PATH_KEYS
        .iter()
        .any(|candidate| key.eq_ignore_ascii_case(candidate))
}

/// Returns `true` when the key looks like a URL field.
pub fn is_url_key(key: &str) -> bool {
    URL_KEYS
        .iter()
        .any(|candidate| key.eq_ignore_ascii_case(candidate))
}

/// Extracts a hostname from a URL or host string without credentials or path.
pub fn extract_domain(raw: &str) -> Option<String> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return None;
    }

    let without_scheme = trimmed
        .split_once("://")
        .map(|(_, rest)| rest)
        .unwrap_or(trimmed);

    let authority = without_scheme
        .split(['/', '?', '#', ' '])
        .next()
        .unwrap_or(without_scheme);

    let host_port = authority.rsplit('@').next().unwrap_or(authority);
    let host = host_port
        .rsplit_once(':')
        .and_then(|(host, port)| {
            if port.chars().all(|c| c.is_ascii_digit()) {
                Some(host)
            } else {
                None
            }
        })
        .unwrap_or(host_port)
        .trim()
        .trim_matches(|c| c == '[' || c == ']');

    if host.is_empty() || host.contains(' ') {
        return None;
    }

    Some(host.to_ascii_lowercase())
}

/// Classifies a destination host as internal / external / localhost / unknown.
pub fn destination_category(host: &str) -> &'static str {
    let lowered = host.to_ascii_lowercase();
    if lowered == "localhost" || lowered == "127.0.0.1" || lowered == "::1" || lowered == "0.0.0.0"
    {
        return "localhost";
    }
    if lowered.ends_with(".local")
        || lowered.ends_with(".internal")
        || lowered.ends_with(".lan")
        || lowered.starts_with("10.")
        || lowered.starts_with("192.168.")
        || lowered.starts_with("172.")
    {
        return "internal";
    }
    if lowered.contains('.') {
        return "external";
    }
    "unknown"
}

/// Redacts a path into a structural summary: hashed absolute path + optional extension.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct PathSummary {
    /// Hashed full path.
    pub path_hash: String,
    /// File extension when present (e.g. `rs`, `pem`) — never the basename.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub extension: Option<String>,
    /// Whether the path looked absolute.
    pub absolute: bool,
    /// Whether the path appears under a sensitive directory (`.ssh`, `.env`, …).
    pub sensitive_location: bool,
}

impl PathSummary {
    /// Builds a summary from a raw path.
    pub fn from_path(path: &str, privacy: &PrivacyPolicy) -> Self {
        let absolute = path.starts_with('/') || path.starts_with('~') || path.contains(":\\");
        let extension = std::path::Path::new(path)
            .extension()
            .and_then(|ext| ext.to_str())
            .map(|ext| ext.to_ascii_lowercase())
            .filter(|ext| ext.len() <= 16 && ext.chars().all(|c| c.is_ascii_alphanumeric()));

        let lowered = path.to_ascii_lowercase();
        let sensitive_location = lowered.contains(".ssh")
            || lowered.contains(".env")
            || lowered.contains(".aws")
            || lowered.contains("credentials")
            || lowered.contains("secret")
            || lowered.contains("id_rsa")
            || lowered.contains("private");

        Self {
            path_hash: privacy.hash_id(path),
            extension,
            absolute,
            sensitive_location,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hash_is_stable_and_opaque() {
        let privacy = PrivacyPolicy::with_salt("test-salt");
        let a = privacy.hash_id("agent-123");
        let b = privacy.hash_id("agent-123");
        assert_eq!(a, b);
        assert!(a.starts_with("h_"));
        assert!(!a.contains("agent"));
    }

    #[test]
    fn different_salts_change_hashes() {
        let left = PrivacyPolicy::with_salt("a").hash_id("x");
        let right = PrivacyPolicy::with_salt("b").hash_id("x");
        assert_ne!(left, right);
    }

    #[test]
    fn extracts_domain_without_credentials_or_path() {
        assert_eq!(
            extract_domain("https://user:pass@api.example.com:443/v1/keys?x=1"),
            Some("api.example.com".to_string())
        );
        assert_eq!(
            extract_domain("api.internal.lan/health"),
            Some("api.internal.lan".to_string())
        );
    }

    #[test]
    fn sensitive_keys_cover_prompts_and_secrets() {
        assert!(is_sensitive_value_key("prompt"));
        assert!(is_sensitive_value_key("OPENAI_API_KEY"));
        assert!(is_sensitive_value_key("file_contents"));
        assert!(!is_sensitive_value_key("path"));
    }

    #[test]
    fn path_summary_never_embeds_raw_path() {
        let privacy = PrivacyPolicy::with_salt("test");
        let summary = PathSummary::from_path("/Users/alice/.ssh/id_rsa", &privacy);
        let encoded = serde_json::to_string(&summary).expect("serialize");
        assert!(!encoded.contains("alice"));
        assert!(!encoded.contains("id_rsa"));
        assert!(summary.sensitive_location);
        assert_eq!(summary.extension.as_deref(), None);
    }
}
