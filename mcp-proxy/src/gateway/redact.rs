//! Secret-safe rendering of anything that ends up in a reason, an audit record, or a log.
//!
//! # The problem this solves
//!
//! Error text is the most reliable secret-exfiltration channel in a security proxy,
//! because it is the one place where a developer writes `{payload}` without thinking of it
//! as output. `failed to parse {params}`, `upstream error: {err:#}`, a debug log of the raw
//! frame — each is a sensible-looking line that copies an API key into a file, a terminal,
//! or an HTTP response body.
//!
//! # The approach
//!
//! Sanitizing at every call site is the same losing game as scattering fallback behavior,
//! so the crate does not do it at call sites. [`sanitize_detail`] is applied inside the
//! constructors of the types that carry operator-facing text —
//! [`crate::gateway::DecisionReason::new`] and
//! [`crate::gateway::SubsystemFailure::new`] — which makes an unsanitized reason
//! unconstructible rather than merely discouraged.
//!
//! Sanitizing means three things, in order:
//!
//! 1. **Mask known secret shapes** using the same scanner that protects payloads
//!    ([`crate::risk::mask_secrets_in_text`]), so a leaked key is replaced rather than the
//!    whole message being dropped.
//! 2. **Strip credentials from URLs**, which the secret scanner does not recognize because
//!    `https://user:pass@host` contains no key-shaped token.
//! 3. **Truncate**, so a message that embedded an entire payload cannot smuggle it past the
//!    scanner in the tail. The cap is generous enough for a real explanation and far short
//!    of a document.
//!
//! Sanitizing is deliberately *not* reversible and *not* configurable. A deployment that
//! wants the raw payload for debugging has the payload; it does not need the error to
//! carry a copy.

use crate::risk::mask_secrets_in_text;

/// Longest operator-facing detail string kept before truncation.
pub const MAX_DETAIL_LEN: usize = 512;

/// Marker appended to a detail that was truncated.
pub const TRUNCATION_SUFFIX: &str = "… [truncated]";

/// Replacement for the credential span of a URL.
const URL_CREDENTIAL_MASK: &str = "***:***@";

/// Renders untrusted text safe to put in a reason, an audit record, or a log line.
///
/// Applies secret masking, URL-credential stripping, control-character removal, and
/// truncation. See the [module documentation](self) for why each step is there.
pub fn sanitize_detail(detail: &str) -> String {
    let (masked, _) = mask_secrets_in_text(detail);
    let stripped = strip_url_credentials(&masked);
    truncate(&collapse_control_characters(&stripped))
}

/// Renders an error chain safe to surface.
///
/// Equivalent to `sanitize_detail(&format!("{error:#}"))`, named so call sites read as
/// intent rather than formatting.
pub fn sanitize_error(error: &anyhow::Error) -> String {
    sanitize_detail(&format!("{error:#}"))
}

/// Replaces the `user:password@` span of any URL-like substring.
///
/// Scans for `://` and, when a `@` appears before the next path or whitespace boundary,
/// masks everything between them. Deliberately syntactic: a real URL parser would reject
/// the malformed URLs that are exactly the ones worth masking.
fn strip_url_credentials(text: &str) -> String {
    const SCHEME_SEPARATOR: &str = "://";

    let mut output = String::with_capacity(text.len());
    let mut rest = text;

    while let Some(scheme_end) = rest.find(SCHEME_SEPARATOR) {
        let authority_start = scheme_end + SCHEME_SEPARATOR.len();
        output.push_str(&rest[..authority_start]);
        rest = &rest[authority_start..];

        let authority_end = rest
            .find(|c: char| c == '/' || c == '?' || c == '#' || c.is_whitespace())
            .unwrap_or(rest.len());
        let authority = &rest[..authority_end];

        match authority.rfind('@') {
            Some(at) => {
                output.push_str(URL_CREDENTIAL_MASK);
                output.push_str(&authority[at + 1..]);
            }
            None => output.push_str(authority),
        }

        rest = &rest[authority_end..];
    }

    output.push_str(rest);
    output
}

/// Replaces control characters with spaces so a detail cannot forge log lines.
///
/// A newline inside an error message lets untrusted input fabricate what looks like a
/// separate audit entry, which is a cheap way to hide a real one.
fn collapse_control_characters(text: &str) -> String {
    text.chars()
        .map(|c| if c.is_control() { ' ' } else { c })
        .collect()
}

/// Truncates on a character boundary, appending [`TRUNCATION_SUFFIX`].
fn truncate(text: &str) -> String {
    if text.len() <= MAX_DETAIL_LEN {
        return text.to_string();
    }

    let mut end = MAX_DETAIL_LEN;
    while end > 0 && !text.is_char_boundary(end) {
        end -= 1;
    }

    format!("{}{TRUNCATION_SUFFIX}", &text[..end])
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::risk::SECRET_MASK_TOKEN;

    #[test]
    fn masks_a_secret_embedded_in_an_error_message() {
        let sanitized = sanitize_detail(
            "failed to parse {\"api_key\":\"sk-proj-abcdefghijklmnopqrstuvwxyz012345\"}",
        );

        assert!(!sanitized.contains("sk-proj-abcdefghijklmnopqrstuvwxyz012345"));
        assert!(sanitized.contains(SECRET_MASK_TOKEN));
        assert!(sanitized.contains("failed to parse"));
    }

    #[test]
    fn strips_credentials_from_a_url() {
        let sanitized =
            sanitize_detail("failed to reach https://device:hunter2@control.example/api/v1/sync");

        assert!(!sanitized.contains("hunter2"));
        assert!(sanitized.contains("control.example/api/v1/sync"));
    }

    #[test]
    fn leaves_a_credential_free_url_intact() {
        let sanitized = sanitize_detail("failed to reach http://localhost:8080/api/v1/policy/sync");

        assert_eq!(
            sanitized,
            "failed to reach http://localhost:8080/api/v1/policy/sync"
        );
    }

    #[test]
    fn strips_credentials_from_every_url_in_a_chain() {
        let sanitized = sanitize_detail(
            "https://a:b@one.example/x failed, then https://c:d@two.example/y failed",
        );

        assert!(!sanitized.contains("a:b@"));
        assert!(!sanitized.contains("c:d@"));
        assert!(sanitized.contains("one.example/x"));
        assert!(sanitized.contains("two.example/y"));
    }

    #[test]
    fn truncates_a_detail_that_smuggles_a_payload() {
        let sanitized = sanitize_detail(&"a".repeat(MAX_DETAIL_LEN * 3));

        assert!(sanitized.ends_with(TRUNCATION_SUFFIX));
        assert!(sanitized.len() <= MAX_DETAIL_LEN + TRUNCATION_SUFFIX.len());
    }

    #[test]
    fn truncation_respects_character_boundaries() {
        let sanitized = sanitize_detail(&"é".repeat(MAX_DETAIL_LEN));

        assert!(sanitized.ends_with(TRUNCATION_SUFFIX));
    }

    #[test]
    fn newlines_cannot_forge_a_second_log_line() {
        let sanitized = sanitize_detail("real failure\n[audit] fabricated allow entry");

        assert!(!sanitized.contains('\n'));
        assert!(sanitized.contains("fabricated allow entry"));
    }

    #[test]
    fn a_clean_message_passes_through_unchanged() {
        let message = "wasm policy extension exhausted its fuel budget";

        assert_eq!(sanitize_detail(message), message);
    }
}
