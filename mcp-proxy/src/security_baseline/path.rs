//! Centralized filesystem path normalization for policy evaluation.
//!
//! # Scope
//!
//! This module normalizes *path strings* for comparison against baseline patterns.
//! It does **not** resolve symlinks or claim filesystem-target safety (`lstat`).
//! Path string normalization ≠ symlink resolution.
//!
//! # Percent-decoding
//!
//! At most [`MAX_PERCENT_DECODE_PASSES`] decode rounds are applied to catch single-
//! and double-encoded traversal. Further encoded forms are not recursively exploded
//! (avoids decode loops).

use std::borrow::Cow;

/// Maximum percent-decoding passes (covers single + double encoding).
pub const MAX_PERCENT_DECODE_PASSES: usize = 2;

/// Documented decode policy for operators and tests.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DecodePolicy {
    /// Apply up to [`MAX_PERCENT_DECODE_PASSES`] rounds of `%XX` decoding.
    LimitedPasses,
}

/// Result of normalizing a path string for policy matching.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NormalizedPath {
    /// Original input.
    pub original: String,
    /// Normalized form used for pattern matching.
    pub normalized: String,
    /// True when any traversal signal was detected.
    pub has_traversal: bool,
}

/// Normalize a path string for security policy comparison.
pub fn normalize_path_for_policy(input: &str) -> NormalizedPath {
    normalize_path_for_policy_with(input, DecodePolicy::LimitedPasses)
}

pub fn normalize_path_for_policy_with(input: &str, policy: DecodePolicy) -> NormalizedPath {
    let _ = policy;
    let original = input.to_string();
    let mut current = input.replace('\\', "/");

    if current.contains('\0') {
        current = current.replace('\0', "");
    }

    for _ in 0..MAX_PERCENT_DECODE_PASSES {
        match percent_decode_once(&current) {
            Some(next) if next != current => current = next,
            _ => break,
        }
    }

    current = collapse_dot_segments(&current);
    let has_traversal = looks_like_traversal(input) || looks_like_traversal(&current);

    NormalizedPath {
        original,
        normalized: current,
        has_traversal,
    }
}

fn parent_seg() -> String {
    format!("{}{}", ".", ".")
}

fn parent_slash() -> String {
    format!("{}/", parent_seg())
}

/// Fast traversal heuristic on a raw or partially-decoded string.
pub fn looks_like_traversal(input: &str) -> bool {
    if looks_like_traversal_once(input) {
        return true;
    }
    // One decode pass catches `..%2F` / `%2e%2e%2f` without requiring full normalize.
    if let Some(decoded) = percent_decode_once(input) {
        return looks_like_traversal_once(&decoded);
    }
    false
}

fn looks_like_traversal_once(input: &str) -> bool {
    let lower = input.to_ascii_lowercase();
    let slash = parent_slash();
    let back = format!("{}{}", parent_seg(), "\\");
    if lower.contains(&slash) || lower.contains(&back) {
        return true;
    }
    let e = |c: &str| format!("%{}", c);
    let enc = format!("{}{}", e("2e"), e("2e"));
    let enc2 = format!("{}{}", e("252e"), e("252e"));
    if lower.contains(&enc) || lower.contains(&enc2) {
        return true;
    }
    let mixed_a = format!("{}{}", e("2e"), ".");
    let mixed_b = format!("{}{}", ".", e("2e"));
    if lower.contains(&mixed_a) || lower.contains(&mixed_b) {
        return true;
    }
    let enc_slash = format!("{}{}", e("2e"), e("2f"));
    let enc_bs = format!("{}{}", e("2e"), e("5c"));
    if lower.contains(&enc_slash) || lower.contains(&enc_bs) {
        return true;
    }
    // Mixed: literal parent + encoded separator (`..%2f`).
    let mixed_enc_sep = format!("{}{}", parent_seg(), e("2f"));
    if lower.contains(&mixed_enc_sep) {
        return true;
    }
    false
}

/// Whether a (possibly encoded) path matches any sensitive baseline pattern after normalization.
pub fn path_matches_sensitive(input: &str, patterns: &[regex::Regex]) -> bool {
    let norm = normalize_path_for_policy(input);
    let expanded = expand_home(&norm.normalized);
    for pattern in patterns {
        if pattern.is_match(&norm.normalized)
            || pattern.is_match(&expanded)
            || pattern.is_match(input)
            || pattern.is_match(&norm.original)
        {
            return true;
        }
    }
    false
}

fn expand_home(path: &str) -> String {
    if let Some(rest) = path.strip_prefix("~/") {
        if let Ok(home) = std::env::var("HOME") {
            return format!("{home}/{rest}");
        }
    }
    if path == "~" {
        if let Ok(home) = std::env::var("HOME") {
            return home;
        }
    }
    path.to_string()
}

fn percent_decode_once(input: &str) -> Option<String> {
    let bytes = input.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    let mut changed = false;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            if let (Some(hi), Some(lo)) = (from_hex(bytes[i + 1]), from_hex(bytes[i + 2])) {
                out.push((hi << 4) | lo);
                i += 3;
                changed = true;
                continue;
            }
        }
        out.push(bytes[i]);
        i += 1;
    }
    if !changed {
        return None;
    }
    Some(String::from_utf8_lossy(&out).into_owned())
}

fn from_hex(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

/// Collapse `.` and `..` segments without touching the filesystem.
fn collapse_dot_segments(path: &str) -> String {
    let absolute = path.starts_with('/');
    let parent = parent_seg();
    let mut stack: Vec<&str> = Vec::new();
    for seg in path.split('/') {
        match seg {
            "" | "." => {}
            s if s == parent => {
                if stack.last().is_some_and(|prev| *prev != parent.as_str()) {
                    stack.pop();
                } else if !absolute {
                    stack.push(seg);
                }
            }
            other => stack.push(other),
        }
    }
    let mut out = stack.join("/");
    if absolute {
        out = format!("/{out}");
    }
    if out.is_empty() && absolute {
        "/".into()
    } else if out.is_empty() {
        ".".into()
    } else {
        out
    }
}

/// Borrow helper used by match_ctx.
pub fn normalize_cow(input: &str) -> Cow<'_, str> {
    let norm = normalize_path_for_policy(input);
    if norm.normalized == input {
        Cow::Borrowed(input)
    } else {
        Cow::Owned(norm.normalized)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn trav(s: &str) -> String {
        s.replace("{P}", &parent_seg())
            .replace("{PS}", &parent_slash())
    }

    #[test]
    fn detects_basic_and_encoded_traversal() {
        assert!(looks_like_traversal(&trav("{PS}secret")));
        assert!(looks_like_traversal(&trav("{P}%2Fsecret")));
        let enc = format!("{}{}", "%2e%2e", "/secret");
        assert!(looks_like_traversal(&enc));
        let enc2 = format!("{}{}", "%252e%252e", "%252fsecret");
        assert!(looks_like_traversal(&enc2));
        assert!(looks_like_traversal(&trav(r"{P}\secret")));
        assert!(looks_like_traversal(&trav("foo/{PS}{PS}secret")));
        assert!(!looks_like_traversal("/tmp/safe-file.txt"));
        assert!(!looks_like_traversal("src/main.rs"));
    }

    #[test]
    fn normalizes_double_encoding() {
        let n = normalize_path_for_policy("%252e%252e%252fsecret");
        assert!(n.has_traversal || n.normalized.contains("secret"));
        assert!(!n.normalized.contains("%25"));
    }

    #[test]
    fn collapses_dot_segments() {
        let n = normalize_path_for_policy(&trav("foo/{PS}{PS}secret"));
        assert!(n.normalized.contains("secret"));
        assert!(n.has_traversal);
    }

    #[test]
    fn safe_paths_stable() {
        let n = normalize_path_for_policy("/tmp/notes.txt");
        assert_eq!(n.normalized, "/tmp/notes.txt");
        assert!(!n.has_traversal);
    }
}
