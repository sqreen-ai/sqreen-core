//! Dynamic risk scoring, DLP heuristics, and interactive terminal confirmation.
//!
//! # Security invariants (fail-closed)
//!
//! - Prompt failures, I/O errors, and parse failures during the risk gate default to **deny**.
//! - DLP masking runs on the client→server path before downstream forwarding; masked payloads
//!   never leave the edge without substitution when a pattern matches.
//! - Risk scoring bonuses are applied at most once per vector per evaluation to prevent
//!   score inflation from repeated substrings in large JSON trees.
//!
//! # Thread safety
//!
//! All functions in this module are **synchronous and stateless** except
//! [`prompt_user_confirmation`], which offloads blocking `/dev/tty` I/O to
//! `tokio::task::spawn_blocking`. Regex engines are compiled once via [`LazyLock`]
//! and are immutable after initialization — safe to call concurrently from multiple
//! relay tasks once constructed.
//!
//! # Memory and mutation boundaries
//!
//! - Inbound `params_json` is parsed into an owned [`serde_json::Value`] tree only when
//!   DLP or scoring requires traversal; clean payloads short-circuit via
//!   [`string_needs_scan`].
//! - Masking mutates the JSON tree in place and re-serializes to an owned `String` only
//!   when at least one segment was replaced with [`MASK_TOKEN`].
//! - Scratch buffers for regex replacement allocate transient `String` values on the
//!   Tokio worker stack/heap; no zero-copy views escape this module.

use std::collections::HashMap;
use std::io::{Read, Write};
use std::sync::LazyLock;

use anyhow::{Context, Result};
use regex::Regex;
use serde_json::Value;

/// Default risk score threshold when no policy file is loaded.
pub const DEFAULT_RISK_THRESHOLD: u8 = 70;

/// Environment variable override for the risk confirmation threshold.
pub const RISK_THRESHOLD_ENV: &str = "MCP_RISK_THRESHOLD";

/// Replacement token written over redacted sensitive segments.
pub const MASK_TOKEN: &str = "[MASKED_PII_BY_PROXY]";

/// Shannon entropy (bits/char) above which a sliding window is treated as obfuscated.
const WINDOW_ENTROPY_THRESHOLD: f64 = 4.5;

/// Minimum string length before any entropy heuristics apply.
const MIN_ENTROPY_STRING_LEN: usize = 16;

/// Minimum string length before sliding-window entropy analysis runs.
const MIN_WINDOW_SCAN_LEN: usize = 48;

/// Sliding-window size for localized entropy spikes.
const ENTROPY_WINDOW_SIZE: usize = 32;

/// Step size between consecutive entropy windows.
const ENTROPY_WINDOW_STEP: usize = 16;

const PII_RISK_BONUS: i32 = 30;
const LUHN_RISK_BONUS: i32 = 40;
const ENTROPY_RISK_BONUS: i32 = 20;

static SSN_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\b\d{3}-\d{2}-\d{4}\b").expect("valid SSN regex"));
static DB_URL_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)(?:postgres|mongodb|mysql)://[^\s"']+"#).expect("valid DB URL regex")
});

/// Outcome of a single-pass risk analysis over tool-call parameters.
///
/// `sanitized_params` is `Some` only when structural masking occurred; callers must
/// rewrite the outbound JSON-RPC frame before forwarding.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RiskAnalysis {
    pub score: u8,
    pub sanitized_params: Option<String>,
}

/// Validates a numeric string (formatted or raw) with the Luhn checksum.
pub fn is_luhn_valid(s: &str) -> bool {
    let digits: Vec<u8> = s
        .bytes()
        .filter(|byte| byte.is_ascii_digit())
        .map(|byte| byte - b'0')
        .collect();

    if !(13..=16).contains(&digits.len()) {
        return false;
    }

    luhn_checksum(&digits)
}

/// Calculates a clamped risk score (0–100) for a tool invocation.
pub fn calculate_risk_score(tool_name: &str, params_json: &str) -> u8 {
    analyze_params(tool_name, params_json).score
}

/// Calculates a real-time risk index \[0, 100\] for an incoming tool call.
///
/// ### Threat heuristics and scoring vectors
/// 1. **Base severity matrix** — Core OS execution vectors (e.g. `execute_bash`) start at a
///    high base severity floor (75) due to raw systemic execution capabilities.
/// 2. **PII and data-loss risk** — Scans parameters for structural patterns matching Social
///    Security Numbers or localized database connection URIs (+30 penalty, once per evaluation).
/// 3. **Financial exfiltration (Luhn check)** — Extracts raw digit streams (13–16 chars).
///    Passing Luhn verification triggers an immediate high-severity penalty (+40).
/// 4. **Sliding-window Shannon entropy analysis** — Evaluates high-entropy windows (32-char
///    chunks, step 16) to flag potential obfuscation, base64 payloads, or indirect prompt
///    injections (+20).
///
/// ### Performance and mutation properties
/// To optimize throughput, strings are pre-checked via [`string_needs_scan`] to bypass clean
/// assets. If structural threats are identified, this method performs a mutating copy, applying
/// a localized [`MASK_TOKEN`] substitution across the target JSON string values.
pub fn analyze_params(tool_name: &str, params_json: &str) -> RiskAnalysis {
    let mut score = base_tool_risk(tool_name) as i32;
    let mut state = ScanState::default();

    match serde_json::from_str::<Value>(params_json) {
        Ok(mut value) => {
            scan_value(&mut value, &mut score, &mut state);
            let sanitized_params = if state.masked {
                serde_json::to_string(&value).ok()
            } else {
                None
            };
            RiskAnalysis {
                score: score.clamp(0, 100) as u8,
                sanitized_params,
            }
        }
        Err(_) => analyze_raw_params(params_json, score),
    }
}

/// Prompts the local operator for manual confirmation via `/dev/tty` or stderr fallback.
///
/// # Fail-closed invariant
/// Any prompt failure, panic in the blocking task, or empty read defaults to **`false`
/// (deny)** so high-risk frames never bypass operator review silently.
///
/// # Threading model
/// Blocking terminal I/O runs on the Tokio blocking pool; the stdio relay task awaits the
/// result without holding an OS read lock on the JSON-RPC stream beyond this await point.
///
/// Returns `true` when the user presses `y`/`Y`, `false` for `n`/`N` or Enter.
pub async fn prompt_user_confirmation(tool_name: &str, score: u8, payload: &str) -> bool {
    let tool_name = tool_name.to_string();
    let payload = payload.to_string();

    match tokio::task::spawn_blocking(move || prompt_user_confirmation_sync(&tool_name, score, &payload))
        .await
    {
        Ok(Ok(approved)) => approved,
        Ok(Err(error)) => {
            eprintln!("mcp-proxy: risk prompt failed ({error:#}); defaulting to deny");
            false
        }
        Err(_) => {
            eprintln!("mcp-proxy: risk prompt task panicked; defaulting to deny");
            false
        }
    }
}

/// Resolves the active risk threshold from policy config or environment.
pub fn resolve_risk_threshold(configured: Option<u8>) -> u8 {
    if let Ok(raw) = std::env::var(RISK_THRESHOLD_ENV) {
        if let Ok(parsed) = raw.parse::<u8>() {
            return parsed;
        }
    }

    configured.unwrap_or(DEFAULT_RISK_THRESHOLD)
}

/// Outcome after threat-intel and behavioral layers are applied to a base score.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SecurityLayerEvaluation {
    pub effective_score: u8,
    pub force_confirmation_gate: bool,
    pub telemetry_marker: Option<&'static str>,
}

/// Merges IOC and behavioral detections into a single gate/score decision.
///
/// Either signal forces the `/dev/tty` confirmation gate. IOC matches add
/// [`crate::threat_intel::IOC_RISK_PENALTY`]; behavioral chains clamp to 100.
pub fn apply_security_layers(
    base_score: u8,
    ioc_match: bool,
    behavioral_anomaly: bool,
) -> SecurityLayerEvaluation {
    use crate::behavior::TELEMETRY_BEHAVIORAL_CHAIN;
    use crate::threat_intel::{IOC_RISK_PENALTY, TELEMETRY_IOC_MATCH};

    let mut score = base_score;
    let mut force_gate = false;
    let mut marker = None;

    if ioc_match {
        score = score.saturating_add(IOC_RISK_PENALTY).min(100);
        force_gate = true;
        marker = Some(TELEMETRY_IOC_MATCH);
    }

    if behavioral_anomaly {
        score = 100;
        force_gate = true;
        marker = Some(TELEMETRY_BEHAVIORAL_CHAIN);
    }

    SecurityLayerEvaluation {
        effective_score: score,
        force_confirmation_gate: force_gate,
        telemetry_marker: marker,
    }
}

#[derive(Default)]
struct ScanState {
    masked: bool,
    pii_detected: bool,
    luhn_detected: bool,
    entropy_detected: bool,
}

#[derive(Default, Clone, Copy)]
struct StringScanFlags {
    pii: bool,
    luhn: bool,
    entropy: bool,
    masked: bool,
}

impl StringScanFlags {
    fn any_signal(self) -> bool {
        self.pii || self.luhn || self.entropy
    }
}

fn analyze_raw_params(params_json: &str, base_score: i32) -> RiskAnalysis {
    let mut score = base_score;
    let mut state = ScanState::default();
    let (sanitized, flags) = scan_string(params_json);

    apply_string_flags(flags, &mut score, &mut state);
    RiskAnalysis {
        score: score.clamp(0, 100) as u8,
        sanitized_params: if state.masked {
            Some(sanitized)
        } else {
            None
        },
    }
}

fn scan_value(value: &mut Value, score: &mut i32, state: &mut ScanState) {
    match value {
        Value::String(text) => {
            let (sanitized, flags) = scan_string(text);
            apply_string_flags(flags, score, state);
            if flags.masked {
                *text = sanitized;
                state.masked = true;
            }
        }
        Value::Array(items) => {
            for item in items {
                scan_value(item, score, state);
            }
        }
        Value::Object(map) => {
            for item in map.values_mut() {
                scan_value(item, score, state);
            }
        }
        _ => {}
    }
}

fn apply_string_flags(flags: StringScanFlags, score: &mut i32, state: &mut ScanState) {
    if flags.pii && !state.pii_detected {
        *score += PII_RISK_BONUS;
        state.pii_detected = true;
    }
    if flags.luhn && !state.luhn_detected {
        *score += LUHN_RISK_BONUS;
        state.luhn_detected = true;
    }
    if flags.entropy && !state.entropy_detected {
        *score += ENTROPY_RISK_BONUS;
        state.entropy_detected = true;
    }
    if flags.masked {
        state.masked = true;
    }
}

fn scan_string(text: &str) -> (String, StringScanFlags) {
    if !string_needs_scan(text) {
        return (text.to_string(), StringScanFlags::default());
    }

    let mut flags = StringScanFlags::default();
    let mut current = text.to_string();

    if SSN_RE.is_match(&current) {
        current = SSN_RE.replace_all(&current, MASK_TOKEN).into_owned();
        flags.pii = true;
        flags.masked = true;
    }

    if DB_URL_RE.is_match(&current) {
        current = DB_URL_RE.replace_all(&current, MASK_TOKEN).into_owned();
        flags.pii = true;
        flags.masked = true;
    } else if contains_db_scheme(&current) {
        flags.pii = true;
    }

    let (luhn_sanitized, luhn_masked) = mask_luhn_sequences(&current);
    if luhn_masked {
        current = luhn_sanitized;
        flags.luhn = true;
        flags.masked = true;
    } else if contains_luhn_sequence(&current) {
        flags.luhn = true;
    }

    let (entropy_sanitized, entropy_masked) = mask_high_entropy_windows(&current);
    if entropy_masked {
        current = entropy_sanitized;
        flags.entropy = true;
        flags.masked = true;
    } else if sliding_entropy_detected(&current) {
        flags.entropy = true;
    }

    if flags.any_signal() || flags.masked {
        (current, flags)
    } else {
        (text.to_string(), StringScanFlags::default())
    }
}

fn string_needs_scan(text: &str) -> bool {
    if text.len() < 8 {
        return false;
    }

    text.contains('-')
        || text.contains("://")
        || text.len() >= MIN_ENTROPY_STRING_LEN
        || text.bytes().any(|byte| byte.is_ascii_digit())
}

fn contains_db_scheme(text: &str) -> bool {
    text.contains("postgres://")
        || text.contains("mongodb://")
        || text.contains("mysql://")
}

fn luhn_checksum(digits: &[u8]) -> bool {
    let mut sum = 0_u32;

    for (index, digit) in digits.iter().rev().copied().enumerate() {
        let mut value = u32::from(digit);
        if index % 2 == 1 {
            value *= 2;
            if value > 9 {
                value -= 9;
            }
        }
        sum += value;
    }

    sum % 10 == 0
}

fn contains_luhn_sequence(text: &str) -> bool {
    extract_digit_runs(text)
        .into_iter()
        .any(|run| is_luhn_valid(&run))
}

fn mask_luhn_sequences(text: &str) -> (String, bool) {
    let mut masked = false;
    let mut output = String::with_capacity(text.len());
    let mut index = 0;
    let chars: Vec<(usize, char)> = text.char_indices().collect();

    while index < chars.len() {
        let Some((end_index, digits)) = read_card_candidate(&chars, index) else {
            output.push(chars[index].1);
            index += 1;
            continue;
        };

        if is_luhn_valid(&digits) {
            output.push_str(MASK_TOKEN);
            masked = true;
            index = end_index;
            continue;
        }

        output.push(chars[index].1);
        index += 1;
    }

    (output, masked)
}

fn read_card_candidate(chars: &[(usize, char)], start: usize) -> Option<(usize, String)> {
    let mut index = start;
    let mut digits = String::new();

    while index < chars.len() {
        let ch = chars[index].1;
        if ch.is_ascii_digit() {
            digits.push(ch);
            index += 1;
            continue;
        }

        if (ch == '-' || ch == ' ') && index + 1 < chars.len() && chars[index + 1].1.is_ascii_digit()
        {
            index += 1;
            continue;
        }

        break;
    }

    if (13..=16).contains(&digits.len()) {
        Some((index, digits))
    } else {
        None
    }
}

fn extract_digit_runs(text: &str) -> Vec<String> {
    let mut runs = Vec::new();
    let mut current = String::new();

    for ch in text.chars() {
        if ch.is_ascii_digit() {
            current.push(ch);
            continue;
        }

        if (13..=16).contains(&current.len()) {
            runs.push(current.clone());
        }
        current.clear();

        if ch == '-' || ch == ' ' {
            continue;
        }
    }

    if (13..=16).contains(&current.len()) {
        runs.push(current);
    }

    runs
}

fn sliding_entropy_detected(text: &str) -> bool {
    let chars: Vec<char> = text.chars().collect();

    if chars.len() >= MIN_WINDOW_SCAN_LEN {
        let mut start = 0;
        while start + ENTROPY_WINDOW_SIZE <= chars.len() {
            let window: String = chars[start..start + ENTROPY_WINDOW_SIZE]
                .iter()
                .collect();
            if shannon_entropy(&window) >= WINDOW_ENTROPY_THRESHOLD {
                return true;
            }
            start += ENTROPY_WINDOW_STEP;
        }
        return false;
    }

    chars.len() >= MIN_ENTROPY_STRING_LEN
        && shannon_entropy(text) >= WINDOW_ENTROPY_THRESHOLD
}

fn mask_high_entropy_windows(text: &str) -> (String, bool) {
    let chars: Vec<char> = text.chars().collect();

    if chars.len() < MIN_ENTROPY_STRING_LEN {
        return (text.to_string(), false);
    }

    let mut ranges = Vec::new();

    if chars.len() >= MIN_WINDOW_SCAN_LEN {
        let mut start = 0;
        while start + ENTROPY_WINDOW_SIZE <= chars.len() {
            let window: String = chars[start..start + ENTROPY_WINDOW_SIZE]
                .iter()
                .collect();
            if shannon_entropy(&window) >= WINDOW_ENTROPY_THRESHOLD {
                ranges.push((start, start + ENTROPY_WINDOW_SIZE));
            }
            start += ENTROPY_WINDOW_STEP;
        }
    } else if shannon_entropy(text) >= WINDOW_ENTROPY_THRESHOLD {
        ranges.push((0, chars.len()));
    }

    if ranges.is_empty() {
        return (text.to_string(), false);
    }

    let merged = merge_ranges(ranges);
    let mut output = String::new();
    let mut cursor = 0;

    for (start, end) in merged {
        output.extend(chars[cursor..start].iter());
        output.push_str(MASK_TOKEN);
        cursor = end;
    }

    output.extend(chars[cursor..].iter());
    (output, true)
}

fn merge_ranges(mut ranges: Vec<(usize, usize)>) -> Vec<(usize, usize)> {
    if ranges.is_empty() {
        return ranges;
    }

    ranges.sort_unstable_by_key(|range| range.0);
    let mut merged = vec![ranges[0]];

    for (start, end) in ranges.into_iter().skip(1) {
        let last = merged.len() - 1;
        if start <= merged[last].1 {
            merged[last].1 = merged[last].1.max(end);
        } else {
            merged.push((start, end));
        }
    }

    merged
}

fn shannon_entropy(text: &str) -> f64 {
    if text.is_empty() {
        return 0.0;
    }

    let mut counts = HashMap::new();
    for ch in text.chars() {
        *counts.entry(ch).or_insert(0_usize) += 1;
    }

    let length = text.chars().count() as f64;
    counts
        .values()
        .map(|&count| {
            let probability = count as f64 / length;
            -probability * probability.log2()
        })
        .sum()
}

fn prompt_user_confirmation_sync(tool_name: &str, score: u8, payload: &str) -> Result<bool> {
    let warning = render_warning_box(tool_name, score, payload);

    #[cfg(unix)]
    {
        if let Ok(approved) = prompt_via_dev_tty(&warning) {
            return Ok(approved);
        }
    }

    prompt_via_stderr(&warning)
}

#[cfg(unix)]
fn prompt_via_dev_tty(warning: &str) -> Result<bool> {
    use std::fs::OpenOptions;

    let mut tty = OpenOptions::new()
        .read(true)
        .write(true)
        .open("/dev/tty")
        .context("failed to open /dev/tty")?;

    tty.write_all(warning.as_bytes())
        .context("failed to write risk prompt to /dev/tty")?;
    tty.write_all(b"Allow this call? [y/N]: ")
        .context("failed to write risk prompt suffix")?;
    tty.flush().context("failed to flush /dev/tty")?;

    read_yes_no(&mut tty)
}

fn prompt_via_stderr(warning: &str) -> Result<bool> {
    let mut stderr = std::io::stderr();
    stderr
        .write_all(warning.as_bytes())
        .context("failed to write risk prompt to stderr")?;
    stderr
        .write_all(b"Allow this call? [y/N]: ")
        .context("failed to write risk prompt suffix to stderr")?;
    stderr.flush().context("failed to flush stderr")?;

    read_yes_no_from_stdin()
}

fn read_yes_no_from_stdin() -> Result<bool> {
    read_yes_no(&mut std::io::stdin())
}

fn read_yes_no(reader: &mut impl Read) -> Result<bool> {
    let mut buffer = [0_u8; 8];

    loop {
        let read = reader.read(&mut buffer).context("failed to read user confirmation")?;
        if read == 0 {
            return Ok(false);
        }

        for byte in &buffer[..read] {
            match *byte {
                b'y' | b'Y' => return Ok(true),
                b'n' | b'N' | b'\r' | b'\n' => return Ok(false),
                b' ' | b'\t' => continue,
                0x03 => return Ok(false),
                _ => continue,
            }
        }
    }
}

fn render_warning_box(tool_name: &str, score: u8, payload: &str) -> String {
    let preview = truncate_payload(payload, 220);
    let inner_width = 58_usize;

    let lines = vec![
        format!("Tool      : {tool_name}"),
        format!("Risk Score: {score} / 100"),
        "Action    : Manual confirmation required".to_string(),
        String::new(),
        "Payload preview:".to_string(),
        preview,
        String::new(),
        "The MCP stdio JSON stream is paused while you decide.".to_string(),
        "This prompt is rendered on /dev/tty — stdout stays clean.".to_string(),
    ];

    let mut output = String::new();
    output.push_str("\n");
    output.push_str(&format!("╔{}╗\n", "═".repeat(inner_width)));
    output.push_str(&format!(
        "║ {:<width$} ║\n",
        "MCP-PROXY HIGH RISK TOOL CALL",
        width = inner_width - 2
    ));
    output.push_str(&format!("╠{}╣\n", "═".repeat(inner_width)));

    for line in lines {
        for wrapped in wrap_line(&line, inner_width - 2) {
            output.push_str(&format!("║ {:<width$} ║\n", wrapped, width = inner_width - 2));
        }
    }

    output.push_str(&format!("╚{}╝\n", "═".repeat(inner_width)));
    output
}

fn wrap_line(line: &str, max_width: usize) -> Vec<String> {
    if line.is_empty() {
        return vec![String::new()];
    }

    if line.len() <= max_width {
        return vec![line.to_string()];
    }

    let mut chunks = Vec::new();
    let mut start = 0;
    while start < line.len() {
        let mut end = (start + max_width).min(line.len());
        while end > start && !line.is_char_boundary(end) {
            end -= 1;
        }
        chunks.push(line[start..end].to_string());
        start = end;
    }
    chunks
}

fn truncate_payload(payload: &str, max_len: usize) -> String {
    if payload.len() <= max_len {
        return payload.to_string();
    }

    format!("{}…", &payload[..max_len])
}

fn base_tool_risk(tool_name: &str) -> u8 {
    match tool_name {
        "read_file" | "read_text_file" | "read_media_file" => 20,
        "write_file" | "edit_file" | "apply_patch" => 60,
        "execute_bash" | "run_terminal_cmd" | "shell" | "bash" => 75,
        "fetch" | "web_search" | "browser_navigate" => 45,
        "delete_file" | "remove_file" => 65,
        _ => 30,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn assigns_base_risk_by_tool_family() {
        assert_eq!(calculate_risk_score("read_file", r#"{"arguments":{"path":"/tmp/a"}}"#), 20);
        assert_eq!(
            calculate_risk_score("execute_bash", r#"{"arguments":{"command":"ls"}}"#),
            75
        );
    }

    #[test]
    fn spikes_risk_for_high_entropy_strings() {
        let low = r#"{"arguments":{"command":"ls -la"}}"#;
        let high = r#"{"arguments":{"token":"YWJjZEFCRWZjR0hnSUlqa0xNTm9QUVJTVFVWV1hZWjAxMjM0NTY3ODk="}}"#;
        assert!(calculate_risk_score("read_file", high) >= calculate_risk_score("read_file", low) + 15);
    }

    #[test]
    fn clamps_score_to_100() {
        let params = format!(
            r#"{{"arguments":{{"ssn":"123-45-6789","db":"postgres://user:pass@db/internal","card":"4242 4242 4242 4242","blob":"{blob}"}}}}"#,
            blob = "YWJjZEFCRWZjR0hnSUlqa0xNTm9QUVJTVFVWV1hZWjAxMjM0NTY3ODk5YWJjZEFCRWZjR0hn"
        );
        assert!(calculate_risk_score("execute_bash", &params) <= 100);
    }

    #[test]
    fn resolves_threshold_from_environment() {
        std::env::set_var(RISK_THRESHOLD_ENV, "55");
        assert_eq!(resolve_risk_threshold(Some(70)), 55);
        std::env::remove_var(RISK_THRESHOLD_ENV);
    }

    #[test]
    fn validates_known_luhn_numbers() {
        assert!(is_luhn_valid("4242424242424242"));
        assert!(is_luhn_valid("4242-4242-4242-4242"));
        assert!(!is_luhn_valid("4242424242424243"));
        assert!(!is_luhn_valid("1234"));
    }

    #[test]
    fn detects_pii_and_financial_data() {
        let params = r#"{"arguments":{"note":"ssn 123-45-6789 and card 4242424242424242"}}"#;
        let analysis = analyze_params("read_file", params);
        assert!(analysis.score >= 20 + PII_RISK_BONUS as u8 + LUHN_RISK_BONUS as u8);
    }

    #[test]
    fn masks_sensitive_segments_in_params() {
        let params = r#"{"name":"read_file","arguments":{"path":"/tmp/x","secret":"postgres://user:pass@db/prod"}}"#;
        let analysis = analyze_params("read_file", params);
        let sanitized = analysis.sanitized_params.expect("sanitized params");
        assert!(sanitized.contains(MASK_TOKEN));
        assert!(!sanitized.contains("postgres://user:pass@db/prod"));
    }

    #[test]
    fn detects_database_connection_strings() {
        let params = r#"{"arguments":{"uri":"mongodb://admin:secret@127.0.0.1:27017/app"}}"#;
        let analysis = analyze_params("fetch", params);
        assert!(analysis.score >= 45 + PII_RISK_BONUS as u8);
    }

    #[test]
    fn clean_payloads_skip_deep_mutation() {
        let params = r#"{"arguments":{"command":"ls -la /tmp"}}"#;
        let analysis = analyze_params("execute_bash", params);
        assert!(analysis.sanitized_params.is_none());
    }

    #[test]
    fn security_layers_force_gate_on_ioc() {
        let eval = apply_security_layers(20, true, false);
        assert_eq!(eval.effective_score, 70);
        assert!(eval.force_confirmation_gate);
        assert_eq!(eval.telemetry_marker, Some("THREAT_INTEL_IOC_MATCH"));
    }

    #[test]
    fn security_layers_force_gate_on_behavioral_chain() {
        let eval = apply_security_layers(20, false, true);
        assert_eq!(eval.effective_score, 100);
        assert!(eval.force_confirmation_gate);
        assert_eq!(eval.telemetry_marker, Some("BEHAVIORAL_CHAIN_ANOMALY"));
    }

    #[test]
    fn behavioral_chain_overrides_ioc_marker() {
        let eval = apply_security_layers(80, true, true);
        assert_eq!(eval.effective_score, 100);
        assert_eq!(eval.telemetry_marker, Some("BEHAVIORAL_CHAIN_ANOMALY"));
    }
}
