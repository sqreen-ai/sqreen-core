//! Evaluation dispatch shared by generated wasm exports.

use alloc::string::String;
use alloc::string::ToString;

use crate::{
    apply_decision, memory, Decision, EvaluationContext, PolicyPlugin, DECISION_BLOCK,
};

/// Shared `evaluate_policy` implementation used by [`crate::export_policy_plugin`].
pub fn dispatch_evaluate<P: PolicyPlugin>(input_len: i32) -> i32 {
    match evaluate_plugin::<P>(input_len) {
        Ok(code) => code,
        Err(error) => match apply_decision(Decision::block(error.to_string())) {
            Ok(code) => code,
            Err(_) => DECISION_BLOCK,
        },
    }
}

fn evaluate_plugin<P: PolicyPlugin>(input_len: i32) -> Result<i32, SdkError> {
    if input_len < 0 {
        return Err(SdkError::InvalidInputLength(input_len));
    }

    memory::reset_scratch();

    let bytes = memory::read_input(input_len as usize)?;
    let raw = core::str::from_utf8(&bytes)
        .map_err(|error| SdkError::InvalidUtf8(error.to_string()))?;
    let ctx = EvaluationContext::from_json(raw)?;
    let decision = P::evaluate(&ctx);
    apply_decision(decision)
}

/// SDK error surfaced to plugin authors and fail-closed dispatch paths.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SdkError {
    InvalidInputLength(i32),
    InputTooLarge { len: usize, max: usize },
    InvalidUtf8(String),
    InvalidJson(String),
    ScratchOverflow,
}

impl core::fmt::Display for SdkError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::InvalidInputLength(len) => write!(f, "invalid input length: {len}"),
            Self::InputTooLarge { len, max } => {
                write!(f, "input length {len} exceeds sdk limit {max}")
            }
            Self::InvalidUtf8(message) => write!(f, "input was not valid utf-8: {message}"),
            Self::InvalidJson(message) => write!(f, "invalid evaluation json: {message}"),
            Self::ScratchOverflow => write!(f, "guest scratch buffer overflow"),
        }
    }
}
