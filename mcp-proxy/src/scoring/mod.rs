//! Risk scoring facade.
//!
//! Open-core builds use a coarse local scorer. Enterprise builds use the advanced
//! weighted engine under [`crate::enterprise::scoring`].

mod types;

pub use types::*;

#[cfg(feature = "enterprise")]
pub use crate::enterprise::scoring::{
    RiskScoreCaps, RiskScoreConfig, RiskScoreEngine, RiskScoreWeights,
};

#[cfg(not(feature = "enterprise"))]
mod basic;

#[cfg(not(feature = "enterprise"))]
pub use basic::{RiskScoreCaps, RiskScoreConfig, RiskScoreEngine, RiskScoreWeights};
