//! Remote vs local approval selection.
//!
//! The control-plane [`RemoteApprovalEngine`] is enterprise-only. Open-core builds
//! keep local TTY approval and treat bare `remote` as unavailable.

#[cfg(feature = "enterprise")]
pub use crate::enterprise::approval::remote::*;

#[cfg(not(feature = "enterprise"))]
mod local;

#[cfg(not(feature = "enterprise"))]
pub use local::*;
