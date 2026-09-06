//! Cloud control-plane client facade.
//!
//! Full HTTP client lives under [`crate::enterprise::cloud_client`] and is compiled
//! only with the `enterprise` feature. Open-core builds expose a stub that never
//! connects remotely so local enforcement stays authoritative offline.

#[cfg(feature = "enterprise")]
pub use crate::enterprise::cloud_client::*;

#[cfg(not(feature = "enterprise"))]
mod stub;

#[cfg(not(feature = "enterprise"))]
pub use stub::*;
