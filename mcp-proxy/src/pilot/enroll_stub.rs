//! Open-core enroll stub — cloud enrollment is enterprise-only.

use anyhow::{bail, Result};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EnrollArgs {
    pub control_plane: String,
    pub device_token: String,
    pub device_id: Option<String>,
    pub org_id: Option<String>,
}

pub fn run_enroll(_args: EnrollArgs) -> Result<()> {
    bail!("enroll requires the enterprise build (control-plane device tokens)")
}
