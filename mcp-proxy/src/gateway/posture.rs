//! Enforcement posture and policy availability — the control plane for "no policy".
//!
//! # Why this exists
//!
//! Historically [`super::Subsystem::PolicyMissing`] defaulted to **FAIL_OPEN**, so an
//! absent policy file silently turned a marketed security control into passthrough. That
//! is unacceptable for enforcing or managed deployments.
//!
//! This module makes the trade-off **explicit**:
//!
//! | Posture | Env value | Missing policy |
//! |---------|-----------|----------------|
//! | [`EnforcementPosture::Development`] | `development` | FAIL_OPEN + loud warning |
//! | [`EnforcementPosture::Enforcing`] | `enforcing` (default) | FAIL_CLOSED |
//! | [`EnforcementPosture::Managed`] | `managed` | FAIL_CLOSED |
//!
//! Adapters and entry points do not decide this. They build a gateway with
//! [`FailurePolicy::from_env`] (or an explicit policy) and receive the same
//! [`PolicyAvailability`] on every outcome.

use std::fmt;

use serde::{Deserialize, Serialize};

use super::failure::FailureMode;

/// Environment variable selecting [`EnforcementPosture`].
///
/// Accepts `development` / `dev` / `permissive`, `enforcing` / `protected`, or
/// `managed` / `fleet`. Unrecognized values warn and fall back to
/// [`EnforcementPosture::Enforcing`] — never to a weaker posture.
pub const ENFORCEMENT_POSTURE_ENV: &str = "SQREEN_ENFORCEMENT_POSTURE";

/// How Sqreen treats an unavailable declarative policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum EnforcementPosture {
    /// Local experimentation. Missing policy may fail open, but only when chosen explicitly.
    Development,
    /// Protected runtime. Missing / invalid policy denies security-sensitive evaluation.
    #[default]
    Enforcing,
    /// Fleet / cloud-managed. Same fail-closed rule; remote outage without a usable
    /// local/cached snapshot is treated as policy unavailable (not a silent allow).
    Managed,
}

impl EnforcementPosture {
    /// Parses [`ENFORCEMENT_POSTURE_ENV`], defaulting to [`EnforcementPosture::Enforcing`].
    pub fn from_env() -> Self {
        match std::env::var(ENFORCEMENT_POSTURE_ENV) {
            Ok(raw) => match raw.trim().to_ascii_lowercase().as_str() {
                "" => Self::Enforcing,
                "development" | "dev" | "permissive" => {
                    eprintln!(
                        "mcp-proxy: WARNING — {ENFORCEMENT_POSTURE_ENV}=development: \
                         missing declarative policy will FAIL OPEN. \
                         Sqreen is NOT enforcing a policy until one is loaded. \
                         Set {ENFORCEMENT_POSTURE_ENV}=enforcing for protected mode."
                    );
                    Self::Development
                }
                "enforcing" | "protected" => Self::Enforcing,
                "managed" | "fleet" | "enterprise" => Self::Managed,
                other => {
                    eprintln!(
                        "mcp-proxy: unrecognized {ENFORCEMENT_POSTURE_ENV}=`{other}`; \
                         using enforcing (expected development|enforcing|managed)"
                    );
                    Self::Enforcing
                }
            },
            Err(_) => Self::Enforcing,
        }
    }

    /// Stable wire / CLI token.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Development => "development",
            Self::Enforcing => "enforcing",
            Self::Managed => "managed",
        }
    }

    /// Operator-facing one-liner for banners and `demo`.
    pub fn enforcement_banner(self) -> &'static str {
        match self {
            Self::Development => {
                "posture=development — permissive: missing policy may FAIL OPEN (not protecting)"
            }
            Self::Enforcing => {
                "posture=enforcing — protected: missing/invalid policy DENIES tool execution"
            }
            Self::Managed => {
                "posture=managed — fleet: missing/invalid/unobtainable policy DENIES tool execution"
            }
        }
    }

    /// Returns `true` when an absent policy is allowed to fail open.
    pub fn allows_missing_policy_passthrough(self) -> bool {
        matches!(self, Self::Development)
    }

    /// Failure mode for [`super::Subsystem::PolicyMissing`].
    pub fn missing_policy_mode(self) -> FailureMode {
        if self.allows_missing_policy_passthrough() {
            FailureMode::FailOpen
        } else {
            FailureMode::FailClosed
        }
    }

    /// Returns `true` when a control-plane outage without a usable policy snapshot must deny.
    pub fn requires_usable_policy_snapshot(self) -> bool {
        matches!(self, Self::Enforcing | Self::Managed)
    }
}

impl fmt::Display for EnforcementPosture {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Machine-readable state of the declarative policy source for one evaluation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, Default)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum PolicyAvailability {
    /// A compiled policy snapshot is loaded and being evaluated.
    #[default]
    Available,
    /// No policy file / engine was configured.
    Missing,
    /// Policy bytes existed but could not be parsed or validated.
    Invalid,
    /// Policy path could not be read (permissions, I/O).
    Unreadable,
    /// Using a previously loaded snapshot after a refresh failure (still enforcing that snapshot).
    Stale,
    /// Managed/remote source unreachable and no local/cache snapshot is usable.
    RemoteUnavailable,
}

impl PolicyAvailability {
    /// Stable wire token (also used in outcome metadata).
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Available => "AVAILABLE",
            Self::Missing => "MISSING",
            Self::Invalid => "INVALID",
            Self::Unreadable => "UNREADABLE",
            Self::Stale => "STALE",
            Self::RemoteUnavailable => "REMOTE_UNAVAILABLE",
        }
    }

    /// Returns `true` when evaluation has a declarative engine to run.
    pub fn has_engine(self) -> bool {
        matches!(self, Self::Available | Self::Stale)
    }

    /// Returns `true` when the posture should treat this as policy unavailable for deny.
    pub fn is_unavailable(self) -> bool {
        !self.has_engine()
    }
}

impl fmt::Display for PolicyAvailability {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_posture_is_enforcing_and_fail_closed() {
        assert_eq!(EnforcementPosture::default(), EnforcementPosture::Enforcing);
        assert_eq!(
            EnforcementPosture::Enforcing.missing_policy_mode(),
            FailureMode::FailClosed
        );
        assert_eq!(
            EnforcementPosture::Managed.missing_policy_mode(),
            FailureMode::FailClosed
        );
        assert_eq!(
            EnforcementPosture::Development.missing_policy_mode(),
            FailureMode::FailOpen
        );
    }
}
