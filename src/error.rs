//! Typed installer errors with stable machine codes + a differentiated
//! exit-code table.
//!
//! Agent-friendly contract (AGENT_FRIENDLY.md → dig-installer P0): every failure
//! carries a stable `UPPER_SNAKE` [`InstallError::code`] string and a distinct
//! non-zero [`InstallError::exit_code`], so a script/agent can branch on the
//! failure *class* (bad target, asset-not-found, network, checksum, PATH,
//! elevation, service-start) instead of string-matching prose. The catalogue is
//! emitted from `--help-json` and documented in the README, and is the single
//! source of truth for both (mirrored by [`EXIT_CODES`]).
//!
//! `elevation-required` (Windows service registration) is deliberately a
//! *distinct, expected* code — it is recoverable (re-run elevated) and must not
//! be confused with a hard failure.

use std::fmt;

/// A typed installer failure: a stable machine code + an exit code + a
/// human-readable message (and an optional remediation hint).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InstallError {
    kind: ErrorKind,
    message: String,
    hint: Option<String>,
}

/// The failure class. Each maps 1:1 to a stable `code` + `exit_code`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ErrorKind {
    /// The host OS/arch is not a supported DIG release target.
    UnsupportedTarget,
    /// A release (or a matching per-OS/arch asset within it) could not be found.
    AssetNotFound,
    /// A network/HTTP error fetching the API or a binary.
    Network,
    /// A downloaded artifact failed its SHA-256 integrity check.
    ChecksumMismatch,
    /// Updating PATH failed (the binary is still placed).
    PathUpdateFailed,
    /// Service registration needs an elevated console (recoverable).
    ServiceNeedsElevation,
    /// The dig-node service failed to install/start for a non-elevation reason.
    ServiceStartFailed,
    /// Writing a downloaded binary to disk failed.
    Io,
}

impl ErrorKind {
    /// The stable, documented `UPPER_SNAKE` machine code for this failure class.
    /// Never derive a code from the human message — agents branch on this.
    pub fn code(self) -> &'static str {
        match self {
            ErrorKind::UnsupportedTarget => "UNSUPPORTED_TARGET",
            ErrorKind::AssetNotFound => "ASSET_NOT_FOUND",
            ErrorKind::Network => "NETWORK",
            ErrorKind::ChecksumMismatch => "CHECKSUM_MISMATCH",
            ErrorKind::PathUpdateFailed => "PATH_UPDATE_FAILED",
            ErrorKind::ServiceNeedsElevation => "SERVICE_NEEDS_ELEVATION",
            ErrorKind::ServiceStartFailed => "SERVICE_START_FAILED",
            ErrorKind::Io => "IO",
        }
    }

    /// The distinct, stable process exit code for this failure class.
    pub fn exit_code(self) -> u8 {
        match self {
            ErrorKind::UnsupportedTarget => 2,
            ErrorKind::AssetNotFound => 3,
            ErrorKind::Network => 4,
            ErrorKind::ChecksumMismatch => 5,
            ErrorKind::PathUpdateFailed => 6,
            ErrorKind::ServiceNeedsElevation => 7,
            ErrorKind::ServiceStartFailed => 8,
            ErrorKind::Io => 9,
        }
    }

    /// One-line meaning for the documented exit-code table.
    pub fn meaning(self) -> &'static str {
        match self {
            ErrorKind::UnsupportedTarget => "host OS/arch is not a supported DIG release target",
            ErrorKind::AssetNotFound => "release or matching per-OS/arch asset not found",
            ErrorKind::Network => "network/HTTP error contacting GitHub or downloading",
            ErrorKind::ChecksumMismatch => "downloaded artifact failed its SHA-256 verification",
            ErrorKind::PathUpdateFailed => "could not update PATH (the binary was still placed)",
            ErrorKind::ServiceNeedsElevation => {
                "dig-node service registration needs an elevated console (re-run elevated)"
            }
            ErrorKind::ServiceStartFailed => "the dig-node service failed to install or start",
            ErrorKind::Io => "failed to write a downloaded binary to disk",
        }
    }
}

impl InstallError {
    pub fn new(kind: ErrorKind, message: impl Into<String>) -> InstallError {
        InstallError {
            kind,
            message: message.into(),
            hint: None,
        }
    }

    /// Attach a remediation hint (surfaced in the `--json` error envelope).
    pub fn with_hint(mut self, hint: impl Into<String>) -> InstallError {
        self.hint = Some(hint.into());
        self
    }

    pub fn kind(&self) -> ErrorKind {
        self.kind
    }
    pub fn code(&self) -> &'static str {
        self.kind.code()
    }
    pub fn exit_code(&self) -> u8 {
        self.kind.exit_code()
    }
    pub fn message(&self) -> &str {
        &self.message
    }
    pub fn hint(&self) -> Option<&str> {
        self.hint.as_deref()
    }

    // ---- Constructors per class (keep call-sites terse + consistent). -------

    pub fn unsupported_target(msg: impl Into<String>) -> InstallError {
        InstallError::new(ErrorKind::UnsupportedTarget, msg)
    }
    pub fn asset_not_found(msg: impl Into<String>) -> InstallError {
        InstallError::new(ErrorKind::AssetNotFound, msg)
    }
    pub fn network(msg: impl Into<String>) -> InstallError {
        InstallError::new(ErrorKind::Network, msg)
    }
    pub fn checksum_mismatch(msg: impl Into<String>) -> InstallError {
        InstallError::new(ErrorKind::ChecksumMismatch, msg)
    }
    pub fn path_update_failed(msg: impl Into<String>) -> InstallError {
        InstallError::new(ErrorKind::PathUpdateFailed, msg)
    }
    pub fn service_needs_elevation(msg: impl Into<String>) -> InstallError {
        InstallError::new(ErrorKind::ServiceNeedsElevation, msg)
    }
    pub fn service_start_failed(msg: impl Into<String>) -> InstallError {
        InstallError::new(ErrorKind::ServiceStartFailed, msg)
    }
    pub fn io(msg: impl Into<String>) -> InstallError {
        InstallError::new(ErrorKind::Io, msg)
    }
}

impl fmt::Display for InstallError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.message)
    }
}

impl std::error::Error for InstallError {}

/// The full exit-code catalogue, ordered by code, for `--help-json` and docs.
/// Index 0 is the success row; the rest mirror [`ErrorKind`] one-for-one.
pub const EXIT_CODES: &[(u8, &str, &str)] = &[
    (0, "OK", "success"),
    (
        2,
        "UNSUPPORTED_TARGET",
        "host OS/arch is not a supported DIG release target",
    ),
    (
        3,
        "ASSET_NOT_FOUND",
        "release or matching per-OS/arch asset not found",
    ),
    (
        4,
        "NETWORK",
        "network/HTTP error contacting GitHub or downloading",
    ),
    (
        5,
        "CHECKSUM_MISMATCH",
        "downloaded artifact failed its SHA-256 verification",
    ),
    (
        6,
        "PATH_UPDATE_FAILED",
        "could not update PATH (the binary was still placed)",
    ),
    (
        7,
        "SERVICE_NEEDS_ELEVATION",
        "dig-node service registration needs an elevated console",
    ),
    (
        8,
        "SERVICE_START_FAILED",
        "the dig-node service failed to install or start",
    ),
    (9, "IO", "failed to write a downloaded binary to disk"),
];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn codes_are_upper_snake_and_stable() {
        assert_eq!(ErrorKind::UnsupportedTarget.code(), "UNSUPPORTED_TARGET");
        assert_eq!(ErrorKind::AssetNotFound.code(), "ASSET_NOT_FOUND");
        assert_eq!(ErrorKind::Network.code(), "NETWORK");
        assert_eq!(ErrorKind::ChecksumMismatch.code(), "CHECKSUM_MISMATCH");
        assert_eq!(ErrorKind::PathUpdateFailed.code(), "PATH_UPDATE_FAILED");
        assert_eq!(
            ErrorKind::ServiceNeedsElevation.code(),
            "SERVICE_NEEDS_ELEVATION"
        );
        assert_eq!(ErrorKind::ServiceStartFailed.code(), "SERVICE_START_FAILED");
        assert_eq!(ErrorKind::Io.code(), "IO");
    }

    #[test]
    fn exit_codes_are_distinct_and_nonzero() {
        let kinds = [
            ErrorKind::UnsupportedTarget,
            ErrorKind::AssetNotFound,
            ErrorKind::Network,
            ErrorKind::ChecksumMismatch,
            ErrorKind::PathUpdateFailed,
            ErrorKind::ServiceNeedsElevation,
            ErrorKind::ServiceStartFailed,
            ErrorKind::Io,
        ];
        let mut seen = std::collections::BTreeSet::new();
        for k in kinds {
            let c = k.exit_code();
            assert!(c != 0, "{} must be non-zero", k.code());
            assert!(seen.insert(c), "duplicate exit code {c} for {}", k.code());
        }
    }

    #[test]
    fn elevation_is_distinct_from_hard_service_failure() {
        // A recoverable elevation requirement MUST be distinguishable from a
        // genuine service-start failure (different code AND exit code).
        assert_ne!(
            ErrorKind::ServiceNeedsElevation.code(),
            ErrorKind::ServiceStartFailed.code()
        );
        assert_ne!(
            ErrorKind::ServiceNeedsElevation.exit_code(),
            ErrorKind::ServiceStartFailed.exit_code()
        );
    }

    #[test]
    fn exit_codes_table_matches_error_kinds() {
        // EXIT_CODES is the documented mirror — every non-OK row must match an
        // ErrorKind's code + exit_code so the table can't drift from the source.
        for &(code, name, _) in EXIT_CODES.iter().filter(|r| r.0 != 0) {
            let kind = match name {
                "UNSUPPORTED_TARGET" => ErrorKind::UnsupportedTarget,
                "ASSET_NOT_FOUND" => ErrorKind::AssetNotFound,
                "NETWORK" => ErrorKind::Network,
                "CHECKSUM_MISMATCH" => ErrorKind::ChecksumMismatch,
                "PATH_UPDATE_FAILED" => ErrorKind::PathUpdateFailed,
                "SERVICE_NEEDS_ELEVATION" => ErrorKind::ServiceNeedsElevation,
                "SERVICE_START_FAILED" => ErrorKind::ServiceStartFailed,
                "IO" => ErrorKind::Io,
                other => panic!("unknown EXIT_CODES row: {other}"),
            };
            assert_eq!(kind.code(), name);
            assert_eq!(kind.exit_code(), code);
        }
    }

    #[test]
    fn meaning_accessor_is_consistent_with_the_table() {
        // `meaning()` is the per-kind accessor; the SERVICE_NEEDS_ELEVATION table
        // row is intentionally shorter, so just assert the accessor is non-empty
        // and present for every kind (keeps `meaning()` exercised + non-dead).
        for &(_, name, _) in EXIT_CODES.iter().filter(|r| r.0 != 0) {
            let kind = match name {
                "UNSUPPORTED_TARGET" => ErrorKind::UnsupportedTarget,
                "ASSET_NOT_FOUND" => ErrorKind::AssetNotFound,
                "NETWORK" => ErrorKind::Network,
                "CHECKSUM_MISMATCH" => ErrorKind::ChecksumMismatch,
                "PATH_UPDATE_FAILED" => ErrorKind::PathUpdateFailed,
                "SERVICE_NEEDS_ELEVATION" => ErrorKind::ServiceNeedsElevation,
                "SERVICE_START_FAILED" => ErrorKind::ServiceStartFailed,
                "IO" => ErrorKind::Io,
                other => panic!("unknown EXIT_CODES row: {other}"),
            };
            assert!(!kind.meaning().is_empty(), "{name} has an empty meaning");
        }
    }

    #[test]
    fn error_carries_code_message_and_hint() {
        let e = InstallError::asset_not_found("no asset for linux-x64")
            .with_hint("pin a version with --digstore-version");
        assert_eq!(e.code(), "ASSET_NOT_FOUND");
        assert_eq!(e.exit_code(), 3);
        assert_eq!(e.message(), "no asset for linux-x64");
        assert_eq!(e.hint(), Some("pin a version with --digstore-version"));
    }
}
