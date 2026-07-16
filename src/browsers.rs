//! Detection of the installed Chromium-family browsers, per OS (#609).
//!
//! WIP stub — types + catalogue land here; the per-OS probes + pure mapping
//! follow (TDD).

/// A detected Chromium-family browser (stub).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DetectedBrowser {
    /// Stable slug id (`chrome`, `edge`, `brave`, …).
    pub id: String,
}

/// Detect the installed Chromium-family browsers on this host (stub).
pub fn detect_installed() -> Vec<DetectedBrowser> {
    Vec::new()
}
