//! Delegates the OS-DNS resolver wiring to the installed `dig-dns` binary
//! (#627 WU2) — the SINGLE source of the split-DNS activation now lives in
//! `dig-dns configure-os`, which (v0.14.0+) also flushes the resolver cache and
//! runs an end-to-end resolve VERIFY, returning whether resolution went LIVE.
//!
//! Before this, the installer's per-OS `dns::{windows,macos,linux}` modules each
//! carried their OWN copy of the resolver wiring (NRPT rule / `lo0` alias +
//! `/etc/resolver` / systemd-resolved drop-in) plus the browser DoH policy — a
//! second implementation that drifted from dig-dns's own `configure-os` (the
//! #627 root cause: dig-dns flushed the DNS cache on Linux/macOS but the
//! installer's duplicate flushed on none, so `.dig` names appeared to need a
//! reboot). WU2 removes that duplication: each per-OS `install`/`uninstall`
//! shells out to `dig-dns configure-os`/`unconfigure-os` and consumes the
//! machine-readable report.
//!
//! Security (#565/#657): the `dig-dns` binary is invoked by the ABSOLUTE path
//! the installer just wrote it to (threaded in from the install root) — never a
//! bare `dig-dns` name resolved through `PATH`, which an unprivileged user could
//! hijack for an elevated install. dig-dns itself spawns the OS resolver tools
//! (`powershell`, `resolvectl`, `dscacheutil`, …) by absolute path.

use std::path::Path;
use std::process::Command;

use serde::Deserialize;

use crate::proc::HideConsole;

/// The subset of `dig-dns`'s `OsConfigReport` (`configure-os`/`unconfigure-os`
/// `--json`) the installer consumes. Deserialized permissively — unknown fields
/// are ignored so a newer dig-dns that adds report fields never breaks parsing
/// (the machine-contract stability rule, CLAUDE.md §6.2).
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
pub struct OsConfigSummary {
    /// Did the action complete its work (or find nothing to do)?
    #[serde(default)]
    pub ok: bool,
    /// The action was REFUSED for lack of elevation.
    #[serde(default)]
    pub needs_elevation: bool,
    /// Resolver/policy artifacts written (`configure-os`) — stable paths/ids.
    #[serde(default)]
    pub applied: Vec<String>,
    /// Artifacts removed (`unconfigure-os`).
    #[serde(default)]
    pub removed: Vec<String>,
    /// `true` iff an end-to-end resolve VERIFY confirmed the OS now routes
    /// `*.dig` to the responder LIVE — the expected outcome, meaning no reboot.
    #[serde(default)]
    pub activated: bool,
    /// `true` ONLY as dig-dns's defensive fallback: resolver wiring WAS applied
    /// but the post-activate verify still failed, so a restart is prompted.
    #[serde(default)]
    pub reboot_required: bool,
    /// Why a reboot is prompted, when [`Self::reboot_required`].
    #[serde(default)]
    pub reboot_reason: Option<String>,
    /// Human-facing notes (one line each), surfaced into the install log.
    #[serde(default)]
    pub notes: Vec<String>,
}

impl OsConfigSummary {
    /// The DNS restart signal the installer ORs into its #562
    /// [`crate::InstallReport::restart_required`]: resolver wiring was applied
    /// but the OS resolver did not go live, so a restart is needed to pick up
    /// the split-DNS. Returns the reason to surface, or `None` when resolution
    /// is live (the expected case — NO reboot prompt).
    ///
    /// Trusts dig-dns's authoritative `reboot_required` AND, defensively,
    /// re-derives "wired but not live" from `applied`/`activated` so a future
    /// report that omitted `reboot_required` could never SUPPRESS a genuinely
    /// needed prompt (the safe direction, per the WU2 security lens). It never
    /// prompts when NOTHING was applied (e.g. the Linux PAC-only path, where
    /// there is no split-DNS to activate).
    pub fn restart_reason(&self) -> Option<String> {
        let wired_but_not_live = !self.applied.is_empty() && !self.activated;
        if self.reboot_required || wired_but_not_live {
            Some(self.reboot_reason.clone().unwrap_or_else(|| {
                "restart to activate .dig name resolution (dig-dns)".to_string()
            }))
        } else {
            None
        }
    }
}

/// Parse a `dig-dns configure-os`/`unconfigure-os` `--json` report. PURE, so the
/// report→restart mapping is unit-tested without spawning a process.
pub fn parse_report(json: &str) -> Result<OsConfigSummary, String> {
    serde_json::from_str(json).map_err(|e| format!("parse dig-dns configure-os report: {e}"))
}

/// Wire the OS resolver for `*.dig` via the installed `dig-dns`: run
/// `<dig_dns_bin> configure-os --browser-policy --json` and parse its report.
///
/// `dig_dns_bin` MUST be the absolute path the installer wrote the binary to
/// (never a bare name — see the module docs). stdout is captured regardless of
/// the child's exit code: a non-zero exit is dig-dns's OWN "did not fully
/// activate" signal (the report is still valid JSON on stdout), not a spawn
/// failure. Errors only when the binary could not be spawned or its output did
/// not parse.
pub fn configure_os(dig_dns_bin: &Path) -> Result<OsConfigSummary, String> {
    run_os_config(dig_dns_bin, &["configure-os", "--browser-policy", "--json"])
}

/// Reverse [`configure_os`]: run `<dig_dns_bin> unconfigure-os --json`, removing
/// the resolver wiring + managed browser policy dig-dns (or the legacy
/// installer) applied. Same spawn/parse contract as [`configure_os`].
pub fn unconfigure_os(dig_dns_bin: &Path) -> Result<OsConfigSummary, String> {
    run_os_config(dig_dns_bin, &["unconfigure-os", "--json"])
}

/// Run [`unconfigure_os`] and return the list of artifacts it removed — the
/// uniform resolver-teardown call every per-OS `uninstall` uses. Best-effort:
/// when the binary path is absent (already deleted, or a machine that was never
/// wired) or the tool fails, returns an empty list rather than an error, so the
/// service-registration teardown (the #568 binary-delete gate) is never blocked
/// by a resolver-teardown hiccup.
pub fn unconfigure_removed(dig_dns_bin: Option<&Path>) -> Vec<String> {
    match dig_dns_bin {
        Some(bin) => unconfigure_os(bin).map(|r| r.removed).unwrap_or_default(),
        None => Vec::new(),
    }
}

/// Spawn `<dig_dns_bin> <args>`, capturing stdout regardless of exit code, and
/// parse the report. The shared body of [`configure_os`]/[`unconfigure_os`].
fn run_os_config(dig_dns_bin: &Path, args: &[&str]) -> Result<OsConfigSummary, String> {
    let output = Command::new(dig_dns_bin)
        .args(args)
        .hide_console()
        .output()
        .map_err(|e| {
            format!(
                "could not run {} {}: {e}",
                dig_dns_bin.display(),
                args.join(" ")
            )
        })?;
    parse_report(&String::from_utf8_lossy(&output.stdout))
}

#[cfg(test)]
mod tests {
    use super::*;

    const LIVE_JSON: &str = r#"{"action":"configure-os","os":"windows","ok":true,"needs_elevation":false,"applied":[".dig NRPT rule"],"removed":[],"notes":["added the .dig NRPT rule","flushed the DNS client cache"],"activated":true,"reboot_required":false}"#;
    const WIRED_NOT_LIVE_JSON: &str = r#"{"action":"configure-os","os":"windows","ok":true,"needs_elevation":false,"applied":[".dig NRPT rule"],"removed":[],"notes":["added the .dig NRPT rule"],"activated":false,"reboot_required":true,"reboot_reason":"the OS resolver has not picked up the .dig split-DNS; restart to activate"}"#;
    const PAC_ONLY_JSON: &str = r#"{"action":"configure-os","os":"linux","ok":true,"needs_elevation":false,"applied":[],"removed":[],"notes":["no systemd-resolved detected; relying on the PAC"],"activated":false,"reboot_required":false}"#;

    #[test]
    fn parses_the_live_activated_report() {
        let r = parse_report(LIVE_JSON).expect("parses");
        assert!(r.ok);
        assert!(r.activated);
        assert!(!r.reboot_required);
        assert_eq!(r.applied, vec![".dig NRPT rule".to_string()]);
    }

    #[test]
    fn live_activation_needs_no_restart_prompt() {
        // The expected case on all three OSes: resolution is live, so the
        // installer must NOT surface a reboot prompt.
        let r = parse_report(LIVE_JSON).unwrap();
        assert_eq!(r.restart_reason(), None);
    }

    #[test]
    fn wired_but_not_live_prompts_a_restart_with_the_reason() {
        let r = parse_report(WIRED_NOT_LIVE_JSON).unwrap();
        let reason = r
            .restart_reason()
            .expect("a wired-but-not-live result prompts a restart");
        assert!(
            reason.contains("split-DNS"),
            "the dig-dns reboot_reason is carried through: {reason}"
        );
    }

    #[test]
    fn nothing_applied_never_prompts_a_restart() {
        // The Linux PAC-only path applies no split-DNS, so there is nothing to
        // "activate" and no restart to prompt — even though `activated` is false.
        let r = parse_report(PAC_ONLY_JSON).unwrap();
        assert_eq!(r.restart_reason(), None);
    }

    #[test]
    fn wired_not_live_without_a_reason_falls_back_to_a_default_reason() {
        // Defensive: a report that flags reboot_required but omits the reason
        // still yields a non-empty, user-facing prompt (never an empty string).
        let json = r#"{"applied":["x"],"activated":false,"reboot_required":true}"#;
        let r = parse_report(json).unwrap();
        let reason = r.restart_reason().expect("prompts");
        assert!(reason.contains(".dig name resolution"));
    }

    #[test]
    fn a_future_report_with_unknown_fields_still_parses() {
        // Machine-contract stability: dig-dns may add report fields; the
        // installer must ignore unknowns, never fail to parse (§6.2).
        let json =
            r#"{"ok":true,"activated":true,"applied":[],"some_new_field":42,"nested":{"a":1}}"#;
        let r = parse_report(json).expect("ignores unknown fields");
        assert!(r.ok);
        assert!(r.activated);
    }

    #[test]
    fn malformed_output_is_an_error_not_a_panic() {
        assert!(parse_report("not json at all").is_err());
    }

    #[test]
    fn defensively_reboot_required_alone_prompts_even_if_applied_is_empty() {
        // If dig-dns ever set reboot_required with an empty `applied`, trust its
        // authoritative signal and still prompt (never suppress a needed reboot).
        let json = r#"{"applied":[],"activated":false,"reboot_required":true,"reboot_reason":"restart needed"}"#;
        let r = parse_report(json).unwrap();
        assert_eq!(r.restart_reason(), Some("restart needed".to_string()));
    }
}
