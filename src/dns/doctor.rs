//! Runs `dig-dns doctor --json` / `dig-dns pac --json` against the installed
//! binary — the self-verification step every dig-dns install ends with (task
//! #177, dig-dns README §"Troubleshooting") — and renders the printed report.
//!
//! Parsing lives in [`super::plan`] (pure); this module only owns the process
//! spawn + a short poll (giving a freshly-started service a moment to bind
//! its sockets) + the human summary text.

use std::path::Path;
use std::process::Command;
use std::time::Duration;

use super::plan::{self, DoctorSummary, PacInfo};

/// Run `<dig_dns_bin> doctor --json`, capturing stdout regardless of the
/// child's exit code (a non-zero exit is dig-dns's OWN "not fully live"
/// signal, not a spawn failure). Errors only if the binary could not be
/// spawned at all, or its output did not parse as a doctor report.
pub fn run_doctor(dig_dns_bin: &Path) -> Result<DoctorSummary, String> {
    let output = Command::new(dig_dns_bin)
        .arg("doctor")
        .arg("--json")
        .output()
        .map_err(|e| format!("could not run {} doctor: {e}", dig_dns_bin.display()))?;
    plan::parse_doctor_json(&String::from_utf8_lossy(&output.stdout))
}

/// Run `<dig_dns_bin> pac --json` (no `--port`, so it probes the running
/// gateway for its actual bound port) and return the parsed PAC info.
pub fn run_pac(dig_dns_bin: &Path) -> Result<PacInfo, String> {
    let output = Command::new(dig_dns_bin)
        .arg("pac")
        .arg("--json")
        .output()
        .map_err(|e| format!("could not run {} pac: {e}", dig_dns_bin.display()))?;
    plan::parse_pac_json(&String::from_utf8_lossy(&output.stdout))
}

/// Poll [`run_doctor`] until it reports `ok: true` or `attempts` is
/// exhausted, sleeping `interval` between tries — giving a freshly
/// (re)started service a moment to bind its sockets before judging it.
/// Returns the LAST result seen (so a genuine failure still surfaces the
/// real report/error, not a synthetic timeout).
pub fn wait_for_doctor(
    dig_dns_bin: &Path,
    attempts: u32,
    interval: Duration,
) -> Result<DoctorSummary, String> {
    let mut last = Err("doctor never ran (attempts=0)".to_string());
    for attempt in 0..attempts.max(1) {
        last = run_doctor(dig_dns_bin);
        if matches!(&last, Ok(s) if s.ok) {
            return last;
        }
        if attempt + 1 < attempts {
            std::thread::sleep(interval);
        }
    }
    last
}

/// Render the human summary block printed after install/uninstall: the
/// doctor text report, which path(s) are live, the bound port, the PAC URL,
/// and the one-line browser-fallback instruction.
pub fn render_summary(doctor: &DoctorSummary, pac: Option<&PacInfo>) -> String {
    let mut out = String::from("dig-dns self-check (doctor):\n");
    for c in &doctor.checks {
        out.push_str(&format!(
            "  [{}] {}: {}\n",
            c.status.to_uppercase(),
            c.name,
            c.detail
        ));
        if let Some(fix) = &c.fix {
            out.push_str(&format!("        fix: {fix}\n"));
        }
    }
    let paths = plan::live_paths(doctor);
    out.push_str(&format!(
        "live path(s): {}\n",
        if paths.is_empty() {
            "NONE".to_string()
        } else {
            paths.join(", ")
        }
    ));
    if let Some(p) = pac {
        out.push_str(&format!("gateway bound port: {}\n", p.port));
        let url = plan::pac_url(&p.loopback_ip, p.port);
        out.push_str(&format!("PAC URL: {url}\n"));
        out.push_str(&format!("{}\n", plan::browser_fallback_instruction(&url)));
    }
    out.push_str(if doctor.ok {
        "RESULT: a .dig URL can load.\n"
    } else {
        "RESULT: a .dig URL will NOT load yet - see the failing checks above.\n"
    });
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    const OK_DOCTOR_JSON: &str = r#"{"ok":true,"path_a":true,"path_b":true,"checks":[{"id":"loopback_ip","name":"Loopback IP is up","status":"pass","detail":"up"}]}"#;
    const FAIL_DOCTOR_JSON: &str = r#"{"ok":false,"path_a":false,"path_b":false,"checks":[{"id":"gateway_port","name":"HTTP gateway answers (Path B)","status":"fail","detail":"no gateway","fix":"start dig-dns serve"}]}"#;
    const PAC_JSON: &str = r#"{"loopback_ip":"127.0.0.5","port":80,"tld":"dig","pac":"function FindProxyForURL(url, host) { return \"DIRECT\"; }"}"#;

    fn tmp_subdir(tag: &str) -> std::path::PathBuf {
        let d =
            std::env::temp_dir().join(format!("dig-installer-doctor-{tag}-{}", std::process::id()));
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    /// A stub `dig-dns`-alike that ignores its args and prints fixed stdout,
    /// exiting with the given code. Mirrors `service.rs`'s `stub_exit` pattern.
    #[cfg(windows)]
    fn stub_stdout(
        dir: &std::path::Path,
        name: &str,
        stdout: &str,
        exit_code: i32,
    ) -> std::path::PathBuf {
        std::fs::create_dir_all(dir).unwrap();
        let p = dir.join(format!("{name}.cmd"));
        // Escape `%` for batch (none expected here) and just echo the JSON verbatim.
        std::fs::write(
            &p,
            format!("@echo off\r\necho {stdout}\r\nexit /b {exit_code}\r\n"),
        )
        .unwrap();
        p
    }

    #[cfg(not(windows))]
    fn stub_stdout(
        dir: &std::path::Path,
        name: &str,
        stdout: &str,
        exit_code: i32,
    ) -> std::path::PathBuf {
        use std::os::unix::fs::PermissionsExt;
        std::fs::create_dir_all(dir).unwrap();
        let p = dir.join(name);
        std::fs::write(
            &p,
            format!("#!/bin/sh\ncat <<'EOF'\n{stdout}\nEOF\nexit {exit_code}\n"),
        )
        .unwrap();
        let mut perms = std::fs::metadata(&p).unwrap().permissions();
        perms.set_mode(0o755);
        std::fs::set_permissions(&p, perms).unwrap();
        // Unlike `service.rs`'s `stub_exit` (which dodges this by pointing at a
        // pre-existing system binary), this helper needs CUSTOM stdout, so it must
        // write a fresh script. A just-written, just-`chmod`'d file can transiently
        // fail exec with ETXTBSY ("Text file busy", os error 26) on Linux — the
        // kernel briefly refuses to exec a file that is/was open for writing (the
        // exact regression documented in `service.rs`). Warm up the exec here
        // (discarding the result, retrying only on ETXTBSY) so the race resolves
        // before the real test invocation spawns it.
        for _ in 0..50 {
            match std::process::Command::new(&p).output() {
                Err(e) if e.raw_os_error() == Some(26) => {
                    std::thread::sleep(std::time::Duration::from_millis(10));
                }
                _ => break,
            }
        }
        p
    }

    #[test]
    fn run_doctor_parses_a_passing_report() {
        let dir = tmp_subdir("doctor-ok");
        let bin = stub_stdout(&dir, "doctor-ok", OK_DOCTOR_JSON, 0);
        let summary = run_doctor(&bin).expect("parses");
        assert!(summary.ok);
        assert_eq!(summary.checks.len(), 1);
    }

    #[test]
    fn run_doctor_parses_a_failing_report_even_on_nonzero_exit() {
        // dig-dns exits non-zero when NOT ok; the JSON on stdout is still valid and must parse.
        let dir = tmp_subdir("doctor-fail");
        let bin = stub_stdout(&dir, "doctor-fail", FAIL_DOCTOR_JSON, 1);
        let summary = run_doctor(&bin).expect("parses despite nonzero exit");
        assert!(!summary.ok);
        assert_eq!(
            summary.checks[0].fix.as_deref(),
            Some("start dig-dns serve")
        );
    }

    #[test]
    fn run_doctor_errors_when_binary_is_missing() {
        let missing = std::env::temp_dir().join("definitely-not-a-real-dig-dns-binary-xyz");
        let err = run_doctor(&missing).unwrap_err();
        assert!(err.contains("could not run"), "got: {err}");
    }

    #[test]
    fn run_doctor_errors_on_malformed_output() {
        let dir = tmp_subdir("doctor-garbage");
        let bin = stub_stdout(&dir, "doctor-garbage", "not json at all", 0);
        assert!(run_doctor(&bin).is_err());
    }

    #[test]
    fn run_pac_parses_bound_port_and_text() {
        let dir = tmp_subdir("pac-ok");
        let bin = stub_stdout(&dir, "pac-ok", PAC_JSON, 0);
        let info = run_pac(&bin).expect("parses");
        assert_eq!(info.port, 80);
        assert!(info.pac.contains("FindProxyForURL"));
    }

    #[test]
    fn wait_for_doctor_returns_immediately_on_first_success() {
        let dir = tmp_subdir("wait-ok");
        let bin = stub_stdout(&dir, "wait-ok", OK_DOCTOR_JSON, 0);
        let summary = wait_for_doctor(&bin, 5, Duration::from_millis(1)).expect("ok");
        assert!(summary.ok);
    }

    #[test]
    fn wait_for_doctor_exhausts_attempts_and_returns_the_last_result() {
        let dir = tmp_subdir("wait-fail");
        let bin = stub_stdout(&dir, "wait-fail", FAIL_DOCTOR_JSON, 1);
        let summary = wait_for_doctor(&bin, 3, Duration::from_millis(1)).expect("parses");
        assert!(
            !summary.ok,
            "never becomes ok, so the last (failing) report is returned"
        );
    }

    #[test]
    fn wait_for_doctor_treats_zero_attempts_as_one() {
        let dir = tmp_subdir("wait-zero");
        let bin = stub_stdout(&dir, "wait-zero", OK_DOCTOR_JSON, 0);
        let summary = wait_for_doctor(&bin, 0, Duration::from_millis(1)).expect("still runs once");
        assert!(summary.ok);
    }

    #[test]
    fn render_summary_includes_checks_paths_port_and_pac_url() {
        let doctor = plan::parse_doctor_json(OK_DOCTOR_JSON).unwrap();
        let pac = plan::parse_pac_json(PAC_JSON).unwrap();
        let text = render_summary(&doctor, Some(&pac));
        assert!(text.contains("[PASS]"));
        assert!(text.contains("live path(s): dns, gateway"));
        assert!(text.contains("gateway bound port: 80"));
        assert!(text.contains("http://127.0.0.5:80/.dig/proxy.pac"));
        assert!(text.contains("a .dig URL can load"));
    }

    #[test]
    fn render_summary_reports_failure_and_fix_hints_without_pac() {
        let doctor = plan::parse_doctor_json(FAIL_DOCTOR_JSON).unwrap();
        let text = render_summary(&doctor, None);
        assert!(text.contains("[FAIL]"));
        assert!(text.contains("fix: start dig-dns serve"));
        assert!(text.contains("live path(s): NONE"));
        assert!(!text.contains("PAC URL"));
        assert!(text.contains("will NOT load yet"));
    }
}
