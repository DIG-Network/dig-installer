#![cfg(windows)]
//! The hidden Windows Service Control Protocol entrypoint dig-installer
//! registers as the dig-dns service's host process (task #177).
//!
//! dig-dns's own `serve` is a plain blocking CLI loop with no
//! `StartServiceCtrlDispatcher` handshake, so the SCM is pointed at THIS
//! installer's persisted binary running the hidden
//! [`plan::SERVICE_HOST_SUBCOMMAND`] entrypoint, which speaks the SCM
//! protocol and spawns the real `dig-dns serve` as a supervised child process
//! — mirroring dig-node-service's `win_service.rs` (see the ecosystem
//! `DEVELOPMENT_LOG.md`). This is never invoked directly by a user; `main.rs`
//! intercepts it before clap parsing (it carries no public `--help` surface).

use std::ffi::OsString;
use std::path::PathBuf;
use std::sync::mpsc;
use std::sync::OnceLock;
use std::time::Duration;

use windows_service::service::{
    ServiceControl, ServiceControlAccept, ServiceExitCode, ServiceState, ServiceStatus, ServiceType,
};
use windows_service::service_control_handler::{self, ServiceControlHandlerResult};
use windows_service::{define_windows_service, service_dispatcher};

use super::plan::{SERVICE_HOST_SUBCOMMAND, SERVICE_LABEL};

const SERVICE_TYPE: ServiceType = ServiceType::OWN_PROCESS;

/// The `dig-dns` binary path (+ optional `--node` override) this service
/// instance spawns, captured from argv before the dispatcher takes over (its
/// callback signature carries no closure state, so this must be a static).
static TARGET: OnceLock<(PathBuf, Option<String>)> = OnceLock::new();

/// Parse `--exec <path> [--node <url>]` — the arguments dig-installer
/// registered as the service's launch arguments, everything AFTER the
/// [`plan::SERVICE_HOST_SUBCOMMAND`] token. Pure.
pub fn parse_target_args(args: &[String]) -> Result<(PathBuf, Option<String>), String> {
    let mut exec: Option<PathBuf> = None;
    let mut node: Option<String> = None;
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--exec" => {
                let v = args.get(i + 1).ok_or("--exec requires a value")?;
                exec = Some(PathBuf::from(v));
                i += 2;
            }
            "--node" => {
                let v = args.get(i + 1).ok_or("--node requires a value")?;
                node = Some(v.clone());
                i += 2;
            }
            other => return Err(format!("unrecognised argument: {other}")),
        }
    }
    let exec = exec.ok_or("missing required --exec <dig-dns-path>")?;
    Ok((exec, node))
}

/// Does `argv` (the process argv, INCLUDING `argv[0]`) invoke the hidden
/// [`SERVICE_HOST_SUBCOMMAND`]? It carries no public `--help` surface (the SCM
/// launches it directly), so `main` must sniff for it BEFORE handing argv to
/// clap. Returns the arguments AFTER the subcommand token (to pass to
/// [`run`]), or `None` so the caller falls through to normal CLI parsing.
///
/// Pure — takes an injected argv slice rather than reading
/// `std::env::args()`, and never calls the (blocking) SCM dispatcher itself,
/// so it is unit-tested directly; `main` passes the real argv.
pub fn matches_service_host_invocation(argv: &[String]) -> Option<Vec<String>> {
    if argv.get(1).map(String::as_str) == Some(SERVICE_HOST_SUBCOMMAND) {
        Some(argv[2..].to_vec())
    } else {
        None
    }
}

/// Entry point for the hidden `run-dig-dns-service` subcommand: hand control
/// to the SCM dispatcher (blocks until the service stops). `args` are the
/// arguments that followed the subcommand on the command line.
pub fn run(args: &[String]) -> std::io::Result<()> {
    let target = parse_target_args(args).map_err(std::io::Error::other)?;
    TARGET
        .set(target)
        .map_err(|_| std::io::Error::other("service target already set"))?;
    service_dispatcher::start(SERVICE_LABEL, ffi_service_main)
        .map_err(|e| std::io::Error::other(e.to_string()))
}

// Generates `ffi_service_main`, the low-level entry the SCM calls, forwarding to `service_main`.
define_windows_service!(ffi_service_main, service_main);

/// Service entry called on a background thread by the SCM. There is no
/// console here, so a failure is surfaced only via the reported service
/// status; the `eprintln!` is best-effort (visible only if attached, e.g.
/// under a debugger).
fn service_main(_args: Vec<OsString>) {
    if let Err(e) = run_service() {
        eprintln!("dig-dns service host error: {e}");
    }
}

/// The actual service body: register the control handler, report `Running`,
/// spawn `dig-dns serve` as a child and supervise it until the SCM sends
/// `Stop` (or the child exits on its own), then report `Stopped`.
fn run_service() -> std::io::Result<()> {
    let (exec, node) = TARGET
        .get()
        .cloned()
        .ok_or_else(|| std::io::Error::other("service target not set"))?;

    let (shutdown_tx, shutdown_rx) = mpsc::channel::<()>();
    let event_handler = move |control_event| -> ServiceControlHandlerResult {
        match control_event {
            // The SCM polls for status; always succeed.
            ServiceControl::Interrogate => ServiceControlHandlerResult::NoError,
            ServiceControl::Stop => {
                let _ = shutdown_tx.send(());
                ServiceControlHandlerResult::NoError
            }
            _ => ServiceControlHandlerResult::NotImplemented,
        }
    };
    let status_handle = service_control_handler::register(SERVICE_LABEL, event_handler)
        .map_err(|e| std::io::Error::other(e.to_string()))?;

    let set = |state: ServiceState, accept: ServiceControlAccept, exit: u32| ServiceStatus {
        service_type: SERVICE_TYPE,
        current_state: state,
        controls_accepted: accept,
        exit_code: ServiceExitCode::Win32(exit),
        checkpoint: 0,
        wait_hint: Duration::default(),
        process_id: None,
    };
    status_handle
        .set_service_status(set(ServiceState::Running, ServiceControlAccept::STOP, 0))
        .map_err(|e| std::io::Error::other(e.to_string()))?;

    let mut cmd = std::process::Command::new(&exec);
    cmd.arg("serve");
    if let Some(n) = &node {
        cmd.arg("--node").arg(n);
    }
    let mut child = match cmd.spawn() {
        Ok(c) => c,
        Err(e) => {
            let _ = status_handle.set_service_status(set(
                ServiceState::Stopped,
                ServiceControlAccept::empty(),
                1,
            ));
            return Err(e);
        }
    };

    // Wait for either the SCM's Stop control or the child exiting on its own, polling at a
    // short interval (the shutdown channel has no async runtime to select! on here).
    loop {
        if shutdown_rx.recv_timeout(Duration::from_millis(500)).is_ok() {
            let _ = child.kill();
            let _ = child.wait();
            break;
        }
        if let Ok(Some(_status)) = child.try_wait() {
            break; // the child exited on its own.
        }
    }

    let _ = status_handle.set_service_status(set(
        ServiceState::Stopped,
        ServiceControlAccept::empty(),
        0,
    ));
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn matches_service_host_invocation_extracts_the_trailing_args() {
        let argv = vec![
            r"C:\dig\dig-installer.exe".to_string(),
            SERVICE_HOST_SUBCOMMAND.to_string(),
            "--exec".to_string(),
            r"C:\dig\dig-dns.exe".to_string(),
        ];
        let rest = matches_service_host_invocation(&argv).expect("matches");
        assert_eq!(
            rest,
            vec!["--exec".to_string(), r"C:\dig\dig-dns.exe".to_string()]
        );
    }

    #[test]
    fn matches_service_host_invocation_is_none_for_the_normal_cli() {
        let argv = vec![
            r"C:\dig\dig-installer.exe".to_string(),
            "--with-dig-dns".to_string(),
        ];
        assert!(matches_service_host_invocation(&argv).is_none());
    }

    #[test]
    fn matches_service_host_invocation_is_none_with_no_args() {
        let argv = vec![r"C:\dig\dig-installer.exe".to_string()];
        assert!(matches_service_host_invocation(&argv).is_none());
    }

    #[test]
    fn matches_service_host_invocation_handles_no_trailing_args() {
        let argv = vec![
            "dig-installer".to_string(),
            SERVICE_HOST_SUBCOMMAND.to_string(),
        ];
        assert_eq!(matches_service_host_invocation(&argv), Some(Vec::new()));
    }

    #[test]
    fn parse_target_args_extracts_exec_path() {
        let (exec, node) =
            parse_target_args(&["--exec".into(), r"C:\dig\dig-dns.exe".into()]).unwrap();
        assert_eq!(exec, PathBuf::from(r"C:\dig\dig-dns.exe"));
        assert!(node.is_none());
    }

    #[test]
    fn parse_target_args_extracts_optional_node_override() {
        let (exec, node) = parse_target_args(&[
            "--exec".into(),
            "dig-dns.exe".into(),
            "--node".into(),
            "http://localhost:9778".into(),
        ])
        .unwrap();
        assert_eq!(exec, PathBuf::from("dig-dns.exe"));
        assert_eq!(node.as_deref(), Some("http://localhost:9778"));
    }

    #[test]
    fn parse_target_args_accepts_node_before_exec() {
        let (exec, node) = parse_target_args(&[
            "--node".into(),
            "http://localhost:9778".into(),
            "--exec".into(),
            "dig-dns.exe".into(),
        ])
        .unwrap();
        assert_eq!(exec, PathBuf::from("dig-dns.exe"));
        assert_eq!(node.as_deref(), Some("http://localhost:9778"));
    }

    #[test]
    fn parse_target_args_requires_exec() {
        assert!(parse_target_args(&[]).is_err());
        assert!(parse_target_args(&["--node".into(), "x".into()]).is_err());
    }

    #[test]
    fn parse_target_args_rejects_unknown_flags() {
        assert!(parse_target_args(&["--bogus".into()]).is_err());
    }

    #[test]
    fn parse_target_args_rejects_a_dangling_value_flag() {
        assert!(parse_target_args(&["--exec".into()]).is_err());
        assert!(parse_target_args(&["--exec".into(), "x".into(), "--node".into()]).is_err());
    }
}
