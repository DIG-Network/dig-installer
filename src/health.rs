//! Post-install RPC health check for the dig-node service (task #223).
//!
//! Registering the OS service and writing the `dig.local` hosts entry
//! ([`crate::hosts`]) proves the service is *installed* and that DNS
//! *resolves* — neither proves the node is actually **answering RPC** on its
//! configured loopback port. This module closes that gap: it sends a
//! standard JSON-RPC `rpc.discover` request (the OpenRPC self-description
//! method every dig-node build answers — see dig-node-service's
//! `server.rs`/`meta.rs`) to `http://127.0.0.1:<port>/` and reports whether
//! the node replied with a well-formed result.
//!
//! A freshly-started service needs a moment to bind its socket, so
//! [`wait_for_node_health`] retries on a short interval (mirroring
//! `dns::doctor::wait_for_doctor`'s poll-until-ok pattern) rather than
//! judging on a single attempt.

use std::time::Duration;

/// The result of the post-install `rpc.discover` health check.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct HealthCheckResult {
    /// Whether a health check was actually attempted (`false` only when the
    /// caller skipped it outright, e.g. the service was never started).
    pub checked: bool,
    /// `true` iff `rpc.discover` answered with a JSON-RPC `result` (not an
    /// error, not a transport failure) within the retry budget.
    pub healthy: bool,
    /// Human-readable detail — never silent (mirrors the rest of this
    /// crate's `dig_local_resolve_note`/`note` convention).
    pub note: String,
}

/// Build the `rpc.discover` JSON-RPC request body sent to the node. Pure —
/// split out so the wire shape is unit-tested without a network.
fn discover_request_body() -> serde_json::Value {
    serde_json::json!({ "jsonrpc": "2.0", "id": 1, "method": "rpc.discover" })
}

/// The loopback URL a dig-node service configured on `port` answers JSON-RPC
/// requests at (`POST /` — see dig-node-service's `server.rs::rpc`).
fn node_rpc_url(port: u16) -> String {
    format!("http://127.0.0.1:{port}/")
}

/// Send one `rpc.discover` request and classify the response. `post` is the
/// injected transport (production: [`ureq_post`]; tests: a stub) so the
/// retry/classification logic here is exercised without a real socket.
fn probe_with(
    port: u16,
    post: &dyn Fn(&str, &serde_json::Value) -> Result<serde_json::Value, String>,
) -> Result<(), String> {
    let url = node_rpc_url(port);
    let body = discover_request_body();
    let v = post(&url, &body)?;
    if v.get("result").is_some() {
        Ok(())
    } else if let Some(err) = v.get("error") {
        Err(format!(
            "{url} answered rpc.discover with a JSON-RPC error: {err}"
        ))
    } else {
        Err(format!(
            "{url} answered rpc.discover with an unexpected shape (no result/error field)"
        ))
    }
}

/// The production transport: a real blocking HTTP POST via `ureq` (rustls,
/// matching the rest of this crate's HTTP posture — see `download.rs`), with
/// a short timeout so a hung socket can't stall the whole install.
fn ureq_post(url: &str, body: &serde_json::Value) -> Result<serde_json::Value, String> {
    let resp = ureq::post(url)
        .timeout(Duration::from_secs(2))
        .send_json(body.clone())
        .map_err(|e| format!("POST {url}: {e}"))?;
    resp.into_json()
        .map_err(|e| format!("parse response from {url}: {e}"))
}

/// Poll the real node once, over the network. Thin wrapper around
/// [`probe_with`] fixing the transport to [`ureq_post`]. Production code only
/// ever retries via [`wait_for_node_health`]; this single-shot form exists so
/// tests can exercise the real `ureq` transport (against a one-shot local
/// HTTP server) without the retry loop's sleeps.
#[cfg(test)]
fn probe_once(port: u16) -> Result<(), String> {
    probe_with(port, &ureq_post)
}

/// Poll [`probe_once`] until it succeeds or `attempts` is exhausted, sleeping
/// `interval` between tries — giving a freshly-(re)started service a moment
/// to bind its socket before judging it not up (mirrors
/// `dns::doctor::wait_for_doctor`). Never panics; always returns a
/// [`HealthCheckResult`] with `checked: true`.
pub fn wait_for_node_health(port: u16, attempts: u32, interval: Duration) -> HealthCheckResult {
    wait_for_node_health_with(port, attempts, interval, &ureq_post)
}

/// [`wait_for_node_health`] with an injectable transport — the pure-ish
/// retry/classification core the unit tests below drive without a network.
fn wait_for_node_health_with(
    port: u16,
    attempts: u32,
    interval: Duration,
    post: &dyn Fn(&str, &serde_json::Value) -> Result<serde_json::Value, String>,
) -> HealthCheckResult {
    let mut last_err = String::from("health check never ran (attempts=0)");
    for attempt in 0..attempts.max(1) {
        match probe_with(port, post) {
            Ok(()) => {
                return HealthCheckResult {
                    checked: true,
                    healthy: true,
                    note: format!("rpc.discover on {} answered", node_rpc_url(port)),
                }
            }
            Err(e) => last_err = e,
        }
        if attempt + 1 < attempts {
            std::thread::sleep(interval);
        }
    }
    HealthCheckResult {
        checked: true,
        healthy: false,
        note: last_err,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Write};
    use std::net::TcpListener;

    // -- Pure request/URL builders -------------------------------------------

    #[test]
    fn discover_request_body_is_a_well_formed_json_rpc_call() {
        let body = discover_request_body();
        assert_eq!(body["jsonrpc"], "2.0");
        assert_eq!(body["method"], "rpc.discover");
        assert!(body.get("id").is_some());
    }

    #[test]
    fn node_rpc_url_targets_loopback_root() {
        assert_eq!(node_rpc_url(9778), "http://127.0.0.1:9778/");
        assert_eq!(node_rpc_url(9099), "http://127.0.0.1:9099/");
    }

    // -- probe_with (injected transport) --------------------------------------

    #[test]
    fn probe_with_succeeds_when_response_carries_a_result() {
        let post = |_url: &str, _body: &serde_json::Value| {
            Ok(serde_json::json!({ "jsonrpc": "2.0", "id": 1, "result": { "openrpc": "1.2.6" } }))
        };
        assert!(probe_with(9778, &post).is_ok());
    }

    #[test]
    fn probe_with_fails_on_a_json_rpc_error_response() {
        let post = |_url: &str, _body: &serde_json::Value| {
            Ok(
                serde_json::json!({ "jsonrpc": "2.0", "id": 1, "error": { "code": -32601, "message": "method not found" } }),
            )
        };
        let err = probe_with(9778, &post).unwrap_err();
        assert!(err.contains("JSON-RPC error"), "got: {err}");
        assert!(err.contains("method not found"), "got: {err}");
    }

    #[test]
    fn probe_with_fails_on_an_unrecognised_response_shape() {
        let post = |_url: &str, _body: &serde_json::Value| Ok(serde_json::json!({ "ok": true }));
        let err = probe_with(9778, &post).unwrap_err();
        assert!(err.contains("unexpected shape"), "got: {err}");
    }

    #[test]
    fn probe_with_propagates_a_transport_failure() {
        let post = |_url: &str, _body: &serde_json::Value| Err("connection refused".to_string());
        let err = probe_with(9778, &post).unwrap_err();
        assert_eq!(err, "connection refused");
    }

    // -- wait_for_node_health_with (retry/backoff) ----------------------------

    #[test]
    fn wait_for_node_health_with_returns_immediately_on_first_success() {
        let post = |_url: &str, _body: &serde_json::Value| {
            Ok(serde_json::json!({ "jsonrpc": "2.0", "id": 1, "result": {} }))
        };
        let r = wait_for_node_health_with(9778, 5, Duration::from_millis(1), &post);
        assert!(r.checked);
        assert!(r.healthy);
        assert!(r.note.contains("9778"), "got: {}", r.note);
    }

    #[test]
    fn wait_for_node_health_with_retries_then_succeeds() {
        let calls = std::sync::atomic::AtomicU32::new(0);
        let post = move |_url: &str, _body: &serde_json::Value| {
            let n = calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            if n < 2 {
                Err("connection refused".to_string())
            } else {
                Ok(serde_json::json!({ "jsonrpc": "2.0", "id": 1, "result": {} }))
            }
        };
        let r = wait_for_node_health_with(9778, 5, Duration::from_millis(1), &post);
        assert!(r.healthy, "should succeed on the 3rd attempt: {}", r.note);
    }

    #[test]
    fn wait_for_node_health_with_exhausts_attempts_and_reports_the_last_error() {
        let post = |_url: &str, _body: &serde_json::Value| Err("connection refused".to_string());
        let r = wait_for_node_health_with(9778, 3, Duration::from_millis(1), &post);
        assert!(r.checked);
        assert!(!r.healthy);
        assert_eq!(r.note, "connection refused");
    }

    #[test]
    fn wait_for_node_health_with_treats_zero_attempts_as_one() {
        let post = |_url: &str, _body: &serde_json::Value| {
            Ok(serde_json::json!({ "jsonrpc": "2.0", "id": 1, "result": {} }))
        };
        let r = wait_for_node_health_with(9778, 0, Duration::from_millis(1), &post);
        assert!(r.healthy);
    }

    #[test]
    fn health_check_result_serializes_with_stable_field_names() {
        let r = HealthCheckResult {
            checked: true,
            healthy: true,
            note: "ok".to_string(),
        };
        let v: serde_json::Value = serde_json::to_value(&r).unwrap();
        assert_eq!(v["checked"], true);
        assert_eq!(v["healthy"], true);
        assert_eq!(v["note"], "ok");
    }

    // -- End-to-end over a REAL loopback socket (no injected transport) -------
    //
    // Exercises probe_once/wait_for_node_health (the production `ureq_post`
    // path) against a minimal one-shot HTTP/1.1 server, so the actual network
    // code (not just the injected-transport core above) is covered.

    /// Spin a one-shot HTTP/1.1 server on an ephemeral loopback port that
    /// replies with a fixed status line + JSON body to the FIRST request it
    /// receives, then exits. Good enough to drive the real `ureq` POST path
    /// without a real dig-node.
    fn one_shot_json_server(status_line: &'static str, json_body: &'static str) -> u16 {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind ephemeral port");
        let port = listener.local_addr().unwrap().port();
        std::thread::spawn(move || {
            if let Ok((mut stream, _)) = listener.accept() {
                // Fully drain the request (headers + the small JSON body) before
                // writing the response. A single best-effort `read()` risks leaving
                // unread bytes in the kernel receive buffer when `stream` is dropped
                // below — on Windows that turns the close into an RST instead of a
                // clean FIN, which the client sees as "connection forcibly closed"
                // mid-response (a flaky-test regression this loop fixes). Read
                // repeatedly on a short timeout; a timeout with no bytes means the
                // client has finished sending (the whole request arrives in well
                // under the timeout window on loopback).
                stream
                    .set_read_timeout(Some(std::time::Duration::from_millis(200)))
                    .ok();
                let mut buf = [0u8; 4096];
                loop {
                    match stream.read(&mut buf) {
                        Ok(0) => break,
                        Ok(_) => continue,
                        Err(_) => break, // timed out (or errored) — assume fully sent
                    }
                }
                let response = format!(
                    "{status_line}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{json_body}",
                    json_body.len()
                );
                let _ = stream.write_all(response.as_bytes());
                let _ = stream.flush();
                // Give the client a moment to read the response before the socket
                // drops, so a slow-scheduled reader never races the close.
                std::thread::sleep(std::time::Duration::from_millis(50));
            }
        });
        port
    }

    #[test]
    fn probe_once_succeeds_against_a_real_socket_answering_a_result() {
        let port = one_shot_json_server(
            "HTTP/1.1 200 OK",
            r#"{"jsonrpc":"2.0","id":1,"result":{"openrpc":"1.2.6"}}"#,
        );
        probe_once(port).expect("a real 200 + result response must be healthy");
    }

    #[test]
    fn probe_once_fails_when_nothing_is_listening() {
        // Bind + immediately drop, freeing the port with nothing listening on it.
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        drop(listener);
        let err = probe_once(port).unwrap_err();
        assert!(err.contains("POST"), "got: {err}");
    }

    #[test]
    fn wait_for_node_health_reports_healthy_against_a_real_socket() {
        let port = one_shot_json_server(
            "HTTP/1.1 200 OK",
            r#"{"jsonrpc":"2.0","id":1,"result":{"openrpc":"1.2.6"}}"#,
        );
        let r = wait_for_node_health(port, 3, Duration::from_millis(1));
        assert!(r.healthy, "note: {}", r.note);
    }
}
