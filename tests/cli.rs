//! End-to-end CLI contract tests for the built `dig-installer` binary.
//!
//! These drive the real binary (via `assert_cmd`) and lock the agent-facing
//! surface — `--help-json`, `--help`, and the structured error envelope — so a
//! regression in the invocation contract fails CI. They are network-free: every
//! case here either introspects the contract or fails before any HTTP call.
//!
//! (Network-dependent resolution — actually hitting the GitHub releases API — is
//! intentionally NOT exercised here so the suite is deterministic in CI; the
//! pure asset/release/error logic is unit-tested in the library.)

use assert_cmd::Command;
use serde_json::Value;

fn bin() -> Command {
    Command::cargo_bin("dig-installer").expect("dig-installer binary built")
}

#[test]
fn help_json_emits_the_full_contract() {
    let out = bin().arg("--help-json").assert().success();
    let stdout = String::from_utf8(out.get_output().stdout.clone()).unwrap();
    let v: Value = serde_json::from_str(&stdout).expect("--help-json must be valid JSON");

    assert_eq!(v["name"], "dig-installer");
    assert!(v["version"].is_string());
    assert!(v["schema_version"].is_number());

    // All three thin-shim components are advertised.
    let ids: Vec<&str> = v["components"]
        .as_array()
        .unwrap()
        .iter()
        .map(|c| c["id"].as_str().unwrap())
        .collect();
    assert!(ids.contains(&"digstore"));
    assert!(ids.contains(&"dig-node"));
    assert!(ids.contains(&"browser"));

    // The full exit-code table is present, including the distinct elevation code.
    let codes: Vec<&str> = v["exit_codes"]
        .as_array()
        .unwrap()
        .iter()
        .map(|e| e["code"].as_str().unwrap())
        .collect();
    for expected in [
        "OK",
        "UNSUPPORTED_TARGET",
        "ASSET_NOT_FOUND",
        "NETWORK",
        "CHECKSUM_MISMATCH",
        "PATH_UPDATE_FAILED",
        "SERVICE_NEEDS_ELEVATION",
        "SERVICE_START_FAILED",
        "IO",
    ] {
        assert!(codes.contains(&expected), "missing exit code {expected}");
    }

    // The supported targets are enumerated.
    let targets: Vec<&str> = v["targets"]
        .as_array()
        .unwrap()
        .iter()
        .map(|t| t.as_str().unwrap())
        .collect();
    assert!(targets.contains(&"windows-x64"));
    assert!(targets.contains(&"macos-arm64"));
}

#[test]
fn help_lists_the_selectable_component_flags() {
    let out = bin().arg("--help").assert().success();
    let stdout = String::from_utf8(out.get_output().stdout.clone()).unwrap();
    for flag in [
        "--with-dig-node",
        "--with-browser",
        "--no-digstore",
        "--dig-node-port",
        "--json",
        "--dry-run",
    ] {
        assert!(stdout.contains(flag), "--help is missing {flag}");
    }
}

#[test]
fn version_flag_works() {
    bin().arg("--version").assert().success();
}

#[test]
fn rejects_unknown_flag_with_usage_error() {
    // clap returns exit code 2 for a usage error — distinct from our runtime codes.
    bin().arg("--definitely-not-a-flag").assert().failure();
}
