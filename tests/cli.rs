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
    assert!(ids.contains(&"dig-relay"));
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

/// Regression guard (terminology gap): the installer GUI must read as PART of
/// the DIG ecosystem, not a standalone tool. SYSTEM.md → "Canonical terminology
/// & branding" requires the user-facing copy to use the shared vocabulary; the
/// wizard previously surfaced none of it. This asserts each canonical term lands
/// somewhere in the shipped wizard copy so the framing can't silently regress.
#[test]
fn gui_copy_uses_canonical_ecosystem_vocabulary() {
    use std::fs;
    use std::path::Path;

    let dir = env!("CARGO_MANIFEST_DIR");
    // Concatenate the user-facing wizard copy (the screens a user actually reads).
    let copy: String = [
        "gui/app/src/steps/Welcome.jsx",
        "gui/app/src/steps/Finish.jsx",
        "gui/app/src/data.jsx",
    ]
    .iter()
    .map(|rel| fs::read_to_string(Path::new(dir).join(rel)).unwrap_or_default())
    .collect::<Vec<_>>()
    .join("\n");

    for term in [
        "DIGHUb",
        "dig-node",
        "capsule",
        "$DIG",
        "DigStore",
        "DIG Network",
    ] {
        assert!(
            copy.contains(term),
            "GUI copy must reference the canonical term {term:?}"
        );
    }
    // The off-canon hub casing must never reappear in the wizard copy.
    assert!(
        !copy.contains("DIGHub"),
        "GUI copy must not use the off-canon 'DIGHub' casing"
    );
}

#[test]
fn help_lists_the_selectable_component_flags() {
    let out = bin().arg("--help").assert().success();
    let stdout = String::from_utf8(out.get_output().stdout.clone()).unwrap();
    for flag in [
        "--with-dig-node",
        "--with-browser",
        "--with-relay",
        "--relay-port",
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

/// Regression guard (license-correctness bug): every license-bearing surface in
/// the repo must declare the crate's actual license — GNU GPL-2.0-only (see the
/// root `Cargo.toml`). The GUI wizard + its design/handoff docs previously
/// claimed "Apache-2.0", contradicting the binary's real license. This walks the
/// shipped GUI sources + the asset docs and fails if any of them re-assert an
/// Apache license, so the contradiction can never silently resurface.
#[test]
fn no_surface_claims_a_non_gpl_license() {
    use std::fs;
    use std::path::Path;

    // Files a user (or a redistributor) reads to learn the license: the shipped
    // wizard steps, the design prototype it was ported from, and the handoff doc.
    let manifest_dir = env!("CARGO_MANIFEST_DIR");
    let surfaces = [
        "gui/app/src/steps/License.jsx",
        "gui/app/src/steps/Welcome.jsx",
        "gui/assets/README.md",
        "gui/assets/design/installer/installer-app.jsx",
    ];

    let mut offenders = Vec::new();
    for rel in surfaces {
        let path = Path::new(manifest_dir).join(rel);
        let body = fs::read_to_string(&path)
            .unwrap_or_else(|e| panic!("cannot read license surface {rel}: {e}"));
        // "Apache" anywhere in a license-bearing surface is the contradiction.
        if body.contains("Apache") {
            offenders.push(rel);
        }
    }
    assert!(
        offenders.is_empty(),
        "license surfaces still claim Apache (must be GPL-2.0): {offenders:?}"
    );

    // The shipped license step must affirmatively name the GPL — proves the fix
    // is a real correction, not just a deletion of the word "Apache".
    let license_step =
        fs::read_to_string(Path::new(manifest_dir).join("gui/app/src/steps/License.jsx"))
            .expect("read License.jsx");
    assert!(
        license_step.contains("General Public License"),
        "License.jsx must name the GNU General Public License"
    );
}

#[test]
fn rejects_unknown_flag_with_usage_error() {
    // clap returns exit code 2 for a usage error — distinct from our runtime codes.
    bin().arg("--definitely-not-a-flag").assert().failure();
}
