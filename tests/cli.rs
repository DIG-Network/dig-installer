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
    assert!(ids.contains(&"digs"));
    assert!(ids.contains(&"dig-node"));
    assert!(ids.contains(&"dig-relay"));
    assert!(ids.contains(&"dig-dns"));
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
        // #301 opt-out flags for the two components now installed by default.
        "--no-dig-node",
        "--no-dig-dns",
        "--dig-node-port",
        "--with-dig-dns",
        "--dig-dns-version",
        "--dig-dns-node",
        "--uninstall-dig-dns",
        "--uninstall-dig-node",
        "--json",
        "--dry-run",
    ] {
        assert!(stdout.contains(flag), "--help is missing {flag}");
    }
}

/// #301: the machine contract must advertise the universal-installer default —
/// digstore, dig-node AND dig-dns as `default: true` — so an agent driving the
/// installer knows a bare run installs all three. dig-relay + browser stay
/// `default: false` (opt-in). Drives the real built binary.
#[test]
fn help_json_advertises_all_three_core_components_as_default() {
    let out = bin().arg("--help-json").assert().success();
    let stdout = String::from_utf8(out.get_output().stdout.clone()).unwrap();
    let v: Value = serde_json::from_str(&stdout).expect("valid JSON");
    let default_of = |id: &str| -> bool {
        v["components"]
            .as_array()
            .unwrap()
            .iter()
            .find(|c| c["id"] == id)
            .unwrap_or_else(|| panic!("component {id} present"))["default"]
            .as_bool()
            .unwrap()
    };
    assert!(default_of("digstore"), "digstore default: true");
    assert!(default_of("dig-node"), "dig-node default: true (#301)");
    assert!(default_of("dig-dns"), "dig-dns default: true (#301)");
    assert!(!default_of("dig-relay"), "dig-relay stays opt-in");
    assert!(!default_of("browser"), "browser stays opt-in");
}

/// #301: `--help` prose must frame the installer as installing the full stack by
/// default with per-component opt-outs (not the old "digstore only" framing).
#[test]
fn help_prose_frames_the_universal_all_three_default() {
    let out = bin().arg("--help").assert().success();
    let stdout = String::from_utf8(out.get_output().stdout.clone()).unwrap();
    let low = stdout.to_lowercase();
    assert!(low.contains("by default"), "--help must state the default");
    assert!(low.contains("dig-node"), "--help mentions dig-node");
    assert!(low.contains("dig-dns"), "--help mentions dig-dns");
    // The stale "only the digstore CLI is installed" framing must be gone.
    assert!(
        !low.contains("only the digstore cli is installed"),
        "--help must not say only digstore is installed by default"
    );
}

/// #301: opting out of ALL THREE components is a valid, network-free, side-
/// effect-free run — proving the `--no-<component>` opt-outs parse and fully
/// disable the default stack (nothing to resolve, so no HTTP call is made).
#[test]
fn opting_out_of_every_component_is_network_free_and_installs_nothing() {
    let out = bin()
        .args([
            "--no-digstore",
            "--no-dig-node",
            "--no-dig-dns",
            "--dry-run",
            "--json",
        ])
        .assert()
        .success();
    let stdout = String::from_utf8(out.get_output().stdout.clone()).unwrap();
    let v: Value = serde_json::from_str(&stdout).expect("valid JSON");
    assert_eq!(v["ok"], true);
    assert!(
        v["result"]["components"].as_array().unwrap().is_empty(),
        "opting out of all three must resolve/install nothing"
    );
}

/// #301 rebrand regression guard (the user's complaint): the shipped GUI must
/// name itself "DIG Installer", never "DigStore Installer". Reads the actual
/// user-facing identity surfaces (Tauri config, HTML title, the on-screen title
/// bar) so the stale brand can never silently return. (The `digstore`/`DigStore`
/// CLI *component* name is untouched — this guards the INSTALLER's own name.)
#[test]
fn installer_is_branded_dig_installer_not_digstore_installer() {
    use std::fs;
    use std::path::Path;

    let dir = env!("CARGO_MANIFEST_DIR");
    let read = |rel: &str| -> String {
        fs::read_to_string(Path::new(dir).join(rel)).unwrap_or_else(|e| panic!("read {rel}: {e}"))
    };

    // No user-visible surface may contain the old installer name.
    for rel in [
        "gui/app/src-tauri/tauri.conf.json",
        "gui/app/index.html",
        "gui/app/src/TitleBar.jsx",
    ] {
        assert!(
            !read(rel).contains("DigStore Installer"),
            "{rel} still contains the stale 'DigStore Installer' brand"
        );
    }

    // The Tauri config names the app "DIG Installer" with the rebranded identifier.
    let conf: Value = serde_json::from_str(&read("gui/app/src-tauri/tauri.conf.json"))
        .expect("tauri.conf.json is valid JSON");
    assert_eq!(conf["productName"], "DIG Installer");
    assert_eq!(conf["app"]["windows"][0]["title"], "DIG Installer");
    assert_eq!(conf["identifier"], "net.dig.installer");

    // The on-screen title bar reads "DIG Installer".
    assert!(
        read("gui/app/src/TitleBar.jsx").contains("DIG Installer"),
        "TitleBar.jsx must render 'DIG Installer'"
    );
    assert!(
        read("gui/app/index.html").contains("<title>DIG Installer</title>"),
        "index.html <title> must be 'DIG Installer'"
    );
}

#[test]
fn version_flag_works() {
    bin().arg("--version").assert().success();
}

/// `--uninstall-dig-dns --dry-run` must be network-free, side-effect-free, and
/// always succeed (task #177: a permission issue is reported via
/// `needs_elevation`, never a process failure) — safe to run in CI on every OS.
#[test]
fn uninstall_dig_dns_dry_run_is_side_effect_free_and_succeeds() {
    let out = bin()
        .arg("--uninstall-dig-dns")
        .arg("--dry-run")
        .arg("--json")
        .assert()
        .success();
    let stdout = String::from_utf8(out.get_output().stdout.clone()).unwrap();
    let v: Value = serde_json::from_str(&stdout).expect("valid JSON");
    assert_eq!(v["ok"], true);
    assert_eq!(v["result"]["uninstalled"], false);
    assert!(v["result"]["residue_removed"]
        .as_array()
        .unwrap()
        .is_empty());
}

/// `--uninstall-dig-node --dry-run` must be network-free, side-effect-free, and
/// always succeed (task #140: a missing binary/elevation issue is reported via
/// the result `note`, never a process failure) — safe to run in CI on every OS.
#[test]
fn uninstall_dig_node_dry_run_is_side_effect_free_and_succeeds() {
    let out = bin()
        .arg("--uninstall-dig-node")
        .arg("--dry-run")
        .arg("--json")
        .assert()
        .success();
    let stdout = String::from_utf8(out.get_output().stdout.clone()).unwrap();
    let v: Value = serde_json::from_str(&stdout).expect("valid JSON");
    assert_eq!(v["ok"], true);
    assert_eq!(v["result"]["uninstalled"], false);
    assert_eq!(v["result"]["dig_local_removed"], false);
    assert!(v["result"]["note"].as_str().unwrap().contains("would run"));
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

/// #491: the GUI component-selection defaults must match the CLI —
/// **dig-relay UNCHECKED by default** (advanced/opt-in) and the **DIG Browser
/// hidden** (not offered). Reads the actual shipped GUI sources (same
/// text-assertion pattern as the branding/vocabulary guards) so neither can
/// silently regress to pre-checked/offered. The CLI side is already guarded by
/// `help_json_advertises_all_three_core_components_as_default` (dig-relay +
/// browser are `default: false`).
#[test]
fn gui_defaults_dig_relay_unchecked_and_browser_hidden() {
    use std::fs;
    use std::path::Path;

    let dir = env!("CARGO_MANIFEST_DIR");
    let read = |rel: &str| -> String {
        fs::read_to_string(Path::new(dir).join(rel)).unwrap_or_else(|e| panic!("read {rel}: {e}"))
    };

    // data.jsx: dig-relay present but NOT pre-checked; browser entry kept but hidden.
    let data = read("gui/app/src/data.jsx");
    assert!(
        data.contains(r#"id: "dig-relay""#),
        "dig-relay entry present"
    );
    assert!(
        data.contains(r#"id: "browser""#),
        "browser entry kept (for easy re-enable)"
    );
    assert!(
        data.contains("hidden: true"),
        "the DIG Browser must be hidden by default (#491)"
    );
    // dig-relay is the only `on: false` optional component.
    assert!(
        data.contains("on: false"),
        "dig-relay must default UNCHECKED (on: false) (#491)"
    );

    // App.jsx initial selection: dig-relay false, browser NOT pre-selected.
    let app = read("gui/app/src/App.jsx");
    assert!(
        app.contains(r#""dig-relay": false"#),
        "dig-relay must default OFF in the initial GUI selection (#491)"
    );
    assert!(
        !app.contains("browser: true"),
        "the DIG Browser must not be pre-selected in the GUI (#491)"
    );

    // Components.jsx filters `hidden` components out of the offered set.
    let comp = read("gui/app/src/steps/Components.jsx");
    assert!(
        comp.contains("!c.hidden"),
        "Components.jsx must not render a hidden component (#491)"
    );
}
