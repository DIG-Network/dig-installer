//! Read-only detection of the installed Chromium-family browsers, per OS (#609).
//!
//! The installer force-installs the DIG extension across every Chromium-family
//! browser on the machine via each browser's `ExtensionInstallForcelist`
//! managed policy (epic #602). Before it can do that it must first learn WHICH
//! browsers are present and WHERE each one's managed-policy hive lives. This
//! module answers exactly that — a read-only enumeration returning one
//! [`DetectedBrowser`] per installed browser, each carrying the per-OS
//! [`PolicyTarget`] the forcelist writer (#612) writes to and the GUI checklist
//! (#611) renders. It writes NOTHING — detection only.
//!
//! Layering (mirrors [`crate::elevation`]'s `gate` vs `is_elevated` split): the
//! [`CATALOGUE`] of known browsers, the per-OS [`PolicyTarget`] mapping, and the
//! pure [`detect`] matcher are cross-platform and fixture-tested; the per-OS
//! [`detect_installed`] probe is the thin runtime I/O layer that gathers raw
//! [`Evidence`] from the host (registry / app bundles / PATH) and feeds it to
//! `detect`. Only the pure layer carries logic, so every mapping and match is
//! unit-tested without a real registry, filesystem, or `Info.plist`.

use serde::Serialize;

use crate::target::Os;

/// The family a browser belongs to. Only Chromium-family browsers honor the
/// `ExtensionInstallForcelist` managed policy the installer targets, so today
/// this is the sole variant — modelled as an enum so a future non-Chromium
/// entry (which the forcelist could NOT target) is a distinct, explicit case
/// rather than a silent assumption.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum BrowserKind {
    /// A Chromium-derived browser that reads Chromium enterprise policy.
    ChromiumFamily,
}

/// Where a browser's DIG-managed extension policy is written, per OS. Carries
/// the exact coordinates the `ExtensionInstallForcelist` writer (#612) needs —
/// the installer NEVER writes here in this module (detection only), it only
/// reports the location.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "os", rename_all = "lowercase")]
pub enum PolicyTarget {
    /// Windows: the `HKEY_LOCAL_MACHINE`-relative registry policy key. The
    /// forcelist lives under `…\ExtensionInstallForcelist` beneath this key.
    Windows {
        /// e.g. `SOFTWARE\Policies\Google\Chrome`.
        policy_key: String,
    },
    /// macOS: the managed-preferences domain (the plist basename without the
    /// `.plist` suffix) whose `ExtensionInstallForcelist` array holds the entry.
    Macos {
        /// e.g. `com.google.Chrome`.
        preferences_domain: String,
    },
    /// Linux: the managed-policy directory a `dig-extension.json` policy file is
    /// dropped into (alongside any org policy, uniquely named).
    Linux {
        /// e.g. `/etc/opt/chrome/policies/managed`.
        managed_policy_dir: String,
    },
}

/// One installed Chromium-family browser found on the host. This is the typed,
/// machine-consumable result (§6.2) the GUI checklist (#611) renders and the
/// forcelist writer (#612) targets.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct DetectedBrowser {
    /// Stable slug id (`chrome`, `edge`, `brave`, `chromium`, `vivaldi`,
    /// `opera`) — the machine key, never localized.
    pub id: String,
    /// Human-friendly name for the GUI checklist (e.g. `Google Chrome`).
    pub display_name: String,
    /// The browser family (all detected browsers are [`BrowserKind::ChromiumFamily`]).
    pub kind: BrowserKind,
    /// The install location that evidenced detection (an executable path, app
    /// bundle, or binary), when one was matched. `None` when presence was
    /// evidenced by a registry uninstall entry alone (Windows).
    pub install_path: Option<String>,
    /// Always `true` for a returned browser — the field makes the "present?"
    /// answer explicit in the serialized contract so a consumer never has to
    /// infer it from list membership.
    pub detected: bool,
    /// Where #612 writes this browser's managed extension policy, for the host OS.
    pub policy_target: PolicyTarget,
}

/// A known Chromium-family browser and how to recognize + police it per OS.
/// Pure static data — the single source of truth the live probes and the pure
/// matcher both read, so a browser is described in exactly one place.
struct BrowserSpec {
    id: &'static str,
    display_name: &'static str,
    /// Case-insensitive substrings matched against Windows uninstall-key
    /// `DisplayName` values.
    windows_display_markers: &'static [&'static str],
    /// Case-insensitive distinctive substrings of the browser's Windows
    /// executable path (matched against confirmed-present paths).
    windows_path_markers: &'static [&'static str],
    /// The `HKLM`-relative Chromium policy key.
    windows_policy_key: &'static str,
    /// The macOS `CFBundleIdentifier`.
    macos_bundle_id: &'static str,
    /// macOS `.app` bundle names (matched against confirmed-present app paths).
    macos_app_names: &'static [&'static str],
    /// The macOS managed-preferences domain.
    macos_preferences_domain: &'static str,
    /// Linux launcher binary basenames.
    linux_binaries: &'static [&'static str],
    /// The Linux managed-policy directory.
    linux_policy_dir: &'static str,
}

impl BrowserSpec {
    /// The per-OS [`PolicyTarget`] for this browser — the pure mapping the
    /// forcelist writer (#612) consumes.
    fn policy_target(&self, os: Os) -> PolicyTarget {
        match os {
            Os::Windows => PolicyTarget::Windows {
                policy_key: self.windows_policy_key.to_string(),
            },
            Os::MacOs => PolicyTarget::Macos {
                preferences_domain: self.macos_preferences_domain.to_string(),
            },
            Os::Linux => PolicyTarget::Linux {
                managed_policy_dir: self.linux_policy_dir.to_string(),
            },
        }
    }
}

/// The catalogue of Chromium-family browsers the installer knows how to detect
/// and force-install into. The per-OS policy coordinates mirror the epic #602
/// D6 table (the single source of truth #612 also writes against).
const CATALOGUE: &[BrowserSpec] = &[
    BrowserSpec {
        id: "chrome",
        display_name: "Google Chrome",
        windows_display_markers: &["Google Chrome"],
        windows_path_markers: &[r"\Google\Chrome\Application\chrome.exe"],
        windows_policy_key: r"SOFTWARE\Policies\Google\Chrome",
        macos_bundle_id: "com.google.Chrome",
        macos_app_names: &["Google Chrome.app"],
        macos_preferences_domain: "com.google.Chrome",
        linux_binaries: &["google-chrome", "google-chrome-stable"],
        linux_policy_dir: "/etc/opt/chrome/policies/managed",
    },
    BrowserSpec {
        id: "edge",
        display_name: "Microsoft Edge",
        windows_display_markers: &["Microsoft Edge"],
        windows_path_markers: &[r"\Microsoft\Edge\Application\msedge.exe"],
        windows_policy_key: r"SOFTWARE\Policies\Microsoft\Edge",
        macos_bundle_id: "com.microsoft.Edge",
        macos_app_names: &["Microsoft Edge.app"],
        macos_preferences_domain: "com.microsoft.Edge",
        linux_binaries: &["microsoft-edge", "microsoft-edge-stable"],
        linux_policy_dir: "/etc/opt/edge/policies/managed",
    },
    BrowserSpec {
        id: "brave",
        display_name: "Brave",
        windows_display_markers: &["Brave"],
        windows_path_markers: &[r"\BraveSoftware\Brave-Browser\Application\brave.exe"],
        windows_policy_key: r"SOFTWARE\Policies\BraveSoftware\Brave",
        macos_bundle_id: "com.brave.Browser",
        macos_app_names: &["Brave Browser.app"],
        macos_preferences_domain: "com.brave.Browser",
        linux_binaries: &["brave-browser", "brave"],
        linux_policy_dir: "/etc/brave/policies/managed",
    },
    BrowserSpec {
        id: "chromium",
        display_name: "Chromium",
        windows_display_markers: &["Chromium"],
        windows_path_markers: &[r"\Chromium\Application\chrome.exe"],
        windows_policy_key: r"SOFTWARE\Policies\Chromium",
        macos_bundle_id: "org.chromium.Chromium",
        macos_app_names: &["Chromium.app"],
        macos_preferences_domain: "org.chromium.Chromium",
        linux_binaries: &["chromium", "chromium-browser"],
        linux_policy_dir: "/etc/chromium/policies/managed",
    },
    BrowserSpec {
        id: "vivaldi",
        display_name: "Vivaldi",
        windows_display_markers: &["Vivaldi"],
        windows_path_markers: &[r"\Vivaldi\Application\vivaldi.exe"],
        windows_policy_key: r"SOFTWARE\Policies\Vivaldi",
        macos_bundle_id: "com.vivaldi.Vivaldi",
        macos_app_names: &["Vivaldi.app"],
        macos_preferences_domain: "com.vivaldi.Vivaldi",
        linux_binaries: &["vivaldi", "vivaldi-stable"],
        linux_policy_dir: "/etc/opt/vivaldi/policies/managed",
    },
    BrowserSpec {
        id: "opera",
        display_name: "Opera",
        windows_display_markers: &["Opera "],
        windows_path_markers: &[r"\Programs\Opera\opera.exe", r"\Opera\opera.exe"],
        windows_policy_key: r"SOFTWARE\Policies\Opera Software\Opera",
        macos_bundle_id: "com.operasoftware.Opera",
        macos_app_names: &["Opera.app"],
        macos_preferences_domain: "com.operasoftware.Opera",
        linux_binaries: &["opera"],
        linux_policy_dir: "/etc/opt/opera/policies/managed",
    },
];

/// Raw signals gathered from the host, in one OS-agnostic container so the pure
/// [`detect`] matcher takes a single fixture-friendly input. A live probe fills
/// only the fields relevant to its OS; the rest stay empty.
#[derive(Debug, Default, Clone)]
pub struct Evidence {
    /// Windows: `DisplayName` values read from the uninstall registry keys.
    pub windows_display_names: Vec<String>,
    /// macOS: `CFBundleIdentifier` values read from installed app bundles.
    pub macos_bundle_ids: Vec<String>,
    /// Confirmed-present absolute paths (Windows executables, macOS `.app`
    /// bundles, or Linux binaries) — every path in here was verified to exist.
    pub present_paths: Vec<String>,
}

/// Match `haystacks` against `needles` case-insensitively, returning whether any
/// haystack CONTAINS any needle. Pure — the core of the Windows/macOS presence
/// test, unit-tested directly.
fn any_contains_ci(haystacks: &[String], needles: &[&str]) -> bool {
    haystacks.iter().any(|h| {
        let h = h.to_lowercase();
        needles.iter().any(|n| h.contains(&n.to_lowercase()))
    })
}

/// The final path component (after the last `/` or `\`), lowercased. Pure — so
/// the Linux "is this binary one of ours" test works on any host's path style.
fn basename_lower(path: &str) -> String {
    path.rsplit(['/', '\\'])
        .next()
        .unwrap_or(path)
        .to_lowercase()
}

/// Detect the installed browsers for `os` from gathered `evidence`. PURE: given
/// the same evidence it always returns the same list, so every OS's matching is
/// fixture-tested without touching a real registry/filesystem.
///
/// Returns one [`DetectedBrowser`] per catalogue entry evidenced as present,
/// in catalogue order, each with its per-OS [`PolicyTarget`] and (where a path
/// evidenced it) the matched `install_path`.
pub fn detect(os: Os, evidence: &Evidence) -> Vec<DetectedBrowser> {
    CATALOGUE
        .iter()
        .filter_map(|spec| {
            let install_path = matched_install_path(os, spec, evidence);
            let present = match os {
                Os::Windows => {
                    install_path.is_some()
                        || any_contains_ci(
                            &evidence.windows_display_names,
                            spec.windows_display_markers,
                        )
                }
                Os::MacOs => {
                    install_path.is_some()
                        || evidence
                            .macos_bundle_ids
                            .iter()
                            .any(|b| b.eq_ignore_ascii_case(spec.macos_bundle_id))
                }
                Os::Linux => install_path.is_some(),
            };
            present.then(|| DetectedBrowser {
                id: spec.id.to_string(),
                display_name: spec.display_name.to_string(),
                kind: BrowserKind::ChromiumFamily,
                install_path,
                detected: true,
                policy_target: spec.policy_target(os),
            })
        })
        .collect()
}

/// The first confirmed-present path that identifies `spec` on `os`, if any.
/// Pure helper feeding both the presence test and the reported `install_path`.
fn matched_install_path(os: Os, spec: &BrowserSpec, evidence: &Evidence) -> Option<String> {
    evidence
        .present_paths
        .iter()
        .find(|path| match os {
            Os::Windows => {
                let p = path.to_lowercase();
                spec.windows_path_markers
                    .iter()
                    .any(|m| p.contains(&m.to_lowercase()))
            }
            Os::MacOs => any_contains_ci(std::slice::from_ref(path), spec.macos_app_names),
            Os::Linux => {
                let base = basename_lower(path);
                spec.linux_binaries.iter().any(|b| base == b.to_lowercase())
            }
        })
        .cloned()
}

/// Detect the Chromium-family browsers installed on THIS host. The thin runtime
/// entry point: gather per-OS [`Evidence`], then delegate to the pure [`detect`].
/// Read-only — never writes any policy or touches any browser.
pub fn detect_installed() -> Vec<DetectedBrowser> {
    let Ok(target) = crate::target::Target::current() else {
        return Vec::new();
    };
    let evidence = gather_evidence(target.os);
    detect(target.os, &evidence)
}

/// Gather host evidence for `os`. Each arm is a thin, best-effort I/O probe that
/// degrades to whatever it can read (a failed probe yields fewer signals, never
/// a panic). Isolated behind `detect_installed` so the pure matcher stays pure.
fn gather_evidence(os: Os) -> Evidence {
    match os {
        Os::Windows => gather_windows_evidence(),
        Os::MacOs => gather_macos_evidence(),
        Os::Linux => gather_linux_evidence(),
    }
}

// -- Windows probe ------------------------------------------------------------

/// Read `DisplayName`s from the three uninstall registry roots and probe the
/// well-known per-browser executable paths. Best-effort: an unreadable hive
/// simply contributes no names.
#[cfg(windows)]
fn gather_windows_evidence() -> Evidence {
    use winreg::enums::{HKEY_CURRENT_USER, HKEY_LOCAL_MACHINE, KEY_READ, KEY_WOW64_64KEY};
    use winreg::RegKey;

    const UNINSTALL: &str = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall";
    const UNINSTALL_WOW: &str = r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall";

    let mut windows_display_names = Vec::new();
    let roots = [
        (HKEY_LOCAL_MACHINE, UNINSTALL),
        (HKEY_LOCAL_MACHINE, UNINSTALL_WOW),
        (HKEY_CURRENT_USER, UNINSTALL),
    ];
    for (hive, path) in roots {
        let Ok(uninstall) =
            RegKey::predef(hive).open_subkey_with_flags(path, KEY_READ | KEY_WOW64_64KEY)
        else {
            continue;
        };
        for entry in uninstall.enum_keys().flatten() {
            if let Ok(app) = uninstall.open_subkey(&entry) {
                if let Ok(name) = app.get_value::<String, _>("DisplayName") {
                    windows_display_names.push(name);
                }
            }
        }
    }

    Evidence {
        windows_display_names,
        present_paths: existing_paths(windows_candidate_paths()),
        ..Default::default()
    }
}

/// The well-known Windows executable paths to probe, expanded from the standard
/// install-root environment variables. Pure given the environment.
#[cfg(windows)]
fn windows_candidate_paths() -> Vec<String> {
    let mut roots = Vec::new();
    for var in ["ProgramFiles", "ProgramFiles(x86)", "LOCALAPPDATA"] {
        if let Ok(root) = std::env::var(var) {
            roots.push(root);
        }
    }
    let suffixes = [
        r"Google\Chrome\Application\chrome.exe",
        r"Microsoft\Edge\Application\msedge.exe",
        r"BraveSoftware\Brave-Browser\Application\brave.exe",
        r"Chromium\Application\chrome.exe",
        r"Vivaldi\Application\vivaldi.exe",
        r"Programs\Opera\opera.exe",
    ];
    let mut paths = Vec::new();
    for root in &roots {
        for suffix in suffixes {
            paths.push(format!(r"{root}\{suffix}"));
        }
    }
    paths
}

#[cfg(not(windows))]
fn gather_windows_evidence() -> Evidence {
    Evidence::default()
}

// -- macOS probe --------------------------------------------------------------

/// Scan the system + per-user `Applications` folders for known browser bundles,
/// reading each bundle's `CFBundleIdentifier` from its `Info.plist`. Best-effort.
#[cfg(target_os = "macos")]
fn gather_macos_evidence() -> Evidence {
    let mut app_dirs = vec![std::path::PathBuf::from("/Applications")];
    if let Some(home) = dirs::home_dir() {
        app_dirs.push(home.join("Applications"));
    }

    let known_app_names: Vec<&str> = CATALOGUE
        .iter()
        .flat_map(|s| s.macos_app_names.iter().copied())
        .collect();

    let mut present_paths = Vec::new();
    let mut macos_bundle_ids = Vec::new();
    for dir in app_dirs {
        for app in &known_app_names {
            let bundle = dir.join(app);
            if bundle.is_dir() {
                present_paths.push(bundle.to_string_lossy().into_owned());
                let plist = bundle.join("Contents/Info.plist");
                if let Ok(xml) = std::fs::read_to_string(&plist) {
                    if let Some(id) = parse_bundle_identifier(&xml) {
                        macos_bundle_ids.push(id);
                    }
                }
            }
        }
    }

    Evidence {
        macos_bundle_ids,
        present_paths,
        ..Default::default()
    }
}

#[cfg(not(target_os = "macos"))]
fn gather_macos_evidence() -> Evidence {
    Evidence::default()
}

/// Extract `CFBundleIdentifier` from an XML `Info.plist` body. Pure — the value
/// is the `<string>` immediately following the `<key>CFBundleIdentifier</key>`
/// element (whitespace between them ignored). `None` when the key is absent.
pub fn parse_bundle_identifier(plist_xml: &str) -> Option<String> {
    let after_key = plist_xml
        .split_once("<key>CFBundleIdentifier</key>")
        .map(|(_, rest)| rest)?;
    let (_, after_open) = after_key.split_once("<string>")?;
    let (value, _) = after_open.split_once("</string>")?;
    Some(value.trim().to_string())
}

// -- Linux probe --------------------------------------------------------------

/// Resolve each known launcher binary against the `PATH` directories, recording
/// the absolute path of every one that exists. Best-effort.
#[cfg(target_os = "linux")]
fn gather_linux_evidence() -> Evidence {
    let path_dirs: Vec<std::path::PathBuf> = std::env::var_os("PATH")
        .map(|p| std::env::split_paths(&p).collect())
        .unwrap_or_default();

    let mut present_paths = Vec::new();
    for spec in CATALOGUE {
        for binary in spec.linux_binaries {
            for dir in &path_dirs {
                let candidate = dir.join(binary);
                if candidate.is_file() {
                    present_paths.push(candidate.to_string_lossy().into_owned());
                    break;
                }
            }
        }
    }

    Evidence {
        present_paths,
        ..Default::default()
    }
}

#[cfg(not(target_os = "linux"))]
fn gather_linux_evidence() -> Evidence {
    Evidence::default()
}

/// Keep only the paths that exist on disk. Isolated so the candidate lists are
/// built purely and only this thin filter touches the filesystem.
#[cfg(windows)]
fn existing_paths(candidates: Vec<String>) -> Vec<String> {
    candidates
        .into_iter()
        .filter(|p| std::path::Path::new(p).exists())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn win_names(names: &[&str]) -> Evidence {
        Evidence {
            windows_display_names: names.iter().map(|s| s.to_string()).collect(),
            ..Default::default()
        }
    }
    fn paths(paths: &[&str]) -> Evidence {
        Evidence {
            present_paths: paths.iter().map(|s| s.to_string()).collect(),
            ..Default::default()
        }
    }

    #[test]
    fn catalogue_covers_the_six_target_browsers() {
        // The epic #602 D6 catalogue: Chrome, Edge, Brave, Chromium, Vivaldi, Opera.
        let ids: Vec<&str> = CATALOGUE.iter().map(|s| s.id).collect();
        assert_eq!(
            ids,
            ["chrome", "edge", "brave", "chromium", "vivaldi", "opera"]
        );
    }

    #[test]
    fn catalogue_ids_are_unique() {
        let mut ids: Vec<&str> = CATALOGUE.iter().map(|s| s.id).collect();
        ids.sort_unstable();
        ids.dedup();
        assert_eq!(
            ids.len(),
            CATALOGUE.len(),
            "duplicate browser id in catalogue"
        );
    }

    #[test]
    fn policy_target_maps_each_browser_to_the_d6_table() {
        // The forcelist writer (#612) depends on these EXACT coordinates.
        let chrome = &CATALOGUE[0];
        assert_eq!(
            chrome.policy_target(Os::Windows),
            PolicyTarget::Windows {
                policy_key: r"SOFTWARE\Policies\Google\Chrome".to_string()
            }
        );
        assert_eq!(
            chrome.policy_target(Os::MacOs),
            PolicyTarget::Macos {
                preferences_domain: "com.google.Chrome".to_string()
            }
        );
        assert_eq!(
            chrome.policy_target(Os::Linux),
            PolicyTarget::Linux {
                managed_policy_dir: "/etc/opt/chrome/policies/managed".to_string()
            }
        );

        let brave = CATALOGUE.iter().find(|s| s.id == "brave").unwrap();
        assert_eq!(
            brave.policy_target(Os::Windows),
            PolicyTarget::Windows {
                policy_key: r"SOFTWARE\Policies\BraveSoftware\Brave".to_string()
            }
        );
        let opera = CATALOGUE.iter().find(|s| s.id == "opera").unwrap();
        assert_eq!(
            opera.policy_target(Os::Windows),
            PolicyTarget::Windows {
                policy_key: r"SOFTWARE\Policies\Opera Software\Opera".to_string()
            }
        );
    }

    #[test]
    fn windows_detects_by_uninstall_display_name() {
        let found = detect(Os::Windows, &win_names(&["Google Chrome", "7-Zip 22.01"]));
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].id, "chrome");
        assert!(found[0].detected);
        assert_eq!(found[0].install_path, None); // evidenced by registry, not a path
    }

    #[test]
    fn windows_display_name_match_is_case_insensitive() {
        let found = detect(Os::Windows, &win_names(&["MICROSOFT EDGE"]));
        assert_eq!(
            found.iter().map(|b| b.id.as_str()).collect::<Vec<_>>(),
            ["edge"]
        );
    }

    #[test]
    fn windows_detects_by_executable_path_and_reports_it() {
        let p = r"C:\Program Files\Google\Chrome\Application\chrome.exe";
        let found = detect(Os::Windows, &paths(&[p]));
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].id, "chrome");
        assert_eq!(found[0].install_path.as_deref(), Some(p));
    }

    #[test]
    fn opera_marker_does_not_falsely_match_unrelated_apps() {
        // The "Opera " marker (trailing space) must not fire on, e.g., an
        // "Operations Manager" uninstall entry.
        let found = detect(Os::Windows, &win_names(&["Operations Manager"]));
        assert!(found.is_empty());
        // But the real Opera installer entry is caught.
        let real = detect(Os::Windows, &win_names(&["Opera Stable 100.0"]));
        assert_eq!(
            real.iter().map(|b| b.id.as_str()).collect::<Vec<_>>(),
            ["opera"]
        );
    }

    #[test]
    fn macos_detects_by_bundle_identifier() {
        let ev = Evidence {
            macos_bundle_ids: vec!["com.brave.Browser".to_string()],
            ..Default::default()
        };
        let found = detect(Os::MacOs, &ev);
        assert_eq!(
            found.iter().map(|b| b.id.as_str()).collect::<Vec<_>>(),
            ["brave"]
        );
    }

    #[test]
    fn macos_detects_by_app_bundle_path() {
        let found = detect(Os::MacOs, &paths(&["/Applications/Vivaldi.app"]));
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].id, "vivaldi");
        assert_eq!(
            found[0].install_path.as_deref(),
            Some("/Applications/Vivaldi.app")
        );
        assert_eq!(
            found[0].policy_target,
            PolicyTarget::Macos {
                preferences_domain: "com.vivaldi.Vivaldi".to_string()
            }
        );
    }

    #[test]
    fn linux_detects_by_binary_basename() {
        let found = detect(Os::Linux, &paths(&["/usr/bin/google-chrome-stable"]));
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].id, "chrome");
        assert_eq!(
            found[0].policy_target,
            PolicyTarget::Linux {
                managed_policy_dir: "/etc/opt/chrome/policies/managed".to_string()
            }
        );
    }

    #[test]
    fn linux_ignores_a_non_browser_binary() {
        let found = detect(Os::Linux, &paths(&["/usr/bin/ls", "/usr/local/bin/node"]));
        assert!(found.is_empty());
    }

    #[test]
    fn detects_multiple_browsers_in_catalogue_order() {
        let ev = win_names(&["Vivaldi", "Google Chrome", "Brave"]);
        let found = detect(Os::Windows, &ev);
        let ids: Vec<&str> = found.iter().map(|b| b.id.as_str()).collect();
        // Returned in catalogue order regardless of evidence order.
        assert_eq!(ids, ["chrome", "brave", "vivaldi"]);
    }

    #[test]
    fn no_evidence_detects_nothing() {
        assert!(detect(Os::Windows, &Evidence::default()).is_empty());
        assert!(detect(Os::MacOs, &Evidence::default()).is_empty());
        assert!(detect(Os::Linux, &Evidence::default()).is_empty());
    }

    #[test]
    fn parse_bundle_identifier_reads_the_value() {
        let plist = r#"<?xml version="1.0"?>
<plist version="1.0"><dict>
  <key>CFBundleName</key><string>Google Chrome</string>
  <key>CFBundleIdentifier</key>
  <string>com.google.Chrome</string>
</dict></plist>"#;
        assert_eq!(
            parse_bundle_identifier(plist).as_deref(),
            Some("com.google.Chrome")
        );
    }

    #[test]
    fn parse_bundle_identifier_absent_key_is_none() {
        assert_eq!(
            parse_bundle_identifier("<plist><dict></dict></plist>"),
            None
        );
        assert_eq!(parse_bundle_identifier(""), None);
    }

    #[test]
    fn detected_browser_serializes_with_tagged_policy_target() {
        let found = detect(Os::Linux, &paths(&["/usr/bin/brave-browser"]));
        let json = serde_json::to_value(&found[0]).unwrap();
        assert_eq!(json["id"], "brave");
        assert_eq!(json["kind"], "chromium-family");
        assert_eq!(json["detected"], true);
        assert_eq!(json["policy_target"]["os"], "linux");
        assert_eq!(
            json["policy_target"]["managed_policy_dir"],
            "/etc/brave/policies/managed"
        );
    }

    #[test]
    fn any_contains_ci_matches_substring_regardless_of_case() {
        assert!(any_contains_ci(&["Google Chrome".to_string()], &["chrome"]));
        assert!(!any_contains_ci(&["Firefox".to_string()], &["chrome"]));
    }

    #[test]
    fn basename_lower_takes_last_component_either_separator() {
        assert_eq!(basename_lower(r"C:\dir\Chrome.EXE"), "chrome.exe");
        assert_eq!(basename_lower("/usr/bin/opera"), "opera");
        assert_eq!(basename_lower("bare"), "bare");
    }

    #[test]
    fn detect_installed_never_panics() {
        // The real probe must be safe on any host (CI runs on all three OSes).
        let _ = detect_installed();
    }
}
