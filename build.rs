//! Build script: on Windows, embed an explicit `asInvoker` application manifest.
//!
//! Windows "Installer Detection" auto-elevates executables whose name/metadata
//! contains "install"/"setup" unless they declare a `requestedExecutionLevel`.
//! `dig-installer` is per-user (it writes to %LOCALAPPDATA% + HKCU only) and
//! must NOT force a UAC prompt — and, crucially, the auto-elevation otherwise
//! makes even `cargo test` fail to launch the test binary ("requires
//! elevation", os error 740). Pin `asInvoker` so the binary (and its tests) run
//! at the caller's level. (Service registration that needs admin is delegated to
//! dig-node, which prompts for elevation itself when required.)
//!
//! It also compiles `assets/dig.rc`, which carries the branded DIG application
//! icon, into the same binaries. The two are independent resource kinds
//! (RT_GROUP_ICON/RT_ICON from the .res, RT_MANIFEST from `/MANIFEST:EMBED`)
//! and coexist: the manifest is NOT declared in the .rc precisely so neither
//! can displace the other.
//!
//! No-op on non-Windows.

fn main() {
    #[cfg(windows)]
    {
        embed_manifest();
        embed_icon();
    }
}

#[cfg(windows)]
fn embed_manifest() {
    use std::path::PathBuf;

    let manifest = r#"<?xml version="1.0" encoding="utf-8"?>
<assembly xmlns="urn:schemas-microsoft-com:asm.v1" manifestVersion="1.0">
  <trustInfo xmlns="urn:schemas-microsoft-com:asm.v3">
    <security>
      <requestedPrivileges>
        <requestedExecutionLevel level="asInvoker" uiAccess="false" />
      </requestedPrivileges>
    </security>
  </trustInfo>
</assembly>"#;

    let out_dir = PathBuf::from(std::env::var("OUT_DIR").unwrap());
    let manifest_path = out_dir.join("dig-installer.manifest");
    std::fs::write(&manifest_path, manifest).expect("write manifest");

    // Link the manifest into every linked artifact of this crate — the `bin` AND
    // the unit-test harness (which is also an .exe Windows tries to auto-elevate
    // because the crate name contains "installer"). `rustc-link-arg` applies to
    // all binary-like targets; the lib is unaffected.
    println!("cargo:rustc-link-arg=/MANIFEST:EMBED");
    println!(
        "cargo:rustc-link-arg=/MANIFESTINPUT:{}",
        manifest_path.display()
    );
    println!("cargo:rerun-if-changed=build.rs");
}

/// Compile the branded DIG icon into the installer binary.
///
/// `embed_resource::compile` links the compiled `.res` with
/// `cargo:rustc-link-arg-bins`, so it reaches the shipped binaries and NOT the
/// unit-test harness. That is the deliberate opposite of the manifest above:
/// the manifest must reach the test harness (Windows would otherwise try to
/// auto-elevate it), whereas a test harness has no need of an icon, and
/// leaving its link line untouched keeps this change off the os-error-740 path.
///
/// The result is checked rather than discarded: an environment that cannot
/// compile a resource would otherwise silently produce an unbranded binary,
/// which is precisely the failure this build step exists to prevent.
#[cfg(windows)]
fn embed_icon() {
    embed_resource::compile("assets/dig.rc", embed_resource::NONE)
        .manifest_required()
        .expect("failed to compile assets/dig.rc — no usable Windows resource compiler?");

    println!("cargo:rerun-if-changed=assets/dig.rc");
    println!("cargo:rerun-if-changed=assets/dig.ico");
}
