//! OS/architecture resolution and GitHub release-asset name derivation.
//!
//! This is the pure, testable heart of the installer: given a `(os, arch)` pair
//! it derives the **release-asset filename** the DIG-Network release workflows
//! publish, and the canonical **download URL** to fetch it from GitHub. No I/O
//! happens here — `current()` reads `std::env::consts`, everything else is a
//! pure function of its inputs so the resolution logic is unit-tested without a
//! network or a particular host.
//!
//! ## Asset naming contracts (mirrored from the producing repos)
//!
//! These names MUST match what the upstream release workflows actually upload,
//! or the installer 404s. They are pinned here and asserted by tests.
//!
//! * **digstore** (`DIG-Network/digstore` `release.yml`, post-extraction)
//!   publishes the raw per-OS CLI binary as `digstore-<ver>-<os_arch>[.exe]` —
//!   exactly what this installer downloads and places on PATH.
//! * **dig-node** (`DIG-Network/dig-node`, formerly `dig-companion`)
//!   `release.yml` publishes `dig-node-<ver>-<os_arch>[.exe]` per OS/arch.
//!
//! `<os_arch>` is one of: `windows-x64`, `linux-x64`, `macos-arm64`,
//! `macos-x64` — exactly the matrix `out_name`s the workflows use.

use std::fmt;

/// A resolved install target: the operating system and CPU architecture the
/// installer is running on (or was asked to resolve for).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Target {
    pub os: Os,
    pub arch: Arch,
}

/// Supported operating systems.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Os {
    Windows,
    Linux,
    MacOs,
}

/// Supported CPU architectures.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Arch {
    X64,
    Arm64,
}

impl Os {
    /// Parse `std::env::consts::OS`-style strings into a supported `Os`.
    pub fn from_consts(os: &str) -> Result<Os, String> {
        match os {
            "windows" => Ok(Os::Windows),
            "linux" => Ok(Os::Linux),
            "macos" => Ok(Os::MacOs),
            other => Err(format!("unsupported OS: {other}")),
        }
    }
}

impl Arch {
    /// Parse `std::env::consts::ARCH`-style strings into a supported `Arch`.
    /// `x86_64` and `aarch64`/`arm64` are the only DIG release matrices.
    pub fn from_consts(arch: &str) -> Result<Arch, String> {
        match arch {
            "x86_64" => Ok(Arch::X64),
            "aarch64" | "arm64" => Ok(Arch::Arm64),
            other => Err(format!("unsupported architecture: {other}")),
        }
    }
}

impl Target {
    /// The actual host target, read from compile-time `std::env::consts`.
    pub fn current() -> Result<Target, String> {
        Ok(Target {
            os: Os::from_consts(std::env::consts::OS)?,
            arch: Arch::from_consts(std::env::consts::ARCH)?,
        })
    }

    /// The `<os_arch>` slug used in release-asset filenames, matching the
    /// release workflows' matrix `out_name`s.
    ///
    /// macOS distinguishes arm64 vs x64; Windows/Linux ship x64 only today, and
    /// an arm64 request on those falls back to the x64 slug (the universal
    /// binaries are x64; arm Linux/Windows run them under emulation), which is
    /// surfaced to the caller as a non-error best-effort.
    pub fn slug(&self) -> &'static str {
        match (self.os, self.arch) {
            (Os::Windows, _) => "windows-x64",
            (Os::Linux, _) => "linux-x64",
            (Os::MacOs, Arch::Arm64) => "macos-arm64",
            (Os::MacOs, Arch::X64) => "macos-x64",
        }
    }

    /// The executable file extension for this OS (`.exe` on Windows, else none).
    pub fn exe_ext(&self) -> &'static str {
        match self.os {
            Os::Windows => ".exe",
            _ => "",
        }
    }

    /// The on-PATH executable name for a tool (adds `.exe` on Windows).
    pub fn exe_name(&self, stem: &str) -> String {
        format!("{stem}{}", self.exe_ext())
    }

    /// Release-asset filename for a tool at a given version.
    ///
    /// e.g. `asset_name("digstore", "0.6.0")` →
    ///   `digstore-0.6.0-windows-x64.exe` on Windows,
    ///   `digstore-0.6.0-linux-x64` on Linux.
    ///
    /// `version` is the bare semver (no leading `v`); callers strip the `v`.
    pub fn asset_name(&self, tool: &str, version: &str) -> String {
        format!("{tool}-{version}-{}{}", self.slug(), self.exe_ext())
    }
}

impl fmt::Display for Target {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let os = match self.os {
            Os::Windows => "windows",
            Os::Linux => "linux",
            Os::MacOs => "macos",
        };
        let arch = match self.arch {
            Arch::X64 => "x64",
            Arch::Arm64 => "arm64",
        };
        write!(f, "{os}/{arch}")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_supported_os() {
        assert_eq!(Os::from_consts("windows").unwrap(), Os::Windows);
        assert_eq!(Os::from_consts("linux").unwrap(), Os::Linux);
        assert_eq!(Os::from_consts("macos").unwrap(), Os::MacOs);
        assert!(Os::from_consts("plan9").is_err());
    }

    #[test]
    fn parses_supported_arch() {
        assert_eq!(Arch::from_consts("x86_64").unwrap(), Arch::X64);
        assert_eq!(Arch::from_consts("aarch64").unwrap(), Arch::Arm64);
        assert_eq!(Arch::from_consts("arm64").unwrap(), Arch::Arm64);
        assert!(Arch::from_consts("riscv64").is_err());
    }

    #[test]
    fn slug_matches_release_matrix_out_names() {
        // These four slugs are exactly the release workflows' matrix out_names.
        let win = Target {
            os: Os::Windows,
            arch: Arch::X64,
        };
        let lin = Target {
            os: Os::Linux,
            arch: Arch::X64,
        };
        let mac_arm = Target {
            os: Os::MacOs,
            arch: Arch::Arm64,
        };
        let mac_x64 = Target {
            os: Os::MacOs,
            arch: Arch::X64,
        };
        assert_eq!(win.slug(), "windows-x64");
        assert_eq!(lin.slug(), "linux-x64");
        assert_eq!(mac_arm.slug(), "macos-arm64");
        assert_eq!(mac_x64.slug(), "macos-x64");
    }

    #[test]
    fn exe_ext_is_exe_only_on_windows() {
        assert_eq!(
            Target {
                os: Os::Windows,
                arch: Arch::X64
            }
            .exe_ext(),
            ".exe"
        );
        assert_eq!(
            Target {
                os: Os::Linux,
                arch: Arch::X64
            }
            .exe_ext(),
            ""
        );
        assert_eq!(
            Target {
                os: Os::MacOs,
                arch: Arch::Arm64
            }
            .exe_ext(),
            ""
        );
    }

    #[test]
    fn exe_name_adds_exe_on_windows_only() {
        assert_eq!(
            Target {
                os: Os::Windows,
                arch: Arch::X64
            }
            .exe_name("digstore"),
            "digstore.exe"
        );
        assert_eq!(
            Target {
                os: Os::Linux,
                arch: Arch::X64
            }
            .exe_name("dig-node"),
            "dig-node"
        );
    }

    #[test]
    fn asset_name_matches_published_release_assets() {
        let win = Target {
            os: Os::Windows,
            arch: Arch::X64,
        };
        let lin = Target {
            os: Os::Linux,
            arch: Arch::X64,
        };
        let mac = Target {
            os: Os::MacOs,
            arch: Arch::Arm64,
        };
        assert_eq!(
            win.asset_name("digstore", "0.6.0"),
            "digstore-0.6.0-windows-x64.exe"
        );
        assert_eq!(
            lin.asset_name("digstore", "0.6.0"),
            "digstore-0.6.0-linux-x64"
        );
        assert_eq!(
            mac.asset_name("dig-node", "0.2.0"),
            "dig-node-0.2.0-macos-arm64"
        );
    }

    #[test]
    fn display_is_os_slash_arch() {
        assert_eq!(
            Target {
                os: Os::Linux,
                arch: Arch::X64
            }
            .to_string(),
            "linux/x64"
        );
        assert_eq!(
            Target {
                os: Os::MacOs,
                arch: Arch::Arm64
            }
            .to_string(),
            "macos/arm64"
        );
    }
}
