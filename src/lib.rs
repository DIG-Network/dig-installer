//! The universal DIG installer (library surface).
//!
//! Installs the **digstore CLI** by downloading the released binary for the host
//! OS/arch from `DIG-Network/digstore` and placing it on PATH, and OPTIONALLY
//! installs the **dig-node** local node (the standalone twin of the DIG
//! Browser's in-process node) as an OS service by delegating to dig-node's own
//! `install`/`start` subcommands.
//!
//! See SYSTEM.md → "Canonical terminology & branding" for the $DIG / DIGHUb /
//! dig-node naming this installer's user-facing copy follows.
//!
//! Layering: the pure logic ([`target`], [`release`], [`paths::path_append`],
//! [`download::tag_name_from_release_json`], [`service::install_env`]) is
//! unit-tested; [`run`] is the imperative orchestration that performs I/O.

pub mod download;
pub mod paths;
pub mod release;
pub mod service;
pub mod target;

use std::path::PathBuf;

use release::Repo;
use service::ServiceConfig;
use target::Target;

/// What the user asked the installer to do.
#[derive(Debug, Clone)]
pub struct InstallPlan {
    /// Directory to place the `digstore` (and `dig-node`) binaries in.
    pub bin_dir: PathBuf,
    /// digstore version/tag to install: `None` ⇒ latest released.
    pub digstore_version: Option<String>,
    /// Also install + register dig-node as a service.
    pub with_dig_node: bool,
    /// dig-node version/tag to install: `None` ⇒ latest released.
    pub dig_node_version: Option<String>,
    /// Service configuration when `with_dig_node` is set.
    pub service: ServiceConfig,
    /// Add the bin dir to PATH (default true).
    pub modify_path: bool,
    /// Print actions without performing them.
    pub dry_run: bool,
}

impl Default for InstallPlan {
    fn default() -> Self {
        InstallPlan {
            bin_dir: paths::default_bin_dir(),
            digstore_version: None,
            with_dig_node: false,
            dig_node_version: None,
            service: ServiceConfig::default(),
            modify_path: true,
            dry_run: false,
        }
    }
}

/// Resolve a tool's tag: an explicit version (normalized to a `v`-tag) or the
/// repo's latest released tag.
fn resolve_tag(repo: &Repo, requested: &Option<String>) -> Result<String, String> {
    match requested {
        Some(v) => Ok(release::tag_from_input(v)),
        None => download::latest_tag(repo),
    }
}

/// Download a tool binary for `target` from `repo` at the resolved tag into
/// `bin_dir`, returning the path it was written to (or would be, on dry-run).
fn install_tool(
    repo: &Repo,
    requested: &Option<String>,
    target: &Target,
    bin_dir: &std::path::Path,
    dry_run: bool,
) -> Result<PathBuf, String> {
    let tag = resolve_tag(repo, requested)?;
    let version = release::version_from_tag(&tag);
    let url = repo.binary_url(&tag, &version, target);
    let dest = bin_dir.join(target.exe_name(&repo.stem));
    println!("  {} {} ({})", repo.stem, version, target);
    println!("    from {url}");
    println!("    to   {}", dest.display());
    if !dry_run {
        download::download_binary(&url, &dest, None)?;
        println!("    ✓ installed {}", dest.display());
    }
    Ok(dest)
}

/// Run the install plan end-to-end. Prints progress to stdout; returns the paths
/// of the installed binaries on success.
pub fn run(plan: &InstallPlan) -> Result<Vec<PathBuf>, String> {
    let target = Target::current()?;
    println!("DIG installer — target {target}");
    if plan.dry_run {
        println!("(dry run — no changes will be made)");
    }
    let mut installed = Vec::new();

    // 1. digstore CLI (always).
    println!("Installing the digstore CLI:");
    let digstore = install_tool(
        &Repo::digstore(),
        &plan.digstore_version,
        &target,
        &plan.bin_dir,
        plan.dry_run,
    )?;
    installed.push(digstore);

    // 2. PATH.
    if plan.modify_path {
        println!("Adding {} to PATH:", plan.bin_dir.display());
        if plan.dry_run {
            println!("    (would add to PATH)");
        } else {
            match paths::add_to_path(&plan.bin_dir) {
                Ok(note) => println!("    ✓ {note}"),
                Err(e) => println!("    ! could not update PATH automatically ({e})"),
            }
        }
    }

    // 3. dig-node service (optional).
    if plan.with_dig_node {
        println!("Installing the dig-node local node:");
        let dig_node = match install_tool(
            &Repo::dig_node(),
            &plan.dig_node_version,
            &target,
            &plan.bin_dir,
            plan.dry_run,
        ) {
            Ok(p) => p,
            // Fall back to the pre-rename repo/asset while the rename is pending.
            Err(primary_err) => {
                println!("    (dig-node release not found: {primary_err})");
                println!("    trying the pre-rename dig-companion release…");
                install_tool(
                    &Repo::dig_node_legacy(),
                    &plan.dig_node_version,
                    &target,
                    &plan.bin_dir,
                    plan.dry_run,
                )?
            }
        };
        installed.push(dig_node.clone());

        println!(
            "Registering dig-node as an OS service (port {}):",
            plan.service.port
        );
        if plan.dry_run {
            println!(
                "    (would run `dig-node install`{})",
                if plan.service.start {
                    " && `dig-node start`"
                } else {
                    ""
                }
            );
        } else {
            match service::install_service(&dig_node, &plan.service) {
                Ok(note) => println!("    ✓ {note}"),
                Err(e) => {
                    // Service install can require elevation (Windows SCM). Surface
                    // it but don't fail the whole install — the binary is placed.
                    println!("    ! {e}");
                    println!("    dig-node is installed at {}; run `dig-node install` from an elevated console to register the service.", dig_node.display());
                }
            }
        }
    }

    println!("Done.");
    Ok(installed)
}
