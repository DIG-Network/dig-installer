//! `dig-installer` — the universal DIG installer CLI.
//!
//! Installs the **digstore CLI** ($DIG content tooling) and, with
//! `--with-dig-node`, the **dig-node** local node as an OS service. Downloads
//! the released binaries for this OS/arch from the DIG-Network GitHub releases
//! and places `digstore` on PATH. See the README for the full flag list.

use clap::Parser;

use dig_installer::service::ServiceConfig;
use dig_installer::{paths, InstallPlan};

#[derive(Parser, Debug)]
#[command(
    name = "dig-installer",
    version,
    about = "Universal DIG installer — installs the digstore CLI and (optionally) the dig-node service",
    long_about = "Installs the digstore CLI (the $DIG content tooling) for this OS/arch by \
downloading the released binary from DIG-Network/digstore and adding it to your PATH. \
With --with-dig-node it also installs the dig-node local node as an OS service \
(Windows service / systemd / launchd) and starts it, so apps and the DIG Browser \
extension can resolve chia:// content through your own machine."
)]
struct Cli {
    /// Directory to install the binaries into (default: per-user DIG bin dir).
    #[arg(long, value_name = "DIR")]
    bin_dir: Option<std::path::PathBuf>,

    /// digstore version to install (e.g. 0.6.0); default: latest released.
    #[arg(long, value_name = "VERSION")]
    digstore_version: Option<String>,

    /// Also install the dig-node local node and register it as an OS service.
    /// `--service` is an alias for the same behaviour.
    #[arg(long, alias = "service")]
    with_dig_node: bool,

    /// dig-node version to install (e.g. 0.2.0); default: latest released.
    #[arg(long, value_name = "VERSION")]
    dig_node_version: Option<String>,

    /// Loopback port the dig-node service serves on (with --with-dig-node).
    #[arg(long, value_name = "PORT", default_value_t = 8080)]
    dig_node_port: u16,

    /// With --with-dig-node, install the service but do NOT start it.
    /// (By default the service is started immediately.)
    #[arg(long = "no-service-start")]
    no_service_start: bool,

    /// Do not modify PATH (just place the binaries).
    #[arg(long)]
    no_path: bool,

    /// Print what would be done without downloading or changing anything.
    #[arg(long)]
    dry_run: bool,
}

fn main() -> std::process::ExitCode {
    let cli = Cli::parse();

    let plan = InstallPlan {
        bin_dir: cli.bin_dir.unwrap_or_else(paths::default_bin_dir),
        digstore_version: cli.digstore_version,
        with_dig_node: cli.with_dig_node,
        dig_node_version: cli.dig_node_version,
        service: ServiceConfig {
            port: cli.dig_node_port,
            start: !cli.no_service_start,
        },
        modify_path: !cli.no_path,
        dry_run: cli.dry_run,
    };

    match dig_installer::run(&plan) {
        Ok(_) => std::process::ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("error: {e}");
            std::process::ExitCode::FAILURE
        }
    }
}
