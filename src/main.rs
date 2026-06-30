//! `dig-installer` — the universal DIG installer CLI (a thin shim).
//!
//! Resolves + downloads the LATEST per-OS/arch GitHub release asset for the
//! selected components — the **digstore CLI**, the **dig-node** local node
//! (installed as an OS service + a `dig.local` hosts entry), and the **DIG
//! Browser** — at install time. Bundles nothing. See the README for the full
//! flag list and the exit-code table.
//!
//! Agent-friendly (AGENT_FRIENDLY.md → dig-installer): a global `--json` emits a
//! single structured result object to stdout (prose → stderr, no prompts);
//! `--help-json` dumps the full invocation contract incl. the exit-code table;
//! failures carry a stable `UPPER_SNAKE` code + a distinct exit code.

use clap::Parser;

use dig_installer::service::ServiceConfig;
use dig_installer::{error_json, help_json, paths, InstallPlan};

#[derive(Parser, Debug)]
#[command(
    name = "dig-installer",
    version,
    about = "Universal DIG installer — installs the digstore CLI, the dig-node service, and the DIG Browser",
    long_about = "Resolves and downloads the latest per-OS/arch release asset for the selected \
components from the DIG-Network GitHub releases (it bundles nothing):\n  \
* the digstore CLI (added to PATH),\n  \
* the dig-node local node (installed + started as an OS service, with a best-effort \
127.0.0.2 dig.local hosts entry), and\n  \
* the DIG Browser native installer.\n\n\
Components are selectable (--with-digstore / --with-dig-node / --with-browser / --service); \
by default only the digstore CLI is installed. Use --json for machine-readable output and \
--help-json for the full invocation contract (incl. the exit-code table)."
)]
struct Cli {
    /// Directory to install the binaries into (default: per-user DIG bin dir).
    #[arg(long, value_name = "DIR")]
    bin_dir: Option<std::path::PathBuf>,

    /// Explicitly select the digstore CLI (it is installed by default anyway;
    /// this flag exists for symmetry/clarity with --with-dig-node/--with-browser).
    #[arg(long)]
    with_digstore: bool,

    /// Skip installing the digstore CLI.
    #[arg(long = "no-digstore")]
    no_digstore: bool,

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

    /// Also download the DIG Browser native installer for this OS.
    #[arg(long)]
    with_browser: bool,

    /// DIG Browser version to install; default: latest released.
    #[arg(long, value_name = "VERSION")]
    browser_version: Option<String>,

    /// Also install + register dig-relay as a service (run-your-own-relay). ADVANCED/optional —
    /// the default node already points at relay.dig.net, so most users do NOT need this.
    #[arg(long)]
    with_relay: bool,

    /// dig-relay version to install (e.g. 0.1.0); default: latest released.
    #[arg(long, value_name = "VERSION")]
    relay_version: Option<String>,

    /// Relay WebSocket port the relay service serves on (with --with-relay).
    #[arg(long, value_name = "PORT", default_value_t = 9450)]
    relay_port: u16,

    /// Relay HTTP /health port the relay service serves on (with --with-relay).
    #[arg(long, value_name = "PORT", default_value_t = 9451)]
    relay_health_port: u16,

    /// Do not modify PATH (just place the binaries).
    #[arg(long)]
    no_path: bool,

    /// Print what would be done without downloading or changing anything.
    #[arg(long)]
    dry_run: bool,

    /// Emit a single structured JSON result to stdout (progress → stderr,
    /// no prompts/spinners). On failure emit {ok:false,error:{code,...}}.
    #[arg(long, global = true)]
    json: bool,

    /// Print the full machine-readable invocation contract (commands, global
    /// flags, the exit-code table) as JSON, then exit.
    #[arg(long = "help-json")]
    help_json: bool,
}

fn main() -> std::process::ExitCode {
    let cli = Cli::parse();

    if cli.help_json {
        print!("{}", help_json());
        return std::process::ExitCode::SUCCESS;
    }
    // (`help_json`/`error_json` live in the library so they are unit-tested
    // directly; main.rs only wires them to stdout/exit codes.)

    // digstore is installed by default; --no-digstore opts out, --with-digstore
    // is the explicit (redundant) opt-in. --no-digstore wins if both are given.
    let with_digstore = cli.with_digstore || !cli.no_digstore;

    let plan = InstallPlan {
        bin_dir: cli.bin_dir.unwrap_or_else(paths::default_bin_dir),
        with_digstore,
        digstore_version: cli.digstore_version,
        with_dig_node: cli.with_dig_node,
        dig_node_version: cli.dig_node_version,
        service: ServiceConfig {
            port: cli.dig_node_port,
            start: !cli.no_service_start,
        },
        with_browser: cli.with_browser,
        browser_version: cli.browser_version,
        with_relay: cli.with_relay,
        relay_version: cli.relay_version,
        relay_service: dig_installer::ServiceConfigRelay {
            port: cli.relay_port,
            health_port: cli.relay_health_port,
            start: !cli.no_service_start,
        },
        modify_path: !cli.no_path,
        dry_run: cli.dry_run,
    };

    if cli.json {
        run_json(&plan)
    } else {
        run_pretty(&plan)
    }
}

/// Pretty mode: human progress to stdout, typed error to stderr with its code.
fn run_pretty(plan: &InstallPlan) -> std::process::ExitCode {
    match dig_installer::run_report(plan, &mut |line| println!("{line}")) {
        Ok(_) => std::process::ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("error [{}]: {}", e.code(), e);
            if let Some(hint) = e.hint() {
                eprintln!("hint: {hint}");
            }
            std::process::ExitCode::from(e.exit_code())
        }
    }
}

/// JSON mode: progress prose to stderr; a single structured object to stdout.
/// Success → the InstallReport with `ok:true`; failure → `{ok:false,error:{…}}`.
fn run_json(plan: &InstallPlan) -> std::process::ExitCode {
    let result = dig_installer::run_report(plan, &mut |line| eprintln!("{line}"));
    match result {
        Ok(report) => {
            let envelope = serde_json::json!({ "ok": true, "result": report });
            println!("{}", serde_json::to_string(&envelope).unwrap());
            std::process::ExitCode::SUCCESS
        }
        Err(e) => {
            println!("{}", error_json(&e));
            std::process::ExitCode::from(e.exit_code())
        }
    }
}
