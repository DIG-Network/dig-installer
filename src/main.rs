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

    /// Also install dig-dns and register it as an OS service (Windows Service / macOS
    /// LaunchDaemon / Linux systemd): local `*.dig` name resolution (a DNS responder + HTTP
    /// gateway), split-DNS/NRPT wiring, and the Chrome/Edge DoH policy.
    #[arg(long)]
    with_dig_dns: bool,

    /// dig-dns version to install (e.g. 0.6.0); default: latest released.
    #[arg(long, value_name = "VERSION")]
    dig_dns_version: Option<String>,

    /// An explicit dig-node endpoint dig-dns's gateway should use (forwarded as `dig-dns serve
    /// --node <URL>`); default: dig-dns's own §5.3 ladder (dig.local -> localhost:9778 ->
    /// rpc.dig.net).
    #[arg(long, value_name = "URL")]
    dig_dns_node: Option<String>,

    /// Uninstall the dig-dns OS service + OS wiring this installer created (idempotent, leaves
    /// zero residue; never removes the downloaded binary or a pre-existing org DNS/browser
    /// policy). Runs standalone — ignores every other install flag.
    #[arg(long = "uninstall-dig-dns")]
    uninstall_dig_dns: bool,

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
    // The Windows Service Control Manager launches THIS binary with the hidden
    // `run-dig-dns-service` subcommand (task #177 — dig-dns has no service-protocol
    // entrypoint of its own; see `dig_installer::dns::service_host`). It carries no public
    // `--help` surface, so it must be sniffed BEFORE handing argv to clap (clap would reject
    // it as an unrecognised argument — the `Cli` struct below defines no subcommands).
    #[cfg(windows)]
    {
        let argv: Vec<String> = std::env::args().collect();
        if let Some(rest) = dig_installer::dns::service_host::matches_service_host_invocation(&argv)
        {
            return match dig_installer::dns::service_host::run(&rest) {
                Ok(()) => std::process::ExitCode::SUCCESS,
                Err(e) => {
                    eprintln!("dig-dns service host error: {e}");
                    std::process::ExitCode::FAILURE
                }
            };
        }
    }

    let cli = Cli::parse();

    if cli.help_json {
        print!("{}", help_json());
        return std::process::ExitCode::SUCCESS;
    }
    // (`help_json`/`error_json` live in the library so they are unit-tested
    // directly; main.rs only wires them to stdout/exit codes.)

    if cli.uninstall_dig_dns {
        return run_uninstall_dig_dns(cli.dry_run, cli.json);
    }

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
        with_dig_dns: cli.with_dig_dns,
        dig_dns_version: cli.dig_dns_version,
        dns_service: dig_installer::dns::DnsInstallConfig {
            start: !cli.no_service_start,
            node: cli.dig_dns_node,
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

/// `--uninstall-dig-dns`: tear down the dig-dns OS service + OS wiring this
/// installer created (idempotent; leaves zero residue). Standalone action —
/// [`dig_installer::dns::uninstall`] never fails (a permission issue is
/// reported via `needs_elevation`, not an `Err`), so this always exits
/// success; the caller re-runs elevated if prompted.
fn run_uninstall_dig_dns(dry_run: bool, json: bool) -> std::process::ExitCode {
    let result = dig_installer::dns::uninstall(dry_run);
    if json {
        println!("{}", dig_installer::dns_uninstall_json(&result));
    } else {
        println!("dig-dns uninstall: {}", result.note);
        if result.needs_elevation {
            eprintln!("hint: re-run in an elevated (Administrator/root) console");
        }
        for artifact in &result.residue_removed {
            println!("  removed: {artifact}");
        }
    }
    std::process::ExitCode::SUCCESS
}
