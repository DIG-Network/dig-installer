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
    about = "Universal DIG installer — installs the digstore CLI, the dig-node service, and the dig-dns service by default",
    long_about = "Resolves and downloads the latest per-OS/arch release asset for the selected \
components from the DIG-Network GitHub releases (it bundles nothing).\n\n\
By DEFAULT it installs the full DIG stack in one run:\n  \
* the digstore CLI (added to PATH, along with its `digs` alias binary),\n  \
* the dig-node local node (installed + started as a boot-start OS service, with a best-effort \
127.0.0.2 dig.local hosts entry), and\n  \
* the dig-dns local *.dig name resolver (installed + started as a boot-start OS service, with \
the OS split-DNS/NRPT + browser DoH wiring).\n\n\
Opt OUT of any of the three with --no-digstore / --no-dig-node / --no-dig-dns. The dig-relay \
(advanced, run-your-own-relay) and the DIG Browser stay OPT-IN (--with-relay / --with-browser). \
Use --json for machine-readable output and --help-json for the full invocation contract (incl. \
the exit-code table)."
)]
struct Cli {
    /// Directory to install the binaries into (default: per-user DIG bin dir).
    #[arg(long, value_name = "DIR")]
    bin_dir: Option<std::path::PathBuf>,

    /// Explicitly select the digstore CLI (it is installed by default anyway;
    /// this flag exists for symmetry/clarity with the --with-* opt-ins). Also
    /// controls the `digs` alias binary (issue #434), which has no flag of its
    /// own and always installs alongside digstore.
    #[arg(long)]
    with_digstore: bool,

    /// Opt OUT of the digstore CLI (installed by default). Also skips its
    /// `digs` alias binary.
    #[arg(long = "no-digstore")]
    no_digstore: bool,

    /// digstore version to install (e.g. 0.6.0); default: latest released.
    /// Also pins the `digs` alias, published in the same release.
    #[arg(long, value_name = "VERSION")]
    digstore_version: Option<String>,

    /// Explicitly select the dig-node local node + boot-start OS service (it is
    /// installed by default anyway; this flag / its `--service` alias exist for
    /// symmetry/clarity and backwards compatibility).
    #[arg(long, alias = "service")]
    with_dig_node: bool,

    /// Opt OUT of the dig-node local node + service (installed by default).
    #[arg(long = "no-dig-node")]
    no_dig_node: bool,

    /// dig-node version to install (e.g. 0.2.0); default: latest released.
    #[arg(long, value_name = "VERSION")]
    dig_node_version: Option<String>,

    /// Loopback port the dig-node service serves on (with --with-dig-node).
    #[arg(long, value_name = "PORT", default_value_t = 9778)]
    dig_node_port: u16,

    /// With --with-dig-node, install the service but do NOT start it.
    /// (By default the service is started immediately.)
    #[arg(long = "no-service-start")]
    no_service_start: bool,

    /// Uninstall the dig-node OS service + remove the `dig.local` hosts entry
    /// this installer created (idempotent; does not touch the digstore/
    /// browser/relay/dig-dns installs). Runs standalone — ignores every other
    /// install flag except --bin-dir/--dry-run/--json.
    #[arg(long = "uninstall-dig-node")]
    uninstall_dig_node: bool,

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

    /// Explicitly select dig-dns + its boot-start OS service (Windows Service /
    /// macOS LaunchDaemon / Linux systemd): local `*.dig` name resolution (a DNS
    /// responder + HTTP gateway), split-DNS/NRPT wiring, and the Chrome/Edge DoH
    /// policy. Installed by default; this flag is the redundant explicit opt-in.
    #[arg(long)]
    with_dig_dns: bool,

    /// Opt OUT of dig-dns + its service (installed by default).
    #[arg(long = "no-dig-dns")]
    no_dig_dns: bool,

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
    // The Windows dig-dns service now runs `dig-dns.exe run-service` DIRECTLY
    // (dig-dns's own SCM entrypoint) — the installer no longer hosts the service
    // via a hidden re-launch subcommand (#499: that indirection missed the SCM
    // start-timeout, causing `1053`). So there is nothing to intercept before
    // clap here.
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

    if cli.uninstall_dig_node {
        let bin_dir = cli.bin_dir.clone().unwrap_or_else(paths::default_bin_dir);
        return run_uninstall_dig_node(&bin_dir, cli.dry_run, cli.json);
    }

    // #301 — universal installer: digstore + dig-node + dig-dns ALL install by
    // default (the full DIG stack in one run). Each has a `--no-<component>`
    // opt-out; the `--with-<component>` flags remain accepted as redundant,
    // explicit opt-ins (backwards compat + symmetry). `--no-*` wins if both are
    // given. dig-relay and DIG Browser stay opt-in (`--with-relay`/`--with-browser`).
    let with_digstore = cli.with_digstore || !cli.no_digstore;
    let with_dig_node = cli.with_dig_node || !cli.no_dig_node;
    let with_dig_dns = cli.with_dig_dns || !cli.no_dig_dns;

    let plan = InstallPlan {
        bin_dir: cli.bin_dir.unwrap_or_else(paths::default_bin_dir),
        with_digstore,
        digstore_version: cli.digstore_version,
        with_dig_node,
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
        with_dig_dns,
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
///
/// Fail-loud (#493): a completed run that is NOT ready (a selected component
/// failed to install or its service isn't running) exits NON-ZERO with an
/// explicit "DIG is NOT ready" summary — never a silent success. The per-line
/// verdict was already streamed by `run_report`; here we surface the aggregate
/// + set the exit code.
fn run_pretty(plan: &InstallPlan) -> std::process::ExitCode {
    match dig_installer::run_report(plan, &mut |line| println!("{line}")) {
        Ok(report) if report.ready => std::process::ExitCode::SUCCESS,
        Ok(report) => {
            eprintln!(
                "DIG is NOT ready — {} component(s) failed:",
                report.failures.len()
            );
            for f in &report.failures {
                eprintln!("  - {f}");
            }
            eprintln!("re-run elevated (Administrator/root) if elevation is the cause, then run the installer again");
            std::process::ExitCode::from(
                dig_installer::error::ErrorKind::InstallIncomplete.exit_code(),
            )
        }
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
/// Success → the InstallReport with `ok:true`; a NOT-ready completion →
/// `ok:false` with the full report (so an agent sees exactly what failed) +
/// exit `INSTALL_INCOMPLETE`; a hard failure → `{ok:false,error:{…}}`.
fn run_json(plan: &InstallPlan) -> std::process::ExitCode {
    let result = dig_installer::run_report(plan, &mut |line| eprintln!("{line}"));
    match result {
        Ok(report) => {
            let ready = report.ready;
            let envelope = serde_json::json!({ "ok": ready, "result": report });
            println!("{}", serde_json::to_string(&envelope).unwrap());
            if ready {
                std::process::ExitCode::SUCCESS
            } else {
                std::process::ExitCode::from(
                    dig_installer::error::ErrorKind::InstallIncomplete.exit_code(),
                )
            }
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

/// `--uninstall-dig-node`: tear down the dig-node OS service + the `dig.local`
/// hosts entry this installer created (task #140). Standalone action —
/// [`dig_installer::uninstall_dig_node`] never fails outright (a missing
/// binary or elevation issue is reported via `note`, not an `Err`), so this
/// always exits success; the caller re-runs elevated if prompted.
fn run_uninstall_dig_node(
    bin_dir: &std::path::Path,
    dry_run: bool,
    json: bool,
) -> std::process::ExitCode {
    let result = if json {
        dig_installer::uninstall_dig_node(bin_dir, dry_run, &mut |line| eprintln!("{line}"))
    } else {
        dig_installer::uninstall_dig_node(bin_dir, dry_run, &mut |line| println!("{line}"))
    };
    if json {
        println!("{}", dig_installer::service_uninstall_json(&result));
    } else {
        println!("dig-node uninstall: {}", result.note);
    }
    std::process::ExitCode::SUCCESS
}
