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
the OS split-DNS/NRPT + browser DoH wiring), and\n  \
* the DIG auto-update beacon (dig-updater, registered as a daily scheduled check that installs \
new signed DIG releases automatically).\n\n\
Opt OUT of any of the four with --no-digstore / --no-dig-node / --no-dig-dns / --no-auto-update. \
The dig-relay (advanced, run-your-own-relay) and the DIG Browser stay OPT-IN (--with-relay / \
--with-browser). Use --json for machine-readable output and --help-json for the full invocation \
contract (incl. the exit-code table)."
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
    #[arg(long, value_name = "PORT", default_value_t = dig_constants::DIG_NODE_PORT)]
    dig_node_port: u16,

    /// With --with-dig-node, install the service but do NOT start it.
    /// (By default the service is started immediately.)
    #[arg(long = "no-service-start")]
    no_service_start: bool,

    /// Uninstall the dig-node OS service, the `dig.local` hosts entry, and the
    /// firewall rule this installer created (idempotent; does not touch the
    /// digstore/browser/relay/dig-dns installs). Runs standalone — ignores
    /// every other install flag except --bin-dir/--dry-run/--json.
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

    /// Opt OUT of registering the `chia://` (+ `urn:`) OS URL-scheme handler
    /// (registered by default): clicking a chia:// link anywhere opens the
    /// resolved DIG content in the browser via the local dig-node (#389).
    #[arg(long = "no-register-scheme")]
    no_register_scheme: bool,

    /// Explicitly register the chia:// URL-scheme handler (redundant — it is
    /// registered by default; here for symmetry with `--no-register-scheme`).
    #[arg(long = "register-scheme")]
    register_scheme: bool,

    /// Unregister the chia:// / urn: URL-scheme handler this installer created
    /// (idempotent). Runs standalone — ignores every other install flag.
    #[arg(long = "unregister-scheme")]
    unregister_scheme: bool,

    /// Opt OUT of opening the app-scoped inbound firewall rule for dig-node's
    /// peer-RPC port (opened by default when dig-node is installed): a
    /// direct-reachable node without it just falls back to the dig-relay
    /// path, so declining is always safe (#424).
    #[arg(long = "no-open-firewall")]
    no_open_firewall: bool,

    /// Explicitly open the firewall rule (redundant — it is opened by
    /// default; here for symmetry with `--no-open-firewall`).
    #[arg(long = "open-firewall")]
    open_firewall: bool,

    /// Opt OUT of installing + registering the DIG auto-update beacon
    /// (installed by default): `dig-updater` + its `dig-updater-worker`
    /// sibling check daily for new signed DIG releases and install them
    /// automatically (#514). Declining is always safe — nothing auto-updates;
    /// re-run the installer manually to get new versions.
    #[arg(long = "no-auto-update")]
    no_auto_update: bool,

    /// Explicitly install the auto-update beacon (redundant — it is on by
    /// default; here for symmetry with `--no-auto-update`).
    #[arg(long = "auto-update")]
    auto_update: bool,

    /// dig-updater version to install (e.g. 0.6.0); default: latest released.
    /// Also pins the `dig-updater-worker` sibling, published in the same release.
    #[arg(long, value_name = "VERSION")]
    dig_updater_version: Option<String>,

    /// Remove the auto-update beacon's daily scheduler registration this
    /// installer created (idempotent; does not remove the downloaded binaries
    /// or touch the digstore/browser/relay/dig-node/dig-dns installs). Runs
    /// standalone — ignores every other install flag.
    #[arg(long = "uninstall-dig-updater")]
    uninstall_dig_updater: bool,

    /// Force a fresh reinstall of digstore/dig-node/dig-dns/dig-updater even
    /// when the version-aware updater (#309) would otherwise skip a component
    /// that's already up to date.
    #[arg(long = "force-reinstall")]
    force_reinstall: bool,

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

    /// List the Chromium-family browsers installed on this machine (read-only)
    /// and their per-OS managed-extension-policy locations, then exit. Feeds
    /// the DIG-extension force-install step (#602). Use `--json` for a machine
    /// result. Runs standalone — ignores every other install flag.
    #[arg(long = "detect-browsers")]
    detect_browsers: bool,

    /// Force-install the DIG extension into every DETECTED Chromium browser by
    /// writing its `ExtensionInstallForcelist` managed policy for the given
    /// channel (`stable` — the default — or `nightly`), then exit (#612). A
    /// channel change writes the per-browser remove->re-add primitive in one
    /// pass (a nightly build outranks stable, so a naive value rewrite would not
    /// downgrade). Note: actually crossing a downgrade needs the uninstall staged
    /// across a policy-refresh cycle before the re-add — that staging is #613's
    /// job. Merges beside any org forcelist; requires elevation. Use `--json` for
    /// a machine result. Runs standalone — ignores every other install flag.
    #[arg(long = "set-ext-forcelist-channel", value_name = "CHANNEL")]
    set_ext_forcelist_channel: Option<String>,

    /// Remove ONLY the DIG extension's `ExtensionInstallForcelist` entry from
    /// every detected Chromium browser (idempotent, zero residue; never touches
    /// a pre-existing org forcelist), then exit (#612). Requires elevation.
    /// Runs standalone.
    #[arg(long = "uninstall-ext-forcelist")]
    uninstall_ext_forcelist: bool,
}

fn main() -> std::process::ExitCode {
    // The Windows dig-dns service now runs `dig-dns.exe run-service` DIRECTLY
    // (dig-dns's own SCM entrypoint) — the installer no longer hosts the service
    // via a hidden re-launch subcommand (#499: that indirection missed the SCM
    // start-timeout, causing `1053`). So there is nothing to intercept before
    // clap on that account.

    // The OS URL-scheme handlers (#567) now delegate directly to `dign open`
    // (dig-node = the single URI-resolve-and-open authority) — the installer no
    // longer hosts a `handle-url` subcommand or its own resolve ladder, so there
    // is nothing to intercept before clap.

    let cli = Cli::parse();

    if cli.help_json {
        print!("{}", help_json());
        return std::process::ExitCode::SUCCESS;
    }
    // (`help_json`/`error_json` live in the library so they are unit-tested
    // directly; main.rs only wires them to stdout/exit codes.)

    if cli.detect_browsers {
        return run_detect_browsers(cli.json);
    }

    if let Some(channel) = cli.set_ext_forcelist_channel.as_deref() {
        return run_set_ext_forcelist_channel(channel, cli.json);
    }

    if cli.uninstall_ext_forcelist {
        return run_uninstall_ext_forcelist(cli.json);
    }

    if cli.uninstall_dig_dns {
        return run_uninstall_dig_dns(cli.dry_run, cli.json);
    }

    if cli.uninstall_dig_node {
        let bin_dir = cli.bin_dir.clone().unwrap_or_else(paths::default_bin_dir);
        return run_uninstall_dig_node(&bin_dir, cli.dry_run, cli.json);
    }

    if cli.uninstall_dig_updater {
        let bin_dir = cli.bin_dir.clone().unwrap_or_else(paths::default_bin_dir);
        return run_uninstall_beacon(&bin_dir, cli.dry_run, cli.json);
    }

    if cli.unregister_scheme {
        let result = dig_installer::scheme::unregister(cli.dry_run);
        if cli.json {
            let envelope = serde_json::json!({ "ok": true, "result": result });
            println!("{}", serde_json::to_string(&envelope).unwrap());
        } else {
            println!("scheme handler: {}", result.note);
        }
        return std::process::ExitCode::SUCCESS;
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
        // #389: register chia:// by default; `--no-register-scheme` opts out
        // (`--register-scheme` is the redundant explicit opt-in).
        register_scheme: cli.register_scheme || !cli.no_register_scheme,
        // #424: open the dig-node peer-RPC firewall rule by default;
        // `--no-open-firewall` opts out (`--open-firewall` is the redundant
        // explicit opt-in) — same "`--no-*` wins" pattern as register_scheme.
        open_firewall: cli.open_firewall || !cli.no_open_firewall,
        // #514: install + register the auto-update beacon by default;
        // `--no-auto-update` opts out (`--auto-update` is the redundant
        // explicit opt-in) — same "`--no-*` wins" pattern as the two above.
        auto_update: cli.auto_update || !cli.no_auto_update,
        dig_updater_version: cli.dig_updater_version,
        force_reinstall: cli.force_reinstall,
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

/// `--detect-browsers`: enumerate the installed Chromium-family browsers +
/// their managed-extension-policy locations (read-only, #609). `--json` emits
/// the typed list a caller scripts against; pretty mode lists them for a human.
fn run_detect_browsers(json: bool) -> std::process::ExitCode {
    let browsers = dig_installer::browsers::detect_installed();
    if json {
        let envelope = serde_json::json!({ "ok": true, "browsers": browsers });
        println!("{}", serde_json::to_string(&envelope).unwrap());
    } else if browsers.is_empty() {
        println!("no Chromium-family browsers detected");
    } else {
        println!("detected {} Chromium-family browser(s):", browsers.len());
        for b in &browsers {
            println!("  - {} ({})", b.display_name, b.id);
        }
    }
    std::process::ExitCode::SUCCESS
}

/// Detected-browser slug ids for the standalone forcelist verbs — the CLI has
/// no GUI selection, so it targets every Chromium browser found on the host.
fn detected_browser_ids() -> Vec<String> {
    dig_installer::browsers::detect_installed()
        .into_iter()
        .map(|b| b.id)
        .collect()
}

/// Emit the shared JSON/pretty result of a forcelist verb + map its exit code
/// (non-success iff any per-browser write failed).
fn report_forcelist(
    verb: &str,
    outcomes: &[dig_installer::forcelist::ForcelistOutcome],
    json: bool,
) -> std::process::ExitCode {
    let any_failed = outcomes
        .iter()
        .any(|o| o.action == dig_installer::forcelist::ForcelistAction::Failed);
    if json {
        println!("{}", dig_installer::forcelist_json(outcomes));
    } else if outcomes.is_empty() {
        println!("{verb}: no Chromium-family browsers detected");
    } else {
        println!("{verb}:");
        for o in outcomes {
            println!("  - {:?} · {} · {}", o.action, o.location, o.note);
        }
        if any_failed {
            eprintln!("hint: re-run in an elevated (Administrator/root) console");
        }
    }
    if any_failed {
        std::process::ExitCode::FAILURE
    } else {
        std::process::ExitCode::SUCCESS
    }
}

/// `--set-ext-forcelist-channel <nightly|stable>`: force-install the DIG
/// extension into every detected Chromium browser on the given channel (#612).
/// A channel change is a clean per-browser reinstall (#613 downgrade rule).
fn run_set_ext_forcelist_channel(channel: &str, json: bool) -> std::process::ExitCode {
    let Some(channel) = dig_installer::forcelist::Channel::parse(channel) else {
        eprintln!("invalid channel {channel:?} — expected 'stable' or 'nightly'");
        return std::process::ExitCode::FAILURE;
    };
    let outcomes =
        dig_installer::switch_extension_forcelist_channel(&detected_browser_ids(), channel);
    report_forcelist("set ext forcelist channel", &outcomes, json)
}

/// `--uninstall-ext-forcelist`: remove ONLY the DIG forcelist entry from every
/// detected Chromium browser (#612), leaving any org forcelist untouched.
fn run_uninstall_ext_forcelist(json: bool) -> std::process::ExitCode {
    let outcomes = dig_installer::unconfigure_extension_forcelist(&detected_browser_ids());
    report_forcelist("uninstall ext forcelist", &outcomes, json)
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

/// `--uninstall-dig-node`: tear down the dig-node OS service, the `dig.local`
/// hosts entry, and the firewall rule (#424) this installer created (task
/// #140). Standalone action —
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

/// `--uninstall-dig-updater`: remove the DIG auto-update beacon's daily
/// scheduler registration (task #514). Standalone action —
/// [`dig_installer::uninstall_beacon`] never fails outright (a missing binary
/// or elevation issue is reported via `note`, not an `Err`), so this always
/// exits success; the caller re-runs elevated if prompted.
fn run_uninstall_beacon(
    bin_dir: &std::path::Path,
    dry_run: bool,
    json: bool,
) -> std::process::ExitCode {
    let result = if json {
        dig_installer::uninstall_beacon(bin_dir, dry_run, &mut |line| eprintln!("{line}"))
    } else {
        dig_installer::uninstall_beacon(bin_dir, dry_run, &mut |line| println!("{line}"))
    };
    if json {
        println!("{}", dig_installer::beacon_uninstall_json(&result));
    } else {
        println!("dig-updater uninstall: {}", result.note);
    }
    std::process::ExitCode::SUCCESS
}
