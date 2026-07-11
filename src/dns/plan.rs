//! Pure content/plan generation for the dig-dns OS-service install (task #177).
//!
//! Every artifact the installer writes (a systemd unit, a launchd plist, a
//! PowerShell NRPT command, a Chrome/Chromium policy JSON body, a doctor/pac
//! JSON parse) is built here as a **pure function of its inputs** — no I/O, no
//! process spawn — so the exact bytes/text written to disk (or piped to a
//! shell) are unit-tested without touching a real system. The imperative apply
//! layer (`super::windows`/`super::macos`/`super::linux`) calls these builders
//! and performs the actual file/registry/process I/O.
//!
//! dig-dns (`DIG-Network/dig-dns`, README §"What the installer sets up per
//! OS") ships NO `install`/`start` subcommands of its own — unlike
//! dig-node/dig-relay, which register THEMSELVES via `service-manager`
//! internally and expose `install`/`start`. dig-installer therefore owns the
//! full per-OS service-registration contract for dig-dns directly.

use serde::Serialize;

/// The reverse-DNS service label (matches dig-node's convention): the SCM
/// service name (Windows), the launchd label (macOS), and the systemd unit
/// script name (Linux, via [`SERVICE_SCRIPT_NAME`]).
pub const SERVICE_LABEL: &str = "net.dignetwork.dig-dns";

/// The systemd unit / script name derived from [`SERVICE_LABEL`] (dashed, no
/// dots) — `dig-dns.service`.
pub const SERVICE_SCRIPT_NAME: &str = "dig-dns";

/// Tag embedded (as a comment/marker value) in every artifact this installer
/// creates, so idempotent re-runs and a clean uninstall can recognise —
/// and only touch — what THIS installer added (mirrors `hosts::MARKER`).
pub const MARKER: &str = "managed by dig-installer (dig-dns, task #177)";

/// The dedicated loopback IP dig-dns binds by default (its own `DIG_DNS_IP`
/// default) — the installer wires OS resolution/routing at this address.
pub const LOOPBACK_IP: &str = "127.0.0.5";

/// dig-dns's default DNS/HTTP ports (its own config defaults) — used only for
/// documentation/messages here; the installer never overrides dig-dns's own
/// config, it just wires the OS around the defaults.
pub const DNS_PORT: u16 = 53;
pub const HTTP_PORT: u16 = 80;
pub const HTTP_FALLBACK_PORT: u16 = 8053;

/// The dedicated, unprivileged Linux service account dig-dns's systemd unit
/// runs as (granted only `CAP_NET_BIND_SERVICE`, never root).
pub const LINUX_SERVICE_USER: &str = "dig-dns";

/// The hidden dig-installer subcommand the Windows service is registered to
/// run (it is not part of the public `--help` surface — see
/// [`super::windows`]). It speaks the Windows Service Control Protocol and
/// spawns the real `dig-dns serve` as a child process.
pub const SERVICE_HOST_SUBCOMMAND: &str = "run-dig-dns-service";

/// dig-dns is registered as a **boot-start** OS service (#301): it starts
/// automatically on every boot, on all three platforms. This single flag is
/// threaded into the `service-manager` `ServiceInstallCtx.autostart` on each OS
/// ([`super::windows`]/[`super::linux`]/[`super::macos`]), which maps to the
/// per-OS boot-start mechanism — Windows SCM `start= auto`, systemd `enable`
/// (paired with the `WantedBy=multi-user.target` in [`systemd_unit`]), and
/// launchd (paired with the `RunAtLoad` in [`launchd_service_plist`]). Keeping
/// it here as one named constant means a regression to manual-start is a
/// one-line change caught by [`tests::dns_service_is_registered_as_boot_start`].
pub const DNS_SERVICE_AUTOSTART: bool = true;

// ---------------------------------------------------------------------------
// Linux — systemd unit (custom `contents`; the crate's own generator has no
// capability/user support, so we hand-roll the full unit text).
// ---------------------------------------------------------------------------

/// The `dig-dns.service` systemd unit body: runs as [`LINUX_SERVICE_USER`]
/// with ONLY `CAP_NET_BIND_SERVICE` (never root), auto-restarts, and starts on
/// boot. `dig_dns_path` is the absolute path to the installed `dig-dns`
/// binary; `node` is an optional `--node <url>` override forwarded on the
/// command line (baked in here, since `service-manager` ignores
/// `ServiceInstallCtx.environment` whenever a custom `contents` is supplied).
pub fn systemd_unit(dig_dns_path: &str, node: Option<&str>) -> String {
    let exec_start = match node {
        Some(n) => format!("ExecStart={dig_dns_path} serve --node {n}"),
        None => format!("ExecStart={dig_dns_path} serve"),
    };
    format!(
        "# {MARKER}\n\
         [Unit]\n\
         Description=dig-dns (local *.dig name resolution)\n\
         After=network.target\n\
         \n\
         [Service]\n\
         Type=simple\n\
         {exec_start}\n\
         User={LINUX_SERVICE_USER}\n\
         AmbientCapabilities=CAP_NET_BIND_SERVICE\n\
         CapabilityBoundingSet=CAP_NET_BIND_SERVICE\n\
         NoNewPrivileges=yes\n\
         Restart=always\n\
         RestartSec=2\n\
         \n\
         [Install]\n\
         WantedBy=multi-user.target\n"
    )
}

/// The `systemd-resolved` per-domain drop-in (`/etc/systemd/resolved.conf.d/dig.conf`) that
/// routes `~dig` lookups at the dig-dns responder.
pub fn systemd_resolved_dropin(ip: &str) -> String {
    format!("# {MARKER}\n[Resolve]\nDNS={ip}\nDomains=~dig\n")
}

/// The NetworkManager-dnsmasq split-DNS config (`/etc/NetworkManager/dnsmasq.d/dig.conf`).
pub fn networkmanager_dnsmasq_conf(ip: &str) -> String {
    format!("# {MARKER}\nserver=/dig/{ip}\n")
}

/// The Chrome/Chromium managed-policy JSON body (Linux): disable DNS-over-HTTPS and the
/// built-in resolver so the OS/PAC-configured resolution path is honoured.
pub fn chrome_policy_json() -> String {
    serde_json::json!({
        "DnsOverHttpsMode": "off",
        "BuiltInDnsClientEnabled": false
    })
    .to_string()
}

// ---------------------------------------------------------------------------
// macOS — launchd plists (custom `contents`; the crate's generator has no
// StandardOutPath/StandardErrorPath support, and LaunchDaemons need root).
// ---------------------------------------------------------------------------

fn plist_header() -> &'static str {
    "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n\
     <!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n\
     <plist version=\"1.0\">\n"
}

/// The dig-dns service LaunchDaemon plist: runs `dig-dns serve` as **root**
/// (no `UserName` key — a system LaunchDaemon defaults to root), restarts on
/// crash (`KeepAlive`), and logs to `/var/log/dig-dns.{out,err}.log`. `node`
/// is an optional `--node <url>` override appended to `ProgramArguments`
/// (baked in here, since `service-manager` ignores
/// `ServiceInstallCtx.environment` whenever a custom `contents` is supplied).
pub fn launchd_service_plist(dig_dns_path: &str, node: Option<&str>) -> String {
    let node_args = match node {
        Some(n) => format!("\t\t<string>--node</string>\n\t\t<string>{n}</string>\n"),
        None => String::new(),
    };
    format!(
        "{header}<!-- {MARKER} -->\n\
         <dict>\n\
         \t<key>Label</key>\n\
         \t<string>{SERVICE_LABEL}</string>\n\
         \t<key>ProgramArguments</key>\n\
         \t<array>\n\
         \t\t<string>{dig_dns_path}</string>\n\
         \t\t<string>serve</string>\n\
         {node_args}\t</array>\n\
         \t<key>RunAtLoad</key>\n\
         \t<true/>\n\
         \t<key>KeepAlive</key>\n\
         \t<true/>\n\
         \t<key>StandardOutPath</key>\n\
         \t<string>/var/log/dig-dns.out.log</string>\n\
         \t<key>StandardErrorPath</key>\n\
         \t<string>/var/log/dig-dns.err.log</string>\n\
         </dict>\n\
         </plist>\n",
        header = plist_header()
    )
}

/// The service label for the boot-persistent `127.0.0.5` lo0-alias LaunchDaemon.
pub const LO0_ALIAS_LABEL: &str = "net.dignetwork.dig-dns-lo0";

/// A one-shot LaunchDaemon that re-applies the `lo0` loopback alias at every
/// boot (`ifconfig lo0 alias <ip> up`) — macOS does not persist `ifconfig`
/// aliases across reboots on its own. `RunAtLoad` only (not `KeepAlive`: the
/// command exits immediately after applying the alias).
pub fn launchd_lo0_alias_plist(ip: &str) -> String {
    format!(
        "{header}<!-- {MARKER} -->\n\
         <dict>\n\
         \t<key>Label</key>\n\
         \t<string>{LO0_ALIAS_LABEL}</string>\n\
         \t<key>ProgramArguments</key>\n\
         \t<array>\n\
         \t\t<string>/sbin/ifconfig</string>\n\
         \t\t<string>lo0</string>\n\
         \t\t<string>alias</string>\n\
         \t\t<string>{ip}</string>\n\
         \t\t<string>up</string>\n\
         \t</array>\n\
         \t<key>RunAtLoad</key>\n\
         \t<true/>\n\
         \t<key>KeepAlive</key>\n\
         \t<false/>\n\
         </dict>\n\
         </plist>\n",
        header = plist_header()
    )
}

/// The `/etc/resolver/dig` content routing `.dig` lookups at the dig-dns responder
/// (macOS's per-TLD resolver mechanism).
pub fn resolver_dig_content(ip: &str) -> String {
    format!("nameserver {ip}\n")
}

/// A best-effort Chrome managed-preference plist body (macOS): disable DNS-over-HTTPS and the
/// built-in resolver. Written only when no existing org-managed policy is detected (see
/// `super::macos`) — Chrome's managed-preference plists are normally provisioned by MDM, so this
/// is a best-effort fallback; the installer always also prints manual instructions.
pub fn chrome_managed_plist() -> String {
    format!(
        "{header}<!-- {MARKER} -->\n\
         <dict>\n\
         \t<key>DnsOverHttpsMode</key>\n\
         \t<string>off</string>\n\
         \t<key>BuiltInDnsClientEnabled</key>\n\
         \t<false/>\n\
         </dict>\n\
         </plist>\n",
        header = plist_header()
    )
}

// ---------------------------------------------------------------------------
// Windows — NRPT (PowerShell) + Chrome/Edge HKLM registry policy.
// ---------------------------------------------------------------------------

/// The DNS namespace the NRPT rule routes to the dig-dns responder.
pub const NRPT_NAMESPACE: &str = ".dig";

/// A PowerShell one-liner that adds the `.dig` NRPT rule **idempotently** (a
/// no-op if a `.dig` namespace rule already exists — never fights a
/// pre-existing rule for the same namespace) and tags it with [`MARKER`] via
/// `-Comment` so [`nrpt_remove_ps_command`] can find + remove only ours.
pub fn nrpt_add_ps_command(ip: &str) -> String {
    format!(
        "if (-not (Get-DnsClientNrptRule | Where-Object {{ $_.Namespace -eq '{NRPT_NAMESPACE}' }})) {{ \
         Add-DnsClientNrptRule -Namespace '{NRPT_NAMESPACE}' -NameServers '{ip}' -Comment '{MARKER}' | Out-Null }}"
    )
}

/// A PowerShell one-liner that removes ONLY the NRPT rule(s) tagged with
/// [`MARKER`] — never a `.dig` rule the user or another tool added.
pub fn nrpt_remove_ps_command() -> String {
    format!(
        "Get-DnsClientNrptRule | Where-Object {{ $_.Comment -eq '{MARKER}' }} | \
         ForEach-Object {{ Remove-DnsClientNrptRule -DisplayName $_.DisplayName -Force }}"
    )
}

/// HKLM registry path (relative to `HKEY_LOCAL_MACHINE`) for the Chrome policy.
pub const CHROME_POLICY_KEY: &str = r"SOFTWARE\Policies\Google\Chrome";
/// HKLM registry path (relative to `HKEY_LOCAL_MACHINE`) for the Edge policy.
pub const EDGE_POLICY_KEY: &str = r"SOFTWARE\Policies\Microsoft\Edge";
/// `DnsOverHttpsMode` policy value name (REG_SZ).
pub const POLICY_DOH_NAME: &str = "DnsOverHttpsMode";
/// The value that disables DoH.
pub const POLICY_DOH_OFF: &str = "off";
/// `BuiltInDnsClientEnabled` policy value name (REG_DWORD).
pub const POLICY_BUILTIN_RESOLVER_NAME: &str = "BuiltInDnsClientEnabled";
/// A marker value written alongside the policy values so uninstall can tell
/// "the installer created this key" apart from "an org GPO already manages
/// it" (in which case the installer must never have written here at all —
/// this marker is a belt-and-braces uninstall safety check).
pub const POLICY_MARKER_NAME: &str = "DigInstallerManaged";

/// Build the launch arguments dig-installer registers as the Windows service's
/// `binPath` arguments (after its own program path): the hidden
/// [`SERVICE_HOST_SUBCOMMAND`], the target `dig-dns` binary to spawn, and an
/// optional `--node` override forwarded to `dig-dns serve`.
pub fn service_host_launch_args(dig_dns_path: &str, node: Option<&str>) -> Vec<String> {
    let mut args = vec![
        SERVICE_HOST_SUBCOMMAND.to_string(),
        "--exec".to_string(),
        dig_dns_path.to_string(),
    ];
    if let Some(n) = node {
        if !n.trim().is_empty() {
            args.push("--node".to_string());
            args.push(n.trim().to_string());
        }
    }
    args
}

// ---------------------------------------------------------------------------
// dig-dns `doctor --json` / `pac --json` parsing (agent-friendly: parse the
// STABLE JSON fields, never scrape the human `detail` prose — CLAUDE.md §6.2).
// ---------------------------------------------------------------------------

/// One check from `dig-dns doctor --json` (`SPEC.md §9`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct DoctorCheck {
    pub id: String,
    pub name: String,
    pub status: String,
    pub detail: String,
    pub fix: Option<String>,
}

/// The parsed `dig-dns doctor --json` report.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct DoctorSummary {
    pub ok: bool,
    pub path_a: bool,
    pub path_b: bool,
    pub checks: Vec<DoctorCheck>,
}

/// Parse `dig-dns doctor --json` stdout into a [`DoctorSummary`]. Pure — no
/// process spawn (the caller captures the child's stdout and passes it here).
pub fn parse_doctor_json(text: &str) -> Result<DoctorSummary, String> {
    let v: serde_json::Value =
        serde_json::from_str(text).map_err(|e| format!("parse dig-dns doctor JSON: {e}"))?;
    let ok = v
        .get("ok")
        .and_then(|x| x.as_bool())
        .ok_or("doctor JSON missing \"ok\"")?;
    let path_a = v.get("path_a").and_then(|x| x.as_bool()).unwrap_or(false);
    let path_b = v.get("path_b").and_then(|x| x.as_bool()).unwrap_or(false);
    let checks = v
        .get("checks")
        .and_then(|x| x.as_array())
        .map(|arr| arr.iter().filter_map(parse_doctor_check).collect())
        .unwrap_or_default();
    Ok(DoctorSummary {
        ok,
        path_a,
        path_b,
        checks,
    })
}

fn parse_doctor_check(c: &serde_json::Value) -> Option<DoctorCheck> {
    Some(DoctorCheck {
        id: c.get("id")?.as_str()?.to_string(),
        name: c.get("name")?.as_str()?.to_string(),
        status: c.get("status")?.as_str()?.to_string(),
        detail: c.get("detail")?.as_str()?.to_string(),
        fix: c.get("fix").and_then(|f| f.as_str()).map(str::to_string),
    })
}

/// Which resolution path(s) `doctor` found live, as stable ids (`"dns"` = Path
/// A / OS split-DNS, `"gateway"` = Path B / the PAC gateway).
pub fn live_paths(summary: &DoctorSummary) -> Vec<&'static str> {
    let mut v = Vec::new();
    if summary.path_a {
        v.push("dns");
    }
    if summary.path_b {
        v.push("gateway");
    }
    v
}

/// The parsed `dig-dns pac --json` output: the bound gateway port + the PAC text itself.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PacInfo {
    pub loopback_ip: String,
    pub port: u16,
    pub tld: String,
    pub pac: String,
}

/// Parse `dig-dns pac --json` stdout. Pure.
pub fn parse_pac_json(text: &str) -> Result<PacInfo, String> {
    let v: serde_json::Value =
        serde_json::from_str(text).map_err(|e| format!("parse dig-dns pac JSON: {e}"))?;
    Ok(PacInfo {
        loopback_ip: v
            .get("loopback_ip")
            .and_then(|x| x.as_str())
            .ok_or("pac JSON missing \"loopback_ip\"")?
            .to_string(),
        port: v
            .get("port")
            .and_then(|x| x.as_u64())
            .ok_or("pac JSON missing \"port\"")? as u16,
        tld: v
            .get("tld")
            .and_then(|x| x.as_str())
            .unwrap_or("dig")
            .to_string(),
        pac: v
            .get("pac")
            .and_then(|x| x.as_str())
            .unwrap_or_default()
            .to_string(),
    })
}

/// The gateway's own served PAC URL (Path B) — the reliable fallback when a
/// browser bypasses OS split-DNS (e.g. forced DNS-over-HTTPS).
pub fn pac_url(loopback_ip: &str, port: u16) -> String {
    format!("http://{loopback_ip}:{port}/.dig/proxy.pac")
}

/// The one-line browser-fallback instruction printed after install.
pub fn browser_fallback_instruction(pac_url: &str) -> String {
    format!(
        "If a browser doesn't resolve .dig sites (e.g. it forces DNS-over-HTTPS), \
         point its proxy configuration at the PAC file: {pac_url}"
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn systemd_unit_has_capability_and_dedicated_user() {
        let unit = systemd_unit("/opt/dig/bin/dig-dns", None);
        assert!(unit.contains("ExecStart=/opt/dig/bin/dig-dns serve"));
        assert!(unit.contains(&format!("User={LINUX_SERVICE_USER}")));
        assert!(unit.contains("AmbientCapabilities=CAP_NET_BIND_SERVICE"));
        assert!(unit.contains("CapabilityBoundingSet=CAP_NET_BIND_SERVICE"));
        assert!(unit.contains("NoNewPrivileges=yes"));
        assert!(unit.contains("Restart=always"));
        assert!(unit.contains("WantedBy=multi-user.target"));
        assert!(unit.contains(MARKER));
    }

    #[test]
    fn systemd_unit_forwards_a_node_override() {
        let unit = systemd_unit("/opt/dig/bin/dig-dns", Some("http://localhost:9778"));
        assert!(unit.contains("ExecStart=/opt/dig/bin/dig-dns serve --node http://localhost:9778"));
    }

    #[test]
    fn systemd_resolved_dropin_routes_dig_domain() {
        let d = systemd_resolved_dropin("127.0.0.5");
        assert!(d.contains("[Resolve]"));
        assert!(d.contains("DNS=127.0.0.5"));
        assert!(d.contains("Domains=~dig"));
        assert!(d.contains(MARKER));
    }

    #[test]
    fn networkmanager_dnsmasq_conf_routes_dig_domain() {
        let c = networkmanager_dnsmasq_conf("127.0.0.5");
        assert!(c.contains("server=/dig/127.0.0.5"));
        assert!(c.contains(MARKER));
    }

    #[test]
    fn chrome_policy_json_disables_doh_and_builtin_resolver() {
        let json = chrome_policy_json();
        let v: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(v["DnsOverHttpsMode"], "off");
        assert_eq!(v["BuiltInDnsClientEnabled"], false);
    }

    #[test]
    fn launchd_service_plist_runs_as_root_with_keepalive_and_logs() {
        let plist = launchd_service_plist("/usr/local/bin/dig-dns", None);
        assert!(plist.contains(&format!("<string>{SERVICE_LABEL}</string>")));
        assert!(plist.contains("<string>/usr/local/bin/dig-dns</string>"));
        assert!(plist.contains("<string>serve</string>"));
        assert!(
            !plist.contains("UserName"),
            "must run as root (no UserName key)"
        );
        assert!(plist.contains("<key>KeepAlive</key>\n\t<true/>"));
        assert!(plist.contains("/var/log/dig-dns.out.log"));
        assert!(plist.contains("/var/log/dig-dns.err.log"));
        assert!(plist.contains(MARKER));
    }

    /// #301 boot-start guarantee (dig-dns, cross-OS). The one shared flag that
    /// drives auto-start-on-boot must stay `true`, and the two artifacts that
    /// encode boot-start declaratively (the systemd unit's install target and
    /// the launchd service plist's `RunAtLoad`) must agree. Windows boot-start is
    /// the SCM `start= auto` that `service-manager` derives from this same
    /// `autostart` flag (asserted structurally here; exercised on the Windows
    /// build in `super::windows`).
    #[test]
    // The `DNS_SERVICE_AUTOSTART` check is intentionally an assert-on-constant:
    // it is a compile-anchored regression guard that a future edit can't silently
    // flip the shared boot-start flag to manual-start (which would break
    // auto-start-on-boot on all three OSes, #301).
    #[allow(clippy::assertions_on_constants)]
    fn dns_service_is_registered_as_boot_start() {
        assert!(
            DNS_SERVICE_AUTOSTART,
            "dig-dns must register as a boot-start (auto-start-on-boot) service (#301)"
        );
        // Linux: systemd unit installs into the multi-user boot target.
        let unit = systemd_unit("/opt/dig/bin/dig-dns", None);
        assert!(
            unit.contains("WantedBy=multi-user.target"),
            "systemd unit must start on boot"
        );
        // macOS: launchd service plist loads at boot.
        let plist = launchd_service_plist("/usr/local/bin/dig-dns", None);
        assert!(
            plist.contains("<key>RunAtLoad</key>\n\t<true/>"),
            "launchd service plist must RunAtLoad (start on boot)"
        );
    }

    #[test]
    fn launchd_service_plist_forwards_a_node_override() {
        let plist = launchd_service_plist("/usr/local/bin/dig-dns", Some("http://localhost:9778"));
        assert!(plist.contains("<string>--node</string>"));
        assert!(plist.contains("<string>http://localhost:9778</string>"));
    }

    #[test]
    fn launchd_lo0_alias_plist_is_a_one_shot_boot_task() {
        let plist = launchd_lo0_alias_plist("127.0.0.5");
        assert!(plist.contains(&format!("<string>{LO0_ALIAS_LABEL}</string>")));
        assert!(plist.contains("<string>/sbin/ifconfig</string>"));
        assert!(plist.contains("<string>127.0.0.5</string>"));
        assert!(plist.contains("<key>RunAtLoad</key>\n\t<true/>"));
        assert!(plist.contains("<key>KeepAlive</key>\n\t<false/>"));
    }

    #[test]
    fn resolver_dig_content_is_a_bind_style_nameserver_line() {
        assert_eq!(resolver_dig_content("127.0.0.5"), "nameserver 127.0.0.5\n");
    }

    #[test]
    fn chrome_managed_plist_disables_doh() {
        let plist = chrome_managed_plist();
        assert!(plist.contains("DnsOverHttpsMode"));
        assert!(plist.contains("<string>off</string>"));
        assert!(plist.contains("BuiltInDnsClientEnabled"));
        assert!(plist.contains(MARKER));
    }

    #[test]
    fn nrpt_add_command_is_idempotent_and_tagged() {
        let cmd = nrpt_add_ps_command("127.0.0.5");
        assert!(cmd.contains("Add-DnsClientNrptRule"));
        assert!(cmd.contains("-Namespace '.dig'"));
        assert!(cmd.contains("-NameServers '127.0.0.5'"));
        assert!(cmd.contains(MARKER));
        assert!(
            cmd.contains("if (-not (Get-DnsClientNrptRule"),
            "must guard re-adding"
        );
    }

    #[test]
    fn nrpt_remove_command_only_targets_marked_rules() {
        let cmd = nrpt_remove_ps_command();
        assert!(cmd.contains(&format!("$_.Comment -eq '{MARKER}'")));
        assert!(cmd.contains("Remove-DnsClientNrptRule"));
    }

    #[test]
    fn service_host_launch_args_wrap_the_target_binary() {
        let args = service_host_launch_args(r"C:\dig\bin\dig-dns.exe", None);
        assert_eq!(
            args,
            vec![
                SERVICE_HOST_SUBCOMMAND.to_string(),
                "--exec".to_string(),
                r"C:\dig\bin\dig-dns.exe".to_string(),
            ]
        );
    }

    #[test]
    fn service_host_launch_args_forward_a_node_override() {
        let args = service_host_launch_args("dig-dns.exe", Some("http://localhost:9778"));
        assert_eq!(
            args,
            vec![
                SERVICE_HOST_SUBCOMMAND.to_string(),
                "--exec".to_string(),
                "dig-dns.exe".to_string(),
                "--node".to_string(),
                "http://localhost:9778".to_string(),
            ]
        );
    }

    #[test]
    fn service_host_launch_args_ignore_a_blank_node_override() {
        let args = service_host_launch_args("dig-dns.exe", Some("   "));
        // Base is [SUBCOMMAND, "--exec", path] = 3; a blank --node adds nothing.
        assert_eq!(args.len(), 3, "a blank --node must not be forwarded");
        assert!(!args.contains(&"--node".to_string()));
    }

    #[test]
    fn parse_doctor_json_extracts_paths_and_checks() {
        let text = r#"{
            "ok": true, "path_a": false, "path_b": true,
            "checks": [
                {"id":"loopback_ip","name":"Loopback IP is up","status":"pass","detail":"127.0.0.5 is assigned"},
                {"id":"gateway_port","name":"HTTP gateway answers (Path B)","status":"pass","detail":"answered on :80"},
                {"id":"os_routing","name":"OS resolves .dig","status":"warn","detail":"not configured","fix":"configure split-DNS"}
            ]
        }"#;
        let s = parse_doctor_json(text).expect("parses");
        assert!(s.ok);
        assert!(!s.path_a);
        assert!(s.path_b);
        assert_eq!(s.checks.len(), 3);
        assert_eq!(s.checks[0].id, "loopback_ip");
        assert_eq!(s.checks[0].status, "pass");
        assert!(s.checks[0].fix.is_none());
        assert_eq!(s.checks[2].fix.as_deref(), Some("configure split-DNS"));
    }

    #[test]
    fn parse_doctor_json_rejects_malformed_input() {
        assert!(parse_doctor_json("not json").is_err());
        assert!(
            parse_doctor_json(r#"{"path_a":true}"#).is_err(),
            "missing ok"
        );
    }

    #[test]
    fn live_paths_reports_dns_and_gateway_ids() {
        let both = DoctorSummary {
            ok: true,
            path_a: true,
            path_b: true,
            checks: vec![],
        };
        assert_eq!(live_paths(&both), vec!["dns", "gateway"]);

        let neither = DoctorSummary {
            ok: false,
            path_a: false,
            path_b: false,
            checks: vec![],
        };
        assert!(live_paths(&neither).is_empty());
    }

    #[test]
    fn parse_pac_json_extracts_bound_port_and_pac_text() {
        let text = r#"{"loopback_ip":"127.0.0.5","port":8053,"tld":"dig","pac":"function FindProxyForURL(url, host) { return \"DIRECT\"; }"}"#;
        let info = parse_pac_json(text).expect("parses");
        assert_eq!(info.loopback_ip, "127.0.0.5");
        assert_eq!(info.port, 8053);
        assert_eq!(info.tld, "dig");
        assert!(info.pac.contains("FindProxyForURL"));
    }

    #[test]
    fn parse_pac_json_rejects_malformed_input() {
        assert!(parse_pac_json("not json").is_err());
        assert!(
            parse_pac_json(r#"{"loopback_ip":"127.0.0.5"}"#).is_err(),
            "missing port"
        );
    }

    #[test]
    fn pac_url_points_at_the_control_endpoint() {
        assert_eq!(
            pac_url("127.0.0.5", 80),
            "http://127.0.0.5:80/.dig/proxy.pac"
        );
        assert_eq!(
            pac_url("127.0.0.5", 8053),
            "http://127.0.0.5:8053/.dig/proxy.pac"
        );
    }

    #[test]
    fn browser_fallback_instruction_mentions_the_pac_url() {
        let url = pac_url(LOOPBACK_IP, HTTP_PORT);
        let msg = browser_fallback_instruction(&url);
        assert!(msg.contains(&url));
        assert!(msg.contains("PAC"));
    }

    #[test]
    fn service_label_and_script_name_are_stable() {
        assert_eq!(SERVICE_LABEL, "net.dignetwork.dig-dns");
        assert_eq!(SERVICE_SCRIPT_NAME, "dig-dns");
    }
}
