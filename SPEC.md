# dig-installer — SPEC

Normative contract for `dig-installer`: the universal DIG installer (CLI thin-shim + the Tauri
GUI wizard at `gui/`). This is the authoritative reference an independent reimplementation, or an
agent driving this installer, could build against. For tutorial/how-to content see `README.md`;
for the full machine-readable invocation contract see `--help-json`
(`help_json()` in `src/lib.rs`).

## 1. Component catalogue

The installer consumes released artifacts only — it builds nothing itself. Every component is
resolved against the LATEST GitHub release for its OS/arch (or a pinned `--<component>-version`),
selecting the matching asset from the release's actual asset list (`src/asset.rs`), never a
guessed filename.

**The default install is the full DIG stack in one run** — the `digstore` CLI, the `dig-node`
service, and the `dig-dns` service are ALL installed by default (a bare `dig-installer` with no
flags installs all three; `InstallPlan::default()` encodes this). `dig-node` and `dig-dns` are
registered as **boot-start** OS services (§2.1). Opt out of any of the three with the matching
`--no-<component>` flag. `dig-relay` (advanced, run-your-own-relay) and the DIG Browser stay
opt-in.

| id         | repo                          | kind                              | CLI flag(s)                          | Selected in the GUI wizard by default |
|------------|-------------------------------|------------------------------------|---------------------------------------|----------------------------------------|
| `digstore` | `DIG-Network/digstore`        | raw binary, added to PATH          | on by default; `--no-digstore` opts out; `--with-digstore` (redundant, symmetry) | always (required, no checkbox) |
| `digs`     | `DIG-Network/digstore` (alias, issue #434) | raw binary, added to PATH (same bin dir as `digstore`) | NO separate flag — follows `digstore`'s `--no-digstore`/`--with-digstore`/`--digstore-version` | follows `digstore` |
| `dig-node` | `DIG-Network/dig-node`        | raw binary + boot-start OS service + `dig.local` hosts entry | on by default; `--no-dig-node` opts out; `--with-dig-node`/`--service` (redundant) | yes |
| `dig-dns`  | `DIG-Network/dig-dns`         | raw binary + boot-start OS service + split-DNS/NRPT + browser DoH policy | on by default; `--no-dig-dns` opts out; `--with-dig-dns` (redundant) | yes |
| `dig-relay`| `DIG-Network/dig-relay`       | raw binary + OS service (advanced, opt-in) | `--with-relay` | no — unchecked, user-checkable (#491) |
| `browser`  | `DIG-Network/DIG_Browser`     | native installer, downloaded only (not run) | `--with-browser` | no — hidden, not offered (#491) |

The GUI wizard's Components screen (`gui/app/src/data.jsx` → `COMPONENTS`, rendered by
`steps/Components.jsx`, initial selection in `App.jsx`) mirrors the CLI defaults (task #491): the
**core stack (digstore + dig-node + dig-dns) is pre-selected** — installing it is the one-click
default path; `digstore` is `REQUIRED` (no checkbox). **`dig-relay` is present but UNCHECKED by
default** (advanced; the node already uses the canonical `relay.dig.net`) — the user may check it.
**The DIG Browser is `hidden`** — not offered in the installer for now (the catalogue entry is kept
for easy re-enable; `Components.jsx` filters out any `hidden` component). Deselecting a component
removes it from the install plan entirely (its artifact is neither downloaded nor registered). This
matches `InstallPlan::default()` (dig-relay + browser are opt-in: `--with-relay`/`--with-browser`).

**Optional GitHub API authentication (#502/#524).** Every release lookup (`/releases/latest`,
`/releases/tags/<tag>`, the releases-list fallback) is an unauthenticated `api.github.com` call by
default — GitHub caps those at 60/hour per source IP, a limit shared/heavily-used networks (CI
runners, corporate NAT) hit routinely. When the `GITHUB_TOKEN` environment variable is set (a
non-empty string), every such call carries `Authorization: Bearer <token>`, raising the limit to
5,000/hour — matching the name GitHub Actions already exposes as `secrets.GITHUB_TOKEN` and the `gh`
CLI convention, so CI needs no new secret. Entirely optional and additive: unset (the default), the
installer behaves exactly as before this existed; the token is never required, never logged, and the
release ASSET download itself (a `github.com/.../releases/download/...` redirect, not the API) is
never authenticated — only the JSON API lookups are. See `download::get_text_with_token`.

### 1.1 `digs` — a first-class alias of `digstore`

`digs` (issue #434) is a real installed binary, not a shell alias: `digs <args>` behaves
IDENTICALLY to `digstore <args>` (same subcommands/flags/`--json`/help — see digstore's `SPEC.md`
§ "CLI binaries"). It is published in the **SAME** `DIG-Network/digstore` GitHub release as
`digstore`, under its own asset stem (`digs-<ver>-<os_arch>[.exe]`, byte-for-byte the same shape as
`digstore-<ver>-<os_arch>[.exe]`) — resolved via the identical asset matcher
(`src/asset.rs::select_asset`), parameterized on stem `"digs"` instead of `"digstore"`.

`digs` has **no CLI flag of its own**: it installs/uninstalls exactly when `digstore` does, pinned
to the SAME version (`--digstore-version` threads through to both), and is written to the SAME bin
dir — so no separate PATH entry is needed. Resolution order in `run_report_with`: `digstore` is
resolved and downloaded first, then `digs`, both gated by `with_digstore`.

### 1.2 dig-dns availability gate

`dig-dns` (EPIC #174) may have no published release at all. If `with_dig_dns` is selected and no
release/matching asset can be resolved for it (an `ASSET_NOT_FOUND`-classified lookup — "nothing
published" as opposed to a network/transport failure), the installer:

- does NOT fail the overall install plan;
- records `InstallReport.dns` with `installed: false`, `started: false`,
  `needs_elevation: false`, and a `note` explicitly stating dig-dns is "not yet available" and
  naming EPIC #174;
- continues installing every other selected component (order preserved: digstore → digs → dig-node →
  dig-dns[gated] → dig-relay → browser).

A genuine transport/network failure resolving dig-dns (not "no release exists") is NOT gated —
it propagates like any other component's resolution failure (`NETWORK`, exit code 4).

### 1.3 `chia://` URL-scheme handler (#389)

By default the installer registers itself as the OS handler for `chia://` links (and, best-effort,
`urn:` where the OS permits a generic handler). This is a **first-class, toggleable install
option**, default ON, controlled identically from the CLI and the GUI:

- **CLI:** registered by default. `--no-register-scheme` opts OUT; `--register-scheme` is the
  redundant explicit opt-in (symmetry with the `--no-<component>`/`--with-<component>` flags). Both
  map to the single `InstallPlan.register_scheme` field (`register_scheme = --register-scheme ||
  !--no-register-scheme`), so `--no-*` wins if both are given. `--unregister-scheme` removes a
  handler this installer created and runs standalone (ignores every other flag).
- **GUI:** the same default-on option, surfaced as a checkbox that sets `register_scheme` on the
  plan handed to the Rust pipeline — the GUI and CLI defaults are in sync.

Registration is **per-user, no elevation** (unlike the OS services). Per-OS mechanism:

| OS | Registration | `urn:` |
|----|--------------|--------|
| Windows | `HKCU\Software\Classes\chia` with an empty `URL Protocol` value + `shell\open\command` = `"<bin>" handle-url "%1"` | yes (`HKCU\Software\Classes\urn`) |
| Linux | a `~/.local/share/applications/dig-network-url-handler.desktop` with `MimeType=x-scheme-handler/chia;` + `xdg-mime default` | yes (`x-scheme-handler/urn`) |
| macOS | LaunchServices binds a scheme to a `.app` bundle, not a bare CLI — a CLI-only install cannot own the scheme, so registration is a documented best-effort no-op (reported honestly in `SchemeResult.note`, never a silent fake success); the DIG Browser `.app` registers it when installed | n/a |

The registered handler is **this installer's own binary**, persisted to the bin dir so it survives
a transient `irm|iex` download copy, invoked by the OS as the hidden subcommand `dig-installer
handle-url <uri>`. `handle-url` parses the URI (`chia://<store>/<path>` or
`urn:dig:chia:<store>[/<path>]`), picks the first reachable §5.3 base
(`http://dig.local` → `http://localhost:9778` → `https://rpc.dig.net`, falling back to the public
gateway so a click always opens something), builds the node serve URL `<base>/s/<store>/<path>`,
and opens it in the default browser. Registration is **best-effort within the install**: a failure
is recorded in `InstallReport.scheme` (a `SchemeResult { registered, schemes, note }`) but never
aborts the install (every other component already succeeded).

### 1.4 App-scoped firewall rule for dig-node's peer-RPC port (#424)

By default the installer opens an inbound firewall rule scoped to the installed **dig-node**
executable on its peer-RPC port — dig-node's ONLY non-loopback listener (every other surface —
`localhost:<dig-node-port>` RPC, `dig-wallet`'s `127.0.0.1:9777`, `dig.local:80` — is loopback-only
and is NEVER opened). This is a **first-class, toggleable install option**, default ON, controlled
identically from the CLI and the GUI — the same convention as §1.3's `chia://` scheme handler:

- **CLI:** opened by default. `--no-open-firewall` opts OUT; `--open-firewall` is the redundant
  explicit opt-in. Both map to `InstallPlan.open_firewall` (`open_firewall = --open-firewall ||
  !--no-open-firewall`), so `--no-*` wins if both are given. Only takes effect when
  `with_dig_node` is also set — there is no standalone `--unopen-firewall` (unlike
  `--unregister-scheme`): removal happens automatically via `--uninstall-dig-node` (below).
- **GUI:** the same default-on option, surfaced as a checkbox (`gui/app/src/data.jsx` `OPTIONS`,
  rendered by `Components.jsx` directly under the component list, only while dig-node itself is
  checked) that sets `open_firewall` on the plan handed to the Rust pipeline.

**Port resolution (`firewall::effective_peer_port`):** the rule targets `DIG_PEER_PORT` (parsed as
a `u16`) if that env var is set, else `firewall::DEFAULT_PEER_PORT` (`9444`) — dig-node's own
`peer::DEFAULT_P2P_PORT` default. The rule therefore always tracks whatever port dig-node is
actually configured to listen on, never a stale hard-coded value.

**Per-OS behaviour** (best-effort — a failure is recorded, never aborts the install; every
per-OS command-line builder is pure and unit-tested, the actual process spawn is the thin,
untested-by-`cargo test` I/O layer):

| OS | Mechanism | Notes |
|----|-----------|-------|
| Windows | A single named `netsh advfirewall firewall add rule name="DIG Network Node (P2P)" dir=in action=allow program="<dig-node.exe>" protocol=TCP localport=<port>` | No `remoteip=`/`interfacetype=` restriction: an omitted `remoteip` defaults to "Any" in Windows Firewall, which is evaluated against BOTH IPv4 and IPv6 (§5.2) — one rule, both families. |
| macOS | Adds the executable to the Application Firewall (ALF) exception list: `socketfilterfw --add <dig-node>` + `--unblockapp <dig-node>` | Only when ALF is actually enabled (`--getglobalstate`) — if it is off, every inbound connection is already unfiltered, so adding an exception would be a silent no-op dressed up as a success; skipped and reported as such. |
| Linux | **Never auto-applied.** | Too many competing firewall managers (`ufw`/`firewalld`/bare `iptables`) to safely automate. The installer prints (and `runbooks/local-running.md` documents) the one-line manual remedy: `sudo ufw allow <port>/tcp`. |

**Removal:** `--uninstall-dig-node` (§3, `ServiceUninstallResult`) removes the rule alongside the OS
service and the `dig.local` hosts entry — idempotent (an already-absent/declined rule is a clean
no-op, `firewall_rule_removed: false` with an explanatory note, never an error). Windows removal
targets the rule by its stable name (`netsh advfirewall firewall delete rule name="DIG Network Node
(P2P)"`), so it is correct even if `DIG_PEER_PORT` changed between install and uninstall.

Declining the option (or a failure applying it) is always safe: a node without the rule remains
fully reachable through the `dig-relay` fallback path — only direct/relay-free peer connections are
affected.

## 2. Install lifecycle — stop before write, start after write

For the two components this installer registers as OS services with their OWN `install`/
`uninstall`/`start`/`stop`/`status` CLI verbs — **dig-node** and **dig-relay** — every
(re-)install follows this order per component, never reversed:

1. **Resolve** the release + asset for the target OS/arch (network).
2. **Stop-if-serving** (task #232): if a binary already exists at the destination path (i.e. this
   is an upgrade, not a first install), probe `<dest> status --json` and, if it reports
   `serving: true`, run `<dest> stop`. Skip-when-absent/not-serving: neither is an error. **A stop
   FAILURE while serving aborts this component's write** (`SERVICE_STOP_FAILED`, exit code 10) —
   the binary is NEVER overwritten out from under a still-running process.
3. **Write** the newly downloaded binary to the destination path (only reached once step 2
   succeeds or was a no-op).
4. **Register + start**: run `<dest> install` (tolerated if it fails — an already-registered
   service reports this on re-install; the registration still points at the same on-disk path, so
   the next step still picks up the binary just written), then, if the plan requests it,
   `<dest> start`. Only a `start` failure is a hard error (`SERVICE_START_FAILED`).

This restores the prior running state: a service that was running before the install is running
again after it (now serving the new binary); a service that was never installed/running is
skipped cleanly at step 2 and freshly installed+started at step 4; re-running the installer at any
point is safe (idempotent).

Every delegated subcommand (`install`/`start`/`stop`/`uninstall`) spawns the component's binary
with its stdio **captured, never inherited** (`service::run_capturing`): a non-zero exit folds the
child's own combined stdout+stderr into the returned error (nothing is lost — a Windows elevation
hint dig-node itself prints, for example, still reaches the user via this installer's OWN error/
`note` reporting), and a success discards it (this installer already logs its own confirmation for
the same event). Inheriting stdio directly was the PRIOR behavior; it silently broke `--json` mode
the moment a real (non-dry-run) install ran a delegated subcommand — the child's prose landed on
the SAME stdout fd `--json` reserves for exactly one structured line, corrupting it for any
consumer (`jq`, an agent) expecting well-formed JSON (found via the 3-OS installer-e2e job,
dig_ecosystem#502/#524).

`status --json`'s envelope shape differs per component and is parsed accordingly:
`dig-node` → flat `{"serving": bool, ...}`; `dig-relay` → nested `{"result": {"serving": bool,
...}}"`. Neither binary's `status` can distinguish "not installed" from "installed but stopped" —
both read as `serving: false`; this installer treats "no binary at the destination path" as the
"first install, nothing to stop" case instead of relying on that distinction.

**digstore** (not a service) and the downloaded **DIG Browser** native installer file are not
service-managed; if writing either destination fails because the file already exists and is
locked by a running process, the write error is annotated with a hint that the destination may be
in use by a running process, rather than a raw OS error code. DIG Browser's OWN native installer
(NSIS/equivalent) is responsible for closing a running browser instance before it overwrites the
installed application — this installer only downloads DIG Browser's installer artifact, it never
runs it or overwrites the installed application itself.

Every managed component is driven through its OWN CLI verbs / OS service manager (`service-manager`
crate for dig-dns, since it ships no verbs of its own — see `src/dns/`); this installer never
hand-rolls a parallel service controller.

### 2.1 Boot-start (auto-start-on-boot) services

Both service components register to **start automatically on every boot**, on all three OSes:

- **dig-node** — registered via its own `dig-node install` verb, which sets `autostart: true`
  (dig-node-service's `service::install`). The installer invokes plain `install` (never a
  manual-start variant), so boot-start is the delegated default.
- **dig-dns** — registered by this installer directly (dig-dns ships no service verbs). The shared
  flag `dns::plan::DNS_SERVICE_AUTOSTART` (always `true`) is threaded into the `service-manager`
  `ServiceInstallCtx.autostart` on each OS.

Per-OS boot-start mechanism (the same for both components):

| OS      | Boot-start mechanism |
|---------|----------------------|
| Windows | SCM `start= auto` (the service comes up at boot) |
| Linux   | systemd `enable` + the unit's `[Install] WantedBy=multi-user.target` |
| macOS   | launchd LaunchDaemon with `RunAtLoad` |

`--no-service-start` installs a service but does not start it *this run* — it is still registered
boot-start, so it comes up on the next boot. This boot-start contract is regression-guarded by
`dns::plan::tests::dns_service_is_registered_as_boot_start` and
`service::tests::dig_node_is_registered_boot_start_via_the_install_verb`.

### 2.2 dig-dns service identity + clean reinstall (task #494)

dig-dns's OS service identity is canonical and stable across releases:

| | value |
|---|---|
| Service NAME (id) | `net.dignetwork.dig-dns` (`dns::plan::SERVICE_LABEL`) — the reverse-DNS SCM service name (Windows), launchd label (macOS); on Linux the REAL systemd unit name is `dignetwork-dig-dns`, derived from `SERVICE_LABEL` via `dns::plan::service_script_name()` (§4.2's "Linux queries the REAL unit name" note) |
| Windows DISPLAY name | `DIG NETWORK: DNS` (`dns::plan::SERVICE_DISPLAY_NAME`) — the human-friendly name shown in `services.msc`/Task Manager's Services tab |

The service NAME is the stable id every OS query/health-check targets; the DISPLAY name is
user-facing only and Windows-specific (macOS/Linux have no separate display-name concept —
`launchctl`/`systemctl` are addressed by the same label/unit name a human sees). Because
`service-manager`'s `ScServiceManager::install` unconditionally sets `displayname=` to the
qualified service name at create time (its `ServiceInstallCtx` has no display-name field),
`dns::windows::install` applies the display name as a follow-up `sc config <name> displayname=
"<display>"` call (`dns::plan::sc_set_display_name_args`).

**Clean reinstall, on every OS.** `install` never reconfigures an already-registered dig-dns
service in place — it always stops + deregisters a pre-existing registration FIRST, then
recreates fresh. This fixes the Windows `CreateService` error 1073 ("already exists") that a
plain re-`install` produced on a second run:

| OS | detect | remove | recreate |
|----|--------|--------|----------|
| Windows | `sc query <name>` exit code (`dns::plan::sc_query_means_not_registered`: 1060 = not registered, anything else = treated as existing) | `sc stop` (best-effort) + `sc delete`, then poll `sc query` up to 5s for the removal to land (`dns::windows::wait_for_removal`) | `sc create` (`ScServiceManager::install`) + re-apply the display name |
| macOS | `launchctl print system/<label>` exit code (`dns::macos::service_registered`) | `launchctl bootout system/<label>` (the modern replacement for `unload`) + delete the `/Library/LaunchDaemons/<label>.plist` file (`dns::macos::clean_remove_existing`) | write a fresh plist + `launchctl load` (`ServiceInstallCtx.autostart`) |
| Linux | the unit file's presence under `/etc/systemd/system/<script>.service` (`dns::linux::unit_registered`) | `systemctl stop` + `systemctl disable` (removes the unit file too, via `SystemdServiceManager::uninstall`) (`dns::linux::clean_remove_existing_unit`) | write a fresh unit file + `systemctl enable` |

An absent registration is a no-op at the detect step (nothing to remove); the removal itself is
best-effort (errors are noted but never abort the install — the subsequent create attempt is the
authoritative outcome).

## 3. `InstallReport` (the `--json` payload)

Stable, versioned (`schema_version`) JSON shape emitted by `--json` on success:
`{schema_version, installer_version, target, dry_run, components[], path, service, relay, dns,
scheme, firewall, installed[], cli_path_checks[], ready, failures[]}`. See `src/lib.rs` doc comments
on `InstallReport`/`ComponentResult`/`PathResult`/`ServiceResult`/`RelayResult`/
`dns::DnsInstallResult`/`scheme::SchemeResult`/`firewall::FirewallResult`/`pathcheck::CliPathCheck`
for the exact field set; every boolean field has a paired human-readable `*_note` — no field is
ever silently omitted to signal failure. `firewall` is `None` when `open_firewall` is off (§1.4) —
distinct from a present-but-`applied: false` result, so a caller can tell "declined" apart from
"attempted and failed". `ready`/`failures` are the aggregate readiness verdict (§4.2) — the firewall
rule is best-effort and never gates `ready`, same as the scheme handler; the `--json` envelope's
`ok` mirrors `ready`.

## 4. Exit codes

| code | name | meaning |
|------|------|---------|
| 0 | `OK` | success |
| 2 | `UNSUPPORTED_TARGET` | host OS/arch is not a supported DIG release target |
| 3 | `ASSET_NOT_FOUND` | release or matching per-OS/arch asset not found |
| 4 | `NETWORK` | network/HTTP error contacting GitHub or downloading |
| 5 | `CHECKSUM_MISMATCH` | downloaded artifact failed its SHA-256 verification |
| 6 | `PATH_UPDATE_FAILED` | could not update PATH (the binary was still placed) |
| 7 | `SERVICE_NEEDS_ELEVATION` | service registration needs an elevated console |
| 8 | `SERVICE_START_FAILED` | the dig-node/dig-relay service failed to install or start |
| 9 | `IO` | failed to write a downloaded binary to disk |
| 10 | `SERVICE_STOP_FAILED` | a running service failed to stop before its binary could be safely replaced (task #232) |
| 11 | `NOT_ELEVATED` | the installer was launched without elevation (Administrator/root) but the plan needs it — re-run elevated (#492) |
| 12 | `INSTALL_INCOMPLETE` | a completed run that is NOT ready: a selected component failed to install or its service is not running — DIG is not ready (#493) |

This table is generated from `src/error.rs::EXIT_CODES` and mirrored in `--help-json`; the two
can never drift (`error::tests::exit_codes_table_matches_error_kinds`).

## 4.1 Elevation enforcement (#492)

The installer REQUIRES elevation — Administrator on Windows, root (sudo) on macOS/Linux — whenever
the plan registers an OS service (dig-node / dig-dns / dig-relay) or writes the `dig.local` hosts
entry (`InstallPlan::requires_elevation()`). The check runs **FIRST**, before resolving/downloading/
writing anything: an un-elevated run of such a plan fails immediately with `NOT_ELEVATED` (exit 11)
and leaves NO partial state. A `--dry-run` or a digstore-only (per-user) install never trips the
gate. The per-OS elevation probe is `elevation::is_elevated` (Windows `net session`, Unix `id -u`);
the pure decision + per-OS remedy is `elevation::gate` (unit-tested). The GUI enforces the same gate
before its first write.

## 4.2 Readiness verdict — fail loud (#493)

A run does not report success merely because downloads succeeded. `InstallReport` carries an
aggregate `ready: bool` + `failures: Vec<String>`: **`ready` is `true` only when every selected
component installed AND its service is verified RUNNING**. The CLI prints `✓ DIG is ready` only when
`ready`; otherwise it prints `✗ DIG is NOT ready` with each failure + the remedy and exits
`INSTALL_INCOMPLETE` (exit 12). `--json` still emits the full report with `ok:false`. The GUI emits
`install://error` (never `install://done`) when not ready. A `--dry-run` installs nothing, so it is
trivially `ready`.

### Real service health — by service id, not a port probe

Post-install health is judged by querying the OS **service manager** for the RUNNING state of the
service THIS run registered, identified by its canonical reverse-DNS id — `net.dignetwork.dig-node`
/ `net.dignetwork.dig-dns` (`svc` module: Windows `sc query`, Linux `systemctl is-active`, macOS
`launchctl print`). A bare listener on port 9778 started by something else can no longer produce a
false success; the JSON-RPC `rpc.discover` probe is retained only as secondary detail. dig-dns
readiness additionally requires at least one live resolution path (`paths_live`).

**Linux checks BOTH systemd scopes (#502/#524).** dig-node's own `install` always prefers a
USER-level unit regardless of privilege (a deliberate no-elevation-needed design), while
dig-installer registers dig-dns machine-wide (§2.2) — so `svc::service_run_state_on` queries
`systemctl --user is-active <id>` AND `systemctl is-active <id>` and combines them
(`combine_systemctl_states`): Running wins if EITHER scope reports it. A single system-scoped-only
query previously could never see a genuinely-running dig-node, permanently reporting "registered but
NOT running" (found + fixed via the 3-OS installer-e2e job, dig_ecosystem#502).

**Linux queries the REAL unit name, not the canonical id, on that one platform.** Windows (`sc`)
and macOS (`launchctl`) both address a service by the FULL canonical id verbatim, but Linux does
not: EVERY dig-node/dig-dns systemd registration in this workspace goes through the
`service-manager` crate's `ServiceLabel`, whose systemd backend derives the unit name via
`to_script_name()` — dropping the reverse-DNS qualifier and hyphen-joining
`{organization}-{application}`, so `net.dignetwork.dig-node` registers as `dignetwork-dig-node` and
`net.dignetwork.dig-dns` as `dignetwork-dig-dns`. `svc::linux_unit_name` applies the SAME
parse-then-derive to any canonical id (never a hardcoded per-service guess), and
`dns::plan::service_script_name` derives dig-dns's OWN registration name identically — so the two
can never drift apart. This was a real, previously-undetected naming mismatch (a stale hardcoded
`SERVICE_SCRIPT_NAME = "dig-dns"` constant, which LOOKED like the obvious dashed form but was never
what actually got registered) that made the Linux health check — and dig-dns's own clean-reinstall
detection — permanently false-negative even BEFORE the dual-scope fix above; only surfaced by a real
`systemctl status` against a live install (dig_ecosystem#502/#524).

### CLI-on-PATH verification (#496)

`digstore`, `dig-node`, and `dig-dns` are placed in one bin dir which is added to PATH; the installer
then verifies each resolves **by bare name from a fresh shell** (`pathcheck` module) so a user can run
`dig-node pair approve <id>` immediately. An unresolvable required CLI makes the install NOT ready.
On Windows the PATH change is broadcast (`WM_SETTINGCHANGE`); a new terminal picks it up.

### Cross-OS end-to-end conformance (#502)

The readiness verdict above is exercised for real — against the actual Windows SCM / systemd /
launchd, never a mock — by `.github/workflows/installer-e2e.yml`: build `dig-installer`, run it
installing both dig-node and dig-dns, assert `ready`/`ok` are `true` with both services registered
and RUNNING by their canonical id and the Windows display names read back correctly (`sc qc`), assert
`dig.local` resolves, then run `--uninstall-dig-node`/`--uninstall-dig-dns` and assert both services
are deregistered and the hosts entry is gone — on `windows-latest`, `macos-14`, and `ubuntu-latest`.
This is distinct from dig-node's and dig-dns's own per-binary "service-smoke" CI (in their own
repos), which prove each BINARY's own `install`/`start`/`uninstall` in isolation; this job proves the
INSTALLER's aggregate contract — the thing an actual user runs — end to end.

## 5. Visual theme (task #233)

The installer GUI (`gui/`) uses the DIG dark cosmic theme as its default and only theme: dark
surfaces (`--bg-space:#101132`, `--bg-void:#0a0a20`), off-white ink, the violet(`#5800D6`)→
magenta(`#FF00DE`) accent gradient, Space Grotesk / Space Mono. This is a deliberate reversion
(a prior revision briefly shipped a white product theme, per a since-superseded reading of
`SYSTEM.md` → "Canonical terminology & branding" — see `DEVELOPMENT_LOG.md`); the installer GUI's
canonical theme going forward is dark.

## 6. GUI (`gui/app`) architecture note

The GUI is a Tauri 2 desktop wizard (Welcome → License → Components → Install → Done). Its `digstore`
CLI install remains a self-contained embedded/staged payload (no network call for that one
component — see `gui/app/src-tauri/src/install.rs` phases 1–6). Every OTHER selected component
(`dig-node`/`dig-dns`/`dig-relay`/`browser`) is installed by delegating to this repo's OWN
`dig_installer::run_report` (the same thin-shim orchestration the CLI uses, including the §2
stop/write/start lifecycle) via a pure `plan_from_selection(selected, bin_dir) -> InstallPlan`
mapping (`install.rs`) — the GUI never reimplements release resolution, download, or service
control.

## 7. Version-aware updater (issue #309)

`dig-installer` is not just an installer — a bare re-run is a version-aware UPDATER: for each of
the three tracked components (`digstore`, `dig-node`, `dig-dns` — `digs`/`dig-relay`/the DIG Browser
are out of scope, see §7.3), it detects what's already at the resolved destination, compares it
against the release it just resolved, and decides what to do. The decision core lives in
`src/update.rs`, deliberately dependency-light and self-contained (a hand-rolled 3-part semver
comparator, no `semver` crate) so it can be extracted verbatim into the planned shared
`dig-release-resolver` crate (#504-B) alongside `release.rs`/`download.rs`.

### 7.1 Detect → compare → decide

For each tracked component, in this order:

1. **Resolve** the release the normal way (§1) — this is unconditional; the version-aware step
   below reuses the version already resolved rather than a second API round trip.
2. **Detect** what's at the destination: `update::detect_installed_version` spawns
   `<dest> --version` (read-only — safe under `--dry-run`, so a dry-run preview is accurate) and
   reads the reported version back, mirroring `pathcheck::cli_resolves`'s spawn convention.
   `Absent` when nothing exists there yet; `Present(raw)` otherwise (`raw` is empty when the binary
   exists but couldn't be queried — spawn failure or non-zero exit).
3. **Decide** (`update::decide`, pure, no I/O) — the full matrix:

   | detected                | vs. latest resolved   | action                              |
   |-------------------------|------------------------|--------------------------------------|
   | absent                  | —                      | **Install**                          |
   | present, parses, older  | installed < latest    | **Update**                            |
   | present, parses, equal  | installed == latest   | **Skip** (up to date)                 |
   | present, parses, newer  | installed > latest    | **Skip** (never downgrade)            |
   | present, does not parse | —                      | **Update** (treated as a reinstall)   |

`--force-reinstall` upgrades a would-be Skip to Update (`update::decide_with_force`); it never
changes an Install/Update decision, since those already replace the artifact.

### 7.2 What Install/Update/Skip each do

- **digstore** (a PATH binary, no service): Install/Update downloads + overwrites the destination;
  Skip leaves the existing binary untouched (no download).
- **dig-node**: Install/Update runs the existing §2 stop-before-write → write → register+start
  lifecycle unchanged. Skip does NOT call `dig-node install`/`start` at all — the already-registered
  service is left exactly as it is (never bounced) — but the post-registration health check
  (`svc::wait_for_service_running`) still independently polls the SAME service-manager RUNNING state
  a fresh install would, so a Skip can never silently paper over a service that died on its own.
- **dig-dns**: Install/Update calls `dns::install` (§2.2's clean-reinstall — stop→delete→recreate).
  Skip instead calls `dns::verify_existing`, which reuses the SAME standalone, read-only `doctor
  --json`/`pac --json` probes an install ends with (no registration is touched) to build the
  identical `DnsInstallResult` shape a fresh install reports — so the caller's logging and the
  `service_running`/`paths_live` readiness gates (§4.2) work unchanged whether this run installed,
  updated, or skipped.

Every decision is logged as a single human-readable line (`UpdateDecision.summary`, e.g. `"v0.14.0
→ v0.15.0 (update)"`, `"v0.15.0 (up to date)"`, `"not installed → install v0.15.0"`) and recorded on
the component's `ComponentResult` (`update_action: "install"|"update"|"skip"`,
`previous_version: string | null`) — both the CLI run summary and the `--json` payload surface it,
so re-running the installer idempotently reports exactly what changed.

### 7.3 Scope

Only `digstore`/`dig-node`/`dig-dns` are update-tracked (`update::tracked_components`). `digs` (the
digstore alias, §1.1) always re-downloads alongside digstore regardless of its own on-disk state
— a known, accepted scope limit (it shares digstore's version pin and is cheap to refetch).
`dig-relay` and the DIG Browser installer are opt-in, advanced/one-shot artifacts and are not
update-tracked at all; selecting them always (re)installs.

### 7.4 GUI preview

The Components screen previews Install/Update/Skip status for `dig-node`/`dig-dns` (NOT `digstore`
— its GUI install is the bundled/embedded payload from §6, with no network "latest" to diff
against; its version is shown separately via the existing bundled-version badge) via the
`component_update_status` Tauri command, calling `update::check_updates` with the real GitHub
resolver. A status pill next to each tracked component reads "Install" / "Update available" / "Up
to date"; a resolution failure (e.g. offline) reads "update check unavailable" rather than guessing.
