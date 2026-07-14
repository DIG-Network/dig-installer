# dig-installer

**The universal DIG installer — a thin shim.** One command resolves and installs
the latest DIG components for your OS/arch:

- the **digstore CLI** (the $DIG content tooling) — added to your `PATH`, along
  with its **`digs` alias binary** (`digs <args>` behaves identically to
  `digstore <args>`; published in the same release, installed alongside it —
  no separate flag or PATH entry needed),
- the **dig-node** local node — installed + started as an OS service (Windows
  service / systemd / launchd), with a best-effort `127.0.0.2 dig.local` hosts
  entry so apps and the DIG Browser can reach it port-free at `http://dig.local`,
- the **dig-dns** local `*.dig` name resolver — installed + started as an OS
  service (Windows Service / macOS LaunchDaemon / Linux systemd), with the OS
  DNS/proxy wiring (split-DNS, NRPT, browser DoH policy) so a browser can open
  `http://<storeId>.dig/…` directly (see [dig-dns](#dig-dns-local-dig-name-resolution) below),
- the **DIG auto-update beacon** (`dig-updater`, + its unprivileged
  `dig-updater-worker` sibling) — installed and registered to check daily for
  new signed DIG releases and install them automatically (see
  [Auto-update beacon](#auto-update-beacon-dig-updater) below),
- the **dig-relay** *(advanced, optional)* — run your own NAT-traversal relay,
  installed + started as an OS service. Most users do **not** need this: every
  node already uses the canonical `relay.dig.net` out of the box.
- the **DIG Browser** — the native installer (`.exe` / `.dmg` / `.AppImage`)
  downloaded for you to run.

It **bundles nothing** and builds nothing. At install time it asks each
component's GitHub release for its **actual asset list** and picks the right
artifact for your OS/arch (resilient to naming differences across repos), then
downloads it. Sources:

- the **digstore CLI** (and its `digs` alias) from [`DIG-Network/digstore`](https://github.com/DIG-Network/digstore/releases)
- the **dig-node** local node from [`DIG-Network/dig-node`](https://github.com/DIG-Network/dig-node/releases)
  (formerly `dig-companion`)
- the **dig-dns** local resolver from [`DIG-Network/dig-dns`](https://github.com/DIG-Network/dig-dns/releases)
- the **auto-update beacon** (+ its worker sibling) from [`DIG-Network/dig-updater`](https://github.com/DIG-Network/dig-updater/releases)
- the **dig-relay** from [`DIG-Network/dig-relay`](https://github.com/DIG-Network/dig-relay/releases)
- the **DIG Browser** from [`DIG-Network/DIG_Browser`](https://github.com/DIG-Network/DIG_Browser/releases)
  — resolution works against DIG Browser's current **alpha/prerelease-only**
  channel (GitHub's "latest release" API excludes prereleases, so the
  installer falls back to the full releases list when that happens) and
  against its current asset naming
  (`ungoogled-chromium_<ver>_installer_x64.exe`, no `windows`/`win` token — the
  matcher keys off the `.exe` extension + the bare `x64` token instead). The
  eventual rebrand to `dig-browser_*` asset names needs no matcher change —
  only the token/extension pattern is checked, not the product-name prefix.

**By default it installs the full DIG stack in one run** — the digstore CLI, the
dig-node service, the dig-dns service (both boot-start OS services that come up
automatically on every boot), and the auto-update beacon (a daily scheduled
task/timer/LaunchDaemon). Opt out of any of them with `--no-digstore` /
`--no-dig-node` / `--no-dig-dns` / `--no-auto-update`. The dig-relay *(advanced)*
and the DIG Browser stay opt-in (`--with-relay` / `--with-browser`). This is the
canonical home of the DIG installer, migrated out of `digstore`.

---

## Install (one-liner)

**macOS / Linux**

```sh
curl -fsSL https://raw.githubusercontent.com/DIG-Network/dig-installer/main/install.sh | sh
```

**Windows (PowerShell)**

```powershell
irm https://raw.githubusercontent.com/DIG-Network/dig-installer/main/install.ps1 | iex
```

This one command installs the **full DIG stack** — the digstore CLI, the
dig-node local node (a boot-start OS service + a `127.0.0.2 dig.local` hosts
entry), and the dig-dns `*.dig` name resolver (a boot-start OS service + the OS
DNS/proxy wiring). Then open a **new** terminal and check it works:

```sh
digstore --version
```

> **The installer REQUIRES elevation** (Administrator on Windows, `sudo` on
> macOS/Linux) because it registers the dig-node + dig-dns OS services and
> writes the `dig.local` hosts entry. An un-elevated run is refused **up front**
> (`NOT_ELEVATED`, exit 11) before anything is downloaded or written — it never
> leaves a half-installed state. On Windows, run PowerShell as Administrator
> before the `irm … | iex` line; on macOS/Linux, `curl -fsSL … | sudo sh`.
> **"✓ DIG is ready" prints only when every selected component installed AND its
> service is verified RUNNING**; otherwise the installer reports exactly what
> failed and exits non-zero (`INSTALL_INCOMPLETE`, exit 12) — never a false
> success.

### Install only some components

Every component installs by default; opt out of any with its `--no-<component>`
flag (the flags pass straight through the bootstrap scripts after `--`):

```sh
# macOS / Linux — just the digstore CLI, nothing else
curl -fsSL https://raw.githubusercontent.com/DIG-Network/dig-installer/main/install.sh | sh -s -- --no-dig-node --no-dig-dns
```

```powershell
# Windows — the full stack minus dig-dns
$s = irm https://raw.githubusercontent.com/DIG-Network/dig-installer/main/install.ps1
& ([scriptblock]::Create($s)) --no-dig-dns
```

See [dig-dns](#dig-dns-local-dig-name-resolution) below for what the dig-dns
service wires up per OS.

### Also install the DIG Browser

The DIG Browser is a separate opt-in (it is a full desktop app, not part of the
default stack).

Add `--with-browser` to download the DIG Browser native installer for your OS:

```sh
curl -fsSL https://raw.githubusercontent.com/DIG-Network/dig-installer/main/install.sh | sh -s -- --with-browser
```

The bootstrap scripts just download the `dig-installer` binary for your machine
and run it; every flag after `--` (sh) / after the script (PowerShell) is passed
straight through to `dig-installer`.

---

## Direct use

Download the `dig-installer` binary for your OS/arch from the
[releases](https://github.com/DIG-Network/dig-installer/releases) and run it:

```sh
dig-installer                      # install the FULL DIG stack: digstore + dig-node + dig-dns
dig-installer --no-dig-node        # skip dig-node (still installs digstore + dig-dns)
dig-installer --no-dig-dns         # skip dig-dns (still installs digstore + dig-node)
dig-installer --no-dig-node --no-dig-dns   # just the digstore CLI
dig-installer --with-browser       # ALSO download the DIG Browser installer
dig-installer --dry-run            # show exactly what would happen, change nothing
dig-installer --dry-run --json     # the same, as a machine-readable plan
dig-installer --uninstall-dig-dns     # remove the dig-dns service + OS wiring this installer created
dig-installer --uninstall-dig-node    # remove the dig-node service + the dig.local hosts entry
dig-installer --uninstall-dig-updater # remove the auto-update beacon's daily scheduler registration
```

### Flags

| Flag | Default | Meaning |
|------|---------|---------|
| `--no-digstore` | off | Skip installing the digstore CLI (installed by default). |
| `--with-digstore` | on | Redundant explicit opt-in — digstore installs by default. |
| `--digstore-version <VER>` | latest | Install a specific digstore version (e.g. `0.6.0`). |
| _(no flag)_ | — | The **`digs`** alias binary (`digs <args>` ≡ `digstore <args>`) installs/uninstalls alongside `digstore` automatically — it follows the `--*-digstore*` flags above and has none of its own. |
| `--no-dig-node` | off | Skip the `dig-node` local node + service (installed by default). |
| `--with-dig-node` (alias `--service`) | on | Redundant explicit opt-in — dig-node installs + registers as a **boot-start** OS service (+ the `dig.local` hosts entry) by default. |
| `--no-service-start` | off | Install the service(s) but don't start them this run (still registered boot-start, so they come up on next boot). |
| `--dig-node-port <PORT>` | `9778` | Loopback port the dig-node service serves on (matches dig-node's own uncommon-high-port default — the sibling of the dig-wallet HTTP API's `9777`; `dig.local` stays on `127.0.0.2:80` regardless). |
| `--dig-node-version <VER>` | latest | Install a specific dig-node version. |
| `--no-open-firewall` | off | Opt out of opening the app-scoped inbound firewall rule for dig-node's peer-RPC port (opened by default when dig-node is installed; see [Firewall](#firewall-dig-nodes-peer-rpc-port) below). |
| `--open-firewall` | on | Redundant explicit opt-in — the firewall rule is opened by default. |
| `--force-reinstall` | off | Reinstall `digstore`/`dig-node`/`dig-dns` even if the [version-aware updater](#version-aware-updater) would otherwise skip them as already up to date. |
| `--uninstall-dig-node` | — | Remove the dig-node OS service, the `dig.local` hosts entry, and the firewall rule this installer created. Idempotent; does not touch the digstore/browser/relay/dig-dns installs. Standalone action — ignores every other flag except `--bin-dir`/`--dry-run`/`--json`. |
| `--no-dig-dns` | off | Skip `dig-dns` + its service (installed by default). |
| `--with-dig-dns` | on | Redundant explicit opt-in — dig-dns installs + registers as a **boot-start** OS service (local `*.dig` name resolution) + wires OS split-DNS/NRPT + the Chrome/Edge DoH policy, by default. |
| `--dig-dns-version <VER>` | latest | Install a specific dig-dns version. |
| `--dig-dns-node <URL>` | dig-dns's own ladder | Explicit dig-node endpoint dig-dns's gateway should use (forwarded as `dig-dns serve --node <URL>`). |
| `--uninstall-dig-dns` | — | Remove the dig-dns service + every OS artifact (service, split-DNS/NRPT rule, browser policy key) THIS installer created; leaves zero residue. Standalone action — ignores every other flag except `--dry-run`/`--json`. |
| `--no-auto-update` | off | Opt out of installing + registering the DIG auto-update beacon (installed by default; see [Auto-update beacon](#auto-update-beacon-dig-updater) below). |
| `--auto-update` | on | Redundant explicit opt-in — the auto-update beacon is installed by default. |
| `--dig-updater-version <VER>` | latest | Install a specific auto-update beacon version (also pins its `dig-updater-worker` sibling). |
| `--uninstall-dig-updater` | — | Remove the auto-update beacon's daily scheduler registration this installer created. Idempotent; does not remove the downloaded binaries or touch the digstore/browser/relay/dig-node/dig-dns installs. Standalone action — ignores every other flag except `--bin-dir`/`--dry-run`/`--json`. |
| `--with-browser` | off | Also download the DIG Browser native installer for this OS (opt-in). |
| `--browser-version <VER>` | latest | Install a specific DIG Browser version. |
| `--with-relay` | off | **Advanced (opt-in).** Also install the `dig-relay` NAT-traversal relay + register it as an OS service (run your own relay). Most users don't need this — nodes use `relay.dig.net` by default. |
| `--relay-port <PORT>` | `9450` | Relay WebSocket port the relay service serves on. |
| `--relay-health-port <PORT>` | `9451` | Relay HTTP `/health` port the relay service serves on. |
| `--relay-version <VER>` | latest | Install a specific dig-relay version. |
| `--bin-dir <DIR>` | per-user DIG bin dir | Where to place the binaries. |
| `--no-path` | off | Don't modify `PATH` (just place the binaries). |
| `--dry-run` | off | Print/resolve actions without downloading or changing anything. |
| `--json` | off | Emit a single structured JSON result to stdout (prose → stderr, no prompts). |
| `--help-json` | — | Print the full machine-readable invocation contract (commands, flags, exit codes). |

Default install location (`--bin-dir`):

- Windows: `%LOCALAPPDATA%\Programs\DIG\bin`
- macOS / Linux: `~/.dig/bin`

---

## What the installer does

1. **Resolve target** — detects OS/arch (`windows-x64`, `linux-x64`,
   `macos-arm64`, `macos-x64`).
2. **Resolve each component's asset** — for every selected component it fetches
   the latest GitHub release (or a pinned `--*-version`), reads the release's
   **actual asset list**, and picks the asset for this OS/arch by matching
   OS/arch tokens + the accepted file extension (raw binary for the CLI/node,
   `.exe`/`.dmg`/`.AppImage` for the browser). No single guessed filename, so a
   naming change in a producing repo doesn't break the installer.
3. **digstore CLI (+ its `digs` alias)** — downloads the resolved raw binary and
   writes it to the bin dir (executable bit set on unix), then does the same for
   `digs` — a real binary published in the SAME digstore release under its own
   asset stem (`digs-<ver>-<os_arch>[.exe]`) that behaves identically to
   `digstore`. `digs` has no flag of its own: it follows `--no-digstore`/
   `--with-digstore`/`--digstore-version` and shares digstore's bin dir, so no
   extra PATH entry is needed.
4. **PATH** — adds the bin dir to your user `PATH` (HKCU on Windows with a
   `WM_SETTINGCHANGE` broadcast; a profile `export PATH` line on unix). Idempotent.
5. **dig-node** *(by default; `--no-dig-node` to skip)* — downloads the
   `dig-node` binary the same way, then **delegates to dig-node's own `install`
   (+ `start`)** subcommands to register it as a **boot-start** (auto-start-on-
   boot), auto-restarting OS service (Windows SCM `start= auto` / systemd
   `enable` / launchd `RunAtLoad` — the installer does not reimplement it),
   best-effort writes the `dig.local` hosts entry, runs a **post-install
   resolve check** confirming the OS actually maps `dig.local` → `127.0.0.2`
   now, and finally a **post-install SERVICE health check** confirming the OS
   service manager reports the service (`net.dignetwork.dig-node`) as RUNNING —
   a bare listener on the port started by something else does NOT count as a
   pass (#493). Because this registers a service, the whole installer requires
   elevation up front (see the elevation note above); an un-elevated run is
   refused before any change. `--uninstall-dig-node` reverses it: removes the OS
   service (delegating to dig-node's own `uninstall`) and the hosts entry.
6. **dig-dns** *(by default; `--no-dig-dns` to skip)* — downloads the `dig-dns`
   binary, then **owns the full per-OS service + DNS/browser wiring itself**
   (unlike dig-node/dig-relay, dig-dns ships no `install`/`start` subcommands of
   its own): registers + starts it as a **boot-start** OS service (Windows SCM
   `start= auto` / systemd `enable` + `WantedBy=multi-user.target` / launchd
   `RunAtLoad`), wires OS split-DNS/NRPT, applies the Chrome/Edge DoH policy
   (never clobbering an existing org policy), then self-verifies with `dig-dns
   doctor` + `dig-dns pac` and prints the report — which resolution path(s) are
   live, the bound gateway port, the PAC URL, and a browser-fallback
   instruction. See [dig-dns](#dig-dns-local-dig-name-resolution) below for the
   full per-OS contract.
7. **Auto-update beacon** *(by default; `--no-auto-update` to skip)* —
   downloads the `dig-updater` binary and its unprivileged `dig-updater-worker`
   sibling (published in the same release), then **delegates to dig-updater's
   own `schedule install`** subcommand to register a daily OS-scheduled task/
   systemd timer/LaunchDaemon that checks for + installs new signed DIG
   releases automatically. See [Auto-update beacon](#auto-update-beacon-dig-updater)
   below. `--uninstall-dig-updater` reverses it: removes the scheduler
   registration (the downloaded binaries stay in place).
8. **DIG Browser** *(opt-in, with `--with-browser`)* — downloads the native
   installer for your OS into the bin dir; run it to finish.

Every download is integrity-checkable (SHA-256). `--dry-run` resolves and prints
every asset, URL, destination, and service command without touching the system
(`--dry-run --json` emits it as a side-effect-free plan).

---

## Version-aware updater

Re-running `dig-installer` is not a blind reinstall — for `digstore`/`dig-node`/`dig-dns`/
`dig-updater` it **detects** what's already at the destination (`<bin> --version`), **compares** it to the release
it just resolved, and **decides**: absent → install; an older (or unreadable) installed version →
update (replace it, reusing the same stop/write/start lifecycle above); already current → skip,
untouched. The decision is printed for every tracked component (`v0.14.0 → v0.15.0 (update)` /
`v0.15.0 (up to date)` / `not installed → install v0.15.0`) and recorded in `--json`'s
`components[].update_action`/`previous_version`. `--force-reinstall` overrides a skip and reinstalls
anyway. The GUI's Components screen shows the same Install/Update/Up-to-date status per component
before you click Install.

---

## `dig.local` (port-free local node)

When you install the dig-node service, the installer best-effort adds a hosts
entry so consumers (the DIG Browser, the extension) can reach your local node
**port-free** at `http://dig.local`:

```
127.0.0.2   dig.local
```

- It uses `127.0.0.2` (not `127.0.0.1`) so `dig.local` has its own loopback IP
  and never collides with anything else you run on `localhost`.
- The write is **idempotent** (skipped if a `dig.local` mapping already exists,
  on install OR re-install/upgrade — never duplicated), **reversible**
  (`--uninstall-dig-node` removes only the line this installer tagged, and the
  OS service itself), and **best-effort** — it needs elevation, and if it can't
  be written the install is **never aborted**: the node stays reachable at
  `localhost`, the failure is printed with a clear reason (never silent), and
  you can re-run elevated to add it.
- Hosts file: `%SystemRoot%\System32\drivers\etc\hosts` (Windows) / `/etc/hosts`.
- **Post-install resolve check** — after writing (or confirming) the entry,
  the installer asks the OS resolver whether `dig.local` actually maps to
  `127.0.0.2` right now (not just a re-read of its own write) and prints
  `dig.local resolve check: …` (pass) or a clear `FAILED` line with the reason
  (stale DNS-client cache, a hosts write that landed in the wrong file, …).
  Under `--json` this is `service.dig_local_resolves` (bool) +
  `service.dig_local_resolve_note` (detail).
- **Post-install health check** — once the service is started, the installer
  sends a JSON-RPC `rpc.discover` request (the standard OpenRPC
  self-description method every dig-node build answers) to
  `http://127.0.0.1:<port>/` and retries for up to ~5s (a freshly-started
  service needs a moment to bind its socket) before judging it not up. This
  proves the node is actually **answering RPC**, not just that the service
  registered and `dig.local` resolves. Prints `health check: …` (pass) or a
  clear `FAILED` line with the reason. Skipped (never a hard failure) on
  dry-run, with `--no-service-start`, or if the service failed to install.
  Under `--json` this is `service.health_checked` / `service.health_ok`
  (bools) + `service.health_note` (detail).

```sh
dig-installer --with-dig-node
#   Registering dig-node as an OS service (port 9778):
#     ✓ dig-node installed as an OS service and started
#     ✓ dig.local: 127.0.0.2 dig.local → /etc/hosts
#     ✓ dig.local resolve check: dig.local → 127.0.0.2
#     ✓ health check: rpc.discover on http://127.0.0.1:9778/ answered

dig-installer --uninstall-dig-node
#   Uninstalling the dig-node OS service:
#     ✓ dig-node service uninstalled
#   Removing the dig.local hosts entry:
#     ✓ removed dig.local from /etc/hosts
```

> The dig-node *dual-listener* that makes `dig.local` actually resolve to the
> node (`127.0.0.2:80` + `localhost:<port>` + a Host allowlist) is dig-node's
> own behaviour; this installer writes the hosts entry, registers/uninstalls
> the service, and runs the resolve + health checks.
>
> **Auto-start + auto-restart:** the registered service starts on boot on all
> three OSes (Windows SCM autostart / systemd `WantedBy=` enable / launchd
> `RunAtLoad`), and Linux (systemd `Restart=on-failure`) + macOS (launchd
> `KeepAlive`) already restart it if it crashes. Windows SCM restart-on-crash
> (recovery actions) is a known gap tracked upstream in dig-node-service — see
> [DIG-Network/dig_ecosystem#224](https://github.com/DIG-Network/dig_ecosystem/issues/224).

---

## Firewall (dig-node's peer-RPC port)

By default, installing dig-node also opens an inbound firewall rule scoped to the dig-node
executable ONLY, on its peer-RPC port (`DIG_PEER_PORT`, default `9444` — dig-node's only
non-loopback listener; every other surface, including the `--dig-node-port` RPC port above, stays
loopback-only and is never opened). This makes a freshly-installed node reachable for direct peer
connections immediately; declining it (`--no-open-firewall`) is always safe — the node still works
via the `dig-relay` fallback.

```sh
dig-installer --with-dig-node
#   Opening the firewall for dig-node's peer-RPC port:
#     ✓ opened inbound TCP 9444 for C:\Users\you\.dig\bin\dig-node.exe (rule "DIG Network Node (P2P)", IPv4+IPv6)

dig-installer --uninstall-dig-node
#   Removing the dig-node firewall rule (#424):
#     ✓ removed the "DIG Network Node (P2P)" firewall rule
```

| OS | What happens |
|----|--------------|
| Windows | A single named `netsh advfirewall firewall` rule (`name="DIG Network Node (P2P)"`), scoped to the installed `dig-node.exe`, `protocol=TCP`, on the port above — covering both IPv4 and IPv6 (no `remoteip=` restriction). |
| macOS | Adds the executable to the Application Firewall (ALF) exception list — but ONLY if ALF is actually turned on; if it's off, every inbound connection is already unfiltered, so nothing is done. |
| Linux | **Never applied automatically** (too many competing firewall managers to safely automate). If you have a firewall active, open the port yourself: `sudo ufw allow 9444/tcp` (or the equivalent for `firewalld`/`iptables`). |

`--uninstall-dig-node` removes the rule alongside the OS service and the `dig.local` hosts entry —
idempotent (a declined/already-absent rule is a clean no-op).

---

## Auto-update beacon (`dig-updater`)

By default, the installer also installs [`dig-updater`](https://github.com/DIG-Network/dig-updater)
— the DIG auto-update **beacon** — plus its unprivileged `dig-updater-worker` sibling (published in
the same release), and asks the freshly-installed `dig-updater` to register its own **daily
scheduler artifact**: a Windows Scheduled Task, a systemd timer, or a macOS LaunchDaemon that wakes
once a day, checks the signed DIG release feed, and installs any new version of the DIG stack
automatically. The installer never hand-rolls the scheduler — it delegates to `dig-updater schedule
install`, the same "drive the component's own subcommands" pattern used for dig-node/dig-relay's OS
service registration above.

```sh
dig-installer --dig-updater-version 0.6.0
#   Installing the DIG auto-update beacon:
#     dig-updater 0.6.0 (dig-updater-0.6.0-windows-x64.exe)
#   Installing the dig-updater-worker sibling (same release, published as a separate binary):
#     dig-updater-worker 0.6.0 (dig-updater-worker-0.6.0-windows-x64.exe)
#   Registering the beacon's daily update-check scheduler:
#     ✓ registered the daily update-check scheduler

dig-installer --uninstall-dig-updater
#   Removing the DIG auto-update beacon's daily scheduler:
#     ✓ removed the daily update-check scheduler
```

Declining the beacon (`--no-auto-update`) is always safe — DIG simply never auto-updates, and you
re-run the installer manually to pick up new versions. Registering a SYSTEM/root-run daily schedule
is itself a privileged operation, so — like dig-node/dig-dns/dig-relay's own service registration —
it requires the installer to run elevated; unlike the firewall rule/scheme handler above, a failed
beacon registration DOES make the overall install report "DIG is NOT ready" (`INSTALL_INCOMPLETE`).
`--uninstall-dig-updater` removes only the scheduler registration — it never deletes the downloaded
binaries or touches the digstore/dig-node/dig-dns/relay/browser installs.

---

## dig-dns (local `.dig` name resolution)

`--with-dig-dns` installs [`dig-dns`](https://github.com/DIG-Network/dig-dns) — the
local `*.dig` name resolver (a DNS responder + HTTP gateway) — and registers it as an
OS service so a browser can open `http://<storeId>.dig/…` directly. Its own README
(`https://github.com/DIG-Network/dig-dns#readme`) is the authoritative per-OS
contract; this installer implements it. The install is **elevated, idempotent** (safe
to re-run — it converges, never duplicates a rule/policy/service), and **fully
reversible** by `--uninstall-dig-dns`. It **never** edits `/etc/hosts` (`dig.local`
above is a separate, unrelated mechanism), never URL-rewrites, and never intercepts
TLS — dig-dns serves plain `http://` on its own dedicated loopback IP.

**Availability gate (task #234):** dig-dns is EPIC #174 and may ship no release
for some period. If `--with-dig-dns` is given and no matching release/asset can
be resolved, this component alone is skipped with a clear
`"dig-dns is not yet available"` note — every other selected component still
installs; the overall run does not fail. Re-run once a release is published.

### What gets installed per OS

| OS | Service | DNS/proxy wiring | Browser policy |
|----|---------|-------------------|-----------------|
| **macOS** | A **LaunchDaemon** (root, `KeepAlive`, logs to `/var/log/dig-dns.{out,err}.log`) runs `dig-dns serve`. A second, one-shot LaunchDaemon re-applies the `127.0.0.5` `lo0` alias at every boot (macOS does not persist `ifconfig` aliases across reboot). | `/etc/resolver/dig` → `nameserver 127.0.0.5` (macOS's per-TLD resolver mechanism). | A best-effort Chrome managed-preference plist (DoH off + built-in-resolver off) — written ONLY if no existing MDM-provisioned policy is detected; manual instructions are always also printed. |
| **Ubuntu / Linux** | A **systemd unit** runs `dig-dns serve` as a dedicated, unprivileged `dig-dns` user granted ONLY `CAP_NET_BIND_SERVICE` (`CapabilityBoundingSet`, `NoNewPrivileges=yes`), `Restart=always`. | The resolv.conf owner is detected and wired accordingly: a `systemd-resolved` `~dig` domain drop-in, OR a NetworkManager-dnsmasq `server=/dig/127.0.0.5` config. A plain (unmanaged) `resolv.conf` is left untouched — never blindly rewritten — relying on the PAC fallback (Path B) instead. | Chrome **and** Chromium managed-policy JSON files (uniquely named, merged alongside any existing admin policy — never overwrites one). |
| **Windows** | A **Windows Service** (admin-checked) registered to run `dig-dns.exe run-service` **directly** — dig-dns's own Service Control Protocol entrypoint, which reports `SERVICE_RUNNING` to the SCM immediately (no re-launching host shim; this is the fix for the field `1053` start-timeout). An explicit dig-node override is baked into the service environment as `DIG_NODE_URL`. | An **NRPT rule** (`Add-DnsClientNrptRule -Namespace .dig -NameServers 127.0.0.5`), added idempotently (never fights a pre-existing `.dig` rule). | Chrome **and** Edge HKLM policy (`DnsOverHttpsMode=off`, `BuiltInDnsClientEnabled=0`) — written ONLY under a key this installer created or already owns; a pre-existing org GPO is never touched. |

Every artifact this installer writes is tagged with a stable marker so a re-run is a
no-op (idempotent) and `--uninstall-dig-dns` removes ONLY what it created — a
pre-existing `.dig` NRPT rule, org browser policy, or resolv.conf config is never
touched. `127.0.0.5:53`/`:80` binding, the `:80` → `:8053` fallback (with the PAC
advertising the actual bound port), and the two independent resolution paths (OS
split-DNS vs. the PAC proxy) are all dig-dns's own runtime behaviour — see its README.

### Self-verification

After starting the service, the installer runs `dig-dns doctor` (+ `dig-dns pac`) and
prints: the per-check pass/fail/warn report, which resolution path(s) are live
(`dns` / `gateway`), the gateway's actually-bound port, the PAC URL, and a one-line
browser-fallback instruction:

```sh
dig-installer --with-dig-dns
#   ...
#   dig-dns doctor:
#     [PASS] Loopback IP is up: 127.0.0.5 is assigned
#     [PASS] HTTP gateway answers (Path B): answered on :80
#   live path(s): dns, gateway
#   gateway bound port: 80
#   PAC URL: http://127.0.0.5:80/.dig/proxy.pac
#   If a browser doesn't resolve .dig sites (e.g. it forces DNS-over-HTTPS), point its
#   proxy configuration at the PAC file: http://127.0.0.5:80/.dig/proxy.pac
```

### Uninstalling

```sh
dig-installer --uninstall-dig-dns            # remove the service + OS wiring, zero residue
dig-installer --uninstall-dig-dns --dry-run  # preview what would be removed
```

Stops + removes the OS service, the split-DNS/NRPT rule, and any browser policy key
this installer created. It does **not** remove the downloaded `dig-dns` binary or any
pre-existing org DNS/browser policy.

---

## Agent-friendly surfaces

`dig-installer` is scriptable for both humans and agents:

- **`--json`** — emits a single structured object to **stdout** (all human prose
  goes to **stderr**, no prompts/spinners). On success:
  `{"ok":true,"result":{schema_version,installer_version,target,dry_run,components:[…],path,service,relay,dns,beacon,installed:[…]}}`
  — `service` (present with `--with-dig-node`) carries
  `{installed,started,port,note,dig_local,dig_local_resolves,dig_local_resolve_note,health_checked,health_ok,health_note}` —
  `dig_local_resolves`/`dig_local_resolve_note` are the task-#140 post-install
  resolve check (whether the OS resolver actually maps `dig.local` →
  `127.0.0.2` right now); `health_checked`/`health_ok`/`health_note` are the
  task-#223 post-install RPC health check (whether `rpc.discover` actually
  answered on the service's loopback port). `dns` (present
  with `--with-dig-dns`) carries `{installed,started,needs_elevation,note,doctor,paths_live,bound_port,pac_url,fallback_instruction}`.
  `beacon` (present unless `--no-auto-update`, issue #514) carries
  `{applied,note}` — whether the daily scheduler registration succeeded.
  On failure: `{"ok":false,"error":{"code","exit_code","message","hint"}}`.
  `--uninstall-dig-dns --json` emits `{"ok":true,"result":{uninstalled,needs_elevation,note,residue_removed:[…]}}`
  standalone (it never touches the other components).
  `--uninstall-dig-node --json` emits `{"ok":true,"result":{uninstalled,dig_local_removed,note}}`
  standalone (never touches the digstore/browser/relay/dig-dns installs).
  `--uninstall-dig-updater --json` emits `{"ok":true,"result":{applied,note}}`
  standalone (never touches the downloaded binaries or the other components).
- **`--help-json`** — prints the full invocation contract (components, flags,
  supported targets, and the exit-code table) as JSON.
- **Stable error codes + exit codes** — every failure carries an `UPPER_SNAKE`
  `code` and a distinct exit code, so a script can branch on the failure class
  (and tell a recoverable "needs elevation" apart from a hard failure):

  | Exit | Code | Meaning |
  |------|------|---------|
  | 0 | `OK` | success |
  | 2 | `UNSUPPORTED_TARGET` | host OS/arch is not a supported DIG release target |
  | 3 | `ASSET_NOT_FOUND` | release or matching per-OS/arch asset not found |
  | 4 | `NETWORK` | network/HTTP error contacting GitHub or downloading |
  | 5 | `CHECKSUM_MISMATCH` | downloaded artifact failed its SHA-256 verification |
  | 6 | `PATH_UPDATE_FAILED` | could not update PATH (the binary was still placed) |
  | 7 | `SERVICE_NEEDS_ELEVATION` | dig-node service registration needs an elevated console |
  | 8 | `SERVICE_START_FAILED` | the dig-node/dig-relay service failed to install or start |
  | 9 | `IO` | failed to write a downloaded binary to disk |
  | 10 | `SERVICE_STOP_FAILED` | a running dig-node/dig-relay service failed to stop before its binary could be safely replaced |
  | 11 | `NOT_ELEVATED` | launched without elevation (Administrator/root) but the plan needs it — refused up front, no partial state (#492) |
  | 12 | `INSTALL_INCOMPLETE` | the run completed but is NOT ready: a selected component failed to install or its service is not running (#493) |

  (Usage errors from argument parsing return clap's own exit code 2.)

  **Stop-before-write, start-after-write (task #232):** before overwriting an
  already-installed dig-node/dig-relay binary, the installer checks
  `<bin> status --json` and, if it reports the service is currently serving,
  runs `<bin> stop` first — skip-when-absent/not-serving (no error); a stop
  FAILURE aborts that component's write (`SERVICE_STOP_FAILED`) rather than
  risk a half-written binary underneath a still-running service. After the
  binary is written, `install`+`start` run as before (an `install` failure
  alone — e.g. "already registered" — is tolerated so `start` still gets a
  chance to bring the new binary's service back up). See `SPEC.md` §2 for the
  full contract.

---

## Terminology

Following the ecosystem's canonical branding (see the superproject's `SYSTEM.md`
→ *Canonical terminology & branding*):

- **$DIG** — the network token.
- **DIGHUb** — the blind host (`hub.dig.net`).
- **dig-node** — the local DIG node (renamed from `dig-companion`); the
  standalone-server twin of the DIG Browser's in-process node.
- **dig-dns** — the local `*.dig` name resolver (a DNS responder + HTTP
  gateway) that lets a browser open `http://<storeId>.dig/…` directly, backed
  by a dig-node as its content source.
- **the beacon** (`dig-updater`) — the DIG auto-update service that checks
  daily for new signed releases and installs them automatically.

---

## GUI installer (`gui/`)

A Tauri-based desktop install **wizard** lives under `gui/` (migrated from
`digstore`), dark-themed by default (Welcome → License → **Components** →
Install → Done). It **embeds** a prebuilt `digstore` binary for an offline,
no-network first install of the CLI specifically. The release workflow builds
it on a tag by downloading the latest released `digstore` binary, staging it
(`gui/app/scripts/stage-binary.mjs --src <path>`), and running `tauri build`.

The Components step lists the SAME catalogue as the CLI (digstore + dig-node +
dig-dns + the auto-update beacon + dig-relay + DIG Browser — see `SPEC.md` §1),
every default-on component pre-selected so "install all" is the one-click
default path; deselect anything you don't want. digstore installs via the
embedded payload above; every other selected component is installed by the
wizard delegating to this repo's own
`dig_installer::run_report` — the exact same release-resolution/download/
service-lifecycle orchestration the CLI uses (see `SPEC.md` §2 for the
stop-before-write/start-after-write service lifecycle both surfaces share).

The CLI (`dig-installer`) remains the canonical universal entrypoint (it
powers the one-liner above and every `--with-*` flag); the GUI is the
brand-designed desktop wizard over the same underlying install engine.

---

## Releasing

Tag-driven (mirrors digstore / dig-node) — **do not hand-push a tag**. On
merge to `main`, `changelog-tag.yml` regenerates `CHANGELOG.md`, commits
`chore(release): vX.Y.Z`, and pushes that commit + the matching `vX.Y.Z` tag
(via `RELEASE_TOKEN`, so the push actually fires the tag-triggered workflow).
The pushed tag runs `release.yml`, which builds the `dig-installer` CLI for
every OS/arch **and** the GUI installers, and attaches them all to one GitHub
Release. See `runbooks/deployment.md` for the full trigger/verify checklist.

A push to `main` builds the CLI (no publish) so a broken build is caught before
the release tag is even created.

## Building from source

```sh
cargo build --release            # the dig-installer CLI
cargo test                       # unit tests (target/URL/PATH/service logic)
```

The CLI needs no special prerequisites. The GUI (`gui/app`) needs Node 20 + the
Tauri toolchain (and the platform webview deps on Linux).
```
