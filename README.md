# dig-installer

**The universal DIG installer — a thin shim.** One command resolves and installs
the latest DIG components for your OS/arch:

- the **digstore CLI** (the $DIG content tooling) — added to your `PATH`,
- the **dig-node** local node — installed + started as an OS service (Windows
  service / systemd / launchd), with a best-effort `127.0.0.2 dig.local` hosts
  entry so apps and the DIG Browser can reach it port-free at `http://dig.local`,
- the **dig-dns** local `*.dig` name resolver — installed + started as an OS
  service (Windows Service / macOS LaunchDaemon / Linux systemd), with the OS
  DNS/proxy wiring (split-DNS, NRPT, browser DoH policy) so a browser can open
  `http://<storeId>.dig/…` directly (see [dig-dns](#dig-dns-local-dig-name-resolution) below),
- the **dig-relay** *(advanced, optional)* — run your own NAT-traversal relay,
  installed + started as an OS service. Most users do **not** need this: every
  node already uses the canonical `relay.dig.net` out of the box.
- the **DIG Browser** — the native installer (`.exe` / `.dmg` / `.AppImage`)
  downloaded for you to run.

It **bundles nothing** and builds nothing. At install time it asks each
component's GitHub release for its **actual asset list** and picks the right
artifact for your OS/arch (resilient to naming differences across repos), then
downloads it. Sources:

- the **digstore CLI** from [`DIG-Network/digstore`](https://github.com/DIG-Network/digstore/releases)
- the **dig-node** local node from [`DIG-Network/dig-node`](https://github.com/DIG-Network/dig-node/releases)
  (formerly `dig-companion`)
- the **dig-dns** local resolver from [`DIG-Network/dig-dns`](https://github.com/DIG-Network/dig-dns/releases)
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

By default only the digstore CLI is installed; add `--with-dig-node` /
`--with-dig-dns` / `--with-browser` (and `--service`) to select more. This is
the canonical home of the DIG installer, migrated out of `digstore`.

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

Then open a **new** terminal and check it works:

```sh
digstore --version
```

### Also run a local DIG node

Add `--with-dig-node` to install the `dig-node` local node and register it as an
OS service (Windows service / systemd / launchd), started automatically. This
also best-effort writes a `127.0.0.2 dig.local` hosts entry so consumers reach
the node port-free at `http://dig.local` (falling back to `localhost`):

```sh
# macOS / Linux
curl -fsSL https://raw.githubusercontent.com/DIG-Network/dig-installer/main/install.sh | sh -s -- --with-dig-node
```

```powershell
# Windows — registering a service (and writing the hosts entry) needs an elevated console
$s = irm https://raw.githubusercontent.com/DIG-Network/dig-installer/main/install.ps1
& ([scriptblock]::Create($s)) --with-dig-node
```

### Also resolve `.dig` names in your browser

Add `--with-dig-dns` to install `dig-dns` and register it as an OS service (Windows
Service / macOS LaunchDaemon / Linux systemd), started automatically, with the OS
DNS/proxy wiring so `http://<storeId>.dig/…` loads directly in a browser. See
[dig-dns](#dig-dns-local-dig-name-resolution) below for what gets installed per OS:

```sh
# macOS / Linux — elevation (sudo) needed to register the service + wire split-DNS
curl -fsSL https://raw.githubusercontent.com/DIG-Network/dig-installer/main/install.sh | sh -s -- --with-dig-dns
```

```powershell
# Windows — registering the service + NRPT rule needs an elevated console
$s = irm https://raw.githubusercontent.com/DIG-Network/dig-installer/main/install.ps1
& ([scriptblock]::Create($s)) --with-dig-dns
```

### Also install the DIG Browser

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
dig-installer                      # install latest digstore CLI + add to PATH
dig-installer --with-dig-node      # ALSO install + start the dig-node service (+ dig.local)
dig-installer --with-dig-dns       # ALSO install + start dig-dns (local *.dig name resolution)
dig-installer --with-browser       # ALSO download the DIG Browser installer
dig-installer --dry-run            # show exactly what would happen, change nothing
dig-installer --dry-run --json     # the same, as a machine-readable plan
dig-installer --uninstall-dig-dns  # remove the dig-dns service + OS wiring this installer created
dig-installer --uninstall-dig-node # remove the dig-node service + the dig.local hosts entry
```

### Flags

| Flag | Default | Meaning |
|------|---------|---------|
| `--with-digstore` | on | Install the digstore CLI (default; explicit form of the always-on behaviour). |
| `--no-digstore` | off | Skip installing the digstore CLI. |
| `--digstore-version <VER>` | latest | Install a specific digstore version (e.g. `0.6.0`). |
| `--with-dig-node` (alias `--service`) | off | Also install the `dig-node` local node + register it as an OS service + write the `dig.local` hosts entry. |
| `--no-service-start` | off | Install the dig-node service but don't start it. |
| `--dig-node-port <PORT>` | `9778` | Loopback port the dig-node service serves on (matches dig-node's own uncommon-high-port default — the sibling of the dig-wallet HTTP API's `9777`; `dig.local` stays on `127.0.0.2:80` regardless). |
| `--dig-node-version <VER>` | latest | Install a specific dig-node version. |
| `--uninstall-dig-node` | — | Remove the dig-node OS service + the `dig.local` hosts entry this installer created. Idempotent; does not touch the digstore/browser/relay/dig-dns installs. Standalone action — ignores every other flag except `--bin-dir`/`--dry-run`/`--json`. |
| `--with-browser` | off | Also download the DIG Browser native installer for this OS. |
| `--browser-version <VER>` | latest | Install a specific DIG Browser version. |
| `--with-relay` | off | **Advanced.** Also install the `dig-relay` NAT-traversal relay + register it as an OS service (run your own relay). Most users don't need this — nodes use `relay.dig.net` by default. |
| `--relay-port <PORT>` | `9450` | Relay WebSocket port the relay service serves on. |
| `--relay-health-port <PORT>` | `9451` | Relay HTTP `/health` port the relay service serves on. |
| `--relay-version <VER>` | latest | Install a specific dig-relay version. |
| `--with-dig-dns` | off | Also install `dig-dns` + register it as an OS service (local `*.dig` name resolution) + wire OS split-DNS/NRPT + the Chrome/Edge DoH policy. |
| `--dig-dns-version <VER>` | latest | Install a specific dig-dns version. |
| `--dig-dns-node <URL>` | dig-dns's own ladder | Explicit dig-node endpoint dig-dns's gateway should use (forwarded as `dig-dns serve --node <URL>`). |
| `--uninstall-dig-dns` | — | Remove the dig-dns service + every OS artifact (service, split-DNS/NRPT rule, browser policy key) THIS installer created; leaves zero residue. Standalone action — ignores every other flag except `--dry-run`/`--json`. |
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
3. **digstore CLI** — downloads the resolved raw binary and writes it to the bin
   dir (executable bit set on unix).
4. **PATH** — adds the bin dir to your user `PATH` (HKCU on Windows with a
   `WM_SETTINGCHANGE` broadcast; a profile `export PATH` line on unix). Idempotent.
5. **dig-node** *(with `--with-dig-node`)* — downloads the `dig-node` binary the
   same way, then **delegates to dig-node's own `install` (+ `start`)**
   subcommands to register it as an OS service (Windows SCM / systemd / launchd —
   the installer does not reimplement it), best-effort writes the `dig.local`
   hosts entry, then runs a **post-install resolve check** confirming the OS
   actually maps `dig.local` → `127.0.0.2` now (see below). On Windows, service
   registration needs an elevated console — if you aren't elevated the
   installer surfaces a clear message and the digstore install still succeeds.
   `--uninstall-dig-node` reverses it: removes the OS service (delegating to
   dig-node's own `uninstall`) and the hosts entry.
6. **dig-dns** *(with `--with-dig-dns`)* — downloads the `dig-dns` binary, then
   **owns the full per-OS service + DNS/browser wiring itself** (unlike
   dig-node/dig-relay, dig-dns ships no `install`/`start` subcommands of its
   own): registers + starts the OS service, wires OS split-DNS/NRPT, applies the
   Chrome/Edge DoH policy (never clobbering an existing org policy), then
   self-verifies with `dig-dns doctor` + `dig-dns pac` and prints the report —
   which resolution path(s) are live, the bound gateway port, the PAC URL, and a
   browser-fallback instruction. See [dig-dns](#dig-dns-local-dig-name-resolution)
   below for the full per-OS contract.
7. **DIG Browser** *(with `--with-browser`)* — downloads the native installer
   for your OS into the bin dir; run it to finish.

Every download is integrity-checkable (SHA-256). `--dry-run` resolves and prints
every asset, URL, destination, and service command without touching the system
(`--dry-run --json` emits it as a side-effect-free plan).

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

```sh
dig-installer --with-dig-node
#   Registering dig-node as an OS service (port 9778):
#     ✓ dig-node installed as an OS service and started
#     ✓ dig.local: 127.0.0.2 dig.local → /etc/hosts
#     ✓ dig.local resolve check: dig.local → 127.0.0.2

dig-installer --uninstall-dig-node
#   Uninstalling the dig-node OS service:
#     ✓ dig-node service uninstalled
#   Removing the dig.local hosts entry:
#     ✓ removed dig.local from /etc/hosts
```

> The dig-node *dual-listener* that makes `dig.local` actually resolve to the
> node (`127.0.0.2:80` + `localhost:<port>` + a Host allowlist) is dig-node's
> own behaviour; this installer writes the hosts entry, registers/uninstalls
> the service, and runs the resolve check.

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

### What gets installed per OS

| OS | Service | DNS/proxy wiring | Browser policy |
|----|---------|-------------------|-----------------|
| **macOS** | A **LaunchDaemon** (root, `KeepAlive`, logs to `/var/log/dig-dns.{out,err}.log`) runs `dig-dns serve`. A second, one-shot LaunchDaemon re-applies the `127.0.0.5` `lo0` alias at every boot (macOS does not persist `ifconfig` aliases across reboot). | `/etc/resolver/dig` → `nameserver 127.0.0.5` (macOS's per-TLD resolver mechanism). | A best-effort Chrome managed-preference plist (DoH off + built-in-resolver off) — written ONLY if no existing MDM-provisioned policy is detected; manual instructions are always also printed. |
| **Ubuntu / Linux** | A **systemd unit** runs `dig-dns serve` as a dedicated, unprivileged `dig-dns` user granted ONLY `CAP_NET_BIND_SERVICE` (`CapabilityBoundingSet`, `NoNewPrivileges=yes`), `Restart=always`. | The resolv.conf owner is detected and wired accordingly: a `systemd-resolved` `~dig` domain drop-in, OR a NetworkManager-dnsmasq `server=/dig/127.0.0.5` config. A plain (unmanaged) `resolv.conf` is left untouched — never blindly rewritten — relying on the PAC fallback (Path B) instead. | Chrome **and** Chromium managed-policy JSON files (uniquely named, merged alongside any existing admin policy — never overwrites one). |
| **Windows** | A **Windows Service** (admin-checked; the SCM launches dig-installer's own persisted binary via a hidden `run-dig-dns-service` entrypoint, which spawns `dig-dns serve` as a supervised child — dig-dns itself has no Windows-service-protocol entrypoint). | An **NRPT rule** (`Add-DnsClientNrptRule -Namespace .dig -NameServers 127.0.0.5`), added idempotently (never fights a pre-existing `.dig` rule). | Chrome **and** Edge HKLM policy (`DnsOverHttpsMode=off`, `BuiltInDnsClientEnabled=0`) — written ONLY under a key this installer created or already owns; a pre-existing org GPO is never touched. |

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
  `{"ok":true,"result":{schema_version,installer_version,target,dry_run,components:[…],path,service,relay,dns,installed:[…]}}`
  — `service` (present with `--with-dig-node`) carries
  `{installed,started,port,note,dig_local,dig_local_resolves,dig_local_resolve_note}` —
  the last two are the task-#140 post-install resolve check (whether the OS
  resolver actually maps `dig.local` → `127.0.0.2` right now). `dns` (present
  with `--with-dig-dns`) carries `{installed,started,needs_elevation,note,doctor,paths_live,bound_port,pac_url,fallback_instruction}`.
  On failure: `{"ok":false,"error":{"code","exit_code","message","hint"}}`.
  `--uninstall-dig-dns --json` emits `{"ok":true,"result":{uninstalled,needs_elevation,note,residue_removed:[…]}}`
  standalone (it never touches the other components).
  `--uninstall-dig-node --json` emits `{"ok":true,"result":{uninstalled,dig_local_removed,note}}`
  standalone (never touches the digstore/browser/relay/dig-dns installs).
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
  | 8 | `SERVICE_START_FAILED` | the dig-node service failed to install or start |
  | 9 | `IO` | failed to write a downloaded binary to disk |

  (Usage errors from argument parsing return clap's own exit code 2.)

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

---

## GUI installer (`gui/`)

A Tauri-based desktop install **wizard** lives under `gui/` (migrated from
`digstore`). It is the polished, brand-designed single-file installer
(`DigStore-Setup-*.exe` / `*.dmg` / `*.AppImage`) that **embeds** a prebuilt
`digstore` binary for an offline, no-network first install. The release workflow
builds it on a tag by downloading the latest released `digstore` binary, staging
it (`gui/app/scripts/stage-binary.mjs --src <path>`), and running `tauri build`.

The CLI (`dig-installer`) is the canonical universal entrypoint (it powers the
one-liner above and supports `--with-dig-node`); the GUI is the friendly desktop
experience for the digstore CLI specifically.

---

## Releasing

Tag-driven (mirrors digstore / dig-node). On a pushed `v*` tag, CI builds the
`dig-installer` CLI for every OS/arch **and** the GUI installers, and attaches
them all to one GitHub Release:

```sh
git tag vX.Y.Z
git push origin vX.Y.Z
```

A push to `main` builds the CLI (no publish) so a broken build is caught before
tagging.

## Building from source

```sh
cargo build --release            # the dig-installer CLI
cargo test                       # unit tests (target/URL/PATH/service logic)
```

The CLI needs no special prerequisites. The GUI (`gui/app`) needs Node 20 + the
Tauri toolchain (and the platform webview deps on Linux).
```
