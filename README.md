# dig-installer

**The universal DIG installer — a thin shim.** One command resolves and installs
the latest DIG components for your OS/arch:

- the **digstore CLI** (the $DIG content tooling) — added to your `PATH`,
- the **dig-node** local node — installed + started as an OS service (Windows
  service / systemd / launchd), with a best-effort `127.0.0.2 dig.local` hosts
  entry so apps and the DIG Browser can reach it port-free at `http://dig.local`,
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
- the **dig-relay** from [`DIG-Network/dig-relay`](https://github.com/DIG-Network/dig-relay/releases)
- the **DIG Browser** from [`DIG-Network/DIG_Browser`](https://github.com/DIG-Network/DIG_Browser/releases)

By default only the digstore CLI is installed; add `--with-dig-node` /
`--with-browser` (and `--service`) to select more. This is the canonical home of
the DIG installer, migrated out of `digstore`.

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
dig-installer --with-browser       # ALSO download the DIG Browser installer
dig-installer --dry-run            # show exactly what would happen, change nothing
dig-installer --dry-run --json     # the same, as a machine-readable plan
```

### Flags

| Flag | Default | Meaning |
|------|---------|---------|
| `--with-digstore` | on | Install the digstore CLI (default; explicit form of the always-on behaviour). |
| `--no-digstore` | off | Skip installing the digstore CLI. |
| `--digstore-version <VER>` | latest | Install a specific digstore version (e.g. `0.6.0`). |
| `--with-dig-node` (alias `--service`) | off | Also install the `dig-node` local node + register it as an OS service + write the `dig.local` hosts entry. |
| `--no-service-start` | off | Install the dig-node service but don't start it. |
| `--dig-node-port <PORT>` | `8080` | Loopback port the dig-node service serves on. |
| `--dig-node-version <VER>` | latest | Install a specific dig-node version. |
| `--with-browser` | off | Also download the DIG Browser native installer for this OS. |
| `--browser-version <VER>` | latest | Install a specific DIG Browser version. |
| `--with-relay` | off | **Advanced.** Also install the `dig-relay` NAT-traversal relay + register it as an OS service (run your own relay). Most users don't need this — nodes use `relay.dig.net` by default. |
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
3. **digstore CLI** — downloads the resolved raw binary and writes it to the bin
   dir (executable bit set on unix).
4. **PATH** — adds the bin dir to your user `PATH` (HKCU on Windows with a
   `WM_SETTINGCHANGE` broadcast; a profile `export PATH` line on unix). Idempotent.
5. **dig-node** *(with `--with-dig-node`)* — downloads the `dig-node` binary the
   same way, then **delegates to dig-node's own `install` (+ `start`)**
   subcommands to register it as an OS service (Windows SCM / systemd / launchd —
   the installer does not reimplement it), and best-effort writes the `dig.local`
   hosts entry (see below). On Windows, service registration needs an elevated
   console — if you aren't elevated the installer surfaces a clear message and
   the digstore install still succeeds.
6. **DIG Browser** *(with `--with-browser`)* — downloads the native installer
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
- The write is **idempotent** (skipped if a `dig.local` mapping already exists),
  **reversible** (an uninstall removes only the line this installer tagged), and
  **best-effort** — it needs elevation, and if it can't be written the install
  is **never aborted**: the node stays reachable at `localhost` and you can
  re-run elevated to add it.
- Hosts file: `%SystemRoot%\System32\drivers\etc\hosts` (Windows) / `/etc/hosts`.

> The dig-node *dual-listener* that makes `dig.local` actually resolve to the
> node (`127.0.0.2:80` + `localhost:<port>` + a Host allowlist) is a separate
> dig-node change; this installer only writes the hosts entry.

---

## Agent-friendly surfaces

`dig-installer` is scriptable for both humans and agents:

- **`--json`** — emits a single structured object to **stdout** (all human prose
  goes to **stderr**, no prompts/spinners). On success:
  `{"ok":true,"result":{schema_version,installer_version,target,dry_run,components:[…],path,service,installed:[…]}}`.
  On failure: `{"ok":false,"error":{"code","exit_code","message","hint"}}`.
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
