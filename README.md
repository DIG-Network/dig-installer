# dig-installer

**The universal DIG installer.** One command installs the **digstore CLI** (the
$DIG content tooling) for your OS and adds it to your `PATH` — and, optionally,
installs the **dig-node** local node as an OS service so apps and the DIG Browser
can resolve `chia://` content through your own machine.

It does **not** build anything itself. It downloads the official, released
binaries from the DIG-Network GitHub releases:

- the **digstore CLI** from [`DIG-Network/digstore`](https://github.com/DIG-Network/digstore/releases)
- the **dig-node** local node from [`DIG-Network/dig-node`](https://github.com/DIG-Network/dig-node/releases)
  (formerly `dig-companion`)

This is the canonical home of the DIG installer, migrated out of `digstore`.

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
OS service (Windows service / systemd / launchd), started automatically:

```sh
# macOS / Linux
curl -fsSL https://raw.githubusercontent.com/DIG-Network/dig-installer/main/install.sh | sh -s -- --with-dig-node
```

```powershell
# Windows — registering a service needs an elevated console
$s = irm https://raw.githubusercontent.com/DIG-Network/dig-installer/main/install.ps1
& ([scriptblock]::Create($s)) --with-dig-node
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
dig-installer --with-dig-node      # ALSO install + start the dig-node service
dig-installer --dry-run            # show exactly what would happen, change nothing
```

### Flags

| Flag | Default | Meaning |
|------|---------|---------|
| `--with-dig-node` | off | Also install the `dig-node` local node and register it as an OS service. |
| `--service` *(implied by `--with-dig-node`)* | — | The dig-node service is installed and started by default; see `--no-service-start`. |
| `--no-service-start` | off | Install the dig-node service but don't start it. |
| `--dig-node-port <PORT>` | `8080` | Loopback port the dig-node service serves on. |
| `--digstore-version <VER>` | latest | Install a specific digstore version (e.g. `0.6.0`). |
| `--dig-node-version <VER>` | latest | Install a specific dig-node version. |
| `--bin-dir <DIR>` | per-user DIG bin dir | Where to place the binaries. |
| `--no-path` | off | Don't modify `PATH` (just place the binaries). |
| `--dry-run` | off | Print actions without downloading or changing anything. |

Default install location (`--bin-dir`):

- Windows: `%LOCALAPPDATA%\Programs\DIG\bin`
- macOS / Linux: `~/.dig/bin`

---

## What the installer does

1. **Resolve target** — detects OS/arch (`windows-x64`, `linux-x64`,
   `macos-arm64`, `macos-x64`).
2. **digstore CLI** — resolves the version (latest release, or `--digstore-version`),
   downloads the matching `digstore-<ver>-<os_arch>[.exe]` release asset, and
   writes it to the bin dir (executable bit set on unix).
3. **PATH** — adds the bin dir to your user `PATH` (HKCU on Windows with a
   `WM_SETTINGCHANGE` broadcast; a profile `export PATH` line on unix). Idempotent.
4. **dig-node** *(with `--with-dig-node`)* — downloads the `dig-node` binary the
   same way, then **delegates to dig-node's own `install` (+ `start`)**
   subcommands to register it as an OS service. dig-node already implements
   Windows SCM / systemd / launchd registration (via the `service-manager`
   crate); the installer does not reimplement it. On Windows, service
   registration needs an elevated console — dig-node prints a clear message if
   you aren't elevated, and the digstore install still succeeds.

`--dry-run` prints every URL, destination, and service command without touching
the system — useful to see exactly what will be fetched.

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
