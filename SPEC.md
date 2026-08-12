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
service, the `dig-app` identity agent, the `dig-dns` service, and the `dig-updater` auto-update
beacon are ALL installed by default (a bare `dig-installer` with no flags installs all five;
`InstallPlan::default()` encodes this). `dig-node` and `dig-dns` are registered as **boot-start** OS
services (§2.1); `dig-updater` registers its own **daily scheduler artifact** (§1.5); `dig-app` is
registered for **per-user login autostart** (§1.11) — it is a user-session agent, never a service.
Opt out of any of the five with the matching `--no-<component>` flag. `dig-relay` (advanced, run-your-own-relay) and the DIG Browser stay
opt-in.

| id         | repo                          | kind                              | CLI flag(s)                          | Selected in the GUI wizard by default |
|------------|-------------------------------|------------------------------------|---------------------------------------|----------------------------------------|
| `digstore` | `DIG-Network/digstore`        | raw binary, added to PATH          | on by default; `--no-digstore` opts out; `--with-digstore` (redundant, symmetry) | always (required, no checkbox) |
| `digs`     | `DIG-Network/digstore` (alias, issue #434) | raw binary, added to PATH (same bin dir as `digstore`) | NO separate flag — follows `digstore`'s `--no-digstore`/`--with-digstore`/`--digstore-version` | follows `digstore` |
| `dig-node` | `DIG-Network/dig-node`        | raw binary + boot-start OS service + `dig.local` hosts entry | on by default; `--no-dig-node` opts out; `--with-dig-node`/`--service` (redundant) | yes |
| `dign`     | `DIG-Network/dig-node` (alias, issue #548) | raw binary, added to PATH (same bin dir as `dig-node`) | NO separate flag — follows `dig-node`'s `--no-dig-node`/`--with-dig-node`/`--dig-node-version` | follows `dig-node` |
| `dig-app`  | `DIG-Network/dig-app`         | raw binary, added to PATH + **per-user login autostart** (§1.11) — never a machine-wide service | on by default; `--no-dig-app` opts out; `--with-dig-app` (redundant); `--no-dig-app-autostart` keeps the binary but skips the login registration | yes |
| `dig-dns`  | `DIG-Network/dig-dns`         | raw binary + boot-start OS service + split-DNS/NRPT + browser DoH policy | on by default; `--no-dig-dns` opts out; `--with-dig-dns` (redundant) | yes |
| `digd`     | `DIG-Network/dig-dns` (alias, issue #548) | raw binary, added to PATH (same bin dir as `dig-dns`) | NO separate flag — follows `dig-dns`'s `--no-dig-dns`/`--with-dig-dns`/`--dig-dns-version` | follows `dig-dns` |
| `dig-updater` | `DIG-Network/dig-updater`  | raw binary + a daily OS-scheduled task/timer/LaunchDaemon (issue #514, §1.5) | on by default; `--no-auto-update` opts out; `--auto-update` (redundant) | yes, as the "Keep DIG up to date automatically" option |
| `dig-updater-worker` | `DIG-Network/dig-updater` (alias, issue #514) | raw binary, added to PATH (same bin dir as `dig-updater`) | NO separate flag — follows `dig-updater`'s `--no-auto-update`/`--auto-update`/`--dig-updater-version` | follows `dig-updater` |
| `extension`| `DIG-Network/dig-chrome-extension` | managed browser extension, force-installed via each browser's `ExtensionInstallForcelist` policy (#602/#612) | (GUI) on by default; selecting it reveals the Browsers step (§1.8) | yes (#611) |
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

**Transient network failures are retried (dig_ecosystem#2784).** An install is a chain of GitHub
requests and ANY failure aborts it and rolls back every completed step, so a single self-healing
blip — a dropped TLS handshake, a 502 from `api.github.com`, a truncated body — MUST NOT fail an
install. Every release lookup and every asset download makes at most **3 attempts**, pausing 500 ms
before the first retry and doubling thereafter. Only failures that could plausibly answer
differently are retried: transport-level errors (DNS, connect, TLS handshake, dropped connection),
HTTP **429**, and HTTP **5xx**. Every other status is a real answer and is reported at once — in
particular a **404** stays a single request, because `download::latest_release` reads it as "no
published release" and falls back to the releases list, and **401** is a rejected credential.
**403** is treated differently by path: on the unauthenticated asset-download path
(`fetch_bytes_retrying`) a 403 is retried, because GitHub returns 403 for anonymous rate-limit and
abuse-detection trips on `releases/download`, which are transient; on the authenticated API path
(`get_text_with_token_retrying` with a non-empty token) a 403 is a rejected or exhausted token and
is not retried. See `download::with_retry` and `download::classify`.

### 1.1 First-class alias binaries (`digs`, `dign`, `digd`)

Three components are real installed binaries, not shell aliases, that behave IDENTICALLY to a
primary component (same subcommands/flags/`--json`/help): `digs` ↔ `digstore` (issue #434), `dign`
↔ `dig-node`, and `digd` ↔ `dig-dns` (both issue #548). Each is published in the **SAME** GitHub
release as its primary, under its own asset stem (`digs-<ver>-<os_arch>[.exe]` /
`dign-<ver>-<os_arch>[.exe]` / `digd-<ver>-<os_arch>[.exe]` — byte-for-byte the same shape as the
primary's own `<stem>-<ver>-<os_arch>[.exe]`) — resolved via the identical asset matcher
(`src/asset.rs::select_asset`), parameterized on the alias's own stem instead of the primary's.

Every alias has **no CLI flag of its own**: it installs/uninstalls exactly when its primary does,
pinned to the SAME version (the primary's own `--<primary>-version` flag threads through to both),
and is written to the SAME bin dir — so no separate PATH entry is needed. Resolution order in
`run_report_with`: each primary resolves and downloads first, then its alias, immediately
afterward, both gated by the primary's own `with_<primary>` flag. None of the three aliases is
update-tracked (§7.3) — each always re-downloads fresh alongside its primary.

`dign` additionally gates its OWN resolution failure gracefully (logged, not fatal, distinct from
`digs`/`digd`): dig-node has a pre-rename `dig-companion` legacy-repo fallback (`resolve_dig_node`
in `src/lib.rs` — the renamed `DIG-Network/dig-node` repo having no release falls back to the
original `DIG-Network/dig-companion` repo) that `Repo::dign()` does not share (it always targets
the modern `DIG-Network/dig-node` repo), so a dig-node install that fell back to the legacy repo
resolves dig-node itself successfully while having no `dign` asset to find. That must never sink
the otherwise-successful install — `digd` needs no equivalent gate, since it resolves against the
identical repo + version pin as `dig-dns` itself with no such divergence.

### 1.11 dig-app — the per-user identity agent + login autostart (#912)

`dig-app` is the USER-FACING half of the node/app split (`SYSTEM.md` → dig-node ⇄ dig-app, epic
#908): the dig-node engine is identity-agnostic, and `dig-app` is the identity — the tray /
menu-bar agent that holds the user's keys and answers the app-sign channel. The installer therefore
treats it unlike every daemon in this catalogue:

- **Placed like a user CLI.** Resolved as an `AssetKind::RawBinary` from `DIG-Network/dig-app`
  (asset stem `dig-app-<ver>-<os>-<arch>[.exe]`, produced by dig-app's reusable
  `build-binaries.yml` for `windows-x64` / `linux-x64` / `macos-arm64` / `macos-x64`), written under
  the canonical `dig-app` exe name into the same bin dir as the other user CLIs, and covered by the
  PATH wiring — so `dig-app` resolves by bare name from a fresh shell.
- **NOT a privileged component.** `paths::is_privileged_component` MUST NOT classify `dig-app` as
  privileged on unix: it is executed by the logged-in user, not by a service manager, so it stays in
  the elevation-free user bin dir and a `dig-app`-only install requires no elevation on unix.
  (On Windows the whole stack shares the protected root, §1.6.)
- **Variant-aware, loadability-driven selection (#1774/#1753).** dig-app publishes TWO Linux builds
  under the SAME `linux-x64` slug — the default GTK-linked `tray` build (`dig-app-<ver>-linux-x64`)
  and a GTK-less `headless` build (`dig-app-<ver>-linux-x64-headless`). Because both match the slug,
  the plain `select_asset` shortest-name tiebreak would always hand a headless server the GTK build,
  which dies inside `ld.so` (`libgtk-3.so.0` absent) before `main`. So `dig-app` is resolved through
  `asset::select_loadable_variant`, which orders the matched builds **tray → headless** and picks the
  first the host can actually LOAD. Loadability is decided by the shared
  `dig_release_resolver::loadability` contract — the SAME crate dig-updater's beacon selects with, so
  the install-time and update-time verdicts are byte-identical — by PARSING each candidate's ELF
  (`inspect_artifact`), never by executing it: running a dig-app candidate under the elevated installer
  could seal a master seed. The three-valued verdict is asymmetric: only an `Unloadable` build is
  skipped; a `Loadable` build is taken immediately; an `Indeterminate` build (a non-Linux host, a
  musl box, an unparseable image) is taken permissively when no build proves loadable. Every build
  `Unloadable` → the installer places NOTHING for dig-app and records `refused`. `--json`
  surfaces `selected_variant` (`tray`/`headless`), `loadable`, and `refused` per component.
- **Registered for autostart, never as a service.** `src/autostart.rs` writes ONE per-user,
  unelevated artifact per OS:

  | OS | mechanism (`InstallReport.autostart.mechanism`) | artifact |
  |----|-----------------------------------------------|----------|
  | Windows | `run-key` | `HKCU\Software\Microsoft\Windows\CurrentVersion\Run` value `DIG App` = the QUOTED dig-app path |
  | macOS | `launch-agent` | `~/Library/LaunchAgents/net.dig.dig-app.plist` (`RunAtLoad` + `KeepAlive`) |
  | Linux | `xdg-autostart` | `$XDG_CONFIG_HOME/autostart/dig-app.desktop` (`Type=Application`, `Exec=<dig-app path>`, `X-GNOME-Autostart-enabled=true`, `Hidden=false`; `$XDG_CONFIG_HOME` defaults to `~/.config`) |

  `HKCU`, never `HKLM`: a machine-wide Run entry would launch one user's identity agent in every
  account on the machine. The Windows command string is quoted, because the default install root
  (`%ProgramFiles%\DIG\bin`) contains a space and an unquoted Run value would never start.
  The Linux artifact MUST be an XDG autostart desktop entry, NOT a systemd user unit. A desktop
  session reads `$XDG_CONFIG_HOME/autostart/*.desktop` at login with no `enable` step, no session bus
  and no privilege, so the installer completes the registration itself. A systemd **user** unit
  cannot be completed by the installer: `systemctl --user enable` requires the TARGET user's session
  bus, which an elevated install does not have (root has none at all), so a written-but-never-enabled
  unit is INERT and is not autostart. An install MUST NOT discharge this obligation by printing a
  command for the user to run.

  An install MUST REMOVE the systemd user unit earlier versions wrote
  (`$XDG_CONFIG_HOME/systemd/user/dig-app.service`), on both install and uninstall: the two
  mechanisms are independent, so a user who ever ran `systemctl --user enable dig-app.service` would
  otherwise get TWO agents at the next login. Failure to remove it is REPORTED, never fatal.

- **Headless hosts are SKIPPED, and say so.** The disposition is
  `svcscope::agent_disposition(os, headless, target_user_known)` and appears verbatim on
  `InstallReport.autostart.disposition`:

  | disposition | when | behaviour |
  |---|---|---|
  | `register` | a graphical session, and a resolvable target user | write the artifact above |
  | `skip-headless` | no graphical session on this host | write NOTHING; report why. MUST NOT enable `loginctl` linger or otherwise force a GUI agent onto a server |
  | `skip-no-target-user` | elevated on unix with no resolvable invoking account (§1.5a) | write NOTHING; report LOUDLY — registering into root's own scope is the §1.5a inversion |

  Windows never reports `skip-no-target-user`: `HKCU` addresses the account this process runs as, so
  a target user is always known.

  `is_headless(os, facts)` MUST err toward REGISTERING, because the two mistakes are not symmetric —
  a wrong "headless" silently denies a desktop user the agent they installed, while a wrong
  "graphical" leaves one inert file no session reads. `true` therefore requires positive evidence:
  Linux — no `DISPLAY`/`WAYLAND_DISPLAY`/graphical `XDG_SESSION_TYPE` **and** no desktop session
  installed on the host at all (so a `sudo` install on a workstation whose `DISPLAY` was not
  forwarded is NOT headless); macOS — no Aqua session infrastructure; Windows — no interactive window
  station (a Session-0/service context).

  A skipped autostart does not gate `ready` (§4.2), and the node/service side is unaffected.
- **The macOS + Linux artifacts are BYTE-IDENTICAL to dig-app's own renderers**
  (`dig_app::autostart::{macos,linux}`, which likewise use the shared `net.dig.dig-app` label);
  dig-app's module documentation assigns Windows autostart to this installer. dig-app exposes those
  renderers as a library only — its binary has no subcommands — so unlike `dig-node install` there is
  nothing to delegate to, and the templates are reproduced here under conformance tests that fail on
  any drift. Should dig-app ever grow an `autostart` subcommand, this installer MUST delegate to it
  and retire the local copies.
- **Autostart is declinable and best-effort.** `--no-dig-app-autostart` installs the binary without
  registering it. A registration FAILURE never fails the install: it is recorded on
  `InstallReport.autostart` with `registered: false` and a note telling the user dig-app is installed
  and can be launched manually. Autostart does not gate `ready` (§4.2).
- **Availability-gated like `dign`.** dig-app publishes nightly pre-releases ahead of its first
  stable `vX.Y.Z`; release lookup already falls back from `/releases/latest` to the newest
  pre-release. A release carrying no asset for the host OS/arch (an `ASSET_NOT_FOUND`-classified
  lookup) is logged and SKIPPED — the rest of the stack still installs.
- **`dign` is unaffected.** dig-app's release also publishes a `dign` asset (the #908 U7 CLI
  migration), but `Repo::dign()` continues to resolve `dign` from the **dig-node** release: the
  `chia://` scheme handler is wired against `dign open` (§1.3), so the binary answering every clicked
  link MUST NOT change as a side effect of shipping dig-app. Resolving `dig-app` from a release
  containing both stems is safe because `select_asset` prefers the canonical-stem match.
- **Uninstalled with the stack.** `dig-app` is in `uninstall::COMPONENT_STEMS`, and the autostart
  artifact is removed by `autostart::deregister` (idempotent — an already-absent artifact is a clean
  success), so no removed install leaves an agent launching at every login. A mid-install failure
  reverses the registration through `InstallAction::AutostartRegistered` (§3.11).

### 1.11a dig-app — starting it when the install completes (#1831)

An install that selects `dig-app` MUST START it before finishing. Registering a login autostart is NOT
sufficient: it makes the agent appear at the user's *next* login, so the observable outcome of a
successful install is an empty system tray.

- **The launch MUST run as the interactive user, never with the installer's authority.** The GUI
  installer is `requireAdministrator` (§1.9) and `dig-app` is a per-user custody surface, so a launch
  that inherits elevation seals account state at an integrity level the normal-integrity login autostart
  cannot read back. On Windows the launched process MUST hold the MEDIUM integrity SID
  (`S-1-16-8192`); a process at `S-1-16-12288` is a FAILURE of this requirement even though a tray icon
  appears. Conformance is measured on the launched process's own token, never inferred from the launch
  returning.
  - A **direct child** of the elevated installer inherits `S-1-16-12288` and MUST NOT be used.
  - `Shell.Application` **`ShellExecute` MUST NOT be used**: the object is instantiated inside the
    elevated process and dispatches in that process's context, so it also yields `S-1-16-12288`.
  - The mechanism is `explorer.exe <path>` (an already-running, medium-integrity shell), or a scheduled
    task at `Limited` level.
  - On unix the launch is delegated to the target user's own shell (`su - <user> -c`, §1.5a), so the
    kernel enforces the identity.
- **On unix, starting now and enabling for login are ONE act.** Where this run registered a
  service-manager artifact, the launch MUST LOAD that artifact — `launchctl bootstrap gui/<uid> <plist>`
  on macOS, `systemctl --user enable --now dig-app.service` on Linux — rather than starting a process
  beside an inert file. Writing the artifact alone leaves the unit `inactive` and `disabled` and starts
  nothing. Windows needs no such step: the `HKCU\…\Run` value is read by the shell at logon.
- **The launch is NOT conditional on `dig_app_autostart`.** "Start it now" and "start it at every login"
  are different consents. Declining the login autostart MUST still start the app for this session, and
  MUST register nothing.
- **Idempotent by delegation.** Finishing an install while dig-app is already running MUST NOT produce a
  second instance. The installer MUST NOT test for a running instance — that races its own spawn.
  Exclusion is `dig-app`'s own per-user OS lock, under which a duplicate launch exits 0 as a no-op.
- **Best-effort, and never silent.** A launch failure MUST NOT fail an otherwise-complete install and
  MUST NOT gate `ready` (§4.2). It is recorded on `InstallReport.dig_app_launch` with `launched: false`
  and a note naming the reason.
- **Never a privileged exec of an installed binary.** Where the plan puts the installed binary on a
  command line this process runs — which happens for a root-ACCOUNT install, since no elevation hint
  names another user to delegate to — that binary MUST first pass `secure::root_exec_guard` (§7.5).

### 1.2 dig-dns availability gate

`dig-dns` (EPIC #174) may have no published release at all. If `with_dig_dns` is selected and no
release/matching asset can be resolved for it (an `ASSET_NOT_FOUND`-classified lookup — "nothing
published" as opposed to a network/transport failure), the installer:

- does NOT fail the overall install plan;
- records `InstallReport.dns` with `installed: false`, `started: false`,
  `needs_elevation: false`, and a `note` explicitly stating dig-dns is "not yet available" and
  naming EPIC #174;
- continues installing every other selected component (order preserved: digstore → digs → dig-node →
  dign → dig-dns[gated, digd skipped alongside it] → dig-relay → browser).

A genuine transport/network failure resolving dig-dns (not "no release exists") is NOT gated —
it propagates like any other component's resolution failure (`NETWORK`, exit code 4).

### 1.3 DIG URL-scheme handlers → `dign open` (#567/#563, was #389)

By default the installer registers the OS handlers for the DIG scheme set — **`dig://`** (primary),
**`chia://`** (legacy/compat), and best-effort **`urn:`** where the OS permits a generic handler —
each delegating to **`dign open <uri>`**. dig-node's shipped `dign open` (v0.27.0; the `dign` alias
v0.31.0) is the SINGLE URI-resolve-and-open authority: the installer no longer carries its own URI
parser or §5.3 resolve ladder (the removed `handle-url` subcommand), so there is exactly one thing
that knows how to resolve a DIG URI. The registered scheme set `{dig, chia, urn} → dign open` is a
cross-repo canon (see the superproject `SYSTEM.md` + the `canonical` skill). This is a **first-class,
toggleable install option**, default ON, controlled identically from the CLI and the GUI:

- **CLI:** registered by default. `--no-register-scheme` opts OUT; `--register-scheme` is the
  redundant explicit opt-in (symmetry with the `--no-<component>`/`--with-<component>` flags). Both
  map to the single `InstallPlan.register_scheme` field (`register_scheme = --register-scheme ||
  !--no-register-scheme`), so `--no-*` wins if both are given. `--unregister-scheme` removes a
  handler this installer created and runs standalone (ignores every other flag).
- **GUI:** the same default-on option, surfaced as a checkbox that sets `register_scheme` on the
  plan handed to the Rust pipeline — the GUI and CLI defaults are in sync.

Registration is **per-user, no elevation** (unlike the OS services). Per-OS mechanism:

| OS | Registration (per scheme `<s>` ∈ {dig, chia[, urn]}) |
|----|--------------|
| Windows | `HKCU\Software\Classes\<s>` with an empty `URL Protocol` value + `shell\open\command` = `"<dign>" open "%1"` |
| Linux | a `~/.local/share/applications/dig-network-url-handler.desktop` with `MimeType=x-scheme-handler/dig;x-scheme-handler/chia;[x-scheme-handler/urn;]` + `xdg-mime default`, `Exec="<dign>" open %u` |
| macOS | LaunchServices binds a scheme to a `.app` bundle, not a bare CLI — a CLI-only install cannot own the scheme, so registration is a documented best-effort no-op (reported honestly in `SchemeResult.note`, never a silent fake success); the DIG Browser `.app` registers it when installed |

The registered handler is the installed **`dign` binary** run as `dign open "%1"` (Windows) /
`dign open %u` (Linux); dig-node resolves the URI (its own §5.3 ladder) and opens the content.
**Argument-injection safety (security-critical):** NO shell is ever invoked — the OS launches the
handler via `ShellExecute`/`CreateProcess` (Windows) or the desktop-entry `Exec` (Linux), never
through `cmd /C` or `/bin/sh -c`, and the URI arrives as a SINGLE substituted argument (`%1` / the
`%u` field code), so an attacker-controlled `dig://…` URI cannot break out into extra tokens or a
shell. Registration is **best-effort within the install**: a failure is recorded in
`InstallReport.scheme` (a `SchemeResult { registered, schemes, note }`) but never aborts the install.
Unregister removes ONLY DIG-owned handlers — those whose command delegates to `dign open` (and,
for upgrade cleanup, the legacy `handle-url` form) — never a foreign registration.

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

### 1.5 The DIG auto-update beacon (`dig-updater`, issue #514)

By default the installer installs the **DIG auto-update beacon** — `DIG-Network/dig-updater`'s
`dig-updater` binary plus its unprivileged `dig-updater-worker` sibling (published in the SAME
release, resolved via `Repo::dig_updater`/`Repo::dig_updater_worker`, exactly like the
`digstore`/`digs` pair in §1.1) — and asks the freshly-installed `dig-updater` to register its own
**daily scheduler artifact** (a Windows Scheduled Task / systemd timer / macOS LaunchDaemon that
runs `dig-updater run` once a day, checking for + installing new signed DIG releases). This is a
**first-class, toggleable install option**, default ON, controlled identically from the CLI and the
GUI — the same convention as §1.3/§1.4:

- **CLI:** installed by default. `--no-auto-update` opts OUT; `--auto-update` is the redundant
  explicit opt-in. Both map to the single `InstallPlan.auto_update` field (`auto_update =
  --auto-update || !--no-auto-update`), so `--no-*` wins if both are given.
  `--dig-updater-version` pins the beacon (and its worker sibling) to a specific release; default
  latest. `--uninstall-dig-updater` removes the scheduler registration this installer created and
  runs standalone (ignores every other flag) — it does NOT delete the downloaded binaries, only the
  scheduler artifact (mirrors `--uninstall-dig-node`'s scope: the binary stays, only the OS
  registration is torn down).
- **GUI:** the same default-on option, surfaced as a checkbox ("Keep DIG up to date automatically
  (recommended)", `gui/app/src/data.jsx` `OPTIONS`) that sets `auto_update` on the plan handed to
  the Rust pipeline — the GUI and CLI defaults are in sync.

**Registration mechanism (`src/beacon.rs`):** this installer does **not** hand-roll a scheduler — it
delegates to the beacon's OWN `dig-updater schedule install`/`schedule uninstall` verbs (the same
"drive the component's own subcommands, never reimplement OS service/scheduler control" pattern
`src/service.rs` uses for dig-node/dig-relay), passing `std::env::current_exe()` implicitly (the
beacon registers a schedule against ITSELF). Registering a SYSTEM/root-run daily schedule is itself
a privileged operation — `InstallPlan::requires_elevation()` includes `auto_update`, the same
elevation gate (§4.1) dig-node/dig-dns/dig-relay service registration already trips.

Unlike a firewall rule (which can be a genuine no-op, e.g. ALF disabled), `dig-updater schedule
install`/`uninstall` are themselves **idempotent** — a re-install overwrites the existing artifact,
and an uninstall of an already-absent artifact still exits zero — so `beacon::BeaconResult.applied`
is `true` on every successful call, `false` only on dry-run or a genuine failure (`note` always
explains which, mirroring `firewall::FirewallResult`).

**Readiness (§4.2):** unlike the firewall rule/scheme handler (best-effort, never gate readiness),
the beacon's scheduler registration is a selected, privileged OS-registration step — like
dig-node/dig-relay's own service registration, a failed registration makes the overall install NOT
ready (`InstallReport.beacon` is `None` when `auto_update` is off — distinct from a
present-but-`applied: false` failed attempt).

**Version-aware updates:** `dig-updater` is one of the four `update::tracked_components()` (§7) —
a bare re-run detects what's already installed and only re-downloads an outdated/unreadable binary,
same as digstore/dig-node/dig-dns. `dig-updater-worker` is not independently tracked (mirrors
`digs`, §7.3) — it always re-downloads alongside `dig-updater`, sharing its version pin.

Declining the beacon (or a registration failure) is always safe: DIG simply never auto-updates, and
the user re-runs the installer manually to pick up new versions.

### 1.5a The target user — an elevated install installs for the INVOKING account (#1748)

The documented unix install path is `curl -fsSL https://dig.net/install.sh | sudo sh`, so the
installer normally runs as **root while acting on behalf of somebody else**. Every per-user decision
MUST therefore be made against the *invoking* account, never against the process's own environment:
under `sudo`, `$HOME` is `/root` and `$PATH`, `$XDG_CONFIG_HOME` and the visible dotfiles are all
root's.

**Target-user resolution (`invoker::resolve`).** The invoking account is resolved from the escalation
tool's own environment and the passwd database:

| Source | Fields | Notes |
|---|---|---|
| `sudo` | `SUDO_USER`, `SUDO_UID`, `SUDO_GID` | Highest precedence |
| `doas` | `DOAS_USER` | Name only; uid comes from the passwd record |
| `pkexec` | `PKEXEC_UID` | uid only; resolved back to a name |

- The hint is read **only when `geteuid() == 0`**. An unelevated process already IS the target user, so
  a stale `SUDO_USER` inherited from an ancestor shell MUST NOT redirect the install.
- A hint naming `root` is not an inversion and MUST be ignored.
- The home directory MUST come from the **passwd database**, never from `$HOME`.
- A named account takes precedence over a conflicting uid.
- `TargetUser.via_elevation` is `true` exactly when we are root acting for a different account.

**KNOWN LIMITATION — the macOS GUI elevation supplies no hint.** Every source in the table above is an
ENVIRONMENT variable, and macOS's `osascript … with administrator privileges` (§4.1c) inherits neither
environment nor stdin. So in that root child no hint exists, resolution falls back to the CALLING
process's own account, and `via_elevation` is `false` while `geteuid() == 0`. Consequences, which a
reimplementation MUST NOT assume are solved:

- per-user artifacts (the LaunchAgent, §1.11) are written into ROOT's home (`/var/root`), so dig-app does
  not start at the real user's login;
- the PATH verification (§1.5) measures ROOT's login `PATH`, not the invoking user's.

The home inversion this section exists to prevent is therefore fixed for the **sudo CLI** path and NOT
for **macOS GUI** installs. The passwd/directory lookup (§7.6) cannot help: the problem is the absent
hint, not the lookup. Closing it requires deriving the account from the console owner, or the GUI passing
it explicitly across the elevation boundary — tracked separately. Predicates that must behave correctly
in that child MUST test `geteuid()`, never the hint (§7.5).

**Placement.** On unix:

| Situation | Placement — where binaries are WRITTEN | Reachability — what is on the user's `PATH` |
|---|---|---|
| Elevated (`geteuid()==0`) | `/opt/dig/bin` (`paths::protected_bin_dir`), root-owned | SYMLINKS in `/usr/local/bin` (`paths::UNIX_MACHINE_BIN_DIR`), already on every login shell's `PATH` |
| Unelevated | `<invoking user>/.dig/bin` | That directory itself, via a per-user profile append |

An elevated install MUST NOT place user-facing CLIs under any home directory: root's is unreachable
(mode `0700`), and one user's would privilege a single account on a multi-user machine.

**`/usr/local/bin` is a PATH VENEER and MUST NOT be an install root.** Placement and reachability are
SEPARATE concerns, and conflating them is a defect class rather than a single defect. `/usr/local/bin` is
root-owned `0755` on a stock Debian/Ubuntu or macOS box, but Homebrew on an Intel Mac makes it
`<user>:admin` mode `0775` — a system directory by convention only. An elevated install therefore writes
every binary into the root-owned protected root and links the user-invoked ones outward, so that:

- root never WRITES into a directory a non-root account can modify, and
- root never EXECUTES a binary from one.

The property `/usr/local/bin` is relied on for is that it is on the default login `PATH`; that is the only
property claimed of it. Making it the elevated install root — which an earlier revision of this release
did — produced a FAMILY of root-write and root-exec paths into it rather than one, each individually
patchable. Under the veneer the class is not representable: the link lives in the possibly-writable
directory, while the target and every root-side write and exec do not. Replacing a link changes what the
USER's shell resolves — the user's own privilege level — and never what root runs, because every service
artifact names the protected target directly (`ExecStart=/opt/dig/bin/dig-dns serve`).

`paths::needs_machine_bin_link` decides which components are linked: everything placed in the protected
root that a user invokes by name, excluding `dig-updater`/`dig-updater-worker` (the beacon invokes those,
a user never does, so they stay off `PATH`). It is keyed on the directory the binary actually landed in,
so an unelevated or `--bin-dir` install plants no links — that placement is wired onto `PATH` directly.

`secure::verify_install_root` rejects a privileged root that is group/other-writable or not root-owned,
checking EVERY level of its path (§7.5). The directory a run's binaries were PLACED in is additionally
verified and reported (`InstallReport::bin_dir_security`): **FATAL under elevation**, because root wrote
those binaries and root-side execs and services resolve them, and a REPORT otherwise, because a
directory holding binaries only that same user runs is their own authority.

**A system-wide `PATH` fragment MUST append, MUST be refused for an unsafe directory, and MUST be
removed on uninstall.** `/etc/profile.d/dig-path.sh` and `/etc/paths.d/dig` are read by every LOGIN shell
of every account, root's included. A PREPEND therefore lets whatever the directory contains win the
resolution of every bare command name machine-wide — executed: `--bin-dir /home/alice/digbin` put alice's
directory in front of root's `PATH`, and `sh -lc 'ls'` ran alice's `ls` as uid 0. So the entry is
APPENDED; an elevated run verifies the directory (§7.5) and REFUSES to write the fragment at all when it
is group/other-writable, before writing rather than after; and uninstall removes the fragment as its own
reported step, since it is machine-wide state in `/etc` that no binary residue scan would ever find.

**PATH wiring is verified, not assumed.** An elevated install MUST NOT wire `PATH` through dotfiles
(the only dotfiles it can see are root's). It instead:

The directory that MUST be searchable is the **reachable** dir of the placement (`paths::reachable_dir`),
not the placement itself: for the protected root that is the `/usr/local/bin` veneer, so the default
elevated install writes no fragment at all; for a `--bin-dir` override or an unelevated run it is the
directory itself. The linking decision and the wiring decision MUST be the SAME decision — a run that
links into one directory while wiring another reports success for CLIs the user cannot find. The
directory binaries were PLACED in MUST additionally be one the target user can enter, because a link
into an untraversable directory resolves by name and then fails to execute.

1. reads the target user's **login-shell** `PATH` and checks whether that dir is already present;
2. only if absent, creates the bin dir when it does not yet exist (root-owned `0755`; `PATH` is wired
   before any component is downloaded, so an absent directory MUST NOT be reported as one the user
   cannot enter) and writes the system-wide fragment its login shells actually read:
   * **Linux** — `paths::PROFILE_D_SCRIPT` (`/etc/profile.d/dig-path.sh`), POSIX `sh`, with a
     source-time `case` guard so a re-source cannot duplicate the entry;
   * **macOS** — `paths::PATHS_D_FILE` (`/etc/paths.d/dig`), one bare directory per line. macOS has no
     `/etc/profile.d`; `/usr/libexec/path_helper`, run from `/etc/profile` and `/etc/zprofile`,
     composes the login `PATH` from `/etc/paths` plus the `/etc/paths.d` fragments;
3. **re-reads** the login-shell `PATH`. If the directory is still absent the result is an ERROR, not a
   success note.

Every required CLI MUST be verified to resolve, by bare name, on the target user's own login `PATH`,
to the copy the run placed. A binary with a command-line surface MUST additionally be RUN
(`--version`). A **GUI application** (`dig-app`) MUST NOT be probed with `--version` — it has no
command-line surface and on macOS the probe never returns — so resolution alone is all that is proven of
it.

**Its ability to START is NOT proven by `resolved`, and MUST NOT be claimed.** A successful autostart
registration is entirely consistent with a binary that cannot load, so a reimplementation MUST NOT treat a
`resolved` verdict for a GUI application as an executability guarantee. Resolution establishes the §1.5
reachability property and nothing more.

The launch (§1.11a) is a SEPARATE record, `InstallReport.dig_app_launch`, and carries a separate and
weaker claim: `launched: true` means the launch mechanism was invoked without error, NOT that dig-app is
still running. On Windows the mechanism is Explorer, which reports only that it accepted the open. A
reimplementation MUST NOT fold `dig_app_launch` into the readiness verdict, and MUST NOT let a failed
launch fail an otherwise-complete install.

Every `--version` probe MUST be bounded by a deadline and the child killed on overrun: no single binary
may hang an install.

The login-shell probe MUST enter a real **login** shell. `su - <user> -c CMD` does not do so on
BSD/macOS — `su`'s own `-c` takes a login CLASS there, so the command is handed to the shell verbatim
and no profile is read — therefore the probed command is itself wrapped in `sh -lc`.

**Protected-root CLIs are linked back onto PATH.** `/opt/dig/bin` is on no shell's default `PATH`, so a
privileged binary a user is expected to invoke by name (`dig-dns doctor`) MUST be symlinked into
`UNIX_MACHINE_BIN_DIR` (`paths::needs_machine_bin_link`). The TARGET is root-owned `0755` by
construction; the directory holding the LINK is not guaranteed to be (Homebrew on an Intel Mac leaves
`/usr/local/bin` `<user>:admin 0775` — §1.5), and it does not need to be: replacing a link there changes
what a USER's shell resolves, which is that account's own privilege level, while every root-side exec and
every service artifact names the protected target directly. Reachability is added without making a
service-executed binary unprivileged-writable. This installer creates the veneer directory `0755` if it
is absent and never re-modes one the distribution already set up.
`dig-node` and `dig-relay` are linked for the same reason: they live in the protected root because root
executes them (§1.6), and they are commands a user runs by name.
`dig-updater`/`dig-updater-worker` MUST NOT be linked — the beacon invokes them, a user never does.

**Per-user artifacts.** The login autostart (§1.11), the `chia://` desktop entry (§1.3) and the
legacy-root migration are all resolved against the target user's home and `chown`ed back to that
account. `$XDG_CONFIG_HOME` MUST be ignored when `via_elevation` is `true`.

**Printed remediation MUST be runnable in a scope where the thing exists.** `systemctl --user enable
--now dig-app.service` is not a valid instruction from a `curl | sudo sh` shell — root has no session
bus and the unit belongs to the user. Under elevation the printed command names the target user and
their runtime dir; a readiness failure MUST NOT advise re-running elevated, because the failing install
was already elevated.

### 1.5b Post-install verification MUST be falsifiable (#496/#1748)

Every post-install check MUST be capable of failing in the situation it exists to detect.

- **The PATH consulted MUST be READ from the target environment and MUST NOT be modified.** Prepending
  the install directory to the PATH being searched makes the check true by construction; it is then an
  executability check misreported as a PATH check. Sources: the target user's fresh **login shell** on
  unix (`su - <user>` under elevation, so `/etc/profile`, `/etc/profile.d/*` and their own profile are
  sourced); the **persisted** machine + user `Environment` `Path` on Windows (never the current
  process's `PATH`).
- **A component MUST NOT be reported ready without its binary having been EXECUTED.** Resolution
  proves a file is reachable; only running it proves it works. The resolved absolute path is executed
  (`<exe> --version`), as the target user under elevation, and a non-zero exit is a failure carrying the
  loader/stderr detail (for example `libxdo.so.3: cannot open shared object file`).
- **The verified set is every user-facing binary the installer places**, including the alias binaries
  and `dig-app`: `dig-store`, `digs`, `dig-node`, `dign`, `dig-dns`, `digd`, `dig-app`. A component that
  is downloaded but never executed MUST NOT print `✓`.
- Any check that cannot fail against the broken layout it guards is itself a defect.

### 1.6 Install locations — the protected install root (#565)

A binary that a PRIVILEGED identity later executes MUST live in a directory an unprivileged user
cannot write. Otherwise a non-admin could replace it and get code execution as that privileged
identity on the next service start / scheduled run — a local privilege escalation. The installer
therefore places binaries into two roots, chosen per component:

- **Protected root** — admin-only-writable, for every binary a service/scheduled-task runs:
  - **Windows:** `%ProgramFiles%\DIG\bin`, resolved via the known-folder API
    (`SHGetKnownFolderPath(FOLDERID_ProgramFiles)`, never the spoofable `%ProgramFiles%` env). Program
    Files' inherited DACL is admin-write / user-read+execute, so no custom DACL is applied. The ENTIRE
    Windows stack (services + user CLIs + the installer self-copy) installs here — one root. The
    installer additionally FORCES owner = SYSTEM (`icacls /setowner`, then `/reset` to restore the
    inherited DACL) on each DIG-scoped level it creates (`…\DIG` and `…\DIG\bin`), so EVERY ancestor of
    the install root is owned by a privileged principal (SYSTEM/Administrators/TrustedInstaller). This
    is required because dig-node's install-root check walks the WHOLE ancestor chain and accepts only
    those owners; a level left owned by the installing admin USER's own SID would make dig-node
    false-reject the tree and silently disable self-heal, local-HTTPS provisioning, and system-service
    install (`secure::force_system_ownership` / `secure::windows_created_root_levels`).

    Every FILE the installer places in that root is adopted the same way, and for the same reason. An
    elevated process's token default owner is the invoking admin USER, and the Program Files DACL the
    root inherits carries a `CREATOR OWNER` full-control entry, so a freshly created file is owned by
    that user AND grants them FullControl — which dig-node correctly refuses to run as SYSTEM. After
    each placement the installer therefore sets the file's owner to SYSTEM and re-derives its DACL from
    the parent (`secure::adopt_placed_file`), then READS IT BACK and requires a privileged owner with no
    write grant to any other principal (`secure::parse_placed_binary_acl`). The read-back bar is
    STRICTER than the install-root check, which rejects only well-known broad principals: the grant here
    is to a single named account, whose SID is not well-known. A file placed OUTSIDE the protected root
    (a `--bin-dir` override) is never re-owned. The outcome is REPORTED, never silent.

    Every ACL read-back MUST bind the security object through .NET
    (`secure::acl_object_expression`) rather than the `Get-Acl` cmdlet, and PowerShell children MUST be
    spawned with `PSModulePath` cleared (`proc::powershell`). `Get-Acl` is reached by module
    autoloading through the INHERITED `PSModulePath`, which a pwsh 7 session shadows with a Core-only
    module — the read then fails, the install fails closed, and the user gets a silently degraded
    install. Clearing the variable also denies an elevated PowerShell child any caller-supplied module
    directory.
  - **macOS/Linux:** `/opt/dig/bin`, root-owned `0755` (owner root writes; group/other read+execute).
    DIG deliberately roots PRIVILEGED binaries here, NOT under a Homebrew-style `/usr/local` prefix,
    which is group-writable on an Intel Mac (`<user>:admin`, mode `0775`) — a group-writable install
    root lets any member of that group replace a service binary, which `secure::verify_install_root`
    (and dig-node's own check) correctly rejects. The same reasoning excludes `/usr/local/bin` from
    being ANY install root under elevation, privileged or not: an elevated run also writes and execs
    user-facing binaries, so the whole stack goes here and `/usr/local/bin` holds only links
    (§1.5 Placement).
- **User root** — the dir user-run binaries go in: those no privileged service executes
  (`digstore`/`digs`/`digd` and the user-level `dig-node`/`dig-relay`). On unix it depends on the
  elevation state, per the §1.5 placement table: the protected root `/opt/dig/bin` under elevation
  (machine-wide, root-owned, reached through the `/usr/local/bin` symlink veneer), the elevation-free
  per-user `~/.dig/bin` when unelevated.
  `paths::default_bin_dir()` is the single resolver and MUST NOT be reimplemented as `~/.dig/bin`
  unconditionally — doing so is #1748: under `sudo` the per-user dir resolves to `/root/.dig/bin`,
  which is mode `0700`, so the CLIs are unreachable by the person who ran the install. It MUST equally
  not be reimplemented as `/usr/local/bin`, which trades that defect for a root-write/root-exec class.
  (On Windows there is no separate user root — everything is in the one protected root.)

The component→root map is `paths::is_privileged_component`: on Windows every component is protected;
on unix the protected set is `dig-dns`, `dig-updater`, `dig-updater-worker`, `dig-node` and
`dig-relay`. An explicit `--bin-dir <DIR>` OVERRIDE wins for the whole stack (the user's chosen dir,
their responsibility). `InstallPlan::bin_dir_for(component, os)` is the single resolver.

The membership test is **"is this binary ever EXECUTED BY ROOT?"** — NOT "does the service it registers
run under a privileged identity?". Those differ, and the difference was a root code-execution defect:
`dig-node` and `dig-relay` register themselves by their own `install` verb, which this installer runs as
root, and their services are user-level — so classifying them by the identity of the resulting service
left them in what was then the elevated user root (`/usr/local/bin`), which Homebrew on an Intel Mac leaves
`<user>:admin 0775`. Any unprivileged account able to write there could drop a binary and have root
execute it on the next `sudo` install, with no race. A binary root executes MUST therefore be
root-owned, whatever it later runs as.

Two consequences a reimplementation MUST reproduce:

* the migration (§5) vacates `dig-node`/`dig-relay` from a legacy user-writable root on upgrade, since a
  copy left there is exactly what root would later execute;
* `needs_machine_bin_link` (§1.5) links `dig-node` and `dig-relay` back onto `PATH`, because protecting
  them would otherwise remove commands users invoke by name.

**Elevation.** Writing into the protected root requires elevation, so even a CLI-only install
elevates on Windows (the CLI lands in Program Files); a CLI-only unix install into the user root does
not (`InstallPlan::requires_elevation`, §4.1). An unelevated run is the case that matters here: it
targets `~/.dig/bin` and needs no privilege to write it. A run that is ALREADY root targets the
protected root instead, so there is no elevation left to require.

**Verification (fail-loud) — the ACL check runs on WHEREVER privileged binaries land.** After
placement the installer reads the effective permissions of the dir every privileged/service-executed
binary landed in (`secure::verify_install_root`): Windows parses `Get-Acl` SID-based output and
REFUSES any Allow-write ACE for a well-known unprivileged principal (`S-1-5-32-545` Users, `S-1-1-0`
Everyone, `S-1-5-11` Authenticated Users, `S-1-5-4` INTERACTIVE); unix requires root ownership with
no group/other write bit. That dir is the admin-only protected root by default, but ALSO a
`--bin-dir` / GUI-chosen custom dir when an override redirected the stack: the verify follows the
binaries (`InstallPlan::privileged_install_root`, DECOUPLED from `installs_a_protected_component`), so
a privileged install into a user-writable custom dir can NEVER silently succeed — it fails loud. A
DEFINITIVE breach makes the install NOT ready (`InstallReport.install_root_security`, readiness §4.2);
an inconclusive read is a warning only (the admin-only LOCATION remains the primary guarantee). The
service binary MUST NEVER be executed to control it — the installer stops/deregisters services by
canonical id via the OS service manager (`svc::stop_service`/`deregister_service`), so an elevated
installer can never be tricked into running an attacker-replaced binary.

**binPath assertion (fail-loud).** Beyond the DIR's ACL, after (re-)registration the installer reads
back the ACTUAL configured binary of every privileged registration — the three LocalSystem services
via `sc qc` / `systemctl show -p ExecStart` / `launchctl print`, and the SYSTEM auto-update beacon
scheduled task via `schtasks /Query /XML` / systemd / launchd (`regaudit::audit`, always by canonical
id / task path — never by executing the binary) — and REFUSES ready if any does NOT resolve UNDER the
trusted install root this run used. The check is an ALLOWLIST (#619): a privileged binPath MUST live
under the expected protected root (`protected_bin_dir`, or the `--bin-dir`/GUI dir the whole stack was
redirected to); anything else is flagged, not merely the KNOWN legacy roots a blocklist would enumerate
— so a registration a prior `--bin-dir` install left in an arbitrary user-writable directory is caught
too. The read-back binPath is CANONICALIZED to its real filesystem path (`std::fs::canonicalize` on
both the binary and the trusted root) before the prefix test, and any path containing a `..` component
is rejected outright, so a value that merely STRING-prefix-matches the root but physically resolves
elsewhere — a `..` traversal (`<root>\..\..\evil.exe`), a junction/symlink at the root, or an 8.3
short name — cannot spoof a match; a binPath that cannot be canonicalized (missing/unreadable) fails
CLOSED (treated as outside the protected root). This catches a service a tolerated
"already exists" re-install left pointing at a writable path, and an orphaned registration a component
opt-out stranded. Like the ACL verify, this audit runs whenever the plan installs a privileged binary
ANYWHERE (`InstallPlan::installs_a_privileged_binary`, DECOUPLED from `installs_a_protected_component`),
so it fires on a `--bin-dir`/GUI privileged install too — not only the default protected root. Recorded
in `InstallReport.registration_audit`.

The ACL read-back that backs the readiness verdict (`secure::verify_install_root`) additionally asserts
it OBSERVED at least one access rule before reporting `secure`: a `Get-Acl` read that emits ZERO ACEs is
treated as indeterminate (`checked:false`), never a vacuous `secure:true` (#619).

**Migration (existing installs).** Gated on the SAME `installs_a_privileged_binary` predicate as the
audit (so it runs on a `--bin-dir`/GUI privileged install too, not only the default protected root;
the migration only ever ACTS on legacy roots, never the chosen dir): on a re-run that detects DIG
binaries in a legacy user-writable root (`%LOCALAPPDATA%\Programs\{DIG,DigStore}\bin` on Windows; the
privileged binaries in `~/.dig/bin` on unix) OR a privileged registration still pointing under one,
the installer re-points the install onto the protected root (`migrate` module): it deregisters EVERY
privileged registration whose binary resolves under a legacy root — INDEPENDENT of the current plan —
the dig-node/dig-relay/dig-dns
services BY ID *and the SYSTEM auto-update beacon scheduled task* by its own scheduler tool
(`schtasks /Delete` on Windows; `systemctl disable --now` **plus removal of the unit FILE** on Linux —
`disable` alone only un-links the enablement symlinks, so the unit stays loadable and the deregister
could never report success; `launchctl bootout` + plist removal on macOS), so a component OMITTED from the run
cannot keep an auto-start service or daily SYSTEM task registered against a replaceable legacy
binPath; the normal install then re-registers whatever is in-plan fresh from the protected path. It
removes the legacy binaries by KNOWN filename (never a recursive walk that could follow a planted
junction/reparse point — all on Windows, only the privileged ones on unix); and drops the legacy dir
from the user PATH on Windows. It never executes a legacy-dir binary. A DEREGISTER FAILURE is FATAL —
the install reports NOT ready (`MigrationResult::deregister_failures`), never a silent continue into a
tolerated re-install that could leave the service at the legacy binPath. Recorded in
`InstallReport.migration`.

**Superseding a competing installation (`supersede`).** DISTINCT from the migration above, and
governed by the opposite policy. A Windows machine could historically carry two managed copies of one
component: this installer places `dig-node.exe` in `%ProgramFiles%\DIG\bin`, while an OLDER dig-node MSI
package placed its own in a SECOND, competing location under `%ProgramFiles%\DIG Network\dig-node\`
(`dig-node.wxs` -> `INSTALLFOLDER`), added that directory to the MACHINE `Path` through its own
`PathEntry` component, and registered the same `net.dignetwork.dig-node` service. A new shell composes
the machine `Path` BEFORE the user `Path`, so that legacy copy wins the bare name and the install
correctly fails its own reachability check. Since dig-node 0.99.9/0.99.10 the MSI instead installs to
the SAME canonical `%ProgramFiles%\DIG\bin` root with NO PATH row — so it is the current install, not a
competing shadow. The installer MUST resolve only a genuine legacy shadow, decided from the product's
recorded install LOCATION.

**A REGISTERED Windows Installer product MUST be removed with `msiexec /x`, never by deleting files**
(`supersede::supersede_msi_products`). Its files, Add/Remove-Programs registration, any machine-PATH
component and its service are one transaction in the Installer database; deleting the directory leaves a
registered product with no files, a repair that fails, and an upgrade that believes an older version is
present. A product is superseded ONLY when its ARP `InstallLocation` resolves under the legacy
`%ProgramFiles%\DIG Network` root AND is NOT the current canonical `%ProgramFiles%\DIG\bin` root, and
its component stem is one THIS RUN installs (`msi::products_to_supersede`, pure). A product installed to
the canonical root, one with an unknown location, or one with no replacement coming MUST be left alone —
the fail-safe that prevents `msiexec /x` from uninstalling the live canonical dig-node
(dig_ecosystem#2304).

**That step MUST run before any service is registered.** The package's `ServiceControl` stops and
deletes the shared service on uninstall, so running it later would remove the service this run had just
registered. It is therefore placed beside the #565 migration, before component installation, and the
normal install re-registers the service from the current root.

**An ORPHANED directory** — the same path with no registered product — has no database to respect and
is removed here, conditionally, after placement and before the reachability check. Candidates are
derived (`paths::superseded_roots`) as one directory per DIG component under
`paths::superseded_root_base` (`%ProgramFiles%\DIG Network` on Windows; NOTHING on unix, whose layout
has always been the single `/opt/dig/bin` root), never the current `protected_bin_dir`, each judged
INDEPENDENTLY.

Removal REFUSES — leaving the directory in place and recording the reason — when any of these holds, in
this precedence (`supersede::decide`, pure):

0. a STILL-REGISTERED Windows Installer product owns the directory. This is ABSOLUTE: it is never a
   fallback, and specifically MUST NOT be bypassed after a failed `msiexec` attempt;
1. a privileged registration (a service `PathName`, the beacon task) resolves under the root;
2. a RUNNING process's image resolves under the root, matched by ROOT and never by executable name (the
   two copies share a filename);
3. the root holds an entry the current install root does not, compared case-insensitively.

Otherwise the KNOWN DIG binary filenames are deleted one by one via `symlink_metadata` (never a
recursive walk, never following a reparse point), the directory is removed NON-recursively, and the root
is dropped from EVERY persisted `Path` scope that carries it — machine and user
(`paths::remove_from_persisted_path`), preserving each value's own registry type so a `REG_SZ` `Path` is
never promoted to `REG_EXPAND_SZ`. A failure cleaning one scope MUST NOT skip the others: an unelevated
run whose machine (`HKLM`) write is refused still cleans the user (`HKCU`) entry, and reports the machine
failure — a short-circuit that left the user entry behind would keep shadowing the current root. The PATH drop MUST also run for a candidate whose directory is already
gone, since a stale machine-PATH entry outlives its directory and still shadows. Nothing here is fatal:
what cannot be cleaned is recorded in `InstallReport.superseded_roots` / `InstallReport.msi_superseded`
and the reachability check remains free to fail the install.

**PATH reachability is a property of PERSISTED state, never of the installer's own environment
(`pathcheck`).** On Windows the PATH consulted is the persisted machine `Path` followed by the persisted
user `Path`, with `%NAME%` references resolved against the persisted `Environment` keys first and this
process's environment only as a last resort for a name neither key defines. That ORDER is normative:
machine key, then user key, then this process (`pathcheck::resolve_env_name`) — consulting the process
value earlier reintroduces the false negative below. A `%PATH%` SELF-REFERENCE MUST
expand to nothing: the name it references is the value being composed, and resolving it through the process
environment splices the launching shell's `PATH` into the verdict — which was measured turning a 63-entry
composed session `PATH` into a 151-entry one and making the shadow check report a clean PATH while a stale
root genuinely won a fresh shell (a false negative). The verdict MUST be identical however the installer
was launched.

**The beacon is registered and deregistered SYSTEM-scope ONLY (`regaudit`).** dig-updater installs
the beacon system-scope on every OS (Linux writes `/etc/systemd/system` under elevation with no
`systemctl --user`; Windows a SYSTEM Scheduled Task; macOS a `/Library/LaunchDaemons` root daemon),
so a `--user`-scope `dig-updater` unit is NEVER a DIG registration. Every beacon query and removal
therefore uses the machine scope only and MUST NOT query or touch the `--user` scope: doing so both
performed root-adjacent file operations inside a user-owned directory AND handed an unprivileged local
account a denial primitive — a planted, still-loaded `--user`-scope `dig-updater.timer` made the
(fatal) deregister post-check fail, turning a blameless upgrade into a fatal migration failure.

**The Linux beacon unit-file removal is BOUNDED (`regaudit::plan_unit_file_removal`).** The path
removed is the one systemd itself names (`systemctl show -p FragmentPath <unit>`), and it MUST be
vetted before anything is unlinked: absolute, no `.`/`..`/empty component, named EXACTLY for the unit
being deregistered, a `.service` or `.timer`, and its parent one of the SYSTEM unit directories —
`/etc/systemd/system` or `/run/systemd/system`, both root-owned. A path under a user tree (e.g.
`~/.config/systemd/user`) is therefore REFUSED, never unlinked with root's authority. A package-owned
directory (`/usr/lib/systemd/system`, `/lib/systemd/system`) is REFUSED, never unlinked: removing a
package-owned unit leaves the package database inconsistent and `apt install --reinstall` would
silently restore the schedule. Every refusal MUST be reported (it is folded into the fatal deregister
verdict), never silent.

A run that does NOT select the auto-update beacon MUST NOT install or register it: declining the
beacon means "install nothing". The #565 migration nevertheless vacates a beacon schedule that
resolves under a legacy user-writable root, independent of the plan, and MUST do so — such a
schedule is itself the vulnerability. A run whose plan declines the beacon and whose migration
deregistered that schedule therefore leaves the host with auto-updates OFF, and MUST REPORT that
state rather than swallow it: the installer MUST record the outcome in
`InstallReport.beacon_rearm` (`{applied, note}`, `null` when there was nothing to restore) and MUST
log that auto-updates are now disabled and the exact command that restores them. It MUST NOT
download, place, or execute `dig-updater` to restore the schedule — doing so would install a
component the run was explicitly asked not to install.

Where a protected-root `dig-updater` is already present, the installer MAY re-register the daily
schedule against `<protected root>/dig-updater` only, never against a legacy binary (which has been
removed and MUST NEVER be executed) and never against a `--bin-dir`/GUI-redirected root: a run
whose privileged install root differs from the protected root MUST SKIP the re-arm and log the
reason, because a machine-wide privileged schedule MUST NEVER be registered at a caller-selected
path. This is not a readiness failure — the beacon was not part of what the run was asked to install.

A re-arm that succeeded is a reversible privileged action: it MUST be recorded in the install's
rollback guard, so a later step's failure deregisters the schedule rather than leaving a
machine-wide privileged registration pointing into a root the rollback reverts. That reversal MUST
deregister the schedule with the OS scheduler tool and MUST NOT run `dig-updater schedule uninstall`:
that verb records a sticky opt-out which suppresses every later self-heal, so a failure in an
unrelated step would leave the host with auto-updates permanently off. A reversed re-arm MUST be
retracted in `InstallReport.beacon_rearm` (`applied: false` plus the reason), never left claiming the
schedule is back.

The re-arm MUST run AFTER the protected root has been created + hardened. The ordering is *attempted*
by the install step, and ENFORCED by `secure::root_exec_guard` (reached through
`guardedcmd::GuardedCommand::for_installed_binary`, the only way an installed binary can be spawned):
an elevated re-arm of a `dig-updater` whose directory is not owner-secure is refused there, so a
failed or skipped root pre-creation cannot turn into a privileged spawn out of a user-writable
directory.

**Authoritative install-root record (`install.json`, #581).** The installer writes
`<install-home>/install.json` (`%ProgramFiles%\DIG\install.json` / `/opt/dig/install.json` — the
protected root's parent, admin-only-writable by inheritance) with `{ "schema": 1, "bin_dir": <the
protected root>, "installer_version": <version> }`. This is the single machine-readable source of
truth for the install root the auto-update beacon consumes; it is coherent with the beacon's own
`current_exe().parent()`-derived root by construction now that the beacon binary lives in the
protected root. A consumer MUST verify the file is admin-only-writable before trusting it. Recorded
in `InstallReport.install_manifest`.

**System-tool resolution (Windows, #657).** Every Windows system tool the installer spawns
(`sc`, `netsh`, `powershell`, `icacls`, `schtasks`, `net`, `whoami`) is addressed by its ABSOLUTE
`%SystemRoot%\System32\<tool>.exe` path, resolved from the OS via `GetSystemDirectoryW` (NOT the
spoofable `%SystemRoot%` env) through the single `proc::system_tool` resolver — never a bare name.
Windows' bare-name search order places the current directory before System32, so an elevated run with
an attacker-controlled CWD could otherwise execute a planted `sc.exe`/`netsh.exe`; absolute resolution
closes that search-order hijack. `powershell.exe` resolves to its real `System32\WindowsPowerShell\v1.0`
location. The machine hosts-file path (`hosts::hosts_path`) uses the same `GetSystemDirectoryW`-resolved
System32 dir rather than the `%SystemRoot%` env.

**Symlink-safe atomic file writes (#650).** A root writer into a compiled-in `/etc/**` policy path (the
Linux `ExtensionInstallForcelist` writer) stages an `O_NOFOLLOW | O_EXCL` temp file in the same
directory and atomically `rename`s it over the target. The rename replaces the final path component
itself — never following a symlink AT it — so a redirecting symlink cannot divert the write, and the
policy file is only ever observed fully-written or absent (never partial). (The Linux DNS/DoH OS-config
write moved to `dig-dns configure-os` in #627-WU2; the same symlink-safe pattern belongs there and is
tracked for that repo.)

### 1.7 Chromium-family browser detection (#609)

The installer force-installs the DIG extension across the Chromium-family browsers on the machine
via each browser's `ExtensionInstallForcelist` managed policy (epic #602). To target that write it
first DETECTS which browsers are installed and WHERE each one's managed-policy location is. This is a
**read-only** capability — detection writes no policy and touches no browser; the forcelist writer
(#612) consumes the detected list.

**CLI:** `dig-installer --detect-browsers` lists the detected browsers; `--detect-browsers --json`
emits the machine result `{ "ok": true, "browsers": [ DetectedBrowser, … ] }`. The action is
standalone (ignores every other flag), network-free, and always exits `0`.

Each `DetectedBrowser` is:

| Field | Type | Meaning |
|-------|------|---------|
| `id` | string | stable slug — one of `chrome`, `edge`, `brave`, `chromium`, `vivaldi`, `opera` |
| `display_name` | string | human name for the GUI checklist (e.g. `Google Chrome`) |
| `kind` | string | `chromium-family` (the only family that honors the forcelist policy) |
| `install_path` | string \| null | the path that evidenced detection, when one matched (null when only a Windows uninstall-registry entry evidenced it) |
| `detected` | bool | always `true` for a returned entry (explicit in the contract) |
| `policy_target` | object | where #612 writes this browser's managed extension policy, for the host OS |

`policy_target` is OS-tagged: `{ "os": "windows", "policy_key": "SOFTWARE\\Policies\\Google\\Chrome" }`,
`{ "os": "macos", "preferences_domain": "com.google.Chrome" }`, or
`{ "os": "linux", "managed_policy_dir": "/etc/opt/chrome/policies/managed" }`. The per-browser policy
coordinates are the epic #602 D6 table (the single source of truth #612 also writes against):

| Browser | Windows policy key (`HKLM`-relative) | macOS preferences domain | Linux managed-policy dir |
|---------|--------------------------------------|--------------------------|--------------------------|
| Chrome | `SOFTWARE\Policies\Google\Chrome` | `com.google.Chrome` | `/etc/opt/chrome/policies/managed` |
| Edge | `SOFTWARE\Policies\Microsoft\Edge` | `com.microsoft.Edge` | `/etc/opt/edge/policies/managed` |
| Brave | `SOFTWARE\Policies\BraveSoftware\Brave` | `com.brave.Browser` | `/etc/brave/policies/managed` |
| Chromium | `SOFTWARE\Policies\Chromium` | `org.chromium.Chromium` | `/etc/chromium/policies/managed` |
| Vivaldi | `SOFTWARE\Policies\Vivaldi` | `com.vivaldi.Vivaldi` | `/etc/opt/vivaldi/policies/managed` |
| Opera | `SOFTWARE\Policies\Opera Software\Opera` | `com.operasoftware.Opera` | `/etc/opt/opera/policies/managed` |

**Per-OS detection mechanism** (best-effort — a failed probe contributes fewer signals, never an
error): **Windows** reads `DisplayName` values from the uninstall registry keys (`HKLM` +
`WOW6432Node` + `HKCU`) and probes the well-known executable paths under `%ProgramFiles%` /
`%ProgramFiles(x86)%` / `%LOCALAPPDATA%`; **macOS** scans `/Applications` + `~/Applications` for the
known `.app` bundles and reads each bundle's `CFBundleIdentifier` from `Contents/Info.plist`;
**Linux** resolves the known launcher binaries against the `PATH` directories. The raw findings feed
a pure matcher against the browser catalogue, so the mapping is fixture-tested without a real
registry, filesystem, or `Info.plist`.

### 1.8 GUI browser-checklist step + the extension selection contract (#611)

The GUI wizard offers the DIG browser extension as a Components entry (id `extension`,
`gui/app/src/data.jsx` → `COMPONENTS`), **checked by default**. When it is selected the wizard shows
one additional step, **Browsers**, slotted between Components and Installing:

```
Welcome → License → Components → [Browsers] → Installing → Finish
```

The step is CONDITIONAL — present exactly when `extension` is selected, absent otherwise. The visible
step list is derived from the selection (`gui/app/src/steps.js` → `computeSteps`), and the rail, the
footer dots, and next/back navigation all key off that one computed list rather than fixed indices.

The Browsers step (`gui/app/src/steps/Browsers.jsx`) calls the `detect_browsers` Tauri command
(which returns the §1.7 `DetectedBrowser` list) and renders the four async states: **loading** while
detection runs, **error** with a Retry when detection fails, **empty** (a clear "no supported browser
detected — install manually later" message, never a dead-end) when none is found, and **success** —
a **scrollable** checklist of the detected browsers. **Every detected browser is checked by default**;
the user may uncheck any browser to skip installing the extension into it. Back and Continue remain
available in every state (the step never traps).

The selection is carried to the install pipeline as `InstallOpts.selected_browsers` — a list of the
detected-browser `id`s the user kept checked (empty when the extension is deselected). This is the
contract the enterprise force-install writer (#612) consumes to decide which browsers'
`ExtensionInstallForcelist` policy to write. In this step the pipeline only CARRIES the selection
(and surfaces it in the install log); it writes no browser policy.

### 1.9 `ExtensionInstallForcelist` force-install writer (#612)

The installer force-installs the DIG Chromium extension into each selected browser by writing an
`ExtensionInstallForcelist` entry into that browser's per-OS enterprise managed-policy surface, and
removes ONLY that entry on uninstall. The written value is the canonical force-install pair
`"<extension-id>;<update_url>"`:

- **Extension id** = `mlibddmbhlgogepnjdienclhnkfpkfah` (compiled-in constant, pinned in the
  `canonical` skill; derived from the extension signing key SPKI — MUST NOT drift). The id is the
  SAME for both channels.
- **`update_url`** = `https://updates.dig.net/ext/<channel>/updates.xml`, `<channel>` ∈
  `stable` | `nightly` (compiled-in HTTPS constant, #608). No user or environment input flows into the
  value — there is no injection surface.
- **Channel** follows the tracked release channel; the **default is `stable`**.

**Per-browser × OS policy locations** (the §1.7 `policy_target`):

| OS | Location written |
|----|------------------|
| Windows | `HKLM\<policy_key>\ExtensionInstallForcelist` — numbered `REG_SZ` values (`"1"`, `"2"`, …), one per entry |
| macOS | the per-bundle managed plist `/Library/Managed Preferences/<preferences_domain>.plist` |
| Linux | a dedicated dig-owned file `<managed_policy_dir>/dig-extension-forcelist.json` (the OS policy union merges it) |

Only browsers the user selected (`InstallOpts.selected_browsers`, §1.8) are written; absent browsers
are skipped. A `policy_target` for a non-host OS is reported `skipped`, never written.

**Security invariants (normative):**

- **Never clobber a pre-existing org forcelist.** `ExtensionInstallForcelist` is a list. On Windows we
  MERGE — our entry is added at the first free numbered slot beside any enterprise entries, and removal
  deletes ONLY the value(s) whose data is ours; the subkey itself is never deleted. On Linux we drop a
  uniquely-named dig-owned file the policy union merges, so nothing is clobbered. On macOS we write our
  managed plist only when none exists for the domain or the existing one is ours; a non-DIG (MDM/org)
  managed plist is left untouched and the outcome recommends MDM for a managed fleet (best-effort,
  honest about MDM).
- **Marker-owned.** On Windows/macOS the entry value itself is the marker — it begins with the
  canonical extension id, which no other tool emits; on Linux the marker is the dedicated filename.
  `remove` deletes only what carries the marker. (Acknowledged edge: an org independently
  force-installing the SAME DIG extension id with a different `update_url` would be recognized as
  ours and its entry removed/replaced. This is negligible — the id is DIG's own, so any such entry is
  force-installing the DIG extension regardless of which `update_url` it points at.)
- **Idempotent + no half-write.** Re-running with the same channel is a no-op (no duplicate entry); a
  partial failure leaves no half-registered policy; removal is complete (zero residue).
- **Channel-switch semantics = clean reinstall (not a rewrite).** The extension id is identical across
  channels, and a nightly build (`X.Y.Z.N`) numerically OUTRANKS the matching stable `X.Y.Z`, so
  repointing a nightly-installed browser at the stable `update_url` is a downgrade Chromium refuses to
  auto-apply. A channel change is therefore performed as a per-browser REMOVE (the browser uninstalls
  the extension) followed by a re-ADD at the new channel (a fresh install of that channel), not a value
  rewrite. The `forcelist::reinstall` primitive supports this transition; the beacon-follow job (#613)
  owns staging the remove and the re-add across policy-refresh cycles and the active-channel→update_url
  mapping.
- **Privileged-only.** Every target location (`HKLM`, `/etc`, `/Library/Managed Preferences`) is
  admin-owned; the writes run only inside the already-gated elevated context (#565). The module neither
  elevates on its own nor reads any user-writable input.

**CLI (standalone actions):** `dig-installer --set-ext-forcelist-channel <stable|nightly>`
force-installs into every DETECTED browser on the given channel (a channel change is a clean
reinstall); `--uninstall-ext-forcelist` removes only the DIG entry from every detected browser. Both
require elevation, run standalone (ignore every other install flag), and support `--json`, emitting
`{ "ok": <bool>, "result": [ ForcelistOutcome, … ] }` (`ok:false` iff any per-browser write failed).
`ForcelistOutcome` = `{ location, action, note }` where `action` ∈ `wrote | already-present | updated
| removed | nothing-to-remove | skipped | failed`.

**Install-flow force-install (GUI/normal install, #648).** A normal install that selects the
`extension` component (default-on) with at least one browser kept checked on the Browsers step
(§1.8) force-installs the extension as part of the install itself — it is not a separate CLI action.
The write is `forcelist::apply` for exactly `InstallOpts.selected_browsers` at the **stable** channel
(the install-time default; a later channel SWITCH is the beacon-follow job #613, never the install
path). The write is a privileged managed-policy write, so it runs in the SAME elevated context as the
component install, and NEVER in an unelevated parent:

- **Elevation.** Wanting the force-install (extension selected + ≥1 browser) makes the install
  `require elevation` on its own — even a browser-only selection with no downloadable component — so
  the fail-closed elevation gate and the Linux `pkexec` relaunch both cover it.
- **Where the write runs.** On Windows (`requireAdministrator`), macOS, and an already-root unix run
  the install process IS the elevated context and performs the write in-process. On an unelevated
  Linux GUI the write is performed by the `pkexec` ROOT CHILD (streamed the selection over stdin,
  #638), after the components install; the unelevated parent performs NO privileged policy write and
  only surfaces that the elevated step handled it.
- **Honest partial-failure.** Every browser's `ForcelistOutcome` is surfaced in the install log
  (which browsers got the policy, which were skipped, which failed). A single `failed` outcome fails
  the whole install step (the install never reports "ready" over a silently-failed force-install),
  naming the failed browser(s) and cause — never swallowed.
- **No injection surface.** The policy VALUE (extension id + `update_url`) is compiled-in (§1.9); the
  only install-time input is WHICH selected browsers to write, which can never widen the value or the
  target set beyond the §1.8 catalogue.

**Uninstall coherence (#568).** A full uninstall calls `unconfigure_extension_forcelist` (the
`--uninstall-ext-forcelist` CLI verb today; the aggregate GUI uninstall #568 wires the same call) so
no `ExtensionInstallForcelist` residue survives a full removal.

### 1.10 Cross-browser auto-update — the same mechanism for every brand (#645)

The force-install auto-updates the extension across EVERY supported Chromium-family browser
(Chrome, Edge, Brave, Chromium, Vivaldi, Opera) with NO browser-specific workaround. Every brand
reads the SAME `ExtensionInstallForcelist` managed policy and runs the SAME built-in Chromium
auto-updater, which polls the pinned `update_url` on its own background schedule and pulls the
latest CRX. The ONLY per-brand difference is the managed-policy LOCATION (§1.9 table) — never the
entry value, the manifest format, or the update mechanism. So the force-install is armed for
auto-update identically for all of them, and this is a normative acceptance property, verified in
three tiers (see `runbooks/cross-browser-ext-acceptance.md` for the full browser × OS × automated|
manual matrix):

- **Tier 1 — configuration matrix (automated, `cargo test`).** For every supported browser on every
  OS, the installer resolves the correct managed-policy location and writes the exact entry
  `mlibddmbhlgogepnjdienclhnkfpkfah;https://updates.dig.net/ext/<channel>/updates.xml`
  (`tests/cross_browser_forcelist.rs`), and the per-writer unit tests
  (`src/forcelist/{windows,macos,linux}.rs`) prove the write mechanics at each location kind.
- **Tier 2 — live update source (automated CI, `cross-browser-ext-acceptance.yml`).** The
  `update_url` every browser polls actually serves a valid Omaha `gupdate` manifest for the DIG
  extension id with a fetchable CRX (stable); the nightly channel is served + armed even before its
  first build.
- **Tier 3 — real end-to-end (automated Linux smoke + documented manual).** The shipped binary
  writes a real Chrome managed-policy file on Linux CI; the other brands' full install→appears→
  auto-updates flow is documented manual acceptance in the runbook (a real browser reading managed
  policy off the network is not reliably CI-drivable headless).

### 1.12 Privileged TLS root — provisioning HTTPS on install (#623/#858)

`dig-node` serves `https://dig.local` from per-machine TLS material it resolves at
`dig_cert::TlsPaths::machine()`, and it REFUSES to serve HTTPS — falling back to plaintext — unless
that root passes its own privileged-owner gate (`dig-node-service`'s `security::dir_is_privileged`):
every path component owned by a privileged principal (Windows SYSTEM `S-1-5-18` / Administrators
`S-1-5-32-544` / TrustedInstaller, non-reparse; unix uid 0, non-symlink, no group/other write bit)
and the `tls` leaf owner-only. This installer is what provisions that root so the node can turn HTTPS
on. Only when dig-node is being installed (`--with-dig-node`); `--dry-run` reports intent only.

- **Location + ownership.** Windows `%ProgramData%\DIG\tls` — `C:\ProgramData` already qualifies
  (TrustedInstaller-owned); the installer owns + locks the `DIG` and `tls` levels NON-recursively to a
  protected `{SYSTEM:F, Administrators:F}` DACL (no interactive-user ACE — the node reads the CA key
  as SYSTEM/Administrator), read-back-verified, fail-closed, exactly the daemon-state-dir hardening
  pattern (§1 / #501/#715). Linux + macOS `/etc/dig/tls` — created by root under root-owned `/etc`,
  `tls` mode `0700`, `/etc/dig` `0755`, symlink-rejected, fail-closed on any chmod failure.
- **Material.** A per-machine, name-constrained CA (`ca.{key,crt}`) + a 90-day leaf (`leaf.{key,crt}`)
  minted via the `dig-cert` crate (never re-implemented) — the CA's critical `nameConstraints` scope
  it to `dig.local`/`.dig`/loopback. Unix key files are `0600`, certs `0644`; on Windows they inherit
  the root's SYSTEM/Administrators-only DACL. **Idempotent:** a run finding a complete, parseable CA +
  leaf already on disk SKIPS the mint — never clobbering a working CA, which would orphan the trust
  anchor already installed against it.
- **Trust anchor.** `ca.crt` is installed as an OS trust root so a browser on the machine trusts
  `https://dig.local`: Windows `certutil -addstore -f Root`, macOS `security add-trusted-cert -d -r
  trustRoot -k /Library/Keychains/System.keychain`, Linux `update-ca-certificates` (Debian anchor
  `/usr/local/share/ca-certificates/dig-local-ca.crt`) with an `update-ca-trust` fallback (RHEL anchor
  `/etc/pki/ca-trust/source/anchors/dig-local-ca.crt`). Every external tool is spawned through the
  crate's guarded, console-hidden wrapper (`proc::system_tool`, absolute on Windows — #657).
- **Trust-manifest ledger.** Each installed anchor is recorded at `dig_cert::TlsPaths::trust_manifest()`
  (`{store, fingerprint (SHA-1 thumbprint of the CA DER), path?}`) so `uninstall` can revert exactly the
  DIG-owned entries (§3.10 step 5a) and nothing else.
- **Readiness.** The `TlsRootResult` `created` flag (root privileged-owned AND holding a CA + leaf) is
  a hard readiness gate: a `created: false` result makes the install NOT ready rather than let the node
  silently serve plaintext. The trust-anchor install is REPORTED but not gated (the node serves HTTPS
  regardless; the anchor only affects client trust, and a headless host may lack the trust tool).

## 2. Install lifecycle — stop before write, start after write

For the two components this installer registers as OS services with their OWN `install`/
`uninstall`/`start`/`stop`/`status` CLI verbs — **dig-node** and **dig-relay** — every
(re-)install follows this order per component, never reversed:

1. **Resolve** the release + asset for the target OS/arch (network).
2. **Stop-if-running** (task #232 / #565): if a binary already exists at the destination path (i.e.
   this is an upgrade, not a first install), query the OS service manager for the service's run
   state BY CANONICAL ID (`svc::service_run_state`, `net.dignetwork.dig-node` /
   `net.dignetwork.dig-relay`) and, if RUNNING, stop it BY ID (`svc::stop_service` — `sc stop` /
   `systemctl stop` / `launchctl bootout`). The service binary is **NEVER executed** to control it
   (the pre-#565 `<dest> status --json` / `<dest> stop` path had the elevated installer run a binary
   a non-admin could have replaced in the legacy user-writable dir → user→SYSTEM escalation; #565).
   Skip-when-absent/not-running: neither is an error. **A stop FAILURE while running aborts this
   component's write** (`SERVICE_STOP_FAILED`, exit code 10) — the binary is NEVER overwritten out
   from under a still-running process.
3. **Write** the newly downloaded binary to the destination path (only reached once step 2
   succeeds or was a no-op).
4. **Register + start**: run `<dest> install` (tolerated if it fails — an already-registered
   service reports this on re-install; the registration still points at the same on-disk path, so
   the next step still picks up the binary just written), then, if the plan requests it,
   `<dest> start`. Only a `start` failure is a hard error (`SERVICE_START_FAILED`).

   A registration that fails with the Windows SCM's TRANSIENT post-delete state is RETRIED before it
   is tolerated: after an uninstall the SCM keeps the deleted record until its last handle closes, and
   a registration in that window reports `ERROR_SERVICE_DOES_NOT_EXIST` (1060) or
   `ERROR_SERVICE_MARKED_FOR_DELETE` (1072). The installer retries those two codes — and ONLY those
   two, recognised by the code rather than by an English phrase a spawn failure shares — on a bounded
   1s/2s backoff (`service::with_scm_retry`). Every other failure is reported at once.

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
service-managed; like every component their bytes are written through the resilient
`download::replace_binary` (§2.3), so a destination locked by a running process on Windows is staged
for a reboot-time replace rather than failing with a raw sharing-violation error. DIG Browser's OWN native installer
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

### 2.1a Service SCOPE — which domain an engine registers in (dig_ecosystem#526)

An **engine** (`dig-node`, `dig-relay`, `dig-dns`) is a machine daemon holding no user identity. The
**agent** (`dig-app`) is per-user and MUST NEVER become a machine daemon (§1.11).

Reboot survival with NO login session comes from exactly three mechanisms — the systemd
`multi-user.target.wants` symlink, a launchd **system**-domain plist with `RunAtLoad`, and the SCM's
`AUTO_START`. Every per-user mechanism (a systemd `--user` unit, a `gui/<uid>` LaunchAgent, an XDG
autostart entry, `HKCU\…\Run`) waits for a login BY DESIGN.

The scope is `svcscope::engine_scope(os, elevated, program_in_protected_root)`:

| OS | elevated + binary in the protected root (§1.6) | elevated + `--bin-dir` override | unelevated |
|---|---|---|---|
| Linux | **System** — `/etc/systemd/system/` + the `multi-user.target.wants` symlink | **User** (forced), reported as "will NOT survive a reboot" | User — `~/.config/systemd/user/` |
| macOS | **System** — `/Library/LaunchDaemons/…plist`, `RunAtLoad` | User (`gui/<uid>`), same report | User — `~/Library/LaunchAgents/` |
| Windows | System — SCM `start= auto` | same | refused by the elevation gate (§4.1) |

A `--bin-dir` run is FORCED to user scope: a machine-wide daemon pointed at a caller-selected path is
the §7.5 escalation itself. The forced downgrade MUST be reported
(`ServiceResult.survives_reboot: false` + `scope_note`), never silent.

**The argument surface.** The installer passes `--scope <system|user>` to the component's
`install`/`start`/`uninstall` verbs, as two tokens. The value set is byte-identical with the
`--scope <auto|system|user>` the component accepts. The installer never passes `auto`, because
"whatever the component defaults to" is the defect this closes.

> **Status.** `--scope` exists as of **dig-node v0.70.0**, on all four service verbs, and its
> `resolve_scope` maps `auto` under root to the system domain. dig-installer therefore requires
> **dig-node v0.70.0 or later for machine-wide registration**, and ships **v0.71.0** as its floor.
> On any such component an elevated protected-root install reaches a system-scope, boot-started
> registration with nobody logged in, which is the acceptance criterion of dig_ecosystem#526.

**Compat with a build older than v0.70.0.** dig-installer installs the LATEST component release with no
version pin, so a real user receives v0.71.0 and the system path automatically. An older binary is
reachable only when an operator EXPLICITLY pins below v0.70.0, and that state is still specified
because such a pin must degrade honestly rather than silently. clap rejects an unknown flag with a non-zero exit
BEFORE running any subcommand body, so that failure is side-effect-free: the installer retries the
verb WITHOUT the flag and records `reboot_survival: false` with a plain-language note. The retry MUST
be gated on a message naming `--scope` specifically (`svcscope::is_unknown_scope_flag_rejection`) —
retrying any other failure unflagged would silently downgrade a system registration to a login-gated
one and still report success. No `--help` probing and no version parsing.

The reported `reboot_survival` after a fallback is the truth about what the component ACTUALLY did,
which is `svcscope::legacy_default_scope(os)` — **System on Windows** (the SCM has no per-user domain,
and `install` sets `start= auto` there), **User on Linux/macOS** (dig-node's pre-`--scope` `install`
preferred a user-level unit regardless of privilege, which is this whole defect). A fallback is
therefore NOT a downgrade on Windows and MUST NOT be warned about as one; it is disclosed either way.

`legacy_default_scope(Linux) == User` is truthful ONLY of a component older than v0.70.0. From
v0.70.0 the flag is accepted, so the fallback is unreachable and this value is never consulted. The
distinction is normative rather than incidental: the value is correct only under the condition that
the flag was REJECTED, so it MUST stay gated on `scope_flag_accepted == false` and MUST NOT become a
general "what does this OS default to" answer. Were the retry predicate ever widened past a
`--scope`-specific rejection, this value would be reported for a component that does understand the
flag, and the report would be wrong.

**An `install` failure is tolerated ONLY at the requested scope.** `install` is not idempotent, so a
re-install over a live registration can hard-fail while the registration is perfectly usable — that
tolerance is retained, but it is now judged by a SCOPE-EXPLICIT probe
(`svc::registration_in_scope`, which answers PRESENCE — `systemctl is-active` says `inactive` for a
unit that does not exist, so a run-state query cannot answer "is anything registered here?" at all). A
failure with nothing registered at the requested scope is an ERROR and fails readiness (§4.2); an
`Unknown` probe result is NOT tolerance, because "could not ask" is not "it is there".

**Presence has exactly three values, and only a RECOGNISED not-found reply is `Absent`.** The
classification is byte-identical with dig-node's own service probe (v0.71.0,
`crates/dig-node-service/src/service.rs`), so the two implementations agree on what absence looks
like:

| backend | classifier | `Absent` iff |
|---|---|---|
| systemd | `svc::classify_systemctl_is_enabled` | the `not-found` state token on stdout, or a stderr naming the missing unit file — including dig-node's verbatim `no files found for` / `could not be found` — with an EMPTY stdout and a NON-ZERO exit |
| launchd | `svc::classify_launchctl_print` | exit `113` (`kLaunchdNoSuchServiceError`), or stderr containing `could not find service` / `no such process` / `no such file` |
| Windows SCM | `svc::classify_sc_registration` | `sc query` reporting `1060` (`ERROR_SERVICE_DOES_NOT_EXIST`) |

A successful query is `Present`, tested BEFORE any absence signal. Everything else is
`Unknown(reason)` carrying the tool's own message: there is no fourth outcome, stderr is matched
case-insensitively as a SUBSTRING, and `Unknown` is NEVER collapsed into "not registered". The two
failures this rules out are the ones that reach exactly the host class #526 describes — `systemctl
--user is-enabled` under `sudo` printing `Failed to connect to bus: No such file or directory`, and
`launchctl print gui/<uid>/<label>` with no Aqua session failing `Bootstrap failed` / `Could not find
domain for` — both of which are a scope that could not be ASKED, not an empty one.

The systemd absence rule is stated over the CLASS of replies, not over a list of phrasings.
dig-installer recognises a SUPERSET of dig-node's two verbatim phrasings, because the two invoke
different verbs (`is-enabled` here, `cat` there) and systemd words their not-found replies
differently. The widening is bounded by three simultaneous conditions, ALL required: the stderr names
a unit (`unit file` or `no such unit`), AND it says that thing was not found (`no such file` /
`does not exist` / `not found`), AND the invocation exited NON-ZERO with an empty stdout. A not-found
word alone MUST NOT yield `Absent` — a missing `systemctl` binary, an unreadable config and a refused
path all contain one — and a reply that exited ZERO cannot establish absence, because a query
reporting success has not failed to find anything. `Absent` is what licenses the uninstall's removal
claim below, so each condition is a precondition of that claim rather than a hint toward it.

**An uninstall claims removal ONLY from the scopes whose absence it ESTABLISHED.** The success report
MUST name the scopes verified removed, and MUST name any scope it could not read as unverified
(`could not verify <scope> (<reason>)`). It MUST NOT say "every scope" unless every scope answered a
definite absence. When NO scope could be read back, the report MUST state that no scope is confirmed
clear. On the #526 host class — root with no session bus — the per-user scope is exactly the one that
cannot be read, so an unqualified "removed from every scope" was false precisely where an operator
most needed it to be true. If any scope is `Unknown`, removal-completeness MUST NOT be asserted.

**No unit may shadow a system registration.** After a system-scope register, no unpackaged per-user
unit for that service — the invoking user's, or root's own, which a pre-#526 `sudo` install wrote —
may remain on disk. `systemd --user` starts such a unit at the next login alongside the system unit,
and both bind the node's port. The normative requirement is the POSITIONAL outcome: the shadowing
unit is gone.

`ServiceResult.shadowing_units_removed` names every unit **this installer's own sweep** removed, and
MUST name each one it removed. It MAY legitimately be EMPTY even though a shadowing unit was cleared
during the run: the installer enumerates the units on disk BEFORE delegating to the component's
`install`, and a component at v0.70.0 or later clears the stale per-user unit itself while registering
machine-wide, leaving the sweep nothing to do. An empty list is therefore not evidence that a shadow
survived — the disk is — and the field MUST NOT be populated with a removal the installer did not
perform.

**The sweep is licensed by the registration that SERVES, never by the scope that was requested.** A
run that registered nothing — the already-up-to-date path, which leaves the existing registration
untouched — MUST take its settled scope from the units observed on disk
(`svcscope::settled_scope` with the observed `UnitRecord`s): System only when a system unit is present
AND enabled, else User. On the commonest host the sole registration is a pre-#526 per-user unit and
there is no system unit at all, so sweeping on the REQUESTED system scope deletes the only
registration while still reporting `installed: true` — a loss first observable at the next reboot.
That path MUST also report the scope it is actually served from, and `survives_reboot: false` with the
login-gated warning when that is per-user.

**An enabled packaged unit is ADOPTED, not duplicated.** When the apt.dig.net `.deb`'s
`net.dignetwork.dig-node.service` is present AND enabled in the system domain, the installer skips
delegating `install` and reports the adoption: two enabled units for one service is a live port
collision. A present-but-DISABLED packaged unit starts nothing and is no reason to skip.

**Uninstall visits EVERY scope, on every OS, unconditionally** — `svcscope::deregister_scopes` always
returns both. An uninstall that only visits the scope THIS run would have installed into leaves an
earlier run's registration starting a service the user believes they removed. On macOS that means
booting out BOTH `system/<id>` and `gui/<uid>/<id>`. The authoritative signal is the scope-explicit
END STATE, never the verbs' exit codes (an `uninstall` of an absent registration exits non-zero on
some platforms); a scope still holding a registration afterwards is a REPORTED failure, and a scope
that could not be reached is reported even when the end state is clean.

**When EVERY scope's attempt failed, the probe decides — and it MUST be consulted before the error.**
The presence probe queries the SERVICE MANAGER (`systemctl` / `launchctl` / `sc`), never the
component's own launcher, so it remains authoritative precisely on the hosts where every `uninstall`
invocation failed (a missing launcher binary among them). A scope that could not be read back leaves
the state UNKNOWN and MUST be an error naming that scope; a definite absence in EVERY scope
establishes that there was nothing to remove and MUST be reported as success, with every failed
attempt disclosed. Erroring on the failed attempts alone reports trouble on a host that has none.

Per-user artifacts resolve
through the target user (§1.5a); when no target user can be determined under elevation this is
reported loudly rather than cleaned silently.

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

### 2.2a OS-DNS resolver activation is delegated to `dig-dns configure-os` (#627 WU2)

The installer does NOT wire the OS resolver itself. After it registers + starts the dig-dns OS
service, it shells out to the INSTALLED dig-dns binary — `dig-dns configure-os --browser-policy
--json` — and consumes the machine-readable `OsConfigReport`. dig-dns (v0.14.0+) is the SINGLE owner
of the OS-DNS wiring: per OS it applies the split-DNS rule (NRPT on Windows, `/etc/resolver/<tld>` +
a boot-persistent `lo0` alias on macOS, a systemd-resolved / NetworkManager-dnsmasq drop-in on
Linux) + the Chrome/Edge managed DoH policy, FLUSHES the resolver cache, then runs an end-to-end
resolve VERIFY and reports whether `*.dig` resolution went LIVE. This removed the installer's OWN
duplicated per-OS resolver-activation (the pre-#627 `dns::{windows,macos,linux}` copies), whose
missing cache-flush was the root cause of the spurious "needs a reboot" symptom.

- **Absolute-path invocation (security, #565/#657).** dig-dns is invoked by the absolute path the
  installer wrote it to (resolved from the install root / protected bin dir via
  `installed_dig_dns_bin`), NEVER a bare `dig-dns` name resolved through `PATH` — an elevated install
  must not be hijackable by a `PATH`-shadowing binary. dig-dns itself spawns the OS resolver tools
  (`powershell`, `resolvectl`, `dscacheutil`, `killall`, `systemctl`) by absolute path.
- **macOS ordering.** The live `lo0` alias is a functional PREREQUISITE for the service to bind
  `127.0.0.5:53`, so the installer applies it live BEFORE starting the service; `configure-os` (run
  after the service is up, so its VERIFY is meaningful) idempotently re-applies + boot-persists it.
- **Report → restart_required mapping (#562 reuse).** The installer derives the DNS restart signal
  from the report as `reboot_required = applied && !activated` — resolver wiring WAS applied but the
  OS did not go live — and ORs it into the existing `InstallReport.restart_required` verdict (§ the
  Restart-required note), carrying the report's `reboot_reason` through into the install log. It
  trusts dig-dns's authoritative `reboot_required` field AND defensively re-derives the same
  condition, so a report can never wrongly SUPPRESS a needed prompt; it never prompts when NOTHING
  was applied (e.g. the Linux PAC-only path). The EXPECTED outcome on all three OSes is `activated:
  true` ⇒ NO restart prompt.
- **Uninstall symmetry.** The teardown delegates the resolver/browser-policy removal to `dig-dns
  unconfigure-os --json` (marker-scoped — removes both dig-dns's own artifacts and the legacy
  installer's), passing the installed binary's absolute path; an absent binary skips the resolver
  teardown best-effort without blocking the service-registration teardown (the #568 binary-delete
  gate). A machine wired by the pre-#627 installer also has its legacy `lo0`-alias LaunchDaemon torn
  down on macOS.

### 2.3 dig-dns stop-before-replace + the locked-binary fallback (#544)

dig-dns is brought to parity with dig-node/dig-relay's §2 stop-before-write. Because dig-dns ships
NO `stop` verb of its own, the installer stops the OS service it registered — through the service
manager, keyed by the canonical id `net.dignetwork.dig-dns` — rather than delegating to a CLI verb.
On an Install/Update (not on Skip), BEFORE the new binary is written:

1. If no binary exists at the destination (first install) → skip (nothing to stop).
2. Else probe `svc::service_run_state(net.dignetwork.dig-dns)`. Only when it reports **RUNNING** is
   the service stopped (`dns::stop_before_replace` → per-OS `stop_service`: `ScServiceManager` stop
   on Windows, `SystemdServiceManager` stop on Linux, `LaunchdServiceManager` stop on macOS), then a
   bounded poll waits for it to leave RUNNING so its process exits and releases the binary's file
   handle. A Stopped/NotFound/Unknown state → skip.
3. Unlike dig-node/dig-relay (whose stop FAILURE aborts the write with `SERVICE_STOP_FAILED`), a
   dig-dns stop failure is **non-fatal** — it is recorded and the install continues. On **Windows**
   the locked-binary write fallback below is the safety net (a still-running dig-dns just stages a
   reboot-time replace). On Linux there is NO such net: if the service is still running, the write
   fails hard with `ETXTBSY` and the destination is left intact (fail-closed) — the failure surfaces
   loudly rather than corrupting the binary.

**Locked-binary write fallback (all components).** Every component binary is written through
`download::replace_binary`, which is resilient to a destination held open by a running process:

- The ordinary case writes the bytes in place (`WriteOutcome::Replaced`).
- On Windows, a running executable cannot be opened for writing, so an in-place overwrite fails with
  a sharing violation (`ERROR_SHARING_VIOLATION`, "os error 32" — the exact reported #544 failure).
  This is an OPEN-time failure (`File::create`), raised BEFORE any truncation, so the destination is
  provably untouched. ONLY then is the new binary STAGED beside the destination and an atomic replace
  scheduled for the next reboot via `MoveFileExW(staging, dest, MOVEFILE_REPLACE_EXISTING |
  MOVEFILE_DELAY_UNTIL_REBOOT)` (`WriteOutcome::ScheduledForReboot`); the destination is NEVER left
  half-written and the old binary keeps running until the reboot applies the swap. A WRITE-time error
  — including `ERROR_LOCK_VIOLATION` (33) — is NOT treated as recoverable: reaching it means the file
  was already opened + truncated, so it propagates as a hard failure rather than staging over a
  half-written destination. The caller LOUDLY logs that a **restart is required** to finish the update.
- On Linux, opening a RUNNING binary for write fails hard AT OPEN with `ETXTBSY` (errno 26): the write
  aborts with the destination intact (fail-closed, never half-written), and this reboot-time staging
  fallback does NOT apply — it is a **Windows-only** guarantee. (A genuine atomic write-temp +
  `rename(2)` replace on unix is a RECOMMENDED FUTURE follow-up, separately ticketed.)

This covers all three run-states idempotently: **running-as-service** (stopped at step 2 → in-place
write), **running-as-foreground-process** (step 2 skips — no registered running service — so on
Windows the write fallback stages a reboot-time replace, while on Linux the write fails closed with
`ETXTBSY`, dest intact), and **not-running** (skip → in-place write).

## 3. `InstallReport` (the `--json` payload)

Stable, versioned (`schema_version`) JSON shape emitted by `--json` on success:
`{schema_version, installer_version, target, dry_run, components[], path, service, relay, dns,
scheme, firewall, beacon, autostart, installed[], cli_path_checks[], ready, failures[]}`. See `src/lib.rs` doc
comments on `InstallReport`/`ComponentResult`/`PathResult`/`ServiceResult`/`RelayResult`/
`dns::DnsInstallResult`/`scheme::SchemeResult`/`firewall::FirewallResult`/`beacon::BeaconResult`/
`pathcheck::CliPathCheck` for the exact field set; every boolean field has a paired human-readable
`*_note` — no field is ever silently omitted to signal failure. `firewall`/`beacon` are `None` when
`open_firewall`/`auto_update` are off (§1.4/§1.5); `autostart` is `None` when `dig_app_autostart` is
off or dig-app was not selected/resolved (§1.11) — distinct from a present-but-`applied: false`
result, so a caller can tell "declined" apart from "attempted and failed". `ready`/`failures` are
the aggregate readiness verdict (§4.2) — the firewall rule and the scheme handler are best-effort
and never gate `ready`; the beacon's scheduler registration DOES gate `ready` (§1.5, like
dig-node/dig-relay's own service registration). The `--json` envelope's `ok` mirrors `ready`.

### 3.1 Scope + re-arm fields (dig_ecosystem#526/#1863)

| field | meaning |
|---|---|
| `service.scope` / `relay.scope` | `system` or `user` — the domain this run registered in (§2.1a) |
| `service.survives_reboot` / `relay.survives_reboot` | will it start after a reboot with NOBODY logged in? `false` for every per-user registration by design, and `false` when the component predates `--scope` |
| `service.scope_note` / `relay.scope_note` | the plain-language reason behind `survives_reboot` — never silent |
| `service.shadowing_units_removed` | per-user unit files this run deleted because they would shadow the system registration (§2.1a) |
| `autostart.disposition` | `register` / `skip-headless` / `skip-no-target-user` (§1.11) |
| `rearmed_registrations[]` | `{label, applied, note}` per engine-service registration the #565 migration removed and this run restored (§3.11a) |

## 3.11a Restoring a registration the migration removed (dig_ecosystem#1854/#1863)

The §7.5 legacy-root migration deregisters every privileged registration whose binary resolves under
a legacy user-writable root, INDEPENDENT of the current plan. Each component's install step
re-registers only when the plan SELECTS that component. A re-run that DECLINES a component therefore
MUST restore the registration the migration vacated: declining a component installs nothing, it never
means "uninstall what is already there".

This applies to the auto-update beacon AND to all three engine services, under one rule
(`rearm::rearm_after_migration`), whose guard order is normative:

1. **plan selects the component** → do nothing; its own install step registers it fresh.
2. **the migration did not deregister it** → do nothing; this host's registration was never touched.
3. **this run's privileged root is not the protected root** → do NOTHING and say why: creating a
   machine-wide privileged registration at a caller-selected `--bin-dir` path is the §7.5 escalation.
4. otherwise **register from the protected root** (never the legacy path, whose binary the migration
   deleted) and REPORT the outcome.

A restored registration is a reversible privileged action: it is recorded for rollback (§3.11) and
deregistered by canonical id if a later step fails, and the report's claim is RETRACTED when that
happens. A re-arm that FAILS is reported with the component's own consequence and the EXACT command
that restores it (§5) — never a generic sentence.

The audited privileged set (`regaudit::privileged_regs`) is all three services plus the beacon on
EVERY OS, matching `paths::is_privileged_component`.

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
the plan registers an OS service (dig-node / dig-dns / dig-relay), the auto-update beacon's daily
scheduler artifact (dig-updater, §1.5), or writes the `dig.local` hosts entry
(`InstallPlan::requires_elevation()`). The check runs **FIRST**, before resolving/downloading/
writing anything: an un-elevated run of such a plan fails immediately with `NOT_ELEVATED` (exit 11)
and leaves NO partial state. It ALSO trips when a CLI-only install writes into the admin-only
protected root (#565, §1.6) — so a Windows CLI-only install (which lands in `%ProgramFiles%\DIG\bin`)
elevates, while a unix CLI-only install into the user root (§1.6) does not. A `--dry-run`, or a CLI-only
install into a `--bin-dir` override or the unix user root, never trips the gate. The per-OS
elevation probe is `elevation::is_elevated` (Windows `net session`; Unix `id -u`, where `id` is
resolved to an ABSOLUTE path from a fixed set of trusted system directories — never `$PATH` — so a
`$PATH`-shadowed `id` can never flip the write-then-exec gate that trusts it, #638); the pure
decision + per-OS remedy is `elevation::gate` (unit-tested). The GUI enforces the same gate before
its first write.

## 4.1a GUI write-then-exec invariant — never exec a user-writable binary under elevation (#610/#637)

The GUI install pipeline (`gui/app/src-tauri/src/install.rs::run`) both WRITES binaries and, in
places, EXECUTES them. Under elevation this is a local-privilege-escalation surface: a lower-
privileged process could swap a binary in the write→exec window and inherit the freshly-granted
privilege. The invariant (established for Windows in #610, generalized to unix in #637 as the
foundation for the mac/linux GUI elevation #638/#639) is:

- **Elevation gate FIRST.** `run()` resolves the plan and decides `needs_elevation`
  (`InstallPlan::requires_elevation` OR the digstore placement lands in the protected root) BEFORE
  any write; a required-but-absent elevation fails closed with `install://error` and no partial state.
- **The digstore write+exec dir comes SOLELY from the vetted #565 routing.** `run()` resolves the
  directory it unpacks AND runs digstore from via `digstore_write_exec_dir` → `InstallPlan::bin_dir_for`
  — the admin-only protected root on Windows (`%ProgramFiles%\DIG\bin`), the unix user root (§1.6,
  i.e. the root-owned `/opt/dig/bin` elevated and `~/.dig/bin` not; digstore runs AS the user — not an
  escalation).
  NEVER an ad-hoc user-writable path. This routing is test-locked (a revert to a hardcoded user dir
  fails a unit test).
- **The `digstore --version` verify (Phase 6) never execs a user-writable binary under elevation.**
  The exec-verify runs in-process only when it is safe — `should_exec_verify`: the process is
  UNELEVATED, OR the binary sits in the root-owned protected root (unswappable). Otherwise (an
  elevated run whose binary is user-writable — the unix user root under elevation) it is DEFERRED to
  the unelevated GUI; the privileged process never execs the user root's `digstore`.

  The predicate is `bin_dir == protected_bin_dir()`, i.e. it turns on the DIRECTORY's privilege, not on
  its name — so it tracks the §1.6 user root wherever it currently points. That matters concretely: an
  elevated unix GUI run routes digstore to the protected root, so the exec-verify is PERMITTED there
  rather than deferred. The deferral remains load-bearing for a `--bin-dir` override, and was what
  stopped the high-integrity process from executing a binary any `admin`-group member could have swapped
  while `/usr/local/bin` was briefly the elevated root (§1.5).
- **Association cache-refresh tools resolve to ABSOLUTE paths.** `register_dig_association` (per-user,
  unelevated) runs `update-mime-database` / `gtk-update-icon-cache` from a fixed allowlist of trusted
  system directories (`/usr/bin`, `/bin`, `/usr/sbin`, `/sbin` — NOT `/usr/local/bin`, §7.5) via
  `resolve_system_tool`, never as a bare
  command name resolved through `$PATH` — removing the root-`PATH`-hijack / pwnkit-class surface if the
  path is ever reached under elevation. A missing tool fails soft (the refresh is best-effort). The
  resolver is `elevation::resolve_system_tool` (the single source of truth, in the `dig-installer`
  library; the GUI no longer keeps a duplicate).

## 4.1b Linux GUI elevation — one-shot `pkexec` root relaunch (#638)

The Linux GUI ships as an unelevated `.AppImage`; unlike Windows (which elevates itself at launch via
a `requireAdministrator` manifest) it must obtain privilege at install time. When the plan
`needs_elevation` and the GUI is not already root, it relaunches its OWN executable as root for the
privileged step ONLY, keeping the WebView unelevated:

- **Mechanism.** `pkexec <abs-installer> __dig-elevated-install`, spawned via
  `elevation::relaunch_elevated`. `pkexec` falls back to polkit's built-in
  `org.freedesktop.policykit.exec` action, so NO custom `.policy` file need be pre-installed (portable
  from a read-only AppImage). The root child runs the headless privileged install
  (`run_elevated_privileged_install_from_stdin`) — `dig_installer::run_report`, routing every privileged
  binary to the protected root `/opt/dig/bin` — and exits; it NEVER starts the WebView (no GUI ever runs
  as root) and NEVER execs a user-writable binary. The latter holds BY PLACEMENT: the root child
  installs into the root-owned protected root (§1.6, §7.5) and execs only from there. It is NOT a
  per-exec check, and it would NOT hold if the root child were ever given a user-writable `--bin-dir`.
- **The selection is streamed over the child's STDIN, never a plan file.** There is no shared-namespace
  file, so the plan-file TOCTOU class is ELIMINATED (a co-located local user has nothing to pre-seed,
  symlink-swap, or race). The payload is a small JSON `InstallOpts` (a component-id → bool map + the
  chosen install path); it is non-secret AND the privileged routing is independent of it (every
  privileged binary routes to `/opt/dig/bin` via `bin_dir_for`, never the user path), so it can only
  toggle which official components install.
- **AppImage-aware relaunch target.** The re-exec target is `elevation::relaunch_target($APPIMAGE,
  current_exe)`: under an AppImage, `current_exe()` points inside the FUSE mount, which is NOT readable
  by root (`allow_other` off) — so root's `pkexec` could not exec it. `$APPIMAGE` (the absolute path of
  the `.AppImage` FILE, a normal root-readable on-disk file) is preferred, so the AppImage bootstrap
  re-mounts as root and runs the binary with the token. A bare (non-AppImage) binary uses `current_exe`.
- **Dropped-privilege verify.** The `digstore --version` verify (Phase 6) runs in the still-unelevated
  GUI parent — a genuinely dropped-privilege context — because `pkexec` elevates only the child, so the
  §4.1a invariant holds (no root-exec of the §1.6 user root's `digstore`).
- **pwnkit (CVE-2021-4034) immunity — structural.** The argv is built by `elevation::pkexec_argv`:
  a real `argv[0]` (`std::process::Command` guarantees `argc >= 1`), a fixed 2-element argv (`[<abs
  installer>, <token>]`, no plan argument), an ABSOLUTE program path (a relative path returns `None`,
  fail-closed), no shell, no user-controlled `argv[0]`; and `pkexec` itself resets the environment
  (sanitised `PATH`, `LD_*` stripped). No setuid shim is ever used.
- **Fail-closed.** `pkexec`/polkit absent (not found under the trusted system dirs) → the install
  refuses BEFORE any write with `elevation::pkexec_unavailable_message` ("install polkit, or run
  `sudo dig-installer` in a terminal"); a dismissed auth prompt (non-zero child status) is surfaced as
  an error. Either way: NO partial state, NO setuid workaround.

## 4.1c macOS GUI elevation — one-shot `osascript` root relaunch (#639)

The macOS GUI ships as an unelevated `.app` inside a `.dmg`; like Linux (and unlike Windows, which
elevates itself at launch) it must obtain privilege at install time. When the plan `needs_elevation`
and the GUI is not already root, it relaunches its OWN executable as root for the privileged step
ONLY, keeping the WebView unelevated:

- **Mechanism.** `osascript -e 'on run argv' -e '<do shell script … with administrator privileges>'
  -e 'end run' <abs installer> __dig-elevated-install <abs plan file>`, spawned via
  `elevation::relaunch_elevated_macos`. `with administrator privileges` routes through Authorization
  Services (`security_authtrampoline`), which renders the native admin-auth dialog. This is the
  standard macOS one-shot escalation and — critically — **works UNSIGNED**: there is NO persistent
  SMJobBless/SMAppService helper daemon (which WOULD require Developer ID code-signing, #536), so
  elevation is NOT gated on #536. The root child runs the headless privileged install
  (`run_elevated_privileged_install_from_file`) — `dig_installer::run_report`, routing every
  privileged binary to the protected root `/opt/dig/bin` — and exits; it NEVER starts the WebView (no
  GUI ever runs as root) and NEVER execs a user-writable binary. The latter holds BY PLACEMENT: the root child
  installs into the root-owned protected root (§1.6, §7.5) and execs only from there. It is NOT a
  per-exec check, and it would NOT hold if the root child were ever given a user-writable `--bin-dir`.
- **The selection is handed over a PRIVATE temp file, not stdin.** Authorization Services does NOT
  inherit the caller's stdin or environment, so the Linux stdin channel (§4.1b) is unavailable on
  macOS. The safest equivalent is used: the JSON `InstallOpts` is written to a `0600` file inside a
  freshly `mkdtemp`'d `0700` directory (via `tempfile`, which sets `0700` on unix) in the per-user
  temp location, created `O_EXCL` (no pre-existing object to hijack); the root child reads it
  `O_NOFOLLOW`. A DIFFERENT unprivileged local user cannot traverse the `0700` dir and the file name
  is unpredictable, so the plan-file TOCTOU/symlink class is closed. The plan is non-secret (a
  component-id → bool map + the chosen install path) AND the privileged routing is INDEPENDENT of it
  (every privileged binary routes to `/opt/dig/bin` via `bin_dir_for`, never the user path), so it can
  only toggle which official components install — never redirect a privileged write. The private dir
  is removed when `relaunch_elevated_macos` returns.
- **Relaunch target.** A macOS `.app` binary lives on a normal root-readable path (`/Applications`,
  `~/Applications`, `~/Downloads`), so `current_exe()` is re-exec'd directly — no FUSE/`$APPIMAGE`
  indirection is needed (contrast the Linux AppImage, §4.1b).
- **Dropped-privilege verify.** The `digstore --version` verify (Phase 6) runs in the still-unelevated
  GUI parent — a genuinely dropped-privilege context — because `osascript` elevates only the child, so
  the §4.1a invariant holds (no root-exec of the §1.6 user root's `digstore`).
- **Command-injection immunity — structural.** The argv is built by `elevation::osascript_argv`: the
  three `-e` lines are FIXED literals; the three data tokens (the absolute installer path, the fixed
  elevation token, the absolute plan-file path) are passed as `osascript` command-line arguments and
  reach the script ONLY as `item N of argv`, each wrapped in AppleScript `quoted form of` (a shell-safe
  single-quoted string) before it reaches the `/bin/sh -c` that `do shell script` invokes. No path is
  ever interpolated into the script source, there is no string concatenation of external input, and no
  shell metacharacter reaches the shell unquoted. Both paths MUST be ABSOLUTE (a relative path returns
  `None`, fail-closed) — the child is exec'd by a root shell with an unknown cwd.
- **Fail-closed.** `osascript` absent from the trusted system dirs → the install refuses BEFORE any
  write with `elevation::osascript_unavailable_message` ("re-run with `sudo dig-installer`"); a
  dismissed auth dialog (AppleScript error `-128`, a non-zero child status) is surfaced as an error.
  Either way: NO partial state.
- **#536 (Developer ID code-signing) is NOT a blocker.** Elevation works unsigned; Gatekeeper's
  first-open warning is a distribution-polish issue (bypass via right-click → Open) deferred to #536.

## 3.10 Whole-stack `uninstall` (#568)

`--uninstall` is a first-class, standalone command that removes the ENTIRE DIG install and leaves
**zero residue** — one orchestration over the previously-piecemeal teardown flags. It runs the fixed
ordered sequence (services/schedulers first so a live service never points at a deleted binary):

1. **services** — stop + deregister dig-node, dig-relay, dig-dns. A component whose LAUNCHER binary is
   absent is not a failure: the service manager is queried BY ID, so "no such service" is confirmed
   absence (the desired end state) and a service that IS registered is deregistered by id;
2. **user-agent** — stop the running user-session processes (`dig-app`, `dign`) and remove dig-app's
   per-user login autostart. It precedes every deletion because Windows refuses to delete a running
   image (`os error 5`). A process that is not running is success;
3. **beacon** — remove the auto-update scheduler registration;
4. **scheme** — unregister the dig/chia/urn handlers (DIG-owned only);
5. **network** — remove the `dig.local` hosts entry + the peer firewall rule;
5a. **tls-trust** — revert the DIG TLS trust anchor(s) recorded in the trust-manifest ledger (§1.12),
   then remove the privileged TLS root. Strictly DIG-owned scope (only the anchors this install's
   ledger recorded, addressed by SHA-1 thumbprint / recorded anchor-file path) and idempotent (an
   already-absent anchor / root is success). A left-behind trust anchor keeps the machine trusting a
   private CA after DIG is gone, so a failed revert makes the run NOT complete;
6. **login-path** — remove the system-wide login-`PATH` fragment;
7. **msi** — remove every MSI-installed DIG product (§3.10.1). Before the binaries, because
   `msiexec /x` runs the product's own uninstall sequence from the product's own files;
8. **binaries** — delete ALL installed binaries across the (deduplicated) bin roots + the Windows ARP
   entry. The running installer image cannot delete itself, so it is scheduled for deletion at the
   next reboot with `MoveFileExW(path, NULL, MOVEFILE_DELAY_UNTIL_REBOOT)`;
9. **forcelist** — unconfigure the browser-extension forcelist (DIG entry only).

The bin roots are deduplicated before the walk: on Windows the default bin dir IS the protected bin
dir, so an undeduplicated list visits every path twice and reports every leftover twice.

### 3.10.1 MSI-installed products (`msiexec`)

A DIG component may be installed from a Windows Installer package (dig-node publishes
`dig-node-<ver>-windows-x64.msi`). Such a product MUST NOT be removed by deleting its files: the
Windows Installer registration outlives them, leaving a ghost Add/Remove-Programs entry, a broken
repair/modify, and an upgrade that believes an older version is still present.

- **Discovery.** The ProductCode is resolved from the package's **stable UpgradeCode** — a DIG-owned
  constant compiled into the package (`dig-node`: `{7E9B1C2D-3A4F-4B5C-8D6E-1F2A3B4C5D6E}`) — via the
  Windows Installer `UpgradeCodes` index under `HKLM\SOFTWARE\Classes\Installer\UpgradeCodes`, whose
  per-UpgradeCode subkey holds the packed ProductCodes installed for it. Matching by `DisplayName` is
  NOT the primary mechanism; a conjunctive Add/Remove-Programs scan (DIG publisher AND a known DIG
  display name AND `WindowsInstaller=1` AND a GUID-shaped key name) is a fallback only.
- **Removal.** `msiexec.exe /x <ProductCode> /qn /norestart`, with `msiexec.exe` resolved to its
  absolute `System32` path (never `PATH`) and the arguments passed as an argv (never a shell string).
  The ProductCode is a parsed type that can only hold a canonical braced GUID, so a value carrying a
  path or a second command cannot reach the command line.
- **Exit codes.** `0` removed; **`1605` (product not installed) is SUCCESS** — the desired end state,
  and what an idempotent second run sees; `3010`/`1641` removed with a reboot required (success, and
  reported as such); anything else is a failure.
- **Proof.** A product still registered with Windows Installer after the step is reported as
  **residue**, so completeness is judged against the Installer database rather than the step's own log.

**The residue scan and the binary deletion both cover an interrupted install's abandoned
write-siblings.** A write backs the destination up (`.<exe>.dig-bak-<pid>`) and may stage bytes for a
reboot-time replace (`.<exe>.pending-<pid>`); both are tagged with the WRITING process's pid, so a run
killed before it cleans up leaves a file no later run ever names again. Scanning only `<root>/<exe>`
therefore reported `residue: []` with a full copy of every replaced binary still in the install root.
Matching is by the writer's own tags and is scoped to a known component's exe name, so a file this
installer never wrote is neither reported nor removed; a component held back by a failed service
teardown keeps its backup, so an elevated re-run still has something to restore.

It then re-scans and reports any residue. The result is a structured `UninstallReport { steps:
[{id, ok, note}], residue: [..], dry_run }`; `complete()` is true iff every step reached its
end-state AND the post-run inventory found nothing left. **Invariants:** idempotent (a second run is
a clean no-op — "already absent" is success, never an error); never deletes pre-existing org policy
the installer did not create (each step stays DIG-scoped). The ordering + residue accounting is a
pure core over an injected `UninstallActions`; `SystemActions` wires the real teardown. `--json`
emits `{ ok: report.complete(), result: <UninstallReport> }`; a real (non-dry-run) incomplete run
exits non-zero so a caller can re-run elevated.

## 3.11 Install hardening — ARP, auto-recovery, rollback (#573)

The install behaves like a well-behaved native package:

- **Add/Remove Programs (Windows).** An `HKLM\…\Uninstall\DIG_Network` entry (`DisplayName` = "DIG
  Network", `DisplayVersion`, `Publisher`, `InstallLocation`, `NoModify=1`, `NoRepair=1`) whose
  `UninstallString` = `"<installer>" --uninstall` — the ARP Uninstall button runs the §3.10
  whole-stack uninstall. `QuietUninstallString` mirrors it: the teardown is fully
  non-interactive, so winget/PowerShell/MDM can drive it unattended. The entry is removed as part of `--uninstall`. The persisted installer and
  the `UninstallString` are an elevated-exec pointer, so both are pinned to the admin-only protected
  install root (never a user-chosen `--bin-dir`), and the machine-wide entry is written ONLY when
  that root is verified owner-secure — never planting an elevated pointer where an unprivileged user
  could repoint it.
- **Service auto-recovery (Windows).** Each installed service is configured via `sc failure` to
  auto-restart on crash: `reset=86400` (daily) + `actions=restart/5000/restart/5000//5000`.
- **Install rollback (WIRED into the install flow).** `run_report` threads a `RollbackGuard` through
  the install: each privileged step records itself the instant it succeeds — a *freshly written*
  binary at a path that had no prior occupant (`FileCreated`), a binary that **overwrote** a
  pre-existing one (`FileReplaced { path, backup }`), a *freshly* registered service
  (`ServiceRegistered`, `Install` only — never an update/skip of a pre-existing service), the
  registered URL-scheme handlers (`SchemeRegistered`), and the ARP entry (`ArpEntryWritten`). If ANY
  step returns an error before the install completes, the guard reverses the recorded steps in
  **LIFO** order BEFORE the error propagates — never a half-written install (the #544 half-write
  lesson). A fully-successful run `commit`s the guard so the steps stand (and the overwrite backups
  are deleted).
- **Rollback returns the machine to its PRIOR state — never one worse (dig_ecosystem#1914/#1915).**
  A rollback MUST NOT delete a binary the install merely OVERWROTE. Before each overwrite the write
  path preserves the destination's prior bytes in a protected sibling backup; on rollback a
  `FileReplaced` action **restores** those bytes (`FileCreated` deletes the new file as before, a
  service is deregistered by canonical id, scheme handlers are unregistered, the ARP entry removed).
  A component whose download was **skipped** because it was already up to date records NO reversible
  action — a later failure's rollback leaves untouched a binary this install never wrote. If a
  replaced file cannot be restored (its backup is missing), the current file is LEFT in place and the
  failure reported — an unrestorable file is strictly better than a working binary removed. This
  guarantee holds specifically on a **reinstall over an existing install**, the population least able
  to absorb losing working binaries. On a locked (running) Windows destination the update is staged
  for a reboot and the *staging* file — not the still-running old binary — is what a rollback removes.
- **The backup is adopted into privileged ownership at creation (§7.x / #1910).** A restore promotes
  the backup onto the live, privileged binary path, and — unlike a fresh install — is NOT followed by
  dig-node's #565 service-registration refusal that normally catches a user-writable SYSTEM binary. So
  the backup MUST carry the same privileged ownership as an installed binary the moment it is created:
  `back_up_existing` adopts it (`adopt_placed_file`, a no-op off Windows / outside the protected root)
  right after the copy, and **fails closed** (aborting the write with `dest` untouched) if it cannot —
  never staging a backup a rollback could promote into a user→SYSTEM write over a SYSTEM-executed
  binary (the §565/#1910 LPE class).
- **Rollback is best-effort + idempotent:** an already-absent target is a clean success, and a single
  failed undo does not strand the earlier reversals — rollback continues and surfaces the failure in
  `RollbackReport { reversed, failures }` (`clean()` iff no undo failed).

Post-install health is the readiness verdict's job (§4.2), not this module's. All value/argument
builders + the guard core are pure + unit-tested; the registry/SCM writes are the thin, best-effort
I/O layer (a hardening failure logs but never fails an otherwise-successful install).

## 4.2 Readiness verdict — fail loud (#493)

A run does not report success merely because downloads succeeded. `InstallReport` carries an
aggregate `ready: bool` + `failures: Vec<String>`: **`ready` is `true` only when every selected
component installed AND its service is verified RUNNING**. The CLI prints `✓ DIG is ready` only when
`ready`; otherwise it prints `✗ DIG is NOT ready` with each failure + the remedy and exits
`INSTALL_INCOMPLETE` (exit 12). `--json` still emits the full report with `ok:false`. The GUI emits
`install://error` (never `install://done`) when not ready. A `--dry-run` installs nothing, so it is
trivially `ready`.

**Reboot survival gates readiness for a system-required daemon engine (#1984).** A machine DAEMON
engine (`dig-node`, `dig-relay`) registered on an **elevated, default-path** install MUST be
registered at machine-wide (system) scope so it starts on boot with nobody logged in; a per-user
registration on such an install (the #526 defect — `dig-node`'s pre-`--scope` `install` preferred a
`systemd --user` unit, which is loaded only inside a login session) is **NOT ready**, with a failure
naming the scope/reboot-survival inadequacy — never `ready: true`. Concretely: for `dig-node`/
`dig-relay`, when the run is elevated AND `!has_custom_bin_dir()` AND the service `installed` but its
`survives_reboot` is false, `evaluate_readiness_when` emits a failure. This closes the false-ready in
which a service running RIGHT NOW (so `health_ok`) but doomed at the next reboot was reported ready.
Three cases are deliberately EXEMPT: (a) an **unelevated** install — a per-user registration is the
best a non-root run can achieve and the person who ran it chose it; (b) a **caller-chosen
`--bin-dir`** — an elevated machine daemon pointed at a user-writable dir is the #565 user→root
escalation, so it is intentionally forced to user scope and reported via `scope_note`, not failed;
(c) the per-user **`dig-app` tray agent** — login-gated by design, tracked in `autostart` (§1.5),
never an engine block. `dig-dns` is not gated here because its install refuses without elevation and
always registers into `/etc/systemd/system` (`multi-user.target`), so it can never be the
registered-but-user-scope shape.

**Restart-required (#562).** `InstallReport` also carries `restart_required: bool`, set true when
ANY component's write was reboot-deferred (its running binary was locked, so the new version is
staged for the next reboot). It is set from EVERY component site (digstore, digs, dign, dig-node,
dig-dns, digd, dig-relay, dig-updater[-worker]), not just one path. It is ALSO set for dig-dns's
DNS-activation case (#627 WU2): when `dig-dns configure-os` wired the OS resolver but the end-to-end
verify shows it did not go live before a restart (`applied && !activated`), the same flag is ORed in
with the report's reason (§2.2a) — expected to stay false, since `configure-os` flushes + verifies so
resolution is normally live at install. When set on an otherwise-ready
install the CLI verdict reads **RESTART REQUIRED** instead of "DIG is ready" (a reboot-deferred step
must not read as fully done), the flag rides the `--json` record, and the GUI Finish step shows an
accessible restart-required notice (detected from the streamed verdict line).

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

## 5.1 Windows executable icon (dig_ecosystem#2917)

The Windows `dig-installer.exe` MUST carry the branded DIG mark as its application icon, so the
shipped binary is identifiable in Explorer, the taskbar and the Alt-Tab switcher.

* The icon is `assets/dig.ico`, vendored verbatim and byte-pinned at sha256
  `2f0fb11a1254fc9275248dc340b7aa9c7236484a9531f8aaad2e4bcdf8900096`. `scripts/check-icon.sh`
  asserts the pin and MUST run on every pull request. The bytes MUST NOT be re-saved, re-exported
  or re-encoded: the identical file is vendored by sibling DIG repos against the same literal.
* It carries ten frames — 16, 20, 24, 32, 40, 48, 64, 96, 128 and 256 pixels — with hardened alpha
  at 32 pixels and below so the D's counter stays open at taskbar size.
* `assets/dig.rc` declares it as icon ordinal `1` and MUST remain the only `ICON` statement in that
  file: Windows renders the lowest-ordinal icon resource as the executable's icon.
* `build.rs` compiles the resource via `embed-resource` and MUST fail the build when compilation
  does not succeed; a silently unbranded binary is the defect this step exists to prevent.
* The `asInvoker` manifest (§4.1) is embedded through the linker and is deliberately NOT declared
  in `assets/dig.rc`, so neither resource can displace the other. Both MUST be present in the
  linked binary.

macOS (`.icns`) and Linux (`.desktop` + hicolor PNG) icons, and the icons carried by the generated
`.msi`/`.pkg`/`.deb` packages, are out of scope here and are specified separately.

## 6. GUI (`gui/app`) architecture note

The GUI is a Tauri 2 desktop wizard (Welcome → License → Components → Install → Done). Its `digstore`
CLI install remains a self-contained embedded/staged payload (no network call for that one
component — see `gui/app/src-tauri/src/install.rs` phases 1–6). Every OTHER selected component
(`dig-node`/`dig-dns`/`dig-relay`/`browser`/the auto-update beacon, §1.5) is installed by delegating
to this repo's OWN `dig_installer::run_report` (the same thin-shim orchestration the CLI uses,
including the §2 stop/write/start lifecycle and the beacon's own scheduler-registration delegation)
via a pure `plan_from_selection(selected) -> InstallPlan` mapping (`install.rs`) — the GUI never
reimplements release resolution, download, service, or scheduler control.

The GUI plan MUST NOT set a user-chosen custom `bin_dir`: it sets `bin_dir = paths::default_bin_dir()`
so `has_custom_bin_dir()` is false and every privileged/service-executed component routes through the
admin-only `protected_bin_dir()` (§1.6), re-arming the §5 migration + fail-loud ACL verify + binPath
audit on the GUI path exactly as on the CLI. The GUI-owned `digstore` CLI is routed the SAME way: the
pipeline places AND executes it via `bin_dir_for("digstore", os)` — the admin-only
`protected_bin_dir()` (`%ProgramFiles%\DIG\bin`) on Windows, the §1.6 user root on unix
(the root-owned `/opt/dig/bin` under elevation, `~/.dig/bin` otherwise — `paths::default_bin_dir()`, never a
hardcoded home-relative path). Because the elevated GUI both WRITES and EXECUTES digstore
(`digstore --version`, Phase 6),
a user-writable location would be a write→exec local privilege escalation under the high-integrity
process (medium-IL malware swaps the exe in the window and inherits the user's freshly-granted
Administrator) — so digstore is NOT a "never a privilege-escalation vector" once the process is
elevated. digstore's protected-root placement on Windows is itself an elevated write, so a
digstore-only Windows GUI run also requires elevation (matching the CLI). A user-chosen install path
receives only the NON-executable install artifacts (shell completions, example store, the `.dig`
icon) — data this process never executes. A service/executed binary in a user-writable dir under a
LocalSystem service / SYSTEM beacon task is the user→SYSTEM local privilege escalation (#565/#610).
On Windows the GUI's embedded manifest requests `requireAdministrator` (not
`asInvoker`) so the elevation needed to write the protected root + register services is obtained up
front via a UAC elevation of the same interactive user (the `elevation::guard` SYSTEM check still
rejects a service/`psexec -s` relaunch); on macOS/Linux the pre-install `elevation::guard` fails loud
with a "re-run elevated" remedy rather than performing a silent unprivileged install of a privileged
component. The pre-install elevation decision is `InstallPlan::requires_elevation` (which also covers
the default-on SYSTEM auto-update beacon) OR-ed with the GUI's own digstore protected-root placement
(so a digstore-only Windows run still elevates), not a hand-maintained component-id list.

The Done screen exposes two footer actions: **Open Documentation** (secondary) and **Close**
(primary, `bridge.js` `closeWindow` → Tauri `getCurrentWindow().close()`, the same window op the
title-bar close control uses), so the user always has a one-click exit on the final step (never trapped).
The footer wraps responsively on narrower windows via `flex-wrap`. The window opens at 1080×720.

### 6.0 Internationalization (#642)

The GUI is internationalized with **react-intl** (`src/i18n/`). An `I18nProvider` wraps the app and
supplies the active locale via context + an `IntlProvider`; the canonical **14-locale** set
(`en, zh-CN, zh-TW, ko, ja, ru, es, pt-BR, fr, de, tr, vi, id, hi` — a cross-repo canon, CLAUDE.md
§6.6 / the `canonical` skill) is registered in `locales.js` with each locale's endonym display name.
The initial locale is a persisted choice (`localStorage`) → the first `navigator.languages` tag that
maps to a supported locale (exact → base-language → regional-variant matching) → English. A
`LanguageSelector` in the app shell footer switches + persists the locale. Copy uses react-intl's
inline `defaultMessage` pattern (the English source IS the extractable catalog); non-English catalogs
fall back to the English source until supplied, and missing-translation errors are swallowed so all
14 locales are selectable today. Brand/scheme literals ($DIG, XCH, DIGHUb, `chia://`/`dig://`,
store/capsule) are preserved verbatim by the message formatter.

### 6.1 No flashing console windows (Windows)

Every non-interactive child process the installer spawns is launched with the Win32 `CREATE_NO_WINDOW`
(`0x08000000`) creation flag so no console window flashes on screen or steals focus during an install.
This includes the library crate's Windows console helpers (`sc`, `net`, `netsh`, `powershell`, `icacls`,
`whoami`, `cmd`), delegated `dig-node`/`dig-dns`/`dig-updater` verbs, and the GUI backend's internal
version-probe spawns (checking the bundled digstore binary version during startup and verification
post-install). This is applied consistently through the single `proc::HideConsole::hide_console()` helper
(a no-op on non-Windows targets) rather than a flag sprinkled at each call site.

The flag suppresses only the console: stdio capture (`.output()`) and child exit codes are unchanged.

## 7. Version-aware updater (issue #309)

`dig-installer` is not just an installer — a bare re-run is a version-aware UPDATER: for each of
the four tracked components (`digstore`, `dig-node`, `dig-dns`, `dig-updater` — `digs`/
`dig-updater-worker`/`dig-relay`/the DIG Browser are out of scope, see §7.3), it detects what's
already at the resolved destination, compares it
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
   | present, parses, newer  | installed > latest    | **Skip** (never downgrade) — reported as AHEAD of the latest release, never as "up to date", and the summary names `--force-reinstall` as the way back onto a published build |
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
- **dig-updater** (§1.5): Install/Update downloads + overwrites both the `dig-updater` and
  `dig-updater-worker` binaries, then registers the scheduler (`beacon::register`) — idempotent, so
  it runs on every Install/Update/Skip alike, self-healing a scheduler that was somehow removed
  without the installer's knowledge even on an otherwise-Skip run.

Every decision is logged as a single human-readable line (`UpdateDecision.summary`, e.g. `"v0.14.0
→ v0.15.0 (update)"`, `"v0.15.0 (up to date)"`, `"not installed → install v0.15.0"`) and recorded on
the component's `ComponentResult` (`update_action: "install"|"update"|"skip"`,
`previous_version: string | null`) — both the CLI run summary and the `--json` payload surface it,
so re-running the installer idempotently reports exactly what changed.

### 7.3 Scope

Only `digstore`/`dig-node`/`dig-dns`/`dig-updater` are update-tracked (`update::tracked_components`).
`digs`/`dign`/`digd` (the alias binaries, §1.1) and `dig-updater-worker` (the beacon's sibling, §1.5)
always re-download alongside their primary regardless of their own on-disk state — a known, accepted
scope limit (each shares its primary's version pin and is cheap to refetch). `dig-relay` and the DIG
Browser installer are opt-in, advanced/one-shot artifacts and are not update-tracked at all;
selecting them always (re)installs.

### 7.4 GUI preview

The Components screen previews Install/Update/Skip status for `dig-node`/`dig-dns` (NOT `digstore`
— its GUI install is the bundled/embedded payload from §6, with no network "latest" to diff
against; its version is shown separately via the existing bundled-version badge) via the
`component_update_status` Tauri command, calling `update::check_updates` with the real GitHub
resolver. A status pill next to each tracked component reads "Install" / "Update available" / "Up
to date"; a resolution failure (e.g. offline) reads "update check unavailable" rather than guessing.
`update::check_updates` also returns a `dig-updater` entry (it is one of the four tracked
components, §7.3) but the Components screen renders no row for the beacon (it is an OPTIONS
checkbox, not a COMPONENTS entry, §1.5) — that entry is simply unused by the current UI rather than
displayed.

### 7.5 Root MUST NOT execute a binary from a directory an unprivileged account can write

An elevated run MUST NOT execute any binary whose containing directory is group/other-writable or not
root-owned. This is §4.1a/§4.1c ("the privileged process never execs the user root's `digstore`", "NEVER
execs a user-writable binary") stated for the library, because the library is what the GUI's root child
calls into and it execs earlier in the run than the GUI's own `should_exec_verify`.

**PLACEMENT is the primary defence, and the guard covers EVERY root-side exec.** An elevated install
places every binary in the root-owned protected root (§1.6), so on the default path the directory root
execs from is not user-writable in the first place. Placement alone is NOT sufficient, because an
explicit `--bin-dir` override redirects the whole stack into a directory the invoking user chose — so
`secure::root_exec_guard` is applied at every root-side exec in the library, all four of them:

1. the version probe (§7.1);
2. every privileged delegation (`service::run_capturing`);
3. `pathcheck::run_version`'s direct-exec branch — reached when there is no account to drop to (a
   root-shell install, or the macOS GUI's `osascript` child, §1.5a);
4. `dns::doctor`'s two `dig-dns` invocations.

The set MUST be closed by CONSTRUCTION, not by an inventory. A reimplementation MUST provide a single
spawn seam that cannot be constructed without the guard having passed, and MUST make an unguarded spawn of an
installed binary fail to BUILD rather than fail a test:

* a written-down list was tried — it named four sites and asserted a count of four while a FIFTH
  (`dns::os_config::run_os_config`, reached on the default plan, on every OS, on install AND uninstall) had
  no guard at all and was proved to root code execution;
* a derived source scan was tried — better, and it found a guard sitting one frame ABOVE its spawn, but it
  is a heuristic pretending to be an enumeration: measured at 8 of 17 evasion forms caught, including two
  ordinary accidents (a discarded verdict, and a `pub(super) fn` body attributed to a guarded sibling).

This implementation uses `guardedcmd::GuardedCommand::for_installed_binary` plus a `clippy.toml`
`disallowed-methods` entry on `std::process::Command::new`. The guard MUST be invoked in the function that
performs the spawn, not merely in its caller: a guard one frame away is one the next caller does not inherit.

**The verdict of a permission check MUST be a single decision, not two fields a caller combines.** Exposing
"was it read?" and "is it safe?" separately let seven call sites each re-derive the policy as "block only on
a definitive breach", which reads INDETERMINATE as a pass — and an unestablished posture is exactly what a
REFUSAL looks like. The same class was consequently found and fixed five rounds running, one site at a time.
So the fields are private, one predicate answers "must this stop what the caller was about to do?", and it
returns true for both detected-unsafe AND indeterminate. A directory whose posture cannot be established
therefore refuses the install and names the level; that is the conservative direction, and it is the whole
of the fix.

**The directory root's own login `PATH` resolves DIG commands from MUST be verified.** It is not enough to
refuse the PATH-WIRING step: that step is non-fatal by design (a binary is placed; only wiring failed), so an
install onto a veneer an unprivileged account owns otherwise reports success while that account can replace a
planted link and have root run it (`InstallReport::veneer_security`).

**An unsafe veneer MUST cause a FALLBACK, never a refusal.** The veneer is a convenience — its only purpose
is reachability — so a reimplementation MUST choose its reachability mechanism from the MEASURED posture
(`paths::Reachability`, `InstallReport::reachability`):

| Veneer posture | Mechanism | Links | `PATH` entry |
|---|---|---|---|
| established safe | `veneer_links` | planted in `/usr/local/bin` | the veneer (already present; nothing written) |
| not established safe | `direct_path_entry` | NONE planted, and any previously planted DIG link REMOVED | the protected root itself, via `/etc/paths.d` or `/etc/profile.d` |

Requirements a reimplementation MUST satisfy:

- **The detection MUST NOT be weakened to accommodate the common case.** Homebrew on an Intel Mac leaves
  `/usr/local/bin` `<user>:admin 0775`, and that IS an escalation even though the account which can write it
  can usually `sudo`: the threat is not the human's privilege but that unprivileged CODE running as them — a
  malicious `npm` postinstall, a compromised editor extension — cannot type their password yet can write that
  directory unprompted and own root at the next elevated run. It also lets one admin silently attack another
  admin's `sudo`.
- **Failing the install instead is equally forbidden.** A refusal is not a fix.
- **The posture MUST be measured ONCE per run** and the same answer MUST drive both the linking and the
  wiring. A run that links into one directory while putting another on `PATH` leaves the CLIs unreachable.
- **`veneer_security` is fatal ONLY when the veneer is the mechanism in play.** Under the fallback the same
  verdict is a recorded downgrade.
- **Removal is part of the fallback**, and MUST be limited to symlinks pointing into the protected root: a
  regular file or a foreign link in a shared system directory belongs to somebody else.
- **If the fallback's `PATH` fragment cannot be written**, there is no safe reachability left. The install MAY
  proceed — the binaries are correctly placed — but it MUST say so explicitly and MUST NOT report ready.
- **The fallback's `PATH` entry MUST be PREPENDED**, and this is a security requirement rather than a
  preference. Appended, the protected root sits behind the directory that made the veneer unsafe, so an
  attacker does not need any link the installer planted — she creates the command name herself and wins
  because her directory is earlier. On macOS this is structural: `/etc/paths` ships `/usr/local/bin` and
  `path_helper` reads it BEFORE `/etc/paths.d/*`, so an appended fragment can never win. Prepending is safe
  for THIS directory specifically because it is root-owned, whole-chain verified, and contains only the
  installer's own binaries; a user-chosen `--bin-dir` MUST still be appended, since it may be attacker-owned
  and must not be able to shadow `/usr/bin` for root.
- **Reachability MUST be verified POSITIONALLY, not by presence.** Any directory that precedes the install
  directory on the target user's login `PATH` and is not established safe MUST fail readiness
  (`InstallReport::preceding_unsafe_path_dirs`). A resolution check alone cannot see this: it only fires once
  the shadowing file exists, so a `PATH` on which a writable directory merely comes first reports ready and
  the attacker creates the name afterwards.
- **The system-wide `PATH` fragment and any parent directory the installer creates for it MUST have their
  modes pinned** (`0644`/`0755`) by the syscall, never left to the process umask, and the write MUST refuse
  to follow a symlink. At `umask 000` the fragment was measured world-writable, and it is sourced by every
  login shell including root's — an unprivileged account appending to it owns root without any install
  running.

**What the fallback does NOT achieve, and MUST NOT be claimed:** it does not remove every writable directory
from root's `PATH`. `/usr/local/bin` is on that `PATH` because the distribution put it there, and a regular
file an attacker leaves in it is not the installer's to delete. After the fallback every DIG name resolves to
the protected root; a NON-DIG name can still be shadowed for root by whoever owns that directory. That
residual is a property of the machine's configuration, and it MUST be reported rather than described as
solved.
Earlier revisions of this section claimed placement covered (3) and (4); it does not under an override,
and a normative claim the code does not satisfy tells a reimplementation to reproduce the gap.

The first two are detailed because they degrade differently:

1. **the version probe (§7.1).** `update::detect_installed_version` RUNS `<dest> --version`, as root,
   for every component, BEFORE anything is downloaded or written. When the guard refuses, the probe is
   SKIPPED and the version treated as undetectable — which §7.1 already resolves to *reinstall*. The
   install proceeds: an unknown version is a safe answer, and strictly better than trusting a version
   string an attacker chose.
2. **every privileged delegation.** `service::run_capturing` is the one choke point for `dig-node
   install`/`start`, `dig-relay install` and dig-updater's `schedule` verbs, so the guard covers all of
   them. Here there is no safe degradation — a service that can only be registered by executing an
   untrusted binary MUST fail LOUDLY rather than proceed.

Unelevated the guard is inert by construction: executing a binary the user can already write is their
own authority, not an escalation. An INDETERMINATE permission read is also permitted, matching §1.6's
posture that an unreadable directory is never a false refusal. Only a DEFINITIVE breach refuses.

**Being root is the condition; how root was reached is irrelevant.** Every predicate deciding whether to
drop privilege MUST ask "am I root, acting for an account that is not root?" — the EFFECTIVE UID plus the
resolved account — and MUST NOT ask whether an elevation HINT
(`SUDO_USER`/`DOAS_USER`/`PKEXEC_UID`) is present. A hint answers how root was REACHED, and it is absent in
uid-0 contexts that really occur: `su -m`/`su -p` preserve the environment, so a non-root account is
resolved with no hint, and a hint-based predicate then reports "not elevated" while holding root — writing
root-owned files into that account's home and executing its binaries as root.

The comparison is by UID, not by the name `root`: a uid-0 account under another name (`toor`) is still root,
and a name comparison would try to drop privilege to it.

The account this process runs AS MUST come from the passwd database (`getpwuid_r(geteuid())`), never from
`$USER`/`$USERNAME`, which the caller controls and which feeds this predicate.

Each decision point MUST read the effective uid itself; a hardcoded answer is the defect, and there are
seven such points (`invoker::TargetUser::acting_for_another_account`).

**This does NOT close the macOS GUI case.** The `osascript` root child inherits no environment, so no
account other than root is knowable there and the predicate answers `false` exactly as a hint-based one
would. That limitation is §1.5a, and a reimplementation MUST NOT read this section as fixing it.

**Root MUST NOT write through a symlink it did not create.** A destination is unlinked and then created
with `O_EXCL` (plus `O_NOFOLLOW`), never opened with a following `O_CREAT|O_TRUNC`
(`download::write_without_following_a_symlink`). The install filenames are deterministic and published,
so a link planted at one would otherwise redirect a root write — and the subsequent `chmod 0755` — to any
path on the filesystem, with no race required. Comparing the resolved paths is NOT a substitute: a
canonicalising comparison reports a link and its target as the same file.

**The directory binaries were placed in MUST be verified**, and the dedupe against the privileged-root
check MUST key on a verdict that was actually PRODUCED, never on where privileged binaries would have
gone (`InstallReport::bin_dir_security`). Those two came apart: the privileged check is gated on the plan
selecting a privileged component, while every elevated install places its binaries in the protected root
— so a CLI-only elevated install wrote into a directory nothing checked.

The verdict is **FATAL under elevation** and a REPORT otherwise. Root wrote the binaries, the veneer's
links resolve into them, and root-side execs and services run them, so a group/other-writable directory
is an escalation. Unelevated, a user-writable directory holding binaries only that same user runs is
their own authority, and failing on it would refuse every ordinary per-user install and every Homebrew
Mac.

**An install root MUST be an absolute, already-normalized path.** A path containing `.` or `..` MUST be
REFUSED, not resolved. Every permission statement here is about the LEVELS of a path, and `..` breaks that
in both directions: a walk that skips it verifies a different directory than the one in use, and a walk that
treats it as a level walks OUTWARD — measured, from one `--bin-dir` argument, as `chown root:root` +
`chmod 0755` on an operator's `~/.ssh` and the loss of `/tmp`'s sticky bit. Resolving it is not an option
either: lexical normalization disagrees with the kernel when a component is a symlink, and `canonicalize`
FOLLOWS symlinks, which is the attack the descriptor discipline exists to prevent.

**Creating a level MUST pass the mode to the SYSCALL** (`mkdirat`), never create-then-`chmod`. `mkdir` masks
the mode it is given, so the result can only be NARROWER than requested; the create-then-fix pair leaves a
window in which the directory carries the umask's permissions, which an unprivileged racer won 12 times in
3000 iterations. This applies to every level this installer brings into existence, including the levels
above the `/usr/local/bin` veneer.

**A symlink or non-directory where a level is expected is a DEFINITIVE refusal**, distinct from a level that
could not be read. `ELOOP` from `O_NOFOLLOW` is the DETECTION, not a failure to inspect; reporting it as
indeterminate makes it a PASS at every gate, because each is written "definitively insecure fails". An
install root symlinked onto another volume therefore MUST fail loudly rather than print a tick.

**The privileged install root is a CHAIN, and EVERY level of it is normative.** Creating `/opt/dig/bin`
with a recursive `mkdir -p` and pinning only that leaf leaves the PARENT at the process umask — measured
`0755` at `umask 022`, `0775` at `002`, `0777` at `000`, all reporting a ready install. Write permission
on `/opt/dig` is permission to rename `/opt/dig/bin` aside and substitute an attacker-owned directory of
the same name, so every service `ExecStart=/opt/dig/bin/…`, every veneer symlink and the root-run beacon
then resolve to planted binaries, with no race. Therefore:

- **every DIG-owned level** (`/opt/dig` and below) MUST be created individually, root-owned, mode `0755`
  — never implicitly at the umask by a deeper call. Levels the distribution owns (`/opt`) MUST NOT be
  re-moded; they are verified, not changed.
- **verification MUST cover every level from `/` down**, including the levels DIG does not own, and MUST
  read each through an `O_NOFOLLOW|O_DIRECTORY` DESCRIPTOR (`fstat`), never a path `stat`. A path-based
  check FOLLOWS symlinks — `--bin-dir /home/alice/bin` where `~/bin` links to `/etc` reported the root
  secure while describing `/etc` — and re-resolves between check and use.
- **the chain MUST be REPAIRED on every run**, not merely created correctly when absent. A machine that
  installed an earlier version under a permissive umask already has a group- or world-writable level, and
  an install that only refrains from making it worse leaves the escalation in place while reporting
  success.

**The protected root's mode MUST be `0755` explicitly, and MUST be enforced on an existing directory.**
`mkdir` applies the process umask, so an inherited `umask 000` yields a WORLD-WRITABLE protected root —
measured at mode `0777` on a real elevated install — which hands every local account the ability to
replace a binary root executes. Setting the mode only at creation is the same defect one run later,
because the next run adopts whatever was left behind (`paths::ensure_bin_dir`). A directory the caller
nominated (`--bin-dir`, a per-user root) is NOT re-moded; its posture is reported instead.

### 7.6 Trusted system-tool resolution

A well-known system tool (`id`, `su`, `sh`, `osascript`, `pkexec`) MUST be resolved to an absolute path
from a fixed list of directories and NEVER through `$PATH`, because macOS's stock sudoers sets no
`secure_path` and an inherited `$PATH` can begin with a user-writable prefix.

The list is `/usr/bin`, `/bin`, `/usr/sbin`, `/sbin`. **`/usr/local/bin` MUST NOT appear in it.** It is a
system directory only by convention: Homebrew on an Intel Mac owns it as `<user>:admin 0775`, so
including it put a user-writable directory inside the trusted set — a planted `/usr/local/bin/<tool>`
was resolved and executed by root, and no `$PATH` hardening could help, because `$PATH` was never
consulted. No supported platform ships any of these tools there.

A resolved candidate MUST additionally be owned by uid 0 with no group/other write bit, so a tool that
only root could have placed is the only one root will execute; unreadable metadata is a refusal, not a
pass.

**The passwd database is read WITHOUT spawning anything.** `/etc/passwd` is parsed directly, and an
account it does not list is resolved through libc's own `getpwnam_r`/`getpwuid_r` — in-process, so there
is no tool to plant and no directory to trust, and the platform's real name service (nsswitch/LDAP/SSSD
on Linux, Open Directory on macOS) answers. A `getent passwd` SPAWN MUST NOT be used: on macOS the
branch is unconditional (stock `/etc/passwd` lists no account with uid >= 1000) while macOS ships no
`getent` at all, so its only successful outcome was a planted binary whose stdout the installer then
parsed as the passwd database — letting the attacker choose the account the rest of the install trusts.
This is also a correctness requirement, not only a hardening one: without it the lookup always failed on
macOS, §1.6's resolution fell back to the CALLING process's home (`/root` under `sudo`), and the §1.6
home inversion was therefore never fixed on that platform.

## 8. Release pipeline — nightly cron + manual dispatch

How the universal `dig-installer` CLI + the Tauri GUI installers are built and released. The shape
is copied from the ecosystem's reference nightlies implementation (`dig-updater`); the ops runbook
is `runbooks/release.md`.

Releases are **batched to a nightly cron plus manual dispatch** — NOT cut on every merge to `main`.
Two channels ship from one orchestrator (`.github/workflows/nightly-release.yml`):

### 8.1 Trigger

The orchestrator triggers ONLY on:

- `schedule: cron '0 0 * * *'` — **midnight UTC** (GitHub Actions cron is always UTC; a top-of-hour
  cron MAY be delayed under load — acceptable, since both channels are idempotent), and
- `workflow_dispatch` with two inputs: `channel` (`both` | `stable` | `nightly`, default `both`) and
  `force` (boolean, default `false`).

It MUST NOT trigger on `push` to `main`. A schedule run exercises BOTH channels; a dispatch runs the
selected channel(s).

**60-day auto-disable caveat.** GitHub auto-disables a `schedule:` trigger after 60 days with no
repo activity on a public repo, with no auto-re-enable — and since this cron is the ONLY automatic
release trigger, a quiet repo can silently stop releasing with no error. Detect it with
`gh api repos/DIG-Network/dig-installer/actions/workflows/nightly-release.yml --jq .state` (a value
of `disabled_inactivity` means it was auto-disabled) and recover with `gh workflow enable
nightly-release.yml` (see `runbooks/release.md`). Any repo activity resets the 60-day counter.

### 8.2 Stable channel

Cuts a semver `vX.Y.Z` **stable** release when — and only when — the version in the root
`Cargo.toml` (`[package].version`) has advanced beyond the newest `vX.Y.Z` tag (the
skip-if-already-tagged check IS the version-changed check). Cutting a release means: `git-cliff`
regenerates `CHANGELOG.md`, commits it to `main` as `chore(release): vX.Y.Z`, tags THAT commit (so
the changelog is inside the tag), and pushes commit + tag with `RELEASE_TOKEN`. The pushed `v*` tag
fires `release.yml`, which builds the CLI (every OS/arch) + the Tauri GUI installers and publishes a
GitHub Release with `prerelease: false` + `make_latest: true` — the ONLY release that moves `latest`.

**Root version + the GUI sub-lockfile (path-dep trap).** The GUI crate `gui/app/src-tauri` depends
on the root `dig-installer` crate by path (`dig-installer = { path = "../../.." }`), so its
`gui/app/src-tauri/Cargo.lock` carries a `dig-installer` entry. A root version bump MUST sync BOTH
lockfiles (`cargo update -p dig-installer` at the root AND with
`--manifest-path gui/app/src-tauri/Cargo.toml`), or the GUI's `--locked` build fails.

`force: true` on a manual dispatch bypasses the skip-if-tagged guard and re-cuts the current version
(moving the tag onto a fresh changelog commit — `main` is never force-pushed).

**Force is guarded against mutating a published release (supply-chain invariant).** A force re-cut
MUST be refused — non-zero exit, clear error — when BOTH: (a) a PUBLISHED (non-draft) GitHub Release
already exists at the version's `vX.Y.Z` tag, AND (b) that tag currently points at a commit
DIFFERENT from the commit this run would build. Force MAY proceed when either is false: a
same-commit re-cut (a failed-build retry) or a tag with no published release (a tag repair). A
version that needs new code released MUST bump `Cargo.toml`, not force-move a tag.

### 8.3 Nightly channel

Every night (and on demand) builds `main` HEAD (CLI + GUI) and publishes a GitHub **pre-release** —
so a fresh nightly always exists regardless of a version bump. It:

- **Synthesizes the version at build time** (nothing is committed): `X.Y.Z-nightly.YYYYMMDD.<shortsha>`.
  As a semver prerelease it sorts BELOW the plain `X.Y.Z`.
- Publishes under a **dated tag `nightly-YYYYMMDD`** AND force-moves a **rolling `nightly` tag**,
  with `prerelease: true` and **never** `latest`. Idempotent: a same-day re-run refreshes today's
  dated release + the rolling pointer.
- **Retention:** keeps the newest **14** dated nightlies plus the rolling `nightly`, pruning older
  dated pre-releases AND their tags together (`gh release delete --cleanup-tag`). `v*` stable
  tags/releases and the rolling `nightly` are NEVER pruned.

The nightly GUI installer embeds the LATEST **stable** released digstore (the GUI's fetch step is
unchanged) — correct for a nightly installer.

### 8.4 Reusable build

The cross-OS build lives once in `.github/workflows/build-binaries.yml` (`on: workflow_call`, inputs
`version` + `ref`). Both `release.yml` (stable) and the nightly channel call it, so the two paths
can never diverge. It builds the `dig-installer` CLI for `windows-x64`, `linux-x64`, `macos-arm64`,
`macos-x64`, and the Tauri GUI installer (`.exe`/`.dmg`/`.AppImage`), stamping the caller's
`version` into each artifact filename.

### 8.5 RELEASE_TOKEN posture

Releasing uses the `RELEASE_TOKEN` org PAT, not `GITHUB_TOKEN`. If `RELEASE_TOKEN` is absent, EVERY
channel NO-OPS with a clear `::warning::` — never a half-release. A `concurrency: nightly-release`
group (cancel-in-progress `false`) serializes runs so an overlapping cron + dispatch cannot race.
