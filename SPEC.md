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
service, the `dig-dns` service, and the `dig-updater` auto-update beacon are ALL installed by
default (a bare `dig-installer` with no flags installs all four; `InstallPlan::default()` encodes
this). `dig-node` and `dig-dns` are registered as **boot-start** OS services (§2.1); `dig-updater`
registers its own **daily scheduler artifact** (§1.5). Opt out of any of the four with the matching
`--no-<component>` flag. `dig-relay` (advanced, run-your-own-relay) and the DIG Browser stay
opt-in.

| id         | repo                          | kind                              | CLI flag(s)                          | Selected in the GUI wizard by default |
|------------|-------------------------------|------------------------------------|---------------------------------------|----------------------------------------|
| `digstore` | `DIG-Network/digstore`        | raw binary, added to PATH          | on by default; `--no-digstore` opts out; `--with-digstore` (redundant, symmetry) | always (required, no checkbox) |
| `digs`     | `DIG-Network/digstore` (alias, issue #434) | raw binary, added to PATH (same bin dir as `digstore`) | NO separate flag — follows `digstore`'s `--no-digstore`/`--with-digstore`/`--digstore-version` | follows `digstore` |
| `dig-node` | `DIG-Network/dig-node`        | raw binary + boot-start OS service + `dig.local` hosts entry | on by default; `--no-dig-node` opts out; `--with-dig-node`/`--service` (redundant) | yes |
| `dign`     | `DIG-Network/dig-node` (alias, issue #548) | raw binary, added to PATH (same bin dir as `dig-node`) | NO separate flag — follows `dig-node`'s `--no-dig-node`/`--with-dig-node`/`--dig-node-version` | follows `dig-node` |
| `dig-dns`  | `DIG-Network/dig-dns`         | raw binary + boot-start OS service + split-DNS/NRPT + browser DoH policy | on by default; `--no-dig-dns` opts out; `--with-dig-dns` (redundant) | yes |
| `digd`     | `DIG-Network/dig-dns` (alias, issue #548) | raw binary, added to PATH (same bin dir as `dig-dns`) | NO separate flag — follows `dig-dns`'s `--no-dig-dns`/`--with-dig-dns`/`--dig-dns-version` | follows `dig-dns` |
| `dig-updater` | `DIG-Network/dig-updater`  | raw binary + a daily OS-scheduled task/timer/LaunchDaemon (issue #514, §1.5) | on by default; `--no-auto-update` opts out; `--auto-update` (redundant) | yes, as the "Keep DIG up to date automatically" option |
| `dig-updater-worker` | `DIG-Network/dig-updater` (alias, issue #514) | raw binary, added to PATH (same bin dir as `dig-updater`) | NO separate flag — follows `dig-updater`'s `--no-auto-update`/`--auto-update`/`--dig-updater-version` | follows `dig-updater` |
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

### 1.6 Install locations — the protected install root (#565)

A binary that a PRIVILEGED identity later executes MUST live in a directory an unprivileged user
cannot write. Otherwise a non-admin could replace it and get code execution as that privileged
identity on the next service start / scheduled run — a local privilege escalation. The installer
therefore places binaries into two roots, chosen per component:

- **Protected root** — admin-only-writable, for every binary a service/scheduled-task runs:
  - **Windows:** `%ProgramFiles%\DIG\bin`, resolved via the known-folder API
    (`SHGetKnownFolderPath(FOLDERID_ProgramFiles)`, never the spoofable `%ProgramFiles%` env). Program
    Files' inherited DACL is admin-write / user-read+execute, so no custom ACL is applied. The ENTIRE
    Windows stack (services + user CLIs + the installer self-copy) installs here — one root.
  - **macOS/Linux:** `/opt/dig/bin`, root-owned `0755` (owner root writes; group/other read+execute).
- **User root** — the elevation-free per-user `~/.dig/bin` (unix only), for user-run binaries that no
  privileged service executes: `digstore`/`digs`/`digd` and the user-level `dig-node`/`dig-relay`.
  (On Windows there is no separate user root — everything is in the one protected root.)

The component→root map is `paths::is_privileged_component`: on Windows every component is protected;
on unix the protected set is exactly `dig-dns`, `dig-updater`, and `dig-updater-worker` (the
machine-wide / root-run binaries). An explicit `--bin-dir <DIR>` OVERRIDE wins for the whole stack
(the user's chosen dir, their responsibility). `InstallPlan::bin_dir_for(component, os)` is the
single resolver.

**Elevation.** Writing into the protected root requires elevation, so even a CLI-only install
elevates on Windows (the CLI lands in Program Files); a CLI-only unix install into `~/.dig/bin` does
not (`InstallPlan::requires_elevation`, §4.1).

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
id / task path — never by executing the binary) — and REFUSES ready if any still resolves UNDER a
legacy/user-writable root. This catches a service a tolerated "already exists" re-install left
pointing at the writable legacy path, and an orphaned registration a component opt-out stranded.
Like the ACL verify, this audit runs whenever the plan installs a privileged binary ANYWHERE
(`InstallPlan::installs_a_privileged_binary`, DECOUPLED from `installs_a_protected_component`), so it
fires on a `--bin-dir`/GUI privileged install too — not only the default protected root. Recorded in
`InstallReport.registration_audit`.

**Migration (existing installs).** Gated on the SAME `installs_a_privileged_binary` predicate as the
audit (so it runs on a `--bin-dir`/GUI privileged install too, not only the default protected root;
the migration only ever ACTS on legacy roots, never the chosen dir): on a re-run that detects DIG
binaries in a legacy user-writable root (`%LOCALAPPDATA%\Programs\{DIG,DigStore}\bin` on Windows; the
privileged binaries in `~/.dig/bin` on unix) OR a privileged registration still pointing under one,
the installer re-points the install onto the protected root (`migrate` module): it deregisters EVERY
privileged registration whose binary resolves under a legacy root — INDEPENDENT of the current plan —
the dig-node/dig-relay/dig-dns
services BY ID *and the SYSTEM auto-update beacon scheduled task* by its own scheduler tool
(`schtasks /Delete` / systemd-timer disable / launchd bootout), so a component OMITTED from the run
cannot keep an auto-start service or daily SYSTEM task registered against a replaceable legacy
binPath; the normal install then re-registers whatever is in-plan fresh from the protected path. It
removes the legacy binaries by KNOWN filename (never a recursive walk that could follow a planted
junction/reparse point — all on Windows, only the privileged ones on unix); and drops the legacy dir
from the user PATH on Windows. It never executes a legacy-dir binary. A DEREGISTER FAILURE is FATAL —
the install reports NOT ready (`MigrationResult::deregister_failures`), never a silent continue into a
tolerated re-install that could leave the service at the legacy binPath. Recorded in
`InstallReport.migration`.

**Authoritative install-root record (`install.json`, #581).** The installer writes
`<install-home>/install.json` (`%ProgramFiles%\DIG\install.json` / `/opt/dig/install.json` — the
protected root's parent, admin-only-writable by inheritance) with `{ "schema": 1, "bin_dir": <the
protected root>, "installer_version": <version> }`. This is the single machine-readable source of
truth for the install root the auto-update beacon consumes; it is coherent with the beacon's own
`current_exe().parent()`-derived root by construction now that the beacon binary lives in the
protected root. A consumer MUST verify the file is admin-only-writable before trusting it. Recorded
in `InstallReport.install_manifest`.

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
scheme, firewall, beacon, installed[], cli_path_checks[], ready, failures[]}`. See `src/lib.rs` doc
comments on `InstallReport`/`ComponentResult`/`PathResult`/`ServiceResult`/`RelayResult`/
`dns::DnsInstallResult`/`scheme::SchemeResult`/`firewall::FirewallResult`/`beacon::BeaconResult`/
`pathcheck::CliPathCheck` for the exact field set; every boolean field has a paired human-readable
`*_note` — no field is ever silently omitted to signal failure. `firewall`/`beacon` are `None` when
`open_firewall`/`auto_update` are off (§1.4/§1.5) — distinct from a present-but-`applied: false`
result, so a caller can tell "declined" apart from "attempted and failed". `ready`/`failures` are
the aggregate readiness verdict (§4.2) — the firewall rule and the scheme handler are best-effort
and never gate `ready`; the beacon's scheduler registration DOES gate `ready` (§1.5, like
dig-node/dig-relay's own service registration). The `--json` envelope's `ok` mirrors `ready`.

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
elevates, while a unix CLI-only install into `~/.dig/bin` does not. A `--dry-run`, or a CLI-only
install into a `--bin-dir` override or the unix user root, never trips the gate. The per-OS
elevation probe is `elevation::is_elevated` (Windows `net session`, Unix `id -u`);
the pure decision + per-OS remedy is `elevation::gate` (unit-tested). The GUI enforces the same gate
before its first write.

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
  — the admin-only protected root on Windows (`%ProgramFiles%\DIG\bin`), the elevation-free per-user
  `~/.dig/bin` on unix (digstore runs AS the user — not an escalation). NEVER an ad-hoc user-writable
  path. This routing is test-locked (a revert to a hardcoded user dir fails a unit test).
- **The `digstore --version` verify (Phase 6) never execs a user-writable binary under elevation.**
  The exec-verify runs in-process only when it is safe — `should_exec_verify`: the process is
  UNELEVATED, OR the binary sits in the root-owned protected root (unswappable). Otherwise (an
  elevated run whose binary is user-writable — the future unix root child) it is DEFERRED to the
  unelevated GUI; the privileged process never execs `~/.dig/bin/digstore`.
- **Association cache-refresh tools resolve to ABSOLUTE paths.** `register_dig_association` (per-user,
  unelevated) runs `update-mime-database` / `gtk-update-icon-cache` from a fixed allowlist of trusted
  system directories (`/usr/bin`, `/bin`, `/usr/local/bin`) via `resolve_system_tool`, never as a bare
  command name resolved through `$PATH` — removing the root-`PATH`-hijack / pwnkit-class surface if the
  path is ever reached under elevation. A missing tool fails soft (the refresh is best-effort).

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
`protected_bin_dir()` (`%ProgramFiles%\DIG\bin`) on Windows, the elevation-free per-user `~/.dig/bin`
on unix. Because the elevated GUI both WRITES and EXECUTES digstore (`digstore --version`, Phase 6),
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

The Done screen exposes a **Close** action (`bridge.js` `closeWindow` → Tauri `getCurrentWindow().close()`,
the same window op the title-bar close control uses) beside the primary **Launch Terminal**, so the
user always has a one-click exit on the final step (never trapped). The window opens at 1080×720 and
enforces a minimum of **980×600** — 980 wide so the three-action Done footer (Open Documentation ·
Close · Launch Terminal) always fits without clipping the primary action.

### 6.1 No flashing console windows (Windows)

Every non-interactive child process the installer spawns is launched with the Win32 `CREATE_NO_WINDOW`
(`0x08000000`) creation flag so no console window flashes on screen or steals focus during an install.
This includes the library crate's Windows console helpers (`sc`, `net`, `netsh`, `powershell`, `icacls`,
`whoami`, `cmd`), delegated `dig-node`/`dig-dns`/`dig-updater` verbs, and the GUI backend's internal
version-probe spawns (checking the bundled digstore binary version during startup and verification
post-install). This is applied consistently through the single `proc::HideConsole::hide_console()` helper
(a no-op on non-Windows targets) rather than a flag sprinkled at each call site.

User-initiated spawns — the `launch_terminal()` command that opens a terminal at the install directory —
are intentionally launched with visible console windows so the user can interact with the terminal.

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
