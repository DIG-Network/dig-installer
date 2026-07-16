# Development log

High-signal, durable realizations from building dig-installer. Concise facts with
context — not a change diary. See CLAUDE.md → §4.5 for how this is maintained.

## #565: a security-relevant predicate swap must sweep EVERY gate, not one

Closing the #565 LPE decoupled the ACL verify from `installs_a_protected_component`
(which is `false` under any `--bin-dir` override) onto `privileged_install_root`.
The first pass applied that ONLY to the verify and left the legacy-root MIGRATION
and the post-install binPath AUDIT still gated on the old predicate — so on a
`--bin-dir`/GUI install (the exact path the GUI passes + the e2e uses) both were
SILENTLY skipped, and a pre-#565 legacy-bound service/beacon registration was never
vacated or flagged: readiness reported ready and the escalation survived. Lesson:
when a security fix changes WHICH predicate a decision keys on, grep every call
site of the old predicate and move them together (or funnel them through one named
gate — here `InstallPlan::installs_a_privileged_binary`), then prove it with a test
that a custom-`--bin-dir` privileged install still migrates + audits. A CI leg that
only ever runs with `--bin-dir` can also make a "no legacy registration" assertion
VACUOUS (empty audit list) — assert the audit array is non-empty (it actually ran)
and add a seeded-legacy default-root leg so the migration path is exercised for real.

## Auto-update beacon registration (#514): `dig-updater schedule install` is idempotent — unlike dig-node's `install`

dig-node's own `install` verb is NOT idempotent (task #232's whole reason for the stop-before-write/
Skip-doesn't-reinstall dance): re-running it over an already-registered service hard-fails on
Windows SCM / macOS launchd ("already exists"), so `register_dig_node` tolerates that failure and
relies on `start` as the real signal. `dig-updater schedule install`/`schedule uninstall` are the
OPPOSITE: `schtasks /Create … /F` always overwrites, `systemctl enable --now` is idempotent, and
launchd's own registration path bootouts any prior registration before rebootstrapping — so a
re-install always succeeds cleanly. This installer's `beacon::register`/`unregister` therefore call
the scheduler unconditionally on every Install/Update/Skip decision for `dig-updater` (never
gated on the version-decide outcome the way dig-node/dig-dns's registration is) — a genuinely
different, simpler contract than every other delegated-subcommand component in this crate, worth
keeping in mind before copying the dig-node pattern onto a new component by reflex.

## Version-aware updater (#309): a stub executable must match the REAL exe-name convention

Testing the detect→compare→decide pipeline (`src/update.rs`) end-to-end (not just the pure
`decide()` matrix) needs a fake binary at the EXACT path `resolve_component` would place the real
one at — `bin_dir.join(target.exe_name(stem))`, i.e. literally `digstore.exe` on Windows, not some
test-chosen name. That kills the `doctor.rs`/`service.rs` "write a `.cmd`/shell-script stub" trick
for a genuine present-and-PARSEABLE (Skip/Update-by-version) integration test: Windows' `CreateProcess`
only special-cases `.bat`/`.cmd`/`.exe`-associated extensions for that shim, and a plain file named
`digstore.exe` containing batch-script text is NOT dispatched through `cmd.exe` — it's read as a
(broken) PE and fails to launch. A cross-platform-safe integration test can therefore only cheaply
prove **absent → Install** (no file at all) and **present-but-unrunnable → Update** (any garbage file
at the exact dest fails to spawn on every OS, landing in the "unreadable" reinstall branch) — the
Skip/Update-by-real-version-compare cells stay covered by `update.rs`'s pure `decide()` unit tests
(which take `DetectedVersion` directly, no process spawn), not a full-pipeline integration test. A
genuine end-to-end Skip test would need a real compiled per-OS stub binary — not worth the CI weight
for what the pure matrix already proves.

## Version-aware updater (#309): dependency-light on purpose — no `semver` crate

Every DIG-Network release tag is a bare git-cliff `vMAJOR.MINOR.PATCH` (no pre-release/build
metadata in practice), so `update.rs`'s comparator is a hand-rolled 3-part `SimpleVersion` rather
than pulling in the `semver` crate: it is (a) all this installer will ever need, (b) trivially
correct/testable, and (c) keeps the module dependency-free for its planned #504-B extraction into
`dig-release-resolver`. A version string that doesn't fit `X.Y.Z` (a real pre-release tag, a
foreign/garbled `--version` output) deliberately fails to parse rather than being approximated —
`decide()` treats "can't parse" as "reinstall to be safe" either way, so under-parsing costs nothing.

## Register dig-dns's OWN `run-service` SCM entrypoint DIRECTLY — a host-shim caused the `1053` (task #494/#499)

The field bug (`dig_ecosystem#499`): installing dig-dns as a Windows service failed with SCM error
`1053` ("the service did not respond to the start request in a timely fashion"). ROOT CAUSE was an
**indirection**: the installer registered its OWN binary as the service, running a hidden
`run-dig-dns-service` host-shim that child-spawned `dig-dns serve`. The host process's
`StartServiceCtrlDispatcher`/RUNNING handshake was gated behind spawning the child, so the SCM's
start-timeout could elapse before RUNNING was reported.

FIX: dig-dns v0.9.0+ ships its OWN Service Control Protocol entrypoint, `dig-dns run-service`, which
reports `SERVICE_RUNNING` to the SCM before any slow startup work. The installer now registers the
SCM service to run **`dig-dns.exe run-service` directly** (program = the dig-dns binary, args =
`["run-service"]`) — no host shim (`src/dns/service_host.rs` + the `run-dig-dns-service` subcommand
DELETED, `windows-service` dep dropped). One coherent service process. An explicit dig-node override
is baked into the service ENVIRONMENT as `DIG_NODE_URL` (dig-dns `config::ENV_NODE_URL`, a byte-identical
cross-repo contract), which `run-service` reads; `ServiceInstallCtx.environment` carries it.

Scope note: dig-dns (v0.9.0+) NOW has its own `install`/`uninstall`/`start`/`stop`/`status`/`run-service`
verbs (it previously had none — old entries elsewhere calling dig-dns "a plain CLI with no service code"
are superseded). But this installer STILL owns the surrounding per-OS wiring — the `.dig` NRPT rule /
split-DNS resolver, the Chrome/Edge DoH policy, and `dig-dns doctor` self-verification — plus the
canonical `dns::plan::SERVICE_LABEL`/`SERVICE_DISPLAY_NAME` it registers under. On macOS/Linux the
service runs `dig-dns serve` directly (no SCM timeout there).

Also: `service-manager` v0.7's `ScServiceManager::install` (Windows) ALWAYS sets `displayname=` to
the qualified service name at create time — `ServiceInstallCtx` has no field to override it. A
custom human-friendly display name (e.g. "DIG NETWORK: DNS") must be applied as a follow-up
`sc config <name> displayname= "<display>"` call, and VERIFIED by reading it back via
`sc qc <id>` DISPLAY_NAME (`svc::verify_display_name`) — `sc config` can appear to succeed while the
panel still shows the raw service id (the #499 display-name symptom).

## The installer's DEFAULT is the full 3-component stack, and boot-start is delegated vs owned (task #301)

`dig-installer` installs digstore + dig-node + dig-dns by default (opt out with
`--no-<component>`); dig-relay + DIG Browser stay opt-in. The default lives in
ONE place — `InstallPlan::default()` in `src/lib.rs` — and `main.rs` just maps
`--no-*`/`--with-*` onto it (`with_x = cli.with_x || !cli.no_x`, so the `--with-*`
flags are redundant-but-accepted). `help_json()`'s `components[].default` mirrors
this and is the machine-readable contract an agent reads.

**Boot-start is registered two different ways, and that split matters:**
- **dig-node** owns its own service lifecycle, so the installer just runs
  `dig-node install` — which itself sets `autostart: true` (dig-node-service's
  `service::install`). We must NOT invent a manual-start variant; boot-start is
  the delegated default. The installer-side contract is only "invoke plain
  `install`" (`service::install_args() == ["install"]`).
- **dig-dns** ships NO service verbs, so the installer registers it directly via
  the `service-manager` crate. Boot-start is the single shared flag
  `dns::plan::DNS_SERVICE_AUTOSTART` (`true`) threaded into `ServiceInstallCtx.autostart`
  on all three OS modules — which maps to Windows SCM `start= auto`, systemd
  `enable`, launchd load. The declarative systemd `WantedBy=multi-user.target`
  and launchd `RunAtLoad` in the hand-rolled unit/plist bodies (`dns::plan`) are
  the belt to that suspenders. One named const keeps a manual-start regression a
  one-line, test-caught change.

## The GUI installer NAME ≠ the digstore CLI component name (task #301 rebrand)

The user-facing installer is "**DIG Installer**" (Tauri `productName`, window
title, `TitleBar.jsx`, identifier `net.dig.installer`) — but "**DigStore**" /
`digstore` legitimately stays as the CLI *component* it installs. A blanket
find-replace of "DigStore" would be wrong (and would break
`tests::gui_copy_uses_canonical_ecosystem_vocabulary`, which asserts "DigStore"
still appears in the wizard copy). The rebrand target is the two-word phrase
"DigStore Installer" only; the internal crate/lib identifiers
(`digstore-installer`, `digstore_installer_lib`) are deliberately left as-is
(not user-visible). `tests::installer_is_branded_dig_installer_not_digstore_installer`
guards the identity surfaces.

## Defaults drift silently when they're duplicated across repos (task #140)

`--dig-node-port` defaulted to `8080` here (`src/main.rs`, `src/service.rs`) long
after dig-node itself moved its own default to `9778` (task #132 — an uncommon
high port, sibling of the dig-wallet HTTP API's `9777`). Nothing failed: the
installer still ran, dig-node still started — it just silently registered the
service on the wrong port relative to what the extension / DIG Browser / the
§5.3 `localhost` tier now expect by default. A duplicated literal default (here:
the installer's own `ServiceConfig::default()` mirroring dig-node's
`config::DEFAULT_PORT` by convention rather than by reference, since they're
different binaries/repos) needs an explicit cross-repo grep whenever the
canonical value moves — `SYSTEM.md` recording the canonical port is necessary
but not sufficient; every consumer's *own* default literal has to be swept too.

## `ToSocketAddrs` on a bare IP literal is a network-free way to unit-test resolver logic

`hosts::resolve_dig_local()` asks the real OS resolver (`getaddrinfo`/the Windows
equivalent, via `std::net::ToSocketAddrs`) whether `dig.local` maps to
`127.0.0.2` — a genuine post-install verification, not a re-parse of the
installer's own hosts-file write (which would trivially always "pass"). The
pure comparison logic (`hosts::resolve_host`) is unit-tested by feeding it bare
IP literals (`"127.0.0.2"`, `"127.0.0.1"`) instead of hostnames: `ToSocketAddrs`
parses a literal directly with **no I/O**, so the success/mismatch branches are
deterministic and CI-safe. The "doesn't resolve" branch is tested with a
`.invalid`-TLD hostname (RFC 2606 reserved, guaranteed never to resolve) rather
than a made-up name, which could theoretically hit a search-domain suffix on
some networks. The real `dig.local` resolution itself is only exercised as a
manual/integration check post-install (mirrors how `write_dig_local()`'s actual
system-hosts-file write was never unit-tested either — see `hosts.rs`'s
`_at`-suffixed pure-path variants for the testable core).

## `service-manager` 0.7.1's restart-on-crash defaults differ silently per OS (task #223)

Both dig-node-service and this installer's own dig-dns wiring register OS
services via the `service-manager` crate pinned at `0.7.1`, with
`ServiceInstallCtx.contents: None` (letting the crate generate the systemd
unit / launchd plist / SCM entry) and no explicit restart config. Checked the
crate source at tag `v0.7.1` (GitHub API, since it isn't vendored locally) to
learn what that actually produces:

- **systemd** — `SystemdConfig::default().restart` is
  `SystemdServiceRestartType::OnFailure`; the generated unit gets
  `Restart=on-failure` automatically. Auto-restart-on-crash "just works" on Linux.
- **launchd** — `LaunchdInstallConfig::default().keep_alive` is `true`; the
  generated plist gets `KeepAlive: true` (+ `RunAtLoad: true` from
  `ServiceInstallCtx.autostart`). Auto-restart-on-crash "just works" on macOS too.
- **Windows (SCM)** — `src/sc.rs`'s `install()` only shells `sc create …`; it
  never calls `sc failure`/`ChangeServiceConfig2` to set recovery actions.
  Windows services do **NOT** restart on crash by default — this is a REAL gap,
  not a documentation gap. Filed as
  [DIG-Network/dig_ecosystem#224](https://github.com/DIG-Network/dig_ecosystem/issues/224)
  (in `dig-node-service`, out of scope for this repo).

Lesson: "delegates to the `service-manager` crate" is not one behavior — its
per-OS default differs, and the only way to know which is to read that crate's
actual per-backend source for the pinned version (docs.rs/the crate's own docs
don't spell this out; `ServiceInstallCtx`'s fields are the same across OSes,
but the *manager's own* config struct, which this installer/dig-node-service
never touch, is what carries the OS-specific default).

## dig-node/dig-relay's service verbs are NOT idempotent; `status` is the only safe probe (task #232)

Before adding the stop-before-write/start-after-write install lifecycle,
audited dig-node-service's and dig-relay's actual `install`/`uninstall`/
`start`/`stop`/`status` implementations (both just thinly shell out to the
`service-manager` crate's `sc`/`systemd`/`launchd` backends via `?` — no
"already installed"/"already running" pre-checks of their own):

- **`install` on an already-registered service hard-fails** on Windows SCM
  ("already exists") and (typically) macOS launchd; systemd tends to
  succeed as a no-op. So a plain re-`install` during an upgrade is NOT safe
  to treat as fatal — the installer now tolerates an `install` failure and
  still attempts `start` (the registration still points at the same on-disk
  path this run just wrote, so `start` picks up the new binary regardless of
  whether `install` itself succeeded).
- **`start`/`stop` are also not idempotent** — `start` on an already-running
  service and `stop` on a stopped one both commonly hard-fail on Windows/
  macOS (systemd tends to tolerate both). Never assume any of these four
  verbs no-ops safely; only `status` is safe to call unconditionally.
- **`status --json`'s envelope shape differs between the two binaries**:
  dig-node returns a FLAT `{"serving": bool, ...}`; dig-relay returns a
  NESTED `{"result": {"serving": bool, ...}}`. `status` never hard-fails
  (always `Ok`, exit 0 when serving / 1 when not) but **cannot distinguish
  "not installed" from "installed but stopped"** — both read as
  `serving: false`. Neither binary exposes an "is it registered" verb, so
  the installer's stop-before-write step treats "binary absent at the
  destination path" (not "service not registered") as its "first install,
  nothing to stop" signal instead.
- No OS-tool error string ("already exists", "not loaded", …) is a literal
  constant in dig-node/dig-relay's own source — it's whatever `sc.exe`/
  `systemctl`/`launchctl` printed, passed through verbatim. Don't
  string-match those messages from a caller; branch on `status`'s
  `serving` boolean and treat everything else as an opaque, best-effort
  outcome recorded in a note.

## The installer GUI's theme has flipped dark→white→dark twice (#233)

`bd4860a` (2026-06-29) deliberately re-skinned the GUI from its original dark
cosmic surface to the clean white DIG product theme, citing `SYSTEM.md` →
"Canonical terminology & branding", which (as of this writing) still lists
"the installer GUI" among the product surfaces using the white theme
(`dig.net`/`docs.dig.net` are the only stated dark exceptions). Task #233
reverted it back to dark per an explicit user bug report. **This leaves
`SYSTEM.md`'s canonical-branding text and the installer's actual shipped
theme in direct disagreement** — flagged for the orchestrator to resolve
(either add the installer GUI to the sanctioned-dark-exception list, or
this reversion needs revisiting) rather than silently drift again. Whoever
touches this theme next should check which way `SYSTEM.md` reads FIRST.

## Closing the gui/app/src-tauri pre-merge CI gap (#238, dig_ecosystem)

`gui/app/src-tauri` deliberately declares its own empty `[workspace]` table
(isolating it from the root workspace so the CLI never drags in Tauri), which
also meant no root-level `cargo` invocation in `ci.yml` ever touched it — it
was only ever compiled by `release.yml`'s `build-gui` job, AFTER a version
tag was already pushed. Added `gui-fmt`/`gui-clippy`/`gui-test`/
`gui-build-os-matrix`/`gui-frontend` jobs scoped via `--manifest-path`.
Findings from actually turning these on:

- **The checked-in `Cargo.lock` for a path-dependency drifts silently when
  nothing ever builds with `--locked`.** Both `Cargo.lock`s (root and GUI)
  had the path-dep `dig-installer` entry pinned at a version *behind* the
  live `Cargo.toml` (the GUI's lock still said `0.4.0`/`0.5.0` after a root
  version bump nobody re-locked against). `cargo build --locked` doesn't
  care about *this* drift normally — but it fails outright the moment the
  lock's recorded version differs from what the path dep's own
  `Cargo.toml` reports, because `--locked` forbids the resync. Direct,
  reproducible proof of the exact gap #238 closes: this had clearly been
  broken for at least one prior version bump and nothing caught it. Fix is
  a 1-line hand-edit of the `version = "..."` field in the lock entry (path
  deps carry no checksum/source to reconcile) — far more minimal than
  `cargo update -p dig-installer`, which cascades into unrelated transitive
  version churn (observed: several `windows-sys`/`getrandom`/`tempfile`
  transitive versions shifted) because unlocking one package still lets the
  resolver re-pick anything downstream of it.
- **A `#[cfg(windows)]`-gated use site does NOT make an un-gated `const`
  declaration warning-free cross-platform.** `install.rs`'s
  `DIG_ICON_ICO` (an embedded `.ico` for the Windows ProgID icon) was a
  plain top-level `const`, but its only reader was inside a
  `#[cfg(windows)]` block — invisible on ubuntu-latest/macos-14, so
  `-D warnings` (`dead_code`) failed there despite the crate being
  perfectly clean on native Windows. This is the *exact* class of bug the
  root crate's `build-os-matrix` job's own header comment warns about,
  now caught in the GUI crate too. Fix: cfg-gate the const itself
  (mirrors the pre-existing `DIG_ICON_PNG` sibling one line below it).
- **The `ERROR_ELEVATION_REQUIRED` (Windows os error 740) quirk running
  this crate's compiled test binary does NOT reproduce on GitHub's hosted
  `windows-latest` runner** — reproduced locally on a non-elevated local
  Windows console, but the experimental `gui-test-windows` CI job (added
  non-blocking specifically to observe this) passed clean on the hosted
  runner. Whatever local heuristic triggers it (binary name containing
  "installer"?) either doesn't apply, or the hosted runner's default
  console privilege context differs. `gui-test` still runs its required
  copy on ubuntu-latest/macos-14 (this crate's only real test content is
  OS-agnostic pure logic), but this is a useful data point if the elevation
  question resurfaces — it is NOT a hosted-CI blocker.
- Tauri/`wry` on Linux needs `libwebkit2gtk-4.1-dev libappindicator3-dev
  librsvg2-dev patchelf` from apt just to **compile** (not just bundle) —
  `gui-clippy`/`gui-test` on ubuntu-latest install these first, mirroring
  `release.yml`'s `build-gui` Linux step. `cargo build`/`cargo test --no-run`
  against this crate do NOT require the frontend `dist/` to exist first —
  `tauri.conf.json`'s `beforeBuildCommand` only fires under the `tauri`
  CLI (`tauri build`/`tauri dev`), never under plain `cargo`.
- **CORRECTION (#424): `cargo clippy` is the exception to the bullet above —
  it DOES need `dist/` on a cold cache.** `src-tauri/src/lib.rs`'s
  `tauri::generate_context!()` reads `frontendDist` ("../dist") and PANICS
  at macro-expansion time if it's absent. `cargo build`/`cargo test --no-run`
  tolerate a missing `dist/` because a warm target dir reuses the cached
  rustc artifact without re-expanding the macro — but `clippy-driver` keeps
  its OWN separate metadata and always re-expands it fresh, so `gui-clippy`
  fails the moment its cache is cold (verified directly: `rm -rf target &&
  cargo clippy` fails without `dist/` present; `cargo build`/`cargo test
  --no-run` on the same clean `target/` do not). `gui-clippy`'s cache key is
  keyed on `gui/app/src-tauri/Cargo.lock` alone, so ANY change that touches
  the root `dig-installer` crate (a path-dependency of this one — a new
  field, a new module, a new upstream dep) forces a fresh recompile of this
  crate too, exposing the gap. Fixed by adding an `npm ci && npm run build`
  step to `gui-clippy` before its `cargo clippy` call (mirrors
  `release.yml`'s `build-gui` job, which already builds the frontend via
  `npx tauri build`'s `beforeBuildCommand`). `gui-fmt` (pure parsing, no
  macro expansion) and `gui-build-os-matrix`/`gui-test`'s compile step are
  unaffected — confirmed on a truly clean `target/` for both.

## Fail-loud installs — never trust a bare port probe or a clean-looking log (#492/#493/#496)

- **A "success" line must be earned, not printed.** The real bug: an un-elevated
  run masked a `dig-node install` exit-6 with a ✓, hit `CreateService 1073`, yet
  ended `✓ DIG is ready`. Lesson: the aggregate readiness verdict (`ready`/
  `failures` on `InstallReport`) is computed from VERIFIED post-conditions, and
  the green line + zero exit are gated on it. A component-level failure that was
  only logged (never propagated) is the classic false-success trap.
- **Verify the SERVICE, not the port.** The old post-install health check probed
  `rpc.discover` on 9778 — a dig-node started by ANYTHING (a manual `serve`, a
  stale process) answered, so the check passed without this run registering a
  service. Fix: query the OS service manager by the canonical service id
  (`net.dignetwork.dig-node`/`-dns`) — `sc query` STATE=RUNNING / `systemctl
  is-active` / `launchctl print state=running`. The port probe is secondary
  detail only. `svc.rs` owns the pure parsers.
- **Enforce elevation FIRST, before any write.** Registering a service / writing
  hosts needs admin; check it before downloading/writing so an un-elevated run
  fails fast (`NOT_ELEVATED`) with zero partial state, rather than half-installing
  then failing on the privileged step. `InstallPlan::requires_elevation()` scopes
  it (dry-run / digstore-only never trips it). Detection: Windows `net session`,
  Unix `id -u` == 0.
- **"On PATH" means resolvable from a FRESH shell, not just "a file exists".**
  `pathcheck` spawns each CLI by BARE NAME with PATH augmented to include the
  install bin dir, so it proves name-resolution the way the user's next shell
  will see it. On Windows the PATH write is followed by a `WM_SETTINGCHANGE`
  broadcast so new shells pick it up without a reboot.

## `--dry-run` still hits the network — a "network-free" test is a claim, not a default (#524)

- **`run_report`'s release RESOLUTION always runs; only the DOWNLOAD/WRITE is
  gated on `--dry-run`.** `resolve_component`/`resolve_dig_node` call the
  injected `ReleaseResolver` unconditionally; `download_component(&c,
  plan.dry_run)` is the only dry-run check. So a `--dry-run` invocation that
  leaves a component SELECTED (dig-node/dig-dns default ON, #301) still makes
  a real GitHub API call to resolve its "latest" release — `--dry-run` means
  "don't write", not "don't touch the network". Two `tests/cli.rs` e2e cases
  (the firewall-intent tests) learned this the hard way: passing no
  `--dig-node-version` left them racing `/releases/latest` on dig-node's own
  release timeline, reddening dig-installer's CI during ANY dig-node
  release-in-progress window (dig_ecosystem#524, surfaced by U7/#309's PR).
  Fix: PIN `--dig-node-version` to a specific, permanently-published tag in
  any e2e test/CI job that leaves a tracked component selected under
  `--dry-run` — a tagged release's asset list never changes shape after
  publish, so `release_by_tag` is deterministic where `/releases/latest`
  is not. Applies equally to the 3-OS installer e2e job (#502): its
  `DIG_NODE_VERSION`/`DIG_DNS_VERSION` are pinned constants, never "latest".
- **Running the installer as a real end user does (elevated) needs `sudo -E`,
  not bare `sudo`, on Linux/macOS.** `daemon_dir.rs`'s Unix ACL step reads
  `SUDO_USER` (which `sudo` always exports regardless) to grant the real
  interactive account read access to the machine-wide state dir, but `-E`
  additionally keeps `$HOME` pointed at the invoking user rather than root's
  — matching what a real UAC-elevated-as-yourself Windows run does
  (`elevation.rs` explicitly refuses a SYSTEM-token run for the identical
  reason, #499). Use `sudo -E` when scripting a real (non `--dry-run`)
  install/uninstall in CI or locally.
- **dig-dns's default gateway loopback IP (127.0.0.5) has no macOS alias out
  of the box.** Unlike Linux/Windows (which accept the whole 127.0.0.0/8
  range on the loopback interface), macOS only aliases 127.0.0.1 on `lo0` by
  default — without `sudo ifconfig lo0 alias 127.0.0.5 up` first, dig-dns's
  gateway can't bind either its primary or fallback port, so
  `dns.paths_live` stays empty and the aggregate `ready` verdict false even
  though the service process itself is registered/running fine (mirrors the
  same gotcha dig-dns's own CI already documents).

## A REAL install run (not dry-run, not a mock) surfaces bugs no unit/mock test can (#502)

Running the actual `dig-installer` binary end-to-end for the first time — the whole point of the
3-OS installer-e2e job — found THREE real, previously-invisible bugs in one pass, none catchable by
the existing mocked-resolver/mocked-service-backend unit suite:

- **A delegated subcommand's INHERITED stdio corrupts `--json` mode.** `service::run_dig_node`/
  `run_relay` used `.status()` (inheriting the child's stdio "so the user sees dig-node's own
  messages"). That's fine in PRETTY mode, but in `--json` mode dig-installer's OWN progress goes to
  STDERR (`eprintln!`) so ONLY its final JSON line reaches stdout — except the child's inherited
  stdio bypasses that routing entirely, writing its own prose directly onto the SAME stdout fd,
  ahead of the JSON line. Every existing `--json` e2e test happened to be `--dry-run` (which never
  spawns the subprocess), so this was invisible until a REAL install ran for the first time. Fixed:
  `run_capturing` (`Command::output()`, never `.status()`) captures unconditionally; a failure folds
  the captured text into the `Err` (nothing lost) and a success just discards it (dig-installer's
  own confirmation line already covers the event). Lesson: an inherited-stdio child process is
  incompatible with ANY "stdout is machine-readable" contract — capture always, surface via your OWN
  reporting layer instead.
- **Linux service-health check was scope-blind.** `svc::service_run_state_on(Os::Linux, ...)` ran a
  bare `systemctl is-active <id>` (system scope only) — but dig-node's own `install` unconditionally
  prefers a USER-level unit (`PREFERS_USER_LEVEL` in dig-node-service, a deliberate no-elevation
  design), while dig-installer's dig-dns wiring is machine-wide. A single system-scoped query could
  NEVER see a genuinely-running dig-node, permanently reporting "registered but NOT running" even on
  a perfectly healthy install. Fixed: query BOTH `systemctl --user is-active` and `systemctl
  is-active`, Running wins if either says so (`combine_systemctl_states`) — scope-agnostic rather
  than hardcoding which service registers where.
- **The canonical reverse-DNS id is NOT the real systemd unit name, on Linux only — for BOTH
  services.** Even after fixing the scope-blindness above, dig-node STILL read "registered but NOT
  running" — a direct `systemctl --user status net.dignetwork.dig-node` diagnostic step (added to
  the e2e job specifically to chase this) revealed the REAL unit was `dignetwork-dig-node.service`,
  not `net.dignetwork.dig-node.service`. Root cause: the `service-manager` crate (v0.7.1) names
  Linux units via `ServiceLabel::to_script_name()`, which DROPS the reverse-DNS qualifier ("net")
  and hyphen-joins `{organization}-{application}` — `net.dignetwork.dig-node` → `dignetwork-dig-node`.
  Windows (`sc.rs`) and macOS (`launchd.rs`) both use `to_qualified_name()` instead (dots preserved
  verbatim), so ONLY Linux drifts from the canonical id — an easy thing to miss since the id LOOKS
  platform-neutral. **This bit dig-dns too, and worse:** dig-installer's OWN `dns/linux.rs` ALSO
  registers dig-dns through this SAME `ServiceLabel` machinery (`net.dignetwork.dig-dns` parsed +
  installed via `service-manager`), yet a SEPARATE hardcoded constant
  (`dns::plan::SERVICE_SCRIPT_NAME = "dig-dns"`) — which LOOKED like the obvious dashed form —
  was used everywhere ELSE (existence checks, uninstall, notes) to refer to it. The REAL registered
  name is `dignetwork-dig-dns`, so `unit_registered()`'s clean-reinstall detection had ALSO been
  silently checking a unit that was never actually written, this whole time, entirely independent
  of the health-check bug. Fixed BOTH: `dns::plan::service_script_name()` now DERIVES the name (same
  transformation dig-dns's own registration applies, so the two can't drift apart again), and
  `svc::linux_unit_name` generically parses ANY canonical id through the same `ServiceLabel` +
  `to_script_name()` rather than hardcoding either result. Lesson: when a health check OR an
  existence check crosses a THIRD-PARTY library's own naming transformation, verify it against a
  REAL running instance on EVERY platform it claims to support, and DERIVE shared identifiers from
  ONE source rather than hand-copying a name that "looks right" into a second constant — a
  mock/unit test that supplies the parser with hand-written "active\n" text, or asserts a hardcoded
  constant equals itself, can never catch "we're asking systemctl about a unit that was never
  registered under that name in the first place."
- **Root has no systemd `--user`/D-Bus session by default (Linux, NOT yet fixed — dig_ecosystem#526).**
  Because dig-installer's elevation gate runs the WHOLE process as root whenever dig-node/dig-dns
  are selected, and dig-node's `install` always targets `--user` scope, a real `sudo dig-installer`
  run genuinely CANNOT register dig-node on Linux today (`systemctl --user` fails with "Failed to
  connect to bus: Operation not permitted" — root has no session unless one is explicitly
  provisioned, e.g. `loginctl enable-linger root` + `XDG_RUNTIME_DIR=/run/user/0`, the workaround the
  e2e CI job itself now applies). This is a genuine cross-repo design gap (dig-installer + dig-node),
  not merely a CI artifact — filed as dig_ecosystem#526 rather than silently worked around in
  production code.
- **Child `Command`s flash a console window on Windows unless `CREATE_NO_WINDOW` is set (#564).**
  A GUI/no-console parent (the Tauri installer) that spawns a console-subsystem child (`sc`, `net`,
  `netsh`, `powershell`, `icacls`, `whoami`, `cmd`, or a delegated dig-node/dig-dns/dig-updater verb)
  gets a brand-new console allocated for that child, which flashes on screen + steals focus for the
  child's lifetime — a storm of blinking boxes across a 15+-spawn install. Fix: the Win32
  `CREATE_NO_WINDOW` (`0x08000000`) creation flag on EVERY spawn, applied crate-wide via the one
  `proc::HideConsole::hide_console()` helper (no-op off Windows) rather than a literal per site. The
  flag hides ONLY the console — `.output()` stdio capture and exit codes are untouched — and
  `std::process::Command` exposes no getter for its creation flags, so the helper is tested
  behaviourally (a hidden child still runs + its stdout is still captured), not by reading the flag
  back. Same defect lives in `dig-updater-broker`'s own schtasks/service spawns — its own lane.
- **Adding a footer action can clip the primary at the window's min width (#564).** The Done screen's
  footer is a fixed-height flex row; adding the Close button pushed its content to ~567px, which
  overflowed (and clipped Launch Terminal) at the old 880px `minWidth` even though it was perfect at
  the 1080px default. `overflow` upstream hid the clip rather than scrolling, so `documentElement`
  showed no horizontal scroll — measure `footer.scrollWidth > footer.clientWidth`, not the document,
  to catch it. Fix: raise `tauri.conf.json` `minWidth` 880 → 980 so the three-action footer always
  has room. Lesson: a new nav/footer control must be re-verified at the window's MINIMUM size, not
  just its default.

## `select_asset` matches by OS/arch + extension only — the `stem` param is a TIE-BREAKER, not a filter (#548)

Adding the `dign`/`digd` alias binaries surfaced a real (and, on reflection, desirable) property of
`asset.rs::select_asset`: the `stem` argument never DISQUALIFIES a candidate — it only orders
multiple candidates that already matched on OS/arch token + accepted extension (`stem_rank` in the
scoring tuple). Consequently, resolving an alias whose OWN asset is genuinely absent from a release
(an old/pinned tag published before the alias existed) does NOT raise `ASSET_NOT_FOUND` as long as
the release has ANY OTHER raw-binary asset for that OS/arch — `select_asset` silently returns the
PRIMARY's own asset under the alias's query. This is harmless-by-design here (an alias and its
primary are byte-for-byte the same shape, so downloading the primary's asset and placing it at the
alias's dest is a correct fallback, not a bug) — but it means "no dedicated `<alias>-*` asset
published for this tag" is **not independently testable** via `select_asset`/`resolve_component`
returning `None`; it can only be exercised by making the WHOLE release lookup fail for the alias's
`Repo` (a different repo entirely, e.g. `dign`'s pre-rename `dig-companion` fallback divergence from
`Repo::dign()`). Two tests that assumed the former (giving a release with only primary-stem assets
and asserting the alias resolves to `None`) were flawed and had to be deleted — asset name matching
in this crate is genuinely permissive by design, not per-stem-strict.

## Cross-browser extension auto-update acceptance (#645)

Every Chromium-family browser (Chrome, Edge, Brave, Chromium, Vivaldi, Opera) force-installs +
auto-updates the DIG extension via the SAME `ExtensionInstallForcelist` policy + the SAME built-in
Chromium auto-updater polling the SAME `update_url` — the ONLY per-brand difference is the
managed-policy location (registry key / plist domain / JSON dir). Acceptance is tiered honestly:
Tier 1 (`tests/cross_browser_forcelist.rs`) proves the location + entry for every browser × OS
deterministically; Tier 2 (CI) proves the live `updates.dig.net` source serves a valid Omaha
manifest + fetchable CRX (stable full; nightly served-but-may-be-empty until its first build);
Tier 3 automates a real Chrome policy-file write on Linux CI, with the in-browser "installs +
auto-updates" step documented manual per `runbooks/cross-browser-ext-acceptance.md`. Force-install
via managed policy + a live `update_url` needs a REAL browser reading enterprise policy off the
network — not reliably CI-drivable headless for most brands, hence the honest auto-vs-manual split.
