# Development log

High-signal, durable realizations from building dig-installer. Concise facts with
context — not a change diary. See CLAUDE.md → §4.5 for how this is maintained.

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
  `release.yml`'s `build-gui` Linux step. `cargo build`/`clippy`/`test`
  against this crate do NOT require the frontend `dist/` to exist first —
  `tauri.conf.json`'s `beforeBuildCommand` only fires under the `tauri`
  CLI (`tauri build`/`tauri dev`), never under plain `cargo`; verified by
  removing `dist/` and rebuilding clean.
