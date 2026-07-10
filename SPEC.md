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

| id         | repo                          | kind                              | CLI flag(s)                          | Selected in the GUI wizard by default |
|------------|-------------------------------|------------------------------------|---------------------------------------|----------------------------------------|
| `digstore` | `DIG-Network/digstore`        | raw binary, added to PATH          | on by default; `--no-digstore` opts out; `--with-digstore` (redundant, symmetry) | always (required, no checkbox) |
| `dig-node` | `DIG-Network/dig-node`        | raw binary + OS service + `dig.local` hosts entry | `--with-dig-node` (alias `--service`) | yes |
| `dig-dns`  | `DIG-Network/dig-dns`         | raw binary + OS service + split-DNS/NRPT + browser DoH policy | `--with-dig-dns` | yes |
| `dig-relay`| `DIG-Network/dig-relay`       | raw binary + OS service (advanced, opt-in) | `--with-relay` | yes |
| `browser`  | `DIG-Network/DIG_Browser`     | native installer, downloaded only (not run) | `--with-browser` | yes |

The GUI wizard's Components screen (`gui/app/src/data.jsx` → `COMPONENTS`) lists exactly this
catalogue, one-line description each. **Every component is pre-selected by default** — "install
all" is the one-click default path; the user may deselect any component except `digstore` (marked
`REQUIRED`, no checkbox). Deselecting a component removes it from the install plan entirely (its
artifact is neither downloaded nor registered).

### 1.1 dig-dns availability gate

`dig-dns` (EPIC #174) may have no published release at all. If `with_dig_dns` is selected and no
release/matching asset can be resolved for it (an `ASSET_NOT_FOUND`-classified lookup — "nothing
published" as opposed to a network/transport failure), the installer:

- does NOT fail the overall install plan;
- records `InstallReport.dns` with `installed: false`, `started: false`,
  `needs_elevation: false`, and a `note` explicitly stating dig-dns is "not yet available" and
  naming EPIC #174;
- continues installing every other selected component (order preserved: digstore → dig-node →
  dig-dns[gated] → dig-relay → browser).

A genuine transport/network failure resolving dig-dns (not "no release exists") is NOT gated —
it propagates like any other component's resolution failure (`NETWORK`, exit code 4).

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

## 3. `InstallReport` (the `--json` payload)

Stable, versioned (`schema_version`) JSON shape emitted by `--json` on success:
`{schema_version, installer_version, target, dry_run, components[], path, service, relay, dns,
installed[]}`. See `src/lib.rs` doc comments on `InstallReport`/`ComponentResult`/`PathResult`/
`ServiceResult`/`RelayResult`/`dns::DnsInstallResult` for the exact field set; every boolean field
has a paired human-readable `*_note` — no field is ever silently omitted to signal failure.

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

This table is generated from `src/error.rs::EXIT_CODES` and mirrored in `--help-json`; the two
can never drift (`error::tests::exit_codes_table_matches_error_kinds`).

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
