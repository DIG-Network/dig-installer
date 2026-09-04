# Contributing to dig-installer

Thanks for your interest in improving the DIG installer. This is the universal,
thin-shim installer that resolves and installs the latest DIG components
(digstore CLI + `digs` alias, dig-node, dig-dns, the dig-updater auto-update
beacon, and optionally dig-relay + the DIG Browser) for the user's OS/arch. It
builds nothing itself — it consumes each component's own GitHub release
artifacts.

## Reporting an issue

File it at <https://github.com/DIG-Network/dig-installer/issues>. Since this
tool's whole job is OS/arch/network resolution, please include:

- your OS + arch (Windows/macOS/Linux, x64/arm64),
- the exact command you ran (flags matter — `--no-dig-app`, `--with-relay`, etc.),
- which component(s) it was resolving/installing/uninstalling when it failed,
- observed vs. expected behavior, and the installer's own output (it fails
  loud rather than silently, so the error text is usually diagnostic),
- a minimal repro if you can manage one.

## Prerequisites

- Stable Rust (there is no `rust-toolchain.toml` pin in this repo — CI installs
  whatever `stable` currently resolves to via `rustup toolchain install stable`).
- No build-time codegen step for the CLI crate itself — `cargo build` at the
  repo root just builds `dig-installer`.
- The repo also contains an **optional Tauri GUI crate** at
  `gui/app/src-tauri` (package `digstore-installer`). It deliberately declares
  its own empty `[workspace]` table, so it is never touched by a root-level
  `cargo` command — you only need it if you're changing the GUI. Building/
  linting/testing it needs Node 20 (`npm ci` in `gui/app`) and, on Linux,
  `libwebkit2gtk-4.1-dev libappindicator3-dev librsvg2-dev patchelf`.

### The installer e2e test — real OS services, not sandboxed

`.github/workflows/installer-e2e.yml` is a genuine end-to-end contract test: on
all three OSes (`windows-latest`, `macos-14`, `ubuntu-latest`) it builds
`dig-installer`, runs it to install **pinned** released versions of dig-node,
dig-dns, and dig-updater as **real OS services** (Windows SCM / launchd /
systemd), asserts they're registered and running under their canonical
service ids, that `dig.local` resolves, and that the update beacon's daily
scheduler artifact exists — then runs the installer's own
`--uninstall-dig-node`/`--uninstall-dig-dns`/`--uninstall-dig-updater` flags
and asserts everything (services, the hosts entry, the scheduler artifact) is
cleanly removed.

It only fires on a PR that touches `src/**`, `tests/**`, `Cargo.toml`,
`Cargo.lock`, or the workflow file itself (plus every push to `main` and manual
dispatch). It is **not realistically something to run locally** unless you're
in a disposable VM/container you don't mind having real services registered
and a hosts-file entry added to — it genuinely mutates OS state, which is the
whole point of the test. Let CI run it; if it fails on your PR, read the
per-OS job log rather than trying to reproduce the full install/uninstall
cycle on your own machine.

## Build & test

```sh
# build the CLI (root crate)
cargo build

# run its tests
cargo test --locked
```

To reproduce CI's coverage gate locally (see below) you'll need
`cargo-llvm-cov` and `cargo-nextest`:

```sh
cargo llvm-cov nextest --all-features --locked \
  --fail-under-lines 80 --ignore-filename-regex 'main\.rs$' --retries 2
```

`main.rs` is excluded from the coverage floor: it's thin binary glue whose
paths mostly require the network, so all agent-facing logic lives in the
library and is unit-tested there.

## The gate (must pass before a PR is merged)

`.github/workflows/ci.yml` runs on every PR to `main`. The jobs below are the
**required** contexts (all scoped to the root `dig-installer` crate unless
noted); reproduce them locally before opening a PR:

```sh
# rustfmt
cargo fmt --all -- --check

# vendored icon byte-pin (assets/dig.ico) — cheap, dependency-free
bash scripts/check-icon.sh

# clippy, no allow-list — every warning is an error
cargo clippy --all-targets --all-features --locked -- -D warnings

# test + coverage, gated at >=80% lines (main.rs excluded, see above)
cargo llvm-cov nextest --all-features --locked \
  --fail-under-lines 80 --ignore-filename-regex 'main\.rs$' --retries 2

# per-OS compile check (Windows + macOS runners in CI; this job is the only
# place #[cfg(windows)]/#[cfg(target_os = "macos")] code, e.g. src/dns/, is
# actually compiled pre-merge) — run on whichever OS you have:
cargo build --all-targets --locked

# every version source that must move in lockstep agrees with itself
bash .github/scripts/check-version-agreement.sh
```

If you touch anything under `gui/` (the optional Tauri GUI), CI also gates
that crate independently: `cargo fmt`/`clippy -D warnings`/`cargo nextest run`
via `--manifest-path gui/app/src-tauri/Cargo.toml`, plus `npm run lint` /
`npm run test:coverage` / `npm run build` in `gui/app`. See the `gui-*` jobs in
`ci.yml` for the exact commands if you're working in that area.

`.github/workflows/installer-e2e.yml` (above) is also required on any PR that
touches `src/**`, `tests/**`, or `Cargo.toml`/`Cargo.lock`.

`.github/workflows/cross-browser-ext-acceptance.yml` only fires on a PR that
touches `src/browsers.rs`, `src/forcelist/**`, `src/main.rs`, or
`tests/cross_browser_forcelist.rs`. It's **not** a required merge gate — its
Tier 2 job hits a live external endpoint (`updates.dig.net`, proving the
cross-browser extension auto-update manifest is actually being served) and is
deliberately non-blocking so a transient network blip can't fail an unrelated
PR; its Tier 3 job installs `google-chrome-stable` on Linux and reads back the
actual Chrome managed-policy file `dig-installer --set-ext-forcelist-channel`
writes, as a real (if single-browser) smoke test. The pure per-browser ×
per-OS matrix logic is already covered by `tests/cross_browser_forcelist.rs`
under the required `ci.yml` test job.

## PR conventions

- **Conventional Commits**, enforced by commitlint in CI: `type(scope): summary`,
  where `type` is one of `feat|fix|docs|style|refactor|perf|test|build|ci|chore|revert`.
  A breaking change appends `!` and/or a `BREAKING CHANGE:` footer.
- **Bump the version** in `Cargo.toml` as the last step before merge — patch
  for a compatible fix, minor for a compatible new capability, major for a
  breaking change. `.github/workflows/ensure-version-increment.yml` fails the
  PR if `Cargo.toml`'s version hasn't increased relative to `main`. (The
  optional GUI crate's own version files are checked only for *internal*
  agreement with each other — they don't need to move in lockstep with the
  root crate's version.)
- `main` is a protected branch: PR required, all checks above green, zero
  unresolved review threads, squash-merge only.
- **Releases are cut on a nightly cron, not on every merge.** Every midnight
  UTC, `.github/workflows/nightly-release.yml`'s `stable` job runs when:

  ```
  !startsWith(github.event.head_commit.message, 'chore(release):') &&
  (github.event_name == 'schedule' || inputs.channel == 'stable' || inputs.channel == 'both')
  ```

  In practice that means the cron itself is enough to cut a stable release: it
  reads the version from `Cargo.toml`, and if the tag `vX.Y.Z` for that version
  doesn't already exist, it generates the changelog, tags, and pushes —
  which fires `release.yml`'s binary build/publish. So merging a version bump
  to `main` doesn't publish a release immediately, but it **will** ship
  automatically at the next nightly cron, with no separate manual step
  required. The same workflow also builds and publishes an unversioned
  `nightly-YYYYMMDD` pre-release from `main` HEAD every night regardless of
  whether the version changed. A manual `workflow_dispatch` can drive either
  channel (or both) on demand.

## Where things live

| Path | Responsibility |
|---|---|
| `src/` | The installer CLI — resolution, download, per-OS service install, DNS/hosts wiring, the update-beacon registration |
| `tests/` | Integration tests against the built binary |
| `gui/app/` | Optional Tauri desktop GUI wrapper (its own workspace, independently gated) |
| `scripts/` | CI helper scripts (e.g. the icon pin check) |
| `runbooks/` | Deploy + local-run operational notes |
| `SPEC.md` | The normative contract for this installer's behavior |
