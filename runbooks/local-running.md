# Runbook — local running

## CLI (`dig-installer`)

Prereqs: a stable Rust toolchain (`rustup toolchain install stable`).

```sh
cargo build                       # builds target/debug/dig-installer[.exe]
cargo run -- --dry-run --json     # exercise the DEFAULT plan (digstore + dig-node + dig-dns + the auto-update beacon), no writes
cargo run -- --dry-run --with-relay --with-browser --json   # + the opt-in components
cargo run -- --dry-run --no-dig-node --no-dig-dns --no-auto-update --json    # opt out to just the digstore CLI
cargo run -- --dry-run --force-reinstall --json              # #309: preview overriding a would-be Skip
cargo test                        # unit + e2e CLI-contract tests (network-free)
cargo fmt --all -- --check        # release gate
cargo clippy --all-targets --all-features -- -D warnings   # release gate
cargo llvm-cov --fail-under-lines 80 --ignore-filename-regex 'main\.rs$'   # coverage gate
```

No env vars are required to run the CLI locally; `--bin-dir` overrides the install location if
you don't want it touching your real PATH/service state while iterating.

**Version-aware updater (#309):** re-running against a `--bin-dir` that already has a component
installed prints its Install/Update/Skip decision (`update_action`/`previous_version` in `--json`)
instead of blindly redownloading — point `--bin-dir` at a directory with an existing `dig-node`/
`dig-dns`/`digstore`/`dig-updater` binary to exercise Update/Skip locally; an empty dir always
decides Install.

**Upgrading over a RUNNING service — locked binary (#544):** before overwriting a component binary
on an Update, a running service is stopped first so it releases its executable (Windows locks a
running `.exe`, so overwriting it in place otherwise fails with "os error 32"). dig-node/dig-relay
delegate this to their own `stop` verb; dig-dns has no such verb, so the installer stops the OS
service it registered (`net.dignetwork.dig-dns`) via the service manager, then writes. If a binary
is STILL locked after that (e.g. a stray foreground `dig-dns serve` process, not the registered
service), the write does not fail: the new binary is staged and an atomic replace is scheduled for
the next reboot (Windows `MoveFileEx …DELAY_UNTIL_REBOOT`), and the run LOUDLY logs that a restart
is required. To reproduce locally on Windows: install once, leave the dig-dns service running, then
re-run with `--force-reinstall` against the same `--bin-dir` — the log shows `stopped the running
dig-dns service before replacing its binary`. If you ever see the "will apply on the next REBOOT"
notice, restart the machine to finish the update.

**Auto-update beacon (#514):** the beacon (`dig-updater` + its `dig-updater-worker` sibling) is
default-on like dig-node/dig-dns, so a bare `--dry-run` still resolves ITS latest release over the
real network too (resolution runs regardless of `--dry-run` — only the download is skipped). Add
`--no-auto-update` when iterating on something unrelated to keep the run scoped to what you're
actually testing; `--uninstall-dig-updater` reverses the scheduler registration a real run created
(delegates to `dig-updater schedule uninstall`, idempotent).

**Alias binaries `digs`/`dign`/`digd` (issues #434/#548):** selecting `digstore`/`dig-node`/
`dig-dns` also installs its alias binary (`digs`/`dign`/`digd` respectively) alongside it, in the
SAME bin dir, with no flag of its own — `--bin-dir` a directory to inspect after a real run shows
both files side by side. `SPEC.md` §1.1 has the full mechanics (including `dign`'s graceful skip
when a pinned/legacy dig-node release predates the alias).

**Firewall rule on Linux (#424):** a real (non-dry-run) `--with-dig-node` install never touches
Linux firewall state — it only prints the manual remedy. If you want the same reachability a
Windows/macOS install gets automatically, run it yourself: `sudo ufw allow 9444/tcp` (swap `9444`
for `$DIG_PEER_PORT` if you've overridden it, or the equivalent command for `firewalld`/`iptables`).

**Elevation is required for a REAL install** (not `--dry-run`): registering the dig-node/dig-dns
services, the beacon's daily scheduler artifact (#514), or writing the `dig.local` hosts entry
needs Administrator (Windows) / root (macOS/Linux).
An un-elevated real install is refused up front (`NOT_ELEVATED`, exit 11) with no partial state
(#492). Iterate against `--dry-run` (no elevation, no writes) or run the real path from an elevated
console. The run reports `✓ DIG is ready` ONLY when every selected component installed AND its
service is verified RUNNING (by service id via `sc query`/`systemctl is-active`/`launchctl print`)
AND each CLI (digstore/dig-node/dig-dns) resolves on PATH; otherwise it exits `INSTALL_INCOMPLETE`
(exit 12) listing what failed (#493/#496). After a real install, verify from a **new** shell:
`dig-node --version` / `dig-dns --version` / `digstore --version` all resolve.

**Cross-OS install -> health -> uninstall e2e (#502).** `.github/workflows/installer-e2e.yml` runs
this exact real, elevated install/uninstall cycle for both dig-node + dig-dns on
`windows-latest`/`macos-14`/`ubuntu-latest` on every PR touching `src/**`/`tests/**`, and can be
triggered manually via `gh workflow run installer-e2e.yml --repo DIG-Network/dig-installer`. It pins
`--dig-node-version`/`--dig-dns-version` to a known-good released tag (dig_ecosystem#524) rather than
"latest", so it stays deterministic across either repo's own release-in-progress window — bump the
`DIG_NODE_VERSION`/`DIG_DNS_VERSION` env values at the top of that workflow when validating a newer
release. To reproduce it locally on Linux/macOS: `sudo -E dig-installer --no-digstore --dig-node-version
<ver> --dig-dns-version <ver> --bin-dir /tmp/dig-bin --json` (Windows: run from an Administrator
console, no `sudo` needed).

## GUI (`gui/app`, Tauri 2)

Prereqs: Node 18+, the Rust stable toolchain, and the Tauri CLI prereqs for your OS
(see https://tauri.app/start/prerequisites/ — WebView2 on Windows, `libwebkit2gtk` on Linux).

```sh
cd gui/app
npm install
npm run dev            # vite dev server only (browser-simulated install, no Tauri backend)
npm run build           # vite production bundle (dist/) — sanity-checks the frontend compiles
npx tauri dev            # the REAL Tauri window, wired to the Rust backend (gui/app/src-tauri)
```

`npm run dev`/`vite preview` alone (no `tauri dev`) runs the GUI in a plain browser tab with
`bridge.js`'s **simulated** install (no real Tauri commands available — `window.__TAURI_INTERNALS__`
is undefined), useful for fast UI/theme/layout iteration and Playwright screenshot captures, but it
never exercises the real Rust install pipeline. Use `npx tauri dev` to test the real pipeline
(digstore embedded-payload install, plus dig-node/dig-dns/the auto-update beacon/dig-relay/browser
via the reused `dig_installer::run_report` — see `SPEC.md` §6). The Components screen's per-component Install/
Update/Skip pills (#309, `SPEC.md` §7.4) likewise fall back to a fixed demo dataset
(`SIM_COMPONENT_STATUS` in `bridge.js`) in plain-browser mode, so they're visible in a screenshot
without a Tauri build; only `tauri dev` checks REAL on-disk versions.

### Rust backend (`gui/app/src-tauri`)

```sh
cd gui/app/src-tauri
cargo build            # a plain library-level ../../../ path dep on the root dig-installer crate
cargo clippy --all-targets --all-features -- -D warnings   # needs gui/app/dist/ built first on a cold cache — see below
cargo fmt --all -- --check
```

**`cargo clippy` needs `gui/app/dist/` built first (on a cold cache).** `src-tauri/src/lib.rs`'s
`tauri::generate_context!()` reads the `frontendDist` config ("../dist") and panics at
macro-expansion time if it's missing. A plain `cargo build`/`cargo test --no-run` tolerates a
missing `dist/` (a warm target dir reuses the cached rustc artifact without re-running the macro),
but `clippy-driver` keeps its own metadata and always re-expands it — so run `cd gui/app && npm
install && npm run build` at least once before `cargo clippy` in this crate (CI's `gui-clippy` job
does this automatically).

**Known local-Windows quirk:** `cargo test` in this specific crate currently fails to even
*launch* its compiled test-harness binary on a non-elevated Windows console
(`the requested operation requires elevation`, os error 740) — `cargo check`/`clippy --all-targets`
(which compile but don't execute the test binary) are unaffected and are how the new
`plan_from_selection` unit tests were verified in this environment. This is Windows' own
"installer detection" heuristic (see the comment in `build.rs`) triggering on the compiled
`digstore_installer_lib-*.exe` test harness even with an explicit `asInvoker` manifest applied to
the app binary — the manifest embedding doesn't cover the separately-compiled test target. Not
introduced by any specific change; `ci.yml` never runs `cargo test` for this crate either (see
`runbooks/deployment.md`'s "known gap"). Run this crate's tests on Linux/macOS, or from an elevated
console, until that's fixed.

### Screenshot capture (manual/one-off, not a committed test suite)

There is no committed Playwright/Vitest suite for the GUI frontend yet (small wizard, no lint/test
script in `package.json`). For a quick visual check:

```sh
cd gui/app
npm run build
npx --yes vite preview --port 4173 --strictPort &
npx --yes playwright install chromium   # first time only
node -e "
  import('playwright').then(async ({chromium}) => {
    const b = await chromium.launch();
    const p = await b.newPage({ viewport: { width: 1200, height: 800 } });
    await p.goto('http://localhost:4173');
    await p.screenshot({ path: 'welcome.png' });
    await b.close();
  });
"
```

Drive `button.btn-primary`/`.agree` clicks to advance through License → Components as needed.
