# Runbook — local running

## CLI (`dig-installer`)

Prereqs: a stable Rust toolchain (`rustup toolchain install stable`).

```sh
cargo build                       # builds target/debug/dig-installer[.exe]
cargo run -- --dry-run --json     # exercise the DEFAULT plan (digstore + dig-node + dig-dns), no writes
cargo run -- --dry-run --with-relay --with-browser --json   # + the opt-in components
cargo run -- --dry-run --no-dig-node --no-dig-dns --json    # opt out to just the digstore CLI
cargo test                        # unit + e2e CLI-contract tests (network-free)
cargo fmt --all -- --check        # release gate
cargo clippy --all-targets --all-features -- -D warnings   # release gate
cargo llvm-cov --fail-under-lines 80 --ignore-filename-regex 'main\.rs$'   # coverage gate
```

No env vars are required to run the CLI locally; `--bin-dir` overrides the install location if
you don't want it touching your real PATH/service state while iterating.

**Firewall rule on Linux (#424):** a real (non-dry-run) `--with-dig-node` install never touches
Linux firewall state — it only prints the manual remedy. If you want the same reachability a
Windows/macOS install gets automatically, run it yourself: `sudo ufw allow 9444/tcp` (swap `9444`
for `$DIG_PEER_PORT` if you've overridden it, or the equivalent command for `firewalld`/`iptables`).

**Elevation is required for a REAL install** (not `--dry-run`): registering the dig-node/dig-dns
services + writing the `dig.local` hosts entry needs Administrator (Windows) / root (macOS/Linux).
An un-elevated real install is refused up front (`NOT_ELEVATED`, exit 11) with no partial state
(#492). Iterate against `--dry-run` (no elevation, no writes) or run the real path from an elevated
console. The run reports `✓ DIG is ready` ONLY when every selected component installed AND its
service is verified RUNNING (by service id via `sc query`/`systemctl is-active`/`launchctl print`)
AND each CLI (digstore/dig-node/dig-dns) resolves on PATH; otherwise it exits `INSTALL_INCOMPLETE`
(exit 12) listing what failed (#493/#496). After a real install, verify from a **new** shell:
`dig-node --version` / `dig-dns --version` / `digstore --version` all resolve.

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
(digstore embedded-payload install, plus dig-node/dig-dns/dig-relay/browser via the reused
`dig_installer::run_report` — see `SPEC.md` §6).

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
