# Runbook — local running

## CLI (`dig-installer`)

Prereqs: a stable Rust toolchain (`rustup toolchain install stable`).

```sh
cargo build                       # builds target/debug/dig-installer[.exe]
cargo run -- --dry-run --with-dig-node --with-dig-dns --json   # exercise the full plan, no writes
cargo test                        # unit + e2e CLI-contract tests (network-free)
cargo fmt --all -- --check        # release gate
cargo clippy --all-targets --all-features -- -D warnings   # release gate
cargo llvm-cov --fail-under-lines 80 --ignore-filename-regex 'main\.rs$'   # coverage gate
```

No env vars are required to run the CLI locally; `--bin-dir` overrides the install location if
you don't want it touching your real PATH/service state while iterating.

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
cargo clippy --all-targets --all-features -- -D warnings
cargo fmt --all -- --check
```

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
