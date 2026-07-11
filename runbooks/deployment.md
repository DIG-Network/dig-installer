# Runbook — deployment (release)

## Trigger

Tag-driven, per CLAUDE.md §3.6. On merge to `main`, `.github/workflows/changelog-tag.yml` reads
the version from `Cargo.toml`, regenerates `CHANGELOG.md` with git-cliff, commits
`chore(release): vX.Y.Z`, and pushes both the commit and the `vX.Y.Z` tag using
`secrets.RELEASE_TOKEN`. The pushed tag fires `.github/workflows/release.yml`.

## Credentials / secrets

- `secrets.RELEASE_TOKEN` — classic PAT, pushes the changelog commit + tag (bypasses branch
  protection and triggers the tag-push workflow, which the default `GITHUB_TOKEN` cannot do).
- No other secrets are required to build/release this repo (public GitHub API reads only; the
  release workflow does not need GitHub API auth for downloading other repos' assets, only for
  publishing its own).

## What gets built + where it lands

`release.yml` builds, on the tag:

- **Universal CLI** (`dig-installer`) for `windows-x64` / `linux-x64` / `macos-arm64` /
  `macos-x64` → attached to the GitHub Release as `dig-installer-<ver>-<os_arch>[.exe]`. This is
  the artifact `install.sh`/`install.ps1` download.
- **GUI installer** (Tauri, embeds the released `digstore` binary) → `DIG-Installer-Setup-<ver>-
  windows-x64.exe` (raw exe) / `-macos.dmg` / `-linux-x86_64.AppImage`, also attached to the same
  GitHub Release.

There is no S3/CloudFront/npm target for this repo — GitHub Releases is the only distribution
channel. `install.sh`/`install.ps1` (repo root) always resolve the LATEST release, so no
CDN/cache invalidation step is needed after a release goes live.

## Verify it went live

1. `gh run list --repo DIG-Network/dig-installer --workflow release.yml --limit 1` then
   `gh run watch <id>` — confirm every per-OS build job is green.
2. `gh release view vX.Y.Z --repo DIG-Network/dig-installer` — confirm all 7 expected assets are
   attached (4 CLI + 3 GUI).
3. Smoke-test the one-liner: `curl -fsSL https://raw.githubusercontent.com/DIG-Network/dig-installer/main/install.sh | sh -s -- --dry-run` (or the PowerShell equivalent) resolves the new
   version without error.

## Known gap (flag it, don't silently work around it)

`ci.yml`'s `fmt`/`clippy`/`test`/`build-os-matrix` jobs all run `cargo <cmd>` from the REPO ROOT.
`gui/app/src-tauri` declares its OWN `[workspace]` table (deliberately, so building the CLI never
drags in the Tauri/GUI dependency tree) — which also means none of those root-level PR gates ever
touch the GUI crate. The GUI crate is only ever actually compiled by `release.yml`, AFTER a tag is
already pushed — a GUI-only compile error is caught post-release, not pre-merge. Worth a follow-up
issue: add a `working-directory: gui/app/src-tauri` fmt/clippy/build job (test currently can't run
non-interactively on Windows in this crate — see the note below).
