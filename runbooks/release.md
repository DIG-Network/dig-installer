# Runbook — releasing dig-installer (nightly cron + manual dispatch)

How this repo's universal `dig-installer` CLI + the Tauri GUI installers are built and released. The
shape is copied from the ecosystem's **reference nightlies system** (`dig-updater`, dig_ecosystem
#590/#592); the normative contract is `SPEC.md` §8. (General deploy/run ops live in
`runbooks/deployment.md` + `runbooks/local-running.md`.)

## TL;DR

- Releases are **NOT cut on merge to `main`**. Nightlies are batched to a **nightly cron at
  midnight UTC**; a **stable** release is cut ONLY by **manual dispatch** — the cron never cuts one.
- **Stable** (`vX.Y.Z`): cut ONLY on a manual `workflow_dispatch(channel: stable|both)`, and only
  when the root `Cargo.toml` version has advanced past the newest `vX.Y.Z` tag (an unchanged
  version is a no-op). Builds the CLI (4 OS/arch) + the Tauri GUI installers
  (`.exe`/`.dmg`/`.AppImage`). `prerelease: false`, marked `latest`.
- **Nightly**: built every night from `main` HEAD as a **pre-release** under a dated tag
  `nightly-YYYYMMDD` + a rolling `nightly` tag. `prerelease: true`, never `latest`. Keeps 14.

## Prerequisites / credentials

- **`RELEASE_TOKEN`** — an org-level classic PAT. Both channels no-op with a warning if it is
  absent. Pushes the changelog commit past branch protection + pushes tags that trigger downstream
  workflows (`GITHUB_TOKEN` cannot do either).

## Bumping the version — TWO lockfiles (path-dep trap)

The GUI crate `gui/app/src-tauri` depends on the root `dig-installer` crate by path, so its
`gui/app/src-tauri/Cargo.lock` carries a `dig-installer` entry. When you bump the root
`[package].version`, sync **both** lockfiles or the GUI's `--locked` build fails:

```bash
cargo update -p dig-installer
cargo update -p dig-installer --manifest-path gui/app/src-tauri/Cargo.toml
```

## If nightlies silently stop — check for the 60-day cron auto-disable

GitHub disables a `schedule:` trigger after **60 days of no repo activity** on a public repo, with
**no automatic re-enable** — and since this cron is the *only* automatic trigger for the **nightly**
channel (a stable release is never automatic, disabled or not), a quiet repo can go dark on
nightlies with no error. If nightlies stop appearing:

```bash
gh api repos/DIG-Network/dig-installer/actions/workflows/nightly-release.yml --jq .state
# "disabled_inactivity" means GitHub turned it off — re-enable it:
gh workflow enable nightly-release.yml --repo DIG-Network/dig-installer
```

Any repo activity (a merged PR, a manual dispatch) resets the 60-day counter.

## Cut a STABLE release (always a manual step)

The `stable` job is reachable ONLY from a manual `workflow_dispatch` — the midnight cron builds and
publishes nightlies but NEVER cuts a stable `vX.Y.Z` (CLAUDE.md §3.6-A). A merged version bump sits
on `main`, tagged and unreleased, until a maintainer deliberately dispatches the stable channel.

1. In your feature PR, bump the root `[package].version` per SemVer and sync both lockfiles (above).
   Merge the PR (squash).
2. Actions → **Nightly + stable release** → **Run workflow** → `channel: stable` (or `both`). The
   job sees the new version has no `vX.Y.Z` tag, regenerates `CHANGELOG.md`, commits
   `chore(release): vX.Y.Z` to `main`, tags it, and pushes with `RELEASE_TOKEN`.
3. The pushed `v*` tag fires `release.yml`, which builds the CLI + GUI and publishes the stable
   GitHub Release (changelog as notes).

### Re-cut a stable release (failed build)

- Same dispatch, with **`force: true`**. `force` REFUSES (non-zero exit) when the tag already has a
  PUBLISHED release AND points at a different commit than this run would build — it only proceeds
  for a same-commit retry or a tag with no published release. To ship new code, bump the version
  instead.

## Cut a NIGHTLY on demand

Actions → **Nightly + stable release** → **Run workflow** → `channel: nightly` (or `both`) → Run.

## Verify a release went live

- **Stable:** `gh release view vX.Y.Z --repo DIG-Network/dig-installer` — CLI (4 OS/arch) + GUI
  (`.exe`/`.dmg`/`.AppImage`), `prerelease: false`, marked latest. Watch: `gh run watch <id>`.
- **Nightly:** `gh release view nightly --repo DIG-Network/dig-installer` (rolling) or
  `gh release view nightly-YYYYMMDD` — `prerelease: true`.

## Workflows

| File | Trigger | Role |
|---|---|---|
| `nightly-release.yml` | midnight-UTC cron (nightly only) + `workflow_dispatch` (either channel) | Orchestrator: nightly (build + pre-release + prune) runs on schedule; stable (changelog + tag) runs ONLY on manual dispatch. |
| `release.yml` | `push: tags: v*` (+ dispatch canary) | Builds + publishes the stable Release (CLI + GUI) for a `vX.Y.Z` tag. |
| `build-binaries.yml` | `workflow_call` | Reusable cross-OS CLI + Tauri GUI build (both channels call it). |
| `ci.yml` | PR + push to main | fmt/clippy/test/coverage + the cross-OS CLI + GUI build matrix (pre-merge). |

## Local build (dev)

```bash
cargo build --release --locked --bin dig-installer
cargo test  --locked        # includes the workflow-shape guard tests
```
