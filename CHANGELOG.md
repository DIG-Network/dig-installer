# Changelog

All notable changes to this project are documented here.
This project adheres to [Semantic Versioning](https://semver.org) and
[Conventional Commits](https://www.conventionalcommits.org).

## [0.2.0] - 2026-07-07

### Features
- **dig-dns:** Install dig-dns as an OS service on all 3 platforms (#4)

## [0.1.3] - 2026-07-04

### Bug Fixes
- **browser:** Resolve DIG Browser's prerelease-only alpha asset naming (#3)

## [0.1.2] - 2026-07-04

### CI
- Add PR quality gates (fmt/clippy/test/build) [#230] (#2)

## [0.1.1] - 2026-07-04

### Bug Fixes
- **ci:** Authenticate digstore release fetch to avoid GitHub API rate-limit 403s (#1)

## [0.1.0] - 2026-07-04

### #168
- Set DIG_NODE_PORT (was DIG_COMPANION_PORT) for the installed service

### Features
- Thin-shim resolution, dig.local, and agent-friendly CLI

### Documentation
- Accurate digstore asset-naming contract in target.rs- Document the thin shim, dig.local, agent surfaces, one-line install

### CI
- Enforce version increment in PRs (package.json / Cargo.toml)- Enforce Conventional Commits with commitlint on PRs- Enforce Conventional Commits with commitlint on PRs- Changelog + tag on merge feeding the existing tag-driven binary release (#230)

### Chores
- **changelog:** Add git-cliff config for Conventional-Commit changelog

### CI
- Gate test coverage at >=80% lines with cargo-llvm-cov

### Gui
- Correct stage-binary error hint for the new home


