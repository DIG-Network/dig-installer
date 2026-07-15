# Changelog

All notable changes to this project are documented here.
This project adheres to [Semantic Versioning](https://semver.org) and
[Conventional Commits](https://www.conventionalcommits.org).

## [0.17.1] - 2026-07-15

### CI
- **release:** Nightlies system (cron + dispatch, nightly channel) (#592) (#26)

## [0.17.0] - 2026-07-14

### Features
- **install:** Install dign + digd alias binaries alongside dig-node/dig-dns (#548) (#24)

## [0.16.0] - 2026-07-14

### Features
- **install:** Hide child-process console windows + Finish-view Close button (#23)

## [0.15.1] - 2026-07-14

### Bug Fixes
- **install:** Stop+deregister dig-dns service before replacing its binary (Windows os error 32) (#22)

## [0.15.0] - 2026-07-14

### Features
- **installer:** Install + register the auto-update beacon by default (#514) (#21)

## [0.14.0] - 2026-07-13

### Features
- **installer:** 3-OS install->health->uninstall e2e CI + Linux service-identity fixes it found (#20)

## [0.13.0] - 2026-07-13

### Features
- **installer:** Version-aware updater — detect/update/skip per component (#309) (#19)

## [0.12.0] - 2026-07-13

### Features
- **installer:** App-scoped firewall option for dig-node's peer-RPC port (#18)

## [0.11.0] - 2026-07-13

### Features
- **installer:** Default components (#491) + chia:// scheme handler (#389) (#16)

## [0.10.0] - 2026-07-13

### Bug Fixes
- **installer:** P0 install-correctness — no SYSTEM token, daemon state dir, dig.local, dig-dns start (#17)

## [0.9.0] - 2026-07-13

### Bug Fixes
- Enforce elevation + fail loud + verify real service/CLI health (#13)

## [0.8.1] - 2026-07-13

### Bug Fixes
- **ci:** Release.yml coverage gate rejects --retries as a test-binary arg (#15)

## [0.8.0] - 2026-07-13

### Features
- **dns:** Dig-dns service display name + clean-reinstall (#494) (#14)

## [0.7.1] - 2026-07-12

### CI
- Add flaky-test management (#489) (#12)

## [0.7.0] - 2026-07-12

### Features
- **install:** Install the digs alias binary alongside digstore (#11)

## [0.6.1] - 2026-07-11

### Bug Fixes
- Rename GUI setup bundle DigStore-Setup to DIG-Installer-Setup (#10)

## [0.6.0] - 2026-07-11

### Features
- Default-install the full DIG stack + boot-start services, rebrand to DIG Installer (#9)

## [0.5.1] - 2026-07-10

### CI
- Gate the Tauri GUI crate (gui/app/src-tauri) pre-merge (#8)

## [0.5.0] - 2026-07-10

### Features
- **installer:** Dark theme, component selection, service stop/restart lifecycle (#7)

## [0.4.0] - 2026-07-10

### Features
- **dig-node:** Post-install RPC health check for the dig-node service (#6)

## [0.3.0] - 2026-07-10

### Features
- **hosts:** Harden dig.local registration + add dig-node uninstall (#5)

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


