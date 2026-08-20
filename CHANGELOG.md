# Changelog

All notable changes to this project are documented here.
This project adheres to [Semantic Versioning](https://semver.org) and
[Conventional Commits](https://www.conventionalcommits.org).

## [0.45.1] - 2026-08-20

### Bug Fixes
- **download:** Retry transient GitHub API/network failures during install (#68)

## [0.45.0] - 2026-08-20

### Testing
- **recovery:** Prove the recovery paths assert outcomes, not plans (#1911) (#71)

## [0.44.1] - 2026-08-19

### CI
- Pin dig-dns version to 0.15.1 (#70)

## [0.44.0] - 2026-08-15

### Features
- **installer:** Embed the branded DIG icon in the Windows binary (#69)

## [0.43.0] - 2026-08-12

### Features
- **installer:** Select a headless-loadable dig-app build via the shared loadability check (#67)

### Testing
- **installer:** Root-secure the guarded-exec test fixtures so the suite runs as uid 0 (#2623)

## [0.42.3] - 2026-08-11

### Bug Fixes
- **installer:** Supersede only a legacy-shadow MSI, decided from install location (#2304)

### Testing
- **installer:** Pin supersede guards + hermetic FS test + both-scope PATH removal (#2305)

### Chores
- **deps:** Dig-constants git 0.3 → crates.io 0.10 (#63)

## [0.42.0] - 2026-08-07

### Bug Fixes
- **installer:** Remove a superseded install root; make the PATH verdict env-independent (#62)

## [0.41.0] - 2026-08-05

### Features
- **tls:** Provision the privileged TLS root on install so dig-node serves HTTPS (#858, #623)

## [0.40.2] - 2026-08-04

### Bug Fixes
- **installer:** Render progress log lines as structured segments, not innerHTML (#2040)- **installer:** Treat a user-scope dig-updater beacon registration as not-ours (#1873)

## [0.40.0] - 2026-08-03

### Features
- **gui:** Reframe the installer identity as the whole DIG Network, not the dig CLI (#56)- **readiness:** Gate a system-required daemon engine on reboot survival (#58)

### Bug Fixes
- **install:** Restore overwritten binaries on rollback, never delete them (#55)

### Testing
- **e2e:** Make the system-scope not-ready guard load-bearing on its reason (#57)

## [0.37.0] - 2026-08-01

### Features
- **service:** Register engines at an explicit scope, with reboot survival reported (#51)

### Bug Fixes
- **secure:** Own the files the elevated installer creates, so a reinstall can register dig-node (#54)

## [0.35.0] - 2026-08-01

### Features
- **uninstall:** Remove MSI-installed products with msiexec and complete the teardown (#53)

## [0.34.1] - 2026-07-31

### Bug Fixes
- **uninstall:** Honour --uninstall in the installed GUI binary so Add/Remove Programs works (#52)

## [0.34.0] - 2026-07-31

### Features
- **install:** Launch dig-app when the install completes, de-elevated to the user (#50)

## [0.33.0] - 2026-07-31

### Bug Fixes
- **migrate:** Guard, order and roll back the beacon re-arm; report lost auto-updates (#49)

## [0.32.0] - 2026-07-31

### Features
- **gui:** Check dig-app by default, and lock dig-node while it is selected (#48)

## [0.31.2] - 2026-07-29

### Bug Fixes
- **gui:** Key the WebView2 pin on SYSTEM, not elevation — the real #1819 cause (#47)

## [0.31.1] - 2026-07-29

### Bug Fixes
- **gui:** Pin WebView2 to the machine root only when the token can write it (#46)

## [0.31.0] - 2026-07-29

### Bug Fixes
- **install:** Install for the invoking user under sudo and make the self-checks falsifiable (#45)

## [0.30.0] - 2026-07-28

### Features
- **payload:** Install dig-app with per-user autostart on all four platforms

## [0.29.2] - 2026-07-17

### Bug Fixes
- **secure:** Force SYSTEM ownership on created Windows install-root levels (#732) (#42)

## [0.29.1] - 2026-07-17

### Bug Fixes
- **gui:** Pin WEBVIEW2_USER_DATA_FOLDER + fix Done-screen footer overflow (#715 #716) (#41)

## [0.29.0] - 2026-07-17

### Features
- Dig-store rename cutover + complete GUI i18n (#40)

## [0.28.0] - 2026-07-16

### Features
- **security:** Installer command-exec, file-write + registration-audit hardening (#39)

## [0.27.0] - 2026-07-16

### Features
- Consume dig-dns v0.14.0 configure-os for live DNS activation (WU2) (#38)

## [0.26.0] - 2026-07-16

### Features
- Installer batch — scheme delegation, uninstall, hardening, GUI i18n/lint/CI (#37)

## [0.25.0] - 2026-07-16

### Features
- **macos:** GUI elevation via osascript + un-withhold .dmg (#639) (#36)

## [0.24.1] - 2026-07-16

### Testing
- **ext-acceptance:** Cross-browser force-install + auto-update E2E (#645) (#35)

## [0.24.0] - 2026-07-16

### Features
- **install:** Force-install the extension in the elevated install flow (#648) (#34)

## [0.23.0] - 2026-07-16

### Features
- **forcelist:** ExtensionInstallForcelist writer + remover per browser per OS (#612) (#33)

## [0.22.0] - 2026-07-16

### Features
- **gui:** Linux GUI elevation via pkexec + un-withhold .AppImage (#638) (#32)

## [0.21.0] - 2026-07-16

### Features
- **gui:** Extension component + conditional scrollable per-browser checklist step (#611) (#31)

## [0.20.0] - 2026-07-16

### Features
- **browsers:** Detect installed Chromium browsers per OS (#609) (#30)

## [0.19.1] - 2026-07-16

### Bug Fixes
- **gui:** Unix write-then-exec hardening (#637) (#29)

## [0.19.0] - 2026-07-16

### Bug Fixes
- **gui:** Route privileged components through the protected install root (#28)

## [0.18.0] - 2026-07-15

### Bug Fixes
- **security:** Run privileged services from a protected install root (#25)

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


