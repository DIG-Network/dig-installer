# Runbook — cross-browser extension force-install + auto-update acceptance (#645)

The DIG installer force-installs the DIG Chromium extension
(id `mlibddmbhlgogepnjdienclhnkfpkfah`) into every detected Chromium-family browser by writing an
`ExtensionInstallForcelist` managed-policy entry that pins that id to a self-hosted `update_url`.
Each browser's own built-in Chromium auto-updater then polls that URL and pulls new CRXs on its own
schedule.

This runbook is the acceptance record for the claim: **the force-installed extension force-installs
AND auto-updates across every supported Chromium browser, regardless of brand.** It states, per
browser × OS, exactly what is verified automatically vs. what is a documented manual acceptance
step — honestly (no tier is claimed to prove more than it does).

## The three tiers

| Tier | What it proves | How | Where |
|------|----------------|-----|-------|
| **1** | For every browser × OS, the installer targets the correct managed-policy location and writes the exact `"<id>;<update_url>"` entry. | Pure, deterministic Rust matrix test. Runs on the normal `cargo test` gate on every runner. | `tests/cross_browser_forcelist.rs` |
| **1b** | The write MECHANICS at each location kind (registry `REG_SZ`, plist array, JSON file) — org-policy merge + marker-owned removal. | Per-writer unit tests. | `src/forcelist/{windows,macos,linux}.rs` |
| **2** | The live `update_url` every browser polls serves a valid Omaha manifest for the DIG id + a fetchable CRX. | Live `curl` + `xmllint` against `updates.dig.net`, per channel. | `.github/workflows/cross-browser-ext-acceptance.yml` → `updates-endpoint-live` |
| **3 (auto)** | The SHIPPED binary writes a REAL browser's REAL managed-policy file end-to-end. | Install Google Chrome on Linux CI, run `dig-installer --set-ext-forcelist-channel`, read back `/etc/opt/chrome/policies/managed/dig-extension-forcelist.json`. | `.github/workflows/cross-browser-ext-acceptance.yml` → `linux-forcelist-smoke` |
| **3 (manual)** | A real browser, given the policy, actually shows the extension force-installed + enabled, then auto-updates to a newly published build. | Manual procedure below. | This runbook |

Why Tier 3 is only partly automated: force-install via managed policy + a live `update_url` needs a
REAL Chromium browser reading enterprise policy and hitting the network on its own update schedule —
not reliably reproducible in headless CI for most brands. Linux Chrome is the one brand a hosted
runner can drive to the point of the real policy-file write; confirming the extension actually
appears in the browser UI and auto-updates is the documented manual step.

## Coverage matrix — browser × OS × automated | manual

Legend: **T1** = policy-target + entry matrix (automated, every runner); **T2** = live update
source (automated CI); **T3a** = shipped-binary real policy-file write (automated CI); **T3m** =
manual "installs + auto-updates in the real browser UI".

| Browser  | Windows            | macOS              | Linux                       |
|----------|--------------------|--------------------|-----------------------------|
| Chrome   | T1 · T2 · **T3m**  | T1 · T2 · **T3m**  | T1 · T2 · **T3a** · T3m     |
| Edge     | T1 · T2 · **T3m**  | T1 · T2 · **T3m**  | T1 · T2 · **T3m**           |
| Brave    | T1 · T2 · **T3m**  | T1 · T2 · **T3m**  | T1 · T2 · **T3m**           |
| Chromium | T1 · T2 · **T3m**  | T1 · T2 · **T3m**  | T1 · T2 · **T3m**           |
| Vivaldi  | T1 · T2 · **T3m**  | T1 · T2 · **T3m**  | T1 · T2 · **T3m**           |
| Opera    | T1 · T2 · **T3m**  | T1 · T2 · **T3m**  | T1 · T2 · **T3m**           |

- **T1 + T2** are automated for **every** cell — the configuration matrix + the shared live update
  source are brand- and OS-complete.
- **T3a** (real policy-file write through the shipped binary) is automated for **Linux Chrome** only.
- **T3m** (the extension visibly installs + auto-updates in the browser UI) is the manual acceptance
  step for every cell; it is expected to be identical across brands because the mechanism is shared,
  but it is NOT claimed as auto-verified.

## Managed-policy location per browser × OS

The single per-OS mechanism; only the location differs (SPEC §1.9). This is what T1 asserts.

| Browser  | Windows `HKLM\` key                          | macOS prefs domain        | Linux managed dir                      |
|----------|----------------------------------------------|---------------------------|----------------------------------------|
| Chrome   | `SOFTWARE\Policies\Google\Chrome`            | `com.google.Chrome`       | `/etc/opt/chrome/policies/managed`     |
| Edge     | `SOFTWARE\Policies\Microsoft\Edge`           | `com.microsoft.Edge`      | `/etc/opt/edge/policies/managed`       |
| Brave    | `SOFTWARE\Policies\BraveSoftware\Brave`      | `com.brave.Browser`       | `/etc/brave/policies/managed`          |
| Chromium | `SOFTWARE\Policies\Chromium`                 | `org.chromium.Chromium`   | `/etc/chromium/policies/managed`       |
| Vivaldi  | `SOFTWARE\Policies\Vivaldi`                  | `com.vivaldi.Vivaldi`     | `/etc/opt/vivaldi/policies/managed`    |
| Opera    | `SOFTWARE\Policies\Opera Software\Opera`     | `com.operasoftware.Opera` | `/etc/opt/opera/policies/managed`      |

The entry value is identical for every cell:
`mlibddmbhlgogepnjdienclhnkfpkfah;https://updates.dig.net/ext/<channel>/updates.xml`.

## Manual acceptance procedure (T3m)

Run on a machine with the target browser(s) installed. Requires administrator/root (managed-policy
writes are privileged).

1. **Force-install.** Run the installer's force-install action for the channel:
   ```
   dig-installer --set-ext-forcelist-channel stable --json
   ```
   Confirm the JSON reports `ok: true` and a non-`failed` outcome for each detected browser.
2. **Confirm the policy landed.** Read the browser's managed-policy location from the table above
   and confirm the `ExtensionInstallForcelist` holds exactly the DIG entry (Windows: `reg query`;
   macOS: `defaults read <domain> ExtensionInstallForcelist`; Linux: `cat` the JSON file).
3. **Confirm in the browser.** Fully quit + relaunch the browser. Open its extensions page
   (`chrome://extensions`, `edge://extensions`, `brave://extensions`, `vivaldi://extensions`,
   `opera://extensions`) and confirm the DIG extension appears, is ENABLED, and is marked
   "Installed by your administrator" (force-installed, cannot be removed by the user).
   - Note the browser's update-check cadence: Chromium polls the `update_url` on a background
     schedule (typically every few hours / on launch). To force it, open the extensions page in
     developer mode and click **Update**, or relaunch the browser.
4. **Confirm auto-update.** After a NEW version is published to
   `https://updates.dig.net/ext/<channel>/updates.xml`, trigger an update check (step 3) or wait for
   the background poll, then confirm the extensions page shows the NEW version number within the
   browser's update window (nominally ≤24h for the background poll).
5. **Record.** Capture a screenshot of each browser's extensions page showing the force-installed,
   enabled DIG extension at the expected version, and note any per-brand quirk observed.

## Live-source check (T2, also runnable locally)

```
curl -fsSL https://updates.dig.net/ext/stable/updates.xml    # valid Omaha gupdate, our appid + codebase
curl -fsSI https://updates.dig.net/ext/stable/<the-codebase>.crx   # 200, application/x-chrome-extension
curl -fsSL https://updates.dig.net/ext/nightly/updates.xml   # valid gupdate; app entry optional until first nightly build
```

## Known honest caveats

- **Nightly channel** is served + armed but may carry NO published app entry until the first nightly
  CRX is cut; T2 asserts the manifest is valid + (if present) ours, never that a nightly build exists.
- **macOS managed preferences** are honored fully only under an MDM/profile-installed managed
  domain; the installer writes the standard managed-preferences plist, but a machine with a
  conflicting org profile is skipped rather than clobbered (SPEC §1.9). Verify T3m on macOS on a
  machine without a conflicting profile.
- **Opera** on some builds reads policy from `SOFTWARE\Policies\Opera Software\Opera`; confirm the
  location above matches the installed build during T3m.
