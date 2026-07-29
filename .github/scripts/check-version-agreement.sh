#!/usr/bin/env bash
# Version-source-agreement gate (#644, the #648 drift guard).
#
# dig-installer carries the SAME version in several files that MUST move in
# lockstep. When a bump touches one and forgets another, an installer ships with
# a mismatched self-reported version — the recurring #648 drift. This script is
# the CI guard: it extracts every version source and fails loudly (naming the
# offenders) unless each track is internally consistent.
#
# Two independent version tracks (the CLI crate and the GUI app version their
# own release cadences, so they are NOT required to equal each other — only to
# be self-consistent within their own set of files):
#   * CLI  : Cargo.toml            <-> Cargo.lock (dig-installer entry)
#   * GUI  : gui/app/package.json  <-> gui/app/src-tauri/tauri.conf.json
#            <-> gui/app/src-tauri/Cargo.toml
#            <-> gui/app/package-lock.json (root + digstore-installer entry)
#            <-> gui/app/src-tauri/Cargo.lock (digstore-installer entry)
set -euo pipefail

fail=0

# Every extractor below is a SINGLE awk process, deliberately — NOT a `grep -m1 | sed` pipeline.
#
# Under this script's own `set -euo pipefail`, `grep -m1` exits at its first match and SIGPIPEs
# whatever is upstream of it, so the pipeline yields 141, the command substitution fails, and `-e`
# aborts the script. Because these run BEFORE the first `echo`, the failure produced no output at all
# — a 15ms exit 1 that reads like a broken script rather than a flake. And it IS a flake: whether the
# upstream finishes writing before the downstream exits is a race, so it passed locally and
# intermittently in CI. (Same class as the three `grep -q` SIGPIPE sites fixed in #1748 round 9;
# swept ecosystem-wide as dig_ecosystem#1813.)
#
# awk also lets each extractor say what it did NOT find, instead of silently yielding an empty string
# that would then be compared as if it were a version.

# Print the first `version = "X"` line (TOML).
toml_version() {
  awk -F'"' '/^version = / { print $2; found=1; exit } END { if (!found) exit 3 }' "$1" \
    || { echo "check-version-agreement: no top-level 'version =' in $1" >&2; return 1; }
}

# Print the first top-level `"version": "X"` (JSON, 2-space indent).
json_top_version() {
  awk -F'"' '/^  "version": / { print $4; found=1; exit } END { if (!found) exit 3 }' "$1" \
    || { echo "check-version-agreement: no top-level '\"version\":' in $1" >&2; return 1; }
}

# --- extract the locked crate version (the `version` line that immediately
# follows the crate's `name = "..."` line in its [[package]] block). ---
locked_crate_version() { # $1=Cargo.lock  $2=crate-name
  awk -v want="name = \"$2\"" -F'"' '
      $0 == want { in_pkg = 1; next }
      in_pkg && /^version = / { print $2; found = 1; exit }
      END { if (!found) exit 3 }
    ' "$1" \
    || { echo "check-version-agreement: no [[package]] '$2' with a version in $1" >&2; return 1; }
}

check_track() { # $1=track-name ; remaining args = "label=value" pairs
  local track="$1"; shift
  local ref="" ref_label="" ok=1
  echo "== $track =="
  for pair in "$@"; do
    local label="${pair%%=*}" val="${pair#*=}"
    printf '   %-40s %s\n' "$label" "$val"
    if [ -z "$ref" ]; then ref="$val"; ref_label="$label"; fi
    if [ "$val" != "$ref" ]; then ok=0; fi
  done
  if [ "$ok" -ne 1 ]; then
    echo "   !! MISMATCH in $track — every source above must equal '$ref' (from $ref_label)"
    fail=1
  else
    echo "   ok: all $track sources agree on '$ref'"
  fi
}

# ---------------------------------------------------------------------------
# CLI crate track
# ---------------------------------------------------------------------------
CLI_TOML="$(toml_version Cargo.toml)"
CLI_LOCK="$(locked_crate_version Cargo.lock dig-installer)"
check_track "CLI crate" \
  "Cargo.toml=$CLI_TOML" \
  "Cargo.lock[dig-installer]=$CLI_LOCK"

# ---------------------------------------------------------------------------
# GUI app track
# ---------------------------------------------------------------------------
GUI_PKG="$(json_top_version gui/app/package.json)"
GUI_TAURI="$(json_top_version gui/app/src-tauri/tauri.conf.json)"
GUI_CARGO="$(toml_version gui/app/src-tauri/Cargo.toml)"
GUI_PKGLOCK_TOP="$(json_top_version gui/app/package-lock.json)"
# The package-lock's self-referential "packages"."" entry (its own version).
GUI_PKGLOCK_SELF="$(grep -m1 '^      "version": ' gui/app/package-lock.json | sed -E 's/.*"([^"]+)".*/\1/')"
GUI_CARGOLOCK="$(locked_crate_version gui/app/src-tauri/Cargo.lock digstore-installer)"
check_track "GUI app" \
  "gui/app/package.json=$GUI_PKG" \
  "gui/app/src-tauri/tauri.conf.json=$GUI_TAURI" \
  "gui/app/src-tauri/Cargo.toml=$GUI_CARGO" \
  "gui/app/package-lock.json[top]=$GUI_PKGLOCK_TOP" \
  "gui/app/package-lock.json[self]=$GUI_PKGLOCK_SELF" \
  "gui/app/src-tauri/Cargo.lock[digstore-installer]=$GUI_CARGOLOCK"

if [ "$fail" -ne 0 ]; then
  echo
  echo "Version sources disagree. Bump ALL of a track's files together (see #648)."
  exit 1
fi
echo
echo "All version sources agree within each track."
