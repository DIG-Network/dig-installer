#!/bin/sh
# Universal DIG installer bootstrap (macOS / Linux).
#
#   curl -fsSL https://raw.githubusercontent.com/DIG-Network/dig-installer/main/install.sh | sh
#
# Downloads the dig-installer binary for this OS/arch from the latest
# DIG-Network/dig-installer release, then runs it to install the digstore CLI
# (the $DIG content tooling) and add it to PATH. Pass dig-installer flags after
# `-s --`, e.g. to also install + start the dig-node local node as a service:
#
#   curl -fsSL .../install.sh | sh -s -- --with-dig-node
#
# Flags are forwarded verbatim to dig-installer (see `dig-installer --help`).
set -eu

REPO="DIG-Network/dig-installer"
STEM="dig-installer"

say()  { printf '%s\n' "$*"; }
die()  { printf 'error: %s\n' "$*" >&2; exit 1; }
have() { command -v "$1" >/dev/null 2>&1; }

# --- resolve OS/arch slug (must match the release matrix out_names) ---------
os="$(uname -s)"
arch="$(uname -m)"
case "$os" in
  Linux)  os_slug="linux-x64" ;;
  Darwin)
    case "$arch" in
      arm64|aarch64) os_slug="macos-arm64" ;;
      *)             os_slug="macos-x64" ;;
    esac ;;
  *) die "unsupported OS: $os (use install.ps1 on Windows)" ;;
esac

# --- discover the latest release tag ---------------------------------------
api="https://api.github.com/repos/${REPO}/releases/latest"
if have curl; then
  body="$(curl -fsSL "$api")"
elif have wget; then
  body="$(wget -qO- "$api")"
else
  die "need curl or wget to download"
fi
tag="$(printf '%s' "$body" | sed -n 's/.*"tag_name":[[:space:]]*"\([^"]*\)".*/\1/p' | head -n1)"
[ -n "$tag" ] || die "could not determine latest $REPO release tag"
ver="${tag#v}"

asset="${STEM}-${ver}-${os_slug}"
url="https://github.com/${REPO}/releases/download/${tag}/${asset}"

# --- download the installer binary -----------------------------------------
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT
bin="${tmp}/${STEM}"
say "Downloading ${STEM} ${ver} (${os_slug})…"
if have curl; then
  curl -fsSL "$url" -o "$bin" || die "download failed: $url"
else
  wget -qO "$bin" "$url" || die "download failed: $url"
fi
chmod +x "$bin"

# --- run it, forwarding any extra flags ------------------------------------
say "Running ${STEM} $*"
exec "$bin" "$@"
