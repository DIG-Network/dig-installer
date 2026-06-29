# Universal DIG installer bootstrap (Windows, PowerShell) — the one-line install.
#
#   irm https://raw.githubusercontent.com/DIG-Network/dig-installer/main/install.ps1 | iex
#
# Downloads the dig-installer binary for this machine from the latest
# DIG-Network/dig-installer release, then runs it. By default the installer is a
# THIN SHIM that resolves + installs the latest digstore CLI (the $DIG content
# tooling) and adds it to PATH. To pass installer flags (e.g. also install the
# dig-node service or the DIG Browser), download then invoke with args:
#
#   $s = irm https://raw.githubusercontent.com/DIG-Network/dig-installer/main/install.ps1
#   & ([scriptblock]::Create($s)) --with-dig-node          # + dig-node service + dig.local
#   & ([scriptblock]::Create($s)) --with-browser           # + DIG Browser installer
#   & ([scriptblock]::Create($s)) --with-dig-node --json   # machine-readable result
#
# Flags are forwarded verbatim to dig-installer (see `dig-installer --help` /
# `dig-installer --help-json`).
#
# Note: registering the dig-node Windows service (and writing the dig.local hosts
# entry) requires an elevated console; the installer surfaces a clear message and
# continues best-effort if you are not elevated.
[CmdletBinding()]
param([Parameter(ValueFromRemainingArguments = $true)] [string[]] $Args)

$ErrorActionPreference = 'Stop'
$Repo = 'DIG-Network/dig-installer'
$Stem = 'dig-installer'

# Windows ships x64; the universal binary runs on arm64 via emulation.
$osSlug = 'windows-x64'

Write-Host "Discovering latest $Repo release..."
$rel = Invoke-RestMethod -Uri "https://api.github.com/repos/$Repo/releases/latest" `
    -Headers @{ 'User-Agent' = 'dig-installer-bootstrap'; 'Accept' = 'application/vnd.github+json' }
$tag = $rel.tag_name
if (-not $tag) { throw "could not determine latest $Repo release tag" }
$ver = $tag.TrimStart('v')

$asset = "$Stem-$ver-$osSlug.exe"
$url = "https://github.com/$Repo/releases/download/$tag/$asset"

$tmp = Join-Path ([System.IO.Path]::GetTempPath()) ("dig-installer-" + [guid]::NewGuid())
New-Item -ItemType Directory -Path $tmp -Force | Out-Null
$bin = Join-Path $tmp "$Stem.exe"

Write-Host "Downloading $Stem $ver ($osSlug)..."
Invoke-WebRequest -Uri $url -OutFile $bin -UseBasicParsing

Write-Host "Running $Stem $($Args -join ' ')"
& $bin @Args
$code = $LASTEXITCODE
Remove-Item -Recurse -Force $tmp -ErrorAction SilentlyContinue
exit $code
