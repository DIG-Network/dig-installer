# Universal DIG installer bootstrap (Windows, PowerShell).
#
#   irm https://raw.githubusercontent.com/DIG-Network/dig-installer/main/install.ps1 | iex
#
# Downloads the dig-installer binary for this machine from the latest
# DIG-Network/dig-installer release, then runs it to install the digstore CLI
# (the $DIG content tooling) and add it to PATH. To pass dig-installer flags
# (e.g. also install + start the dig-node local node as a Windows service),
# download then invoke with args:
#
#   $s = irm https://raw.githubusercontent.com/DIG-Network/dig-installer/main/install.ps1
#   & ([scriptblock]::Create($s)) --with-dig-node
#
# Flags are forwarded verbatim to dig-installer (see `dig-installer --help`).
#
# Note: registering the dig-node Windows service requires an elevated console;
# dig-node detects this and prints a clear message if you are not elevated.
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
