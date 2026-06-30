#Requires -Version 5
<#
.SYNOPSIS
  Build and package the QPV2 GUI app for Windows (x86_64).

.DESCRIPTION
  Mirrors the build-gui-windows release job: builds the GUI (.exe, with
  its embedded icon), the vendored ckb-light-client.exe and ckb.exe, and
  pinentry-w32.exe (via MSYS2), then stages them into a folder (plus a
  .zip) under target\{debug,release}\.

  Prerequisites:
    - Rust toolchain (MSVC): https://rustup.rs
    - For pinentry: MSYS2 with the MinGW toolchain & autotools, e.g.
        pacman -S mingw-w64-x86_64-toolchain automake autoconf libtool make gettext-devel
      If bash.exe is not at C:\msys64\usr\bin\bash.exe, set $env:MSYS2_BASH.
    - Submodules: git submodule update --init --recursive

.PARAMETER Release
  Build in release mode (default: debug).

.EXAMPLE
  ./crates/qpv2-gui/scripts/bundle-windows.ps1 -Release
#>
param(
    [switch]$Release
)
$ErrorActionPreference = 'Stop'

$ScriptDir   = Split-Path -Parent $MyInvocation.MyCommand.Path
$ProjectRoot = (Resolve-Path (Join-Path $ScriptDir '..\..\..')).Path
Set-Location $ProjectRoot

$BuildType  = if ($Release) { 'release' } else { 'debug' }
$BinaryName = 'qpv2-gui'
$TargetDir  = Join-Path $ProjectRoot "target\$BuildType"
$PkgName    = 'qpv2-gui-windows-x86_64'
$PkgDir     = Join-Path $TargetDir $PkgName

function Invoke-Cargo {
    param([string[]]$ExtraArgs)
    $a = @('build') + $ExtraArgs
    if ($Release) { $a += '--release' }
    & cargo @a
    if ($LASTEXITCODE -ne 0) { throw "cargo $($a -join ' ') failed" }
}

if (-not (Get-Command cargo -ErrorAction SilentlyContinue)) {
    throw "cargo not found on PATH. Install Rust (MSVC): https://rustup.rs"
}

# ── Build pinentry-w32 (the default password dialog; always bundled) ──
# pinentry is required; a missing toolchain is a hard error so it gets
# fixed rather than silently producing a build without the default auth
# method.
$bash = $env:MSYS2_BASH
if (-not $bash) {
    foreach ($cand in @('C:\msys64\usr\bin\bash.exe', 'C:\msys2\usr\bin\bash.exe')) {
        if (Test-Path $cand) { $bash = $cand; break }
    }
}
if (-not $bash -or -not (Test-Path $bash)) {
    throw "MSYS2 bash not found - pinentry-w32 cannot be built. Install MSYS2 (https://www.msys2.org), then in its shell: pacman -S mingw-w64-x86_64-toolchain automake autoconf libtool make gettext-devel. If bash.exe is not at C:\msys64\usr\bin\bash.exe, set `$env:MSYS2_BASH."
}
$existingPinentry = Get-ChildItem (Join-Path $ProjectRoot 'vendor\pinentry-build\MINGW*\pinentry-w32.exe') -ErrorAction SilentlyContinue | Select-Object -First 1
if ($existingPinentry) {
    Write-Host "==> pinentry-w32 already built: $($existingPinentry.FullName)"
} else {
    Write-Host "==> Building pinentry-w32 via $bash (MINGW64)..."
    # Mirror the CI's `msystem: MINGW64` + `shell: msys2 {0}`: the login shell
    # reads MSYSTEM to put the MinGW64 toolchain on PATH, so build-pinentry.sh
    # sees `uname -s` = MINGW64_NT-... and writes to
    # vendor/pinentry-build/MINGW64_NT-...-<arch>/ (matched by the glob below).
    # Plain bash.exe defaults to MSYSTEM=MSYS, which builds the wrong flavor.
    $env:MSYSTEM = 'MINGW64'
    $unixRoot = (& $bash -lc "cygpath -u '$ProjectRoot'").Trim()
    & $bash -lc "cd '$unixRoot' && ./vendor/build-pinentry.sh"
    if ($LASTEXITCODE -ne 0) { throw "build-pinentry.sh failed under MSYS2 (MINGW64)" }
}

# ── Build binaries ────────────────────────────────────────────────
Write-Host "==> Building $BinaryName ($BuildType)..."
Invoke-Cargo @('-p', 'qpv2-gui')

Write-Host "==> Building ckb-light-client ($BuildType)..."
Invoke-Cargo @('-p', 'ckb-light-client', '--manifest-path', (Join-Path $ProjectRoot 'vendor\ckb-light-client\Cargo.toml'))

Write-Host "==> Building ckb ($BuildType)..."
Invoke-Cargo @('-p', 'ckb', '--manifest-path', (Join-Path $ProjectRoot 'vendor\ckb\Cargo.toml'))

$GuiBin   = Join-Path $TargetDir "$BinaryName.exe"
$LightBin = Join-Path $ProjectRoot "vendor\ckb-light-client\target\$BuildType\ckb-light-client.exe"
$NodeBin  = Join-Path $ProjectRoot "vendor\ckb\target\$BuildType\ckb.exe"
foreach ($b in @($GuiBin, $LightBin, $NodeBin)) {
    if (-not (Test-Path $b)) { throw "expected binary not found: $b" }
}

# ── Stage the package folder ──────────────────────────────────────
Write-Host "==> Packaging $PkgDir..."
if (Test-Path $PkgDir) { Remove-Item -Recurse -Force $PkgDir }
New-Item -ItemType Directory -Force -Path $PkgDir | Out-Null

Copy-Item $GuiBin   $PkgDir
Copy-Item $LightBin $PkgDir
Copy-Item $NodeBin  $PkgDir
$pinentry = Get-ChildItem (Join-Path $ProjectRoot 'vendor\pinentry-build\MINGW*\pinentry-w32.exe') -ErrorAction SilentlyContinue | Select-Object -First 1
if (-not $pinentry) { throw "pinentry-w32.exe not found under vendor\pinentry-build\MINGW*\" }
Copy-Item $pinentry.FullName $PkgDir

# ── Zip ───────────────────────────────────────────────────────────
$Zip = Join-Path $TargetDir "$PkgName.zip"
if (Test-Path $Zip) { Remove-Item -Force $Zip }
Compress-Archive -Path $PkgDir -DestinationPath $Zip

Write-Host ""
Write-Host "==> Done: $PkgDir"
Write-Host "    Archive: $Zip"
