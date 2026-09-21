# Build two release artifacts in one command:
#   dist/port-scan-rs-lite.exe   default build, zero external dependency (no NIC capture)
#   dist/port-scan-rs-full.exe   with the `pcap` feature, supports NIC capture
#
# NOTE: this script is intentionally ASCII-only. Windows PowerShell 5.1 reads
# .ps1 files as ANSI unless they carry a UTF-8 BOM, so non-ASCII text here would
# get mangled and break parsing.
#
# Npcap's kernel driver cannot be embedded into the exe and the free edition
# forbids redistribution, so the `full` build expects the target machine to
# install Npcap itself. Without Npcap the exe still starts (wpcap.dll is
# delay-loaded) and only reports guidance when capture is requested.
#
# Usage:
#   powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\build-release.ps1
#   powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\build-release.ps1 -SkipFull
#   powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\build-release.ps1 -Profile dev
[CmdletBinding()]
param(
    [string]$OutDir = 'dist',
    [ValidateSet('release', 'dev')]
    [string]$Profile = 'release',
    [switch]$SkipFull
)

$ErrorActionPreference = 'Stop'

$root = Split-Path -Parent $PSScriptRoot
Push-Location $root
try {
    # the `dev` profile writes to target/debug
    $profileDir = if ($Profile -eq 'dev') { 'debug' } else { $Profile }
    $binDir = Join-Path $root "target/$profileDir"

    $outDir = Join-Path $root $OutDir
    New-Item -ItemType Directory -Force -Path $outDir | Out-Null

    function Copy-Artifact([string]$source, [string]$target) {
        $src = Join-Path $binDir $source
        if (-not (Test-Path $src)) { throw "build artifact not found: $src" }
        Copy-Item $src $target -Force
    }

    function Show-Artifact([string]$path, [string]$label) {
        $item = Get-Item $path
        $hash = (Get-FileHash $path -Algorithm SHA256).Hash.Substring(0, 16)
        Write-Host ("  {0,-6} {1,9:N0} KB   sha256:{2}..." -f $label, ($item.Length / 1KB), $hash)
    }

    # ---------- 1) lite: default features, no external dependency ----------
    Write-Host "[1/2] building lite (default features, no Npcap needed) ..." -ForegroundColor Cyan
    & cargo build --profile $Profile
    if ($LASTEXITCODE -ne 0) { throw "lite build failed (cargo exit code $LASTEXITCODE)" }

    $lite = Join-Path $outDir 'port-scan-rs-lite.exe'
    Copy-Artifact 'port-scan-rs.exe' $lite

    # ---------- 2) full: with the pcap feature ----------
    $full = $null
    $gui = $null
    if ($SkipFull) {
        Write-Host "[2/2] skipping full build (-SkipFull)" -ForegroundColor Yellow
    }
    else {
        Write-Host "[2/2] building full (pcap feature) ..." -ForegroundColor Cyan

        if (-not $env:LIBPCAP_LIBDIR) {
            # look for the Npcap SDK in the usual places
            $candidates = @()
            if ($env:NPCAP_SDK_DIR) { $candidates += (Join-Path $env:NPCAP_SDK_DIR 'Lib\x64') }
            $candidates += @(
                (Join-Path $env:USERPROFILE 'npcap-sdk\Lib\x64'),
                'C:\npcap-sdk\Lib\x64',
                'C:\Program Files\Npcap\SDK\Lib\x64'
            )

            $found = $candidates |
                Where-Object { Test-Path (Join-Path $_ 'wpcap.lib') } |
                Select-Object -First 1

            if (-not $found) {
                throw @'
Cannot find wpcap.lib from the Npcap SDK, so the "full" build cannot be linked.
Download the Npcap SDK: https://npcap.com/#download
then unpack it and set the env var before re-running this script:

    $env:LIBPCAP_LIBDIR = 'C:\npcap-sdk\Lib\x64'
    powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\build-release.ps1

Or build the lite version only:

    powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\build-release.ps1 -SkipFull
'@
            }
            $env:LIBPCAP_LIBDIR = $found
        }
        Write-Host "      LIBPCAP_LIBDIR=$env:LIBPCAP_LIBDIR"

        & cargo build --profile $Profile --features pcap
        if ($LASTEXITCODE -ne 0) { throw "full build failed (cargo exit code $LASTEXITCODE)" }

        $full = Join-Path $outDir 'port-scan-rs-full.exe'
        Copy-Artifact 'port-scan-rs.exe' $full

        # 仅 GUI 的目标（Windows 子系统）：双击不会出现控制台黑窗口。
        # 用 pcap 版本，这样 GUI 里的「网卡抓包」可用。
        $gui = Join-Path $outDir 'port-scan-rs-gui.exe'
        Copy-Artifact 'port-scan-rs-gui.exe' $gui
    }

    # ---------- 3) release zip + sha256 ----------
    $versionLine = Select-String -Path (Join-Path $root 'Cargo.toml') `
        -Pattern '^version\s*=\s*"([^"]+)"' | Select-Object -First 1
    if (-not $versionLine) { throw "cannot read [package] version from Cargo.toml" }
    $version = $versionLine.Matches[0].Groups[1].Value

    $zipName = "port-scan-rs-$version-x64.zip"
    $zipPath = Join-Path $outDir $zipName

    $payload = @($lite)
    if ($full) { $payload += $full }
    if ($gui) { $payload += $gui }
    foreach ($extra in @('LICENSE', 'README.md')) {
        $p = Join-Path $root $extra
        if (Test-Path $p) { $payload += $p }
    }

    Remove-Item $zipPath -Force -ErrorAction SilentlyContinue
    Compress-Archive -Path $payload -DestinationPath $zipPath -Force

    # sha256sum 风格：<hash>  <filename>，Scoop 的 hash.url 可以直接读
    $zipHash = (Get-FileHash $zipPath -Algorithm SHA256).Hash.ToLower()
    "$zipHash  $zipName" | Set-Content -Path "$zipPath.sha256" -Encoding ascii

    # ---------- summary ----------
    Write-Host ""
    Write-Host "artifacts written to $outDir :" -ForegroundColor Green
    Show-Artifact $lite 'lite'
    if ($full) { Show-Artifact $full 'full' }
    if ($gui) { Show-Artifact $gui 'gui' }
    Show-Artifact $zipPath 'zip'
    Write-Host "  sha256 $zipHash"
    Write-Host "         (also in $zipName.sha256)"

    Write-Host ""
    Write-Host "notes:" -ForegroundColor Green
    Write-Host "  lite  local / scan / ifaces(system enumeration) / analyze / gui, no external component"
    if ($full) {
        Write-Host "  full  adds NIC capture; the target machine must install Npcap"
        Write-Host "        (check 'WinPcap API-compatible Mode'); without it the exe still starts"
        Write-Host "        and only explains how to install when ifaces / capture is used"
    }
    Write-Host "  gui   GUI-only exe (Windows subsystem): double-click shows no console window"
    Write-Host "  zip   release asset for GitHub Releases / Scoop (all exes + LICENSE + README)"
}
finally {
    Pop-Location
}
