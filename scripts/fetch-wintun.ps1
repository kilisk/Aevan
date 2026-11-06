# Fetch the exact Wintun release that the MSI and portable zip ship.
#
# The build never downloads Wintun implicitly: `just dist-windows` fails with a
# clear message if target\release\wintun.dll is absent, and this script is the
# explicit way to arrange it. WireGuard LLC's prebuilt-binary license allows
# redistribution alongside software that uses only the documented API; see
# packaging/legal/LICENSE-WINTUN.txt.
[CmdletBinding()]
param(
    [string]$Destination = ""
)

$ErrorActionPreference = "Stop"
$ProgressPreference = "SilentlyContinue"

$version = "0.14.1"
$expected = "E5DA8447DC2C320EDC0FC52FA01885C103DE8C118481F683643CACC3220DAFCE"
$url = "https://www.wintun.net/builds/wintun-$version.zip"

$root = Split-Path -Parent $PSScriptRoot
if ([string]::IsNullOrWhiteSpace($Destination)) {
    $Destination = Join-Path $root "target\release"
}

$target = Join-Path $Destination "wintun.dll"
if (Test-Path -LiteralPath $target) {
    $actual = (Get-FileHash -LiteralPath $target -Algorithm SHA256).Hash.ToUpperInvariant()
    if ($actual -eq $expected) {
        Write-Host "wintun.dll $version is already present at $target"
        exit 0
    }
    Write-Host "existing $target does not match Wintun $version; replacing it"
}

$work = Join-Path ([System.IO.Path]::GetTempPath()) ("aevan-wintun-" + [guid]::NewGuid().ToString("N"))
New-Item -ItemType Directory -Path $work | Out-Null
try {
    $zip = Join-Path $work "wintun-$version.zip"
    Write-Host "downloading $url"
    Invoke-WebRequest -Uri $url -OutFile $zip -UseBasicParsing

    Expand-Archive -Path $zip -DestinationPath $work -Force
    $source = Join-Path $work "wintun\bin\amd64\wintun.dll"
    if (-not (Test-Path -LiteralPath $source)) {
        throw "the Wintun archive did not contain wintun\bin\amd64\wintun.dll"
    }

    $actual = (Get-FileHash -LiteralPath $source -Algorithm SHA256).Hash.ToUpperInvariant()
    if ($actual -ne $expected) {
        throw "wintun.dll SHA256 mismatch: expected $expected, got $actual"
    }

    New-Item -ItemType Directory -Path $Destination -Force | Out-Null
    Copy-Item -LiteralPath $source -Destination $target -Force
    Write-Host "installed wintun.dll $version at $target (SHA256 $expected)"
}
finally {
    Remove-Item -LiteralPath $work -Recurse -Force -ErrorAction SilentlyContinue
}
