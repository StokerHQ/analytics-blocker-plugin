<#
.SYNOPSIS
Builds every Windows target stoker-plugin.yaml lists into build\<architecture>, and with -Linux the Linux target into
build\linux through WSL.

.DESCRIPTION
Fetches the Stoker plugin SDK release stoker-plugin.yaml pins (scripts\fetch-sdk.ps1: downloaded once, checked by
SHA-256, cached), then builds each Windows target with the SDK's helper. Needs Visual Studio with the C++ workload,
found through vswhere. -Linux runs build.sh in the default WSL distribution, which needs g++. STOKER_PLUGIN_SDK names
a local SDK folder or zip instead of the release.

The rules are compiled in from src\generated\rules.h; after changing rules\hosts.yaml, run tools\gen_rules.py first.
#>
param([switch]$Linux)
$ErrorActionPreference = 'Stop'
$root = $PSScriptRoot

$sdk = & (Join-Path $root 'scripts\fetch-sdk.ps1') -Project (Join-Path $root 'stoker-plugin.yaml')
$targets = @(Get-Content (Join-Path $root 'stoker-plugin.yaml') |
    Where-Object { $_ -match '^\s*-\s*\{\s*os:\s*windows' } |
    ForEach-Object { if ($_ -match 'architecture:\s*(\w+)') { $Matches[1] } })
foreach ($architecture in $targets) {
    $platform = if ($architecture -eq 'x86') { 'Win32' } else { 'x64' }
    $dll = & (Join-Path $sdk 'build\Build-HookPlugin.ps1') `
        -Source (Join-Path $root 'src\analytics_blocker_windows.cpp') `
        -Name 'analytics-blocker' -Platform $platform -Out (Join-Path $root "build\$architecture")
    Write-Host "Built $dll"
}

if ($Linux) {
    $wslRoot = (wsl -e wslpath -a ($root -replace '\\', '/')).Trim()
    $wslSdk = (wsl -e wslpath -a ($sdk -replace '\\', '/')).Trim()
    wsl -e env "STOKER_PLUGIN_SDK=$wslSdk" sh "$wslRoot/build.sh"
    if ($LASTEXITCODE -ne 0) { throw 'The Linux build failed.' }
}
