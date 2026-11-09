<#
.SYNOPSIS
    The plugin end to end inside Stoker's real Windows hook host: started by stoker-inject with the carrier and
    stoker_hookhost.dll before the stand-in game's first instruction, as the launcher starts every game.

.DESCRIPTION
    Needs a Stoker checkout with the Release builds of stoker_loader.dll, stoker_hookhost.dll and stoker-inject.exe for
    both architectures (-Stoker), the plugin's DLLs in build\x64 and build\x86 (build.ps1), and Visual Studio's C++
    tools for the stand-in game.

    The blocked name is this machine's own host name, given in extraHosts: it resolves locally with no network, so a
    "not found" can only be the plugin's. Each API the plugin hooks is asked for it:

      0. without the modules, every API answers (the control);
      1. x64 and x86: every API answers "not found", localhost still answers, and the log names the block once;
      2. the same name in allowHosts answers;
      3. the same name as the host of STOKER_URL answers - what Stoker needs is never blocked;
      4. observe mode answers, and logs "would block";
      5. a 64-bit child of a 32-bit game is blocked too (the carrier gives it the modules).

    Exit code 0 is a pass.
#>
param(
    [Parameter(Mandatory)][string] $Stoker
)
$ErrorActionPreference = 'Stop'
$repo = (Resolve-Path (Join-Path $PSScriptRoot '../..')).Path
$Stoker = (Resolve-Path $Stoker).Path
$work = (New-Item -ItemType Directory -Force (Join-Path ([IO.Path]::GetTempPath()) "analytics-blocker-e2e-$PID")).FullName
$vs = & "${env:ProgramFiles(x86)}\Microsoft Visual Studio\Installer\vswhere.exe" -latest -products '*' -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath
$env:PATH += ";${env:ProgramFiles(x86)}\Microsoft Visual Studio\Installer"

$runtime = Join-Path $work 'runtime'
$game = Join-Path $work 'game'
$data = Join-Path $game '.stoker'
$injected = Join-Path $data 'injected'
New-Item -ItemType Directory -Force $game, $injected | Out-Null

$plugins = @{}
foreach ($arch in 'x86', 'x64') {
    $sub = $arch -eq 'x64' ? 'x64/Release' : 'Release'
    $folder = New-Item -ItemType Directory -Force (Join-Path $runtime "win-$arch")
    Copy-Item (Join-Path $Stoker "integrations/loader/$sub/stoker_loader.dll") $folder
    Copy-Item (Join-Path $Stoker "integrations/hookhost/$sub/stoker_hookhost.dll") $folder
    Copy-Item (Join-Path $Stoker "integrations/bootstrap/injector/$sub/stoker-inject.exe") $folder

    $exe = Join-Path $game "target_$arch.exe"
    cmd /c "call `"$vs\VC\Auxiliary\Build\vcvarsall.bat`" $arch >nul && cl /nologo /std:c++20 /EHsc /O2 /MT `"$PSScriptRoot\resolve_target.cpp`" /Fo`"$work\\`" /Fe:`"$exe`" >nul"
    if (-not (Test-Path $exe)) { throw "$exe did not build" }

    $plugin = Join-Path $repo "build/$arch/analytics-blocker.dll"
    if (-not (Test-Path $plugin)) { throw "$plugin is missing; run build.ps1" }
    $id = [guid]::NewGuid().ToString('N')
    $destination = New-Item -ItemType Directory -Force (Join-Path $injected "stoker-hook-plugins\$id\$arch")
    Copy-Item $plugin (Join-Path $destination 'plugin.dll')
    $plugins[$arch] = @{ id = $id; sha = (Get-FileHash $plugin -Algorithm SHA256).Hash.ToLowerInvariant() }
}

# The sidecars as the agent writes them, with this run's options.
function Configure([hashtable] $options) {
    foreach ($arch in 'x86', 'x64') {
        $entry = @{ id = $plugins[$arch].id; architecture = $arch.ToUpperInvariant(); sha256 = $plugins[$arch].sha;
                    configJson = ($options | ConvertTo-Json -Compress); name = "Analytics blocker $arch" }
        @{ hooks = @(); plugins = @($entry) } | ConvertTo-Json -Depth 4 |
            Set-Content (Join-Path $injected "stoker_hooks.$arch.json") -Encoding utf8NoBOM
    }
}

$out = Join-Path $work 'out.txt'
$log = Join-Path $data 'logs/stoker_inject.log'
$env:STOKER_INSTALL_DIR = $data
$env:STOKER_MODULES = 'stoker_hookhost.dll'
$env:AB_OUT = $out
Remove-Item Env:STOKER_URL -ErrorAction SilentlyContinue
$apis = 'getaddrinfo', 'GetAddrInfoW', 'GetAddrInfoExW', 'GetAddrInfoExA', 'gethostbyname', 'DnsQuery_W', 'DnsQuery_A', 'DnsQuery_UTF8', 'DnsQueryEx'
$self = [Net.Dns]::GetHostName().ToLowerInvariant()
$failures = 0

function Check([string] $name, [bool] $passed, [string] $detail) {
    if ($passed) { Write-Host "ok   $name" -ForegroundColor Green }
    else { Write-Host "FAIL $name`n     $detail" -ForegroundColor Red; $script:failures++ }
}

# Starts a stand-in game, with the modules through the injector unless -Bare, and returns its output lines.
function Run([string] $arch, [string[]] $arguments, [switch] $Bare) {
    Remove-Item $out -ErrorAction SilentlyContinue
    $exe = Join-Path $game "target_$arch.exe"
    # The injector takes the game's own command-line tail on stdin, as the launcher hands it over.
    $tail = ($arguments | ForEach-Object { "`"$_`"" }) -join ' '
    if ($Bare) { $file = $exe; $list = $arguments; $tail = '' }
    else {
        $file = Join-Path $runtime "win-$arch/stoker-inject.exe"
        $list = @('--dll', (Join-Path $runtime "win-$arch/stoker_loader.dll"), '--dll', (Join-Path $runtime "win-$arch/stoker_hookhost.dll"), $exe)
    }
    $start = New-Object Diagnostics.ProcessStartInfo $file
    $list | ForEach-Object { $start.ArgumentList.Add($_) }
    $start.UseShellExecute = $false; $start.RedirectStandardOutput = $true; $start.RedirectStandardInput = $true
    $process = [Diagnostics.Process]::Start($start)
    if ($tail) { $process.StandardInput.Write($tail) }
    $process.StandardInput.Close()
    $null = $process.StandardOutput.ReadToEnd()
    $process.WaitForExit()
    # The injector returns once the game is running; wait for the game's lines.
    $expected = $arguments.Count * $apis.Count
    if ($arguments[0] -eq 'spawn') { $expected = ($arguments.Count - 2) * $apis.Count }
    $deadline = (Get-Date).AddSeconds(30)
    while ((Get-Date) -lt $deadline -and -not ((Test-Path $out) -and @(Get-Content $out).Count -ge $expected)) { Start-Sleep -Milliseconds 100 }
    @(Get-Content $out -ErrorAction SilentlyContinue)
}

# Whether every API gave `name` an answer (0) or every API refused it, for the lines of one architecture.
function Every([string[]] $lines, [string] $arch, [string] $name, [bool] $answered) {
    foreach ($api in $apis) {
        $line = $lines | Where-Object { $_ -match "^$arch $api $([regex]::Escape($name)) (-?\d+)$" } | Select-Object -First 1
        if (-not $line) { return $false }
        $status = [long]($line -split ' ')[-1]
        if ($answered -and $status -ne 0) { return $false }
        if (-not $answered -and $status -notin 11001, 9003) { return $false }
    }
    return $true
}

try {
    $lines = Run 'x64' @($self, 'localhost') -Bare
    Check "control: every API answers $self without the plugin" (Every $lines 'x64' $self $true) ($lines -join ' | ')

    foreach ($arch in 'x64', 'x86') {
        Configure @{ extraHosts = "$self`n*.not-this.example" }
        Remove-Item $log -ErrorAction SilentlyContinue
        $lines = Run $arch @($self, 'localhost', 'api.gameanalytics.com')
        Check "${arch}: every API refuses a blocked name" (Every $lines $arch $self $false) ($lines -join ' | ')
        Check "${arch}: every API refuses a rule's host" (Every $lines $arch 'api.gameanalytics.com' $false) ($lines -join ' | ')
        Check "${arch}: localhost still answers" (Every $lines $arch 'localhost' $true) ($lines -join ' | ')
        $text = Get-Content $log -Raw -ErrorAction SilentlyContinue
        Check "${arch}: the log names the block once, with the caller" (
            ([regex]::Matches($text, "blocked $([regex]::Escape($self)) ")).Count -eq 1 -and
            $text -match "blocked $([regex]::Escape($self)) \(getaddrinfo, from target_$arch\.exe\): extra, extraHosts" -and
            $text -match 'blocked api\.gameanalytics\.com \(getaddrinfo, from target_\w+\.exe\): analytics, GameAnalytics' -and
            $text -match 'blocking: \d+ rules') $text
    }

    Configure @{ extraHosts = $self; allowHosts = $self }
    $lines = Run 'x64' @($self)
    Check 'allowHosts beats extraHosts' (Every $lines 'x64' $self $true) ($lines -join ' | ')

    Configure @{ extraHosts = $self }
    $env:STOKER_URL = "http://${self}:1/"
    try { $lines = Run 'x64' @($self) } finally { Remove-Item Env:STOKER_URL }
    Check "STOKER_URL's host is never blocked" (Every $lines 'x64' $self $true) ($lines -join ' | ')

    Configure @{ extraHosts = $self; mode = 'observe' }
    Remove-Item $log -ErrorAction SilentlyContinue
    $lines = Run 'x64' @($self, 'localhost')
    $text = Get-Content $log -Raw -ErrorAction SilentlyContinue
    Check 'observe mode answers and logs what it would block' ((Every $lines 'x64' $self $true) -and $text -match "would block $([regex]::Escape($self)) " -and $text -match 'protected localhost ') "$($lines -join ' | ')`n$text"

    Configure @{ extraHosts = $self }
    $lines = Run 'x86' @('spawn', (Join-Path $game 'target_x64.exe'), $self)
    Check "a 64-bit child of a 32-bit game is blocked too" (Every $lines 'x64' $self $false) ($lines -join ' | ')
}
finally {
    if ($failures -or $env:AB_KEEP) { Write-Host "work folder kept: $work" } else { Remove-Item -Recurse -Force $work -ErrorAction SilentlyContinue }
}
if ($failures) { Write-Host "$failures failed" -ForegroundColor Red; exit 1 }
Write-Host 'hook host tests: PASS' -ForegroundColor Green
