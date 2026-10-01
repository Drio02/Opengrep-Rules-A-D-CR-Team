<#
.SYNOPSIS
  Scan an A&D service with the rule packs of this repository (Windows).

.EXAMPLE
  .\scripts\scan.ps1 -Target ..\services\notes
  .\scripts\scan.ps1 -Target ..\services\notes -Packs python,infra -Severity WARNING
#>
param(
    [Parameter(Mandatory = $true)][string]$Target,
    [string[]]$Packs = @(),
    [ValidateSet('INFO', 'WARNING', 'ERROR')][string]$Severity = 'INFO',
    [string]$OutDir = '',
    [string]$Opengrep = 'opengrep'
)

$ErrorActionPreference = 'Stop'
$Repo = Split-Path -Parent $PSScriptRoot
$Service = Split-Path -Leaf (Resolve-Path $Target)
if (-not $OutDir) { $OutDir = Join-Path (Get-Location) "opengrep-out\$Service" }

$Aliases = @{ python = 'pyhton'; py = 'pyhton'; javascript = 'js'; typescript = 'js'; ts = 'js'; node = 'js';
              cpp = 'c'; 'c++' = 'c'; cs = 'csharp'; dotnet = 'csharp' }

if ($Packs.Count -eq 0) {
    $ext = Get-ChildItem -Path $Target -Recurse -File -ErrorAction SilentlyContinue |
        Where-Object { $_.FullName -notmatch '[\\/](node_modules|\.git)[\\/]' } |
        ForEach-Object { $_.Extension.ToLower() } | Sort-Object -Unique
    $map = [ordered]@{
        python = '.py'; js = '.js', '.ts', '.jsx', '.tsx', '.mjs'; php = '.php', '.phtml'; go = '.go';
        java = '.java', '.jsp', '.kt'; ruby = '.rb', '.erb'; rust = '.rs';
        c = '.c', '.h', '.cpp', '.cc', '.hpp'; csharp = '.cs', '.cshtml'
    }
    foreach ($k in $map.Keys) { if ($ext | Where-Object { $map[$k] -contains $_ }) { $Packs += $k } }
}
$Packs += 'infra'

$configArgs = @()
foreach ($p in $Packs) {
    $dir = if ($Aliases.ContainsKey($p)) { $Aliases[$p] } else { $p }
    $full = Join-Path $Repo $dir
    if (-not (Test-Path $full)) { throw "unknown pack: $p" }
    $configArgs += @('--config', $full)
}

$sevArgs = switch ($Severity) {
    'ERROR'   { @('--severity', 'ERROR') }
    'WARNING' { @('--severity', 'WARNING', '--severity', 'ERROR') }
    default   { @() }
}

New-Item -ItemType Directory -Force -Path $OutDir | Out-Null
Write-Host "[*] service : $Target"
Write-Host "[*] packs   : $($Packs -join ' ')"
Write-Host "[*] reports : $OutDir"

& $Opengrep scan @configArgs @sevArgs `
    --taint-intrafile --x-ignore-semgrepignore-files --no-git-ignore `
    --exclude node_modules --exclude .git --exclude '*.min.js' --timeout 30 --quiet `
    --json-output (Join-Path $OutDir 'results.json') `
    --sarif-output (Join-Path $OutDir 'results.sarif') `
    --text-output (Join-Path $OutDir 'results.txt') `
    $Target | Out-Null

# pick a working interpreter ("python3" can be a Microsoft Store stub)
$py = Get-Command python3, python -ErrorAction SilentlyContinue |
    Where-Object { & $_.Source -c 'import sys' 2>$null; $LASTEXITCODE -eq 0 } | Select-Object -First 1
if ($py) {
    & $py.Source (Join-Path $Repo 'scripts\triage.py') (Join-Path $OutDir 'results.json') |
        Tee-Object -FilePath (Join-Path $OutDir 'triage.txt')
}
