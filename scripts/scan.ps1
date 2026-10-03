<#
.SYNOPSIS
  Scan an A&D service with the rule packs of this repository (Windows).

.EXAMPLE
  .\scripts\scan.ps1 -Target ..\services\notes
  .\scripts\scan.ps1 -Target ..\services\notes -Packs python,infra -Severity WARNING
  .\scripts\scan.ps1 -Target ..\services\notes -ReportDir C:\ctf\reports

  Besides results.{json,sarif,txt} and triage.txt in -OutDir, an HTML report
  is written to -ReportDir (default .\opengrep-reports) unless -NoReport.
#>
param(
    [Parameter(Mandatory = $true)][string]$Target,
    [string[]]$Packs = @(),
    [ValidateSet('INFO', 'WARNING', 'ERROR')][string]$Severity = 'INFO',
    [string]$OutDir = '',
    [string]$Opengrep = 'opengrep',
    [string]$ReportDir = '',
    [switch]$NoReport
)

$ErrorActionPreference = 'Stop'
$Repo = Split-Path -Parent $PSScriptRoot
$Service = Split-Path -Leaf (Resolve-Path $Target)
if (-not $OutDir) { $OutDir = Join-Path (Get-Location) "opengrep-out\$Service" }
if (-not $ReportDir) { $ReportDir = Join-Path (Get-Location) 'opengrep-reports' }

$Aliases = @{ python = 'pyhton'; py = 'pyhton'; javascript = 'js'; typescript = 'js'; ts = 'js'; node = 'js';
              cpp = 'c'; 'c++' = 'c'; cs = 'csharp'; dotnet = 'csharp' }

$sourcePacksFound = $false
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
    $sourcePacksFound = $Packs.Count -gt 0
} else {
    $sourcePacksFound = $true
}
$Packs += 'infra'

# native binaries are invisible to opengrep (pwn services often ship only
# the ELF), so say it loudly instead of printing "0 findings"
$binaries = Get-ChildItem -Path $Target -Recurse -File -ErrorAction SilentlyContinue |
    Where-Object { $_.Length -gt 1KB -and $_.FullName -notmatch '[\\/](node_modules|\.git|\.venv)[\\/]' } |
    Where-Object {
        try {
            $fs = [System.IO.File]::OpenRead($_.FullName)
            $magic = New-Object byte[] 4
            $n = $fs.Read($magic, 0, 4)
            $fs.Close()
            ($n -ge 4 -and $magic[0] -eq 0x7f -and $magic[1] -eq 0x45 -and $magic[2] -eq 0x4c -and $magic[3] -eq 0x46) -or
            ($n -ge 2 -and $magic[0] -eq 0x4d -and $magic[1] -eq 0x5a)
        } catch { $false }
    }

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
if ($binaries) {
    $names = $binaries | Select-Object -First 5 | ForEach-Object { $_.Name }
    Write-Host "[!] native binaries, NOT analyzed by opengrep (reverse them): $($names -join ' ')"
    if (-not $sourcePacksFound) {
        Write-Host "[!] binary-only service: no source code found, only the infra pack ran"
    }
}

# never let a stale report from a previous run pass as this one
'results.json', 'results.sarif', 'results.txt', 'meta.json' | ForEach-Object {
    Remove-Item -Force -ErrorAction SilentlyContinue (Join-Path $OutDir $_)
}

& $Opengrep scan @configArgs @sevArgs `
    --taint-intrafile --x-ignore-semgrepignore-files --no-git-ignore `
    --exclude node_modules --exclude .git --exclude '*.min.js' --timeout 30 --quiet `
    --json-output (Join-Path $OutDir 'results.json') `
    --sarif-output (Join-Path $OutDir 'results.sarif') `
    --text-output (Join-Path $OutDir 'results.txt') `
    $Target | Out-Null

# pick a working interpreter ("python3" can be a Microsoft Store stub)
# (the stub writes to stderr, which Windows PowerShell 5 turns into a
# terminating error under ErrorActionPreference=Stop, hence the try/catch)
$py = $null
foreach ($cand in Get-Command python3, python -ErrorAction SilentlyContinue) {
    try {
        & $cand.Source -c 'import sys' 2>$null | Out-Null
        if ($LASTEXITCODE -eq 0) { $py = $cand; break }
    } catch { }
}

# scan metadata for report.py (service name, where the sources are, ...)
$targetFull = (Resolve-Path $Target).Path
[ordered]@{
    service     = $Service
    target      = $targetFull
    cwd         = (Get-Location).Path
    scanned_at  = (Get-Date -Format 's')
    packs       = @($Packs)
    binaries    = @($binaries | ForEach-Object { $_.FullName.Substring($targetFull.Length).TrimStart('\', '/') })
    binary_only = [bool]($binaries -and -not $sourcePacksFound)
} | ConvertTo-Json | Set-Content -Encoding utf8 -Path (Join-Path $OutDir 'meta.json')

if (-not $py) {
    Write-Host "[!] python not found: no triage / HTML report"
} else {
    if (Test-Path (Join-Path $OutDir 'results.json')) {
        & $py.Source (Join-Path $Repo 'scripts\triage.py') (Join-Path $OutDir 'results.json') |
            Tee-Object -FilePath (Join-Path $OutDir 'triage.txt')
    } else {
        Write-Host "[!] opengrep produced no results.json (see the error above)"
    }
    if (-not $NoReport) {
        $html = Join-Path $ReportDir ("{0}-{1}.html" -f $Service, (Get-Date -Format 'yyyyMMdd-HHmmss'))
        & $py.Source (Join-Path $Repo 'scripts\report.py') --no-clobber --title "A&D scan - $Service" -o $html $OutDir
    }
}
