<#
.SYNOPSIS
  Scan many A&D services in one go and build ONE combined HTML report (Windows).

.DESCRIPTION
  -Source is either a directory (every sub-directory is a service; hidden
  dirs, opengrep-out and opengrep-reports are skipped) or a text file with
  one service path per line (blank lines and "# comments" ignored, relative
  paths resolved from the list file's directory).

  Per-service reports go to -OutDir\<service> (default .\opengrep-out), the
  combined HTML report to -ReportDir (default .\opengrep-reports).

.EXAMPLE
  .\scripts\scan-bulk.ps1 -Source C:\vulnbox\services
  .\scripts\scan-bulk.ps1 -Source .\services.txt -Severity WARNING -Parallel 3
#>
param(
    [Parameter(Mandatory = $true)][string]$Source,
    [string[]]$Packs = @(),
    [ValidateSet('INFO', 'WARNING', 'ERROR')][string]$Severity = 'INFO',
    [string]$OutDir = '',
    [string]$ReportDir = '',
    [string]$Opengrep = 'opengrep',
    [int]$Parallel = 1
)

$ErrorActionPreference = 'Stop'
$Repo = Split-Path -Parent $PSScriptRoot
$ScanScript = Join-Path $PSScriptRoot 'scan.ps1'
if (-not $OutDir) { $OutDir = Join-Path (Get-Location) 'opengrep-out' }
if (-not $ReportDir) { $ReportDir = Join-Path (Get-Location) 'opengrep-reports' }
$Stamp = Get-Date -Format 'yyyyMMdd-HHmmss'

# ---- collect the service directories ---------------------------------
$services = @()
if (Test-Path -PathType Container $Source) {
    foreach ($d in Get-ChildItem -Path $Source -Directory) {
        if ($d.Name -like '.*' -or $d.Name -in 'opengrep-out', 'opengrep-reports', 'node_modules') { continue }
        # do not scan a copy of this rules repository living next to the services
        if ($d.FullName -eq $Repo) { continue }
        if ((Test-Path (Join-Path $d.FullName 'scripts\scan.sh')) -and
            (Test-Path (Join-Path $d.FullName 'scripts\triage.py'))) { continue }
        $services += $d.FullName
    }
} elseif (Test-Path -PathType Leaf $Source) {
    $listDir = Split-Path -Parent (Resolve-Path $Source).Path
    foreach ($line in Get-Content $Source) {
        $line = ($line -replace '#.*$', '').Trim()
        if (-not $line) { continue }
        if ($line.StartsWith('~')) { $line = $HOME + $line.Substring(1) }
        elseif (-not [System.IO.Path]::IsPathRooted($line)) { $line = Join-Path $listDir $line }
        if (Test-Path -PathType Container $line) { $services += (Resolve-Path $line).Path }
        else { Write-Warning "skipping, not a directory: $line" }
    }
} else {
    throw "not a directory or file: $Source"
}
if ($services.Count -eq 0) { throw "no services found in $Source" }

# ---- unique output name per service (two "api" dirs -> api, api-2) ------
$names = @()
foreach ($s in $services) {
    $base = Split-Path -Leaf $s; $name = $base; $n = 2
    while ($names -contains $name) { $name = "$base-$n"; $n++ }
    $names += $name
}

New-Item -ItemType Directory -Force -Path $OutDir, $ReportDir | Out-Null
Write-Host "[*] services : $($services.Count) (parallel: $Parallel)"
Write-Host "[*] reports  : $OutDir\<service>"

$scanOne = {
    param($ScanScript, $Svc, $Out, $Packs, $Severity, $Opengrep)
    New-Item -ItemType Directory -Force -Path $Out | Out-Null
    $scanArgs = @{ Target = $Svc; OutDir = $Out; Severity = $Severity; Opengrep = $Opengrep; NoReport = $true }
    if ($Packs.Count) { $scanArgs.Packs = $Packs }
    try {
        & $ScanScript @scanArgs *> (Join-Path $Out 'scan.log')
        "[+] done     : $(Split-Path -Leaf $Out)"
    } catch {
        "[!] FAILED   : $(Split-Path -Leaf $Out) (see $(Join-Path $Out 'scan.log'))"
        $_ | Out-File -Append (Join-Path $Out 'scan.log')
    }
}

$jobs = @()
for ($i = 0; $i -lt $services.Count; $i++) {
    $out = Join-Path $OutDir $names[$i]
    $jobArgs = @($ScanScript, $services[$i], $out, $Packs, $Severity, $Opengrep)
    if ($Parallel -gt 1) {
        while (@($jobs | Where-Object State -eq 'Running').Count -ge $Parallel) {
            Wait-Job -Job $jobs -Any | Out-Null
        }
        $jobs += Start-Job -ScriptBlock $scanOne -ArgumentList $jobArgs
    } else {
        Write-Host "[*] scanning : $($names[$i]) ($($services[$i]))"
        & $scanOne @jobArgs | Write-Host
    }
}
if ($jobs) { $jobs | Wait-Job | Receive-Job | Write-Host; $jobs | Remove-Job }

# ---- summary + combined report ----------------------------------------
$dirs = $names | ForEach-Object { Join-Path $OutDir $_ }
Write-Host ""
Write-Host ("{0,-28} {1,6} {2,6} {3,6} {4,6}  notes" -f 'service', 'total', 'error', 'warn', 'info')
foreach ($d in $dirs) {
    $name = Split-Path -Leaf $d
    $resFile = Join-Path $d 'results.json'
    if (-not (Test-Path $resFile)) {
        Write-Host ("{0,-28} {1,6} {1,6} {1,6} {1,6}  no results (see scan.log)" -f $name, '-')
        continue
    }
    $res = Get-Content -Raw -Encoding utf8 $resFile | ConvertFrom-Json
    $meta = $null
    $metaFile = Join-Path $d 'meta.json'
    if (Test-Path $metaFile) { $meta = Get-Content -Raw -Encoding utf8 $metaFile | ConvertFrom-Json }
    $sev = @($res.results | ForEach-Object { $_.extra.severity })
    $notes = @()
    if ($meta -and $meta.binary_only) { $notes += 'BINARY-ONLY, reverse it' }
    if (@($res.errors).Count) { $notes += "$(@($res.errors).Count) scan error(s)" }
    Write-Host ("{0,-28} {1,6} {2,6} {3,6} {4,6}  {5}" -f $name, $sev.Count,
        @($sev | Where-Object { $_ -eq 'ERROR' }).Count, @($sev | Where-Object { $_ -eq 'WARNING' }).Count,
        @($sev | Where-Object { $_ -eq 'INFO' }).Count, ($notes -join '; '))
}
Write-Host ""

# pick a working interpreter ("python3" can be a Microsoft Store stub that
# writes to stderr, a terminating error in Windows PowerShell 5 here)
$py = $null
foreach ($cand in Get-Command python3, python -ErrorAction SilentlyContinue) {
    try {
        & $cand.Source -c 'import sys' 2>$null | Out-Null
        if ($LASTEXITCODE -eq 0) { $py = $cand; break }
    } catch { }
}
if (-not $py) { Write-Host "[!] python not found: no HTML report"; exit 0 }
& $py.Source (Join-Path $Repo 'scripts\report.py') --no-clobber `
    --title "A&D bulk scan - $($services.Count) services" `
    -o (Join-Path $ReportDir "bulk-$Stamp.html") @dirs
