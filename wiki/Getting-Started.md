# Getting Started

## 1. Install Opengrep

Opengrep ships as a single self-contained binary. **Download it before the
competition** and keep a copy on every laptop: game networks are often
isolated or slow.

Linux / macOS:

```bash
curl -fsSL https://raw.githubusercontent.com/opengrep/opengrep/main/install.sh | bash
# or download the release asset for your platform manually:
#   https://github.com/opengrep/opengrep/releases
opengrep --version
```

Windows (PowerShell):

```powershell
Invoke-WebRequest -OutFile opengrep.exe `
  https://github.com/opengrep/opengrep/releases/latest/download/opengrep_windows_x86.exe
.\opengrep.exe --version
```

If the binary is not in `PATH`, point the scripts to it:

```bash
export OPENGREP=/opt/tools/opengrep          # bash
$env:OPENGREP = "C:\tools\opengrep.exe"      # PowerShell (or pass -Opengrep)
```

Optional, needed only for `triage.py` and `gen-catalog.py`: Python 3, plus
`pip install pyyaml` for the catalog generator.

## 2. Clone the rules

```bash
git clone https://github.com/Drio02/Opengrep-Rules-A-D-CR-Team.git
cd Opengrep-Rules-A-D-CR-Team
scripts/test-rules.sh        # optional: validates every pack and runs the fixtures
```

## 3. Scan a service

### With the wrapper (recommended)

```bash
scripts/scan.sh <service-dir> [pack ...]
```

- Without packs, the script looks at the file extensions and picks the
  matching packs. `infra` (compose/Dockerfile/nginx) is always added.
- Pack names: `python js php go java ruby rust c csharp infra`. Aliases such as
  `ts`, `node`, `cpp` and `dotnet` also work.
- Environment variables:
  - `SEVERITY=WARNING` hides INFO findings; `SEVERITY=ERROR` keeps only ERROR.
  - `OUT_DIR=/path` changes where the reports go.
  - `REPORT_DIR=/path` changes where the HTML report goes
    (default `./opengrep-reports`); `NO_REPORT=1` skips it.
  - `JOBS=8` sets the number of parallel jobs.

```bash
SEVERITY=WARNING scripts/scan.sh ~/vulnbox/services/shop python infra
```

PowerShell:

```powershell
.\scripts\scan.ps1 -Target C:\vulnbox\shop -Packs python,infra -Severity WARNING
```

### Many services at once

```bash
scripts/scan-bulk.sh <services-dir | services-list-file> [pack ...]
```

- A **directory**: every sub-directory is scanned as a service (hidden dirs,
  `opengrep-out/`, `opengrep-reports/` and a copy of this repo are skipped).
- A **list file**: one service path per line; blank lines and `# comments` are
  ignored, relative paths are resolved from the list file's directory:

  ```
  # services.txt
  notes
  shop/backend
  ~/vulnbox/services/pwnable
  ```
- Each service gets its own `opengrep-out/<service>/` (with a `scan.log`), the
  terminal shows a per-service summary, and ONE combined HTML report is
  written to `opengrep-reports/bulk-<timestamp>.html`.
- `PARALLEL=4` scans four services at the same time. `SEVERITY`, `OPENGREP`,
  `JOBS`, `OUT_DIR` and `REPORT_DIR` work as for `scan.sh`.

```bash
PARALLEL=4 SEVERITY=WARNING scripts/scan-bulk.sh ~/vulnbox/services
```

PowerShell:

```powershell
.\scripts\scan-bulk.ps1 -Source C:\vulnbox\services -Parallel 4 -Severity WARNING
.\scripts\scan-bulk.ps1 -Source .\services.txt -ReportDir C:\ctf\reports
```

### Raw Opengrep commands

```bash
# everything in the repo
opengrep scan --config . --taint-intrafile --x-ignore-semgrepignore-files ./service

# one pack
opengrep scan --config pyhton/ --config infra/ --taint-intrafile ./service

# one rule file, JSON output
opengrep scan --config js/taint.yaml --json -o out.json ./service

# only the A&D logic rules of every language
opengrep scan $(for f in */ad-logic.yaml; do echo --config $f; done) ./service
```

Important flags:

| Flag | Why |
|---|---|
| `--taint-intrafile` | Taint rules also follow data across functions in the same file (e.g. `get_param()` -> `run_query()`). |
| `--x-ignore-semgrepignore-files` | By default Opengrep **skips** `tests/`, `test/`, `vendor/`, `node_modules/` and similar. Services sometimes keep real code in those folders. |
| `--no-git-ignore` | Do not skip files listed in `.gitignore` (the services are not our repo). |
| `--severity ERROR` | Only the highest-confidence findings. Use this for a first pass. |
| `--sarif-output f.sarif` | Open the results in VS Code with the SARIF Viewer extension and click through them. |
| `--exclude-rule <id>` | Silence a noisy rule for the current scan. |

## 4. Read the output

`triage.txt` (printed at the end of `scan.sh`):

```
== 47 findings, 0 scan errors ==
by impact : auth-bypass=14, flag-leak=11, rce=10, other=9, ...
top rules : py-taint-command-injection=2, py-taint-sqli=2, ...

[E] rce           py-taint-command-injection        backend/app.py:54
      os.system(cmd)
[E] auth-bypass   js-hardcoded-session-secret       server.js:11
      app.use(session({ secret: "keyboard cat", resave: false }));
```

- The first letter is the severity: **E**RROR, **W**ARNING, **I**NFO.
- The second column is the `ad-impact` tag. Findings are sorted by it:
  `rce` > `flag-leak` > `auth-bypass` > `session-theft` > `integrity` > `dos` >
  `phishing`. The original rules have no impact tag and show as `-`.
- Rule IDs are documented in the [Rule Catalog](Rule-Catalog.md).

For the full message and code context, open the HTML report, `results.txt`,
or load `results.sarif` into an IDE.

### HTML report

`opengrep-reports/<service>-<timestamp>.html` (single scan) or
`opengrep-reports/bulk-<timestamp>.html` (bulk scan) is one self-contained file
with no external assets, so it opens offline and can be shared in the team
channel:

- summary cards and a per-service table (findings by severity and impact,
  binary-only services, scan errors); click a service to filter on it;
- every finding with severity, `ad-impact`, CWE, confidence, file:line (click
  to copy), the rule message and the matched source lines with context;
- search, severity / service / impact filters, grouping by service, rule or
  impact, and CSV export of the filtered list;
- a triage status per finding (confirmed / false positive / patched), saved
  in the browser so it survives a reload and a re-scan of the same code.

Build a report from existing scan directories without re-scanning:

```bash
python scripts/report.py -o report.html opengrep-out/notes opengrep-out/shop
```

## 5. Next steps

- Follow the [A&D Game Playbook](AD-Game-Playbook.md) during the game.
- Use the [Patching Cheatsheet](Patching-Cheatsheet.md) to fix findings
  without breaking the checker.
