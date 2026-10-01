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
  - `JOBS=8` sets the number of parallel jobs.

```bash
SEVERITY=WARNING scripts/scan.sh ~/vulnbox/services/shop python infra
```

PowerShell:

```powershell
.\scripts\scan.ps1 -Target C:\vulnbox\shop -Packs python,infra -Severity WARNING
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

For the full message and code context, open `results.txt`, or load
`results.sarif` into an IDE.

## 5. Next steps

- Follow the [A&D Game Playbook](AD-Game-Playbook.md) during the game.
- Use the [Patching Cheatsheet](Patching-Cheatsheet.md) to fix findings
  without breaking the checker.
