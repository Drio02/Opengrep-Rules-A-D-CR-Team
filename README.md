# Opengrep Rules - A&D Costa Rica Team

Opengrep rule set for the **Attack & Defense** competition at **ECSC 2026
(Germany)**, maintained by Team Costa Rica.

- **469 rules** for Python, JavaScript/TypeScript, PHP, Go, Java, Ruby, Rust,
  C/C++, C# and deployment files (docker-compose, Dockerfile, nginx).
- Syntactic rules, taint (dataflow) rules and A&D-specific logic rules.
- Annotated test fixtures for every new rule.

## Quick start

```bash
scripts/scan.sh path/to/service                   # Linux / macOS / Git Bash
.\scripts\scan.ps1 -Target path\to\service        # Windows PowerShell
scripts/scan-bulk.sh path/to/services             # every sub-directory is a service
scripts/scan-bulk.sh services.txt                 # or a list file, one path per line
.\scripts\scan-bulk.ps1 -Source path\to\services  # bulk scan on Windows
scripts/test-rules.sh                             # validate packs + run fixtures
```

Reports are written to `opengrep-out/<service>/`. The `triage.txt` file there
ranks findings by A&D impact. Every scan (single or bulk) also writes an HTML
report to `opengrep-reports/`: all the findings of each service with source
context, filters and a per-finding triage status.

For the whole team during the game, run the web dashboard (analysis, git pull
of the services, labels and patcher assignment shared by everyone):

```bash
python3 webapp/server.py --root path/to/services   # http://localhost:8765/
```

## Documentation

See the [wiki](wiki/Home.md):

- [Getting Started](wiki/Getting-Started.md)
- [Competition Deployment (plug and play)](wiki/Competition-Deployment.md)
- [Findings Dashboard (web app)](wiki/Dashboard.md)
- [A&D Game Playbook](wiki/AD-Game-Playbook.md)
- [Repository Layout](wiki/Repository-Layout.md)
- [Scenarios Covered](wiki/Scenarios-Covered.md)
- [Rule Catalog](wiki/Rule-Catalog.md)
- [Patching Cheatsheet](wiki/Patching-Cheatsheet.md)
