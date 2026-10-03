# Opengrep Rules - A&D Costa Rica Team

Opengrep rule set for the **Attack & Defense** competition at **ECSC 2026
(Germany)**, maintained by Team Costa Rica.

- **469 rules** for Python, JavaScript/TypeScript, PHP, Go, Java, Ruby, Rust,
  C/C++, C# and deployment files (docker-compose, Dockerfile, nginx).
- Syntactic rules, taint (dataflow) rules and A&D-specific logic rules.
- Annotated test fixtures for every new rule.

## Quick start

```bash
scripts/scan.sh path/to/service            # Linux / macOS / Git Bash
.\scripts\scan.ps1 -Target path\to\service # Windows PowerShell
scripts/test-rules.sh                      # validate packs + run fixtures
```

Reports are written to `opengrep-out/<service>/`. The `triage.txt` file there
ranks findings by A&D impact.

## Documentation

See the [wiki](wiki/Home.md):

- [Getting Started](wiki/Getting-Started.md)
- [A&D Game Playbook](wiki/AD-Game-Playbook.md)
- [Repository Layout](wiki/Repository-Layout.md)
- [Scenarios Covered](wiki/Scenarios-Covered.md)
- [Rule Catalog](wiki/Rule-Catalog.md)
- [Patching Cheatsheet](wiki/Patching-Cheatsheet.md)
