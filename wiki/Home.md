# Opengrep Rules - A&D Costa Rica Team (ECSC 2026)

Static-analysis rule set used by **Team Costa Rica** for the **Attack & Defense**
competition at **ECSC 2026 (Germany)**.

In an A&D game every team runs the same vulnerable services ("vulnbox"). Each
service hides bugs that let an attacker read the flags stored by the game
checker. Points come from:

- **Attack**: exploiting other teams' services and submitting their flags.
- **Defense**: patching your own services so others cannot steal your flags.
- **SLA**: keeping the services up and functional for the checker.

This repository speeds up the first two by scanning the services' source with
[Opengrep](https://github.com/opengrep/opengrep), an open-source Semgrep fork,
right after the game starts. Every finding is something to patch on our box,
and also something to try against the other teams.

## Wiki pages

| Page | What it covers |
|---|---|
| [Getting Started](Getting-Started.md) | Install Opengrep, run the first scan, read the output |
| [Findings Dashboard](Dashboard.md) | Web app: analyze all services, pull their latest code, label and assign findings |
| [A&D Game Playbook](AD-Game-Playbook.md) | How to use the rules during the game, minute by minute |
| [Repository Layout](Repository-Layout.md) | Folders, rule file types, metadata, naming |
| [Scenarios Covered](Scenarios-Covered.md) | Vulnerability classes x languages coverage matrix |
| [Rule Catalog](Rule-Catalog.md) | Every rule, with severity, CWE, impact and description (generated) |
| [Patching Cheatsheet](Patching-Cheatsheet.md) | Quick, checker-safe patches for each bug class |

## At a glance

- **469 rules** in **10 packs**: Python, JavaScript/TypeScript, PHP, Go, Java,
  Ruby, Rust, C/C++, C#/.NET and infrastructure (docker-compose, Dockerfile,
  nginx).
- Three kinds of rules:
  1. **Original syntactic rules** (`backend*.yaml`, `frontend*.yaml`,
     `extra.yaml`, `<language>.yaml`). They match dangerous calls written
     inline.
  2. **Taint rules** (`taint.yaml`). They follow user input from the HTTP
     request through variables and helper functions to a dangerous sink.
  3. **A&D logic rules** (`ad-logic.yaml`). They cover bugs that are typical
     of A&D services: forgeable sessions, hardcoded keys shared by every team,
     predictable tokens, mass assignment, auth bypasses, debug consoles.
- Every new rule has an annotated test fixture in `tests/`, run by
  `scripts/test-rules.sh`.

## Quick start

```bash
# scan a service; packs are auto-detected from the file extensions
scripts/scan.sh ../services/notes-app

# Windows
.\scripts\scan.ps1 -Target ..\services\notes-app
```

The reports are written to `opengrep-out/<service>/`: `results.txt`,
`results.json`, `results.sarif` and `triage.txt`, which ranks findings by A&D
impact.
