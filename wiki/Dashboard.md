# Findings Dashboard (web app)

A small web app to run the analysis on every service, keep the service code
up to date from git, and coordinate patching: each finding can be labelled and
assigned to a patcher, and the whole team sees the same state.

It uses only the Python standard library (nothing to install besides Python 3,
Opengrep and git) and runs where the services and Opengrep are, e.g. the
Linux laptop or WSL.

## Start

```bash
python3 webapp/server.py --root ~/demo-ad
# [*] dashboard: http://localhost:8765/
```

| Option | Default | |
|---|---|---|
| `--root` | (set in the UI) | Directory with one sub-directory per service, or a single service |
| `--port` | `8765`, else next free | Never `3001` nor a port declared by the services. Without `--port`, if `8765` is taken or used by a service, the next free port is picked and printed. An explicit `--port` that collides is refused |
| `--host` | `127.0.0.1` | Use `0.0.0.0` to share with the team (see below) |
| `--data` | `~/.local/share/opengrep-dashboard` | Settings, labels and scan output. Never written inside the services |
| `--token` | generated | Access token, required when `--host` is not localhost |

From WSL, `http://localhost:8765/` also opens in the Windows browser.

Service ports are read from the deployment files of every service (up to two
folders deep) and from the top of the services directory: `.env` / `PORT=`,
compose `ports:` (short `"8080:80"`, `"127.0.0.1:8080:80"`, `"8080"`,
`${PORT:-9000}`, and long `published:` / `target:` syntax), Dockerfile
`EXPOSE` (several ports, `/tcp`), xinetd `port =`, socat `TCP-LISTEN:`,
nginx `listen`, `--port` flags.

### Works with any competition layout

- a directory with one folder per service (each with its own Dockerfile or
  compose), as on the ECSC vulnbox;
- a FAUST-style directory with one `docker-compose.yml` at the top and one
  folder per service;
- a single service directory (it becomes the only service);
- services with or without git (tarballs are scanned, just not pulled), any
  language with a rule pack (Python, JS/TS, PHP, Go, Java, Ruby, Rust, C/C++,
  C#), names with spaces, and binary-only services (flagged "reverse it").

### Sharing with the team

```bash
python3 webapp/server.py --root ~/vulnbox/services --host 0.0.0.0
# [*] dashboard: http://10.13.37.5:8765/#token=8v4kDH9y...
```

Send that URL (with the token) to the team over a private channel. The token is
kept in the browser after the first visit. The game network is hostile: never
bind to `0.0.0.0` without the token, and prefer the team VPN / LAN interface
(`--host 10.13.37.5`) over all interfaces.

## Use

1. **Services directory**: path of the folder with all the services (each
   sub-directory is a service; hidden folders, `opengrep-out`,
   `opengrep-reports` and copies of this repo are skipped). *Save* shows the
   services found.
2. **Run analysis**: runs `scripts/scan.sh` on every service (in parallel)
   with **docker-compose files skipped** (`docker-compose*.yml`,
   `compose*.yaml`; can be turned off in *Settings*). Progress per service and
   the log are shown live.
3. **Pull latest**: `git fetch` + fast-forward of every service repository to
   `origin/<branch>` (*Settings*, default `main`). If the remote has no such
   branch it tries, in order: the remote's default branch, `main`, `master`,
   the branch the checkout tracks, and the remote's only branch (`trunk`,
   `develop`, ...). The vulnbox snapshot repos use `master`. It never
   switches branches and never overwrites local changes:
   a service on another branch, with local commits, or with conflicting local
   edits is reported as skipped / failed and left untouched.
4. **Pull latest + re-run**: both, one after the other.
5. **Download HTML report**: the same offline report as `scan-bulk.sh`.

For the vulnbox repos set *SSH key for git* in *Settings* (the key used by
`backup-services-v2.sh`, saved to a file with `chmod 600`).

### Git access check

Git access is checked **before any pull**: when the server starts, when the
services directory or the SSH key changes, before every *Pull*, and with
*Check git access again*. It does one `git ls-remote` per remote host (all the
vulnbox services share one host, so it is one SSH connection), and shows a
banner with the problem and the fix:

| Problem | Shown as | Fix |
|---|---|---|
| no key / wrong key | `authentication refused (publickey/password)` | set *SSH key for git* to the vulnbox key |
| key readable by others | `permissions too open` | `chmod 600`; a key under `/mnt/c` cannot be chmod'ed, copy it to `~/.ssh` |
| broken key file | `the SSH key file could not be loaded` | full BEGIN/END block, LF line endings, no passphrase |
| VPN down / vulnbox off | `connection timed out`, `no route to host`, ... | bring the VPN up |
| vulnbox reinstalled | `host key changed` | `ssh-keygen -R <host>` |
| HTTPS remote (GitHub/GitLab of the organizers) | `HTTPS remote needs credentials` / `authentication failed` | SSH remote + key, or a git credential helper / token |
| wrong URL or no access | `repository not found` | check the remote URL and the key / token |
| services copied as root | `repository owned by another user` | run the dashboard as the owner, or `chown` the services |

While every remote fails, *Pull latest* and *Pull latest + re-run* are
disabled. Saving a key whose permissions are too open is refused right away,
and when a pull runs anyway, services of an unreachable host fail at once with
that reason instead of trying one by one.

### Labels and assignees

Every finding has two drop-downs:

- **Label**: *Open*, *Patch in progress*, *Patched in prod*, *False positive*.
- **Patcher**: Dario, David, Juanca, Andres, Caleb, Damian, Jerelyn, plus any
  name added with *Add patcher* (also from the drop-down: *+ Add patcher...*).
  Added patchers can be removed; their findings become unassigned.

Labels are stored on the server, so everybody sees the same state (the page
refreshes by itself every few seconds). They are keyed on service + rule +
file + matched code, not on the line number, so they survive edits elsewhere
in the file and re-scans.

Filters: text search, severity, service, impact, label (including *Not
patched / not FP*), assignee (*Unassigned*), *New only*; group by service,
rule, impact or assignee.

### After patching

Re-run the analysis:

- findings that disappeared are listed under **Resolved since the previous
  analysis** with the label and patcher they had: check that the service still
  passes the checker;
- findings that were not there before are marked **NEW** (e.g. a pull brought
  new code, or a patch introduced something).

## Files

| Path | |
|---|---|
| `webapp/server.py` | HTTP server, JSON API, background jobs (scan / pull) |
| `webapp/static/` | UI (`index.html`, `app.js`, `style.css`), no external assets |
| `<data>/state.json` | settings, patchers, labels |
| `<data>/last_scan.json` | last analysis (findings with code context, resolved list) |
| `<data>/runs/<timestamp>/<service>/` | raw scan output of the last 3 runs (`results.json`, `scan.log`, ...) |
