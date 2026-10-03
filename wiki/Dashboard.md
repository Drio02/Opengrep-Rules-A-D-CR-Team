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
# [*] dashboard: http://localhost:8765/  (login: patcher)
```

Log in with user **`patcher`**, password **`patcherspatching!`**, then change
the password (*Change password* at the top right). This repository is public,
so every team can read the default password.

| Option | Default | |
|---|---|---|
| `--root` | (set in the UI) | Directory with one sub-directory per service, or a single service |
| `--port` | `8765`, else next free | Never `3001` nor a port declared by the services. Without `--port`, if `8765` is taken or used by a service, the next free port is picked and printed. An explicit `--port` that collides is refused |
| `--host` | `127.0.0.1` | Use `0.0.0.0` to share with the team (see below) |
| `--data` | `~/.local/share/opengrep-dashboard` | Settings, labels and scan output. Never written inside the services |
| `--allow` | everybody | Only these IPs / CIDRs may connect (`10.60.39.0/24`), `any` clears it. Saved; also in *Settings* |
| `--deny` | none | IPs / CIDRs always rejected, even inside `--allow` (`10.60.39.1,10.60.39.2`). Saved; also in *Settings* |
| `--set-password` | | Set the `patcher` password on the terminal and exit (also the way to recover a forgotten password) |

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

### Login

Every page and API call needs a login, also on localhost:

- one shared team account, `patcher` (default password `patcherspatching!`);
- the password is stored only as a PBKDF2-SHA256 hash in `<data>/state.json`
  (mode `600`, data directory `700`);
- sessions are an `HttpOnly`, `SameSite=Strict` cookie valid for 12 h
  (renewed while used); restarting the server logs everybody out;
- after **100 failed logins from one IP within 5 minutes** that IP is blocked
  for the rest of the window (even with the right password); failed logins are
  printed on the server console;
- changing the password logs out every other browser using the account;
- while the default password is in use, the dashboard shows a warning, and
  when it is **reachable from the network** (`--host` other than localhost)
  the password must be changed at the first login before anything else is
  shown.

Forgot the password: stop the server, run
`python3 webapp/server.py --set-password` (same `--data` if you use one), and
start it again.

### IP access control

A second layer next to the login (and to `iptables` on the host): every new
connection is checked against an allow / deny list **before the request is
read**; a rejected IP gets the connection closed, it does not even see the
login page.

- **Allow**: only these IPs / CIDRs may connect (empty = everybody).
- **Deny**: always rejected, even when inside *Allow* (e.g. the vulnbox,
  which other teams attack all game long, and the NAT/gateway address of the
  team subnet if attacks arrive from it).
- Set them with `--allow` / `--deny` at start or in *Settings* (saved in
  `state.json`, kept across restarts; the start flags replace the saved ones).
- A change in *Settings* applies **immediately** to the next connection,
  without restart, also to browsers that are already logged in.
- Localhost is always allowed (local console, SSH tunnel), and *Settings*
  refuses rules that would block the IP you are saving them from, so a typo
  cannot lock the team out.
- Blocked connections are printed on the server console (once per IP and
  minute).

ECSC 2026 example (team subnet `10.60.39.0/24`, vulnbox `.2`, exploiter `.3`):

```bash
python3 webapp/server.py --root ~/services --host 10.60.39.3 \
    --allow 10.60.39.0/24 --deny 10.60.39.1,10.60.39.2
```

Check on the vulnbox where attack traffic comes from (`ss -tn`, service
logs): if other teams arrive with an address of your own subnet (NAT), put
that address in *Deny* or switch *Allow* to the explicit VPN IPs of the team.

### Sharing with the team

```bash
python3 webapp/server.py --root ~/vulnbox/services --host 10.13.37.5
# [*] dashboard: http://10.13.37.5:8765/  (login: patcher)
```

Bind to the team VPN / LAN address rather than `0.0.0.0`, change the default
password first (or at the first login, which is then required), and share the
password over a private team channel. The game network is hostile and the
traffic is plain HTTP: do not expose the dashboard on the game network
interface.

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
| `<data>/state.json` | settings, patchers, labels, login password hash (mode `600`) |
| `<data>/last_scan.json` | last analysis (findings with code context, resolved list) |
| `<data>/runs/<timestamp>/<service>/` | raw scan output of the last 3 runs (`results.json`, `scan.log`, ...) |
