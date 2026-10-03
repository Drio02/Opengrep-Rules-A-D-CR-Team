# Competition Deployment (plug and play)

Everything we set up and tested in the ECSC 2026 practice environment, packed
into **one settings file and three scripts**. The real competition runs on the
same platform with the same machines (vulnbox + exploiter + WireGuard VPN), only
the IPs, keys and services change: fill in the new values and run the scripts.

```
   laptops (WireGuard VPN)                     team subnet (portal: "Network")
  +----------------------+   ssh   +--------------------------+  git clone  +------------------+
  | 01-setup-laptop.sh   | ------> | EXPLOITER                | ----------> | VULNBOX          |
  | 02-deploy-exploiter  |         |  ad-dashboard (port 8765)|  read-only  |  /root/services  |
  | 03-ops.sh            |  http   |  iptables: team only     |             |  (game services) |
  |  browser ------------+-------> |  user addash, opengrep   |             |                  |
  +----------------------+         +--------------------------+             +------------------+
```

All scripts run on a laptop (Linux, or **WSL** on Windows), never by hand on the
servers. They are idempotent: when in doubt, run them again.

---

## 0. The day before (or as soon as the portal shows the network)

1. VPN: import the WireGuard config of the competition and **Activate** it.
2. On the laptop (WSL terminal), in a folder of its own (the services will be
   copied next to the repository):

   ```bash
   mkdir -p ~/compe && cd ~/compe
   git clone https://github.com/Drio02/Opengrep-Rules-A-D-CR-Team.git
   cd Opengrep-Rules-A-D-CR-Team
   git checkout ecsc2026/web-dashboard        # or main once the PRs are merged
   cp deploy/competition.env.example deploy/competition.env
   nano deploy/competition.env
   ```
3. Fill in `deploy/competition.env` from the portal (*Network* page):

   | Variable | Portal / value |
   |---|---|
   | `TEAM_NET` | *Team subnet*, e.g. `10.60.39.0/24` |
   | `VULNBOX_IP` | *Your Vulnbox*, e.g. `10.60.39.2` |
   | `EXPLOITER_IP` | *Your Exploiter*, e.g. `10.60.39.3` |
   | `TEAM_KEY` | where the team private key will live on the laptop (`~/.ssh/ecsc2026`) |
   | `VULNBOX_KEY_ON_EXPLOITER` | a key already on the exploiter that logs into the vulnbox (`/root/.ssh/pull` in practice). Empty = the scripts copy `TEAM_KEY` |
   | `DASH_PORT` | `8765` (never `3001`, never a service port) |
   | `DASH_ALLOW` | who may open the dashboard: the team subnet |
   | `DASH_DENY` | empty (team decision); e.g. `10.60.39.1,10.60.39.2` to exclude gateway and vulnbox |
   | `REPO_BRANCH` | `ecsc2026/web-dashboard` until the PRs are merged, then `main` |

   The file is git-ignored. **Never commit keys or this file** (the repo is public).

## 1. Every team member: prepare the laptop

```bash
deploy/01-setup-laptop.sh --key /path/to/team_private_key   # first time
deploy/01-setup-laptop.sh                                   # later: re-check only
```

The key file: copy the team private key from the A&D dashboard of the
competition into a file (e.g. `nano ~/team.key`, or the file downloaded to
`/mnt/c/Users/<you>/Downloads/`) and pass it with `--key`. The script copies it
to `TEAM_KEY`; delete the original afterwards.

It then:

1. installs the key in `TEAM_KEY` (fixes Windows line endings and permissions);
2. adds `vulnbox` / `exploiter` entries to `~/.ssh/config` (so `ssh vulnbox`
   works by hand; the deploy scripts do not need them);
3. checks VPN + SSH;
4. **copies the services of the vulnbox next to this repository** (its parent
   folder), read-only on the vulnbox:

   ```
   ~/compe/
   ├── Opengrep-Rules-A-D-CR-Team/   <- run the scripts from here
   ├── service1/                     <- git clone when the vulnbox dir is a git repo
   └── service2/                     <- plain copy otherwise
   ```

   Running it again fast-forwards the git clones (never over local changes)
   and **keeps** existing plain copies (your patches). `--services-dir DIR`
   changes the folder, `--no-services` skips it, and
   `deploy/03-ops.sh fetch [--refresh] [DIR]` updates the copies later
   (`--refresh` replaces plain copies, keeping the old one as `<name>.bak-<time>`).
   Keep this folder inside WSL (e.g. `~/compe`): service data may have file
   names that do not fit on a Windows drive.

Expected end: **`Laptop ready.`** Anything marked `[FAIL]` comes with a `->`
line telling you what to do.

Who needs this step: whoever runs `02` / `03` or will SSH into the machines
to patch. Teammates who only use the dashboard in the browser just need the
VPN.

Optional: `--opengrep` installs opengrep locally (for `scripts/scan.sh` and
`scripts/scan-bulk.sh` on the laptop).

## 2. One person: deploy the dashboard on the exploiter

```bash
deploy/02-deploy-exploiter.sh --check   # read-only preflight: changes nothing
deploy/02-deploy-exploiter.sh           # install (shows the plan, asks y/N)
```

What it does on the exploiter (and nothing on the vulnbox):

- user `addash` (no login shell) that runs the dashboard;
- opengrep `OPENGREP_VERSION`, sha256 checked;
- this repository (`REPO_BRANCH`);
- read-only copies of the services: `git clone` from the vulnbox when the
  service directory is a git repository (the dashboard can then *Pull* it),
  plain copy otherwise;
- iptables chain `ADDASH`: `DASH_PORT` reachable only from `DASH_ALLOW`
  (and localhost); everything else is dropped;
- systemd service `ad-dashboard`: starts at boot, restarts on failure, applies
  the firewall before every start and refuses to start if that fails.

Expected end: **`Dashboard deployed.`** with the URL.

## 3. First login and first analysis

1. Open `http://<EXPLOITER_IP>:8765/` (from a laptop on the VPN).
2. Log in: user **`patcher`**, password **`patcherspatching!`**.
3. Because the dashboard is reachable on the network, it asks for a **new team
   password** right away (the default one is public). Share it on the private
   team channel.
4. Check the green **Git access OK** banner, then click **Run analysis**.

From here the team works in the dashboard: labels (*Patch in progress*,
*Patched in prod*, *False positive*), patcher assignee (Dario, David, Juanca,
Andres, Caleb, Damian, Jerelyn, plus *Add patcher*), *Pull latest + re-run*
after patches, *Resolved since the previous analysis* to confirm a fix.

## 4. During the game

| Need | Command (from a laptop) |
|---|---|
| Is everything fine? | `deploy/03-ops.sh doctor` |
| Service state / URL | `deploy/03-ops.sh status` |
| Logs (failed logins, blocked IPs, errors) | `deploy/03-ops.sh logs` (`logs -f` to follow) |
| Restart (also re-applies the firewall) | `deploy/03-ops.sh restart` |
| New rules / dashboard code pushed to `REPO_BRANCH` | `deploy/03-ops.sh update` |
| Services that were copied without git changed (on the exploiter) | `deploy/03-ops.sh sync` |
| Update the service copies on my laptop | `deploy/03-ops.sh fetch` (`--refresh` to replace plain copies) |
| Change port / allow / deny / branch | edit `competition.env`, run `02-deploy-exploiter.sh` again |
| Remove it (keeps labels and copies) | `deploy/03-ops.sh uninstall` |
| Remove everything, including labels | `deploy/03-ops.sh purge` |

The dashboard *Pull* only brings what is **committed** on the vulnbox repos.
If somebody edits a service on the vulnbox without committing, the dashboard
does not see it until it is committed there.

## 5. When something fails

Run `deploy/03-ops.sh doctor` first: it checks the laptop, the VPN, both SSH
logins, the dashboard from the laptop and, on the exploiter, the user,
opengrep, repo, service, port, firewall, git access to the vulnbox and disk,
and prints the fix for every problem. Common cases:

| Symptom | Cause | Fix |
|---|---|---|
| `... :22 not reachable`, `No route to host`, `timed out` | VPN down | Activate WireGuard; `ping <IP>` |
| `Permission denied (publickey...)` | wrong `TEAM_KEY` / key not deployed in the portal | `ssh-keygen -y -f <key>` must print the key registered in the portal; re-run `01 --key <file>` |
| `UNPROTECTED PRIVATE KEY FILE` | key under `/mnt/c` or not `600` | keep it in `~/.ssh`, re-run `01 --key <file>` |
| `has Windows line endings` | env or key edited on Windows | `sed -i 's/\r$//' <file>` (`01 --key` does it for the key) |
| `REMOTE HOST IDENTIFICATION HAS CHANGED` | machine reinstalled | `ssh-keygen -f ~/.ssh/known_hosts_ad -R <IP>` |
| `port N is already used` | another program on the exploiter | change `DASH_PORT`, re-run `02` |
| `EXPLOITER_IP ... is not configured here` / `not inside TEAM_NET` | typo in `competition.env` | copy the IPs from the portal again |
| `no key to reach the vulnbox from the exploiter` | `VULNBOX_KEY_ON_EXPLOITER` does not exist there | leave it empty (the team key is copied) or point it to the right key |
| `... does not exist on the vulnbox` | different services path | set `VULNBOX_SERVICES_DIR` |
| `branch ... has no webapp/server.py` | wrong `REPO_BRANCH` | `ecsc2026/web-dashboard` (or `main` after merging) |
| Dashboard does not open from a laptop, `doctor` on the exploiter is OK | that laptop's VPN IP is outside `DASH_ALLOW` | add it to `DASH_ALLOW`, re-run `02` |
| Banner *Git pull will fail* | the dashboard user cannot reach the vulnbox repos | `03-ops.sh doctor`; then re-run `02` |
| Forgot the dashboard password | | `ssh exploiter`, then: `systemctl stop ad-dashboard; runuser -u addash -- env HOME=/home/addash python3 /home/addash/Opengrep-Rules-A-D-CR-Team/webapp/server.py --set-password; systemctl start ad-dashboard` |
| Anything else / half-installed | | re-run `02-deploy-exploiter.sh` (safe to repeat); last resort `03-ops.sh uninstall` + `02` |

## 6. Decisions behind the defaults

- Port **8765**, fixed (no auto-pick in the deployment). `3001` is reserved
  (used on the exploiter), and service ports are refused.
- Access: **iptables** on the exploiter + the dashboard's own allow list, both
  limited to the team subnet. No deny list by default; the vulnbox and the
  gateway of the subnet can therefore reach the login page. Check where attack
  traffic comes from on the vulnbox and set `DASH_DENY` if it arrives from an
  address of our subnet (NAT).
- Login: shared user `patcher` with a public default password that **must** be
  changed at the first login on an exposed instance; 100 failed logins per IP
  and 5 minutes; sessions 12 h.
- Services are copied **read-only** from the vulnbox. The tooling never runs
  `backup-services-v2.sh` (it commits snapshots of live data on the vulnbox:
  heavy IO during the game). Run it by hand only if you want new snapshots.
- Checks skip `docker-compose` files; the Dockerfiles are still analyzed.
- The dashboard runs as an unprivileged user, never as root.

## 7. What is installed where (exploiter)

| Path | |
|---|---|
| `/home/addash/Opengrep-Rules-A-D-CR-Team` | rules + dashboard code (`REPO_BRANCH`) |
| `/home/addash/services/<svc>` | service copies analyzed by the dashboard |
| `/home/addash/.local/share/opengrep-dashboard` | settings, labels, password hash, last runs |
| `/home/addash/.local/bin/opengrep` | opengrep binary |
| `/home/addash/.ssh/vulnbox`, `config` | access exploiter -> vulnbox for the dashboard |
| `/etc/systemd/system/ad-dashboard.service` | the service (`systemctl status ad-dashboard`) |
| `/usr/local/sbin/addash-firewall.sh` | iptables rule for the dashboard port (`iptables -L ADDASH -v -n`) |
