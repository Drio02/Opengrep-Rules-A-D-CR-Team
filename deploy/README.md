# deploy/

Plug-and-play setup of the team laptops and of the findings dashboard on the
exploiter. Full guide: [wiki/Competition-Deployment.md](../wiki/Competition-Deployment.md).

```bash
mkdir -p ~/compe && cd ~/compe && git clone <this repo> && cd Opengrep-Rules-A-D-CR-Team
cp deploy/competition.env.example deploy/competition.env   # fill in the portal values
deploy/01-setup-laptop.sh --key /path/to/team_key           # key + SSH + services copied to ~/compe/
deploy/02-deploy-exploiter.sh --prepare-offline             # while you have internet (offline kit)
deploy/02-deploy-exploiter.sh --check                       # one person: preflight
deploy/02-deploy-exploiter.sh                               # one person: install
deploy/03-ops.sh doctor                                     # anyone: health + fixes
```

| File | |
|---|---|
| `competition.env.example` | settings template (copy to `competition.env`, git-ignored) |
| `01-setup-laptop.sh` | team key, `~/.ssh/config`, VPN and SSH checks, read-only copy of the services next to the repo |
| `02-deploy-exploiter.sh` | installs / repairs the dashboard on the exploiter |
| `03-ops.sh` | doctor, status, logs, restart, update, sync, fetch, uninstall, purge |
| `lib.sh` | shared helpers |
| `remote/exploiter.sh` | the part that runs on the exploiter (uploaded by 02 / 03) |

If the exploiter has no internet, `02` and `03-ops.sh update` detect it and
upload opengrep and a git bundle of the repo from the laptop (`--offline` /
`--online` to force). Run them from Linux or WSL. Never commit keys or `competition.env`: the
repository is public.
