# shellcheck shell=bash
# ---------------------------------------------------------------------
# Shared helpers of the deploy scripts (sourced, not executed).
# ---------------------------------------------------------------------
set -euo pipefail

DEPLOY_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

if [[ -t 1 ]]; then
  C_OK=$'\e[32m'; C_ERR=$'\e[31m'; C_WARN=$'\e[33m'; C_B=$'\e[1m'; C_0=$'\e[0m'
else
  C_OK=""; C_ERR=""; C_WARN=""; C_B=""; C_0=""
fi
FAILS=0
step() { printf '\n%s== %s%s\n' "$C_B" "$*" "$C_0"; }
ok()   { printf '  %s[ok]%s   %s\n' "$C_OK" "$C_0" "$*"; }
warn() { printf '  %s[warn]%s %s\n' "$C_WARN" "$C_0" "$*"; }
fail() { printf '  %s[FAIL]%s %s\n' "$C_ERR" "$C_0" "$*"; FAILS=$((FAILS + 1)); }
fix()  { printf '         -> %s\n' "$*"; }
die()  { fail "$1"; [[ -n "${2:-}" ]] && fix "$2"; exit 1; }

VARS=(TEAM_NET VULNBOX_IP EXPLOITER_IP TEAM_KEY VULNBOX_USER EXPLOITER_USER VULNBOX_SERVICES_DIR
      VULNBOX_KEY_ON_EXPLOITER GIT_SERVER_IP GIT_SERVER_USER DASH_PORT DASH_ALLOW DASH_DENY DASH_USER
      REPO_URL REPO_BRANCH OPENGREP_VERSION OPENGREP_SHA256 VULNBOX_KEY_UPLOADED)

load_env() {
  ENV_FILE="${ENV_FILE:-$DEPLOY_DIR/competition.env}"
  [[ -f "$ENV_FILE" ]] || die "missing $ENV_FILE" \
    "cp deploy/competition.env.example deploy/competition.env and fill it in"
  if grep -q $'\r' "$ENV_FILE"; then
    die "$ENV_FILE has Windows line endings" "sed -i 's/\\r\$//' $ENV_FILE"
  fi
  set -a
  # shellcheck disable=SC1090
  source "$ENV_FILE"
  set +a
  VULNBOX_USER="${VULNBOX_USER:-root}"; EXPLOITER_USER="${EXPLOITER_USER:-root}"
  VULNBOX_SERVICES_DIR="${VULNBOX_SERVICES_DIR:-/root/services}"
  DASH_PORT="${DASH_PORT:-8765}"; DASH_ALLOW="${DASH_ALLOW:-$TEAM_NET}"; DASH_DENY="${DASH_DENY:-}"
  DASH_USER="${DASH_USER:-addash}"; GIT_SERVER_USER="${GIT_SERVER_USER:-git}"
  VULNBOX_KEY_ON_EXPLOITER="${VULNBOX_KEY_ON_EXPLOITER:-}"; GIT_SERVER_IP="${GIT_SERVER_IP:-}"
  OPENGREP_VERSION="${OPENGREP_VERSION:-1.30.0}"; OPENGREP_SHA256="${OPENGREP_SHA256:-}"
  REPO_BRANCH="${REPO_BRANCH:-main}"
  TEAM_KEY="${TEAM_KEY/#\~/$HOME}"
  VULNBOX_KEY_UPLOADED="${VULNBOX_KEY_UPLOADED:-}"
  SSH_KEY_OPTS=(-i "$TEAM_KEY" -o IdentitiesOnly=yes)
  local v missing=()
  for v in TEAM_NET VULNBOX_IP EXPLOITER_IP TEAM_KEY REPO_URL; do
    [[ -n "${!v:-}" ]] || missing+=("$v")
  done
  [[ ${#missing[@]} -eq 0 ]] || die "empty in $ENV_FILE: ${missing[*]}" "fill them with the values of the portal"
  python3 - "$TEAM_NET" "$VULNBOX_IP" "$EXPLOITER_IP" "$DASH_ALLOW" "$DASH_DENY" <<'PY' || exit 1
import ipaddress, sys
net, vuln, expl, allow, deny = sys.argv[1:]
def bad(msg, hint):
    print(f"  [FAIL] {msg}\n         -> {hint}"); sys.exit(1)
try:
    net = ipaddress.ip_network(net, strict=False)
except ValueError:
    bad(f"TEAM_NET={net} is not a subnet", "copy 'Team subnet' from the portal, e.g. 10.60.39.0/24")
for name, ip in (("VULNBOX_IP", vuln), ("EXPLOITER_IP", expl)):
    try:
        if ipaddress.ip_address(ip) not in net:
            bad(f"{name}={ip} is not inside TEAM_NET={net}", "check the IPs against the portal")
    except ValueError:
        bad(f"{name}={ip} is not an IP address", "check the IPs against the portal")
if vuln == expl:
    bad("VULNBOX_IP and EXPLOITER_IP are the same", "the dashboard goes on the exploiter, not on the vulnbox")
for name, value in (("DASH_ALLOW", allow), ("DASH_DENY", deny)):
    for item in filter(None, value.replace(",", " ").split()):
        try:
            ipaddress.ip_network(item, strict=False)
        except ValueError:
            bad(f"{name}: '{item}' is not an IP or CIDR", "comma separated list, e.g. 10.60.39.0/24")
PY
  [[ "$DASH_PORT" =~ ^[0-9]+$ && "$DASH_PORT" -ge 1024 && "$DASH_PORT" -le 65535 && "$DASH_PORT" != 3001 ]] \
    || die "DASH_PORT=$DASH_PORT is not valid" "use a free port >= 1024 that is not 3001 (default 8765)"
}

# -F none: only what is passed here counts (a key in ~/.ssh/config must not
# hide a wrong TEAM_KEY)
SSH_COMMON=(-F none -o BatchMode=yes -o ConnectTimeout=8 -o ServerAliveInterval=15
            -o StrictHostKeyChecking=accept-new -o "UserKnownHostsFile=$HOME/.ssh/known_hosts_ad")
SSH_KEY_OPTS=()
# on_exploiter [-n] [-t] command...   (-n: stdin from /dev/null, -t: terminal)
on_exploiter() {
  local f=(); while [[ "${1:-}" == -n || "${1:-}" == -t ]]; do f+=("$1"); shift; done
  ssh "${f[@]}" "${SSH_COMMON[@]}" "${SSH_KEY_OPTS[@]}" "$EXPLOITER_USER@$EXPLOITER_IP" "$@"
}
on_vulnbox() {
  local f=(); while [[ "${1:-}" == -n || "${1:-}" == -t ]]; do f+=("$1"); shift; done
  ssh "${f[@]}" "${SSH_COMMON[@]}" "${SSH_KEY_OPTS[@]}" "$VULNBOX_USER@$VULNBOX_IP" "$@"
}

# Explain an ssh failure (output in $1) with the most likely fix.
ssh_hint() {
  case "$1" in
    *"Permission denied"*) echo "key refused: is TEAM_KEY the key deployed in the portal? (ssh-keygen -y -f $TEAM_KEY)";;
    *"UNPROTECTED PRIVATE KEY"*|*"bad permissions"*) echo "chmod 600 $TEAM_KEY (on WSL keep it in ~/.ssh, not under /mnt/c)";;
    *"timed out"*|*"No route to host"*|*"Network is unreachable"*) echo "VPN down? bring up WireGuard and check: ip route get <IP>";;
    *"Connection refused"*) echo "sshd not running on the target, or wrong IP";;
    *"Could not resolve"*) echo "check the IP in deploy/competition.env";;
    *"REMOTE HOST IDENTIFICATION HAS CHANGED"*|*"Host key verification failed"*)
      echo "machine reinstalled: ssh-keygen -f ~/.ssh/known_hosts_ad -R <IP>";;
    *"Load key"*) echo "broken key file: full BEGIN/END block, LF line endings (sed -i 's/\\r\$//' $TEAM_KEY)";;
    *) echo "run: ssh -v -i $TEAM_KEY <user>@<IP> true";;
  esac
}

# "export VAR='value'" lines for every setting, to prepend to a remote script
env_header() {
  local v
  for v in "${VARS[@]}"; do printf 'export %s=%q\n' "$v" "${!v:-}"; done
}

# Upload and run deploy/remote/exploiter.sh on the exploiter with MODE=$1.
# The script is copied first (not piped) so commands on the remote side
# that read stdin (ssh, git) cannot swallow it.
run_remote() {
  local mode="$1" sudo="" tmp
  [[ "$EXPLOITER_USER" == root ]] || sudo="sudo -n"
  tmp="/tmp/ad-deploy-$$.sh"
  { env_header; printf 'export MODE=%q\n' "$mode"; cat "$DEPLOY_DIR/remote/exploiter.sh"; } \
    | on_exploiter "umask 077; cat > $tmp"
  on_exploiter -n "$sudo bash $tmp; rc=\$?; rm -f $tmp; exit \$rc"
}
