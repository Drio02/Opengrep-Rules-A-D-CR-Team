#!/usr/bin/env bash
# ---------------------------------------------------------------------
# Step 1 - every team member, on their laptop (Linux, or WSL on Windows).
#
#   deploy/01-setup-laptop.sh --key /path/to/team_private_key   # first time
#   deploy/01-setup-laptop.sh                                   # re-check
#
# Installs the team SSH key, writes ~/.ssh/config entries (vulnbox,
# exploiter, optional gitserver), tests VPN + SSH (explaining how to fix
# whatever fails) and copies the services of the vulnbox, read-only, next
# to this repository (its parent folder). Safe to run again at any time.
#
# Options:
#   --key FILE           install FILE as TEAM_KEY (CRLF stripped, chmod 600)
#   --services-dir DIR   where to copy the services (default: parent folder of the repo)
#   --no-services        do not copy the services
#   --opengrep           also install opengrep locally (for scan.sh / scan-bulk.sh)
# ---------------------------------------------------------------------
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

KEY_IN=""; WITH_OG=0; FETCH=1; SERVICES_DIR="$LOCAL_SERVICES_DIR"
while [[ $# -gt 0 ]]; do
  case "$1" in
    --key) KEY_IN="${2:-}"; shift 2 ;;
    --services-dir) SERVICES_DIR="${2:-}"; shift 2 ;;
    --no-services) FETCH=0; shift ;;
    --opengrep) WITH_OG=1; shift ;;
    -h|--help) sed -n '2,21p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) die "unknown option $1" "see --help" ;;
  esac
done
load_env

step "tools on this laptop"
for t in ssh ssh-keygen git curl python3; do
  command -v "$t" >/dev/null && ok "$t" || { fail "$t missing"; fix "sudo apt-get install -y openssh-client git curl python3"; }
done
if grep -qi microsoft /proc/version 2>/dev/null; then ok "running inside WSL"; fi

step "team SSH key ($TEAM_KEY)"
mkdir -p "$HOME/.ssh"; chmod 700 "$HOME/.ssh"
if [[ -n "$KEY_IN" ]]; then
  [[ -f "$KEY_IN" ]] || die "key file $KEY_IN not found"
  if [[ -f "$TEAM_KEY" ]] && ! cmp -s <(tr -d '\r' < "$KEY_IN") "$TEAM_KEY"; then
    cp "$TEAM_KEY" "$TEAM_KEY.bak.$(date +%s)"; warn "existing $TEAM_KEY backed up"
  fi
  install -d -m 700 "$(dirname "$TEAM_KEY")"
  ( umask 077; tr -d '\r' < "$KEY_IN" > "$TEAM_KEY" )
  chmod 600 "$TEAM_KEY"
  ok "installed from $KEY_IN"
fi
if [[ ! -f "$TEAM_KEY" ]]; then
  die "no key at $TEAM_KEY" "run again with --key /path/to/the/team/private/key"
fi
case "$TEAM_KEY" in
  /mnt/*) die "the key is on the Windows drive ($TEAM_KEY): ssh refuses it" \
              "set TEAM_KEY=~/.ssh/<name> and run again with --key $TEAM_KEY" ;;
esac
[[ "$(stat -c %a "$TEAM_KEY")" == 600 ]] || { chmod 600 "$TEAM_KEY"; warn "permissions fixed to 600"; }
if PUB=$(ssh-keygen -y -f "$TEAM_KEY" 2>&1); then
  ok "valid key: ${PUB:0:40}... ${PUB##* }"
  [[ -f "$TEAM_KEY.pub" ]] || { echo "$PUB" > "$TEAM_KEY.pub"; chmod 644 "$TEAM_KEY.pub"; }
else
  die "the key file is not a valid private key: $PUB" \
      "copy the full -----BEGIN/END----- block again (no passphrase, LF line endings)"
fi

step "~/.ssh/config entries"
CFG="$HOME/.ssh/config"; touch "$CFG"; chmod 600 "$CFG"
[[ -s "$CFG" ]] && cp "$CFG" "$CFG.bak.$(date +%s)"
sed -i '/# >>> ad-competition >>>/,/# <<< ad-competition <<</d' "$CFG"
{
  echo "# >>> ad-competition >>>"
  echo "# written by deploy/01-setup-laptop.sh from $ENV_FILE"
  for spec in "vulnbox $VULNBOX_IP $VULNBOX_USER" "exploiter $EXPLOITER_IP $EXPLOITER_USER" \
              ${GIT_SERVER_IP:+"gitserver $GIT_SERVER_IP $GIT_SERVER_USER"}; do
    read -r alias ip user <<<"$spec"
    printf 'Host %s %s\n    HostName %s\n    User %s\n    IdentityFile %s\n    IdentitiesOnly yes\n' \
      "$alias" "$ip" "$ip" "$user" "$TEAM_KEY"
    printf '    StrictHostKeyChecking accept-new\n    UserKnownHostsFile ~/.ssh/known_hosts_ad\n\n'
  done
  echo "# <<< ad-competition <<<"
} > "$CFG.new"
cat "$CFG" >> "$CFG.new"      # our block first: the first matching Host wins
mv "$CFG.new" "$CFG"; chmod 600 "$CFG"
ok "vulnbox, exploiter${GIT_SERVER_IP:+, gitserver} -> ssh vulnbox / ssh exploiter"
if sed '/# >>> ad-competition >>>/,/# <<< ad-competition <<</d' "$CFG" | grep -qiE '^\s*Host .*\b(vulnbox|exploiter)\b'; then
  warn "older 'Host vulnbox/exploiter' entries exist further down in $CFG (ignored: ours come first)"
fi

if [[ -n "$GIT_SERVER_IP" ]]; then
  git config --global --unset-all url."gitserver:".insteadOf 2>/dev/null || true
  git config --global --add url."gitserver:".insteadOf "$GIT_SERVER_USER@$GIT_SERVER_IP:"
  git config --global --add url."gitserver:".insteadOf "ssh://$GIT_SERVER_USER@$GIT_SERVER_IP"
  ok "git URLs of $GIT_SERVER_IP use the gitserver alias"
fi

step "VPN"
if command -v ip >/dev/null; then
  ROUTE=$(ip route get "$VULNBOX_IP" 2>&1 | head -1 || true)
  ok "route to the vulnbox: $ROUTE"
fi
for target in "vulnbox $VULNBOX_IP" "exploiter $EXPLOITER_IP"; do
  read -r name ip <<<"$target"
  if timeout 5 bash -c "exec 3<>/dev/tcp/$ip/22" 2>/dev/null; then ok "$name $ip:22 reachable"
  else fail "$name $ip:22 not reachable"; fix "is the WireGuard VPN up? (Windows: WireGuard app -> Activate; then ping $ip)"; fi
done

step "SSH logins"
VULNBOX_OK=0
for target in vulnbox exploiter; do
  rc=0
  if [[ $target == vulnbox ]]; then out=$(on_vulnbox -n 'echo "$(whoami)@$(hostname)"' 2>&1) || rc=$?
  else out=$(on_exploiter -n 'echo "$(whoami)@$(hostname)"' 2>&1) || rc=$?; fi
  if [[ $rc -eq 0 ]]; then ok "$target: logged in as $(tail -1 <<<"$out")"; [[ $target == vulnbox ]] && VULNBOX_OK=1
  else fail "$target: $(tail -1 <<<"$out")"; fix "$(ssh_hint "$out")"; fi
done
if [[ -n "$GIT_SERVER_IP" ]]; then
  if out=$(ssh -n "${SSH_COMMON[@]}" "${SSH_KEY_OPTS[@]}" "$GIT_SERVER_USER@$GIT_SERVER_IP" true 2>&1); then ok "gitserver: login works"
  else warn "gitserver: $(tail -1 <<<"$out") (only needed to clone/push team repos)"
       fix "add $TEAM_KEY.pub to ~$GIT_SERVER_USER/.ssh/authorized_keys on $GIT_SERVER_IP"; fi
fi

if [[ $FETCH -eq 1 ]]; then
  step "local copy of the services ($(realpath -m "$SERVICES_DIR"))"
  if [[ $VULNBOX_OK -eq 1 ]]; then
    fetch_services "$SERVICES_DIR"
  else
    warn "skipped: no SSH access to the vulnbox (fix the items above and run again)"
  fi
fi

if [[ $WITH_OG -eq 1 ]]; then
  step "opengrep $OPENGREP_VERSION (local)"
  if [[ "$(opengrep --version 2>/dev/null)" == "$OPENGREP_VERSION" ]]; then ok "already installed"
  else
    tmp=$(mktemp); curl -fsSL -o "$tmp" \
      "https://github.com/opengrep/opengrep/releases/download/v$OPENGREP_VERSION/opengrep_manylinux_x86" \
      || die "download failed" "check internet access"
    if [[ -n "$OPENGREP_SHA256" ]] && [[ "$(sha256sum "$tmp" | cut -d' ' -f1)" != "$OPENGREP_SHA256" ]]; then
      rm -f "$tmp"; die "opengrep sha256 mismatch" "check OPENGREP_VERSION / OPENGREP_SHA256"
    fi
    install -D -m 755 "$tmp" "$HOME/.local/bin/opengrep"; rm -f "$tmp"
    ok "installed in ~/.local/bin ($("$HOME/.local/bin/opengrep" --version))"
    [[ ":$PATH:" == *":$HOME/.local/bin:"* ]] || warn "add ~/.local/bin to PATH"
  fi
fi

echo
if [[ $FAILS -eq 0 ]]; then
  echo "${C_OK}Laptop ready.${C_0} Next (one person): deploy/02-deploy-exploiter.sh"
else
  echo "${C_ERR}$FAILS problem(s).${C_0} Fix the items marked [FAIL] (see '->') and run this script again."
  exit 2
fi
