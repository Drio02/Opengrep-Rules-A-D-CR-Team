#!/usr/bin/env bash
# ---------------------------------------------------------------------
# Step 3 - day-to-day operations and troubleshooting, from a laptop.
#
#   deploy/03-ops.sh doctor      check everything, print the fix for each problem
#   deploy/03-ops.sh status      service state + URL
#   deploy/03-ops.sh logs [-f]   last log lines of the dashboard (-f: follow)
#   deploy/03-ops.sh restart     restart the dashboard (re-applies the firewall)
#   deploy/03-ops.sh update      pull the latest rules/dashboard code + restart
#   deploy/03-ops.sh sync        refresh the service copies from the vulnbox
#   deploy/03-ops.sh uninstall   remove service + firewall rule (keeps labels)
#   deploy/03-ops.sh purge       uninstall + delete user, labels and copies
# ---------------------------------------------------------------------
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

CMD="${1:-}"; shift || true
case "$CMD" in
  doctor|status|logs|restart|update|sync|uninstall|purge) ;;
  *) sed -n '2,14p' "$0" | sed 's/^# \{0,1\}//'; exit 1 ;;
esac
load_env
URL="http://$EXPLOITER_IP:$DASH_PORT"

need_exploiter() {
  local rc=0 out
  out=$(on_exploiter -n true 2>&1) || rc=$?
  [[ $rc -eq 0 ]] || die "cannot log into the exploiter: $(tail -1 <<<"$out")" "$(ssh_hint "$out")"
}

case "$CMD" in
doctor)
  step "this laptop"
  [[ -f "$TEAM_KEY" ]] && ok "team key $TEAM_KEY" || { fail "team key $TEAM_KEY missing"; fix "deploy/01-setup-laptop.sh --key <file>"; }
  for target in "vulnbox $VULNBOX_IP" "exploiter $EXPLOITER_IP"; do
    read -r name ip <<<"$target"
    if timeout 5 bash -c "exec 3<>/dev/tcp/$ip/22" 2>/dev/null; then ok "VPN: $name $ip:22 reachable"
    else fail "VPN: $name $ip:22 not reachable"; fix "bring the WireGuard VPN up, then: ping $ip"; fi
  done
  rc=0; out=$(on_vulnbox -n true 2>&1) || rc=$?
  [[ $rc -eq 0 ]] && ok "SSH vulnbox" || { fail "SSH vulnbox: $(tail -1 <<<"$out")"; fix "$(ssh_hint "$out")"; }
  rc=0; out=$(on_exploiter -n true 2>&1) || rc=$?
  if [[ $rc -eq 0 ]]; then ok "SSH exploiter"
  else fail "SSH exploiter: $(tail -1 <<<"$out")"; fix "$(ssh_hint "$out")"; exit 2; fi
  if page=$(curl -s --max-time 8 "$URL/") && grep -q "<title>" <<<"$page"; then
    myip=$(curl -s --max-time 8 "$URL/api/me" | python3 -c 'import json,sys; print(json.load(sys.stdin).get("ip",""))' 2>/dev/null || true)
    ok "dashboard $URL answers (it sees this laptop as ${myip:-?})"
  else
    fail "dashboard $URL does not answer from this laptop"
    fix "if the exploiter checks below are OK: this laptop's VPN IP is not in DASH_ALLOW ($DASH_ALLOW)"
  fi
  rc=0; run_remote doctor || rc=$?
  echo
  if [[ $FAILS -eq 0 && $rc -eq 0 ]]; then echo "${C_OK}All checks passed.${C_0}"
  else echo "${C_ERR}Problems found.${C_0} Apply the '->' fixes; if unsure, re-run deploy/02-deploy-exploiter.sh (safe to repeat)."; exit 2; fi
  ;;
status)
  need_exploiter
  on_exploiter -n "systemctl --no-pager status ad-dashboard.service | head -12; echo; ss -ltnH 'sport = :$DASH_PORT'"
  echo; echo "URL: $URL/"
  ;;
logs)
  need_exploiter
  if [[ "${1:-}" == -f ]]; then on_exploiter -t "journalctl -u ad-dashboard.service -f -o cat"
  else on_exploiter -n "journalctl -u ad-dashboard.service --no-pager -n 80 -o cat"; fi
  ;;
restart)
  need_exploiter
  sudo=""; [[ "$EXPLOITER_USER" == root ]] || sudo="sudo -n"
  on_exploiter -n "$sudo systemctl restart ad-dashboard.service && sleep 2 && systemctl is-active ad-dashboard.service"
  ;;
update|sync)
  need_exploiter
  run_remote "$CMD"
  ;;
uninstall|purge)
  need_exploiter
  what="the dashboard service and its firewall rule (labels and service copies are kept)"
  [[ $CMD == purge ]] && what="the dashboard service, firewall rule, user $DASH_USER, ALL labels and service copies"
  read -r -p "Remove $what from $EXPLOITER_IP? [y/N] " answer
  [[ "$answer" =~ ^[yYsS]$ ]] || { echo "Nothing changed."; exit 0; }
  run_remote "$CMD"
  ;;
esac
