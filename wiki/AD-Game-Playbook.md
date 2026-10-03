# A&D Game Playbook

How Team Costa Rica uses this rule set during an Attack & Defense game.
Static analysis does not replace reading the code. Its job is to show, within
minutes, **where to read first**.

---

## Before the competition

- [ ] Opengrep binary downloaded on **every** laptop (offline copy), plus
      Python 3.
- [ ] This repo cloned. `scripts/test-rules.sh` passes.
- [ ] Each person knows which packs they own. Suggested split: one person per
      service, plus one person on infra/compose.
- [ ] Rehearse on old A&D services: ECSC / FAUST CTF / saarCTF / ENOWARS
      services are public on GitHub. Scan a few, note the false positives,
      and tune the rules.
- [ ] Agree on a patch workflow: git on the vulnbox, one commit per fix, so a
      broken patch can be reverted fast.

## T+0 - Network opens

1. **Copy the services off the vulnbox** (rsync/scp the whole service
   folders) and `git init` them locally, so you can diff your patches.
2. **Scan everything at once**:
   ```bash
   for s in services/*/; do SEVERITY=WARNING scripts/scan.sh "$s"; done
   ```
3. Post each `opengrep-out/<service>/triage.txt` in the team channel.

## T+5 - Infra quick wins (no code reading needed)

Look at the `compose-*`, `dockerfile-*` and `nginx-*` findings first. They are
usually fixable in a minute and every team has them:

| Finding | Action |
|---|---|
| `compose-backing-service-port-exposed` | Remove the `ports:` entry of the DB/Redis/Mongo service, or bind it to `127.0.0.1:`. |
| `compose-default-or-empty-db-credentials` | Change the password in **both** the DB service and the app's connection string, then restart both. |
| `compose-hardcoded-app-secret` / `*-hardcoded-*-secret` / `*-jwt-hardcoded-*` | Rotate the secret: same format and length, new random value. Existing sessions break, but the checker logs in again. |
| `compose-debug-mode-enabled`, `*-debug-*` | Turn debug off. |
| `nginx-alias-traversal`, `nginx-autoindex-on` | Fix the config and reload nginx. |

> Rotating a hardcoded secret is a **defense**, and an **attack** at the same
> time: the teams that did not rotate it can be attacked with the public
> value (forge a session or JWT for the flag owner).

## T+10 - Triage the code findings

Work top-down through `triage.txt` (it is already sorted by impact):

1. **`rce`**: command injection, SSTI, eval, deserialization, file upload,
   format strings and memory bugs. Patch immediately: with RCE an attacker can
   read every flag and even break your service.
2. **`flag-leak`**: SQLi, path traversal, SSRF, IDOR, unauthenticated
   sensitive routes, debug leaks.
3. **`auth-bypass`**: forgeable cookies/JWT, weak randomness, timing/loose
   comparisons, mass assignment, cookie/IP-based authorization.
4. Everything else, when time allows.

For each finding:

- Confirm it by reading the code around it. Is the source really controlled
  by the attacker? Does the sink really reach flag data?
- Note it in the team tracker as `service | rule | file:line | status`.
- Two people should not patch the same file at the same time.

## Patching rules of thumb

- **Do not break the checker** (SLA points). Keep inputs, outputs and formats
  identical for legitimate requests. Prefer *narrow* fixes: parameterize the
  query, add an allowlist, add an ownership check.
- Avoid blanket WAF-style filters (blocking `'` or `..` everywhere). They often
  break legitimate flag strings and usernames.
- After each patch: restart the service, run the service's own functionality
  manually (register, store, retrieve), and watch the scoreboard SLA.
- See the [Patching Cheatsheet](Patching-Cheatsheet.md) for per-language
  snippets.

## Attack side

Every team runs the same code, so each confirmed finding is also an exploit
lead:

1. Write the exploit against **your own unpatched copy** first (local docker
   compose).
2. Typical first exploits: hardcoded secret -> forged session; SQLi /
   path traversal -> dump the flag table or file; IDOR -> iterate IDs from the
   attack-info / flag IDs the game publishes.
3. Automate across all team IPs with the team's exploit runner, and submit
   flags every tick.
4. Teams patch over time: keep the exploit, but expect it to stop working.
   Then look for the next finding in `triage.txt`.

## Re-scan after patching

```bash
scripts/scan.sh services/notes        # the fixed finding should disappear
```

If a finding is a false positive, write it down in the team notes and fix the
rule after the game. Do not spend game time tuning rules.

## Backdoors

Services sometimes contain deliberately planted backdoors: magic passwords,
debug routes, hidden parameters. The original `extra.yaml` files have
`*-backdoor-magic-string` rules, and the new `*-sensitive-route-without-*`,
`*-cookie-based-authorization`, `*-ip-based-auth-spoofable` and
`*-debug-*` rules catch the usual shapes. When you find one:

- Remove it on your box.
- Exploit it against the other teams immediately. Backdoors are the fastest
  flags of the game.
