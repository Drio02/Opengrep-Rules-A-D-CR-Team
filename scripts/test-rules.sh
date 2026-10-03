#!/usr/bin/env bash
# ---------------------------------------------------------------------
# Validate every rule pack and run the annotated fixtures in tests/.
#
#   scripts/test-rules.sh            # all packs
#   scripts/test-rules.sh go java    # only some folders
#
# A rule file <pack>/<name>.yaml is tested against every file
# tests/<pack>/<name>.* (one fixture per extension, e.g. frontend.jsp
# and frontend.html). Annotations: "ruleid: <id>" marks a line that must
# match, "ok: <id>" marks a line that must NOT match.
# ---------------------------------------------------------------------
set -uo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OPENGREP="${OPENGREP:-opengrep}"
cd "$REPO"

PACKS=("$@")
if [[ ${#PACKS[@]} -eq 0 ]]; then
  for d in */; do
    d="${d%/}"
    [[ "$d" == tests || "$d" == scripts || "$d" == wiki ]] && continue
    ls "$d"/*.yaml >/dev/null 2>&1 && PACKS+=("$d")
  done
fi

fail=0
echo "== validate =="
for p in "${PACKS[@]}"; do
  if ! out=$("$OPENGREP" scan --validate --config "$p" 2>&1); then
    echo "[FAIL] $p"; echo "$out" | tail -5; fail=1
  else
    echo "[ ok ] $p: $(echo "$out" | grep -o '[0-9]* rule(s)' | tail -1)"
  fi
done

echo "== fixtures =="
for p in "${PACKS[@]}"; do
  for rule in "$p"/*.yaml; do
    name="$(basename "$rule" .yaml)"
    shopt -s nullglob
    fixtures=(tests/"$p"/"$name".*)
    shopt -u nullglob
    [[ ${#fixtures[@]} -eq 0 ]] && continue
    for fx in "${fixtures[@]}"; do
      out=$("$OPENGREP" test --config "$rule" "$fx" 2>&1 | sed 's/\x1b\[[0-9;]*m//g')
      if echo "$out" | grep -q "All tests passed"; then
        echo "[ ok ] $fx ($(echo "$out" | grep -o '^[0-9]*/[0-9]*' | head -1))"
      else
        echo "[FAIL] $fx"; echo "$out" | grep -E "ERROR|did not pass" | head -10; fail=1
      fi
    done
  done
done

exit $fail
