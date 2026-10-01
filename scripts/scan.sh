#!/usr/bin/env bash
# ---------------------------------------------------------------------
# Scan an A&D service with the rule packs of this repository.
#
#   scripts/scan.sh <service-dir> [pack ...]
#
# Packs are the top-level rule folders (python js php go java ruby rust
# c csharp infra). Without packs, they are auto-detected from the file
# extensions found in <service-dir>; "infra" is always included.
#
# Environment variables:
#   OPENGREP   opengrep binary (default: opengrep in PATH)
#   OUT_DIR    where reports are written (default: ./opengrep-out/<service>)
#   SEVERITY   minimum severity: INFO | WARNING | ERROR (default: INFO)
#   JOBS       parallel jobs (default: opengrep default)
# ---------------------------------------------------------------------
set -euo pipefail

if [[ $# -lt 1 || "$1" == "-h" || "$1" == "--help" ]]; then
  sed -n '2,18p' "$0" | sed 's/^# \{0,1\}//'
  exit 1
fi

TARGET="$1"; shift
REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OPENGREP="${OPENGREP:-opengrep}"
SERVICE="$(basename "$(cd "$TARGET" && pwd)")"
OUT_DIR="${OUT_DIR:-./opengrep-out/$SERVICE}"
SEVERITY="${SEVERITY:-INFO}"

# folder name of each pack (the Python folder is spelled "pyhton" in this repo)
pack_dir() {
  case "$1" in
    python|py) echo "pyhton" ;;
    javascript|typescript|ts|node) echo "js" ;;
    cpp|c++) echo "c" ;;
    cs|dotnet) echo "csharp" ;;
    *) echo "$1" ;;
  esac
}

detect_packs() {
  local found=()
  has() { find "$TARGET" -type f \( "$@" \) -not -path '*/node_modules/*' -not -path '*/.git/*' -print -quit | grep -q .; }
  has -name '*.py'                                   && found+=(python)
  has -name '*.js' -o -name '*.ts' -o -name '*.jsx' -o -name '*.tsx' -o -name '*.mjs' && found+=(js)
  has -name '*.php' -o -name '*.phtml'               && found+=(php)
  has -name '*.go'                                   && found+=(go)
  has -name '*.java' -o -name '*.jsp' -o -name '*.kt' && found+=(java)
  has -name '*.rb' -o -name '*.erb'                  && found+=(ruby)
  has -name '*.rs'                                   && found+=(rust)
  has -name '*.c' -o -name '*.h' -o -name '*.cpp' -o -name '*.cc' -o -name '*.hpp' && found+=(c)
  has -name '*.cs' -o -name '*.cshtml'               && found+=(csharp)
  echo "${found[@]:-}"
}

PACKS=("$@")
if [[ ${#PACKS[@]} -eq 0 ]]; then
  read -r -a PACKS <<< "$(detect_packs)"
fi
PACKS+=(infra)

CONFIG_ARGS=()
for p in "${PACKS[@]}"; do
  d="$REPO/$(pack_dir "$p")"
  [[ -d "$d" ]] || { echo "[!] unknown pack: $p" >&2; exit 2; }
  CONFIG_ARGS+=(--config "$d")
done

SEV_ARGS=()
case "$SEVERITY" in
  ERROR)   SEV_ARGS=(--severity ERROR) ;;
  WARNING) SEV_ARGS=(--severity WARNING --severity ERROR) ;;
esac

JOB_ARGS=()
[[ -n "${JOBS:-}" ]] && JOB_ARGS=(--jobs "$JOBS")

mkdir -p "$OUT_DIR"
echo "[*] service : $TARGET"
echo "[*] packs   : ${PACKS[*]}"
echo "[*] reports : $OUT_DIR"

# --x-ignore-semgrepignore-files: the default ignore list skips tests/,
#   vendor dirs, etc. A&D services sometimes keep real code there.
# --taint-intrafile: follow user input across functions of the same file.
"$OPENGREP" scan \
  "${CONFIG_ARGS[@]}" \
  "${SEV_ARGS[@]}" \
  "${JOB_ARGS[@]}" \
  --taint-intrafile \
  --x-ignore-semgrepignore-files \
  --no-git-ignore \
  --exclude node_modules --exclude .git --exclude '*.min.js' \
  --timeout 30 --quiet \
  --json-output "$OUT_DIR/results.json" \
  --sarif-output "$OUT_DIR/results.sarif" \
  --text-output "$OUT_DIR/results.txt" \
  "$TARGET" > /dev/null || true

# pick a working interpreter (on Windows "python3" can be a Store stub)
for PY in python3 python; do
  if "$PY" -c 'import sys' >/dev/null 2>&1; then
    "$PY" "$REPO/scripts/triage.py" "$OUT_DIR/results.json" | tee "$OUT_DIR/triage.txt"
    break
  fi
done
