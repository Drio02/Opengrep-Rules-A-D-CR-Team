#!/usr/bin/env bash
# ---------------------------------------------------------------------
# Scan many A&D services in one go and build ONE combined HTML report.
#
#   scripts/scan-bulk.sh <services-dir | services-list-file> [pack ...]
#
# <services-dir>        every sub-directory is a service (hidden dirs,
#                       opengrep-out/ and opengrep-reports/ are skipped)
# <services-list-file>  one service path per line; blank lines and
#                       "# comments" are ignored, relative paths are
#                       resolved from the list file's directory
#
# Packs are passed to scan.sh as-is (default: auto-detected per service).
#
# Environment variables (plus the ones of scan.sh: OPENGREP, SEVERITY, JOBS):
#   OUT_DIR     per-service reports go to $OUT_DIR/<service>
#               (default: ./opengrep-out)
#   REPORT_DIR  where the combined HTML report goes (default: ./opengrep-reports)
#   PARALLEL    services scanned at the same time (default: 1)
# ---------------------------------------------------------------------
set -euo pipefail

if [[ $# -lt 1 || "$1" == "-h" || "$1" == "--help" ]]; then
  sed -n '2,21p' "$0" | sed 's/^# \{0,1\}//'
  exit 1
fi

SOURCE="$1"; shift
REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BULK_OUT="${OUT_DIR:-./opengrep-out}"
REPORT_DIR="${REPORT_DIR:-./opengrep-reports}"
PARALLEL="${PARALLEL:-1}"
STAMP="$(date +%Y%m%d-%H%M%S)"

# ---- collect the service directories --------------------------------
SERVICES=()
if [[ -d "$SOURCE" ]]; then
  for d in "$SOURCE"/*/; do
    [[ -d "$d" ]] || continue
    d="${d%/}"
    case "$(basename "$d")" in
      .*|opengrep-out|opengrep-reports|node_modules) continue ;;
    esac
    # do not scan a copy of this rules repository living next to the services
    [[ "$(cd "$d" && pwd)" == "$REPO" ]] && continue
    [[ -f "$d/scripts/scan.sh" && -f "$d/scripts/triage.py" ]] && continue
    SERVICES+=("$d")
  done
elif [[ -f "$SOURCE" ]]; then
  LIST_DIR="$(cd "$(dirname "$SOURCE")" && pwd)"
  while IFS= read -r line || [[ -n "$line" ]]; do
    line="${line%%#*}"                                  # strip comments
    line="${line%$'\r'}"                                # CRLF lists from Windows
    line="$(echo "$line" | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')"
    [[ -z "$line" ]] && continue
    if [[ "$line" == "~"* ]]; then
      line="$HOME${line:1}"
    elif [[ "$line" != /* ]]; then
      line="$LIST_DIR/$line"
    fi
    if [[ -d "$line" ]]; then
      SERVICES+=("${line%/}")
    else
      echo "[!] skipping, not a directory: $line" >&2
    fi
  done < "$SOURCE"
else
  echo "[!] not a directory or file: $SOURCE" >&2
  exit 2
fi

if [[ ${#SERVICES[@]} -eq 0 ]]; then
  echo "[!] no services found in $SOURCE" >&2
  exit 2
fi

# ---- unique output name per service (two "api" dirs -> api, api-2) -----
NAMES=()
for s in "${SERVICES[@]}"; do
  base="$(basename "$(cd "$s" && pwd)")"; name="$base"; n=2
  while printf '%s\n' "${NAMES[@]:-}" | grep -qxF "$name"; do name="$base-$n"; n=$((n + 1)); done
  NAMES+=("$name")
done

mkdir -p "$BULK_OUT" "$REPORT_DIR"
echo "[*] services : ${#SERVICES[@]} (parallel: $PARALLEL)"
echo "[*] reports  : $BULK_OUT/<service>"

scan_one() {
  local svc="$1" name="$2"; shift 2
  mkdir -p "$BULK_OUT/$name"
  if OUT_DIR="$BULK_OUT/$name" NO_REPORT=1 bash "$REPO/scripts/scan.sh" "$svc" "$@" \
       > "$BULK_OUT/$name/scan.log" 2>&1; then
    echo "[+] done     : $name"
  else
    echo "[!] FAILED   : $name (see $BULK_OUT/$name/scan.log)"
  fi
}

for i in "${!SERVICES[@]}"; do
  if [[ "$PARALLEL" -gt 1 ]]; then
    while [[ "$(jobs -rp | wc -l)" -ge "$PARALLEL" ]]; do wait -n || true; done
    scan_one "${SERVICES[$i]}" "${NAMES[$i]}" "$@" &
  else
    echo "[*] scanning : ${NAMES[$i]} (${SERVICES[$i]})"
    scan_one "${SERVICES[$i]}" "${NAMES[$i]}" "$@"
  fi
done
wait

# ---- summary + combined report ---------------------------------------
PY=""
for p in python3 python; do
  if "$p" -c 'import sys' >/dev/null 2>&1; then PY="$p"; break; fi
done
[[ -z "$PY" ]] && { echo "[!] python not found: no summary / HTML report"; exit 0; }

DIRS=()
for name in "${NAMES[@]}"; do DIRS+=("$BULK_OUT/$name"); done

"$PY" - "${DIRS[@]}" <<'PY'
import collections, json, os, sys
print()
print(f"{'service':<28} {'total':>6} {'error':>6} {'warn':>6} {'info':>6}  notes")
for d in sys.argv[1:]:
    name = os.path.basename(d)
    try:
        with open(os.path.join(d, "results.json"), encoding="utf-8") as fh:
            res = json.load(fh)
    except (OSError, ValueError):
        print(f"{name:<28} {'-':>6} {'-':>6} {'-':>6} {'-':>6}  no results (see scan.log)")
        continue
    try:
        with open(os.path.join(d, "meta.json"), encoding="utf-8") as fh:
            meta = json.load(fh)
    except (OSError, ValueError):
        meta = {}
    c = collections.Counter(r["extra"].get("severity", "INFO") for r in res.get("results", []))
    notes = []
    if meta.get("binary_only"):
        notes.append("BINARY-ONLY, reverse it")
    if res.get("errors"):
        notes.append(f"{len(res['errors'])} scan error(s)")
    print(f"{name:<28} {sum(c.values()):>6} {c['ERROR']:>6} {c['WARNING']:>6} {c['INFO']:>6}  {'; '.join(notes)}")
print()
PY

"$PY" "$REPO/scripts/report.py" --no-clobber --title "A&D bulk scan - ${#SERVICES[@]} services" \
  -o "$REPORT_DIR/bulk-$STAMP.html" "${DIRS[@]}"
