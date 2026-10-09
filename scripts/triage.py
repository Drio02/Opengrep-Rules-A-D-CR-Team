#!/usr/bin/env python3
"""Summarize an opengrep JSON report for A&D triage.

Groups findings by A&D impact (rce > flag-leak > auth-bypass > ...) and
severity so the team can decide what to patch first.

    python scripts/triage.py opengrep-out/<service>/results.json [--all]
"""
import collections
import json
import os
import sys

IMPACT_ORDER = ["rce", "flag-leak", "auth-bypass", "session-theft", "integrity",
                "dos", "phishing", None]
SEV_ORDER = {"ERROR": 0, "WARNING": 1, "INFO": 2}


def main() -> int:
    if len(sys.argv) < 2:
        print(__doc__)
        return 1
    show_all = "--all" in sys.argv
    with open(sys.argv[1], encoding="utf-8-sig") as fh:
        report = json.load(fh)

    results = report.get("results", [])
    errors = report.get("errors", [])

    def impact(r):
        return (r.get("extra", {}).get("metadata", {}) or {}).get("ad-impact")

    def sort_key(r):
        imp = impact(r)
        return (IMPACT_ORDER.index(imp) if imp in IMPACT_ORDER else len(IMPACT_ORDER),
                SEV_ORDER.get(r["extra"].get("severity", "INFO"), 3),
                r["path"], r["start"]["line"])

    results.sort(key=sort_key)
    by_impact = collections.Counter(impact(r) or "other" for r in results)
    by_rule = collections.Counter(r["check_id"].split(".")[-1] for r in results)

    print(f"\n== {len(results)} findings, {len(errors)} scan errors ==")
    print("by impact : " + ", ".join(f"{k}={v}" for k, v in by_impact.most_common()))
    print("top rules : " + ", ".join(f"{k}={v}" for k, v in by_rule.most_common(8)))
    print()

    # show paths relative to the scanned service, not to the current dir
    root = ""
    if results:
        dirs = [os.path.dirname(os.path.abspath(r["path"])) for r in results]
        root = os.path.commonpath(dirs) if len(set(dirs)) > 1 else dirs[0]

    limit = None if show_all else 60
    for r in results[:limit]:
        rule = r["check_id"].split(".")[-1]
        sev = r["extra"].get("severity", "?")[0]
        imp = impact(r) or "-"
        loc = f"{os.path.relpath(os.path.abspath(r['path']), root)}:{r['start']['line']}"
        code = r["extra"].get("lines", "").strip().splitlines()[0][:100] if r["extra"].get("lines") else ""
        print(f"[{sev}] {imp:<13} {rule:<45} {loc}")
        if code:
            print(f"      {code}")
    if limit and len(results) > limit:
        print(f"\n... {len(results) - limit} more (use --all, or open results.txt / results.sarif)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
