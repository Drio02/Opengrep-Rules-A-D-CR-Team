#!/usr/bin/env python3
"""Build a self-contained HTML report from one or more scan output dirs.

    python scripts/report.py [-o report.html] [--title T] <scan-dir> [<scan-dir> ...]

A <scan-dir> is what scan.sh / scan.ps1 write (OUT_DIR): it holds
results.json and, when written by the wrappers, meta.json (service name,
target path, packs, native binaries found). The report shows every
finding of every service, ranked like triage.py, with the surrounding
source lines, filters, and a per-finding triage status (confirmed / false
positive / patched) kept in the browser's localStorage.

Only the standard library is needed; the HTML has no external assets, so
it opens offline on the vulnbox or a laptop without internet.
"""
import argparse
import datetime
import html
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from triage import IMPACT_ORDER, SEV_ORDER  # noqa: E402

CONTEXT = 3          # source lines shown above / below a finding
MAX_MATCH_LINES = 30  # a match spanning a whole function is cut here
MAX_CONTEXT_LINE = 240


def load_json(path):
    try:
        # utf-8-sig: Windows PowerShell 5 writes meta.json with a BOM
        with open(path, encoding="utf-8-sig") as fh:
            return json.load(fh)
    except (OSError, ValueError):
        return None


def read_context(src, start, end):
    """Return [[lineno, text, is_hit], ...] around start..end, or []."""
    try:
        with open(src, encoding="utf-8", errors="replace") as fh:
            lines = fh.read().splitlines()
    except OSError:
        return []
    lo = max(1, start - CONTEXT)
    cut = end - start + 1 > MAX_MATCH_LINES
    hi = min(len(lines), start + MAX_MATCH_LINES - 1 if cut else end + CONTEXT)
    ctx = [[n, lines[n - 1][:MAX_CONTEXT_LINE], start <= n <= end] for n in range(lo, hi + 1)]
    if cut:
        ctx.append(["...", f"({end - hi} more matched lines)", False])
    return ctx


def load_service(scan_dir):
    scan_dir = os.path.abspath(scan_dir)
    meta = load_json(os.path.join(scan_dir, "meta.json")) or {}
    report = load_json(os.path.join(scan_dir, "results.json"))
    name = meta.get("service") or os.path.basename(scan_dir.rstrip("/\\"))
    svc = {
        "name": name,
        "target": meta.get("target", ""),
        "scanned_at": meta.get("scanned_at", ""),
        "packs": meta.get("packs", []),
        "binaries": meta.get("binaries", []),
        "binary_only": bool(meta.get("binary_only")),
        "errors": [],
        "findings": [],
        "missing": report is None,
    }
    if report is None:
        return svc

    for e in report.get("errors", []):
        msg = e.get("message") or e.get("type") or "error"
        svc["errors"].append(" ".join(str(msg).split())[:400])

    cwd = meta.get("cwd") or os.getcwd()
    target = meta.get("target") or ""
    results = report.get("results", [])
    if not target and results:
        # same fallback as triage.py: common directory of all findings
        dirs = [os.path.dirname(os.path.abspath(os.path.join(cwd, r["path"]))) for r in results]
        target = os.path.commonpath(dirs) if len(set(dirs)) > 1 else dirs[0]

    for r in results:
        extra = r.get("extra", {})
        md = extra.get("metadata", {}) or {}
        src = r["path"] if os.path.isabs(r["path"]) else os.path.join(cwd, r["path"])
        src = os.path.normpath(src)
        rel = os.path.relpath(src, target) if target else r["path"]
        start, end = r["start"]["line"], r["end"]["line"]
        cwe = md.get("cwe", "")
        if isinstance(cwe, list):
            cwe = ", ".join(cwe)
        svc["findings"].append({
            "rule": r["check_id"].split(".")[-1],
            "sev": extra.get("severity", "INFO"),
            "impact": md.get("ad-impact") or "",
            "cwe": str(cwe).split(":")[0],
            "confidence": md.get("confidence", ""),
            "path": rel.replace("\\", "/"),
            "line": start,
            "end": end,
            "message": " ".join(str(extra.get("message", "")).split()),
            "code": extra.get("lines", ""),
            "context": read_context(src, start, end),
            "fp": extra.get("fingerprint", "") + f":{rel}:{start}",
        })

    def sort_key(f):
        imp = f["impact"] or None
        return (IMPACT_ORDER.index(imp) if imp in IMPACT_ORDER else len(IMPACT_ORDER),
                SEV_ORDER.get(f["sev"], 3), f["path"], f["line"])

    svc["findings"].sort(key=sort_key)
    return svc


def build(services, title):
    data = {
        "title": title,
        "generated": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "impactOrder": [i for i in IMPACT_ORDER if i],
        "services": services,
    }
    blob = json.dumps(data, ensure_ascii=False).replace("</", "<\\/")
    return TEMPLATE.replace("__TITLE__", html.escape(title)).replace("__DATA__", blob)


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("scan_dirs", nargs="+", help="scan output dirs (with results.json)")
    ap.add_argument("-o", "--output", default="opengrep-report.html", help="HTML file to write")
    ap.add_argument("--title", default="", help="report title")
    ap.add_argument("--no-clobber", action="store_true",
                    help="never overwrite: add -2, -3, ... to the file name")
    args = ap.parse_args()

    services = [load_service(d) for d in args.scan_dirs]
    if all(s["missing"] for s in services):
        print("[!] no results.json found in: " + " ".join(args.scan_dirs), file=sys.stderr)
        return 1
    title = args.title or ("A&D scan - " + (services[0]["name"] if len(services) == 1
                                             else f"{len(services)} services"))
    out = os.path.abspath(args.output)
    os.makedirs(os.path.dirname(out), exist_ok=True)
    # two scans in the same second must not overwrite each other's report
    stem, ext = os.path.splitext(out)
    n = 2
    while args.no_clobber and os.path.exists(out):
        out = f"{stem}-{n}{ext}"
        n += 1
    with open(out, "w", encoding="utf-8", newline="\n") as fh:
        fh.write(build(services, title))
    total = sum(len(s["findings"]) for s in services)
    print(f"[*] html report: {out} ({len(services)} service(s), {total} findings)")
    return 0


TEMPLATE = r"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>__TITLE__</title>
<style>
:root {
  --bg: #f6f7f9; --panel: #ffffff; --text: #1d2330; --muted: #5d6677; --line: #dde1e8;
  --code-bg: #f3f4f7; --hit: #fff3c4; --accent: #2f6fdb;
  --err: #c9372c; --warn: #b7791f; --info: #3b74c4; --ok: #2f855a; --fp: #718096;
}
@media (prefers-color-scheme: dark) {
  :root {
    --bg: #12151b; --panel: #1b2029; --text: #e3e7ee; --muted: #99a3b3; --line: #2c3442;
    --code-bg: #141920; --hit: #3d3514; --accent: #6ea0ff;
    --err: #ff6b5e; --warn: #f0b44c; --info: #74a7f2; --ok: #5fcf91; --fp: #a0aec0;
  }
}
* { box-sizing: border-box; }
body { margin: 0; background: var(--bg); color: var(--text);
  font: 14px/1.45 system-ui, -apple-system, "Segoe UI", Roboto, sans-serif; }
header { padding: 20px 24px 8px; }
h1 { margin: 0 0 4px; font-size: 22px; }
.sub { color: var(--muted); font-size: 13px; }
main { padding: 0 24px 40px; max-width: 1400px; }
.cards { display: flex; flex-wrap: wrap; gap: 10px; margin: 14px 0; }
.card { background: var(--panel); border: 1px solid var(--line); border-radius: 8px;
  padding: 10px 14px; min-width: 120px; }
.card .n { font-size: 22px; font-weight: 650; }
.card .l { color: var(--muted); font-size: 12px; text-transform: uppercase; letter-spacing: .04em; }
table { width: 100%; border-collapse: collapse; background: var(--panel);
  border: 1px solid var(--line); border-radius: 8px; overflow: hidden; }
th, td { text-align: left; padding: 7px 10px; border-bottom: 1px solid var(--line); vertical-align: top; }
th { font-size: 12px; color: var(--muted); text-transform: uppercase; letter-spacing: .04em; }
tr.svc-row { cursor: pointer; }
tr.svc-row:hover td { background: var(--code-bg); }
.num { text-align: right; font-variant-numeric: tabular-nums; }
.toolbar { position: sticky; top: 0; z-index: 5; background: var(--bg); padding: 12px 0;
  display: flex; flex-wrap: wrap; gap: 8px; align-items: center; border-bottom: 1px solid var(--line); }
input[type=search], select, button { font: inherit; color: var(--text); background: var(--panel);
  border: 1px solid var(--line); border-radius: 6px; padding: 5px 8px; }
input[type=search] { min-width: 260px; flex: 1; }
button { cursor: pointer; }
button:hover { border-color: var(--accent); }
.chip { user-select: none; }
.chip input { margin-right: 4px; }
.count { color: var(--muted); margin-left: auto; }
h2 { font-size: 16px; margin: 26px 0 8px; }
details.group { margin: 14px 0; }
details.group > summary { cursor: pointer; font-weight: 650; font-size: 15px; padding: 6px 0; }
details.group > summary .meta { font-weight: 400; color: var(--muted); font-size: 13px; margin-left: 6px; }
.warnbox { border-left: 4px solid var(--warn); background: var(--panel); padding: 8px 12px;
  margin: 6px 0; border-radius: 4px; }
.f { background: var(--panel); border: 1px solid var(--line); border-left: 4px solid var(--info);
  border-radius: 6px; margin: 8px 0; padding: 10px 12px; }
.f.ERROR { border-left-color: var(--err); }
.f.WARNING { border-left-color: var(--warn); }
.f.st-fp { opacity: .55; }
.f.st-patched { border-left-color: var(--ok); }
.fh { display: flex; flex-wrap: wrap; gap: 8px; align-items: center; }
.badge { font-size: 11px; font-weight: 700; padding: 1px 7px; border-radius: 10px; color: #fff; }
.badge.ERROR { background: var(--err); } .badge.WARNING { background: var(--warn); }
.badge.INFO { background: var(--info); }
.pill { font-size: 12px; padding: 1px 8px; border-radius: 10px; border: 1px solid var(--line); color: var(--muted); }
.pill.imp { color: var(--text); font-weight: 600; }
.rule { font-family: ui-monospace, SFMono-Regular, Consolas, monospace; font-weight: 600; }
.loc { font-family: ui-monospace, SFMono-Regular, Consolas, monospace; color: var(--accent); cursor: pointer; }
.fh .right { margin-left: auto; display: flex; gap: 6px; align-items: center; }
.msg { margin: 6px 0; }
pre { margin: 6px 0 0; background: var(--code-bg); border: 1px solid var(--line); border-radius: 4px;
  padding: 6px 0; overflow-x: auto; font: 12.5px/1.5 ui-monospace, SFMono-Regular, Consolas, monospace; }
pre .ln { display: block; padding: 0 10px; white-space: pre; }
pre .ln.hit { background: var(--hit); }
pre .no { display: inline-block; width: 4.5em; color: var(--muted); user-select: none; }
.empty { color: var(--muted); padding: 30px 0; text-align: center; }
@media print { .toolbar, .right button, select.status { display: none; } .f { break-inside: avoid; } }
</style>
</head>
<body>
<header>
  <h1 id="title"></h1>
  <div class="sub" id="subtitle"></div>
</header>
<main>
  <div class="cards" id="cards"></div>
  <table id="svc-table">
    <thead><tr><th>Service</th><th class="num">Findings</th><th class="num">Error</th>
      <th class="num">Warning</th><th class="num">Info</th><th>By impact</th><th>Notes</th></tr></thead>
    <tbody></tbody>
  </table>

  <div class="toolbar">
    <input type="search" id="q" placeholder="Search rule, file, message, code...">
    <label class="chip"><input type="checkbox" class="sev" value="ERROR" checked>Error</label>
    <label class="chip"><input type="checkbox" class="sev" value="WARNING" checked>Warning</label>
    <label class="chip"><input type="checkbox" class="sev" value="INFO" checked>Info</label>
    <select id="svc"><option value="">All services</option></select>
    <select id="imp"><option value="">All impacts</option></select>
    <select id="st">
      <option value="">Any status</option><option value="new">Untriaged</option>
      <option value="confirmed">Confirmed</option><option value="fp">False positive</option>
      <option value="patched">Patched</option><option value="open">Not FP / not patched</option>
    </select>
    <select id="group"><option value="service">Group by service</option>
      <option value="rule">Group by rule</option><option value="impact">Group by impact</option></select>
    <button id="expand">Expand all</button><button id="collapse">Collapse all</button>
    <button id="csv">Export CSV</button>
    <span class="count" id="count"></span>
  </div>
  <div id="list"></div>
</main>
<script id="data" type="application/json">__DATA__</script>
<script>
(function () {
  "use strict";
  var D = JSON.parse(document.getElementById("data").textContent);
  var SEVS = ["ERROR", "WARNING", "INFO"];
  var STATUS_LABEL = { "": "Untriaged", confirmed: "Confirmed", fp: "False positive", patched: "Patched" };
  var KEY = "ogreport-status:";

  function esc(s) {
    return String(s == null ? "" : s).replace(/[&<>"']/g, function (c) {
      return { "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c];
    });
  }
  function getStatus(fp) { try { return localStorage.getItem(KEY + fp) || ""; } catch (e) { return ""; } }
  function setStatus(fp, v) {
    try { if (v) localStorage.setItem(KEY + fp, v); else localStorage.removeItem(KEY + fp); } catch (e) {}
  }
  function impactRank(i) { var k = D.impactOrder.indexOf(i); return k < 0 ? D.impactOrder.length : k; }

  // flatten
  var all = [];
  D.services.forEach(function (s, si) {
    s.findings.forEach(function (f, fi) { f.service = s.name; f.si = si; f.id = si + "-" + fi; all.push(f); });
  });

  // header + cards
  document.getElementById("title").textContent = D.title;
  document.title = D.title;
  document.getElementById("subtitle").textContent = "Generated " + D.generated + " - " +
    D.services.length + " service(s)";
  var bySev = { ERROR: 0, WARNING: 0, INFO: 0 }, byImp = {};
  all.forEach(function (f) {
    bySev[f.sev] = (bySev[f.sev] || 0) + 1;
    var i = f.impact || "other"; byImp[i] = (byImp[i] || 0) + 1;
  });
  var cards = [["Services", D.services.length], ["Findings", all.length],
    ["Error", bySev.ERROR], ["Warning", bySev.WARNING], ["Info", bySev.INFO]];
  Object.keys(byImp).sort(function (a, b) { return impactRank(a) - impactRank(b); })
    .forEach(function (i) { cards.push([i, byImp[i]]); });
  document.getElementById("cards").innerHTML = cards.map(function (c) {
    return '<div class="card"><div class="n">' + esc(c[1]) + '</div><div class="l">' + esc(c[0]) + "</div></div>";
  }).join("");

  // services table
  var tbody = document.querySelector("#svc-table tbody");
  tbody.innerHTML = D.services.map(function (s, si) {
    var c = { ERROR: 0, WARNING: 0, INFO: 0 }, imp = {};
    s.findings.forEach(function (f) { c[f.sev] = (c[f.sev] || 0) + 1; var i = f.impact || "other"; imp[i] = (imp[i] || 0) + 1; });
    var imps = Object.keys(imp).sort(function (a, b) { return impactRank(a) - impactRank(b); })
      .map(function (i) { return '<span class="pill">' + esc(i) + " " + imp[i] + "</span>"; }).join(" ");
    var notes = [];
    if (s.missing) notes.push("no results.json (scan failed?)");
    if (s.binary_only) notes.push("binary-only: not analyzed, reverse it");
    else if (s.binaries.length) notes.push("native binaries not analyzed: " + s.binaries.slice(0, 3).join(", "));
    if (s.errors.length) notes.push(s.errors.length + " scan error(s)");
    return '<tr class="svc-row" data-si="' + si + '"><td><b>' + esc(s.name) + "</b>" +
      (s.packs.length ? '<div class="sub">' + esc(s.packs.join(" ")) + "</div>" : "") + "</td>" +
      '<td class="num">' + s.findings.length + '</td><td class="num">' + c.ERROR + '</td><td class="num">' +
      c.WARNING + '</td><td class="num">' + c.INFO + "</td><td>" + imps + "</td><td>" + esc(notes.join("; ")) + "</td></tr>";
  }).join("");

  // filter options
  var svcSel = document.getElementById("svc"), impSel = document.getElementById("imp");
  D.services.forEach(function (s, si) {
    svcSel.insertAdjacentHTML("beforeend", '<option value="' + si + '">' + esc(s.name) + "</option>");
  });
  Object.keys(byImp).sort(function (a, b) { return impactRank(a) - impactRank(b); }).forEach(function (i) {
    impSel.insertAdjacentHTML("beforeend", '<option value="' + esc(i) + '">' + esc(i) + "</option>");
  });
  Array.prototype.forEach.call(document.querySelectorAll("tr.svc-row"), function (tr) {
    tr.addEventListener("click", function () {
      svcSel.value = tr.getAttribute("data-si"); render();
      document.querySelector(".toolbar").scrollIntoView({ behavior: "smooth" });
    });
  });

  function visible() {
    var q = document.getElementById("q").value.trim().toLowerCase();
    var sevs = Array.prototype.filter.call(document.querySelectorAll(".sev"), function (c) { return c.checked; })
      .map(function (c) { return c.value; });
    var si = svcSel.value, imp = impSel.value, st = document.getElementById("st").value;
    return all.filter(function (f) {
      if (sevs.indexOf(f.sev) < 0) return false;
      if (si !== "" && String(f.si) !== si) return false;
      if (imp && (f.impact || "other") !== imp) return false;
      var s = getStatus(f.fp);
      if (st === "new" && s) return false;
      if (st === "open" && (s === "fp" || s === "patched")) return false;
      if (st && st !== "new" && st !== "open" && s !== st) return false;
      if (q) {
        var hay = (f.rule + " " + f.path + " " + f.message + " " + f.code + " " + f.service + " " + f.cwe).toLowerCase();
        if (hay.indexOf(q) < 0) return false;
      }
      return true;
    });
  }

  function findingHtml(f) {
    var st = getStatus(f.fp);
    var ctx = f.context && f.context.length ? f.context.map(function (l) {
      return '<span class="ln' + (l[2] ? " hit" : "") + '"><span class="no">' + l[0] + "</span>" + esc(l[1]) + "</span>";
    }).join("") : (f.code ? '<span class="ln hit"><span class="no">' + f.line + "</span>" + esc(f.code) + "</span>" : "");
    var opts = Object.keys(STATUS_LABEL).map(function (k) {
      return '<option value="' + k + '"' + (k === st ? " selected" : "") + ">" + STATUS_LABEL[k] + "</option>";
    }).join("");
    var loc = f.service + "/" + f.path + ":" + f.line;
    return '<div class="f ' + f.sev + (st ? " st-" + st : "") + '" data-id="' + f.id + '">' +
      '<div class="fh"><span class="badge ' + f.sev + '">' + f.sev + "</span>" +
      (f.impact ? '<span class="pill imp">' + esc(f.impact) + "</span>" : "") +
      '<span class="rule">' + esc(f.rule) + "</span>" +
      '<span class="loc" title="Click to copy" data-loc="' + esc(loc) + '">' + esc(f.path) + ":" + f.line + "</span>" +
      (f.cwe ? '<span class="pill">' + esc(f.cwe) + "</span>" : "") +
      (f.confidence ? '<span class="pill">conf ' + esc(f.confidence) + "</span>" : "") +
      '<span class="right"><select class="status" data-fp="' + esc(f.fp) + '">' + opts + "</select></span></div>" +
      '<div class="msg">' + esc(f.message) + "</div>" + (ctx ? "<pre>" + ctx + "</pre>" : "") + "</div>";
  }

  function render() {
    var list = visible(), mode = document.getElementById("group").value, groups = {}, order = [];
    list.forEach(function (f) {
      var k = mode === "service" ? f.service : mode === "rule" ? f.rule : (f.impact || "other");
      if (!groups[k]) { groups[k] = []; order.push(k); }
      groups[k].push(f);
    });
    if (mode === "impact") order.sort(function (a, b) { return impactRank(a) - impactRank(b); });
    if (mode === "rule") order.sort(function (a, b) { return groups[b].length - groups[a].length; });
    var out = order.map(function (k) {
      var g = groups[k], e = g.filter(function (f) { return f.sev === "ERROR"; }).length;
      var extra = "";
      if (mode === "service") {
        var s = D.services[g[0].si];
        if (s.binary_only) extra = '<div class="warnbox">Binary-only service: opengrep could not analyze it. Reverse the binary.</div>';
      }
      return '<details class="group" open><summary>' + esc(k) + '<span class="meta">' + g.length +
        " finding(s), " + e + " error</span></summary>" + extra + g.map(findingHtml).join("") + "</details>";
    });
    // services with nothing to show still deserve a line when grouping by service
    if (mode === "service" && !document.getElementById("q").value && svcSel.value === "") {
      D.services.forEach(function (s) {
        if (groups[s.name]) return;
        var why = s.binary_only ? "binary-only service, not analyzed - reverse it" :
          s.missing ? "no results (scan failed?)" : s.findings.length ? "all findings filtered out" : "no findings";
        out.push('<details class="group"><summary>' + esc(s.name) + '<span class="meta">' + esc(why) + "</span></summary></details>");
      });
    }
    document.getElementById("list").innerHTML = out.join("") ||
      '<div class="empty">No findings match the current filters.</div>';
    document.getElementById("count").textContent = list.length + " / " + all.length + " shown";
  }

  document.getElementById("list").addEventListener("change", function (ev) {
    var t = ev.target;
    if (!t.classList.contains("status")) return;
    setStatus(t.getAttribute("data-fp"), t.value);
    var card = t.closest(".f");
    card.className = card.className.replace(/\sst-\w+/g, "") + (t.value ? " st-" + t.value : "");
  });
  document.getElementById("list").addEventListener("click", function (ev) {
    var t = ev.target;
    if (!t.classList.contains("loc")) return;
    var v = t.getAttribute("data-loc");
    if (navigator.clipboard) navigator.clipboard.writeText(v).catch(function () {});
    t.title = "Copied: " + v;
  });
  ["q", "svc", "imp", "st", "group"].forEach(function (id) {
    document.getElementById(id).addEventListener("input", render);
  });
  Array.prototype.forEach.call(document.querySelectorAll(".sev"), function (c) { c.addEventListener("change", render); });
  document.getElementById("expand").addEventListener("click", function () {
    Array.prototype.forEach.call(document.querySelectorAll("details.group"), function (d) { d.open = true; });
  });
  document.getElementById("collapse").addEventListener("click", function () {
    Array.prototype.forEach.call(document.querySelectorAll("details.group"), function (d) { d.open = false; });
  });
  document.getElementById("csv").addEventListener("click", function () {
    var rows = [["service", "severity", "impact", "rule", "cwe", "file", "line", "status", "message"]];
    visible().forEach(function (f) {
      rows.push([f.service, f.sev, f.impact, f.rule, f.cwe, f.path, f.line, STATUS_LABEL[getStatus(f.fp)], f.message]);
    });
    var csv = rows.map(function (r) {
      return r.map(function (v) { return '"' + String(v == null ? "" : v).replace(/"/g, '""') + '"'; }).join(",");
    }).join("\n");
    var a = document.createElement("a");
    a.href = URL.createObjectURL(new Blob([csv], { type: "text/csv" }));
    a.download = "findings.csv"; document.body.appendChild(a); a.click(); a.remove();
  });
  render();
})();
</script>
</body>
</html>
"""


if __name__ == "__main__":
    sys.exit(main())
