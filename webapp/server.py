#!/usr/bin/env python3
"""A&D findings dashboard.

Scan every service of a directory with the rule packs of this repository,
pull the latest service code from git, re-run the analysis, and track every
finding: label (patch in progress / patched in prod / false positive) and
patcher assignee.

    python3 webapp/server.py [--root ~/vulnbox/services] [--port 8765]
                             [--host 127.0.0.1] [--data DIR] [--token T]

Only the Python standard library is used. State (settings, patchers,
labels) and scan output live in --data (default
~/.local/share/opengrep-dashboard), never inside the services.

Binding to anything other than localhost requires a token: one is
generated and printed when --token is not given. The game network is
hostile, so do not expose the dashboard without it.
"""
import argparse
import concurrent.futures
import datetime
import hashlib
import http.server
import ipaddress
import json
import os
import re
import secrets
import shutil
import socket
import subprocess
import sys
import threading
import traceback
import urllib.parse

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(HERE)
sys.path.insert(0, os.path.join(REPO, "scripts"))
import report  # noqa: E402  (scripts/report.py: parsing + HTML export)

DEFAULT_PORT = 8765          # not 3001, not 9000-9400 used by the services
RESERVED_PORTS = {3001}
DEFAULT_PATCHERS = ["Dario", "David", "Juanca", "Andres", "Caleb", "Damian", "Jerelyn"]
STATUSES = {
    "": "Open",
    "in_progress": "Patch in progress",
    "patched": "Patched in prod",
    "false_positive": "False positive",
}
COMPOSE_GLOBS = "docker-compose*.yml docker-compose*.yaml compose*.yml compose*.yaml"
SKIP_DIRS = {"opengrep-out", "opengrep-reports", "node_modules"}
MAX_BODY = 64 * 1024
KEEP_RUNS = 3

DEFAULT_SETTINGS = {
    "root": "",
    "branch": "main",
    "ssh_key": "",
    "skip_compose": True,
    "severity": "INFO",
    "parallel": 3,
    "opengrep": "",
}


def now():
    return datetime.datetime.now().isoformat(timespec="seconds")


def run(cmd, cwd=None, env=None, timeout=120):
    """Run a command without a shell. Returns (rc, combined output)."""
    try:
        p = subprocess.run(cmd, cwd=cwd, env=env, timeout=timeout, text=True,
                           stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        return p.returncode, p.stdout.strip()
    except subprocess.TimeoutExpired:
        return 124, f"timed out after {timeout}s"
    except OSError as e:
        return 127, str(e)


# ---------------------------------------------------------------------------
# services discovery / git helpers
# ---------------------------------------------------------------------------
def discover_services(root):
    """Sub-directories of root that look like services (same rules as scan-bulk)."""
    out = []
    if not root or not os.path.isdir(root):
        return out
    for name in sorted(os.listdir(root)):
        path = os.path.join(root, name)
        if not os.path.isdir(path) or name.startswith(".") or name in SKIP_DIRS:
            continue
        # a copy of this rules repository living next to the services
        if os.path.realpath(path) == os.path.realpath(REPO) or (
                os.path.isfile(os.path.join(path, "scripts", "scan.sh"))
                and os.path.isfile(os.path.join(path, "scripts", "triage.py"))):
            continue
        out.append((name, path))
    return out


def service_ports(root):
    """Ports declared by the services: .env *PORT=, compose ports, EXPOSE."""
    ports = set()
    for _, path in discover_services(root):
        for fname in (".env", "docker-compose.yml", "docker-compose.yaml",
                      "compose.yml", "compose.yaml", "Dockerfile"):
            try:
                with open(os.path.join(path, fname), encoding="utf-8", errors="replace") as fh:
                    text = fh.read()
            except OSError:
                continue
            ports.update(int(p) for p in re.findall(r"(?im)^\s*\w*PORT\w*\s*=\s*(\d{2,5})\s*$", text))
            ports.update(int(p) for p in re.findall(r"(?im)^\s*EXPOSE\s+(\d{2,5})", text))
            # "8080:80", "${SERVICE_PORT:-9000}:${SERVICE_PORT:-9000}"
            for a, b in re.findall(r"(\d{2,5})\}?\s*:\s*\$?\{?[\w:-]*?(\d{2,5})", text):
                ports.update((int(a), int(b)))
    return {p for p in ports if 0 < p < 65536}


def git_info(path):
    if not os.path.isdir(os.path.join(path, ".git")):
        return {"git": False}
    _, branch = run(["git", "-C", path, "branch", "--show-current"], timeout=15)
    _, head = run(["git", "-C", path, "log", "-1", "--format=%h|%cI|%s"], timeout=15)
    _, dirty = run(["git", "-C", path, "status", "--porcelain"], timeout=30)
    h = (head.split("|", 2) + ["", "", ""])[:3]
    return {"git": True, "branch": branch, "head": h[0], "date": h[1], "subject": h[2][:120],
            "dirty": len([line for line in dirty.splitlines() if line.strip()])}


def git_env(ssh_key):
    env = dict(os.environ, GIT_TERMINAL_PROMPT="0")
    ssh = "ssh -o BatchMode=yes -o ConnectTimeout=10 -o StrictHostKeyChecking=accept-new"
    if ssh_key:
        ssh += f" -i '{ssh_key}' -o IdentitiesOnly=yes"
    env["GIT_SSH_COMMAND"] = ssh
    return env


def pull_service(path, branch, ssh_key):
    """Fast-forward the service to origin/<branch>. Never switches branches
    and never discards local patches. Returns (state, message)."""
    if not os.path.isdir(os.path.join(path, ".git")):
        return "skipped", "not a git repository"
    env = git_env(ssh_key)
    rc, out = run(["git", "-C", path, "fetch", "--prune", "origin"], env=env, timeout=90)
    if rc != 0:
        noise = ("Warning: Permanently added", "fatal: Could not read from remote",
                 "Please make sure you have", "and the repository exists")
        lines = [ln for ln in out.splitlines() if ln.strip() and not ln.startswith(noise)]
        msg = "git fetch failed: " + " | ".join(lines)[-300:]
        if "Permission denied" in out:
            msg += " (set the SSH key for git in Settings)"
        return "failed", msg
    target = branch
    rc, _ = run(["git", "-C", path, "rev-parse", "--verify", "--quiet", f"origin/{target}"])
    fallback = ""
    if rc != 0:
        # the remote has no <branch> (e.g. vulnbox repos use master): use its default
        rc, ref = run(["git", "-C", path, "symbolic-ref", "--short", "refs/remotes/origin/HEAD"])
        candidates = ([ref.split("/", 1)[1]] if rc == 0 and "/" in ref else []) + ["main", "master"]
        for c in candidates:
            if run(["git", "-C", path, "rev-parse", "--verify", "--quiet", f"origin/{c}"])[0] == 0:
                fallback, target = f" (origin has no '{branch}', used '{c}')", c
                break
        else:
            return "failed", f"origin has no branch '{branch}'"
    _, current = run(["git", "-C", path, "branch", "--show-current"])
    if current != target:
        return "skipped", f"checked out '{current or 'detached HEAD'}', not '{target}': not switching{fallback}"
    _, before = run(["git", "-C", path, "rev-parse", "--short", "HEAD"])
    rc, out = run(["git", "-C", path, "merge", "--ff-only", f"origin/{target}"], env=env, timeout=60)
    if rc != 0:
        lines = [ln.strip() for ln in out.splitlines() if ln.strip() and not ln.startswith("hint:")]
        return "failed", ("fast-forward failed (local commits or conflicting local changes): "
                          + " | ".join(lines)[:300])
    _, after = run(["git", "-C", path, "rev-parse", "--short", "HEAD"])
    if before == after:
        return "ok", f"already up to date with origin/{target}{fallback}"
    _, n = run(["git", "-C", path, "rev-list", "--count", f"{before}..{after}"])
    return "ok", f"updated {before} -> {after} ({n} commit(s)) from origin/{target}{fallback}"


def finding_keys(service, findings):
    """Stable id per finding: survives line shifts (no line number inside)."""
    seen = {}
    for f in findings:
        code = " ".join(str(f.get("code", "")).split())
        base = f"{service}|{f['rule']}|{f['path']}|{code}"
        n = seen.get(base, 0)
        seen[base] = n + 1
        f["key"] = hashlib.sha1(f"{base}|{n}".encode()).hexdigest()[:16]


# ---------------------------------------------------------------------------
# state
# ---------------------------------------------------------------------------
class Store:
    def __init__(self, data_dir):
        self.dir = data_dir
        self.lock = threading.RLock()
        os.makedirs(os.path.join(data_dir, "runs"), exist_ok=True)
        self.state_file = os.path.join(data_dir, "state.json")
        self.scan_file = os.path.join(data_dir, "last_scan.json")
        self.state = {"settings": dict(DEFAULT_SETTINGS), "patchers": list(DEFAULT_PATCHERS),
                      "labels": {}, "version": 0}
        loaded = self._read(self.state_file)
        if loaded:
            self.state["settings"].update(loaded.get("settings", {}))
            self.state["patchers"] = loaded.get("patchers") or list(DEFAULT_PATCHERS)
            self.state["labels"] = loaded.get("labels", {})
            self.state["version"] = loaded.get("version", 0)
        self.scan = self._read(self.scan_file) or {}

    @staticmethod
    def _read(path):
        try:
            with open(path, encoding="utf-8") as fh:
                return json.load(fh)
        except (OSError, ValueError):
            return None

    def _write(self, path, data):
        tmp = path + ".tmp"
        with open(tmp, "w", encoding="utf-8") as fh:
            json.dump(data, fh, ensure_ascii=False)
        os.replace(tmp, path)

    def save(self):
        with self.lock:
            self.state["version"] += 1
            self._write(self.state_file, self.state)

    def save_scan(self, scan):
        with self.lock:
            self.scan = scan
            self._write(self.scan_file, scan)
            self.state["version"] += 1
            self._write(self.state_file, self.state)


# ---------------------------------------------------------------------------
# background jobs
# ---------------------------------------------------------------------------
class Jobs:
    def __init__(self, store):
        self.store = store
        self.lock = threading.Lock()
        self.job = None

    def busy(self):
        return self.job is not None and self.job["state"] == "running"

    def start(self, kind):
        with self.lock:
            if self.busy():
                return None
            s = self.store.state["settings"]
            if not s["root"] or not os.path.isdir(s["root"]):
                raise ValueError("set an existing services directory first")
            self.job = {"kind": kind, "state": "running", "started": now(), "finished": "",
                        "steps": {}, "log": [], "error": ""}
            threading.Thread(target=self._run, args=(kind, dict(s)), daemon=True).start()
            return self.job

    def log(self, line):
        self.job["log"].append(f"[{datetime.datetime.now():%H:%M:%S}] {line}")
        del self.job["log"][:-500]

    def step(self, service, phase, state, msg=""):
        self.job["steps"].setdefault(service, {})[phase] = {"state": state, "message": msg}

    def _run(self, kind, settings):
        try:
            if kind in ("pull", "pull-scan"):
                self._pull(settings)
            if kind in ("scan", "pull-scan"):
                self._scan(settings)
            self.job["state"] = "done"
        except Exception as e:  # keep the server alive, show the error in the UI
            self.job["state"] = "failed"
            self.job["error"] = str(e)
            self.log("ERROR: " + "".join(traceback.format_exception_only(type(e), e)).strip())
        finally:
            self.job["finished"] = now()
            self.log(f"{kind} {self.job['state']}")
            with self.store.lock:
                self.store.state["version"] += 1

    # -- git pull ------------------------------------------------------------
    def _pull(self, s):
        services = discover_services(s["root"])
        self.log(f"pulling {len(services)} service(s) from origin/{s['branch']}")
        for name, _ in services:
            self.step(name, "pull", "queued")

        def one(item):
            name, path = item
            self.step(name, "pull", "running")
            state, msg = pull_service(path, s["branch"], s["ssh_key"])
            self.step(name, "pull", state, msg)
            self.log(f"pull {name}: {state} - {msg}")

        with concurrent.futures.ThreadPoolExecutor(max_workers=max(1, int(s["parallel"]))) as ex:
            list(ex.map(one, services))

    # -- scan ------------------------------------------------------------------
    def _scan(self, s):
        services = discover_services(s["root"])
        if not services:
            raise ValueError(f"no services found in {s['root']}")
        run_dir = os.path.join(self.store.dir, "runs", datetime.datetime.now().strftime("%Y%m%d-%H%M%S"))
        os.makedirs(run_dir, exist_ok=True)
        opengrep = s["opengrep"] or shutil.which("opengrep") or os.path.expanduser("~/.local/bin/opengrep")
        env = dict(os.environ, OPENGREP=opengrep, NO_REPORT="1", SEVERITY=s["severity"],
                   EXCLUDE=COMPOSE_GLOBS if s["skip_compose"] else "")
        self.log(f"scanning {len(services)} service(s) with {opengrep}"
                 + (" (docker-compose files skipped)" if s["skip_compose"] else ""))
        for name, _ in services:
            self.step(name, "scan", "queued")

        def one(item):
            name, path = item
            out = os.path.join(run_dir, name)
            os.makedirs(out, exist_ok=True)
            self.step(name, "scan", "running")
            rc, text = run(["bash", os.path.join(REPO, "scripts", "scan.sh"), path],
                           env=dict(env, OUT_DIR=out), timeout=900)
            with open(os.path.join(out, "scan.log"), "w", encoding="utf-8") as fh:
                fh.write(text)
            ok = rc == 0 and os.path.isfile(os.path.join(out, "results.json"))
            m = re.search(r"== (\d+) findings, (\d+) scan errors ==", text)
            msg = f"{m.group(1)} findings, {m.group(2)} scan errors" if m else text[-300:]
            self.step(name, "scan", "ok" if ok else "failed", msg)
            self.log(f"scan {name}: {msg}")

        with concurrent.futures.ThreadPoolExecutor(max_workers=max(1, int(s["parallel"]))) as ex:
            list(ex.map(one, services))

        # parse, give every finding a stable key, diff against the previous run
        prev = self.store.scan or {}
        prev_by_key = {f["key"]: dict(f, service=svc["name"])
                       for svc in prev.get("services", []) for f in svc.get("findings", [])}
        prev_names = {svc["name"] for svc in prev.get("services", [])}
        result = []
        for name, path in services:
            svc = report.load_service(os.path.join(run_dir, name))
            svc["name"] = name
            svc["path"] = path
            svc["git"] = git_info(path)
            finding_keys(name, svc["findings"])
            for f in svc["findings"]:
                f["new"] = bool(prev) and name in prev_names and f["key"] not in prev_by_key
            result.append(svc)
        cur_keys = {f["key"] for svc in result for f in svc["findings"]}
        scanned = {name for name, _ in services}
        resolved = [f for k, f in prev_by_key.items() if k not in cur_keys and f["service"] in scanned]
        self.store.save_scan({"run": os.path.basename(run_dir), "run_dir": run_dir, "finished": now(),
                              "root": s["root"], "skip_compose": s["skip_compose"],
                              "severity": s["severity"], "services": result, "resolved": resolved})
        self.log(f"analysis done: {len(cur_keys)} findings, {len(resolved)} resolved since the previous run")

        runs = sorted(os.listdir(os.path.join(self.store.dir, "runs")))
        for old in runs[:-KEEP_RUNS]:
            shutil.rmtree(os.path.join(self.store.dir, "runs", old), ignore_errors=True)


# ---------------------------------------------------------------------------
# HTTP
# ---------------------------------------------------------------------------
STATIC = {"/": "index.html", "/app.js": "app.js", "/style.css": "style.css"}
CTYPES = {".html": "text/html; charset=utf-8", ".js": "text/javascript; charset=utf-8",
          ".css": "text/css; charset=utf-8"}


class Handler(http.server.BaseHTTPRequestHandler):
    server_version = "opengrep-dashboard"
    store = None
    jobs = None
    token = ""

    def log_message(self, fmt, *args):  # quieter console: only errors
        if args and str(args[1]).startswith(("4", "5")) and str(args[1]) != "401":
            sys.stderr.write("%s %s\n" % (self.address_string(), fmt % args))

    # -- helpers -------------------------------------------------------------
    def send(self, code, body, ctype="application/json; charset=utf-8", extra=None):
        if not isinstance(body, (bytes, str)):
            body = json.dumps(body, ensure_ascii=False)
        if isinstance(body, str):
            body = body.encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Content-Security-Policy",
                         "default-src 'self'; style-src 'self'; script-src 'self'; img-src 'self' data:")
        for k, v in (extra or {}).items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(body)

    def authorized(self):
        if not self.token:
            return True
        q = urllib.parse.parse_qs(urllib.parse.urlparse(self.path).query)
        given = self.headers.get("X-Token", "") or (q.get("token") or [""])[0]
        return secrets.compare_digest(given, self.token)

    def body(self):
        n = int(self.headers.get("Content-Length") or 0)
        if n > MAX_BODY:
            raise ValueError("request too large")
        if self.headers.get("Content-Type", "").split(";")[0].strip() != "application/json":
            raise ValueError("expected application/json")
        return json.loads(self.rfile.read(n) or b"{}")

    # -- routes ----------------------------------------------------------------
    def do_GET(self):
        path = urllib.parse.urlparse(self.path).path
        if path == "/favicon.ico":
            return self.send(204, b"", "image/x-icon")
        if path in STATIC:
            fname = os.path.join(HERE, "static", STATIC[path])
            with open(fname, "rb") as fh:
                return self.send(200, fh.read(), CTYPES[os.path.splitext(fname)[1]])
        if not path.startswith("/api/"):
            return self.send(404, {"error": "not found"})
        if not self.authorized():
            return self.send(401, {"error": "token required"})
        st = self.store
        if path == "/api/state":
            with st.lock:
                scan = st.scan or {}
                return self.send(200, {
                    "settings": st.state["settings"], "patchers": st.state["patchers"],
                    "defaultPatchers": DEFAULT_PATCHERS, "statuses": STATUSES,
                    "version": st.state["version"], "job": self.jobs.job,
                    "scan": {k: scan.get(k) for k in ("run", "finished", "root", "skip_compose", "severity")},
                    "impactOrder": [i for i in report.IMPACT_ORDER if i],
                })
        if path == "/api/version":
            j = self.jobs.job
            return self.send(200, {"version": st.state["version"], "job": j and j["state"]})
        if path == "/api/job":
            return self.send(200, {"job": self.jobs.job})
        if path == "/api/findings":
            with st.lock:
                scan = st.scan or {}
                return self.send(200, {"services": scan.get("services", []),
                                       "resolved": scan.get("resolved", []),
                                       "labels": st.state["labels"], "version": st.state["version"]})
        if path == "/api/report.html":
            scan = st.scan or {}
            if not scan.get("services"):
                return self.send(404, {"error": "no analysis yet"})
            html = report.build(scan["services"], f"A&D scan - {len(scan['services'])} services")
            return self.send(200, html, "text/html; charset=utf-8",
                             {"Content-Disposition": f'attachment; filename="opengrep-{scan["run"]}.html"'})
        return self.send(404, {"error": "not found"})

    def do_POST(self):
        path = urllib.parse.urlparse(self.path).path
        if not self.authorized():
            return self.send(401, {"error": "token required"})
        try:
            data = self.body()
            return self.send(200, self.post(path, data))
        except LookupError as e:
            return self.send(404, {"error": str(e)})
        except ValueError as e:
            return self.send(400, {"error": str(e)})
        except RuntimeError as e:
            return self.send(409, {"error": str(e)})

    def post(self, path, data):
        st = self.store
        if path == "/api/settings":
            new = dict(st.state["settings"])
            if "root" in data:
                root = os.path.abspath(os.path.expanduser(str(data["root"]).strip()))
                if not os.path.isdir(root):
                    raise ValueError(f"not a directory: {root}")
                new["root"] = root
            if "branch" in data:
                b = str(data["branch"]).strip()
                if not re.fullmatch(r"[A-Za-z0-9._/-]{1,100}", b) or b.startswith("-") or ".." in b:
                    raise ValueError("invalid branch name")
                new["branch"] = b
            if "ssh_key" in data:
                k = os.path.expanduser(str(data["ssh_key"]).strip())
                if k and not os.path.isfile(k):
                    raise ValueError(f"ssh key not found: {k}")
                if "'" in k:
                    raise ValueError("invalid ssh key path")
                new["ssh_key"] = k
            if "opengrep" in data:
                o = os.path.expanduser(str(data["opengrep"]).strip())
                if o and not (os.path.isfile(o) and os.access(o, os.X_OK)):
                    raise ValueError(f"opengrep binary not found / not executable: {o}")
                new["opengrep"] = o
            if "skip_compose" in data:
                new["skip_compose"] = bool(data["skip_compose"])
            if "severity" in data:
                if data["severity"] not in ("INFO", "WARNING", "ERROR"):
                    raise ValueError("invalid severity")
                new["severity"] = data["severity"]
            if "parallel" in data:
                new["parallel"] = max(1, min(16, int(data["parallel"])))
            with st.lock:
                st.state["settings"] = new
                st.save()
            return {"settings": new, "services": [n for n, _ in discover_services(new["root"])]}

        if path in ("/api/scan", "/api/pull", "/api/pull-scan"):
            job = self.jobs.start(path.rsplit("/", 1)[1])
            if job is None:
                raise RuntimeError("another job is still running")
            return {"job": job}

        if path == "/api/label":
            key = str(data.get("key", ""))
            if not re.fullmatch(r"[0-9a-f]{16}", key):
                raise ValueError("invalid finding key")
            with st.lock:
                label = dict(st.state["labels"].get(key, {}))
                if "status" in data:
                    if data["status"] not in STATUSES:
                        raise ValueError("invalid status")
                    label["status"] = data["status"]
                if "assignee" in data:
                    if data["assignee"] and data["assignee"] not in st.state["patchers"]:
                        raise ValueError("unknown patcher")
                    label["assignee"] = data["assignee"]
                label["updated"] = now()
                if label.get("status") or label.get("assignee"):
                    st.state["labels"][key] = label
                else:
                    st.state["labels"].pop(key, None)
                st.save()
                return {"key": key, "label": label, "version": st.state["version"]}

        if path == "/api/patchers":
            name = " ".join(str(data.get("name", "")).split())
            if not re.fullmatch(r"[\w .'-]{1,40}", name):
                raise ValueError("patcher name: 1-40 letters, digits, spaces, . ' -")
            with st.lock:
                if name.lower() in (p.lower() for p in st.state["patchers"]):
                    raise ValueError(f"{name} is already a patcher")
                st.state["patchers"].append(name)
                st.save()
                return {"patchers": st.state["patchers"]}

        if path == "/api/patchers/remove":
            name = str(data.get("name", ""))
            with st.lock:
                if name not in st.state["patchers"]:
                    raise LookupError("unknown patcher")
                if name in DEFAULT_PATCHERS:
                    raise ValueError("default patchers cannot be removed")
                st.state["patchers"].remove(name)
                for label in st.state["labels"].values():
                    if label.get("assignee") == name:
                        label["assignee"] = ""
                st.save()
                return {"patchers": st.state["patchers"]}

        raise LookupError("not found")


def is_loopback(host):
    try:
        return ipaddress.ip_address(socket.gethostbyname(host)).is_loopback
    except (OSError, ValueError):
        return False


def main():
    ap = argparse.ArgumentParser(description="A&D findings dashboard")
    ap.add_argument("--root", default="", help="services directory (can also be set in the UI)")
    ap.add_argument("--port", type=int, default=DEFAULT_PORT, help=f"default {DEFAULT_PORT}")
    ap.add_argument("--host", default="127.0.0.1", help="default 127.0.0.1 (localhost only)")
    ap.add_argument("--data", default=os.path.expanduser("~/.local/share/opengrep-dashboard"),
                    help="state + scan output directory")
    ap.add_argument("--token", default="", help="access token (generated when --host is not local)")
    args = ap.parse_args()

    store = Store(os.path.abspath(os.path.expanduser(args.data)))
    if args.root:
        root = os.path.abspath(os.path.expanduser(args.root))
        if not os.path.isdir(root):
            sys.exit(f"[!] not a directory: {root}")
        store.state["settings"]["root"] = root
        store.save()

    used = service_ports(store.state["settings"]["root"]) | RESERVED_PORTS
    if args.port in used:
        sys.exit(f"[!] port {args.port} is reserved or used by a service "
                 f"({', '.join(map(str, sorted(used)))}); pick another with --port")

    token = args.token
    if not token and not is_loopback(args.host):
        token = secrets.token_urlsafe(18)
    Handler.store, Handler.jobs, Handler.token = store, Jobs(store), token

    try:
        httpd = http.server.ThreadingHTTPServer((args.host, args.port), Handler)
    except OSError as e:
        sys.exit(f"[!] cannot listen on {args.host}:{args.port}: {e}")
    shown = "localhost" if is_loopback(args.host) else args.host
    if shown in ("0.0.0.0", "::"):
        try:  # the address teammates can reach (no packet is sent)
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                s.connect(("10.255.255.255", 1))
                shown = s.getsockname()[0]
        except OSError:
            pass
    print(f"[*] data     : {store.dir}")
    print(f"[*] services : {store.state['settings']['root'] or '(set it in the UI)'}")
    print(f"[*] dashboard: http://{shown}:{args.port}/" + (f"#token={token}" if token else ""), flush=True)
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
