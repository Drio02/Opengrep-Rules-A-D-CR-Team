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
SERVICE_MARKERS = ("Dockerfile", "docker-compose.yml", "docker-compose.yaml", "compose.yml", "compose.yaml")


def _has_marker(path):
    return any(os.path.isfile(os.path.join(path, m)) for m in SERVICE_MARKERS)


def discover_services(root):
    """Sub-directories of root that look like services (same rules as scan-bulk).

    If root itself is a service (Dockerfile / compose at the top and no
    sub-directory with its own), it is returned as the only service."""
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
    if _has_marker(root) and not any(_has_marker(p) for _, p in out):
        return [(os.path.basename(os.path.normpath(root)) or "service", root)]
    return out


PORT_FILE = re.compile(r"(?i)^(\.env.*|.*\.env|(docker-)?compose.*\.ya?ml|.*dockerfile.*|xinetd.*|"
                       r".*\.conf|.*\.ini|.*\.toml|entrypoint.*\.sh|start.*\.sh|run.*\.sh)$")
PORT_PATTERNS = [
    r"(?im)^\s*(?:export\s+)?[\w.]*port\w*\s*[=:]\s*['\"]?(\d{2,5})['\"]?\s*$",  # PORT=9000, port: 80
    r"(?im)^\s*port\s*=\s*(\d{2,5})",                                            # xinetd
    r"(?im)\bpublished:\s*['\"]?(\d{2,5})",                                      # compose long syntax
    r"(?im)\btarget:\s*(\d{2,5})\s*$",
    r"(?m)^\s*-\s*['\"]?(?:[\d.]+:)?(\d{2,5})(?:/(?:tcp|udp))?['\"]?\s*$",      # - "8080"
    r"(?i)TCP\d?-LISTEN:(\d{2,5})",                                              # socat
    r"(?im)^\s*listen\s+(?:[\w.\[\]:]+:)?(\d{2,5})\b",                           # nginx
    r"--port[= ](\d{2,5})\b",
]


def service_ports(root):
    """Ports the services declare anywhere near their deployment files:
    .env / compose (short and long syntax, ${VAR:-default}), Dockerfile
    EXPOSE, xinetd / socat / nginx, --port flags."""
    ports = set()
    files_to_read = []
    if root and os.path.isdir(root):
        # top-level files of the services directory (one compose for all services)
        files_to_read += [os.path.join(root, f) for f in os.listdir(root)
                          if PORT_FILE.match(f) and os.path.isfile(os.path.join(root, f))]
    for _, path in discover_services(root):
        base_depth = path.rstrip(os.sep).count(os.sep)
        for cur, dirs, files in os.walk(path):
            dirs[:] = [d for d in dirs if not d.startswith(".") and d not in SKIP_DIRS
                       and cur.count(os.sep) - base_depth < 2]
            files_to_read += [os.path.join(cur, f) for f in files if PORT_FILE.match(f)]
    for fpath in sorted(set(files_to_read)):
        try:
            if os.path.getsize(fpath) > 256 * 1024:
                continue
            with open(fpath, encoding="utf-8", errors="replace") as fh:
                text = fh.read()
        except OSError:
            continue
        for pat in PORT_PATTERNS:
            ports.update(int(p) for p in re.findall(pat, text))
        for line in re.findall(r"(?im)^\s*EXPOSE\s+(.+)$", text):
            ports.update(int(p) for p in re.findall(r"\b(\d{2,5})\b", line))
        # "8080:80", "127.0.0.1:8080:80", "${SERVICE_PORT:-9000}:${SERVICE_PORT:-9000}"
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


def remote_host(url):
    """Group key for a remote: user@host for ssh/https remotes, 'local' for paths."""
    if "://" in url:
        p = urllib.parse.urlparse(url)
        netloc = p.netloc
        if p.scheme in ("http", "https"):
            netloc = netloc.rsplit("@", 1)[-1]  # never show embedded credentials
        return netloc or "local"
    m = re.match(r"^([\w.-]+@)?([\w.-]+|\[[0-9A-Fa-f:]+\]):(?!//)", url)  # scp-like user@host:path
    if m and not re.match(r"^[A-Za-z]:[\\/]", url):
        return (m.group(1) or "") + m.group(2)
    return "local"


# (substring in git/ssh output, kind, short error, hint)
GIT_ERRORS = [
    ("UNPROTECTED PRIVATE KEY FILE", "key_perms", "ssh refused the key: permissions too open",
     "chmod 600 the key (a key under /mnt/c cannot be chmod'ed: copy it to ~/.ssh first)"),
    ("bad permissions", "key_perms", "ssh refused the key: bad permissions",
     "chmod 600 the key (a key under /mnt/c cannot be chmod'ed: copy it to ~/.ssh first)"),
    ("Load key", "key_invalid", "the SSH key file could not be loaded",
     "check the key file (full BEGIN/END block, LF line endings, no passphrase)"),
    ("Permission denied", "auth", "authentication refused (publickey/password)",
     "set 'SSH key for git' in Settings to the vulnbox key (chmod 600)"),
    ("Host key verification failed", "hostkey", "host key verification failed",
     "the vulnbox host key changed: remove the old entry with ssh-keygen -R <host>"),
    ("REMOTE HOST IDENTIFICATION HAS CHANGED", "hostkey", "host key changed",
     "the vulnbox host key changed: remove the old entry with ssh-keygen -R <host>"),
    ("Could not resolve hostname", "unreachable", "host name does not resolve",
     "check the remote URL / DNS"),
    ("Connection timed out", "unreachable", "connection timed out",
     "is the VPN up and the vulnbox reachable?"),
    ("No route to host", "unreachable", "no route to host", "is the VPN up?"),
    ("Network is unreachable", "unreachable", "network unreachable", "is the VPN up?"),
    ("Connection refused", "unreachable", "connection refused (sshd down / wrong port)",
     "check that sshd runs on the vulnbox"),
    ("timed out after", "unreachable", "no answer from the remote", "is the VPN up and the vulnbox reachable?"),
    ("does not appear to be a git repository", "repo", "remote path is not a git repository",
     "run the backup script once to create the repos on the vulnbox"),
    ("detected dubious ownership", "ownership", "repository owned by another user (git safe.directory)",
     "run the dashboard as the owner of the services, or chown them to this user"),
    ("could not read Username", "auth", "HTTPS remote needs credentials",
     "use an SSH remote with the key in Settings, or a git credential helper / token for HTTPS"),
    ("Authentication failed", "auth", "HTTPS authentication failed",
     "check the token / credential helper for this remote"),
    ("Repository not found", "repo", "repository not found (or no access)",
     "check the remote URL and that the key / token can read it"),
    ("terminal prompts disabled", "auth", "remote asked for a username/password",
     "use an SSH remote with the key in Settings, or a git credential helper"),
]


def classify_git_error(out):
    for needle, kind, error, hint in GIT_ERRORS:
        if needle in out:
            return kind, error, hint
    lines = [ln for ln in out.splitlines() if ln.strip() and not ln.startswith("Warning: Permanently added")]
    return "other", (" | ".join(lines) or "git failed")[:200], ""


def check_git_access(root, ssh_key):
    """One `git ls-remote` per remote host (not per service) to find auth /
    network problems before pulling."""
    hosts, no_git, no_remote = {}, [], []
    for name, path in discover_services(root):
        if not os.path.isdir(os.path.join(path, ".git")):
            no_git.append(name)
            continue
        rc, url = run(["git", "-C", path, "remote", "get-url", "origin"], timeout=10)
        if rc != 0 and "dubious ownership" in url:
            hosts.setdefault("(local repository ownership)", []).append((name, path))
            continue
        if rc != 0 or not url:
            no_remote.append(name)
            continue
        hosts.setdefault(remote_host(url), []).append((name, path))
    env = git_env(ssh_key)
    result = []
    for host, items in sorted(hosts.items()):
        rc, out = run(["git", "-C", items[0][1], "ls-remote", "--heads", "origin"], env=env, timeout=25)
        entry = {"host": host, "services": [n for n, _ in items], "ok": rc == 0,
                 "kind": "", "error": "", "hint": ""}
        if rc != 0:
            entry["kind"], entry["error"], entry["hint"] = classify_git_error(out)
        result.append(entry)
    failed = [h for h in result if not h["ok"]]
    state = "none" if not result else "ok" if not failed else "failed" if len(failed) == len(result) else "partial"
    return {"state": state, "checked": now(), "hosts": result, "no_git": no_git, "no_remote": no_remote,
            "ssh_key": ssh_key}


class GitAccess:
    """Background git access check, refreshed on start / settings change / pull."""

    def __init__(self, store):
        self.store = store
        self.lock = threading.Lock()
        self.result = {"state": "none"}
        self.running = False
        self.again = False

    def view(self):
        return dict(self.result, running=self.running)

    def set(self, result):
        self.result = result
        with self.store.lock:
            self.store.state["version"] += 1

    def trigger(self):
        with self.lock:
            if self.running:
                self.again = True
                return
            self.running = True
        threading.Thread(target=self._loop, daemon=True).start()

    def _loop(self):
        while True:
            s = dict(self.store.state["settings"])
            try:
                res = check_git_access(s["root"], s["ssh_key"]) if s["root"] else {"state": "none"}
            except Exception as e:  # never kill the server for a check
                res = {"state": "failed", "checked": now(), "hosts": [], "no_git": [], "no_remote": [],
                       "error": str(e)}
            with self.lock:
                if not self.again:
                    self.running = False
                    self.set(res)
                    return
                self.again = False


def pull_service(path, branch, ssh_key):
    """Fast-forward the service to origin/<branch>. Never switches branches
    and never discards local patches. Returns (state, message)."""
    if not os.path.isdir(os.path.join(path, ".git")):
        return "skipped", "not a git repository"
    env = git_env(ssh_key)
    rc, out = run(["git", "-C", path, "fetch", "--prune", "origin"], env=env, timeout=90)
    if rc != 0:
        _, error, hint = classify_git_error(out)
        return "failed", "git fetch failed: " + error + (f" -> {hint}" if hint else "")
    target = branch
    rc, _ = run(["git", "-C", path, "rev-parse", "--verify", "--quiet", f"origin/{target}"])
    fallback = ""
    if rc != 0:
        # the remote has no <branch> (e.g. vulnbox repos use master): use its
        # default branch, then main/master, then what the current branch
        # tracks, then the remote's only branch (trunk, develop, ...)
        rc, ref = run(["git", "-C", path, "symbolic-ref", "--short", "refs/remotes/origin/HEAD"])
        candidates = ([ref.split("/", 1)[1]] if rc == 0 and "/" in ref else []) + ["main", "master"]
        rc, up = run(["git", "-C", path, "rev-parse", "--abbrev-ref", "--symbolic-full-name", "@{upstream}"])
        if rc == 0 and up.startswith("origin/"):
            candidates.append(up.split("/", 1)[1])
        _, refs = run(["git", "-C", path, "for-each-ref", "--format=%(refname:short)", "refs/remotes/origin"])
        remote_branches = [r.split("/", 1)[1] for r in refs.splitlines() if "/" in r and r != "origin/HEAD"]
        if len(remote_branches) == 1:
            candidates.append(remote_branches[0])
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
    def __init__(self, store, access):
        self.store = store
        self.access = access
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
        for name, _ in services:
            self.step(name, "pull", "queued")

        # preflight: one connection per remote host instead of N identical failures
        self.log("checking git access to the remotes...")
        access = check_git_access(s["root"], s["ssh_key"])
        self.access.set(access)
        blocked = {}
        for h in access["hosts"]:
            if h["ok"]:
                self.log(f"git access to {h['host']}: ok ({len(h['services'])} service(s))")
                continue
            msg = f"{h['host']}: {h['error']}" + (f" -> {h['hint']}" if h["hint"] else "")
            self.log("git access FAILED, not pulling " + ", ".join(h["services"]) + ": " + msg)
            for n in h["services"]:
                blocked[n] = msg
        for n in access["no_remote"]:
            blocked[n] = "no 'origin' remote"
        for n, msg in blocked.items():
            self.step(n, "pull", "failed", msg)
        services = [(n, p) for n, p in services if n not in blocked]
        self.log(f"pulling {len(services)} service(s) from origin/{s['branch']}")

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
                    "gitAccess": self.jobs.access.view(),
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
                if k:
                    k = os.path.abspath(k)
                    if not os.access(k, os.R_OK):
                        raise ValueError(f"ssh key not readable by this user: {k}")
                    mode = os.stat(k).st_mode & 0o777
                    if mode & 0o077:
                        hint = (" Files under /mnt/c cannot be chmod'ed: copy it to ~/.ssh first."
                                if k.startswith("/mnt/") else "")
                        raise ValueError(f"ssh key permissions {oct(mode)} are too open, ssh will refuse it: "
                                         f"run chmod 600 {k}.{hint}")
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
                old = st.state["settings"]
                st.state["settings"] = new
                st.save()
            if (old["root"], old["ssh_key"]) != (new["root"], new["ssh_key"]):
                self.jobs.access.trigger()
            return {"settings": new, "services": [n for n, _ in discover_services(new["root"])]}

        if path == "/api/git-check":
            self.jobs.access.trigger()
            return {"gitAccess": self.jobs.access.view()}

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
    ap.add_argument("--port", type=int, default=None,
                    help=f"default {DEFAULT_PORT}, or the next free port not used by the services")
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
    if args.port is not None and args.port in used:
        sys.exit(f"[!] port {args.port} is reserved or used by a service "
                 f"({', '.join(map(str, sorted(used)))}); pick another with --port")

    token = args.token
    if not token and not is_loopback(args.host):
        token = secrets.token_urlsafe(18)
    access = GitAccess(store)
    Handler.store, Handler.jobs, Handler.token = store, Jobs(store, access), token

    # explicit --port: that one or nothing. Default: 8765, else the next free
    # port that no service declares (another competition may use 8765)
    if args.port is not None:
        candidates = [args.port]
    else:
        candidates = [p for p in range(DEFAULT_PORT, DEFAULT_PORT + 200) if p not in used]
    httpd, error = None, None
    for port in candidates:
        try:
            httpd = http.server.ThreadingHTTPServer((args.host, port), Handler)
            break
        except OSError as e:
            error = e
    if httpd is None:
        sys.exit(f"[!] cannot listen on {args.host}:{candidates[0]}: {error}")
    args.port = httpd.server_address[1]
    if args.port != DEFAULT_PORT and len(candidates) > 1:
        print(f"[*] port {DEFAULT_PORT} is busy or used by a service, using {args.port}")
    if store.state["settings"]["root"]:
        access.trigger()  # detect missing SSH key / unreachable vulnbox right away
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
