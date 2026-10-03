#!/usr/bin/env python3
"""A&D findings dashboard.

Scan every service of a directory with the rule packs of this repository,
pull the latest service code from git, re-run the analysis, and track every
finding: label (patch in progress / patched in prod / false positive) and
patcher assignee.

    python3 webapp/server.py [--root ~/vulnbox/services] [--port 8765]
                             [--host 127.0.0.1] [--data DIR]
    python3 webapp/server.py --set-password      # change the login password

Only the Python standard library is used. State (settings, patchers,
labels) and scan output live in --data (default
~/.local/share/opengrep-dashboard), never inside the services.

Every page and API call requires a login (default user "patcher").
The default password is public (this repository is public): when the
dashboard is reachable from the network it must be changed at the first
login. The game network is hostile.
"""
import argparse
import concurrent.futures
import datetime
import getpass
import hashlib
import hmac
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
import time
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

DEFAULT_USER = "patcher"
DEFAULT_PASSWORD = "patcherspatching!"   # public: change it (--set-password or the UI)
PBKDF2_ITERS = 240000
MIN_PASSWORD = 10
SESSION_TTL = 12 * 3600                 # seconds, renewed on every request
SESSION_COOKIE = "ogdash_session"
LOGIN_MAX_FAILURES = 100                # failed logins per IP and window
LOGIN_WINDOW = 300                      # seconds

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


def hash_password(password, salt=None, iters=PBKDF2_ITERS):
    salt = salt or secrets.token_hex(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode(), bytes.fromhex(salt), iters).hex()
    return {"salt": salt, "iters": iters, "hash": digest}


def check_password(password, rec):
    digest = hashlib.pbkdf2_hmac("sha256", password.encode(), bytes.fromhex(rec["salt"]), rec["iters"]).hex()
    return hmac.compare_digest(digest, rec["hash"])


class Auth:
    """Login sessions (in memory: a restart logs everybody out) and a
    per-IP limit on failed logins."""

    def __init__(self, store):
        self.store = store
        self.lock = threading.Lock()
        self.sessions = {}      # sha256(token) -> {"user", "expires"}
        self.failures = {}      # ip -> [timestamps]

    def blocked(self, ip):
        with self.lock:
            cutoff = time.time() - LOGIN_WINDOW
            recent = [t for t in self.failures.get(ip, []) if t > cutoff]
            self.failures[ip] = recent
            return len(recent) >= LOGIN_MAX_FAILURES

    def login(self, ip, user, password):
        rec = self.store.state["accounts"].get(user)
        # always run PBKDF2, so a wrong user name takes as long as a wrong password
        ok = check_password(password, rec or self.store.state["accounts"][DEFAULT_USER]) and rec is not None
        if not ok:
            with self.lock:
                self.failures.setdefault(ip, []).append(time.time())
            return None
        token = secrets.token_urlsafe(32)
        with self.lock:
            self.failures.pop(ip, None)
            self.sessions[hashlib.sha256(token.encode()).hexdigest()] = {
                "user": user, "expires": time.time() + SESSION_TTL}
        return token

    def user(self, token):
        if not token:
            return None
        key = hashlib.sha256(token.encode()).hexdigest()
        with self.lock:
            sess = self.sessions.get(key)
            if not sess or sess["expires"] < time.time():
                self.sessions.pop(key, None)
                return None
            sess["expires"] = time.time() + SESSION_TTL
            return sess["user"]

    def logout(self, token):
        with self.lock:
            self.sessions.pop(hashlib.sha256((token or "").encode()).hexdigest(), None)

    def drop_user_sessions(self, user, keep=None):
        keep_key = hashlib.sha256(keep.encode()).hexdigest() if keep else None
        with self.lock:
            for k in [k for k, v in self.sessions.items() if v["user"] == user and k != keep_key]:
                del self.sessions[k]

    def is_default(self, user):
        return bool(self.store.state["accounts"].get(user, {}).get("default"))


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
        os.chmod(data_dir, 0o700)
        self.state_file = os.path.join(data_dir, "state.json")
        self.scan_file = os.path.join(data_dir, "last_scan.json")
        self.state = {"settings": dict(DEFAULT_SETTINGS), "patchers": list(DEFAULT_PATCHERS),
                      "labels": {}, "version": 0, "accounts": {}}
        loaded = self._read(self.state_file)
        if loaded:
            self.state["settings"].update(loaded.get("settings", {}))
            self.state["patchers"] = loaded.get("patchers") or list(DEFAULT_PATCHERS)
            self.state["labels"] = loaded.get("labels", {})
            self.state["version"] = loaded.get("version", 0)
            self.state["accounts"] = loaded.get("accounts", {})
        if DEFAULT_USER not in self.state["accounts"]:
            self.state["accounts"][DEFAULT_USER] = dict(hash_password(DEFAULT_PASSWORD), default=True)
            self._write(self.state_file, self.state)
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
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)  # holds password hashes
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
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
STATIC = {"/app.js": "app.js", "/style.css": "style.css", "/login.js": "login.js"}
PUBLIC_API = {"/api/login", "/api/logout", "/api/me"}
# allowed while the default password must still be changed
CHANGE_PW_API = PUBLIC_API | {"/api/password"}
CTYPES = {".html": "text/html; charset=utf-8", ".js": "text/javascript; charset=utf-8",
          ".css": "text/css; charset=utf-8"}


class Handler(http.server.BaseHTTPRequestHandler):
    server_version = "opengrep-dashboard"
    store = None
    jobs = None
    auth = None
    exposed = False   # reachable from the network (not bound to localhost)

    def log_message(self, fmt, *args):  # quieter console: only errors
        if args and str(args[1]).startswith(("4", "5")) and str(args[1]) not in ("401", "403"):
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
                         "default-src 'self'; style-src 'self'; script-src 'self'; img-src 'self' data:; "
                         "frame-ancestors 'none'; form-action 'self'")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Referrer-Policy", "no-referrer")
        for k, v in (extra or {}).items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(body)

    def session_token(self):
        for part in self.headers.get("Cookie", "").split(";"):
            k, _, v = part.strip().partition("=")
            if k == SESSION_COOKIE:
                return v
        return ""

    def current_user(self):
        return self.auth.user(self.session_token())

    def must_change_password(self, user):
        return self.exposed and self.auth.is_default(user)

    def gate(self, path):
        """None when the request may go on, else (code, body)."""
        if path in PUBLIC_API:
            return None
        user = self.current_user()
        if not user:
            return 401, {"error": "login required"}
        if path not in CHANGE_PW_API and self.must_change_password(user):
            return 403, {"error": "change the default password first", "mustChange": True}
        return None

    def cookie(self, token, max_age):
        return {"Set-Cookie": f"{SESSION_COOKIE}={token}; HttpOnly; SameSite=Strict; Path=/; Max-Age={max_age}"}

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
        if path in ("/", "/index.html", "/login"):
            page = "index.html" if self.current_user() else "login.html"
            with open(os.path.join(HERE, "static", page), "rb") as fh:
                return self.send(200, fh.read(), CTYPES[".html"])
        if path in STATIC:
            fname = os.path.join(HERE, "static", STATIC[path])
            with open(fname, "rb") as fh:
                return self.send(200, fh.read(), CTYPES[os.path.splitext(fname)[1]])
        if not path.startswith("/api/"):
            return self.send(404, {"error": "not found"})
        denied = self.gate(path)
        if denied:
            return self.send(*denied)
        st = self.store
        if path == "/api/me":
            user = self.current_user()
            return self.send(200, {"user": user, "defaultPassword": bool(user) and self.auth.is_default(user),
                                   "mustChange": bool(user) and self.must_change_password(user),
                                   "minPassword": MIN_PASSWORD})
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
        denied = self.gate(path)
        if denied:
            return self.send(*denied)
        try:
            data = self.body()
            if path == "/api/login":
                return self.login(data)
            if path == "/api/logout":
                self.auth.logout(self.session_token())
                return self.send(200, {"ok": True}, extra=self.cookie("", 0))
            return self.send(200, self.post(path, data))
        except LookupError as e:
            return self.send(404, {"error": str(e)})
        except ValueError as e:
            return self.send(400, {"error": str(e)})
        except RuntimeError as e:
            return self.send(409, {"error": str(e)})

    def login(self, data):
        ip = self.client_address[0]
        if self.auth.blocked(ip):
            return self.send(429, {"error": f"too many failed logins from {ip}, wait a few minutes"})
        user, password = str(data.get("user", "")).strip(), str(data.get("password", ""))
        token = self.auth.login(ip, user, password)
        if not token:
            print(f"[!] failed login for {user[:40]!r} from {ip}", file=sys.stderr, flush=True)
            return self.send(401, {"error": "wrong user or password"})
        return self.send(200, {"user": user, "mustChange": self.must_change_password(user)},
                         extra=self.cookie(token, SESSION_TTL))

    def post(self, path, data):
        st = self.store
        if path == "/api/password":
            user = self.current_user()
            current, new = str(data.get("current", "")), str(data.get("new", ""))
            rec = st.state["accounts"][user]
            if not check_password(current, rec):
                raise ValueError("current password is wrong")
            if len(new) < MIN_PASSWORD:
                raise ValueError(f"the new password needs at least {MIN_PASSWORD} characters")
            if new == DEFAULT_PASSWORD or check_password(new, rec):
                raise ValueError("choose a password different from the current / default one")
            with st.lock:
                st.state["accounts"][user] = hash_password(new)
                st.save()
            self.auth.drop_user_sessions(user, keep=self.session_token())  # log out other browsers
            return {"ok": True}
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
    ap.add_argument("--set-password", action="store_true",
                    help=f"set the password of the '{DEFAULT_USER}' login (asked on the terminal) and exit")
    args = ap.parse_args()

    store = Store(os.path.abspath(os.path.expanduser(args.data)))
    if args.set_password:
        pw = getpass.getpass(f"New password for '{DEFAULT_USER}': ")
        if len(pw) < MIN_PASSWORD or pw == DEFAULT_PASSWORD:
            sys.exit(f"[!] use at least {MIN_PASSWORD} characters, different from the default one")
        if getpass.getpass("Repeat it: ") != pw:
            sys.exit("[!] the passwords do not match")
        store.state["accounts"][DEFAULT_USER] = hash_password(pw)
        store.save()
        sys.exit(f"[*] password of '{DEFAULT_USER}' changed (restart the dashboard to log everybody out)")
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

    access = GitAccess(store)
    Handler.store, Handler.jobs, Handler.auth = store, Jobs(store, access), Auth(store)
    Handler.exposed = not is_loopback(args.host)

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
    print(f"[*] dashboard: http://{shown}:{args.port}/  (login: {DEFAULT_USER})", flush=True)
    if store.state["accounts"][DEFAULT_USER].get("default"):
        print("[!] the login still uses the DEFAULT password, which is public: change it in the UI or with "
              "--set-password" + (" (required at the first login: the dashboard is reachable from the network)"
                                   if Handler.exposed else ""), flush=True)
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
