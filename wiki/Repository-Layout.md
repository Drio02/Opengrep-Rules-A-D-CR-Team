# Repository Layout

```
.
├── pyhton/           Python                (folder name keeps the original spelling)
├── js/               JavaScript / TypeScript (Node, React, Vue)
├── php/              PHP (plain, Laravel, Symfony)
├── go/               Go (net/http, gorilla, chi, gin, echo, fiber)
├── java/             Java (Spring, Servlet, JAX-RS, JSP/Thymeleaf/FreeMarker)
├── ruby/             Ruby (Rails, Sinatra)
├── rust/             Rust (axum, actix-web, rocket)
├── c/                C / C++                      (new)
├── csharp/           C# / ASP.NET Core            (new)
├── infra/            docker-compose, Dockerfile, nginx   (new)
├── tests/<pack>/     annotated fixtures for the rule files (new)
├── scripts/          scan / triage / test / catalog helpers (new)
└── wiki/             this documentation (new)
```

## Rule files inside a language pack

| File | Origin | Style | Content |
|---|---|---|---|
| `backend*.yaml` | original | syntactic | Server-side injection, crypto, TLS, IDOR candidates. Messages are in Spanish. |
| `frontend*.yaml` | original (Java: new) | syntactic / regex | XSS sinks, template escaping, open redirects, insecure cookies. |
| `extra.yaml` | original | syntactic | Cloud-metadata SSRF, ReDoS, GraphQL introspection, JWT `alg=none`, backdoor magic strings. |
| `<language>.yaml` (`python.yaml`, `go.yaml`, ...) | original | syntactic | Second-generation rules: archive extraction, request-bound inputs, panics/unwraps in handlers (DoS), unbounded `Content-Length`. Messages are in English. |
| `taint.yaml` | **new** | taint mode | Source -> sink dataflow from the web framework's request objects to SQL, shell, eval, filesystem, SSRF, templates, deserializers, redirects, regex... |
| `ad-logic.yaml` | **new** | syntactic | A&D-specific logic bugs: hardcoded session/JWT keys, weak or seeded PRNGs, timing-unsafe compares, mass assignment, cookie/IP-based authz, unauthenticated sensitive routes, debug consoles, language-specific traps. |
| `c/c.yaml`, `c/taint.yaml` | **new** | both | Memory corruption, format strings, UAF/double free, weak `rand()`, `strncmp(…, strlen(input))`. |
| `infra/*.yaml` | **new** | regex / dockerfile | Deployment misconfigurations of the vulnbox. |

The `(n)` suffix in some original file names (`backend(3).yaml`) comes from
browser downloads. Opengrep does not care about file names, so the files were
not renamed.

## Rule anatomy (new rules)

```yaml
- id: py-taint-sqli                 # <lang>-<kind>-<what>
  mode: taint                       # only for dataflow rules
  languages: [python]
  severity: ERROR                   # ERROR | WARNING | INFO
  message: >
    What is wrong, why it matters in A&D, and how to fix it.
  metadata:
    category: security
    cwe: CWE-89
    confidence: HIGH                # HIGH | MEDIUM | LOW (how often it is a true positive)
    ad-impact: flag-leak            # see below
  pattern-sources: [...]
  pattern-sanitizers: [...]
  pattern-sinks: [...]
```

### Severity vs confidence

- **severity** is how bad the bug is *if real*.
- **confidence** is how likely the match is to be real. LOW-confidence rules
  (e.g. `*-timing-unsafe-secret-compare`, `*-sensitive-route-without-*`) are
  pointers for reading, not proof.

### `ad-impact` values

Used by `scripts/triage.py` to rank findings:

| Value | Meaning in the game |
|---|---|
| `rce` | Code execution on the vulnbox: read all flags, possibly take the service down. |
| `flag-leak` | Direct read of stored data/flags (SQLi, LFI, SSRF to internal services, IDOR, debug leaks). |
| `auth-bypass` | Log in as / act as another user (the flag owner). |
| `session-theft` | Steal the checker's session (XSS, CORS). Usually needs the checker to visit a page. |
| `integrity` | Tamper with data or state (races, permissions). |
| `dos` | Take the service down. **Usually forbidden by the game rules**, but relevant for defense (SLA). |
| `phishing` | Open redirect. Rarely useful in A&D. Low priority. |

## Prefixes of rule IDs

| Prefix | Pack |
|---|---|
| `py-`, `python-`, `pyfe-` | Python |
| `js-`, `jsfe-` | JavaScript / TypeScript |
| `php-`, `phpfe-` | PHP |
| `go-`, `gofe-` | Go |
| `java-`, `javafe-` | Java |
| `ruby-`, `rubyfe-` | Ruby |
| `rust-`, `rust-fe-` | Rust |
| `c-` | C / C++ |
| `cs-` | C# |
| `compose-`, `dockerfile-`, `nginx-` | Infra |

`*-taint-*` means a taint rule. `fe` means frontend.

## tests/

`tests/<pack>/<rule-file-name>.<ext>` holds code samples with annotations:

```python
# ruleid: py-taint-sqli
cur.execute(query)           # this line MUST be reported
# ok: py-taint-sqli
cur.execute("... ?", (x,))   # this line must NOT be reported
```

`scripts/test-rules.sh` runs every fixture with `opengrep test`. See
the Opengrep docs on testing rules.

## scripts/

| Script | Purpose |
|---|---|
| `scan.sh` / `scan.ps1` | Scan a service with auto-detected packs and write `results.{txt,json,sarif}`, `triage.txt` and an HTML report. |
| `scan-bulk.sh` / `scan-bulk.ps1` | Scan every service of a directory or list file and build one combined HTML report. |
| `triage.py` | Rank an Opengrep JSON report by A&D impact and severity. |
| `report.py` | Build the self-contained HTML report from one or more scan output directories. |
| `test-rules.sh` | Validate every pack and run all fixtures. Exits non-zero on failure. |
| `gen-catalog.py` | Regenerate [Rule Catalog](Rule-Catalog.md) from the YAML files. |
