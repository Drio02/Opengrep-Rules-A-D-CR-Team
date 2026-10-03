# Scenarios Covered

## Coverage matrix

Legend: **●** covered by the original rules · **★** added in the ECSC 2026 work
· **●★** both (the new taint/logic rules extend the original ones) · **·** not
covered.

| Vulnerability class | Python | JS/TS | PHP | Go | Java | Ruby | Rust | C/C++ | C# | Infra |
|---|---|---|---|---|---|---|---|---|---|---|
| SQL injection | ●★ | ●★ | ●★ | ●★ | ●★ | ●★ | ●★ | · | ★ | · |
| NoSQL injection (Mongo operators) | ★ | ●★ | · | ★ | · | · | · | · | · | · |
| OS command injection | ●★ | ●★ | ●★ | ●★ | ●★ | ●★ | ●★ | ★ | ★ | · |
| Code injection / eval / expression languages | ●★ | ●★ | ●★ | · | ●★ | ●★ | ● | · | · | · |
| Path traversal / file inclusion | ●★ | ●★ | ●★ | ●★ | ●★ | ●★ | ●★ | · | ★ | ★ |
| SSRF | ●★ | ●★ | ●★ | ●★ | ●★ | ●★ | ●★ | · | ★ | ★ |
| Server-side template injection | ●★ | ★ | ★ | ★ | ★ | ★ | ★ | · | ★ | · |
| XSS | ● | ●★ | ●★ | ●★ | ★ | ●★ | ●★ | · | ★ | · |
| Insecure deserialization | ●★ | ●★ | ●★ | · | ●★ | ●★ | ● | · | ★ | · |
| XXE | ● | · | ●★ | ● | ● | · | ● | · | ★ | · |
| Open redirect | ●★ | ●★ | ●★ | ●★ | ★ | ●★ | ●★ | · | ★ | · |
| JWT verification / algorithm flaws | ● | ●★ | ● | ●★ | ● | ●★ | ●★ | · | ★ | · |
| Hardcoded secrets / signing keys | ●★ | ●★ | ●★ | ●★ | ★ | ●★ | ●★ | · | ★ | ★ |
| Weak / seeded randomness | ★ | ★ | ★ | ●★ | ●★ | ★ | ●★ | ★ | ★ | · |
| Timing-unsafe / loose comparisons | ★ | ★ | ●★ | ★ | ●★ | ★ | ★ | ★ | ★ | · |
| Mass assignment / variable overwrite | ★ | ★ | ●★ | ★ | ★ | ●★ | · | · | ★ | · |
| Missing authentication on sensitive routes | ★ | ★ | ★ (EAR) | · | ★ | ★ | · | · | · | · |
| IDOR candidates (lookup by id) | ● | ● | · | ● | ● | ● | ● | · | · | · |
| Client-controlled authz (cookie / X-Forwarded-For) | · | ★ | ★ | ★ | ★ | ★ | ★ | · | ★ | ★ |
| Prototype pollution | · | ●★ | · | · | · | · | · | · | · | · |
| ReDoS / regex injection | ●★ | ●★ | ●★ | ● | ● | ● | ● | · | · | · |
| Regex validation bypass (`$` + newline, line anchors) | · | · | ★ | · | · | ★ | · | · | · | · |
| Memory corruption / format strings | ★¹ | · | · | ★² | · | · | ★ | ★ | · | · |
| Debug consoles / info leaks | ●★ | ● | ●★ | ● | ●★ | ●★ | ● | · | ★ | ★ |
| TLS verification disabled | ● | ● | ● | ● | ● | ● | ● | · | ★ | · |
| Weak crypto / hashes | ● | ★ | ● | ● | ● | ● | · | · | · | · |
| Unrestricted file upload | · | · | ★ | · | · | · | · | · | · | · |
| Planted backdoors (magic strings) | ● | ● | ● | ● | ● | ● | ● | · | · | · |
| Exposed DB ports / default creds / privileged containers | · | · | · | · | · | · | · | · | · | ★ |

¹ Python `str.format` injection (format string leaking globals).
² Go `unsafe` / integer truncation.

---

## What the new rules add

### 1. Dataflow (taint) instead of one-line patterns

The original rules match a dangerous call only when the payload is built
**in the same expression**:

```python
cur.execute(f"SELECT * FROM users WHERE name = '{name}'")    # original rule: found
```

Most service code builds the value first:

```python
name = request.args.get("name")
q = "SELECT * FROM users WHERE name = '" + name + "'"
cur.execute(q)                                                 # original: missed, taint rule: found
```

The `taint.yaml` files model, for each framework:

- **Sources**: request parameters, bodies, headers, cookies, path params,
  framework extractors (`@RequestParam`, `Query<T>`, `c.Query()`, `params`,
  `$_GET`...).
- **Sanitizers**: integer parsing, `secure_filename`, `basename`,
  `escapeshellarg`, HTML encoders...
- **Sinks**: SQL, NoSQL, shell, eval, files, HTTP clients, template compilers,
  deserializers, redirects, regex, raw HTML responses.

### 2. A&D-specific logic bugs

These bugs show up again and again in A&D services, but generic SAST rule
sets rarely cover them:

| Scenario | Why it matters in A&D | Rules |
|---|---|---|
| Session/JWT secret in the source | Every team has the same source, so anyone can forge the flag owner's session | `*-hardcoded-*secret*`, `*-jwt-hardcoded-*`, `compose-hardcoded-app-secret` |
| Predictable tokens / IDs | Flag IDs, reset codes and session IDs can be regenerated | `*-weak-random-token`, `*-seed*`, `c-weak-rand-token`, `rust-predictable-rng` |
| Broken password checks | `bcrypt.compare` without `await`, `strncmp(in, pw, strlen(in))`, ignored `CompareHashAndPassword` | `js-password-compare-not-awaited`, `c-strncmp-attacker-length`, `go-password-compare-result-ignored` |
| JWT parsed but not verified | `token, _ := jwt.Parse(...)`, `JWT.decode(t, nil, false)`, `insecure_disable_signature_validation` | `go-jwt-parse-error-ignored`, `ruby-jwt-hardcoded-or-unverified`, `rust-jwt-insecure-validation`, `cs-jwt-validation-disabled` |
| Mass assignment | Register with `{"role":"admin"}` or move a note to the victim's account | `*-mass-assignment*`, `ruby-rails-permit-sensitive-attribute`, `java-spring-mass-assignment` |
| Client-controlled authorization | `cookie role=admin`, `X-Forwarded-For: 127.0.0.1` | `*-cookie-based-authorization`, `*-ip-based-auth-spoofable`, `nginx-internal-trusted-header` |
| Unauthenticated sensitive route | `/admin/flags` without a decorator/middleware; PHP redirect without `exit` | `*-sensitive-route-without-*`, `php-redirect-without-exit`, `java-spring-permitall-sensitive-path` |
| Language traps | PHP `in_array` without strict, PHP/Ruby `$` matching before a newline, Python `assert` stripped by `-O`, Java `==` on strings, Express query arrays | `php-in-array-loose`, `php-preg-match-dollar-allows-newline`, `ruby-regex-validation-line-anchors`, `py-assert-used-for-auth`, `java-string-reference-compare`, `js-type-confusion-query-array` |
| Framework RCE gadgets | `res.render(view, req.query)` (EJS), Thymeleaf view-name injection, Jackson default typing, Python `str.format` on user input | `js-res-render-user-options`, `java-spring-view-name-injection`, `java-jackson-polymorphic-typing`, `py-taint-format-string-injection` |
| Hand-rolled signatures | DSA verify without `0 < r,s < q` (r=1, s=0 verifies anything), nonce derived from the public key, "expected signature" in the login error | `py-crypto-dsa-verify-no-range-check`, `py-crypto-dsa-static-nonce`, `py-taint-signature-oracle` |
| Ownership never checked | `/profile/{user}` shows private data to any logged-in session (`if "user" in session`) | `py-idor-session-presence-only` |
| Native services | Stack overflows, format strings, UAF, off-by-one, `char c = fgetc()` vs `EOF`, `%02x` of a signed char | `c/*.yaml` |
| Deployment | Redis/Postgres/Mongo published on 0.0.0.0 with default passwords; nginx alias traversal | `infra/*.yaml` |

### 3. New languages

- **C/C++**: native TCP daemons and CGI binaries are common in A&D.
- **C#**: ASP.NET Core services have appeared in recent European A&D events.
- **Java view layer**: JSP / Thymeleaf / FreeMarker templates (the original
  Java pack had no frontend rules).
- **Infra**: the vulnbox configuration itself.

## Validation against demo A&D services

The rule packs were run with `scripts/scan.sh` against the Attacking-Lab demo
services (`demo-service-*`) and compared with the vulnerabilities documented
in each upstream repository. Every documented bug in a service that ships
source code is now reported:

| Service | Documented vulnerability | Rule | Location |
|---|---|---|---|
| fastvuln | `/backdoor` returns any user's profile without auth | `py-sensitive-route-without-auth` | `main.py:160` |
| fireworx | DSA verify accepts r = 1, s = 0 (mod q) | `py-crypto-dsa-verify-no-range-check` | `crypto.py:85` |
| fireworx | static nonce `k = H(y)` + expected signature leaked on login failure | `py-crypto-dsa-static-nonce`, `py-taint-signature-oracle` | `crypto.py:59`, `app.py:349` |
| fireworx | (not in the docs) `/profile/{username}` shows the private key to any logged-in user | `py-idor-session-presence-only` | `app.py:385` |
| stldoctor | `char c = fgetc(f)` compared with `EOF` (0xff truncates the model name, so the attacker controls the stored hash) | `c-char-eof-comparison` | `util.c:82` |
| stldoctor | `sprintf("%02x", signed char)` overflows the static hash buffer into `loggedin` | `c-sprintf-hex-signed-char` | `util.c:59` |
| stonksexchange | NoSQL injection: `{"$ne": null}` username stored in the session | `js-taint-nosqli` | `routes/index.js:63,85` |
| bambinotes | heap overflow: fixed-size `read()` into the smaller first note, then `note[n] = 0` | `c-off-by-one-null-terminator` (on the upstream source) | `bambi-notes.c:341` |

The same run was used to remove false positives:
- typed FastAPI parameters / `Depends()` values as NoSQL sources;
- `innerHTML = "literal"`;
- `vprintf(fmt, ap)` inside variadic wrappers and `#define`'d format strings;
- uses on a `goto` cleanup label after `return`;
- `buf[strlen(buf)-1]` behind a non-empty check;
- indexes checked by `VALID_*()` macros;
- cosmetic `random` calls.

Binary-only services (bambinotes ships only the ELF) cannot be analyzed by
opengrep; `scan.sh` / `scan.ps1` now print a warning instead of a silent
"0 findings".

## Not covered (yet)

Kotlin, Elixir, Haskell, Scala, Lua and other languages; business-logic bugs that need semantic
understanding (e.g. race conditions in balance transfers, most crypto protocol
flaws beyond the hand-rolled DSA checks); and binaries shipped without source.
