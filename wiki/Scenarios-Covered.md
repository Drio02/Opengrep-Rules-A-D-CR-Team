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
| Native services | Stack overflows, format strings, UAF, off-by-one | `c/*.yaml` |
| Deployment | Redis/Postgres/Mongo published on 0.0.0.0 with default passwords; nginx alias traversal | `infra/*.yaml` |

### 3. New languages

- **C/C++**: native TCP daemons and CGI binaries are common in A&D.
- **C#**: ASP.NET Core services have appeared in recent European A&D events.
- **Java view layer**: JSP / Thymeleaf / FreeMarker templates (the original
  Java pack had no frontend rules).
- **Infra**: the vulnbox configuration itself.

## Not covered (yet)

Kotlin, Elixir, Haskell, Scala, Lua and other languages; business-logic bugs that need semantic
understanding (e.g. race conditions in balance transfers, crypto protocol
flaws); and binaries shipped without source.
