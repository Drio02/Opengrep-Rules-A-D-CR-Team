# Patching Cheatsheet

Minimal, checker-safe fixes for the bug classes the rules report. The goal is
to **close the hole without changing behaviour for legitimate requests**, so
the SLA stays green.

General rules:

1. Fix the sink (parameterize, allowlist), not the input. Global input
   filters break checkers.
2. Keep response formats, status codes and field names identical.
3. Restart the service and test the normal flow (register, store flag, read
   flag) after every patch.
4. Commit every patch separately so it can be reverted in seconds.

---

## SQL injection (`*-sqli*`)

```python
cur.execute("SELECT * FROM notes WHERE id = ? AND owner = ?", (note_id, user_id))   # sqlite3 / ? style
cur.execute("SELECT * FROM notes WHERE id = %s", (note_id,))                        # psycopg / MySQLdb
```
```js
db.query("SELECT * FROM notes WHERE id = ?", [id]);           // mysql
pool.query("SELECT * FROM notes WHERE id = $1", [id]);        // pg
```
```php
$st = $pdo->prepare("SELECT * FROM notes WHERE id = ?"); $st->execute([$id]);
```
```go
db.Query("SELECT body FROM notes WHERE id = $1", id)
```
```java
PreparedStatement ps = conn.prepareStatement("SELECT * FROM notes WHERE id = ?"); ps.setString(1, id);
```
```ruby
Note.where("title LIKE ?", "%#{q}%")   # or Note.where(title: q)
```
```rust
sqlx::query("SELECT body FROM notes WHERE id = $1").bind(&id)
```
```csharp
_db.Notes.FromSqlInterpolated($"SELECT * FROM Notes WHERE Id = {id}")
```

`ORDER BY`, `LIMIT`, table and column names cannot be parameterized. Use an
allowlist:

```python
sort = {"date": "created_at", "title": "title"}.get(request.args.get("sort"), "created_at")
```

## NoSQL injection (`*-nosqli`)

Force the type before building the query:

```js
User.findOne({ username: String(req.body.username), password: String(req.body.password) })
```
```python
users.find_one({"username": str(data["username"])})
```

## Command injection (`*-command-injection`, `c-command-execution-dynamic`)

```python
subprocess.run(["ping", "-c", "1", host], timeout=5)              # no shell=True
```
```js
execFile("ping", ["-c", "1", host], cb)
```
```php
system("ping -c 1 " . escapeshellarg($host));
```
```go
exec.Command("ping", "-c", "1", host)                              // no "sh -c"
```
```ruby
system("ping", "-c", "1", host)
```

Also reject values that start with `-` (argument injection: `--output=/flag`).

## Path traversal / LFI (`*-path-traversal`, `*-file-inclusion`)

```python
name = os.path.basename(user_name)                                 # or werkzeug secure_filename
path = (BASE / name).resolve()
if not path.is_relative_to(BASE): abort(403)
```
```js
const p = path.resolve(BASE, name);
if (!p.startsWith(BASE + path.sep)) return res.sendStatus(403);
```
```php
$p = realpath(BASE . '/' . basename($name));
if ($p === false || strpos($p, BASE . '/') !== 0) { http_response_code(403); exit; }
```
```go
p := filepath.Join(base, filepath.Base(name))
```
nginx alias: `location /static/ { alias /srv/static/; }` (trailing slash on both).

## SSRF (`*-ssrf`)

Allowlist the scheme and the host. If arbitrary hosts are a feature, resolve
the name and reject loopback, private, link-local and the Docker network
ranges before connecting. Disable redirects.

## SSTI (`*-ssti`)

Render a **fixed** template and pass user data as variables:

```python
render_template_string("<h1>Hello {{ name }}</h1>", name=name)
```
```js
ejs.render("<h1><%= name %></h1>", { name })
```

## Deserialization (`*-deserialization`, `*-insecure-deserializer`)

Replace with JSON: `pickle` -> `json`, `yaml.load` -> `yaml.safe_load`,
`unserialize` -> `json_decode`, `Marshal.load` -> `JSON.parse`,
`BinaryFormatter` -> `System.Text.Json`, `ObjectInputStream` -> Jackson into a
fixed DTO. If the stored format must stay (existing flags!), deserialize with
a strict allowlist of classes (`unserialize($x, ['allowed_classes' => false])`,
a `pickle.Unpickler` subclass with `find_class`).

## Hardcoded secrets / JWT keys (`*-hardcoded-*`, `*-jwt-hardcoded-*`, `compose-hardcoded-app-secret`)

Replace the value with a new random one of the **same format**:

```bash
python3 -c "import secrets; print(secrets.token_hex(32))"
```

Then restart. Users' sessions are invalidated, but the checker logs in again.
Do not remove signature verification "to make it work".

## JWT verification (`*-jwt-*`)

- Always verify: `jwt.decode(t, key, algorithms=["HS256"])`,
  `jwt.verify(t, key, { algorithms: ["HS256"] })`.
- Go: check `err` **and** `token.Valid`, and pass
  `jwt.WithValidMethods([]string{"HS256"})`.
- Never `decode` without verifying for authorization decisions.

## Weak randomness (`*-weak-random-token`, `*-seed*`)

| Language | Use |
|---|---|
| Python | `secrets.token_hex(16)`, `secrets.randbelow(n)` |
| JS | `crypto.randomBytes(16).toString("hex")`, `crypto.randomUUID()` |
| PHP | `bin2hex(random_bytes(16))`, `random_int(a, b)` |
| Go | `crypto/rand` |
| Java | `SecureRandom` |
| Ruby | `SecureRandom.hex(16)` |
| Rust | `rand::rngs::OsRng`, `rand::thread_rng()` |
| C | `getrandom(buf, n, 0)` or read `/dev/urandom` |
| C# | `RandomNumberGenerator.GetBytes(16)` |

Keep the output length/charset the same if the checker validates the format.

## Comparisons (`*-timing-unsafe-*`, `php-in-array-loose`, `c-strncmp-attacker-length`)

```python
hmac.compare_digest(a, b)
```
```js
a.length === b.length && crypto.timingSafeEqual(Buffer.from(a), Buffer.from(b))
```
```php
hash_equals($known, (string)$given);  in_array($x, $list, true);
```
```c
if (strlen(in) != strlen(pw) || CRYPTO_memcmp(in, pw, strlen(pw)) != 0) fail();
```

## Mass assignment (`*-mass-assignment*`, `*-permit-sensitive-attribute`)

Copy explicit fields:

```python
user = User(username=data["username"], password=hash_pw(data["password"]))
```
```js
const { name, bio } = req.body; await User.create({ name, bio });
```
```ruby
params.require(:user).permit(:name, :email)        # remove :role, :admin, :user_id
```

## Missing auth / IDOR (`*-sensitive-route-without-*`, `*-idor-candidate`)

Add the decorator/middleware **and** an ownership check:

```python
note = Note.query.get_or_404(note_id)
if note.owner_id != current_user.id: abort(404)
```

PHP redirect without `exit` (`php-redirect-without-exit`): add `exit;` right
after `header("Location: ...")`.

## Client-controlled authorization (`*-cookie-based-authorization`, `*-ip-based-auth-spoofable`)

- Read identity and role from the server-side session or a signed token, not
  from a plain cookie.
- Use the socket address (`request.remote_addr`, `req.socket.remoteAddress`,
  `r.RemoteAddr`) instead of `X-Forwarded-For`. In nginx, set
  `proxy_set_header X-Real-IP $remote_addr;`.

## Debug modes (`*-debug-*`, `compose-debug-mode-enabled`)

Turn debug off: `app.run(debug=False)`, `DEBUG = False`, `NODE_ENV=production`,
remove `UseDeveloperExceptionPage()`, `set :show_exceptions, false`.

## Infra (`compose-*`, `dockerfile-*`)

```yaml
db:
  image: postgres:16
  environment:
    POSTGRES_PASSWORD: <new random>     # and update the app's DATABASE_URL
  # ports:                              # removed: the app reaches db over the compose network
  #   - "5432:5432"
```

Remove `privileged: true` and Docker socket mounts unless the service really
needs them (check the service still starts).

## C memory bugs (`c-*`)

| Finding | Patch |
|---|---|
| `c-gets` | `fgets(buf, sizeof buf, stdin)` and strip the newline |
| `c-unbounded-string-copy` | `snprintf(dst, sizeof dst, "%s", src)` |
| `c-scanf-unbounded-string` | `scanf("%63s", buf)` (size - 1) |
| `c-format-string` | `printf("%s", buf)` |
| `c-read-larger-than-buffer` | Use `sizeof(buf)` as the length |
| `c-off-by-one-null-terminator` | `buf[sizeof(buf) - 1] = 0` / `read(fd, buf, sizeof(buf) - 1)` |
| `c-use-after-free`, `c-double-free` | `free(p); p = NULL;` and check for NULL before use |
| `c-taint-size-or-index` | `if (idx < 0 \|\| idx >= COUNT) return;` |
