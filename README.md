# auth-spring-boot-starter

A plug-in Spring Boot library that adds ready-made authentication and
security features to any Spring Boot app — just add it as a dependency
and turn features on with a few lines in `application.yml`. No copying
security code between projects, no rewriting login logic every time.

## What this actually does, in plain words

Most Spring Security tutorials show you _one_ way to log a user in.
This library gives you **six**, all built the same way, all switchable
by config:

- **Session (cookies)** — the classic way, server remembers you via a
  cookie
- **JWT** — a signed token the client keeps and sends back on every
  request, no server memory needed to check it
- **OAuth2 (Google)** — "Sign in with Google"
- **OIDC** — same as OAuth2, but also tells your app _who_ the person
  really is (email, name), not just that they're allowed in
- **WebAuthn (Passkeys)** — fingerprint/Face ID/security-key login, no
  password at all
- **MFA / TOTP** — the 6-digit code from Google Authenticator, as an
  extra step after any of the above

On top of that, it adds two things every real app needs regardless of
login method:

- **RBAC** — "only admins can see this page"
- **Rate limiting** — stops someone from guessing passwords thousands
  of times a minute

## How I actually built this

Ten days, one thing at a time — session cookies first, then JWT, then
OAuth2, OIDC, WebAuthn, MFA, RBAC, rate limiting, then a full day
wiring everything together behind config, then a final day of testing
and cleanup. Every day's code went through a real pull request, and
every PR was reviewed by an automated code review bot (Sourcery) before
merging — it caught real bugs almost every single day: security holes,
crashes on edge cases, wrong HTTP status codes, memory leaks. Every bug
found and every fix is written down in `DEBUG.md`.

## How I actually tested this

Building the code and clicking through it in my own project isn't
proof it works as a _library_ — it only proves it works inside itself.
So the real test was: build the actual `.jar` file, create a completely
separate, brand-new Spring Boot project that's never seen this code
before, add the jar as a normal dependency, and see if it works from
the outside. It didn't, at first — that one test uncovered seven real
bugs that had been invisible the whole time (see `DEBUG.md` for all of
them). After fixing those, I went further: built a real PostgreSQL
database with a real user table in that separate project, swapped it in
for the library's fake test user, and confirmed every login method
still worked correctly against real, independent data — no changes
needed to the library itself. That's the actual proof this is a real,
reusable library, not just working code.

## How a consumer (you) would use this

**Step 1 — add the dependency.**

```xml
<dependency>
    <groupId>io.github.nafisrohan</groupId>
    <artifactId>auth-spring-boot-starter</artifactId>
    <version>0.0.1-SNAPSHOT</version>
</dependency>
```

**Maven Central publishing is in progress** (namespace verification
pending) — once live, this block resolves directly, no extra setup.
Until then, install locally first with `mvn clean install -DskipTests`
in this repo, then the same coordinates resolve from your machine's
local Maven cache.

**Step 2 — tell it which login method to use.**

```yaml
unifyauth:
  strategy: jwt # or: session
```

**Step 3 — give it your own users.** The library never assumes where
your users come from — a database, a spreadsheet, whatever. You just
provide a normal Spring Security `UserDetailsService`:

```java
@Service
public class RealUserDetailsService implements UserDetailsService {
    // load a real user from wherever you keep them
}
```

**Step 4 — that's it.** `POST /auth/unified-login` (or the
protocol-specific endpoint) now checks real credentials, real password
hashes, and correctly rejects wrong passwords or unknown usernames.

**Want OAuth2, WebAuthn, or MFA too?** Same pattern — add a small
config block, nothing else. Full details, every endpoint, and every
config option are in `ENDPOINTS.md`.

## Read next

- **[`ENDPOINTS.md`](./ENDPOINTS.md)** — every URL this library exposes
  and what it does
- **[`DEBUG.md`](./DEBUG.md)** — the best real bugs found and fixed
  while building this

## Known limitations, stated honestly

- Sessions, the JWT logout blocklist, MFA secrets, and WebAuthn
  passkeys are stored in memory by default — fine for one server,
  won't survive a restart or scale to multiple servers. Swap in your
  own Redis/database-backed version if you need that.
- OAuth2/Google logins don't currently get mapped to your app's own
  roles (ADMIN/USER) — RBAC works for Session, JWT, and WebAuthn, not
  yet for OAuth2/OIDC.
- WebAuthn always results in a session right now — there's no option
  yet to say "log in with a passkey, but give me back a JWT."
- Refresh tokens aren't rotated on use.

None of these are secret — they're deliberate, documented trade-offs,
and every one of them is a genuine next step if you want to extend this
further.

## License

MIT — see [`LICENSE`](./LICENSE). Contributions welcome.
