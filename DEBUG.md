# Debug Log

---

### 1. Session ID never rotated on login (session fixation)

**Problem:** logging in reused whatever session ID already existed,
instead of issuing a fresh one.
**Risk:** an attacker who plants a known session ID on a victim's
browser, then waits for them to log in, ends up with a session ID that's
now "authenticated" too.
**Fix:** one line — `request.changeSessionId()` right after login.

### 2. Session login worked, but only for `/auth/**` — nowhere else

**Problem:** `SessionAuthStrategy` correctly tracked login state, but
nothing told _Spring Security's own_ authentication system about it —
so any endpoint outside the test routes still treated a logged-in user
as anonymous.
**Fix:** a custom filter (`SessionAuthFilter`) that checks the session
on every request and populates Spring Security's `SecurityContext`
directly — the actual bridge between "my code thinks you're logged in"
and "Spring Security thinks you're logged in."

### 3. An access token could be used as a refresh token

**Problem:** access and refresh tokens were structurally identical JWTs
— nothing distinguished them. A stolen short-lived access token could
be submitted to the refresh endpoint and used to mint new access tokens
indefinitely.
**Fix:** added a `type` claim (`access`/`refresh`) to every signed
token; refresh explicitly checks it, not just general validity.

### 4. JWT logout blacklisted the access token, but not the refresh token

**Problem:** logout only revoked whichever token(s) were explicitly
sent — a client sending only the access token left the refresh token
fully alive.
**Fix, after weighing two approaches:** considered auto-tracking each
user's refresh token so logout could find it even if not sent;
ultimately decided the simpler, more honest fix was to _require_ the
refresh token on logout, rejecting the request with a clear error if
missing — no new server-side state needed.

### 5. Library packaged as a runnable app, not a library

**Problem:** built the jar, imported it into a genuinely separate test
project — it failed immediately with a `FileNotFoundException` looking
for a class that definitely existed in the jar.
**Why:** `spring-boot-maven-plugin` was repackaging into an executable
"fat jar," nesting all classes under `BOOT-INF/classes/` instead of the
jar's root — invisible from inside the library's own project, only
detectable by actually consuming the built artifact from outside.
**Fix:** `<skip>true</skip>` on the plugin, disabling the repackage
step.

### 6. Every strategy class was invisible to an external consumer

**Problem:** `SessionAuthStrategy`, `JwtAuthStrategy`, and others were
all `@Component`-annotated — which only gets discovered by scanning the
_consuming_ application's own package. A separate project in a
different package never found any of them.
**Fix:** removed `@Component`, registered each explicitly as a `@Bean`
inside the library's `@AutoConfiguration` class — works regardless of
the consumer's package structure.

### 7. OAuth2 was mandatory for every consumer, even ones who didn't want it

**Problem:** the OAuth2 strategy bean, the security filter chain, and a
supporting resolver bean all unconditionally required
`ClientRegistrationRepository` — a consumer using only JWT or Session
would be forced to configure Google credentials just for the app to
start.
**Fix:** `@ConditionalOnBean`/`@Autowired(required = false)` throughout
— OAuth2 wiring only activates if OAuth2 is actually configured.

### 8. `@ConditionalOnBean` silently failed — wrong base annotation

**Problem:** even with real Google credentials configured, the
conditional OAuth2 beans still failed to activate.
**Why:** `SecurityConfig` was `@Configuration`, not `@AutoConfiguration`
— only the latter participates in Spring Boot's deferred, ordered
processing that `@ConditionalOnBean` actually relies on to evaluate
correctly against other auto-configurations (like Spring's own OAuth2
client setup).
**Fix:** one annotation change — `@Configuration` → `@AutoConfiguration`.
**Why it stayed hidden so long:** every earlier test of the conditional
logic used a project _without_ real OAuth2 credentials, so the
condition happened to resolve correctly by coincidence (nothing to find)
rather than by the ordering actually working.

### 9. A duplicate, unbound config bean silently shadowed the real one

**Problem:** `@EnableConfigurationProperties` already creates a
correctly YAML-bound `AuthProperties` bean — but a second, manual `@Bean`
method also existed, returning a plain, unbound `new AuthProperties()`.
With both present, the wrong one sometimes won, meaning
`unifyauth.strategy: jwt` in config was silently ignored.
**Fix:** deleted the manual bean entirely, trusting
`@EnableConfigurationProperties` to do its one job.

### 10. MFA/RBAC endpoints returned 200 OK even when the request failed

**Problem (found twice, same pattern):** an ownership-check endpoint
and MFA's code-verification endpoint both returned plain `String`
values — Spring defaults any returned `String` to a real `200 OK`,
regardless of whether the _text_ said "denied" or "invalid."
**Risk:** a human reads the message and understands it failed; any real
API client checking `response.status` sees success.
**Fix:** switched both to `ResponseEntity<String>` with the actual
correct status code (`403`, `401`) attached.

### 11. A "fixed" bug's fix had three of its own bugs

**Problem:** the fix for OAuth2 logout not revoking Google tokens
introduced: (1) local cleanup could be skipped entirely if the
revocation call failed, since the ordering ran the risky part before
the guaranteed part; (2) the access token was concatenated directly
into a URL, corrupting it if it ever contained reserved characters; (3)
the response always claimed success even when revocation silently
failed.
**Fix:** moved cleanup into a `finally` block so it always runs;
switched to proper URL-parameter encoding; made the method return
`boolean` so the caller reports the real outcome.
**Lesson:** a fix isn't automatically correct just because it solves
the original problem — review it with the same scrutiny as anything
else.

### 12. A library shouldn't require config for a feature nobody's using

**Problem:** `webauthn.rp-id`/`webauthn.allowed-origins` had no
defaults — every consumer was forced to set them, even ones with zero
interest in WebAuthn.
**Fix:** sensible fallback defaults (`localhost`,
`http://localhost:8080`) — fully overridable, no longer mandatory.

### 13. A demo/test controller shipped to every production consumer

**Problem:** `TestController` (with `/admin-only`, `/protected-test`)
was registered as a permanent, unconditional bean to help this
project's own testing — meaning every real consumer, including
production deployments, got these endpoints exposed too.
**Found by:** automated code review, not manual testing.
**Fix:** gated behind the same explicit opt-in flag as the fake
in-memory test user — off by default.

### 14. A global exception handler caught the consumer's own exceptions

**Problem:** the library's `@RestControllerAdvice` applied across the
_entire_ consuming application — any `IllegalArgumentException` thrown
anywhere in the consumer's own code got silently intercepted and turned
into a generic library error message, overriding their own handling.
**Fix:** scoped the advice to only the library's own controller
(`assignableTypes = { AuthController.class }`).

### 15. API endpoints silently became HTML login redirects

**Problem:** unauthenticated/unauthorized requests to protected
endpoints returned `200 OK` with an HTML login page instead of a clean
`401`/`403` — invisible in Postman by default, since it silently
follows redirects and shows the final page's status.
**Fix:** a custom `AuthenticationEntryPoint`/`AccessDeniedHandler`
writing the response directly (`response.setStatus()` +
`getWriter().write()`) instead of using `sendError()`, which was
triggering Spring Boot's internal error-page forward — itself subject
to the same redirect behavior.
