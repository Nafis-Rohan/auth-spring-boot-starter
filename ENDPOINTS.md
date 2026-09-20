# Endpoints

Every URL this library exposes, grouped by feature, with what it does
and what headers/params it needs. `permitAll` means no authentication
needed to *reach* the endpoint (login endpoints obviously can't require
you to already be logged in).

## Session

| Endpoint | Method | Needs | Does |
|---|---|---|---|
| `/auth/login` | POST | `username`, `password` params, CSRF token | Logs in, creates a session cookie |
| `/auth/check` | GET | session cookie | Returns whether you're logged in (session-strategy only — see note below) |
| `/auth/logout` | POST | session cookie, CSRF token | Destroys the session |

> `/auth/check` only recognizes sessions created by this library's own
> `SessionAuthStrategy` — a WebAuthn or OAuth2 login won't show as
> "authenticated" here, even though it genuinely is. Use `/admin-only`
> or your own protected endpoint for a general auth check.

## JWT

| Endpoint | Method | Needs | Does |
|---|---|---|---|
| `/auth/jwt/check` | GET | `Authorization: Bearer <token>` | Validates the access token |
| `/auth/jwt/refresh` | POST | `X-Refresh-Token` header | Issues a new access token |
| `/auth/jwt/logout` | POST | **both** `Authorization: Bearer <access>` and `X-Refresh-Token` headers | Blacklists both tokens immediately — logout fails with 400 if the refresh token is missing or invalid |

Login for JWT goes through the unified endpoint below (or
`/auth/unified-login` with `unifyauth.strategy: jwt`). Access + refresh
tokens are returned in the `Authorization` and `X-Refresh-Token`
response headers.

## Unified login

| Endpoint | Method | Needs | Does |
|---|---|---|---|
| `/auth/unified-login` | POST | `username`, `password` params, CSRF token | Logs in using whichever strategy is set in `unifyauth.strategy` — session or JWT, same endpoint either way |

This is the actual intended login endpoint for Session/JWT — one URL,
config decides the mechanism underneath.

## OAuth2 / OIDC

| Endpoint | Method | Needs | Does |
|---|---|---|---|
| `/oauth2/authorization/google` | GET | nothing | Redirects to Google's real login page (built into Spring Security, not written by this library) |
| `/auth/oauth2/success` | GET | active OAuth2 session | Returns the logged-in Google user's profile attributes |
| `/auth/oidc/identity` | GET | active OIDC session | Returns decoded ID token claims — `sub`, `email`, `name`, `picture` |
| `/auth/oauth2/logout` | POST | active OAuth2 session | Clears the local session AND revokes the token at Google |

## WebAuthn (Passkeys)

| Endpoint | Method | Needs | Does |
|---|---|---|---|
| `/webauthn/register` | GET/POST | logged in (any method) | Registration page + endpoint for adding a passkey — built into Spring Security |
| `/login` | GET | nothing | Shows the login page, including "Sign in with a passkey" |

WebAuthn login/registration are Spring Security's native pages — this
library doesn't add custom endpoints, only the config (`webauthn.rp-id`,
`webauthn.allowed-origins`) that makes them work correctly.

## MFA / TOTP

| Endpoint | Method | Needs | Does |
|---|---|---|---|
| `/auth/mfa/enable` | POST | authenticated (any method), CSRF or Bearer token | Generates a secret + QR code for the current user |
| `/auth/mfa/verify` | POST | authenticated, `code` param | Checks a 6-digit code — 200 if valid, 401 if wrong, 400 if MFA was never enabled |

Compatible with any standard TOTP app (Google Authenticator, Authy).
`/auth/mfa/verify` is rate-limited (brute-forceable 6-digit code).

## Other

| Endpoint | Method | Needs | Does |
|---|---|---|---|
| `/auth/csrf-token` | GET | nothing | Returns a fresh CSRF token, both as a cookie and in the response body |

## CSRF — when you need a token

- **Cookie-based requests** (Session login, MFA, OAuth2 logout) — need
  a CSRF token in the `X-XSRF-TOKEN` header, fetched from
  `/auth/csrf-token` first
- **Requests carrying a valid `Authorization: Bearer` token** — exempt
  from CSRF entirely, regardless of which endpoint, since JWT isn't
  vulnerable to CSRF (checked by actually validating the token, not
  just checking the header exists)

## Demo / test-only endpoints (disabled by default)

Only exist if `unifyauth.demo-endpoints.enabled: true` — **never enable
in production**, these exist purely to demonstrate RBAC/ownership
checks.

| Endpoint | Method | Does |
|---|---|---|
| `/protected-test` | GET | Returns success for any authenticated user, regardless of strategy |
| `/admin-only` | GET | Requires `ROLE_ADMIN` — 403 for anyone else |
| `/my-resource/{username}` | GET | Only the matching authenticated user can access their own `{username}` path — 403 for anyone else (BOLA-prevention example) |

## Testing-only configuration (disabled by default)

```yaml
unifyauth:
  test-user:
    enabled: true     # adds in-memory nafis/password + admin/adminpass users
  form-login:
    enabled: true      # enables Spring's default username/password login page
  demo-endpoints:
    enabled: true       # exposes the 3 demo endpoints above
```
