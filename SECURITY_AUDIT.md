# Security Audit by ChatGPT 5.6 Luna on 22 July 

## Security Review

The existing client-side ownership checks are generally strong. The phase-6 authorization tests cover many ID-tampering cases, and I did not find a confirmed cross-user client API bypass in the tested routes.

However, there are several serious issues.

### Critical: Passwordless webmail login

[app.py:638](/Users/abdullah/Desktop/MangoPanel/mangopanel/app.py:638) allows:

```text
GET /webmail/login/{mailbox_id}
```

This loads the mailbox and redirects into webmail without requiring a password or authenticated session. Mailbox IDs are sequential, so an attacker may enumerate IDs and access mailboxes.

Fix:

- Remove this route entirely, or require a signed, short-lived, single-use launch token.
- Never authenticate based only on a mailbox ID.
- Add regression tests confirming `/webmail/login/{id}` returns `401` or `403` without a valid token.

### Critical: Admin roles are not enforced

`require_auth("admin")` only verifies that the account is an active admin. It does not check the admin’s role.

As a result, a `support_admin` can currently:

- Create another `super_admin`
- Reset any administrator’s password
- Disable administrator 2FA
- Delete customers
- Change plans and hosting accounts
- Modify DNS and registrar credentials
- Impersonate clients with `login-as`

Relevant code:

- [app.py:1406](/Users/abdullah/Desktop/MangoPanel/mangopanel/app.py:1406)
- [app.py:3467](/Users/abdullah/Desktop/MangoPanel/mangopanel/app.py:3467)
- [app.py:3494](/Users/abdullah/Desktop/MangoPanel/mangopanel/app.py:3494)
- [app.py:3550](/Users/abdullah/Desktop/MangoPanel/mangopanel/app.py:3550)

Fix:

- Add centralized permissions such as:
  - `admin.read`
  - `clients.manage`
  - `hosting.manage`
  - `dns.manage`
  - `billing.manage`
  - `admins.manage`
  - `impersonate`
- Enforce permissions on every admin route.
- Only `super_admin` should manage administrators, credentials, 2FA, and impersonation.
- Prevent an admin from deleting or disabling the last active super administrator.
- Add tests for every role against destructive routes.

### High: Session cookies lack `HttpOnly` and `Secure`

Cookies are created without protective flags:

[app.py:137](/Users/abdullah/Desktop/MangoPanel/mangopanel/app.py:137)

Current cookies use `SameSite=Lax`, but not:

```text
HttpOnly
Secure
```

Any JavaScript injection can steal the session cookie. `Secure` is also required in production to prevent transmission over plain HTTP.

Fix:

```text
HttpOnly; Secure; SameSite=Lax
```

Use `Secure` conditionally only for local HTTP development. Production should always require HTTPS.

### High: Login and TOTP endpoints need rate limiting

Password login and TOTP verification have no visible IP-, account-, or device-based rate limiting:

- [app.py:1308](/Users/abdullah/Desktop/MangoPanel/mangopanel/app.py:1308)
- [app.py:1343](/Users/abdullah/Desktop/MangoPanel/mangopanel/app.py:1343)

An attacker can repeatedly attempt user and admin credentials.

Fix:

- Rate-limit failed password attempts by IP and account.
- Rate-limit TOTP failures by account and IP.
- Add exponential backoff and temporary lockouts.
- Avoid exposing whether an email exists.
- Record and alert on repeated admin login failures.

### High: First-admin setup has a race condition

The first-admin endpoint checks the admin count and then inserts:

[app.py:1277](/Users/abdullah/Desktop/MangoPanel/mangopanel/app.py:1277)

Two concurrent requests can both observe zero admins and both create an administrator.

Fix:

- Use a transaction with an exclusive lock.
- Add a database-enforced singleton/setup-state constraint.
- Re-check the condition immediately before insertion.
- Disable the public setup endpoint once initialization begins.

### High: Git deployment allows untrusted repository schemes

User-controlled repository URLs are passed directly to Git:

[agent.py:1669](/Users/abdullah/Desktop/MangoPanel/mangopanel/agent.py:1669)

This can allow dangerous schemes such as:

```text
file://
ssh://
ext::
```

It may also allow access to internal network resources or local files through the agent.

Fix:

- Allow only `https://` Git URLs by default.
- Explicitly reject `file:`, `ssh:`, `git:`, `ext:`, local paths, and URLs resolving to private/link-local IPs.
- Validate branch names and reject values beginning with `-`.
- Run Git deployments in a network-restricted worker/container.
- Set Git environment restrictions such as disabling interactive prompts.

### High: Production transport security is externalized

The application serves plain HTTP directly through `ThreadingHTTPServer`. There is no application-level TLS enforcement.

Fix:

- Require HTTPS behind Caddy/Nginx/Traefik.
- Redirect HTTP to HTTPS.
- Add HSTS after HTTPS is confirmed.
- Validate forwarded headers only from trusted proxies.
- Do not construct login URLs from arbitrary `Host` or `X-Forwarded-Host` headers without an allowlist.

### Medium: Internal exception details are returned to clients

The global exception handler returns raw exception text:

[app.py:311](/Users/abdullah/Desktop/MangoPanel/mangopanel/app.py:311)

This can expose filesystem paths, SQL details, provider credentials embedded in exceptions, or infrastructure information.

Fix:

- Return a generic error and request ID to clients.
- Log full exceptions server-side.
- Never include raw provider/API errors in production responses.

### Medium: Admin impersonation tokens are exposed in URLs

The admin login-as flow places a user access token in a URL fragment:

[app.py:3581](/Users/abdullah/Desktop/MangoPanel/mangopanel/app.py:3581)

Fragments are not normally sent in HTTP requests, but they can remain in browser history, screenshots, logs, extensions, and analytics tooling.

Fix:

- Use a short-lived, single-use impersonation exchange token.
- Exchange it server-side and immediately remove it from the URL.
- Add explicit audit records and visible impersonation indicators.
- Require a dedicated `impersonate` permission.

### Medium: Sensitive credentials are stored reversibly

The project stores mailbox passwords and provider secrets reversibly using a custom XOR/HMAC construction:

[security.py:42](/Users/abdullah/Desktop/MangoPanel/mangopanel/security.py:42)

The MAC prevents undetected modification, but this is not a standard authenticated-encryption construction.

Fix:

- Replace it with AES-GCM or ChaCha20-Poly1305.
- Keep the encryption key outside SQLite and outside the repository.
- Support key rotation and versioned ciphertext.
- Prefer provider OAuth/token mechanisms that avoid storing passwords.

### Medium: Sensitive database credentials are stored in plaintext

Some database-related credentials appear to be stored as plaintext values, including PostgreSQL and FTP credentials. Examples include:

- [app.py:2013](/Users/abdullah/Desktop/MangoPanel/mangopanel/app.py:2013)
- [app.py:3065](/Users/abdullah/Desktop/MangoPanel/mangopanel/app.py:3065)

Fix:

- Store only password hashes when verification is required.
- Store encrypted secrets only when the system must recover the password.
- Never return passwords after creation.
- Rotate existing plaintext credentials during migration.

### Medium: New registrar routes need authorization regression tests

The new nameserver endpoints include ownership checks, for example:

[app.py:1643](/Users/abdullah/Desktop/MangoPanel/mangopanel/app.py:1643)

That is good, but they currently need explicit cross-user tests for:

- Client nameserver updates
- Website connection checks
- Registrar nameserver updates
- Domain export/rebuild actions
- Multi-hosting-account users

Add tests confirming another user receives `404` and that no registrar API call is made.

### Medium: Multi-account user boundary is ambiguous

`client_api()` automatically selects the first hosting account for the user:

[app.py:1422](/Users/abdullah/Desktop/MangoPanel/mangopanel/app.py:1422)

This does not currently expose another user’s account, but it creates a boundary problem for users who own multiple accounts. Requests cannot explicitly select an account, and actions may operate on the wrong account.

Fix:

- Require an explicit account context selected from accounts owned by the authenticated user.
- Validate every resource against both `user_id` and `account_id`.
- Never trust a client-provided account ID without ownership validation.

## Authorization Assessment

The following areas appear to use appropriate account ownership checks:

- Websites
- DNS records
- Databases
- PostgreSQL databases
- Mailboxes
- Backups
- Cron jobs
- Git deployments
- FTP accounts
- Protected directories
- Cache actions
- SSL custom certificates
- Analytics and PHP information

The existing `tests/test_security.py` and most of `tests/test_phase6_hardening.py` passed. One existing phase-6 test failed because a signup account remained in `provisioning` instead of becoming `active`; that is a provisioning behavior regression, not an authorization failure.

## Recommended Fix Order

1. Remove passwordless `/webmail/login/{mailbox_id}` access.
2. Implement admin RBAC and protect administrator/impersonation routes.
3. Add `HttpOnly`, `Secure`, and HTTPS enforcement.
4. Add login and TOTP rate limiting.
5. Fix first-admin setup race conditions.
6. Restrict Git repository URL schemes and network access.
7. Replace raw exception responses with request IDs.
8. Add cross-user tests for the newly added domain and connection endpoints.
9. Replace custom reversible encryption with standard authenticated encryption.
10. Add explicit multi-account context handling.
