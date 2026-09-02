# Task 06 — The superuser and the console session

## Context

Read [decisions-admin.md](../../wiki/decisions-admin.md) in full before starting.
It defines **two** privileged identities that are not interchangeable, and
conflating them is the specific mistake that page exists to prevent.

The **superuser** is break-glass: it lives only in `.env`, has **no account
row**, no subject and no grants, and can reach the console and nothing else.
The **owner account** is an ordinary account with explicit admin grants — that
is what runs the apps, and it is created *through* the console (brief 05).

## Files you OWN

- `api/src/auth/superuser.ts` — the credential check and the console session
- `api/src/auth/console-guard.ts` — the gate brief 05's routes import

## Files you must NOT touch

`api/src/tokens/**` (brief 02 — the superuser session is **not** a JWT and must
not go near it), `api/src/routes/auth.ts` (brief 03), `api/src/db/**` (brief 01
— the superuser has no row and this brief creates none).

## What to do

1. **`POST /console/login`** — checks `WARD_ADMIN_USERNAME` /
   `WARD_ADMIN_PASSWORD` from the environment. Nothing is read from the
   database. Compare with `timingSafeEqual`, and apply brief 03's IP lockout.
2. **The session is a distinct console session and is never a JWT.** A separate
   opaque token in its own cookie scoped to `Path=/ward-api/console`, held in
   memory or its own table, with a short idle timeout.
   **This is the load-bearing part of the brief.** A reserved sentinel subject
   inside a normal JWT was rejected because it works only while all six apps
   remember to reject it — it fails on discipline. A session that is not a JWT
   cannot accidentally satisfy an app's ordinary auth check at all.
3. **No bypass.** The superuser gets no implicit grants and no special case in
   brief 04's introspection. "Console only" must fall out of it having no
   grants, not out of code that checks for it.
4. **Log every console login** — success and failure — to `audit_log`. This
   credential cannot be revoked or rotated without a redeploy, so the audit
   trail is the only observability it has.
5. `WARD_ADMIN_*` are **required outside development** and the service refuses
   to start without them (brief 00 validates this; assert the behaviour here).

## Acceptance

- A superuser console token presented to `/introspect` returns `active: false`.
  **This is the single most important test in the brief** — it proves the
  break-glass credential cannot open atrium.
- No row exists in `users` for the superuser after a console login.
- Console routes reject an ordinary account's access token, and app routes
  reject a console token. Both directions tested.
- Console login attempts appear in the audit log, including failures.
- Rotating the password is an `.env` edit plus a restart, and is documented as
  such — there is deliberately no UI for it.
