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

---

## Outcome — landed 2026-09-04

`POST /console/login` against the environment credential, plus a console session
that is deliberately not a JWT, and `console-guard.ts` for brief 05 to attach.
All acceptance criteria met except the one that cannot exist yet — see below.

### The property that matters, and why it holds structurally

A console token is `wcs_` + base64url random: **one** dot-separated segment
where a compact JWS has three, so `verifyWardAccessToken` rejects it as
`JWSInvalid`. It cannot accidentally satisfy an app's ordinary auth check
because it is not the same kind of thing. A reserved sentinel subject inside a
normal JWT was rejected precisely because that only works while all six apps
remember to reject it — it fails on discipline.

There is **no `isSuperuser` branch anywhere** in production code, confirmed by
review. "Console only" falls out of the superuser having no grants. Brief 04
needs no superuser case either, and adding one would be the bypass the decision
rejected.

Session state is an in-memory `Map` keyed on `sha256(token)`, capped at 16 with
least-recently-seen eviction — **no table**, so "the superuser has no row
anywhere" is literally true. 15-minute sliding idle timeout, 4-hour absolute
lifetime, both enforced.

### Review findings fixed

- **The break-glass credential shared its lockout budget with ordinary login.**
  Five wrong `/login` attempts from an address made a *correct* `/console/login`
  from that address return `429` — verified in both directions. On a one-operator
  estate behind a home NAT that is the same address, and it defeats the whole
  point: the superuser exists for when things are broken, **including when
  `/login` is under attack**. The failure budget is now partitioned per surface.
  Sharing the *address derivation* remains correct and deliberate.
- **`consoleCookieSecure()` failed open where its sibling fails closed.** It
  tested `startsWith("https:")`, dropping the loopback check its own comment
  claimed. `cookie.ts` deliberately keeps `Secure` for plain HTTP on a real
  hostname so the cookie breaks loudly rather than travelling in clear — so with
  `WARD_PUBLIC_ORIGIN=http://gandolh.ro` the session cookies failed closed while
  the **console** cookie, carrying the non-revocable credential, shipped without
  `Secure`. It now delegates to `cookie.ts`.
- `idleExpiresAt` was not clamped to the absolute deadline, so the console UI
  could promise time a dead session did not have. Enforcement was always right;
  only the reported value was wrong.

### Contracts for dependents

```ts
// auth/console-guard.ts — brief 05 attaches this
export function requireConsoleSession(req, reply): Promise<FastifyReply | undefined>;  // preHandler
export function getConsoleSession(req): ConsoleSession | undefined;
// api/src/routes/console.ts
export async function consoleRoutes(app, options?: { db?: Database.Database }): Promise<void>;
```

Attach with `app.addHook("preHandler", requireConsoleSession)` for a whole plugin
scope, or per route. `getConsoleSession` reads a module-private `WeakMap`, not a
request decorator — deliberately, so no `declare module "fastify"` augmentation
makes `request.consoleSession` visible and tempting in other briefs.

The guard's failure is `401 {"error":"unauthorized"}` with `cache-control:
no-store` and **no** `WWW-Authenticate`, byte-identical for missing, malformed,
unknown and expired.

**Cookie:** `ward_console`, `Path=/ward-api/console`, `HttpOnly`,
`SameSite=Strict` — stricter than the session cookie's `Lax` because nothing
legitimately navigates into the console, which closes CSRF at the cookie on a
surface where every route changes authority. No `Max-Age`: the server-side
sliding timeout is the only deadline, and two clocks would drift.

**Audit:** `console.login` (actor `superuser`, no subject), `console.login.failed`
(actor **`system`** — a wrong password proves nothing about who tried, and
attributing it would make the log claim an identity the request never
established), `console.logout`. The submitted username is deliberately never
recorded: there is one credential, so it says nothing, and a username field is
where a mistyped password lands.

**Rotating the password is an `.env` edit plus a restart, with deliberately no
UI.** A restart also drops every console session.

### One acceptance criterion is owed by brief 04

> *"A superuser console token presented to `/introspect` returns
> `active: false`"* — the brief's single most important test. `/introspect` did
> not exist in wave 3. Asserted **structurally** here instead (the token fails
> `verifyWardAccessToken`; the superuser holds no row in `users` or `grants`).
> **Brief 04 must add the end-to-end test.** There is nothing to implement for
> it — that is the point.
