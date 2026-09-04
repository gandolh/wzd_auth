# Task 04 — Introspection and grant resolution

## Context

This is the endpoint every app calls on every request, and it is what makes
revocation work at all:
[apps ask Ward whether a session is live](../../wiki/decisions-tokens.md#apps-ask-ward-whether-a-session-is-still-live-and-cache-the-answer-briefly).
Revoking becomes one write, and every app stops honouring the session within its
cache window — instead of six denylists to synchronize.

## Files you OWN

- `api/src/routes/introspect.ts`
- `api/src/grants/resolve.ts`

## Files you must NOT touch

`api/src/tokens/**` (brief 02), `api/src/routes/auth.ts` (brief 03), the grant
*management* routes (brief 05 — this brief only reads).

## What to do

1. **`POST /introspect`** — takes the access token (from the cookie or an
   explicit body field for server-to-server use) and answers:
   `{ active, subject, username, grants: { atrium: ["admin"], … } }`.
2. **`active` is false** when the account is disabled, or the session's refresh
   family has been revoked, or the token is expired or unverifiable. One code
   path, so there is one answer to "is this live".
3. **Grants ride in the response, not in the token.** A permission change must
   land in the same window a revocation does. This is the whole reason the
   endpoint returns more than a boolean.
4. **This is a loopback call**, so it is allowed to be chatty — but it must be
   cheap: one indexed read for the session state, one for the grants. No N+1
   across six apps.
5. **Rate-limit it separately from `/login`**, or not at all — it is called
   constantly by trusted local services, and a lockout here would take the whole
   estate down.
6. Never return the password hash, the email, or anything the caller has no use
   for. Apps get identity and authority, nothing else.

## Acceptance

- A live session returns `active: true` with its grants; a revoked one returns
  `active: false` within the cache window and never leaks why.
- Disabling an account makes every app reject it on the next introspection —
  tested end to end, not just at the unit level.
- A grant added through the console appears in the next introspection response.
- Response shape contains no field an app cannot justify needing.

---

## Outcome — landed 2026-09-04

`POST /introspect` answering `{ active, subject, username, grants }`. All
acceptance criteria met, including the one brief 06 owed forward.

### Shape

Accepts the token from the `ward_session` cookie **or** an `accessToken` body
field for server-to-server callers; the cookie wins when both are present. There
is no `GET` variant — a token in a query string is written to disk by Fastify's
default request log on every request.

**Always `200`, always `cache-control: no-store`, exactly four fields.** The
response is filtered by a Fastify serialisation schema rather than by hand, so a
future change returning a whole `UserRow` still could not put `password_hash` or
`email` on the wire — there is a test that pushes a real row through the real
schema to prove it.

**Every failure is the identical body `{"active":false}`**, asserted
byte-for-byte across six causes. It never says which. There is deliberately **no
4xx for a credential problem**: an app forced to branch on 400-versus-200 gets it
wrong under load, and usually in the direction of treating an error as
authenticated. A `500` is still possible and is not swallowed — an unreadable
signing key is Ward being broken, not the session being dead, and answering
`active: false` there would sign the whole estate out silently instead of paging
someone.

**Three indexed point reads, no writes.** Auditing a call every app makes on
every request would turn `audit_log` into a write amplifier fed by ordinary
traffic. `grantsBySlug` returns the whole estate's authority for one person in
one read, so there is no N+1 across six apps.

### The revocation gap, found here and then closed

The brief was implemented honestly rather than optimistically, and that is what
surfaced the problem worth recording: **`jti` is never persisted and no claim
named the refresh family**, so a revoked family could not be linked to a
still-valid access token. What brief 04 implemented was the strongest sound
statement available at the time — *an account with no live refresh token has no
live session*. It also **rejected a half-fix** and wrote down why: refusing
tokens whose `iat` postdates the newest live refresh row catches about half the
orderings, rests on an invariant in a file it does not own, and fails by
spuriously signing a legitimate person out of six apps.

The controller then closed it properly with a **`sid` claim** carrying the
family id — see [decisions-implementation.md](../../wiki/decisions-implementation.md).
`resolveSession` now takes the session id and asks `hasLiveFamily`, so
per-device revocation works. The test that documented the gap was **inverted,
not deleted**; it is the regression guard for the change.

### Brief 06's owed test now lives here

> A superuser console token presented to `/introspect` returns `active: false`.

Nothing implements it, which is the point. A console token is `wcs_`+random with
one dot-separated segment where a compact JWS has three, so it fails
verification; and the superuser holds no row in `users` or `grants`. **There is
no `isSuperuser` branch in this file and there must never be one** —
[decisions-admin.md](../../wiki/decisions-admin.md) rejects it by name.

### Contract for dependents

```ts
export async function introspectRoutes(app, options?: { db?: Database.Database }): Promise<void>;
// grants/resolve.ts
export function resolveSession(db, subject, sessionId, now?): SessionResolution;
export function hasLiveFamily(db, familyId, subject, now?): boolean;   // family AND owner
export function hasLiveSession(db, subject, now?): boolean;            // account-scoped; NOT the introspection answer
```

**Caching contract for apps:** verify the signature locally first — that is
authentication and needs no call — then introspect for liveness and authority,
caching **per token, in-process, 30 seconds**. Ward caches nothing and sends
`no-store`, because this is a per-person authorisation answer that no HTTP cache
may hold. A signature stays valid for the full 15 minutes after revocation, so a
signature alone is never permission to proceed.

**No rate limit, and never a `429`.** Six apps call this on every request, every
one of them would read a `429` as "not live", and a lockout here signs the estate
out rather than degrading an attacker. It does not borrow brief 03's `"login"`
budget.
