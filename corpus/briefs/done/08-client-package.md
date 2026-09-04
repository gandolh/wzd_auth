# Task 08 — The `@ward/client` package

## Context

Six apps have to do the same three things: verify the access token locally, ask
Ward whether the session is live and what it may do, and cache that answer for
30 seconds. **Written once here, or written wrong six times.** Ward exists to
delete copies of auth, and this package is where that promise is kept.

The two lifetimes are locked:
[15-minute access token, 30-second introspection cache](../../wiki/decisions-tokens.md).
The 30 seconds is the number that matters — it is what a revocation waits on.

## Files you OWN

- `client/**` — the whole workspace

## Files you must NOT touch

Anything in `api/`. Any consuming app (briefs 12–14).

## What to do

1. **Export a framework-agnostic core** plus a thin Fastify plugin, since five
   of the six apps are Fastify. Do not couple the core to Fastify.
2. **`verify(token)`** — local EdDSA verification against Ward's JWKS, fetched
   once and cached with the `kid` respected so a key rotation is picked up
   without a redeploy. Algorithm pinned to EdDSA; `alg` never read from the
   token.
3. **`introspect(token)`** — calls Ward, caches the answer **per session for 30
   seconds**, and collapses concurrent calls for the same token into one
   in-flight request. Six apps polling on every request must not become six
   stampedes.
4. **The guard** resolves `{ subject, username, grants }` onto the request, and
   offers `requireGrant(app, role)`. Apps ask "does this person hold this role
   here"; they never parse a token themselves.
5. **Fail closed.** If Ward is unreachable, requests are rejected — not served
   from an expired cache. Ward being down already means nobody can log in; it
   must not also mean revocation silently stops working.
6. **Reading the cookie is the package's job**, including the `Path=/` access
   cookie. No app should know the cookie's name.
7. Ship types. Six TypeScript consumers.

## Acceptance

- A revoked session stops being accepted within 30 seconds — timed, in a test.
- Fifty concurrent requests on one cold token produce **one** introspection
  call.
- A rotated signing key is picked up without restarting the consumer.
- With Ward stopped, the guard rejects rather than allowing.
- `requireGrant` refuses a role the person does not hold, and the negative test
  is the one that matters.

---

## Outcome — landed 2026-09-04

`@ward/client` — a framework-agnostic core plus a thin Fastify plugin. 39 tests.
All acceptance criteria met, and the negatives are the ones that carry the
weight.

### The API

```ts
import { createWardClient, requireGrant } from "@ward/client";
import { wardFastifyPlugin } from "@ward/client/fastify";

const ward = createWardClient({
  publicOrigin: process.env.WARD_PUBLIC_ORIGIN!,
  apiBasePath: "/ward-api",   // REQUIRED — no default, deliberately
});

await app.register(wardFastifyPlugin, { client: ward });
app.get("/x", { preHandler: app.wardAuthenticate }, async (req) => req.ward);
app.get("/admin", { preHandler: app.wardRequireGrant("atrium", "admin") }, handler);
```

`request.ward` is `{ subject, username, grants }` — **never a raw token**.
Reading the `ward_session` cookie is the package's job, so no app needs to know
its name. Errors carry `statusCode`: `WardAuthenticationError` (401),
`WardForbiddenError` (403), `WardUnavailableError` (503).

Non-Fastify consumers use the core: `ward.authenticate(cookieHeader)`,
`ward.verify(token)`, `ward.introspect(token)`,
`requireGrant(session, app, role)`.

### `apiBasePath` has no default, and that is the point

It used to default to `""`, which resolved to `https://<origin>/.well-known/jwks.json`
while Caddy serves Ward under `/ward-api/*`. Review caught it before this
package existed. Had it shipped that way, every app would have fetched a 404,
`jose` would have thrown, and **all six apps would have rejected every token at
once** — an estate-wide lockout on the deploy that shipped the client. It fails
closed, so an outage rather than a bypass, but it is exactly the kind of wrong
default that gets copied six times.

### Two caches, two jobs — conflating them is the mistake

- **`jose`'s JWKS cache** answers *"did Ward sign this"*. Holds keys ~10
  minutes; an unrecognised `kid` triggers an immediate refetch **except** inside
  a ~30-second `cooldownDuration`, where it fails fast instead. That cooldown is
  the anti-stampede floor, and in production it never delays a real rotation.
- **The package's 30-second introspection cache** answers *"is this session
  live, what may it do"*, and **it alone bounds how long a revocation takes to
  land**.

So raising the JWKS cache does not slow revocation, and lowering the
introspection TTL does not speed up rotation pickup. Tune the one whose question
you are actually asking.

### It fails closed, in all three ways it could have failed open

Ward being unavailable already means nobody can log in; it must not *also* mean
revocation quietly stops working. So: a `500` from Ward **throws** rather than
reading as `active: false`; an unreachable Ward throws rather than allowing; and
an expired cache entry is **not** served when Ward is down. There is a test for
each.

Fifty concurrent requests on one cold token collapse to **exactly one**
introspection call — counted, not asserted in principle. Six apps polling every
request must not become six stampedes.

### For briefs 13–15

Each app needs only its own slug as it appears in Ward's `grants` table, and the
role names it defines. **Roles are opaque**: test membership with
`hasGrant`/`requireGrant`, never equality or ordering, and never interpret what
a role string means — that meaning lives in the app, which is why Ward does not
need redeploying when an app grows a capability.

`client/README.md` carries the full wiring example including the base path. Six
repos will copy from it, so an error there is an error six times.
