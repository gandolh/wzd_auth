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
