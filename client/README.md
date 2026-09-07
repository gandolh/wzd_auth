# `@ward/client`

Six apps have to do the same three things: verify the access token locally,
ask Ward whether the session is live and what it may do, and cache that
answer for 30 seconds. Written once here, or written wrong six times.

This package is deliberately split in two:

- **The core** (`@ward/client`) — framework-agnostic. No Fastify import
  anywhere in it.
- **The Fastify plugin** (`@ward/client/fastify`) — a thin layer on top of the
  core, for the five of six apps that are Fastify.

## Install

Already in this workspace as `@ward/client`. In a real consuming repo it
would be published or linked as a normal npm dependency; its own dependency is
just `jose` (pinned to `6.2.10`), and `fastify` is an **optional peer** — the
core has no runtime dependency on it at all.

## Every app needs a key

`POST /ward-api/introspect` refuses any request that does not carry a valid
`x-ward-app-key`, so `appKey` is a **required** option — an app without one
authenticates nobody. Issue it from Ward's console (the app's page → *Service
keys*); it is shown once and cannot be read back.

It is a **secret**, and `createWardClient` is therefore a server-side
constructor. A key in a browser bundle is a published string, not a
credential. Keep this package out of your client build.

```ts
const ward = createWardClient({
  publicOrigin: process.env.WARD_PUBLIC_ORIGIN!,
  apiBasePath: "/ward-api",
  appKey: process.env.WARD_APP_KEY!, // required
});
```

If the key is absent, wrong, or revoked, Ward answers `401` and this package
raises **`WardConfigurationError`** — a subclass of `WardUnavailableError`, so
existing fail-closed handling already catches it, while the message names
`WARD_APP_KEY` so the failure reads as "my deployment is broken" rather than
"Ward is down" or, worse, "everyone is signed out".

## The one thing every app must get right: the base path

Ward is served behind Caddy at `/ward-api/*`. Every app in this estate must
pass `apiBasePath: "/ward-api"` — there is **no default**, on purpose. An
earlier version of the underlying helper defaulted the base path to `""`,
which resolves to `https://<origin>/.well-known/jwks.json` — a path nothing
serves. Review caught it before it shipped: had it gone out, every app would
have fetched a 404 for Ward's public key, `jose` would have thrown on every
verification, and the estate would have rejected every token on the deploy
that shipped this client. Making the base path a required argument turns that
mistake into a compile error instead of an outage.

```ts
import { createWardClient } from "@ward/client";

const ward = createWardClient({
  publicOrigin: "https://gandolh.ro", // WARD_PUBLIC_ORIGIN, bare origin, no trailing slash
  apiBasePath: "/ward-api", // required — see above
  appKey: process.env.WARD_APP_KEY!, // required — see above
});
```

## Wiring a Fastify app

```ts
import Fastify from "fastify";
import { createWardClient } from "@ward/client";
import { wardFastifyPlugin } from "@ward/client/fastify";

const ward = createWardClient({
  publicOrigin: process.env.WARD_PUBLIC_ORIGIN!,
  apiBasePath: "/ward-api",
  appKey: process.env.WARD_APP_KEY!,
});

const app = Fastify();
await app.register(wardFastifyPlugin, { client: ward });

// A route that just needs to know who is signed in:
app.get("/dashboard", { preHandler: app.wardAuthenticate }, async (request) => {
  const { subject, username } = request.ward!;
  return { hello: username };
});

// A route that needs a specific role in *this* app:
app.get(
  "/admin",
  { preHandler: [app.wardAuthenticate, app.wardRequireGrant("atrium", "admin")] },
  async (request) => {
    return { subject: request.ward!.subject };
  },
);

// wardRequireGrant runs wardAuthenticate itself if it hasn't already run, so
// this is equivalent to the route above with one less line:
app.get("/admin", { preHandler: app.wardRequireGrant("atrium", "admin") }, async (request) => {
  return { subject: request.ward!.subject };
});
```

`request.ward` is `{ subject, username, grants }` — never a raw token, and no
route ever parses a JWT or reads a cookie by name. `app.wardAuthenticate`
throws `WardAuthenticationError` (mapped to `401`) or `WardUnavailableError`
(mapped to `503`, see "Fail closed" below); both carry `statusCode`, so
Fastify's own default error handler already answers correctly with no extra
error-handler wiring. `app.wardRequireGrant(app, role)` additionally throws
`WardForbiddenError` (`403`) when the session doesn't hold that role.

Every app's own slug is whatever key the console uses for it in Ward's grants
table — e.g. `"atrium"`, `"newspapper"`, `"prm"`. Roles are opaque strings this
package never interprets; ask your own app what roles it defined.

## Wiring anything else (the framework-agnostic core)

```ts
import { createWardClient, WardAuthenticationError, WardUnavailableError } from "@ward/client";

const ward = createWardClient({ publicOrigin: "...", apiBasePath: "/ward-api" });

async function handleRequest(cookieHeader: string | undefined) {
  try {
    const session = await ward.authenticate(cookieHeader);
    // session.subject, session.username, session.grants
  } catch (error) {
    if (error instanceof WardUnavailableError) {
      // Ward could not be reached — reject the request. Do NOT let this
      // fall through to "not authenticated" handling; log/alert on it.
    }
    if (error instanceof WardAuthenticationError) {
      // No cookie, bad signature, or the session isn't live — an ordinary 401.
    }
    throw error;
  }
}
```

`ward.readAccessCookie(cookieHeader)` is available directly if you only need
the raw token (for a server-to-server call, say) — but no app should ever
need to know the cookie is named `ward_session`. That is this package's job.

## What each call actually does

- **`ward.verify(token)`** — local, offline, EdDSA signature verification
  against Ward's published JWKS. Establishes _authentication_ only: that Ward
  signed this token for this subject. Says nothing about whether the session
  is still live.
- **`ward.introspect(token)`** — asks Ward's `POST /introspect` whether the
  session is live and what it may do, caching the answer **30 seconds per
  token** and collapsing concurrent calls for the same token into one
  in-flight request.
- **`ward.resolveSession(token)`** — `verify` then `introspect`, in that
  order: cheap local rejection first, network call only for a token that
  already checks out.
- **`ward.authenticate(cookieHeader)`** — the guard: reads the cookie,
  resolves the session, and returns it _active_ or throws.

## The two caches, and why they are not the same cache

This package holds two independent caches, and conflating them is the mistake
to avoid:

1. **`jose`'s remote JWKS cache**, inside `createRemoteJwksKeyStore` /
   `ward.verify`. Once fetched, Ward's public keys are held in memory for
   `cacheMaxAgeMs` (default 10 minutes) with **no network call** needed for a
   `kid` already seen. A token signed with an unrecognised `kid` — the shape a
   rotation takes — triggers an immediate refetch, **provided** the last
   fetch was more than `cooldownDurationMs` ago (default 30 seconds); within
   that cooldown window an unmatched `kid` fails fast instead of refetching,
   which is what stops a burst of bad-`kid` tokens from hammering Ward's JWKS
   endpoint. In practice a real rotation is always well past that 30-second
   floor, since it happens long after an app's first request. This cache
   answers "did Ward sign this" and has nothing to do with liveness.
2. **This package's own introspection cache**, inside `createIntrospector` /
   `ward.introspect`. Holds Ward's `{active, subject, username, grants}`
   answer **per token, for 30 seconds** — the number
   `corpus/wiki/decisions-tokens.md` calls out as the one that matters,
   because it is what a revocation waits on. This cache answers "is this
   session still live and what may it do", and it is the only thing that
   makes revocation and permission changes visible in bounded time. **Do not
   raise it in production.**

Raising the JWKS cache's `cacheMaxAgeMs` does not slow down revocation (that's
the other cache's job), and lowering the introspection TTL does not make a
key rotation land faster (that's this one's). They answer different
questions.

## Fail closed

If Ward cannot be reached — a network error, a timeout, or any HTTP status
other than the documented `200` (a `500` included) — `introspect` throws
`WardUnavailableError` and **never** falls back to a stale cached answer.
Ward being down already means nobody can log in anywhere in the estate; it
must not _also_ mean revocation silently stops working. A route wired through
`wardAuthenticate`/`wardRequireGrant` rejects the request (`503`) in this
case rather than letting it through.

## `requireGrant`

```ts
import { requireGrant } from "@ward/client";

requireGrant(session, "atrium", "admin"); // throws WardForbiddenError if not held
```

Always a **set-membership** test — one person can hold several roles in one
app. Never compare roles for equality, and never interpret what a role string
means beyond "does this session hold it": that meaning belongs to the app
that defined the role.

## Testing against this package

`createWardClient` takes `jwksEndpoint`/`introspectEndpoint` overrides and an
injectable `fetch`, specifically so a test (or a staging environment whose
layout doesn't match this estate's Caddy routing) can point at a server it
controls instead of `publicOrigin`/`apiBasePath`'s derived URLs:

```ts
const ward = createWardClient({
  publicOrigin: "http://127.0.0.1:9999", // unused when both endpoints below are given
  apiBasePath: "",
  jwksEndpoint: new URL("http://127.0.0.1:PORT/.well-known/jwks.json"),
  introspectEndpoint: new URL("http://127.0.0.1:PORT/introspect"),
});
```

This package's own test suite uses exactly this seam: `client/src/testing/fakeWard.ts`
is a small local HTTP server (real EdDSA keys via `jose`'s `generateKeyPair`,
a real JWKS endpoint, a real `/introspect`) that stands in for Ward without
running `api/`.
