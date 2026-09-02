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
