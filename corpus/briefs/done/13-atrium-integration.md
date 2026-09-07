# Task 13 — Atrium cuts over to Ward

## Context

Atrium has the estate's most developed auth and loses all of it: operator-seeded
accounts, scrypt hashes, opaque server sessions, the `sessions` table, the
`?token=` query-string fallback and its own login screen.

**Two of atrium's own decisions are revised by this and need revision notes in
`atrium/corpus/wiki/decisions.md`:**
- **D30** — accounts and sessions move to Ward entirely.
- **D35** — profiles **stay**, and stay atrium-local. Ward does not know they
  exist. A profile remains an identity boundary and explicitly not a security
  one; the account above it is now a Ward subject.

## Files you OWN

- `atrium/apps/api/src/modules/auth/**` — mostly deletion
- `atrium/apps/api/src/modules/profiles/profiles.model.ts` — re-key to subject
- `atrium/apps/web/src/auth/**`, `apps/web/src/lib/auth.ts`
- `atrium/apps/api/scripts/seed.ts` — delete it

## Files you must NOT touch

The library, reader, LaTeX and notes modules beyond the re-key. `packages/shared`
beyond the auth contract.

## What to do

1. **Delete** `auth.service.ts`, `auth.model.ts`, the `users` and `sessions`
   tables, `password.ts`, and `scripts/seed.ts`. Accounts are Ward's now.
2. **Replace `registerAuthGuard`** with `@ward/client`'s guard. Keep the
   app-wide `onRequest` shape — atrium's rule that no route does its own auth is
   correct and survives.
3. **Re-key `profiles.user_id` → `profiles.subject`.** This is the only schema
   change and it is the whole integration on the data side. Everything
   profile-scoped below it is untouched.
4. **Delete the `?token=` fallback.** It existed because `<img>` cover tags
   cannot send an `Authorization` header. The `Path=/` cookie is sent on image
   requests automatically, which is one of the concrete wins of the one-origin
   decision. **Verify covers still load** — this is the test that proves it.
5. **Delete the login screen**; redirect to `/ward/login?next=/atrium/`.
6. **`GET /auth/status` goes**, along with the allowlist entries for it.
7. **Guard on `requireGrant("atrium", …)`.** An account with no atrium grant
   gets a 403 even with a perfectly valid Ward session — that is the point of
   the grant model and needs a test.

## Acceptance

- Covers, audio and video all load with no `?token=` anywhere in the codebase.
- The PWA's offline shell and service worker still work; the login redirect does
  not break the cached start URL.
- Profile switching still needs no password (D35 intact) and follows the session.
- A Ward account without an atrium grant is refused.
- Revoking the session in Ward's console locks atrium within 30 seconds.
- Revision notes added to atrium's D30 and D35.
