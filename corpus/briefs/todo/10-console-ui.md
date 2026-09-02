# Task 10 — The admin console

## Context

Grants are the estate's security boundary and are unusable without somewhere to
see and set them ([decision](../../wiki/decisions.md)). This is that place.

It is **superuser-only** and always will be
([decisions-admin.md](../../wiki/decisions-admin.md)) — there is exactly one
console credential and therefore exactly one administrator, deliberately. Do not
add a second path.

## Files you OWN

- `ui/src/pages/console/**`
- `ui/src/console-api.ts`

## Files you must NOT touch

`ui/src/pages/Login.tsx` and the self-service pages (brief 09), everything under
`api/` (briefs 05 and 06 own the routes this consumes).

## What to do

1. **Console login** — its own page, against `/console/login`, its own session
   cookie. Make it visibly *not* the ordinary login page; someone reaching for
   break-glass should know they have.
2. **Accounts** — list, create (username + password, no email), disable,
   re-enable, rotate password. Creating the **owner account** at cutover happens
   here, so this screen is on the critical path of brief 12.
3. **Grants** — per account, per app, roles as a **set**. Adding and removing a
   role must be one obvious click each. Show plainly when an account holds *no*
   grants, because that is the default and is easy to mistake for a bug.
4. **Apps** — create, rename, and flip `public_registration`. The flag needs a
   confirmation step: turning it on opens an anonymous write surface on the
   public internet, and it should not be a stray click.
5. **Sessions** — active refresh families per account, with revoke. This is the
   operator's answer to a suspected theft.
6. **Audit log** — filterable by actor and target. It is the only observability
   the superuser credential has, since it cannot be revoked or rotated without a
   redeploy.
7. **Never render a password back**, and never put one in a URL or a log line.

## Acceptance

- The full cutover path works from this UI alone: create the owner account,
  grant it admin on all six apps, sign in as it.
- Revoking a session from the console ends it in the target app within 30
  seconds.
- Turning on public registration requires a deliberate confirmation.
- The console is unreachable with an ordinary account's token however many
  grants it holds — the same assertion as brief 05, now through the UI.
- An account with no grants renders as an obvious, intentional state.
