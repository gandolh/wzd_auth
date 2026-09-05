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

---

## Outcome — landed 2026-09-04

The superuser console — accounts, grants, apps, sessions and the audit log.
Acceptance criteria met, including the cutover path driven end to end in a
browser.

### The identity is a safety property

The console re-points `tokens.css`'s names under `data-ward-surface="console"`
rather than carrying its own colours, so it stays consistent when the login
page's values change. Dark, warmer accent, hazard band, visible session
countdown. That is not decoration: there is exactly one console credential, it
cannot be revoked or rotated without a redeploy, and every route here changes
authority. Someone reaching for break-glass should know they have.

### Endpoints this brief needed and did not have

It reported four rather than faking them, and **all four now exist**:
`GET /console/audit`, `GET /console/accounts/:subject/sessions`,
`DELETE .../sessions/:familyId`, and `POST .../sessions/revoke`.

**It also found a design gap behind the audit route, not just a missing route.**
Every console mutation is written `actor_kind='superuser'` with
`actor_subject=NULL`, and the only actor filter `AuditQuery` had was on subject —
so "filterable by actor" was unsatisfiable **for the actor that matters most**.
`actorKind` and `actorLabel` were added.

Until those landed it composed "end all sessions" out of **disable →
re-enable**, and said so honestly in the UI: two audit rows, a window where the
account cannot sign in, and a failure between the two calls leaving it disabled.
That composition is now gone, and so is the recovery copy — keeping it would be
a lie in the other direction.

### What survives from the constrained version

- **Ward records no device or address per family**, so the console cannot show
  which device is which. `refresh_tokens` has no such column and adding one needs
  a migration. The note stays, because a session list without it implies an
  operator can tell them apart.
- **`issuedAt` is the current token's issuance — the last refresh, not the
  original sign-in.** Labelled "Last refreshed" for that reason.

### Two contract corrections it found by building against the API

- **`POST /console/login`'s `429` carries no `retryAfterSeconds` in the body** —
  the number is in the `Retry-After` header. That route also answers prose
  (`"invalid credentials"`) rather than snake_case codes, unlike every other
  console route, so the client maps it by status.
- **`GET /console/apps/:slug` returns `{ app, grantCount }`**, not a bare
  `AppView`.

### Three bugs only a browser showed

`flex: 1 1 12rem` on a column field read as a 12rem **height**; `.wc-form-row`
never overrode `.wc-form`'s `flex-direction: column`, so filter rows rendered as
right-aligned columns; and bare `<a>` inherited UA blue on near-black.

### For the cutover (briefs 12/16)

`/ward/console` → sign in with `WARD_ADMIN_*` → **Apps** → register each app
(slug + name; leave registration unticked — a new app is closed and reachable by
nobody) → **Accounts** → new account (username + password; **there is no email
field**) → open it → **Access** → add each role. **Six times: there is no
wildcard and no bulk grant, by decision.**

- **Write the owner password down before leaving the page.** No email means no
  reset link; recovery is an operator rotating it, which also ends every session.
- **Slugs are permanent** — renaming changes only the display name.
- **A no-op reports itself as one.** A repeated grant says nothing changed and no
  audit row was written. That is correct, not a failure.
- **The session is 15 min idle / 4 h absolute and nothing polls to keep it
  warm** — polling `/console/session` would slide the window and silently delete
  the idle timeout. A Ward restart drops every console session.
- **Verify outside the console**: `POST /ward-api/login` as the owner, then
  `/introspect` with `{"accessToken": "<the ward_session value>"}`. That is the
  only thing that proves the six grants landed.
