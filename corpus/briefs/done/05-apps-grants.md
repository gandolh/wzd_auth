# Task 05 — The apps registry, grants, and the registration flag

## Context

A grant is the estate's actual security boundary
([decision](../../wiki/decisions-accounts.md)). This brief is the write side of
it: creating apps, issuing and revoking grants, and flipping each app's
public-registration flag. Brief 04 reads what this writes.

Two rules from the decisions pages constrain the whole brief:

- **Ward stores role strings opaquely and never interprets them.** It knows
  `(cristian, prm, admin)`; it does not know what an admin may do. Putting that
  meaning here means redeploying Ward every time any of six apps grows a
  capability.
- **There is no wildcard grant.** Even the owner account holds explicit rows,
  one per app, so a newly-added app is reachable by nobody until someone says
  otherwise.

## Files you OWN

- `api/src/routes/admin/apps.ts`, `api/src/routes/admin/grants.ts`
- `api/src/grants/write.ts`
- `api/src/audit.ts`

## Files you must NOT touch

`api/src/grants/resolve.ts` (brief 04 owns reads), the console UI (brief 10),
the superuser gate (brief 06 — import it).

## What to do

1. **Every route here is behind the superuser gate** from brief 06. There is no
   `ward:admin` grant and nothing else opens this surface.
2. **Apps CRUD** — slug, name, `public_registration` (**default false**), and
   the baseline role conferred on self-signup. Creating an app must not require
   a deploy.
3. **Grants** — add and remove `(subject, app, role)`. Adding a role a person
   already holds is idempotent, not an error. Removing one they do not hold is
   likewise.
4. **Accounts** — create (username + password, no email), disable, re-enable,
   rotate password. Creating an account is how the **owner account** and every
   invited person comes into existence.
5. **Everything here writes to `audit_log`** — actor, action, target, when. This
   is the only surface where authority changes, so it is the only one whose
   history genuinely matters.
6. **Disabling an account must invalidate its sessions**, not merely block
   future logins. Delete its refresh families; brief 04's introspection then
   reports `active: false` within the cache window.

## Acceptance

- A new app defaults to closed registration — asserted, because the fails-safe
  property is the entire reason the flag exists.
- Granting two roles in one app works and both appear in introspection.
- Disabling an account ends its live sessions within the cache window, verified
  end to end.
- Every mutation leaves an audit row naming the actor.
- No route here is reachable with an ordinary account's token, however many
  grants it holds — one test proving it.

---

## Outcome — landed 2026-09-04

The write side of the estate's security boundary: apps, grants, accounts and the
audit trail, entirely behind the superuser gate. All acceptance criteria met.

**No route here is reachable with an ordinary account's token**, however many
grants it holds — proven with a real signed access token carrying two grants,
refused `401` through cookie, bearer and console-cookie headers alike. There is
no `ward:admin` grant and nothing else opens this surface.

### Routes

All under `/console/`, and that is **functional rather than cosmetic**: the
`ward_console` cookie is scoped to `Path=/ward-api/console`, so a route mounted
anywhere else would simply never receive it.

- `GET|POST /console/apps`, `GET|PATCH|DELETE /console/apps/:slug`
- `GET|POST|DELETE /console/grants`
- `GET|POST /console/accounts`, `GET /console/accounts/:subject`,
  `POST /console/accounts/:subject/{disable,enable,password}`

Error bodies are always `{"error":"<snake_case_code>"}`; every response carries
`cache-control: no-store`.

### The calls worth knowing about

- **Apps default to closed** and cannot be opened without naming the baseline
  role a stranger gets. The fails-safe property the flag exists for now holds at
  the schema *and* at the route. Setting a baseline role on a closed app is
  **refused** rather than silently dropped, so an operator never believes they
  set something that was discarded.
- **Grants are idempotent both ways** — adding a role someone holds returns
  `200 created:false`; revoking one nobody holds returns `removed:0`. **POST is
  never `201`**, because a status that changes on a repeat makes an idempotent
  retry look like a different outcome.
- **DELETE `/console/grants` carries a JSON body.** A role is opaque and may
  contain `/`, `%` or `:`, so it cannot be a path segment.
- **Disabling revokes every refresh family** in the same transaction, so the
  sessions end rather than merely future logins being blocked. Password rotation
  does the same — a rotation that leaves a 30-day refresh alive achieves
  nothing. **Re-enabling deliberately does not restore sessions**, and grants
  survive a disable so a re-enable restores exactly what was there.
- **A no-op writes no audit row.** A duplicate grant, a revoke of nothing, a
  PATCH that changes nothing, a second disable: all `200`, no row. "Every
  mutation leaves an audit row" is read as being about actual changes of
  authority — auditing double-clicks buries the rows an operator needs under
  noise they generated by mis-clicking. Every response carries a
  `created`/`removed`/`changed` flag so a UI can still tell.
- **`app.registration` is a separate audit action from `app.update`.** One PATCH
  doing both writes two rows, because "who renamed this" and "who opened this to
  the public" are different questions and `action` is how they are asked.

### Deviation

`api/src/routes/admin/support.ts` was added beyond the brief's file list — the
shared view mappers, the SQLite-constraint-to-status translation and
`SLUG_PATTERN`. Duplicating a constraint-error mapper across three route files
invited drift. It registers nothing and exports no plugin.

### Audit actions

`app.create`, `app.update`, `app.registration`, `app.delete`, `grant.create`,
`grant.revoke`, `grant.revoke_app`, `user.create`, `user.disable`, `user.enable`,
`user.password_rotate`.

All carry `actor_kind="superuser"`, `actor_subject=NULL`,
`actor_label="superuser"` and `detail.session` naming the console session. Grant
rows use `target_id = grantTargetId(...)`, which is **percent-encoded** — parse
it with `parseGrantTargetId`, never by splitting on `:`.

### For brief 10 (the console UI)

Build directly against the routes above. Two things to render carefully:
`session.refresh_raced` is **benign** (two tabs) and `session.reuse_detected` is
**the alarm** — do not present them alike. And `grants.granted_by` is either a
subject or the literal `"superuser"`; it is not a foreign key and must never be
joined to `users`.
