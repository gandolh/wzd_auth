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
