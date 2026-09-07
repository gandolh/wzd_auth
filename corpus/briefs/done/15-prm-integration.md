# Task 15 — public-resource-map cuts over to Ward

## Context

prm is the reason the estate's security boundary moved from registration to
authorization ([decision](../../wiki/decisions-accounts.md)). It is **the only
app that keeps public self-registration**, and the way it keeps it is by that
registration now happening in Ward, conferring `prm:user` and nothing else.

Two of its properties change hands:

- **Roles** move to Ward as grants. prm stops owning `user` / `admin`.
- **`emailVerified`** was always an account-level fact, not an app-level one. It
  belongs to Ward now, and prm's `verification_token` / `reset_token` tables go
  — after brief 07 has cribbed their flow.

Note prm keys on **email** and Ward keys on **username**. Nothing migrates
([full prune](../../wiki/decisions-accounts.md)), so this is a difference to
delete, not to reconcile.

## Files you OWN

- `public-resource-map/backend/src/db/schema.ts` — drop the user-side tables
- `public-resource-map/backend/src/**` auth routes and middleware
- `public-resource-map/shared/src/types/auth.ts`
- `public-resource-map/ui/app/routes/login.tsx`, `ui/app/lib/authApi.ts`,
  `ui/app/stores/authStore.ts`

## Files you must NOT touch

Places, events, geocoding, ingestion. Favorites and notifications keep their
tables — only their key changes.

## What to do

1. **Drop** `user`, `session`, `reset_token`, `verification_token` and the
   `registerSchema` / `loginSchema` surface. A Drizzle migration, in dependency
   order — every FK is `ON DELETE no action`, so dependents go first.
2. **Re-key `favorite_event`, `favorite_place` and `notification`** from
   `user_id` to `subject`.
3. **Adopt `@ward/client`.** `requireGrant("prm", "admin")` replaces the role
   check; `requireGrant("prm", "user")` replaces "is logged in".
4. **Point signup at Ward** — `/ward/register?app=prm`. prm renders no
   registration form of its own. Its app row is the **only** one with
   `public_registration` on.
5. **Delete the email/password login form**; redirect to
   `/ward/login?next=/prm/`.
6. **Public reads stay public.** prm is a public resource map; only the
   authenticated surface moves. Verify anonymous browsing is untouched — it is
   the easiest thing to break here and the most visible.

## Acceptance

- An anonymous visitor still browses places and events with no session at all.
- A new person can self-register via Ward, lands back in prm, and holds exactly
  `prm:user` — with no access to atrium, asserted.
- Promoting someone to `prm:admin` is a console action and takes effect within
  30 seconds.
- Favorites and notifications survive the re-key and still resolve per person.
- No table in prm holds a credential.
