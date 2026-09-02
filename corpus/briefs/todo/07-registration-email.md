# Task 07 — Public registration and email verification

## Context

[Anyone may register; registering grants almost nothing](../../wiki/decisions-accounts.md).
Signing up at an app whose flag allows it creates a Ward account and confers
**that app's baseline role only**. Reaching anything else needs a grant.

[Email is optional and required only on the public path](../../wiki/decisions-accounts.md):
owner-issued accounts skip it entirely, which is what keeps you from verifying
your own address to use atrium. This brief is the single largest chunk of build
cost in the repo, and it exists only because public registration is in scope.

**prm already ships `reset_token` and `verification_token` tables and a working
flow. Read it before inventing anything here.**

## Files you OWN

- `api/src/routes/register.ts`
- `api/src/mail/**` — the sender and the templates
- `api/src/auth/verification.ts`

## Files you must NOT touch

`api/src/routes/admin/**` (brief 05 — owner-issued accounts are created there
and skip everything in this brief), `api/src/auth/refresh.ts` (brief 03).

## What to do

1. **`POST /register`** takes `{ app, username, email, password }`. **Refuse
   unless that app's `public_registration` flag is true** — the flag is the
   whole point, and a new app must be closed until someone opens it.
2. On success create the account **unverified**, confer only that app's baseline
   role, and send a verification mail. An unverified account may exist; whether
   it may sign in is the app's business via its baseline role, not Ward's.
3. **`GET /verify?token=`** — single-use, time-limited, and constant-time
   compared. Mark `email_verified`, delete the token.
4. **`nodemailer`** with SMTP settings from the environment, pinned exact. In
   development, write the mail to disk or the log instead of sending — nobody
   should need an SMTP account to run this locally.
5. **Rate-limit registration hard, keyed on IP.** This is the only anonymous
   write surface in the estate, and abuse control is precisely why email
   verification was put in scope at all.
6. **Username collisions** are the ordinary case here, not an edge case. Return
   a clear, non-enumerating error.
7. **Do not build password reset in this brief.** Owner-issued accounts have no
   email and therefore no recovery channel by decision; reset is only meaningful
   for the verified-email population and is a separate, later question.

## Acceptance

- Registering against an app with the flag off is refused, with a test.
- A registered account holds exactly one grant — that app's baseline role — and
  introspection against any other app shows nothing.
- A verification token works once; replaying it fails.
- Development needs no SMTP credentials to exercise the whole flow.
- Registration flooding from one address is throttled.
