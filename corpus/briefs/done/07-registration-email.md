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

---

## Outcome — landed 2026-09-04

`POST /register`, `GET /verify`, and the mail sender. All acceptance criteria
met. This brief called itself the largest single chunk of build cost in the
repo and it was.

### Routes

**`POST /register`** — `{ app, username, email, password }`, all required.
- `201` → `{ subject, username, email, emailVerified: false, app, role, verificationSent, verificationExpiresAt }`.
  **No cookie and no token: registering does not sign you in** — send the person
  to the login form. `verificationSent: false` means the account is real but the
  mail failed.
- `400 invalid_request` (malformed; **does not spend rate budget**) ·
  `400 password_too_short` / `password_too_long` · `403 registration_closed` ·
  `409 username_taken` · `429 too_many_attempts` with `retryAfterSeconds`.

**`GET /verify?token=<64 hex>`** — single-use, 24h, `exposeHeadRoute: false` so
a HEAD previewer gets a 404 rather than burning the token. Content-negotiated.
`400 expired_token` is its own code because it is actionable; unknown, used and
wrong-purpose all collapse to `invalid_token`.

**`registration_closed` covers a closed app and an app that does not exist**,
identically — so the endpoint is not also an app-discovery oracle.

### The collision question, and why the answer is to be plain

The tension between "clear" and "non-enumerating" resolves once you see the
oracle **cannot** be closed: the username *is* the canonical identifier, so a
duplicate must be refused, and the refusal carries the fact. Being vague costs
every real person the one thing they need to know — in the single most likely
response this endpoint gives — while costing a prober nothing, since they learn
the same bit from the failure either way.

So `409 username_taken` is stated plainly, and what is withheld is everything
*else*: byte-identical whether the holder is disabled, verified, owner-issued or
already holds a grant in that app; **byte-identical for `WARD_ADMIN_USERNAME`**,
which is also refused, so blocking it cannot be used to discover the break-glass
name; and no timing tell, because the password is hashed before the insert on
every path that reaches it.

**The enumeration that actually matters is not offered at all: there is no
"email already registered" error.** `users.email` has no uniqueness constraint,
two accounts may share an address, and `/register` never confirms or denies that
an address is known to the estate. prm answers `409 EMAIL_TAKEN` today because
email is its primary key; Ward's is not, so giving that oracle up costs nothing.

### Keeping the token out of the request log

The link has to be clickable from a mail client, so the token travels in a URL —
and Fastify writes its `incoming request` line **before any `onRequest` hook
could scrub it**. So `/verify` is registered in its own encapsulated scope whose
`req` serializer replaces the **whole query string** with `<redacted>`, not just
`token`, so a parameter added later cannot leak by omission. Verified: zero
occurrences of a real token in a complete server log.

Belt as well as braces: `referrer-policy: no-referrer`, a page with no links or
subresources, `cache-control: no-store`, and `sendMail` logging the outbox
*path* rather than the link.

### `granted_by = "self-registration"`

Now in [`db/grants.ts`](../../../api/src/db/grants.ts) beside `SUPERUSER_ACTOR`,
so the sentinels this column may carry stay together. Both alternatives were
wrong: `SUPERUSER_ACTOR` would make the audit trail claim the break-glass
credential acted when nobody did, and the registrant's own subject would read as
"this person granted themselves", implying an authority they do not hold. What
conferred it is the registration flow acting on a flag the operator set earlier.

### Notes for later briefs

**Brief 09** — build the two screens against the shapes above. There is **no
resend endpoint**, so an expired link has no self-service recovery. Survivable
only because verification gates nothing: `email_verified` blocks no sign-in, so
the honest message is "your account works, the address just isn't confirmed."

**Brief 15 (prm cutover)** — prm's `POST /auth/register` becomes Ward's
`POST /register` with `app: "prm"` **plus a username**, which prm has never had:
its rows key on email, and email is not an identifier in Ward. prm's verify took
a token in a body and linked to its UI; Ward's is a `GET` linking to the API.
Two changes prm's UI must absorb: `EMAIL_TAKEN` no longer exists, and prm's
`reset_token` flow has **no Ward equivalent** — `password_reset` is an unused
`verification_tokens.purpose`, deliberately unbuilt.

**A trap for anyone testing by hand:** apps are **not** seeded in production.
`seedApps` is test support, so a fresh database has no apps and *every*
registration answers `registration_closed` until the console creates one. That
is correct — creating an app takes no deploy — but it looks like a bug.
