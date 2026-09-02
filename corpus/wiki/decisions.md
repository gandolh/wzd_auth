---
summary: The foundational calls for Ward — the one-origin topology and the isolation it costs, what the service owns versus what apps keep, the single central login page, what the UI carries, newspapper's move off loopback, the name, and the two inherited atrium decisions.
updated: 2026-09-01
---

# Decisions

An entry earns a place here only if all three hold: **hard to reverse**,
**surprising without context**, and **a genuine trade-off** with real
alternatives that were rejected. Do not reopen one without an explicit revisit
and a [../log.md](../log.md) entry.

Account, registration and grant calls live in
[decisions-accounts.md](./decisions-accounts.md); session and token mechanics in
[decisions-tokens.md](./decisions-tokens.md). Still undecided:
[open-questions.md](./open-questions.md).

## The estate stays on one origin; sub-paths are routing, not a boundary
_2026-09-01, grilled Q3_ — Everything stays at `https://gandolh.ro/<path>`.
A single session cookie at `Path=/` is therefore sent to every app with no
redirect protocol, no CORS and no token relay, and it rides on `<img>` and
`<video>` requests — which retires atrium's `?token=` query-string workaround,
added only because cover tags cannot send an `Authorization` header.

**The cost is accepted, not overlooked: there is no isolation between apps.**
The browser treats `/design-study` and `/atrium-api` as one security context, so
an XSS anywhere in the estate reaches every app's API with credentials attached.
This is judged bounded because the static sites take no user input and one
person writes all of it.

**Rejected: subdomains** (`auth.gandolh.ro`, `atrium.gandolh.ro`). They buy real
isolation and force a proper redirect protocol, at the cost of rewriting the
master Caddyfile, re-cutting build config across seventeen projects, and
breaking atrium specifically — it bakes an absolute `VITE_API_URL` into its
bundle and derives its service-worker runtime-cache regex from that origin.

If the isolation cost ever needs paying down without moving to subdomains, the
known mitigation is to keep the SSO cookie at `Path=/` but exchange it for
app-scoped tokens at `Path=/atrium-api`, `Path=/prm-api` and so on. Not decided,
recorded so it is not re-derived.

## wzd_auth owns credentials and account identity; apps keep their own rows
_2026-09-01, grilled Q4_ — One `users` table, one password, one place a person
signs in. Every app keeps its **own** per-user rows keyed by a stable
**subject** — atrium keeps profiles, reading progress and notes; imbatranimOS
keeps whatever it keeps.

> **⚠ REVISED 2026-09-01 (Q12): the roles clause no longer holds.** This
> originally said apps keep their own roles. Ward now owns **which apps a person
> may use and at what role** — see *Ward owns access grants* below. What each
> role is permitted to *do inside* an app stays the app's business.

**Rejected: wzd_auth as the store of record for everything per-user.** It reads
as tidier and is not: it makes the identity service a dumping ground that must
be redeployed whenever any app grows a per-user field, and it couples six
release cycles to one schema. **Also rejected: credentials only**, with each app
still owning its own account concept — that leaves six answers to "who is this
person", which is the problem this repo exists to remove.

The load-bearing consequence: **the subject id is the contract.** It must be
stable forever, opaque, and never recycled — an app's rows outlive any rename,
and reusing a subject silently hands one person's data to another.

## Newspapper leaves loopback, which retires the premise under its security decisions
_2026-09-01, grilled Q1; **revises `newspapper/corpus/wiki/decisions-security.md`**_
— Newspapper is deployed to the VPS on the same domain as everything else. Its
security page opens by saying every call on it was made against "one person, on
localhost", and that **the assumption is the first thing to revisit on
exposure**. This is that moment, and three calls are now live:

- **`/uploads/*` is deliberately public** — headless Chromium fetches images
  mid-render carrying no cookie. On loopback the exposure was bounded by 32 bits
  of ref entropy and an unreachable port. On the public internet only the
  entropy is left.
- **The session cookie is a stateless 30-day HMAC** and cannot be revoked before
  it expires. Rotating `SESSION_SECRET` is the only revocation, and it signs
  everyone out.
- **The lockout is IP-keyed, never username-keyed** — correct reasoning for a
  single-account app, and it now meets real internet traffic.

None of these are fixed by centralizing auth on its own. A revision note belongs
in newspapper's own corpus.

## The service is called Ward
_2026-09-01, grilled Q14_ — A ward is a protective enchantment on a threshold:
it *is* access control, it puns on "warden", and it keeps the estate's
architectural naming (Atrium, Citadel, Hollow). Deploy path `/ward-api`, cookie
`ward_session`.

**Rejected: `wzd_auth`**, the repo's working name — `wzd` is *newspapper's
markup file extension*, so it names the estate's identity service after one
app's file format. Renaming cost one `git mv` at this point and an afternoon
once it is baked into a deploy path, a pm2 process name and six client configs.
**Also rejected:** *Gatehouse* (right meaning, no magic), *Sigil* (maps well to
a token, less well to the service), *Sanctum* (best architectural fit, collides
with Laravel Sanctum).

## There is one login page, and it lives in Ward
_2026-09-01, grilled Q21_ — Apps redirect to a central `/ward/login` with a
`?next=` and are returned once the cookie is set. No app renders its own login
form.

**Rejected: per-app login forms** posting to `/ward-api/login`. Same origin
means both are equally safe, so this was a design and maintenance call, and the
deciding argument is that Ward exists to delete six copies of auth — per-app
forms would keep six copies of the *form*, which is where lockout states, email
verification prompts and error handling get subtly wrong in six different ways.

**The cost is a real one and is accepted:** atrium's Reading Room and
newspapper's Mechanical are strongly-designed, very different systems, and both
now hand their sign-in moment to a third visual identity. `?next=` keeps the
interruption short, but the seam is visible and no amount of theming removes it.

## The UI is a console plus a minimal self-service page
_2026-09-01, grilled Q22_ — Two surfaces:

- **Console** — accounts, grants per app, each app's public-registration flag,
  active sessions with revoke, and an audit trail. Not optional: grants are the
  estate's security boundary and are unusable without somewhere to see and set
  them.
- **Self-service** — change password, see my own grants, sign out my other
  devices. Deliberately minimal.

Self-service earns its place on one specific argument: owner-issued accounts
carry **no verified email** and therefore **no recovery channel**, so
"sign out my other devices" is the only self-serve response available to someone
who suspects their session was stolen. Password rotation has to live somewhere
too, and putting it in six apps contradicts the decision above.

## Inherited — not ours to break quietly

Locked in another repo. A design here may contradict one, but must say so out
loud and carry a revision note back to the source.

### Atrium D30 — accounts are operator-seeded, sessions are opaque and revocable
_2026-07-08_ — No self-registration. Login trades username + password for a
random 32-byte server-stored token that `/auth/logout` revokes. Auth is always
on. Unknown usernames still spend a dummy scrypt hash so timing cannot reveal
whether an account exists. **Upheld** by the no-public-signup decision above.

### Atrium D35 — a profile is an identity boundary, explicitly not a security one
_2026-08-24_ — An account is a household; profiles are the people in it; they
switch freely with no password and no PIN. Anyone holding a live session can
become any profile on that account, **by design**.

Recorded here because the tempting mistake when centralizing is to promote a
profile to a permission. It is not one — and per the ownership decision above,
profiles stay **atrium-local**. wzd_auth does not know they exist.
