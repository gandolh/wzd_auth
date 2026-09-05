# Task 09 — The login page and self-service

## Context

[There is one login page and it lives in Ward](../../wiki/decisions.md).
Apps redirect to `/ward/login?next=…` and are returned once the cookie is set.
No app renders its own login form.

The accepted cost is real and worth holding in mind while designing: atrium's
Reading Room and newspapper's Mechanical are strongly-designed, very different
systems, and both now hand their sign-in moment to a third visual identity.
`?next=` keeps the interruption short; nothing removes the seam. **Design for a
fast handover, not for a destination** — this page should feel like a door, not
a lobby.

## Files you OWN

- `ui/src/pages/Login.tsx`, `ui/src/pages/Register.tsx`, `ui/src/pages/Verify.tsx`
- `ui/src/pages/Account.tsx` — self-service
- `ui/src/app.tsx`, routing, and the design tokens for all of it

## Files you must NOT touch

`ui/src/pages/console/**` (brief 10), everything under `api/`.

## What to do

1. **Vite + React**, matching the estate's other SPAs. Served at `/ward`.
2. **Login** — username + password, `?next=` honoured. **Validate `next` against
   an allowlist of estate paths.** An open redirect on the estate's login page
   is the worst possible place to have one.
3. Surface the states the API actually produces: bad credentials (without
   revealing which half), the `429` lockout with its `Retry-After`, and an
   unverified-email prompt where relevant. These are the six inconsistent
   implementations the central page exists to replace — get them right once.
4. **Register** — only reachable for apps with the flag on, and told which app
   it is signing up for. **Verify** — the landing page for the mail link.
5. **Self-service (`/ward/account`)**, deliberately minimal:
   - change password (requires the current one; rotates the session)
   - see my own grants, read-only
   - **sign out my other devices** — revokes every refresh family but this one.
     This earns its place: owner-issued accounts have no verified email and so
     no recovery channel, making this the only self-serve response available to
     someone who suspects their session was stolen.
6. **No account listing, no grant editing, nothing about other people.** That is
   the console, it is superuser-only, and it is brief 10.

## Acceptance

- A round trip from `/atrium` through login and back to `/atrium` works, and the
  cookie is set for the whole origin.
- `?next=https://evil.example` is refused; `?next=/atrium/` is honoured.
- The lockout state renders with its retry time rather than a generic failure.
- "Sign out my other devices" leaves the current session working and kills the
  rest — verified with two browsers, not just a unit test.
- Nothing on this surface exposes another account's existence.

---

## Outcome — landed 2026-09-04

The estate's one login page, plus register, verify and self-service. All
acceptance criteria met.

### The `?next=` allowlist

`resolveNext(raw)` — 73 table-driven cases, and **any refusal yields `/`
silently**, with the return type making the path safe to use even if a caller
forgets to check `accepted`.

Two subtleties worth keeping, because both are the kind of thing a later "tidy
up" removes:

- **Raw and decoded forms are both validated, because they can disagree.**
  `/atrium/%2e%2e/%2e%2e/evil` keeps `atrium` as its first segment — the URL
  parser does not treat `%2e` as a dot segment — while its decoded form resolves
  to `/evil`.
- **The estate's own origin spelled absolutely is refused** as firmly as
  `evil.example`. Accepting one absolute host is how a later edit accepts two.

Rejected and tested: absolute URLs, `javascript:`, `data:`, `//evil`,
backslashes raw and encoded and double-encoded, control characters and
whitespace, encoded slashes, malformed encoding, on-origin non-apps, fullwidth
lookalikes, **the `-api` roots** (nobody was reading an API endpoint), and the
`/ward/login` loop.

Two helpers exist because mixing them is silent: `loginUrlFor()` gives the origin
path for apps outside Ward, `loginRouteFor()` the router path — a
`<Link to="/ward/login">` under a `/ward` basename yields `/ward/ward/login`.

### What the browser found that the tests could not

- **Focus stayed on the button after a blank submit**, telling a keyboard or
  screen-reader user from three elements away that something invisible was
  wrong. Fixed on Login and Register.
- **A blank Register submit round-tripped three empty strings to the API** and
  spent lockout budget to be told about spacing rules.
- The heading broke as "Continue / to Atrium" with the rule's weight change
  landing mid-heading, reading as a bug rather than a design.

### Endpoints this brief needed and did not have

It reported five rather than faking them, and **all but one now exist** — see
[the wave 6 log entry](../../log.md). `POST /account/password`,
`POST /account/sessions/revoke-others`, `GET /account` and `GET /apps` all
landed and the flags are on.

**`CAN_RESEND_VERIFICATION` stays `false`.** There is still no resend endpoint,
by decision — survivable only because `email_verified` gates nothing, so the
honest message is "your account works, the address just isn't confirmed."

**It also found the mail link pointed at `/ward-api/verify`**, the API's own
server-rendered page, so this brief's `/ward/verify` screen was not on the path
a person takes from their inbox. Fixed.

### Contrast and accessibility floor

Text 15:1, muted 7.2:1, faint 4.95:1 (**the floor — do not lighten it**),
accent-on-white 8.9:1. Real `<form>`s, bound labels, `autocomplete`,
`aria-describedby`, focus moved to errors, visible focus rings.

### For briefs 13–15 adding "sign in with Ward"

Build the link as `/ward/login?next=<encodeURIComponent(path)>` — copy
`loginUrlFor()` rather than hand-rolling, since an unencoded `&` truncates
`next` at the first parameter and lands the person on the app's home page.
**`next` must be a path, not an absolute URL**, and **your app's root must be a
row in `ESTATE_APPS`** or the redirect silently goes to `/`. That table is
hard-coded on purpose: it is also the allowlist, and an allowlist fetched over
the network is not an allowlist.
