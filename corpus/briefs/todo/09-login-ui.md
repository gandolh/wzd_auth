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
