# Task 03 — Passwords, login, refresh rotation and lockout

## Context

The session shape is locked in
[decisions-tokens.md](../../wiki/decisions-tokens.md): a short signed access
token plus a **long-lived opaque refresh token that is a row**. Rotation is not
optional, and a replayed refresh token is the estate's stolen-cookie alarm.

## Files you OWN

- `api/src/auth/password.ts`, `api/src/auth/lockout.ts`
- `api/src/auth/refresh.ts`
- `api/src/routes/auth.ts` — `/login`, `/logout`, `/refresh`
- `api/src/auth/cookie.ts`

## Files you must NOT touch

`api/src/tokens/**` (brief 02 — import its mint function), `api/src/db/**`
(brief 01), the superuser path (brief 06).

## What to do

1. **Passwords.** `node:crypto` scrypt with a per-password random salt, stored
   `saltHex:hashHex`. Minimum length 8. Compare with `timingSafeEqual`.
2. **Unknown username spends a dummy hash** so response timing does not reveal
   whether an account exists. Atrium does this; copy the shape, not the file.
3. **Lockout keyed on IP, never on username.** Newspapper's reasoning holds and
   generalizes: a username-keyed lockout lets a stranger lock a real person out
   of their own account indefinitely. Five failures → `429` with `Retry-After`.
   In-memory, capped, entries expiring; a success clears the counter. **Do not
   add an artificial delay** — holding a connection open *is* the denial of
   service the measure exists to prevent.
4. **`POST /login`** → sets **two** cookies on `Path=/`, `HttpOnly`,
   `SameSite=Lax`, `Secure` (except plain HTTP on loopback): the 15-minute
   access token, and the refresh token scoped to `Path=/ward-api/refresh` so it
   is not sent on every request in the estate.
5. **`POST /refresh` rotates.** Presenting `R1` returns a new access token and
   `R2`, and invalidates `R1`. **Presenting an already-used `R1` is a theft
   signal: revoke the entire family and force re-authentication.** Log it to the
   audit table.
6. **`POST /logout`** clears both cookies and deletes the refresh row. This is
   why logout is near-instant in practice — the client then holds nothing.
7. Refresh tokens are 32 random bytes; **store only a hash** of them.

## Acceptance

- Login sets both cookies with the exact attributes above; verified against the
  response headers, not the code.
- Refreshing twice with the same token revokes the family — a test, and the most
  important one here.
- Six failed logins from one address earn a `429`; a seventh from a *different*
  address succeeds. Both asserted.
- Timing for an unknown username and a wrong password are within noise.
- Logout leaves no refresh row and no usable cookie.
