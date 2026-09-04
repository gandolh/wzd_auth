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

---

## Outcome — landed 2026-09-04

`/login`, `/refresh`, `/logout`, scrypt passwords, and an IP-keyed lockout. All
acceptance criteria met. Reuse detection was demonstrated over a real socket,
not only in the test runner: `R1` replayed → family swept, and `R2` (the token
the legitimate client still held) dead too.

Three resolutions are recorded as decisions in
[decisions-implementation.md](../../wiki/decisions-implementation.md): the
absolute 30-day family lifetime, logout revoking rather than deleting, and the
lockout key never being `request.ip`.

### Review found two bugs that broke ordinary use, not just attacks

**Two tabs refreshing at once destroyed the session.** Only one caller can win
the single-use `UPDATE` — that held — but the loser's reuse sweep then revoked
the winner's brand-new `R2`, leaving zero live tokens and a false theft record.
On a one-origin estate where six apps share one access cookie at `Path=/`,
several tabs waking together is the *expected* shape. A used token presented
again is now a **race** rather than a theft when its family still has a live
successor issued within `REFRESH_RACE_GRACE_SECONDS` (10s): the family survives,
audited as `session.refresh_raced`.

**That fix was itself incomplete, and the reviewer caught it.** The controller
first ruled the raced response must stay byte-identical, which meant the loser's
`401` still carried cookie-clearing headers. Both responses race into **one**
cookie jar, so if the loser landed second the browser dropped the tokens and the
person was signed out anyway — a certain loss became a coin flip. The raced
branch now clears nothing. The reasoning worth keeping: clearing exists to stop
a client looping on a **dead** session; in a race the session is alive, so
clearing does not tidy up after it, it destroys it. What that concedes is a
`Set-Cookie`-shaped signal that the presented token was genuine and freshly
rotated — available only to someone already holding it, who can learn the same
thing by presenting it again after the window.

**One valid account bought unlimited password guessing.** `clearFailures` was
keyed on address, so a correct login to the attacker's own account wiped guesses
aimed at someone else — four wrong, one right, repeat: 40 guesses, zero 429s.
`prm` ships public registration, so brief 07 makes obtaining that account
self-service. The lockout *decision* stays on the address; *forgiveness* is now
per account, with the per-address breakdown capped because anonymous input feeds
it.

**A cross-site form POST signed the victim out of the whole estate, silently.**
`SameSite=Lax` stops the cookies being *sent* cross-site, not the response
*deleting* them, and `enctype="text/plain"` slips past Fastify's content-type
rejection. Cookies are now cleared only when a token was actually presented, and
both routes refuse a request whose `Sec-Fetch-Site` or `Origin` says cross-site.
**Absent headers still pass** — brief 08's server-side clients send neither.

Also fixed: minting after the rotation commit burnt families on a dropped
response (mint now precedes the transaction); an unauthenticated `500` echoed the
signing key's absolute path (`setErrorHandler` now answers a fixed body); the
reuse alarm recorded no presenter address and could be written without bound by
replaying one spent token.

### Contracts for dependents

```ts
// auth/lockout.ts — BREAKING: takes a target, not a bare key
export interface LockoutTarget { surface: "login" | "console"; address: string; account?: string }
export function checkLockout(t: LockoutTarget): LockoutDecision;   // ignores `account`
export function recordFailure(t: LockoutTarget): void;
export function clearFailures(t: LockoutTarget): void;             // forgives that account only
export function lockoutKeyFor(peer, xff, options?: { warn?(detail, msg): void }): string;
// A new credential surface adds a LockoutSurface member — it must not borrow "login".

// auth/refresh.ts
export function rotateRefreshToken(db, presented, now?, options?: { presentedBy?: string }): RotationOutcome;
export function subjectForRefreshToken(db, presented): string | undefined;  // lookup, NOT authorisation
export const REFRESH_RACE_GRACE_SECONDS = 10;
// RotationOutcome has a NEW variant: { status: "refresh_raced", subject, familyId }
// Any exhaustive switch must handle it — same as reuse_detected on the wire, NOT an alarm.
```

**Cookies** — `ward_session` (`Path=/`, `HttpOnly`, `SameSite=Lax`, `Secure`
unless plain-HTTP loopback, `Max-Age=900`) and `ward_refresh`
(`Path=/ward-api/refresh`, same flags, `Max-Age=2592000`). `/ward-api/refresh`
is the **browser-side** path; Caddy's `handle_path` strips the prefix, so the
Fastify route is `/refresh`. Getting that backwards yields a cookie that is
never sent — "refresh always 401s in production, works in tests".

**Audit actions:** `session.login`, `session.login_failed` (only for an account
that exists — auditing unknown usernames makes the table a write amplifier fed
by anonymous input), `session.logout`, `session.reuse_detected` (at most once per
family), `session.refresh_raced`, `session.refresh_denied`. The last two carry
`detail.ip`. Brief 05's console must render `refresh_raced` as benign and
`reuse_detected` as the alarm.

**Every `/refresh` failure answers `401 invalid_refresh`** whatever went wrong;
`/login` answers identically for unknown username and wrong password, and reports
`account_disabled` only *after* the password verifies. `/logout` always answers
`204` for a request that presented a token.
