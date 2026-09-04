---
summary: The locked calls about sessions and tokens — the short-lived signed access token, the opaque rotating refresh token, introspection-with-cache as the revocation mechanism, why there is no JWT denylist, EdDSA signing held by Ward alone, the two lifetimes that define the logout delay, and the calls settled once these were built: the absolute family lifetime, logout revoking rather than deleting, and the sid claim that makes revocation per-session.
updated: 2026-09-04
---

# Decisions — tokens and sessions

Foundational scope calls live in [decisions.md](./decisions.md); account,
registration and grant calls in
[decisions-accounts.md](./decisions-accounts.md).
Same rule: do not reopen one without an explicit revisit and a
[../log.md](../log.md) entry.

## A session is a short signed access token plus an opaque rotating refresh row
_2026-09-01, grilled Q6/Q10_ — Three parts, and each one exists for a reason:

- **Access token** — a short-lived JWT in the `Path=/` cookie, signed by Ward.
  Carries `sub`, `jti`, `exp`. Apps verify the signature locally.
- **Refresh token** — long-lived, **opaque, and a row in Ward's database**.
  Rotated on every use: presenting `R1` returns `R2` and invalidates `R1`.
  Presenting an already-invalidated refresh token is a **theft signal** and
  kills the entire token family, forcing re-authentication.
- **Revocation** — a session row marked inactive, not a list of dead tokens.

**Rejected: a denylist table of revoked JWTs**, which was the original ask. A
JWT's entire value is verifying locally with no lookup; a denylist consulted per
request pays that lookup anyway, and then owes key management, clock skew and
the `alg`-confusion bug class on top. It is opaque sessions with extra steps.
Once the revocable thing is a row, "revoked" is that row's absence and no
denylist needs to exist.

**Rejected: purely stateless JWTs with no server-side record.** They cannot
support rotation or reuse detection at all — the two measures that actually
catch a stolen token.

**If a denylist is ever reintroduced anyway, key it on `jti`.** OWASP is
explicit that keying on the raw JWT or a hash of it is unsafe: JWT malleability
lets an attacker produce a different serialization of the same token and walk
straight past the list.

## Apps ask Ward whether a session is still live, and cache the answer briefly
_2026-09-01, grilled Q10_ — Local signature verification establishes
*authentication*. A call to Ward establishes **liveness and permissions**, and
each app caches that answer per session for a short window.

This is the owner's proposal, and the research supports it over the alternative:
with introspection, revoking is **one** operation — mark the session inactive —
and every app stops honouring it within its own cache window, with no denylist
to synchronize across six services. A denylist inverts that into six lookups and
six separate cache-invalidation problems.

**The cost is accepted:** Ward becomes a runtime dependency of every app. Judged
acceptable because Ward runs on the **same box** as all six apps, so this is a
loopback call rather than a network round-trip, and because an unavailable Ward
already means nobody can log in anywhere.

**Permissions are deliberately NOT claims in the access token.** A token minted
before a grant changed carries stale authority for its whole lifetime; carrying
permissions in the introspection response instead means a permission change
lands in the same short window a revocation does.

**The cache window is the honest logout delay.** Clicking "log out" also clears
the cookie, so in the normal case the client simply no longer holds a token —
the window only matters against a token that was already stolen.

## Only Ward can sign; apps get a key that can only verify
_2026-09-01, grilled Q11_ — Asymmetric signing (EdDSA), private key held by Ward
alone, public key published at a JWKS endpoint.

**Rejected: a shared HMAC secret.** It gives every app the power to *mint*
tokens, not merely verify them — so on a single origin, one compromised app
forges identity for all six. That is the same blast radius the one-origin
decision already accepted once, and there is no reason to accept it twice for
something this cheap to avoid.

The cost is a JWKS endpoint and a key-rotation story, both of which are
ordinary.

## 15-minute access tokens, 30-second introspection cache
_2026-09-01, grilled Q18_ — Access token TTL **15 minutes**; each app caches an
introspection answer for **30 seconds** per session. Refresh token 30 days,
rotated on every use.

**The 30 seconds is the number that matters**, not the 15 minutes. Because apps
introspect on every request, a revoked session stops working within the cache
window regardless of how long its access token had left to run — the TTL only
bounds how often the refresh endpoint is hit.

**Logout is near-instant in practice and this is why:** logging out clears the
cookie, so the client no longer holds a token at all. The 30-second window is
only ever exposed against a token that was **already stolen** — which is the
threat it exists for, and 30 seconds is a reasonable answer to it.

15 minutes sits inside the 5–15 minute range current practice recommends, with
anything over 60 minutes said to need explicit justification.

## A refresh family's 30 days is absolute, not sliding
_2026-09-04, brief 03_ — `R2` inherits `R1`'s `expires_at`. The 30 days runs
from **login**, not from the most recent rotation, so a family dies 30 days
after it was born however often it is used.

[decisions-tokens.md](./decisions-tokens.md) says "30-day rotating refresh" and
does not say which, so this resolves it in the bounded direction.

**Rejected: a sliding expiry**, which is the more common implementation and is
friendlier — nobody active ever re-authenticates. It was rejected because it
makes a family **immortal for as long as anyone keeps rotating it**, and the
party most likely to rotate quietly every fourteen minutes forever is a thief.
The reuse alarm only fires when the *victim* returns, and a victim who has
stopped using the app never returns. A sliding window therefore hands unbounded
persistence to exactly the party the rotation scheme exists to catch.

The cost is accepted and is real: an active person re-enters their password
about once a month. Reversing it is one argument at one call site
(`completeRotation`), so this is cheap to revisit — but it should be revisited
deliberately, not discovered.

## Logout revokes the family; it does not delete rows
_2026-09-04, brief 03_ — `POST /logout` marks the family
`revoked_reason = 'logout'` rather than deleting it. Nothing usable remains —
`claimRefreshToken` cannot match a revoked row — and the natural-expiry sweep
removes it later.

This is a **deliberate departure from brief 03's literal wording**, which said
"deletes the refresh row". Recorded because the brief's text and the code
disagree and a future reader will otherwise think one of them is a mistake.

**Rejected: `DELETE`.** The `revoked_reason` column exists precisely so the
console can tell an ordinary logout from a rotation from a theft signal, and
deleting the row erases exactly what an operator investigating a stolen session
needs to see. "Leaves no refresh row" was read as "leaves no *usable* row",
which is the property the acceptance criterion was actually after.

## The access token carries a `sid` claim, so revocation is per-session
_2026-09-04, after brief 04_ — The access token carries the **refresh family's
id** as `sid`, and introspection asks whether *that family* is live rather than
whether the account holds any live family at all.

Brief 04 found the gap and documented it instead of overclaiming: `jti` is a
fresh UUID that is **never persisted**, and no other claim named the family, so
a revoked family could not be linked to a still-valid access token. The
strongest sound statement available then was *an account with no live refresh
token has no live session* — which catches logout on a single-session account,
reuse sweeps, admin revoke-all, lapsed families, disabled and deleted accounts,
and misses exactly one case: **one family revoked while another stays live.**

That case is the whole reason the self-service UI exists.
[decisions.md](./decisions.md) justifies it on one feature — *"sign out my other
devices is the only self-serve response available to someone who suspects their
session was stolen"* — and without `sid` the signed-out device kept
introspecting `active: true` for its full 15 minutes, against an attacker who by
hypothesis is actively using the token. So this was closed rather than accepted.

**This does not contradict [the no-permissions-in-claims rule](./decisions-tokens.md).**
That rule exists because a token minted before a grant changed would carry
**stale authority** for its whole lifetime. A session id cannot go stale that
way: it names a row, and the row's liveness is looked up fresh on every
introspection. `sid` carries identity, not authority — and it is the standard
OIDC name for exactly this, which is why it was not invented here.

**Required, not optional**, in both the claim and the mint parameter. An
optional one lets a call site mint a silently unlinkable token, and introspection
then has to decide what an absent `sid` means — where the only safe answer is
"not live", which turns a forgotten argument into an outage instead of a
compile error. Nothing is deployed, so requiring it costs nothing.

**Rejected: an `iat`-ordering heuristic** — refusing any token issued later than
the newest live refresh row. Brief 04 considered and declined it, and the
reasoning is worth keeping: it catches roughly half the two-family orderings, it
rests on an invariant in a file that brief did not own, and its failure mode is
**spuriously signing a legitimate person out of six apps**. Half a fix presented
as a whole one, at the cost of a possible owner lockout.

`hasLiveFamily` also requires the family's row to **belong to the subject**.
That pairing cannot be forged through `/introspect`, which reads `sub` and `sid`
off the same verified token — but the safety was living in the caller, and
brief 09's "sign out my other devices" is precisely the shape that pairs a
subject from a session with a family id from a request.
