---
summary: The locked calls about sessions and tokens — the short-lived signed access token, the opaque rotating refresh token, introspection-with-cache as the revocation mechanism, why there is no JWT denylist, EdDSA signing held by Ward alone, and the two lifetimes that define the logout delay.
updated: 2026-09-01
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
