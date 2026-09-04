# Task 02 — Signing keys, JWKS, and access-token minting

## Context

[Only Ward can sign](../../wiki/decisions-tokens.md#only-ward-can-sign-apps-get-a-key-that-can-only-verify):
EdDSA, private key held by Ward alone, public key published so apps can verify
and nothing more. A shared HMAC secret was rejected because it lets any one
compromised app mint identity for all six.

## Files you OWN

- `api/src/tokens/**` — key loading, JWKS, access-token mint and verify
- `api/src/routes/jwks.ts`

## Files you must NOT touch

`api/src/db/**` (brief 01), login and refresh (brief 03), introspection
(brief 04).

## What to do

1. **`jose`**, pinned exact. It supports EdDSA and JWKS with no native build.
2. **Key material.** An Ed25519 keypair loaded from `WARD_SIGNING_KEY_PATH`.
   Generate one with a documented command if absent in development; **refuse to
   boot** without one in production rather than generating silently — a key that
   regenerates on restart invalidates every live token and looks like an outage.
3. **`GET /.well-known/jwks.json`** — public key only, with a `kid`. This is
   the one route apps fetch. Cacheable.
4. **Mint** an access token: `sub` (the subject), `jti`, `iat`, `exp` at **15
   minutes**, `iss` = `WARD_PUBLIC_ORIGIN`, `aud` = the estate.
   **No permissions in the claims** — a token minted before a grant changed
   would carry stale authority for its whole lifetime, which is precisely what
   [the decision](../../wiki/decisions-tokens.md) forbids.
5. **Verify** helper, used by Ward itself and re-exported through the client
   package (brief 08). Pin the accepted algorithm to EdDSA explicitly. Never
   accept `alg` from the token — that is the `alg`-confusion bug class the
   decisions page names.
6. **Key rotation:** support two keys in the JWKS (current + previous) so a
   rotation does not sign everyone out. Document the procedure.

## Acceptance

- A minted token verifies against the published JWKS and nothing else.
- A token signed with a different key, or with `alg: none`, or with `alg` set to
  an HMAC variant, is rejected — one test each. This is the highest-value test
  in the brief.
- `exp` is 15 minutes; changing it is one constant with a comment pointing at
  the decision.
- Deleting the key file stops the service starting in production, loudly.

---

## Outcome — landed 2026-09-02

Ed25519 signing keys, `GET /.well-known/jwks.json`, 15-minute access tokens,
and a verify helper. All acceptance criteria met. As with brief 01, the
implementing agent was killed by a quota limit after finishing the work but
before reporting; the contracts below were reconstructed from source by the
controller.

### The ruling that resolved an ambiguity in the brief

The brief said "generate in development, refuse to boot in production."
`config.ts` has **no `NODE_ENV`** — brief 00 deliberately gave the environment
contract no environment branch — so the resolution was to drop the distinction
entirely: **Ward never generates a signing key, in any environment.** A missing
key is a hard boot failure naming `npm run keygen`. Key creation is an explicit
human act. This is strictly safer than the brief's own wording and needs no
environment detection, because a key that regenerates on restart invalidates
every live token and looks like an outage.

`npm run keygen` writes `0600` and refuses to overwrite a live key without
`--force`.

### What is structurally guaranteed, not merely careful

Two properties were confirmed by review to hold by construction rather than by
discipline, which is worth recording so nobody "simplifies" them away:

- **Private material cannot reach the JWKS.** The published JWK is built
  field-by-field from an allowlist off a separate public `KeyObject`, and an
  unexpected parameter fails at **boot**. A future key type or library version
  adding a field cannot leak it — it refuses to start instead.
- **The algorithm is genuinely pinned.** `algorithms: ["EdDSA"]` is a literal
  with no input path, and the option type has no `algorithms` field. Confirmed
  rejected: `alg: "none"`, `alg: "HS256"` signed with the public key's own bytes
  (the classic confusion attack), `alg: "Ed25519"`, and `alg: "constructor"` —
  the last of which would otherwise index the library's algorithm lookup table
  into `Object`.

### Review findings fixed before closeout

- **Every claim check except the algorithm was caller-overridable.** Options
  were spread *after* the pinned issuer, so a call site could set
  `clockToleranceSeconds` (an unbounded lifetime extension), `issuer: undefined`
  (accepting any issuer), or `currentDate` (backdating the clock). All three
  were confirmed by execution. The trust-critical claims are now
  **not expressible** by a caller, at the type level and at runtime — a spread
  reorder was rejected as a fix, because it still type-checks the dangerous
  fields and the next refactor reintroduces the hole. This mattered because
  brief 08 re-exports this surface into six apps.
- **`keygen --force` could not restore `0600`** and printed `0600` regardless —
  `writeFile`'s `mode` applies only on create, so a forced overwrite inherited
  whatever permissions the existing file had. Now chmods explicitly and reports
  the mode it actually observes.
- **The loader never checked key permissions** — it booted silently on a
  world-readable key. Now warns at boot (warn, not refuse: refusing on a
  permission bit turns hardening into an outage, and the operator may be
  mid-recovery).
- **The previous-key slot was additive trust granted by a filename.** Any
  Ed25519 key appearing at `<key>.previous.pem` was published and trusted —
  confirmed by minting a valid token for an arbitrary subject with an unrelated
  key. Note the asymmetry: filling that slot needs only **write** access to the
  key directory, while abusing the current key needs **read** access. Now logs
  at `warn` with the lifecycle documented.
- **`jwksUrl`'s default base path resolved to a 404.** Ward is served under
  `/ward-api/*`, so the documented usage would have made all six apps fetch
  nothing and reject every token — an estate-wide lockout on the deploy that
  ships `@ward/client`. Fails closed, so availability rather than a bypass.

### Rotation lifecycle

The JWKS publishes current + previous so a rotation does not sign everyone out.
Minting **always** uses current. `kid` is an RFC 7638 thumbprint — stable and
derivable rather than invented. The previous slot is safe to delete once one
access-token lifetime (15 minutes) has elapsed since the rotation; leaving it
populated means permanently trusting two keys.

One residual sharp edge, recorded rather than fixed because no call site is
wrong today: "current signs" is conventional, not structural. `getKeySet()`
exposes `.previous`, and the lower-level `signAccessToken` accepts any key, so a
future brief *could* sign with the outgoing key without tripping anything.
**Briefs 03 and 04 should mint through `mintAccessToken(subject)` and nothing
else.**

### Note for brief 04 (introspection)

The library's `JWTExpired` / `JWTClaimValidationFailed` errors carry a `payload`
own-property holding the decoded claims, and pino's error serializer copies own
properties — so logging that `cause` puts `sub` and `jti` in the log. Those are
not credentials and it is not a defect, but **the raw token must never join
them**, and Fastify's default request log already carries the query string.
