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
