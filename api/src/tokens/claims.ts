/**
 * The access token's shape, as constants — the two or three literals that six
 * independent verifiers have to agree on exactly.
 *
 * This module is deliberately dependency-free: no `jose`, no `config.js`, no
 * `node:` anything. Brief 08 re-exports the verification surface through
 * `@ward/client`, which runs inside six other repos, and a constants module
 * that drags Ward's environment validation along with it would call
 * `process.exit(1)` inside somebody else's app on import. Keep it that way.
 */

/**
 * The one algorithm Ward signs with and the one it accepts.
 *
 * Written as a constant and passed explicitly to both the signer and the
 * verifier so that no code path anywhere reads `alg` out of a token header and
 * uses it to pick a verification routine. That is the `alg`-confusion bug class
 * named in wiki/decisions-tokens.md ("Only Ward can sign"), and the defence is
 * not vigilance, it is that the accepted algorithm is a compile-time literal
 * with no input to it.
 */
export const ACCESS_TOKEN_ALG = "EdDSA";

/**
 * The curve behind `EdDSA` here. Ed25519 specifically — `EdDSA` in the JOSE
 * registry also covers Ed448, and Ward does not accept that; key loading
 * rejects anything whose curve is not this.
 */
export const SIGNING_KEY_CURVE = "Ed25519";

/**
 * **Access-token lifetime: 15 minutes.** This is the single constant; changing
 * it is changing this line and nothing else.
 *
 * Locked in wiki/decisions-tokens.md, "15-minute access tokens, 30-second
 * introspection cache". The reasoning worth carrying here is that this number
 * is *not* the number that matters — the 30-second introspection cache is what
 * bounds how long a revoked session keeps working, because apps introspect on
 * every request. All this bounds is how often `/refresh` is hit. 15 minutes
 * sits inside the 5–15 minute range current practice recommends; anything over
 * 60 minutes is said to need explicit justification.
 *
 * Do not extend it to paper over a refresh bug. A longer access token does not
 * make revocation slower (introspection already covers that), but it does widen
 * the window in which a stolen token is useful against any app that has not yet
 * wired introspection up.
 */
export const ACCESS_TOKEN_TTL_SECONDS = 15 * 60;

/**
 * The `aud` claim: the estate, as a single opaque audience string.
 *
 * The estate is one origin (wiki/glossary.md, "Origin"), so there is one
 * audience and every app in it is inside that audience. It is a fixed literal
 * rather than `WARD_PUBLIC_ORIGIN` on purpose: `aud` is compared as an exact
 * string by six verifiers, and tying it to a value an operator edits in `.env`
 * means moving the estate to a new hostname silently invalidates every token
 * that is already in flight, on top of the `iss` change that is unavoidable.
 *
 * Per-app audiences are a deliberate non-feature. Authorisation is a grant
 * (glossary.md, "Grant"), resolved by introspection at request time — not a
 * claim baked into a token 15 minutes ago.
 */
export const ACCESS_TOKEN_AUDIENCE = "ward-estate";

/**
 * Small clock-skew allowance for `exp`/`iat`, in seconds.
 *
 * Every verifier in the estate runs on the same box as Ward, so real skew is
 * zero; this exists for the case where an app is developed on a laptop against
 * a deployed Ward. Kept tight — a large tolerance is a quiet extension of the
 * token lifetime.
 */
export const ACCESS_TOKEN_CLOCK_TOLERANCE_SECONDS = 5;

/**
 * The verified claim set of a Ward access token.
 *
 * Note what is absent, and that the absence is the design: **no permissions, no
 * roles, no grants**. wiki/decisions-tokens.md forbids them outright — a token
 * minted before a grant changed would carry stale authority for its whole
 * lifetime, and the fix is that authority lives in the introspection response
 * (brief 04) where a change lands in the same 30-second window a revocation
 * does. If you are reaching for a place to put a role, this type is not it.
 *
 * `sub` is the **Subject** in the glossary's sense: the stable, opaque
 * identifier Ward gives an account, which apps key their rows on forever. It is
 * not any app's local user id, and it is not a username.
 */
export interface AccessTokenClaims {
  /** The Subject — stable, opaque, never recycled. */
  sub: string;
  /** Unique per token. The handle a revocation or an audit line refers to. */
  jti: string;
  /** Issued-at, seconds since the epoch. */
  iat: number;
  /** Expiry, seconds since the epoch. Always `iat + ACCESS_TOKEN_TTL_SECONDS`. */
  exp: number;
  /** `WARD_PUBLIC_ORIGIN`, exactly — a bare origin with no trailing slash. */
  iss: string;
  /** `ACCESS_TOKEN_AUDIENCE`. */
  aud: string;
}
