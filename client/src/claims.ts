/**
 * The access token's shape, mirrored from `api/src/tokens/claims.ts`.
 *
 * This package may not import from `api/` — brief 08's isolation rule — so
 * these constants are reimplemented rather than shared. They must stay in
 * lockstep with Ward's own `claims.ts` by construction: the value on the wire
 * is Ward's, and a drift here would silently reject (or worse, silently
 * accept) tokens Ward actually mints. If Ward ever changes one of these, the
 * fix is here too.
 */

/**
 * The one algorithm Ward signs with and the one this package accepts.
 *
 * A literal, never read off a token's `alg` header. That is the whole defence
 * against the `alg`-confusion bug class (`alg: "none"`, HS256-with-the-public-
 * key, and so on) — see `verify.ts` for where this constant is actually used.
 */
export const ACCESS_TOKEN_ALG = "EdDSA" as const;

/** The `aud` claim every Ward access token carries. A fixed estate-wide value. */
export const ACCESS_TOKEN_AUDIENCE = "ward-estate";

/**
 * Default clock-skew allowance in seconds, matching Ward's own.
 * Every verifier in the estate runs on the same box as Ward, so real skew is
 * effectively zero; this only matters when developing against a deployed Ward
 * from elsewhere. Kept tight — a large tolerance quietly extends token life.
 */
export const ACCESS_TOKEN_CLOCK_TOLERANCE_SECONDS = 5;

/**
 * The introspection cache window: **30 seconds**.
 *
 * This is the number that matters, per
 * `corpus/wiki/decisions-tokens.md` ("15-minute access tokens, 30-second
 * introspection cache") — it is what a revocation waits on. Do not raise it to
 * paper over Ward being slow; fix the slowness instead. Lowering it is safe
 * but pointless below Ward's own read latency.
 */
export const DEFAULT_INTROSPECTION_CACHE_TTL_MS = 30_000;

/**
 * The verified claim set of a Ward access token.
 *
 * No permissions, no roles — that is deliberate and is Ward's rule, not this
 * package's: a token minted before a grant changed would carry stale authority
 * for its whole 15-minute life. Authority comes from `introspect`, never from
 * these claims.
 */
export interface AccessTokenClaims {
  /** The Subject — stable, opaque, never recycled. The join key for an app's own rows. */
  sub: string;
  /** Unique per token. Not needed by consumers; kept because stripping it serves no purpose. */
  jti: string;
  /**
   * The refresh family this token was minted under. Not needed by consumers
   * directly — Ward reads it during introspection — but never strip it from a
   * claim set you pass along.
   */
  sid: string;
  /** Issued-at, seconds since the epoch. */
  iat: number;
  /** Expiry, seconds since the epoch. */
  exp: number;
  /** The bare origin that signed this token. */
  iss: string;
  /** `ACCESS_TOKEN_AUDIENCE`. */
  aud: string;
}
