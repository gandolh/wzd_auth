import { randomUUID } from "node:crypto";
import { SignJWT } from "jose";
import { ACCESS_TOKEN_ALG, ACCESS_TOKEN_AUDIENCE, ACCESS_TOKEN_TTL_SECONDS } from "./claims.js";
import type { WardSigningKey } from "./keys.js";

/**
 * Minting an access token — the pure half, with the signing key and the issuer
 * passed in. `service.ts` is what binds this to Ward's configuration.
 *
 * **There is no parameter for extra claims, and that is the point.** Permissions,
 * roles and grants are forbidden in the token by wiki/decisions-tokens.md: a
 * token minted before a grant changed would carry stale authority for its whole
 * 15 minutes, whereas authority carried in the introspection response (brief 04)
 * changes in the same 30-second window a revocation does. Making the signer take
 * only a subject means nobody can add a claim in a hurry from a call site — the
 * decision is enforced by the signature of this function rather than by a
 * comment somebody has to read first.
 */

/** What a caller gets back. `jti` and `expiresAt` are here so brief 03 need not decode its own token. */
export interface MintedAccessToken {
  /** The compact JWS. This is what goes in the `Path=/` cookie. */
  readonly token: string;
  /** The token's unique id, already extracted. Audit lines refer to this. */
  readonly jti: string;
  /** `iat`, seconds since the epoch. */
  readonly issuedAt: number;
  /** `exp`, seconds since the epoch. Always `issuedAt + ACCESS_TOKEN_TTL_SECONDS`. */
  readonly expiresAt: number;
  /** Which key signed it — the `kid` in the header. Useful in logs during a rotation. */
  readonly kid: string;
}

/** Everything the signer needs. Note the absence of any way to inject a claim. */
export interface SignAccessTokenParams {
  /** The Subject: Ward's stable opaque account identifier. Not a username, not an app's row id. */
  subject: string;
  /** The key to sign with. Always the *current* key — see `service.ts`. */
  signingKey: WardSigningKey;
  /** `WARD_PUBLIC_ORIGIN`. Compared as an exact string by six verifiers. */
  issuer: string;
  /** Defaults to `ACCESS_TOKEN_AUDIENCE`; a parameter only so tests can mint a wrong-`aud` token. */
  audience?: string;
  /**
   * Issue time. A parameter only so tests can mint a token that is already
   * expired without waiting 15 minutes — there is deliberately no way to
   * override the *lifetime*, which stays `ACCESS_TOKEN_TTL_SECONDS` for every
   * token Ward has ever signed.
   */
  now?: Date;
}

export async function signAccessToken(params: SignAccessTokenParams): Promise<MintedAccessToken> {
  const subject = params.subject;
  if (typeof subject !== "string" || subject.trim().length === 0) {
    // A blank `sub` would mint a valid, correctly-signed token that authenticates
    // nobody in particular — and every app keys its rows on `sub`. Refuse early.
    throw new TypeError("signAccessToken: subject must be a non-empty string");
  }
  if (params.issuer.trim().length === 0) {
    throw new TypeError("signAccessToken: issuer must be a non-empty string");
  }

  const jti = randomUUID();
  // Seconds, floored — `exp` and `iat` are NumericDate, and a fractional value
  // is the kind of thing one verifier in six rounds differently.
  const issuedAt = Math.floor((params.now?.getTime() ?? Date.now()) / 1000);
  const expiresAt = issuedAt + ACCESS_TOKEN_TTL_SECONDS;

  const token = await new SignJWT({})
    // `alg` is the constant, never anything derived from input. `kid` lets a
    // verifier pick the right key out of a two-key JWKS during a rotation
    // without trial-verifying against both.
    .setProtectedHeader({ alg: ACCESS_TOKEN_ALG, kid: params.signingKey.kid, typ: "JWT" })
    .setSubject(subject)
    .setJti(jti)
    .setIssuer(params.issuer)
    .setAudience(params.audience ?? ACCESS_TOKEN_AUDIENCE)
    .setIssuedAt(issuedAt)
    .setExpirationTime(expiresAt)
    .sign(params.signingKey.privateKey);

  return { token, jti, issuedAt, expiresAt, kid: params.signingKey.kid };
}
