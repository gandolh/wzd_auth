import { createLocalJWKSet, createRemoteJWKSet, jwtVerify } from "jose";
import type { JSONWebKeySet } from "jose";
import {
  ACCESS_TOKEN_ALG,
  ACCESS_TOKEN_AUDIENCE,
  ACCESS_TOKEN_CLOCK_TOLERANCE_SECONDS,
  type AccessTokenClaims,
} from "./claims.js";

/**
 * Verifying a Ward access token.
 *
 * This module is the one brief 08 re-exports through `@ward/client`, so it is
 * written to be liftable: its only import is `jose` and its own constants, it
 * never touches `config.js`, `node:fs`, Fastify or the database, and every
 * input arrives as an argument. Importing it has no side effects, which matters
 * because it will end up inside six other applications.
 *
 * ## The two things that must never change
 *
 * 1. **`algorithms: [ACCESS_TOKEN_ALG]` is passed on every call.** Without it,
 *    `jose` accepts any algorithm the resolved key happens to support, and the
 *    header's `alg` starts steering the verification. That is the
 *    `alg`-confusion class named in wiki/decisions-tokens.md, in both its
 *    classic forms: `alg: "none"`, and `alg: "HS256"` with the *public* key's
 *    bytes handed over as the HMAC secret — a public key being, by definition,
 *    something the attacker already has.
 * 2. **The key comes from the JWKS, resolved by `kid`, never from the token.**
 *    `createLocalJWKSet` and `createRemoteJWKSet` both take the JOSE header only
 *    as a *selector* over a key set that was fetched out of band. Nothing here
 *    ever reads embedded key material (`jwk`, `jku`, `x5u` header parameters).
 */

/**
 * A resolver over Ward's published keys. Both constructors below return one,
 * and both pick the key by `kid`/`alg`/`use` out of a set the caller obtained
 * independently of the token.
 */
export type WardKeyStore =
  ReturnType<typeof createLocalJWKSet> | ReturnType<typeof createRemoteJWKSet>;

/**
 * A key store over a JWKS already in hand — the JSON body of
 * `GET /.well-known/jwks.json`. Used inside Ward, and by any consumer that
 * wants to control fetching itself.
 *
 * Handles rotation for free: a two-key set resolves either `kid`, so tokens
 * signed by the outgoing key keep verifying until they expire.
 */
export function createJwksKeyStore(jwks: JSONWebKeySet): WardKeyStore {
  return createLocalJWKSet(jwks);
}

/**
 * A key store that fetches and caches Ward's JWKS over HTTP — the shape brief
 * 08's `@ward/client` wants, since an app must pick up a rotated key without a
 * redeploy. `jose` refetches when it meets an unknown `kid`, rate-limited
 * internally, so a rotation costs one extra request rather than a stampede.
 */
export function createRemoteJwksKeyStore(
  jwksUrl: URL,
  options?: { timeoutMs?: number; cacheMaxAgeMs?: number },
): WardKeyStore {
  return createRemoteJWKSet(jwksUrl, {
    timeoutDuration: options?.timeoutMs ?? 5_000,
    cacheMaxAge: options?.cacheMaxAgeMs ?? 10 * 60_000,
  });
}

/** Where Ward publishes its keys, given the estate's public origin and Ward's API base path. */
export function jwksUrl(publicOrigin: string, apiBasePath = ""): URL {
  return new URL(`${apiBasePath.replace(/\/+$/, "")}/.well-known/jwks.json`, publicOrigin);
}

/** Options for `verifyAccessToken`. `issuer` is required — an unpinned `iss` verifies nothing useful. */
export interface VerifyAccessTokenOptions {
  /** Expected `iss`: `WARD_PUBLIC_ORIGIN`, exactly, with no trailing slash. */
  issuer: string;
  /** Expected `aud`. Defaults to `ACCESS_TOKEN_AUDIENCE`. */
  audience?: string;
  /** Clock skew allowance in seconds. Defaults to `ACCESS_TOKEN_CLOCK_TOLERANCE_SECONDS`. */
  clockToleranceSeconds?: number;
  /** The moment to compare `exp`/`iat` against. Tests use it; nothing else should. */
  currentDate?: Date;
}

/**
 * Every rejection, as one type.
 *
 * The message is deliberately coarse — "expired" and "signed by an unknown key"
 * are the same answer to a caller. `cause` carries `jose`'s own error for the
 * log, which is where the detail belongs; brief 04's `/introspect` must not
 * relay it to the caller, since "why is this token bad" is an oracle.
 */
export class AccessTokenVerificationError extends Error {
  override readonly name = "AccessTokenVerificationError";

  constructor(message: string, options?: { cause?: unknown }) {
    super(message, options);
  }
}

/**
 * Verify a compact JWS against Ward's keys and return its claims.
 *
 * Rejects — by throwing `AccessTokenVerificationError` — a token that is
 * malformed, unsigned (`alg: "none"`), signed with any algorithm other than
 * EdDSA, signed by a key that is not in the key store, expired, not yet valid,
 * or carrying the wrong `iss` or `aud`. Resolving to a claim set means all of
 * those passed.
 *
 * What it does **not** establish is liveness: the signature stays valid for the
 * full 15 minutes after a session is revoked. That is introspection's job
 * (brief 04), and the distinction is the one the glossary's "Introspection"
 * entry exists to keep sharp.
 */
export async function verifyAccessToken(
  token: string,
  keyStore: WardKeyStore,
  options: VerifyAccessTokenOptions,
): Promise<AccessTokenClaims> {
  let payload: Record<string, unknown>;
  try {
    const result = await jwtVerify(token, keyStore, {
      // Pinned. See the header comment — this single line is what closes the
      // `alg: none` and HMAC-confusion attacks, and it is not derived from the
      // token in any way.
      algorithms: [ACCESS_TOKEN_ALG],
      issuer: options.issuer,
      audience: options.audience ?? ACCESS_TOKEN_AUDIENCE,
      clockTolerance: options.clockToleranceSeconds ?? ACCESS_TOKEN_CLOCK_TOLERANCE_SECONDS,
      ...(options.currentDate ? { currentDate: options.currentDate } : {}),
      // `jose` requires `exp` only when it is present; naming these makes a
      // token that simply omits one a rejection rather than a token that never
      // expires. `typ` pins the header so a JWT of some other purpose — a
      // future signed email link, say — cannot be replayed as a session.
      requiredClaims: ["sub", "jti", "iat", "exp", "iss", "aud"],
      typ: "JWT",
    });
    payload = result.payload as Record<string, unknown>;
  } catch (cause) {
    throw new AccessTokenVerificationError("access token is not valid", { cause });
  }

  // `jose` has verified presence and the registered-claim semantics; this
  // narrows the types so callers get `AccessTokenClaims` rather than a bag of
  // `unknown`. `aud` can legitimately be an array in JOSE — Ward mints a single
  // string, and anything else is not a token Ward minted.
  const { sub, jti, iat, exp, iss, aud } = payload;
  if (
    typeof sub !== "string" ||
    typeof jti !== "string" ||
    typeof iat !== "number" ||
    typeof exp !== "number" ||
    typeof iss !== "string" ||
    typeof aud !== "string"
  ) {
    throw new AccessTokenVerificationError(
      "access token verified but its claims are not the shape Ward mints",
    );
  }

  return { sub, jti, iat, exp, iss, aud };
}
