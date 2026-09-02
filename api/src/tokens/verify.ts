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

/**
 * Where Ward publishes its keys, given the estate's public origin and Ward's
 * API base path.
 *
 *     jwksUrl("https://gandolh.ro", "/ward-api")
 *     // → https://gandolh.ro/ward-api/.well-known/jwks.json
 *
 * **`apiBasePath` is required, and has no default.** It used to default to `""`,
 * which produced `https://gandolh.ro/.well-known/jwks.json` — a path nothing
 * serves, because Caddy reverse-proxies Ward under `/ward-api/*`. Brief 08's
 * `@ward/client` uses this helper to build every app's remote key store, so the
 * default would have had all six apps fetch a 404, `jose` throw, and every
 * token be rejected: an estate-wide lockout on the deploy that shipped the
 * client. It fails closed, so it was availability rather than a bypass — but a
 * wrong default in a module six repositories copy is a bug waiting for a
 * deploy.
 *
 * Required rather than defaulted to `/ward-api`, because the mistake is then a
 * compile error at the call site instead of a 404 in production, and because
 * this module is deliberately ignorant of Ward's own configuration (it is the
 * one file brief 08 lifts unchanged) — baking this estate's deploy path into it
 * as a default is exactly the knowledge it is not supposed to hold. Pass `""`
 * explicitly for a Ward served at the root of its origin.
 */
export function jwksUrl(publicOrigin: string, apiBasePath: string): URL {
  return new URL(`${apiBasePath.replace(/\/+$/, "")}/.well-known/jwks.json`, publicOrigin);
}

/**
 * Options for `verifyAccessToken`. `issuer` is required — an unpinned `iss`
 * verifies nothing useful.
 *
 * **Every field here except `issuer` weakens verification if it is got wrong,
 * so none of them is reachable from Ward's own entry point.**
 * `service.verifyWardAccessToken` takes a token and nothing else: it pins the
 * issuer from configuration and exposes no options parameter at all, which is
 * what keeps `audience`, `clockToleranceSeconds` and `currentDate` out of
 * production call sites structurally rather than by convention. This type is
 * the lower-level, fully-explicit surface — the one the tests drive and the one
 * brief 08 lifts into `@ward/client`, where the consuming app supplies the
 * issuer itself.
 */
export interface VerifyAccessTokenOptions {
  /** Expected `iss`: `WARD_PUBLIC_ORIGIN`, exactly, with no trailing slash. */
  issuer: string;
  /** Expected `aud`. Defaults to `ACCESS_TOKEN_AUDIENCE`. */
  audience?: string;
  /**
   * Clock skew allowance in seconds. Defaults to
   * `ACCESS_TOKEN_CLOCK_TOLERANCE_SECONDS` (5).
   *
   * `jose` applies it as `exp <= now - tolerance`, so this is an unbounded
   * lifetime extension and not a nicety: a day here is a day of extra life for
   * every stolen token. Leave it alone unless you have measured a real skew.
   */
  clockToleranceSeconds?: number;
  /**
   * The moment to compare `exp`/`iat` against. **Tests only** — and unlike the
   * comment that used to sit here, that is now enforced by reachability rather
   * than asserted: no production entry point can set it, because
   * `verifyWardAccessToken` has no options parameter to set it through.
   */
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
