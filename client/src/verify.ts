import { createRemoteJWKSet, jwtVerify } from "jose";
import {
  ACCESS_TOKEN_ALG,
  ACCESS_TOKEN_AUDIENCE,
  ACCESS_TOKEN_CLOCK_TOLERANCE_SECONDS,
  type AccessTokenClaims,
} from "./claims.js";
import { WardAuthenticationError } from "./errors.js";

/**
 * Local, offline verification of a Ward access token.
 *
 * This is the reimplementation of `api/src/tokens/verify.ts`'s public surface
 * (`createRemoteJwksKeyStore`, `jwksUrl`, and the verification call) that
 * brief 08 was told to wrap rather than import — this package may not depend
 * on `api/`. The behaviour matches exactly:
 *
 * 1. **`algorithms: [ACCESS_TOKEN_ALG]` is passed on every call.** This is a
 *    literal, never derived from the token's own `alg` header. Without it,
 *    `jose` would accept whatever algorithm the resolved key happens to
 *    support, which is the `alg`-confusion bug class named in
 *    `corpus/wiki/decisions-tokens.md` — `alg: "none"`, and `alg: "HS256"`
 *    with the *public* key's own bytes handed over as the HMAC secret (a
 *    public key being, by definition, something an attacker already has).
 * 2. **The key is resolved by `kid` out of the JWKS, never read from the
 *    token.** `createRemoteJWKSet` treats the JOSE header purely as a
 *    *selector* over a key set fetched independently of the token in hand.
 */

/** A resolver over Ward's published keys, as `jose` returns it. */
export type WardKeyStore = ReturnType<typeof createRemoteJWKSet>;

/**
 * Where Ward publishes its keys, given the estate's public origin and Ward's
 * API base path behind the reverse proxy.
 *
 *     jwksUrl("https://gandolh.ro", "/ward-api")
 *     // -> https://gandolh.ro/ward-api/.well-known/jwks.json
 *
 * **`apiBasePath` is required and has no default.** It used to default to
 * `""`, which resolved to `https://<origin>/.well-known/jwks.json` — a path
 * nothing serves, because Caddy reverse-proxies Ward under `/ward-api/*`. That
 * shipped once, review caught it before it reached a consumer, and the fix was
 * to make the mistake a compile error instead of a 404: every app in this
 * estate must pass `"/ward-api"` explicitly. Pass `""` only for a Ward served
 * at the root of its own origin (a bare local test server, say).
 */
export function jwksUrl(publicOrigin: string, apiBasePath: string): URL {
  return new URL(`${apiBasePath.replace(/\/+$/, "")}/.well-known/jwks.json`, publicOrigin);
}

/**
 * A key store that fetches and caches Ward's JWKS over HTTP.
 *
 * **What this caches, and for how long — read before tuning either option:**
 *
 * - `cacheMaxAge` (default 10 minutes, matching Ward's own default) bounds how
 *   long a *successfully fetched* JWKS document is trusted before `jose` will
 *   go fetch it again on its own, even if every `kid` seen so far still
 *   resolves. Within that window, verifying a token whose `kid` is already
 *   known costs **no network call at all** — the keys live in memory on this
 *   object.
 * - When a token arrives with a `kid` that is *not* in the cached set — the
 *   shape a rotation takes — `jose` refetches to look for it, so a rotation is
 *   picked up without restarting the consumer, **provided** the last fetch
 *   was more than `cooldownDuration` ago (30 seconds by default). That floor
 *   is what stops a burst of tokens signed by an unknown key from becoming a
 *   stampede against Ward's JWKS endpoint: within the cooldown window, an
 *   unmatched `kid` fails fast instead of triggering a second fetch. In
 *   practice this never delays a real rotation, because an app's *first*
 *   request is essentially always more than 30 seconds before anyone
 *   deliberately rotates a key — but a test that mints a rotated-key token in
 *   the same tick as the first fetch needs `cooldownDurationMs: 0` to see the
 *   refetch happen immediately.
 *
 * **This is a completely different cache from `introspect`'s 30-second one,
 * and they answer different questions.** This cache is about not re-fetching
 * a public-key document that changes maybe once a quarter; it establishes
 * *authenticity* (this token was signed by a key Ward published) and has
 * nothing to say about whether the session behind it is still live. Raising
 * `cacheMaxAge` here does not slow down revocation, and lowering the
 * introspection TTL does not make a key rotation land faster — conflating the
 * two is the mistake this comment exists to prevent.
 */
export function createRemoteJwksKeyStore(
  jwksEndpoint: URL,
  options?: { timeoutMs?: number; cacheMaxAgeMs?: number; cooldownDurationMs?: number },
): WardKeyStore {
  return createRemoteJWKSet(jwksEndpoint, {
    timeoutDuration: options?.timeoutMs ?? 5_000,
    cacheMaxAge: options?.cacheMaxAgeMs ?? 10 * 60_000,
    cooldownDuration: options?.cooldownDurationMs ?? 30_000,
  });
}

/** Options for `verifyAccessToken`. `issuer` is required — an unpinned `iss` verifies nothing useful. */
export interface VerifyAccessTokenOptions {
  /** Expected `iss`: Ward's public origin, exactly, no trailing slash. */
  issuer: string;
  /** Expected `aud`. Defaults to `ACCESS_TOKEN_AUDIENCE`. */
  audience?: string;
  /** Clock skew allowance in seconds. Defaults to `ACCESS_TOKEN_CLOCK_TOLERANCE_SECONDS`. */
  clockToleranceSeconds?: number;
  /** The moment to compare `exp`/`iat` against. Tests only. */
  currentDate?: Date;
}

/**
 * Verify a compact JWS against Ward's keys and return its claims.
 *
 * Throws `WardAuthenticationError` for a token that is malformed, unsigned
 * (`alg: "none"`), signed with anything other than EdDSA, signed by a key not
 * in the key store, expired, not yet valid, or carrying the wrong `iss`/`aud`.
 *
 * This establishes **authentication only** — that Ward signed this token for
 * this subject. It says nothing about **liveness**: the signature stays valid
 * for the token's full 15 minutes even after the session behind it is
 * revoked. Call `introspect` for that; never treat a verified signature alone
 * as permission to proceed.
 */
export async function verifyAccessToken(
  token: string,
  keyStore: WardKeyStore,
  options: VerifyAccessTokenOptions,
): Promise<AccessTokenClaims> {
  let payload: Record<string, unknown>;
  try {
    const result = await jwtVerify(token, keyStore, {
      // Pinned, not derived from the token. See the header comment.
      algorithms: [ACCESS_TOKEN_ALG],
      issuer: options.issuer,
      audience: options.audience ?? ACCESS_TOKEN_AUDIENCE,
      clockTolerance: options.clockToleranceSeconds ?? ACCESS_TOKEN_CLOCK_TOLERANCE_SECONDS,
      ...(options.currentDate ? { currentDate: options.currentDate } : {}),
      requiredClaims: ["sub", "jti", "sid", "iat", "exp", "iss", "aud"],
      typ: "JWT",
    });
    payload = result.payload as Record<string, unknown>;
  } catch (cause) {
    throw new WardAuthenticationError("access token is not valid", { cause });
  }

  const { sub, jti, sid, iat, exp, iss, aud } = payload;
  if (
    typeof sub !== "string" ||
    typeof jti !== "string" ||
    typeof sid !== "string" ||
    typeof iat !== "number" ||
    typeof exp !== "number" ||
    typeof iss !== "string" ||
    typeof aud !== "string"
  ) {
    throw new WardAuthenticationError(
      "access token verified but its claims are not the shape Ward mints",
    );
  }

  return { sub, jti, sid, iat, exp, iss, aud };
}
