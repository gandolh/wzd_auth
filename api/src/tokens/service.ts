import type { JSONWebKeySet } from "jose";
import { loadKeySet, type WardKeySet } from "./keys.js";
import { signAccessToken, type MintedAccessToken } from "./mint.js";
import { createJwksKeyStore, verifyAccessToken, type WardKeyStore } from "./verify.js";
import type { AccessTokenClaims } from "./claims.js";

/**
 * The Ward-bound token surface: the same mint and verify as `mint.ts` and
 * `verify.ts`, with the signing key and `iss` already filled in from
 * configuration. This is what the rest of the API imports; briefs 03 and 04
 * should never need to hold a key or an issuer themselves.
 *
 * **This is the only module in `tokens/` that knows `config.js` exists**, and it
 * reaches it through a *dynamic* import for the reason `db/connection.ts`
 * documents: a static import is hoisted, so it would run zod validation — and
 * its `process.exit(1)` — merely because something imported `signAccessToken`.
 * Everything else here stays pure and takes its inputs as arguments, which is
 * also what lets brief 08 lift `verify.ts` into `@ward/client` untouched.
 */

/**
 * Loaded once per process and cached. The key file is read at boot (see
 * `routes/jwks.ts`, which awaits this during registration) and never again —
 * so a rotation is picked up by restarting Ward, which is what step 3 of the
 * procedure in `keys.ts` says to do. Reloading on a file watch was considered
 * and rejected: a half-written key file appearing mid-flight would take the
 * estate's signing down with no operator present, and a restart is already
 * required to be safe.
 */
let keySetPromise: Promise<WardKeySet> | undefined;
let keyStore: WardKeyStore | undefined;

/**
 * Load — or return the already-loaded — key set.
 *
 * Rejects with `SigningKeyError` if the key file is missing, unreadable, or not
 * an Ed25519 private key, and the message names `npm run keygen` as the fix.
 * Because `routes/jwks.ts` awaits this while `buildApp()` runs, that rejection
 * is a boot failure: Ward does not start without a key, in any environment.
 */
export async function getKeySet(): Promise<WardKeySet> {
  keySetPromise ??= (async () => {
    const { WARD_SIGNING_KEY_PATH } = await import("../config.js");
    return loadKeySet(WARD_SIGNING_KEY_PATH);
  })();
  return keySetPromise;
}

/**
 * The published JWKS, exactly as `GET /.well-known/jwks.json` serves it: public
 * parameters only, deep-frozen, current key first. A caller cannot get from
 * this to a private key — the private halves are not reachable from the object
 * this returns.
 */
export async function getPublicJwks(): Promise<JSONWebKeySet> {
  return (await getKeySet()).jwks;
}

/**
 * Mint an access token for a subject. **The whole API: a subject in, a token
 * out.** No claims parameter — see the note in `mint.ts` about why permissions
 * cannot travel in a token.
 *
 * Always signs with the *current* key, never the previous one, even mid
 * rotation. Brief 03 calls this on login and on refresh.
 */
export async function mintAccessToken(
  subject: string,
  sessionId: string,
): Promise<MintedAccessToken> {
  const [keySet, { WARD_PUBLIC_ORIGIN }] = await Promise.all([getKeySet(), import("../config.js")]);
  return signAccessToken({
    subject,
    sessionId,
    signingKey: keySet.current,
    issuer: WARD_PUBLIC_ORIGIN,
  });
}

/**
 * Verify a token Ward itself received — brief 04's `/introspect` is the caller
 * that matters. Checks against Ward's own published key set, so a token signed
 * by the previous key during a rotation still verifies.
 *
 * Remember what this does not answer: the signature stays good for the full 15
 * minutes after the session was revoked. Liveness is a database read, and it is
 * introspection's other half.
 *
 * ## Why this takes a token and nothing else
 *
 * **A token is the only input, on purpose.** Every claim check is pinned here
 * and none of them is expressible by a caller. That is structural rather than
 * conventional, and the difference is the whole point: an earlier version took
 * a `Partial<VerifyAccessTokenOptions>` and spread it *after* the pinned
 * issuer, so any call site could — and would still type-check —
 *
 *  - extend a token's life without bound (`clockToleranceSeconds`, which `jose`
 *    applies as `exp <= now - tolerance`, so one `86_400` written while chasing
 *    imagined clock skew makes every expired token in the estate introspect as
 *    authentic),
 *  - accept any issuer at all (`issuer: undefined` — `requiredClaims` forces
 *    only *presence*, and `jose` gates the value check on the option being
 *    defined),
 *  - accept any audience (`audience`),
 *  - or backdate the clock (`currentDate`).
 *
 * Reordering the spread was rejected as the fix. A reorder still type-checks
 * every one of those fields, so it survives exactly until the next refactor.
 *
 * `clockToleranceSeconds` was **removed from this surface entirely** rather than
 * clamped to a ceiling. A clamp is a second number to justify, and there is
 * nothing to justify it with: every verifier in the estate runs on the same box
 * as Ward, so the 5 seconds `claims.ts` already documents is the answer, and a
 * caller with a real skew problem has a clock to fix rather than a tolerance to
 * widen. `currentDate` stays reachable on the lower-level `verifyAccessToken`,
 * where the tests that need to move time live and where no production path
 * goes.
 *
 * `algorithms` was already pinned inside `verifyAccessToken` and is untouched.
 *
 * Because there is no options parameter, extra arguments forced past the
 * compiler (`as unknown as ...`) are not read at runtime either — the guarantee
 * does not rest on the type checker alone, and `tokens.test.ts` asserts that.
 */
export async function verifyWardAccessToken(token: string): Promise<AccessTokenClaims> {
  const [keySet, { WARD_PUBLIC_ORIGIN }] = await Promise.all([getKeySet(), import("../config.js")]);
  keyStore ??= createJwksKeyStore(keySet.jwks);
  return verifyAccessToken(token, keyStore, { issuer: WARD_PUBLIC_ORIGIN });
}

/**
 * Drop the cached key set. For tests that point `WARD_SIGNING_KEY_PATH` at a
 * fresh temporary key between cases; nothing in the running service calls it.
 */
export function resetTokenServiceForTests(): void {
  keySetPromise = undefined;
  keyStore = undefined;
}
