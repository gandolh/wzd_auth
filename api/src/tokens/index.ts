/**
 * The token layer's public surface.
 *
 * Import from `../tokens/index.js` rather than reaching into individual files —
 * briefs 03 and 04 consume this, and brief 08 re-exports the verification half
 * through `@ward/client`.
 *
 * The split worth knowing about:
 *
 * - **`service.ts`** is Ward-bound. `mintAccessToken(subject)` and
 *   `verifyWardAccessToken(token)` already know the signing key and the issuer.
 *   This is what the API's own routes want.
 * - **`verify.ts` and `mint.ts`** are pure — every input is an argument, and
 *   importing them has no side effects at all. `verify.ts` in particular
 *   imports nothing but `jose` and `claims.ts`, so it lifts into `@ward/client`
 *   (and therefore into six other repositories) unchanged.
 * - **`claims.ts`** holds the literals six independent verifiers must agree on,
 *   including the 15-minute lifetime.
 *
 * `keygen.ts` is intentionally absent: it is a command, not a library, and
 * nothing in the running service should be able to create a key.
 */

export {
  ACCESS_TOKEN_ALG,
  ACCESS_TOKEN_AUDIENCE,
  ACCESS_TOKEN_CLOCK_TOLERANCE_SECONDS,
  ACCESS_TOKEN_TTL_SECONDS,
  SIGNING_KEY_CURVE,
  type AccessTokenClaims,
} from "./claims.js";

export {
  loadKeySet,
  previousSigningKeyPath,
  SigningKeyError,
  type WardKeySet,
  type WardSigningKey,
} from "./keys.js";

export { signAccessToken, type MintedAccessToken, type SignAccessTokenParams } from "./mint.js";

export {
  AccessTokenVerificationError,
  createJwksKeyStore,
  createRemoteJwksKeyStore,
  jwksUrl,
  verifyAccessToken,
  type VerifyAccessTokenOptions,
  type WardKeyStore,
} from "./verify.js";

export {
  getKeySet,
  getPublicJwks,
  mintAccessToken,
  resetTokenServiceForTests,
  verifyWardAccessToken,
} from "./service.js";
