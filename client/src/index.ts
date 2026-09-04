/**
 * `@ward/client` — the framework-agnostic core.
 *
 * Six apps have to do the same three things: verify the access token
 * locally, ask Ward whether the session is live and what it may do, and cache
 * that answer for 30 seconds. Written once here, or written wrong six times.
 *
 * This entry point has no Fastify dependency. `@ward/client/fastify` is the
 * thin plugin built on top of it — see that module for the Fastify-specific
 * wiring (`request.ward`, `app.wardAuthenticate`, `app.wardRequireGrant`).
 *
 * See `client/README.md` for a full wiring example, including the
 * `/ward-api` base path every app in this estate must pass.
 */

export {
  createWardClient,
  requireGrant,
  type WardClient,
  type WardClientOptions,
} from "./client.js";

export {
  type ActiveSession,
  type InactiveSession,
  type GrantsByApp,
  type SessionResolution,
  hasGrant,
} from "./session.js";

export { WardAuthenticationError, WardForbiddenError, WardUnavailableError } from "./errors.js";

export { readAccessCookie } from "./cookie.js";

export type { AccessTokenClaims } from "./claims.js";
export {
  ACCESS_TOKEN_ALG,
  ACCESS_TOKEN_AUDIENCE,
  DEFAULT_INTROSPECTION_CACHE_TTL_MS,
} from "./claims.js";

// Lower-level surfaces — the ones brief 08 was told to wrap from
// `api/src/tokens/verify.ts`. Most apps want `createWardClient` above and
// never touch these directly; they are exported for a consumer that wants to
// control JWKS fetching or verification itself (or that is only verifying,
// with no need for the introspection cache).
export {
  jwksUrl,
  createRemoteJwksKeyStore,
  verifyAccessToken,
  type WardKeyStore,
  type VerifyAccessTokenOptions,
} from "./verify.js";
