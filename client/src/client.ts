import type { AccessTokenClaims } from "./claims.js";
import { WardAuthenticationError, WardForbiddenError } from "./errors.js";
import { createIntrospector } from "./introspect.js";
import { readAccessCookie } from "./cookie.js";
import {
  jwksUrl,
  createRemoteJwksKeyStore,
  verifyAccessToken,
  type WardKeyStore,
} from "./verify.js";
import type { ActiveSession, SessionResolution } from "./session.js";
import { hasGrant } from "./session.js";

/**
 * The framework-agnostic core: everything an app needs to verify a token,
 * check liveness and authority, and read the session cookie — with no
 * dependency on Fastify or any other framework. `./fastify` is a thin layer on
 * top of exactly this.
 */
export interface WardClientOptions {
  /** Ward's public origin — a bare origin, no trailing slash. Also the expected `iss` unless `issuer` is given. */
  publicOrigin: string;
  /**
   * Ward's API base path behind the reverse proxy — for this estate,
   * `"/ward-api"`. **Required, no default**: see `verify.ts#jwksUrl` for why a
   * default here is exactly the estate-wide-lockout bug this package exists to
   * not repeat. Pass `""` for a Ward served at the root of its own origin
   * (a bare local test server, typically).
   */
  apiBasePath: string;
  /**
   * This app's Ward app key, from its server-side environment
   * (`WARD_APP_KEY`). Sent as `x-ward-app-key` on every introspection.
   *
   * **Required.** Ward refuses `POST /introspect` without it, so an app that
   * omits it can authenticate nobody — see `introspect.ts#IntrospectorOptions`
   * on why that is a required field rather than an optional one.
   *
   * A secret. `createWardClient` is therefore a **server-side** constructor:
   * anything that runs in a browser must not call it, because a key in a
   * bundle is a published key. Nothing in this package enforces that — there
   * is no runtime that could — so it is a rule an app follows by keeping this
   * package out of its client build.
   */
  appKey: string;
  /** Expected `iss` on a verified token. Defaults to `publicOrigin`. Override only for a test/staging Ward with a different signing identity than its own origin. */
  issuer?: string;
  /** Expected `aud`. Defaults to Ward's estate-wide audience. */
  audience?: string;
  /** Clock skew allowance in seconds for local verification. Defaults to 5. */
  clockToleranceSeconds?: number;
  /**
   * Override the JWKS URL directly instead of deriving it from
   * `publicOrigin`/`apiBasePath`. This — together with `fetch` below — is the
   * seam a test uses to point at a local server it spun up itself, and it is
   * also how an app would point at a staging Ward whose layout doesn't match
   * this estate's Caddy routing.
   */
  jwksEndpoint?: URL;
  /** Override the introspect URL directly. Same rationale as `jwksEndpoint`. */
  introspectEndpoint?: URL;
  /** Injectable fetch, e.g. for a test harness or a custom HTTP client. Defaults to the global `fetch`. */
  fetch?: typeof fetch;
  /** JWKS fetch timeout, ms. Default 5000. */
  jwksTimeoutMs?: number;
  /** How long `jose` trusts an already-fetched JWKS before proactively refetching. Default 10 minutes. Unrelated to `introspectionCacheTtlMs` — see `verify.ts`. */
  jwksCacheMaxAgeMs?: number;
  /** The introspection cache window, per token. Default 30 seconds — the number `corpus/wiki/decisions-tokens.md` calls out as the one that matters. Do not raise it in production. */
  introspectionCacheTtlMs?: number;
  /** Introspection request timeout, ms. Default 5000. */
  introspectTimeoutMs?: number;
}

export interface WardClient {
  /**
   * Verify a compact JWS locally against Ward's JWKS. Authentication only —
   * says nothing about liveness. Throws `WardAuthenticationError`.
   */
  verify(token: string): Promise<AccessTokenClaims>;

  /**
   * Ask Ward whether the session behind `token` is live and what it may do,
   * caching the answer for `introspectionCacheTtlMs` and collapsing
   * concurrent calls for the same token into one request. Throws
   * `WardUnavailableError` if Ward cannot be reached or answers outside its
   * documented contract — **never** falls back to a stale answer.
   */
  introspect(token: string): Promise<SessionResolution>;

  /**
   * `verify` then `introspect`, in that order — local, cheap authentication
   * first, then the network call for liveness and authority. Throws
   * `WardAuthenticationError` (bad signature) or `WardUnavailableError` (Ward
   * unreachable); resolves to whatever `introspect` returned otherwise
   * (including `{ active: false }` for a verified-but-dead session).
   */
  resolveSession(token: string): Promise<SessionResolution>;

  /** Read Ward's access token out of a raw `Cookie` header. No app needs to know its name. */
  readAccessCookie(header: string | string[] | undefined): string | undefined;

  /**
   * The guard: read the cookie, verify, introspect, and return an
   * **active** session — or throw. Throws `WardAuthenticationError` when
   * there is no cookie, the token does not verify, or the session is not
   * active; throws `WardUnavailableError` when Ward could not be reached
   * (fail closed — this is a rejection, not a pass-through).
   */
  authenticate(cookieHeader: string | string[] | undefined): Promise<ActiveSession>;
}

/** Build a `@ward/client` instance wired to one Ward deployment. */
export function createWardClient(options: WardClientOptions): WardClient {
  const issuer = options.issuer ?? options.publicOrigin;
  const jwksEndpoint = options.jwksEndpoint ?? jwksUrl(options.publicOrigin, options.apiBasePath);
  const introspectEndpoint =
    options.introspectEndpoint ??
    new URL(`${options.apiBasePath.replace(/\/+$/, "")}/introspect`, options.publicOrigin);

  const keyStore: WardKeyStore = createRemoteJwksKeyStore(jwksEndpoint, {
    timeoutMs: options.jwksTimeoutMs,
    cacheMaxAgeMs: options.jwksCacheMaxAgeMs,
  });

  const introspectFn = createIntrospector({
    introspectUrl: introspectEndpoint,
    appKey: options.appKey,
    fetch: options.fetch,
    cacheTtlMs: options.introspectionCacheTtlMs,
    timeoutMs: options.introspectTimeoutMs,
  });

  async function verify(token: string): Promise<AccessTokenClaims> {
    return verifyAccessToken(token, keyStore, {
      issuer,
      audience: options.audience,
      clockToleranceSeconds: options.clockToleranceSeconds,
    });
  }

  async function resolveSession(token: string): Promise<SessionResolution> {
    // Local, no-network authentication first — a malformed, expired or
    // forged token is rejected before Ward is ever asked anything.
    await verify(token);
    // Liveness and authority. May throw WardUnavailableError; that is
    // deliberate (fail closed) and must propagate, not be swallowed here.
    return introspectFn(token);
  }

  async function authenticate(cookieHeader: string | string[] | undefined): Promise<ActiveSession> {
    const token = readAccessCookie(cookieHeader);
    if (token === undefined) {
      throw new WardAuthenticationError("no access token presented");
    }

    // Let WardAuthenticationError and WardUnavailableError propagate
    // unchanged. The latter is the fail-closed path: Ward being unreachable
    // must surface as a rejection here, never be swallowed into "not
    // authenticated" (which a caller might mistake for an ordinary signed-out
    // response) or, worse, into an allow.
    const session: SessionResolution = await resolveSession(token);

    if (!session.active) {
      throw new WardAuthenticationError("session is not active");
    }

    return session;
  }

  return { verify, introspect: introspectFn, resolveSession, readAccessCookie, authenticate };
}

/**
 * Require that `session` holds `role` in `app`, or throw `WardForbiddenError`.
 *
 * Apps ask "does this person hold this role here"; they never parse a token
 * or interpret a role string's meaning themselves. Always a set-membership
 * test — never equality — because one person can legitimately hold several
 * roles in one app.
 */
export function requireGrant(session: ActiveSession, app: string, role: string): void {
  if (!hasGrant(session.grants, app, role)) {
    throw new WardForbiddenError(`missing grant: ${app}/${role}`);
  }
}
