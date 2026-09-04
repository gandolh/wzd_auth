import type Database from "better-sqlite3";
import type { FastifyInstance, FastifyRequest } from "fastify";
import { z } from "zod";

import { ACCESS_COOKIE_NAME, readCookie } from "../auth/cookie.js";
import { getDb } from "../db/connection.js";
import { INACTIVE, resolveSession, type SessionResolution } from "../grants/resolve.js";
import { AccessTokenVerificationError } from "../tokens/verify.js";
import { verifyWardAccessToken } from "../tokens/service.js";

/**
 * `POST /introspect` — the endpoint every app calls on every request, and the
 * reason revocation works at all.
 *
 * An app verifies the signature locally to learn **who** (that is
 * authentication, and it needs no network call), then asks Ward whether the
 * session is still **live** and what it may **do**, caching the answer for 30
 * seconds. Revoking is then one write against one row and every app stops
 * honouring the session within its cache window — instead of six denylists to
 * synchronise, which is the design `corpus/wiki/decisions-tokens.md` rejected.
 *
 * Registered by `app.ts`, which this brief does not touch: the plugin is
 * exported and the controller wires it in. The path is **Fastify-side** —
 * Caddy serves Ward under `handle_path /ward-api/*`, so this is
 * `POST /ward-api/introspect` to a caller.
 *
 * ## One code path, one answer
 *
 * Everything that is not a live session — no token, a malformed body, a forged
 * or expired or foreign-signed token, a console token, an unknown subject, a
 * disabled account, a session with no live refresh family — resolves to the
 * **same** `200 {"active":false}`, byte for byte. Two properties fall out of
 * that and both are wanted:
 *
 * - **It never leaks why.** "Expired" and "revoked" and "no such account" are
 *   one answer to a caller, the way `/login` gives one answer to an unknown
 *   username and a wrong password. The operator gets the distinction in the
 *   server log; the caller does not.
 * - **A consuming app has one failure mode.** An app that has to branch on
 *   `400` versus `200` will get it wrong under load, and the direction it gets
 *   it wrong in is usually "treat the error as authenticated". There is no
 *   `4xx` on this route for a credential problem at all.
 *
 * The corollary is that an integration bug — posting `{ token }` instead of
 * `{ accessToken }`, say — reads as "signed out" rather than as an error. That
 * fails closed and shows up on the first manual test, and there is a `debug`
 * log line naming it, which is the right trade for never handing an app a
 * second code path.
 *
 * `500` remains possible and is deliberately **not** swallowed: only
 * `AccessTokenVerificationError` is treated as "not a live session". If the
 * signing key cannot be read, that is Ward being broken, not the session being
 * dead, and answering `active: false` to six apps would sign the whole estate
 * out silently instead of paging an operator.
 *
 * ## POST only, and nothing sensitive in a URL
 *
 * `app.ts` records that Fastify's default request log line carries `url`, and
 * therefore the query string, at info level on every request. An access token
 * in a query parameter would be written to disk on every request of every app,
 * so there is no `GET` variant and no `?token=`. The token arrives in the
 * cookie the browser already sends, or in the request body.
 *
 * ## No rate limit, and that is a decision rather than an omission
 *
 * Nothing here counts failures, and nothing here can return `429`.
 *
 * This is a loopback call from six trusted local services on the same box, made
 * on **every request** they serve. A lockout on this surface does not degrade
 * an attacker, it takes the entire estate down: every app reads `429` as "not
 * live", so one noisy client, or one app looping on a genuinely dead session,
 * would sign everybody out of everything. The failure mode is strictly worse
 * than the abuse it would prevent.
 *
 * It must also not borrow brief 03's budget. `LockoutSurface` is a closed union
 * (`"login" | "console"`) precisely so that a new credential surface has to add
 * its own member and think about its own budget; reusing `"login"` would mean
 * an app's introspection storm locking real people out of the login form, and
 * brief 06 already had to partition that budget once for exactly this reason.
 * Adding a member is an edit to `auth/lockout.ts`, which this brief does not
 * own — and the answer here is "no lockout" anyway.
 *
 * What does bound the endpoint: Fastify's default 1 MB body limit, plus the
 * length cap on the token field below, so an anonymous caller cannot post a
 * megabyte for Ward to hash. Genuine abuse from outside the box is Caddy's
 * problem; this route is not reachable from the internet in the deployed
 * topology.
 *
 * ## Nothing is written, and nothing is audited
 *
 * No audit row, no counter, no `used_at` stamp — the endpoint is a pure read.
 * Auditing a call made on every request of every app would turn `audit_log`
 * into a write amplifier fed by ordinary traffic and bury the six lines an
 * operator actually needs (see brief 03's reasoning for not auditing unknown
 * usernames). A revocation is already audited where it happens.
 *
 * ## Cross-site requests are deliberately not refused
 *
 * `/logout` and `/refresh` reject a request whose `Sec-Fetch-Site` or `Origin`
 * says cross-site, because a cross-site `POST` to those endpoints *changes*
 * something. This one changes nothing, and Ward sends no CORS headers, so a
 * cross-origin caller cannot read the response body it provokes. The check
 * would buy nothing and would cost something real: a server-side app that
 * forwards the browser's headers along with the token — an ordinary thing for
 * proxy code to do — would forward `Sec-Fetch-Site: cross-site` from a
 * perfectly legitimate cross-site navigation and read the refusal as "signed
 * out". Turning a non-attack into a spurious logout is the wrong direction to
 * fail in for the endpoint every request depends on.
 *
 * ## What may reach the log
 *
 * No branch logs the token, the cookie header or the body. Brief 02's warning
 * applies to the one error line here: `jose`'s `JWTExpired` and
 * `JWTClaimValidationFailed` carry a `payload` own-property with the decoded
 * claims, and pino's error serialiser copies own properties, so logging that
 * error puts `sub` and `jti` in the log. Those are identifiers rather than
 * credentials and that is accepted — but the raw token must never join them,
 * and it does not.
 */

/**
 * Options accepted at registration.
 *
 * The declared contract is `introspectRoutes(app)`; `db` exists so a test can
 * register against `openDatabase(":memory:")` without the process ever
 * resolving `WARD_DB_PATH`. Nothing in production passes it.
 */
export interface IntrospectRoutesOptions {
  db?: Database.Database;
}

/**
 * The request body: `{ accessToken }`, optional, and the whole body is optional
 * too so a cookie-bearing browser can post nothing at all.
 *
 * **Named `accessToken`, not `token`.** This is not RFC 7662 introspection —
 * there is no client authentication and the response is Ward's own shape, so
 * borrowing the RFC's parameter name would imply a compatibility it does not
 * have. `accessToken` mirrors `refreshToken` on `/refresh` and, more usefully,
 * makes it unmistakable at a call site that a **refresh** token is not what
 * goes here: a refresh token posted to this field simply fails verification and
 * reads as "not live", which is a confusing five minutes for whoever wired it.
 *
 * Capped at 4096: a compact JWS with an Ed25519 signature is a few hundred
 * bytes, and the cap is what stops an anonymous caller handing an endpoint on
 * the hot path something large to parse.
 */
const introspectBody = z.object({ accessToken: z.string().min(1).max(4096).optional() }).optional();

/**
 * The token to introspect: the `ward_session` cookie, else the body field.
 *
 * **The cookie wins when both are present**, matching `/refresh` and `/logout`.
 * That is the path a browser actually takes, and a body field is the easier of
 * the two to populate with the wrong thing — a stale token a server held onto,
 * say. In the case that matters the two are the same value anyway: a
 * server-side caller has no cookie jar and sends only the body.
 *
 * A body that does not parse yields `undefined` rather than a `400`; see the
 * header on why this route has no client-error branch.
 */
function tokenFromRequest(request: FastifyRequest): string | undefined {
  const cookie = readCookie(request.headers.cookie, ACCESS_COOKIE_NAME);
  if (cookie !== undefined) return cookie;

  const parsed = introspectBody.safeParse(request.body);
  if (!parsed.success) {
    // Deliberately terse and deliberately not echoed: zod's issue list would
    // put the submitted value — a bearer token — in the log line.
    request.log.debug("introspect: request body is not { accessToken?: string }");
    return undefined;
  }

  return parsed.data?.accessToken;
}

/**
 * The response shape, as a Fastify serialisation schema.
 *
 * This is not validation, it is a **filter**, and it is here to make the
 * "no field an app cannot justify needing" criterion structural rather than
 * careful. `fast-json-stringify` emits only the properties named below, so a
 * future change that returned a whole `UserRow` from `resolveSession` — with
 * `password_hash` and `email` on it — would serialise to exactly these four
 * fields anyway. The comments in `grants/resolve.ts` justify each one; this is
 * the enforcement.
 *
 * `subject`, `username` and `grants` are absent from an inactive answer and are
 * therefore not `required`.
 *
 * Exported because it *is* the response contract — brief 08's `@ward/client`
 * and the app integrations consume this shape verbatim — and so that a test can
 * push a deliberately over-full object through the real schema and prove the
 * filter rather than assert it.
 */
export const INTROSPECT_RESPONSE_SCHEMA = {
  200: {
    type: "object",
    properties: {
      active: { type: "boolean" },
      subject: { type: "string" },
      username: { type: "string" },
      grants: {
        type: "object",
        // App slugs are data, so the keys cannot be enumerated in a schema. The
        // value shape can be, and is: a set of opaque role strings.
        additionalProperties: { type: "array", items: { type: "string" } },
      },
    },
    required: ["active"],
    additionalProperties: false,
  },
} as const;

export async function introspectRoutes(
  app: FastifyInstance,
  options: IntrospectRoutesOptions = {},
): Promise<void> {
  /**
   * Lazy, and memoised by `getDb()` itself. Not resolved at registration for
   * the reason `routes/auth.ts` gives: `index.ts` runs migrations strictly
   * before `buildApp()`, and opening the database from inside registration
   * would blur that ordering.
   */
  const database = async (): Promise<Database.Database> => options.db ?? (await getDb());

  app.post(
    "/introspect",
    { schema: { response: INTROSPECT_RESPONSE_SCHEMA } },
    async (request, reply): Promise<SessionResolution> => {
      /**
       * `no-store`, unconditionally. The 30-second cache this endpoint is
       * designed around is the **calling app's** own in-process cache, keyed
       * per session and holding an answer it just received; it is emphatically
       * not an HTTP cache. A per-session authorisation answer sitting in a
       * shared proxy cache is one person's grants served to the next caller, so
       * nothing in the chain is invited to keep it.
       */
      reply.header("cache-control", "no-store");

      const token = tokenFromRequest(request);
      if (token === undefined) return INACTIVE;

      let subject: string;
      let sessionId: string;
      try {
        // Takes the token and nothing else — no options bag, so no call site
        // can weaken the issuer, audience, expiry or clock tolerance. Brief 02
        // narrowed it deliberately after review found all four overridable;
        // do not widen it.
        const claims = await verifyWardAccessToken(token);
        subject = claims.sub;
        // `sid` names the refresh family this token was minted under, which is
        // what makes liveness a question about *this session* rather than about
        // the account. `verify.ts` requires the claim, so it is present on any
        // token that got this far.
        sessionId = claims.sid;
      } catch (error) {
        /**
         * Only a verification failure means "not a live session". Anything else
         * — an unreadable signing key, a `jose` fault — is Ward being broken,
         * and rethrowing turns it into a `500` an operator sees rather than an
         * estate-wide silent logout.
         *
         * This is also the branch a **console token** lands in, and it is the
         * only thing that has to happen for the superuser to be unable to open
         * atrium: `wcs_`+random has one dot-separated segment where a compact
         * JWS has three, so it is `JWSInvalid` here. There is no `isSuperuser`
         * check in this file and there must never be one — the superuser has no
         * account row and no grants, so "console only" falls out of the model
         * rather than out of a branch. `corpus/wiki/decisions-admin.md` rejects
         * that branch by name.
         */
        if (!(error instanceof AccessTokenVerificationError)) throw error;
        request.log.debug({ err: error }, "introspect: access token did not verify");
        return INACTIVE;
      }

      // One code path from here: liveness and authority are decided in
      // `grants/resolve.ts`, for every caller, on every call.
      return resolveSession(await database(), subject, sessionId);
    },
  );
}
