import type Database from "better-sqlite3";
import type { FastifyInstance, FastifyRequest } from "fastify";
import { z } from "zod";

import { readAppKeyHeader, resolveAppKey } from "../auth/app-key.js";
import { getDb } from "../db/connection.js";
import { INACTIVE, resolveSession } from "../grants/resolve.js";
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
 * ## Every call carries an app key
 *
 * `x-ward-app-key`, checked before anything else happens
 * (`auth/app-key.ts`). This endpoint is **published on the public origin** —
 * `vps-deploy/stacks/ward.ts` serves the whole API with
 * `handle_path /ward-api/*` — so an earlier revision of this comment, which
 * said the route "is not reachable from the internet in the deployed
 * topology", was simply wrong, and two of the decisions below leaned on it.
 * The key is what makes them true instead of hoped for: an anonymous caller is
 * refused before Ward verifies a signature or reads a row on their behalf, and
 * every call that does happen names the app that made it.
 *
 * **A bad key is a `401`, not `{"active":false}`**, and it is the single
 * exception to the one-answer rule below. The rest of this endpoint refuses to
 * distinguish failures because they are all the same fact to a caller — the
 * session is not usable. A rejected app key is not that fact. It means the app
 * is misconfigured, and answering `{"active":false}` to it would sign every one
 * of that app's users out simultaneously, silently, with a clean server log and
 * no signal anywhere that anything was wrong. That failure has to be loud, it
 * has to be distinguishable from a dead session, and `@ward/client` turns it
 * into a `WardConfigurationError` naming this exact cause.
 *
 * The `401` carries `{"error":"invalid_app_key"}` and nothing more: absent,
 * malformed, unknown and revoked are one answer to a caller, so the endpoint
 * cannot be used to probe whether a held key was revoked or never existed. The
 * distinction is on the log line, for an operator.
 *
 * ## There is no cookie path here any more
 *
 * The token comes from the body. It used to also come from the `ward_session`
 * cookie, for the benefit of Ward's own UI; that caller now has
 * `GET /session` (`routes/session.ts`), which explains at length why a
 * cookie-shaped exemption from the key requirement would have been worthless.
 * The short version: an attacker picks their own headers, so "no key needed if
 * you send a cookie" is "no key needed".
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
 * The app key is carved out of this rule on purpose; see above for why a
 * misconfigured app must not present as an app full of signed-out people.
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
 * request body, and the app key in a header — neither of which Fastify logs.
 *
 * ## No rate limit, and that is a decision rather than an omission
 *
 * Nothing here counts failures, and nothing here can return `429`.
 *
 * This is a call from six trusted services, made on **every request** they
 * serve. A lockout on this surface does not degrade an attacker, it takes the
 * entire estate down: every app reads `429` as "not live", so one noisy client,
 * or one app looping on a genuinely dead session, would sign everybody out of
 * everything. The failure mode is strictly worse than the abuse it would
 * prevent.
 *
 * What changed with the app key is not this conclusion but the shape of the
 * option. The surface is no longer anonymous, so a limit could now be applied
 * **per key** — degrading one misbehaving app rather than the estate — if one is
 * ever wanted. Nothing counts anything today, and adding a counter would still
 * need the estate-wide blast radius argued through first.
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
 * length cap on the token field below, so a caller cannot post a megabyte for
 * Ward to hash — and the key check, which runs first and refuses everyone who
 * is not one of six apps before any of that work is done.
 *
 * ## Nothing is audited, and almost nothing is written
 *
 * No audit row and no counter. Auditing a call made on every request of every
 * app would turn `audit_log` into a write amplifier fed by ordinary traffic and
 * bury the six lines an operator actually needs (see brief 03's reasoning for
 * not auditing unknown usernames). A revocation is already audited where it
 * happens.
 *
 * The one write is `app_keys.last_used_at`, and it is **throttled to at most
 * once an hour per key** in `auth/app-key.ts` — so the endpoint is a pure read
 * on essentially every call, and the exception exists because rotating a key
 * across six independently deployed apps is unsafe without knowing whether the
 * old one is still in use. The throttle is what keeps that from becoming the
 * write amplifier the paragraph above rejects. It is best-effort and never
 * fails a request.
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
 * The token to introspect: the body field, and nothing else.
 *
 * The `ward_session` cookie used to win here when present. It no longer
 * participates at all — this route is server-to-server now, its callers have no
 * cookie jar, and leaving the cookie branch in place would mean the estate's
 * most security-sensitive endpoint had a second way in that no app uses and
 * nobody tests. Browser callers go to `GET /session`.
 *
 * A body that does not parse yields `undefined` rather than a `400`; see the
 * header on why this route has no client-error branch for a credential problem.
 */
function tokenFromRequest(request: FastifyRequest): string | undefined {
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

/**
 * What `/introspect` actually declares: the shared `200` shape plus the `401`
 * that only this route can send.
 *
 * Composed rather than folded into `INTROSPECT_RESPONSE_SCHEMA` because
 * `routes/session.ts` reuses that constant and has no `401` — it answers `200`
 * for every outcome, by design. Declaring a status a route cannot produce would
 * make the schema a worse description of the contract than no schema at all,
 * and `@ward/client` treats "any status but 200" as a hard failure precisely
 * because that contract is narrow.
 */
const INTROSPECT_ROUTE_SCHEMA = {
  ...INTROSPECT_RESPONSE_SCHEMA,
  401: {
    type: "object",
    properties: { error: { type: "string" } },
    required: ["error"],
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
    { schema: { response: INTROSPECT_ROUTE_SCHEMA } },
    // No explicit return type: the handler now has two shapes — a
    // `SessionResolution` and the `401` refusal it sends through `reply` — and
    // the admin routes established that a handler mixing the two is annotated
    // by inference rather than by a union that has to name Fastify's reply.
    async (request, reply) => {
      /**
       * `no-store`, unconditionally. The 30-second cache this endpoint is
       * designed around is the **calling app's** own in-process cache, keyed
       * per session and holding an answer it just received; it is emphatically
       * not an HTTP cache. A per-session authorisation answer sitting in a
       * shared proxy cache is one person's grants served to the next caller, so
       * nothing in the chain is invited to keep it.
       */
      reply.header("cache-control", "no-store");

      /**
       * The app key, **first** — ahead of body parsing, signature verification
       * and every database read except the one indexed lookup this check itself
       * costs.
       *
       * The ordering is the point rather than an accident of layout. The route
       * is published on the public origin, so anything expensive placed above
       * this line is work an anonymous caller can make Ward do. `resolveAppKey`
       * is a prefix test, one `sha256` and one index seek; nothing cheaper than
       * that belongs in front of it.
       */
      const presented = readAppKeyHeader(request);
      const caller = resolveAppKey(await database(), presented);
      if (!caller.ok) {
        /**
         * One refusal for four causes. The reason is logged at `warn` and never
         * sent: an operator needs to tell "the key you rotated is still
         * deployed" from "somebody is guessing", and a caller must not be able
         * to.
         *
         * `warn`, not `debug`, and this is the one log level in the file chosen
         * upward. Every other rejection here is an ordinary dead session and
         * would drown an operator at `warn`; this one always means somebody has
         * to do something — fix a deployment, or look at who is knocking. The
         * key itself is not logged, in any branch.
         */
        request.log.warn(
          { reason: caller.reason },
          "introspect: refusing a request with no usable app key",
        );
        return reply.code(401).send({ error: "invalid_app_key" });
      }

      // Attributable from here on. `keyId` and `appSlug` are non-secret
      // handles — the key is never in a log line, but which app asked is
      // exactly what an operator reading this endpoint's traffic needs.
      request.log.debug(
        { app: caller.app.appSlug, keyId: caller.app.keyId },
        "introspect: authenticated app",
      );

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
