import type Database from "better-sqlite3";
import type { FastifyInstance } from "fastify";

import { ACCESS_COOKIE_NAME, readCookie } from "../auth/cookie.js";
import { getDb } from "../db/connection.js";
import { INACTIVE, resolveSession, type SessionResolution } from "../grants/resolve.js";
import { AccessTokenVerificationError } from "../tokens/verify.js";
import { verifyWardAccessToken } from "../tokens/service.js";
import { INTROSPECT_RESPONSE_SCHEMA } from "./introspect.js";

/**
 * `GET /session` — "who am I", for a browser holding Ward's own cookie.
 *
 * ## Why this exists, and what it took over from
 *
 * `POST /introspect` used to serve two callers with one code path: consuming
 * apps posting a token in the body, and **Ward's own UI** posting nothing and
 * relying on the `ward_session` cookie the browser attaches. That dual purpose
 * became untenable the moment `/introspect` grew an app-key requirement
 * (`auth/app-key.ts`), because the two callers cannot both satisfy it: a key
 * embedded in a Vite bundle is not a secret, it is a published string.
 *
 * The tempting shortcut — keep the cookie path on `/introspect` and require a
 * key only when there is no cookie — is worthless, and worth naming so nobody
 * re-proposes it. An attacker chooses their own headers. Moving a token from
 * the body into a `Cookie:` header is a one-line change to a `curl` command, so
 * a cookie-shaped exemption exempts everybody and the key protects nothing.
 * Splitting the two callers into two routes is what makes the requirement on
 * `/introspect` absolute, and absolute is the only useful kind.
 *
 * ## What this endpoint is, and is not
 *
 * It is the browser half, and only the browser half: the token comes from the
 * cookie and from nowhere else. There is no body, no query parameter and no
 * header form, so this route cannot be used to introspect a token the caller
 * obtained some other way — presenting a stolen token here requires already
 * being able to set it as a cookie on this origin, at which point the session is
 * simply being used, which is what a stolen token does anyway.
 *
 * It carries **no app key**, deliberately. This is a first-party, same-origin
 * call from the login/self-service UI, and the estate's hot path no longer runs
 * through it: six apps make one `/introspect` call per request each, and this
 * one is called when somebody has Ward's own pages open.
 *
 * ## The response is byte-identical to `/introspect`
 *
 * Same shape, same schema object, same `200`-always contract, same reasons —
 * `ui/src/lib/session.ts` was built against `{ active, subject, username,
 * grants }` and its two-call "introspect, refresh once, introspect again" dance
 * depends on a dead session being a `200` rather than a `401`. Reusing
 * `INTROSPECT_RESPONSE_SCHEMA` rather than declaring a second one keeps the
 * field filter (and the guarantee that no `password_hash` can ever escape
 * through it) in exactly one place.
 *
 * `GET` rather than `POST`, because unlike `/introspect` there is nothing in the
 * request to put in a body — and nothing sensitive goes in the URL, which is the
 * constraint `routes/introspect.ts` records about Fastify logging query strings.
 * The credential is the cookie, which is never logged.
 */

export interface SessionRoutesOptions {
  db?: Database.Database;
}

export async function sessionRoutes(
  app: FastifyInstance,
  options: SessionRoutesOptions = {},
): Promise<void> {
  const database = async (): Promise<Database.Database> => options.db ?? (await getDb());

  app.get(
    "/session",
    { schema: { response: INTROSPECT_RESPONSE_SCHEMA } },
    async (request, reply) => {
      /**
       * `no-store`, for the reason `/introspect` gives: a per-session
       * authorisation answer sitting in any shared cache is one person's grants
       * served to the next caller.
       */
      reply.header("cache-control", "no-store");

      const token = readCookie(request.headers.cookie, ACCESS_COOKIE_NAME);
      if (token === undefined) return INACTIVE;

      let subject: string;
      let sessionId: string;
      try {
        const claims = await verifyWardAccessToken(token);
        subject = claims.sub;
        sessionId = claims.sid;
      } catch (error) {
        // Only a verification failure means "not a live session". Anything else
        // is Ward being broken and must surface as a `500`, not as a silent
        // logout — the same rule `/introspect` and `/account` both follow.
        //
        // A console token (`wcs_` + random) lands here too, and that is the whole
        // mechanism by which the superuser has no self-service page: it has no
        // account row, so there is nothing for this route to describe.
        if (!(error instanceof AccessTokenVerificationError)) throw error;
        request.log.debug({ err: error }, "session: access token did not verify");
        return INACTIVE;
      }

      const resolution: SessionResolution = resolveSession(await database(), subject, sessionId);
      return resolution;
    },
  );
}
