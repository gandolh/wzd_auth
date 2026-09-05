import type Database from "better-sqlite3";
import type { FastifyInstance, FastifyReply, FastifyRequest } from "fastify";
import { z } from "zod";

import { recordAudit } from "../db/audit-log.js";
import { getDb } from "../db/connection.js";
import { findUserBySubject, foldUsername, setPasswordHash, type UserRow } from "../db/users.js";
import {
  newFamilyId,
  revokeAllForSubject,
  revokeAllForSubjectExceptFamily,
  listLiveTokensForSubject,
} from "../db/refresh-tokens.js";
import { resolveSession } from "../grants/resolve.js";
import { mintAccessToken, verifyWardAccessToken } from "../tokens/service.js";
import { AccessTokenVerificationError } from "../tokens/verify.js";
import {
  ACCESS_COOKIE_NAME,
  readCookie,
  sessionCookies,
  wardSecureCookies,
} from "../auth/cookie.js";
import {
  checkLockout,
  clearFailures,
  lockoutKeyFor,
  recordFailure,
  type LockoutTarget,
} from "../auth/lockout.js";
import {
  hashPassword,
  MAX_PASSWORD_LENGTH,
  PasswordPolicyError,
  verifyPassword,
} from "../auth/password.js";
import { issueRefreshToken } from "../auth/refresh.js";

/**
 * `/account` — the self-service surface. `GET /account`,
 * `POST /account/password`, `POST /account/sessions/revoke-others`.
 *
 * Cookie-authenticated as an **ordinary account**, and that is the whole reason
 * these routes exist separately from `/console/accounts/:subject/…`. The
 * console is superuser-only by decision and there is deliberately no second
 * path into it (`corpus/wiki/decisions-admin.md`), so an ordinary person's
 * browser gets `401` there; the only way to make the console's password route
 * serve a person would be to put the estate's one plaintext, unrotatable
 * break-glass credential into their browser. Brief 09 declined to do that and
 * reported the gap instead, which is why this file exists.
 *
 * ## Why the self-service page is justified at all
 *
 * `corpus/wiki/decisions.md` rests the entire surface on one feature:
 * owner-issued accounts carry **no verified email and therefore no recovery
 * channel**, so *"sign out my other devices" is the only self-serve response
 * available to someone who suspects their session was stolen*. That is
 * `POST /account/sessions/revoke-others` below. Without it the page is a grants
 * viewer with a sign-out button.
 *
 * ## Authentication: two steps, and the second is the one that matters
 *
 * Every route here reads the `ward_session` cookie, verifies it, and then asks
 * `resolveSession` whether the session is **live** — the same pair `/introspect`
 * performs. A valid signature is not enough on its own: an access token stays
 * verifiable for its full 15 minutes after the session behind it was revoked,
 * so a signature alone is never permission to proceed. Skipping the liveness
 * check would let a revoked session change the password of the account it was
 * revoked from, which inverts the feature.
 *
 * Unlike `/introspect`, failure here is a `401` rather than
 * `200 {"active":false}`. The reasoning that makes introspection statusless is
 * specific to it — six apps on the hot path must have exactly one failure mode
 * — and does not transfer: this is a person's own browser making a
 * state-changing request, the UI has to distinguish "signed out" from "that
 * didn't work", and there is no third party to leak anything to.
 *
 * ## Cross-site requests are refused on the two `POST`s
 *
 * `SameSite=Lax` stops the cookies being *sent* on a cross-site POST but does
 * nothing about a top-level form navigation, and `enctype="text/plain"` sails
 * past Fastify's content-type rejection — the exact hole that let a cross-site
 * form sign a victim out of all six apps through `/logout`. Both mutations here
 * are cookie-driven and one of them signs the person out of every other device,
 * which is precisely the sort of thing worth doing to a victim from another
 * origin. So both apply the same `Sec-Fetch-Site`/`Origin` rule `/logout` and
 * `/refresh` do, with the same carve-out: **absent headers pass**, because
 * brief 08's server-side clients send neither.
 *
 * `GET /account` is not checked. It changes nothing, Ward sends no CORS headers
 * so a cross-origin caller cannot read the body it provokes, and refusing it
 * would break a server-side caller forwarding a browser's headers — the
 * reasoning `/introspect` records for the same decision.
 *
 * ## What is never on the wire
 *
 * `password_hash`, in any branch. `GET /account` is filtered by a Fastify
 * serialisation schema rather than by a hand-written mapper, so a future change
 * that returned a whole `UserRow` would still serialise to the five fields
 * named below.
 */

export interface AccountRoutesOptions {
  db?: Database.Database;
}

/**
 * `{ currentPassword, newPassword }`.
 *
 * `currentPassword` is bounded but has **no minimum policy** — it is whatever
 * the account holds, including one set before a policy change, and rejecting it
 * here for being short would answer `invalid_request` to somebody whose
 * password is simply short and correct.
 *
 * `newPassword` carries no length rule either, for the reason `accounts.ts`
 * gives: `auth/password.ts` owns the policy and throws `PasswordPolicyError`
 * with a stable `code`, and duplicating the bounds in zod would answer
 * `invalid_request` where the caller needs `password_too_short`.
 */
const passwordBody = z.object({
  currentPassword: z.string().min(1).max(MAX_PASSWORD_LENGTH),
  newPassword: z.string(),
});

/**
 * The response shape of `GET /account`, as a serialisation filter.
 *
 * Same technique and same purpose as `INTROSPECT_RESPONSE_SCHEMA`: making the
 * omission of `password_hash` structural rather than careful.
 *
 * The difference in *content* is the point of the endpoint. `/introspect`
 * answers four fields to six apps on every request and must not grow a fifth —
 * an app has no use for a contact address and six copies of one is six places
 * to leak it from. This endpoint answers one person about themselves, so
 * `email` and `emailVerified` belong here and nowhere else. Without it the
 * self-service page cannot show a person their own address or verification
 * state after a reload at all.
 */
export const ACCOUNT_RESPONSE_SCHEMA = {
  200: {
    type: "object",
    properties: {
      subject: { type: "string" },
      username: { type: "string" },
      email: { type: ["string", "null"] },
      emailVerified: { type: "boolean" },
      createdAt: { type: "string" },
    },
    required: ["subject", "username", "email", "emailVerified", "createdAt"],
    additionalProperties: false,
  },
} as const;

/** A live session, resolved from the request's cookie. */
interface Caller {
  row: UserRow;
  /** The access token's `sid` — the refresh family this session belongs to. */
  familyId: string;
}

export async function accountRoutes(
  app: FastifyInstance,
  options: AccountRoutesOptions = {},
): Promise<void> {
  /** Resolved once, at registration — see `routes/auth.ts` for both reasons. */
  const secure = await wardSecureCookies();
  const { WARD_PUBLIC_ORIGIN } = await import("../config.js");

  const database = async (): Promise<Database.Database> => options.db ?? (await getDb());

  /**
   * Who is calling, or `undefined` for anything that is not a live session.
   *
   * Two steps, in order: verify, then resolve. `resolveSession` decides
   * liveness — the account exists, is not disabled, and this token's **family**
   * still holds a live refresh row — so a device that was signed out cannot act
   * here for the remaining minutes of its signature.
   *
   * The `UserRow` is fetched after `resolveSession` rather than instead of it.
   * It is one indexed read by primary key, and the alternative — reimplementing
   * the liveness rule here to get the row in one pass — would put a second
   * definition of "live" in the codebase, which `grants/resolve.ts` explicitly
   * warns against.
   */
  async function callerFor(request: FastifyRequest): Promise<Caller | undefined> {
    const token = readCookie(request.headers.cookie, ACCESS_COOKIE_NAME);
    if (token === undefined) return undefined;

    let subject: string;
    let familyId: string;
    try {
      const claims = await verifyWardAccessToken(token);
      subject = claims.sub;
      familyId = claims.sid;
    } catch (error) {
      /**
       * Only a verification failure means "not signed in". Anything else — an
       * unreadable signing key — is Ward being broken, and rethrowing turns it
       * into a `500` an operator sees rather than a silent "you are signed
       * out". Same rule as `/introspect`.
       *
       * This is also the branch a **console token** lands in: `wcs_`+random has
       * one dot-separated segment where a compact JWS has three. There is no
       * `isSuperuser` check here and there must never be one — the superuser has
       * no account row, so it has no account to self-service.
       */
      if (!(error instanceof AccessTokenVerificationError)) throw error;
      request.log.debug({ err: error }, "account: access token did not verify");
      return undefined;
    }

    const db = await database();
    if (!resolveSession(db, subject, familyId).active) return undefined;

    const row = findUserBySubject(db, subject);
    if (row === undefined) return undefined;

    return { row, familyId };
  }

  /**
   * `GET /account` — the caller's own record.
   *
   * `{ subject, username, email, emailVerified, createdAt }`. Read-only, no
   * audit row, `no-store` — this is a per-person answer that no shared cache
   * may hold, the same reasoning `/introspect` records.
   */
  app.get("/account", { schema: { response: ACCOUNT_RESPONSE_SCHEMA } }, async (request, reply) => {
    reply.header("cache-control", "no-store");

    const caller = await callerFor(request);
    if (caller === undefined) return unauthorized(reply);

    return reply.code(200).send({
      subject: caller.row.subject,
      username: caller.row.username,
      email: caller.row.email,
      emailVerified: caller.row.email_verified === 1,
      createdAt: caller.row.created_at,
    });
  });

  /**
   * `POST /account/password` — change my own password.
   *
   * ## The current password is verified first, and it is the whole point
   *
   * `POST /console/accounts/:subject/password` takes no current password,
   * correctly: it is an operator override and the recovery path for an account
   * with no email. A *self-service* change that skipped it would be an account
   * takeover one borrowed laptop or one XSS away, with no recovery channel
   * behind it for an owner-issued account. Requiring it is the entire security
   * property this endpoint has that the console's does not.
   *
   * ## It rotates the session, which is what makes it a response to theft
   *
   * Every refresh family for the account is revoked and one fresh pair is
   * issued to the caller. So a password change signs out anything holding the
   * old credential — including the caller's own other devices, and including
   * whoever they changed it because of — while leaving the browser that made
   * the request signed in. A rotation that left a 30-day refresh token minting
   * access tokens for whoever holds it has not achieved the thing it was
   * performed for; `accounts.ts` and `db/users.ts` both say the same.
   *
   * ## Its own lockout budget
   *
   * `LockoutSurface` is a closed union so that a new credential surface must
   * add a member rather than borrow `"login"`. Borrowing it here would be the
   * bug review already caught once between `/login` and `/console/login`, and
   * in this direction it is worse: guessing a current password would spend the
   * budget for the login form, which is exactly how the person would recover.
   *
   * The gate runs **after** authentication, before the scrypt verify. An
   * unauthenticated request cannot spend the budget at all, and the request
   * that can is already the threat model — somebody holding a live session and
   * guessing at the password.
   */
  app.post("/account/password", async (request, reply) => {
    if (!sameOrigin(request, WARD_PUBLIC_ORIGIN)) return crossSite(reply);

    reply.header("cache-control", "no-store");

    const caller = await callerFor(request);
    if (caller === undefined) return unauthorized(reply);

    const target: LockoutTarget = {
      surface: "account_password",
      address: lockoutKey(request),
      // The folded username of the **authenticated** account, so a success
      // forgives only the guesses aimed at it — `auth/lockout.ts` on why
      // forgiveness is per account while the `429` decision is per address.
      account: foldUsername(caller.row.username),
    };

    const gate = checkLockout(target);
    if (!gate.allowed) return lockedOut(reply, gate.retryAfterSeconds ?? 1);

    const body = passwordBody.safeParse(request.body);
    if (!body.success) {
      // Not a lockout failure: a malformed body is a client bug, not a guess.
      // Also deliberately terse — zod's issue list would echo both passwords.
      return reply.code(400).send({ error: "invalid_request" });
    }

    const ok = await verifyPassword(body.data.currentPassword, caller.row.password_hash);
    if (!ok) {
      recordFailure(target);
      recordAudit(await database(), {
        actorKind: "account",
        actorSubject: caller.row.subject,
        actorLabel: caller.row.username,
        action: "user.password_change_failed",
        targetKind: "user",
        targetId: caller.row.subject,
        detail: { ip: target.address, session: caller.familyId },
      });
      // The same code `/login` answers for a wrong password, so the UI has one
      // sentence for "that password is not right" wherever it is typed.
      return reply.code(401).send({ error: "invalid_credentials" });
    }

    clearFailures(target);

    let passwordHash: string;
    try {
      passwordHash = await hashPassword(body.data.newPassword);
    } catch (error) {
      if (error instanceof PasswordPolicyError) {
        // The stable `code`, never the message — brief 09 renders these.
        return reply.code(400).send({ error: error.code });
      }
      throw error;
    }

    const db = await database();

    /**
     * **Minted before the transaction opens**, and the ordering is the same fix
     * `/login` and `/refresh` document: a mint failure after the commit would
     * leave the password changed, every family revoked, and no cookie in the
     * response — signing the person out of an account whose new password they
     * only think they set. Minting first means a failure here changes nothing.
     */
    const familyId = newFamilyId();
    const access = await mintAccessToken(caller.row.subject, familyId);

    const result = db.transaction(
      (): { sessionsRevoked: number; refreshToken: string; refreshExpiresAt: string } => {
        setPasswordHash(db, caller.row.subject, passwordHash);

        // Counted before the write for the same reason `admin/sessions.ts` does
        // it: the number reported must describe the same moment as the rows.
        const families = new Set(
          listLiveTokensForSubject(db, caller.row.subject).map((row) => row.family_id),
        );
        revokeAllForSubject(db, caller.row.subject, "admin");

        /**
         * Issued **after** the sweep, so the caller's new family survives it.
         * Doing it the other way round would revoke the pair that was just
         * minted and sign the person out of the browser they changed their
         * password in.
         */
        const issued = issueRefreshToken(db, caller.row.subject, { familyId });

        recordAudit(db, {
          actorKind: "account",
          actorSubject: caller.row.subject,
          actorLabel: caller.row.username,
          action: "user.password_change",
          targetKind: "user",
          targetId: caller.row.subject,
          detail: {
            sessionsRevoked: families.size,
            // The family that was replaced, and the one that replaced it.
            // Neither is a secret — a family id is a handle, never a
            // credential.
            previousSession: caller.familyId,
            session: familyId,
            ip: target.address,
          },
        });

        return {
          sessionsRevoked: families.size,
          refreshToken: issued.token,
          refreshExpiresAt: issued.row.expires_at,
        };
      },
    )();

    for (const cookie of sessionCookies({
      accessToken: access.token,
      refreshToken: result.refreshToken,
      secure,
    })) {
      reply.header("set-cookie", cookie);
    }

    request.log.info(
      { subject: caller.row.subject, family: familyId, sessionsRevoked: result.sessionsRevoked },
      "self-service password change rotated the session",
    );

    return reply.code(200).send({
      subject: caller.row.subject,
      /**
       * How many sessions the change ended, **including the caller's own old
       * one** — it was revoked and replaced. So a person with one device sees
       * `1`, which is honest: the credential they were holding a moment ago is
       * dead.
       */
      sessionsRevoked: result.sessionsRevoked,
      accessTokenExpiresAt: access.expiresAt,
      refreshTokenExpiresAt: result.refreshExpiresAt,
    });
  });

  /**
   * `POST /account/sessions/revoke-others` — sign out my other devices.
   *
   * **The feature `corpus/wiki/decisions.md` rests the whole self-service page
   * on.** Owner-issued accounts have no verified email and therefore no
   * recovery channel, so this is the only self-serve response available to
   * somebody who suspects their session was stolen.
   *
   * ## The family to spare comes from the access token, not the refresh cookie
   *
   * `ward_refresh` is scoped `Path=/ward-api/refresh` and is simply **not sent
   * to this path** — reaching for it would produce a route that works in a test
   * harness and answers "nothing to spare" in a browser. The access token's
   * `sid` claim names the family, it arrives in the cookie that *is* sent here,
   * and it is read off the same verified token as `sub`, so the pair cannot be
   * mismatched without forging a signature.
   *
   * ## The caller's own session stays live
   *
   * That is the requirement, not a nicety: a person doing this because they
   * think they were robbed must not be signed out by it. `family_id <> ?` in
   * `revokeAllForSubjectExceptFamily` is the whole mechanism, and it is one
   * atomic statement so a family that rotates mid-sweep cannot slip out of it.
   *
   * ## Reason `logout`, not `admin`
   *
   * `revoked_reason` is CHECK-constrained to five values and this is the person
   * themselves signing those devices out, not an operator acting on them. The
   * console's routes use `admin`; keeping the distinction means an operator
   * reading `refresh_tokens` can still tell which of the two happened.
   */
  app.post("/account/sessions/revoke-others", async (request, reply) => {
    if (!sameOrigin(request, WARD_PUBLIC_ORIGIN)) return crossSite(reply);

    reply.header("cache-control", "no-store");

    const caller = await callerFor(request);
    if (caller === undefined) return unauthorized(reply);

    const db = await database();

    const result = db.transaction((): { revoked: number; tokensRevoked: number } => {
      const others = new Set(
        listLiveTokensForSubject(db, caller.row.subject)
          .map((row) => row.family_id)
          .filter((family) => family !== caller.familyId),
      );

      const tokensRevoked = revokeAllForSubjectExceptFamily(
        db,
        caller.row.subject,
        caller.familyId,
        "logout",
      );

      if (tokensRevoked > 0) {
        recordAudit(db, {
          actorKind: "account",
          actorSubject: caller.row.subject,
          actorLabel: caller.row.username,
          action: "session.revoke_others",
          targetKind: "user",
          targetId: caller.row.subject,
          detail: {
            sessionsRevoked: others.size,
            tokensRevoked,
            spared: caller.familyId,
            ip: lockoutKey(request),
          },
        });
      }

      return { revoked: others.size, tokensRevoked };
    })();

    request.log.info(
      { subject: caller.row.subject, spared: caller.familyId, revoked: result.revoked },
      "self-service revoke of other sessions",
    );

    /**
     * **The count, not "done".** Somebody who came here because they think
     * their session was stolen needs to know whether there was anything to sign
     * out: "3 other sessions signed out" is reassuring and "0" is information,
     * where "done" is neither.
     */
    return reply.code(200).send({
      revoked: result.revoked,
      tokensRevoked: result.tokensRevoked,
      spared: caller.familyId,
    });
  });
}

/**
 * `401` with no `WWW-Authenticate`, byte-identical for a missing, malformed,
 * expired, revoked, disabled or deleted session — matching `console-guard.ts`.
 * Which of those it was is in the server log and not on the wire.
 */
function unauthorized(reply: FastifyReply): FastifyReply {
  return reply.code(401).send({ error: "unauthorized" });
}

/** `403`, decided on headers alone and before any credential is read. */
function crossSite(reply: FastifyReply): FastifyReply {
  return reply.code(403).send({ error: "cross_site" });
}

/**
 * `429` with `Retry-After`. **No artificial delay** — holding the connection
 * open is the denial of service the lockout exists to prevent
 * (`auth/lockout.ts`). `retryAfterSeconds` is repeated in the body so brief 09
 * can render the wait without reading a header.
 */
function lockedOut(reply: FastifyReply, retryAfterSeconds: number): FastifyReply {
  reply.header("retry-after", String(retryAfterSeconds));
  return reply.code(429).send({ error: "too_many_attempts", retryAfterSeconds });
}

/** The lockout key for a request. See `lockoutKeyFor` for why not `request.ip`. */
function lockoutKey(request: FastifyRequest): string {
  return lockoutKeyFor(request.socket.remoteAddress, request.headers["x-forwarded-for"], {
    warn: (detail, message) => {
      request.log.warn(detail, message);
    },
  });
}

/**
 * Whether the request is same-origin enough to act on the session cookies.
 *
 * A deliberate duplicate of the predicate in `routes/auth.ts`, which does not
 * export it and which this brief does not own. The rule is stated in one place
 * — that file's header — and both copies must agree; if a third surface ever
 * needs it, that is the moment to lift it into `auth/cookie.ts` rather than
 * write it a third time.
 *
 * **Absent headers pass.** `Sec-Fetch-Site` and `Origin` are set by browsers,
 * and brief 08's server-side clients send neither; refusing a header-less
 * request would break every non-browser caller to defend against a browser-only
 * attack. `Sec-Fetch-Site` must be exactly `same-origin` — not `same-site`
 * (the estate is one origin, so there is no sibling a legitimate request could
 * come from) and not `none` (nothing navigates directly into these endpoints).
 * An unparseable `Origin`, including the literal `null` some cross-origin
 * contexts send, is a mismatch, which is the direction to fail in.
 */
function sameOrigin(request: FastifyRequest, publicOrigin: string): boolean {
  const fetchSite = request.headers["sec-fetch-site"];
  if (typeof fetchSite === "string" && fetchSite.length > 0 && fetchSite !== "same-origin") {
    return false;
  }

  const origin = request.headers.origin;
  if (origin !== undefined && origin.length > 0) {
    let parsed: URL;
    try {
      parsed = new URL(origin);
    } catch {
      return false;
    }
    if (parsed.origin !== publicOrigin) return false;
  }

  return true;
}
