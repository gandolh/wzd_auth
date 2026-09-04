import type Database from "better-sqlite3";
import type { FastifyInstance, FastifyReply, FastifyRequest } from "fastify";
import { z } from "zod";

import { recordAudit } from "../db/audit-log.js";
import { getDb } from "../db/connection.js";
import { findUserByUsername } from "../db/users.js";
import { mintAccessToken } from "../tokens/service.js";
import {
  ACCESS_COOKIE_NAME,
  REFRESH_COOKIE_NAME,
  clearedSessionCookies,
  readCookie,
  sessionCookies,
  wardSecureCookies,
} from "../auth/cookie.js";
import { checkLockout, clearFailures, lockoutKeyFor, recordFailure } from "../auth/lockout.js";
import { MAX_PASSWORD_LENGTH, spendDummyHash, verifyPassword } from "../auth/password.js";
import {
  endSession,
  issueRefreshToken,
  refreshCookieMaxAge,
  rotateRefreshToken,
} from "../auth/refresh.js";

/**
 * `POST /login`, `POST /refresh`, `POST /logout` — the account session surface.
 *
 * Registered by `app.ts` (which this brief does not touch) as
 * `await app.register(authRoutes)`. The paths here are **Fastify-side**: Caddy
 * serves Ward with `handle_path /ward-api/*`, which strips the prefix, so
 * `/login` here is `POST /ward-api/login` in a browser. That distinction is why
 * the refresh cookie's `Path` is `/ward-api/refresh` (a browser-side path)
 * while its route is `/refresh`.
 *
 * ## Nothing sensitive travels in a URL, ever
 *
 * `app.ts` records that Fastify's default request log line includes `url`, and
 * therefore the query string, on every request at info level. So credentials
 * live in the **body** on all three routes and there is no `?token=` anywhere —
 * which also retires atrium's `?token=` wart rather than reproducing it. There
 * is no `GET` variant of any of these for the same reason.
 *
 * ## What may and may not reach the log
 *
 * Subjects, `jti`s, family ids and usernames appear in log lines and audit
 * rows. **Passwords, access tokens, refresh tokens and cookie values never
 * do.** Note the specific trap brief 02 recorded: `jose`'s `JWTExpired` and
 * `JWTClaimValidationFailed` carry a `payload` own-property holding decoded
 * claims, and pino's error serialiser copies own properties — so logging such
 * an error puts `sub` and `jti` in the log, which is acceptable, but the raw
 * token must never be logged alongside it. This file logs no token in any
 * branch, including its error branches.
 */

/**
 * Options accepted at registration.
 *
 * The declared contract is `authRoutes(app)`, and `db` is an optional extra so
 * a test can register against `openDatabase(":memory:")` without the process
 * ever resolving `WARD_DB_PATH`. Nothing in production passes it — `app.ts`
 * calls `app.register(authRoutes)` and the handlers resolve the singleton on
 * first use.
 */
export interface AuthRoutesOptions {
  db?: Database.Database;
}

/** `{ username, password }`. Both required, neither trimmed except of surrounding space. */
const loginBody = z.object({
  // Trimmed because a trailing space in a username is invisible and is never
  // intentional; `foldUsername` handles case and Unicode form.
  username: z.string().trim().min(1).max(256),
  // NOT trimmed: a space is a legitimate password character and silently
  // removing one makes a correct password fail with no explanation. Capped only
  // so an unauthenticated endpoint cannot be handed a multi-megabyte string.
  password: z.string().min(1).max(MAX_PASSWORD_LENGTH),
});

/**
 * `/refresh` and `/logout` read the refresh token from its cookie. The optional
 * body field exists for a non-browser client (a script, a test) that has no
 * cookie jar; the cookie wins when both are present, because that is the path a
 * browser actually takes and a body field is easier to get wrong.
 */
const refreshBody = z.object({ refreshToken: z.string().min(1).max(512).optional() }).optional();

export async function authRoutes(
  app: FastifyInstance,
  options: AuthRoutesOptions = {},
): Promise<void> {
  /**
   * Resolved once, at registration, because it never changes for the life of
   * the process — and resolving it here rather than per request means a
   * misconfigured origin is visible at boot.
   */
  const secure = await wardSecureCookies();

  /**
   * Lazy, and memoised by `getDb()` itself. Not resolved at registration
   * because `app.ts` is deliberately free of any reach into the database (see
   * its header): `index.ts` runs migrations strictly before `buildApp()`, and a
   * registration-time `getDb()` would open the file from inside `buildApp` and
   * blur that ordering.
   */
  const database = async (): Promise<Database.Database> => options.db ?? (await getDb());

  /**
   * `POST /login` — the only anonymous read-credentials surface in Ward.
   *
   * Success sets **two** cookies and returns the identity, never the tokens:
   * a body carrying the access token would put it in reach of any script on the
   * page, which is the entire thing `HttpOnly` is for.
   */
  app.post("/login", async (request, reply) => {
    const key = lockoutKey(request);

    const gate = checkLockout(key);
    if (!gate.allowed) {
      return lockedOut(reply, gate.retryAfterSeconds ?? 1);
    }

    const parsed = loginBody.safeParse(request.body);
    if (!parsed.success) {
      // Deliberately NOT a lockout failure: a malformed body is a client bug,
      // not a guess, and counting it means one broken integration locks its own
      // users out. Also deliberately terse — zod's issue list would echo the
      // submitted field values back, and one of them is the password.
      return reply.code(400).send({ error: "invalid_request" });
    }

    const { username, password } = parsed.data;
    const db = await database();
    const user = findUserByUsername(db, username);

    /**
     * **The unknown-username branch spends a hash.** Atrium does the same, and
     * without it this endpoint answers in under a millisecond for a name that
     * does not exist and in ~50 ms for one that does — an account-enumeration
     * oracle that needs no error message and leaves nothing unusual in a log.
     * The two branches below must stay symmetric in cost; that is the whole
     * reason `spendDummyHash` exists as a named function rather than as a
     * comment saying "remember to hash anyway".
     */
    const ok =
      user === undefined
        ? await spendDummyHash(password)
        : await verifyPassword(password, user.password_hash);

    // `user === undefined` is repeated rather than inferred from `ok`: the
    // compiler cannot see that `spendDummyHash` returns the literal `false`
    // through the ternary above, and the alternative — asserting the narrowing —
    // would let a future edit that makes the dummy path succeed type-check.
    if (user === undefined || !ok) {
      recordFailure(key);
      if (user !== undefined) {
        /**
         * Failures are audited **only for an account that exists**.
         *
         * Not squeamishness about enumeration — the audit log is not readable
         * by the attacker — but growth. Auditing every unknown username makes
         * this table a write amplifier driven entirely by anonymous input;
         * bounding it to real accounts keeps the rows an operator actually
         * wants ("somebody is guessing at *this* account") without handing a
         * wordlist a way to fill the disk.
         */
        recordAudit(db, {
          actorKind: "account",
          actorSubject: user.subject,
          actorLabel: user.username,
          action: "session.login_failed",
          targetKind: "user",
          targetId: user.subject,
          detail: { ip: key },
        });
      }
      // One answer for "no such username" and "wrong password". The client is
      // told which *half* was wrong by nothing at all — brief 09 renders this
      // as "check your username and password".
      return reply.code(401).send({ error: "invalid_credentials" });
    }

    if (user.disabled_at !== null) {
      /**
       * Answered **after** the password verified, and with its own code.
       *
       * Order matters: checking `disabled_at` before verifying would let anyone
       * discover that a given username exists *and* is disabled without knowing
       * the password. Checking it after means the caller has already proved they
       * are the account holder, so telling them plainly is not a leak — and it
       * saves a person whose account was disabled from retyping a password that
       * was correct all along.
       */
      recordFailure(key);
      return reply.code(403).send({ error: "account_disabled" });
    }

    clearFailures(key);

    const issued = issueRefreshToken(db, user.subject);
    const access = await mintAccessToken(user.subject);

    recordAudit(db, {
      actorKind: "account",
      actorSubject: user.subject,
      actorLabel: user.username,
      action: "session.login",
      targetKind: "session",
      targetId: issued.row.family_id,
      detail: { jti: access.jti, ip: key },
    });

    // No `refreshMaxAgeSeconds` override: the row was created a millisecond
    // ago, so the flat 30-day constant is both correct and exact. The override
    // exists for a *rotation*, where R2 inherits an expiry already partly spent.
    setSessionCookies(reply, {
      accessToken: access.token,
      refreshToken: issued.token,
      secure,
    });

    request.log.info(
      { subject: user.subject, jti: access.jti, family: issued.row.family_id },
      "login succeeded",
    );

    return reply.code(200).send({
      subject: user.subject,
      username: user.username,
      emailVerified: user.email_verified === 1,
      accessTokenExpiresAt: access.expiresAt,
      refreshTokenExpiresAt: issued.row.expires_at,
    });
  });

  /**
   * `POST /refresh` — rotate. `R1` in, a new access token plus `R2` out, and
   * `R1` invalidated.
   *
   * **Not rate-limited by the IP lockout.** A refresh presents a 256-bit
   * credential rather than a guessable secret, so there is nothing to throttle;
   * applying the login counter here would let a burst of stale refreshes from
   * one office lock that office out of logging in, which is the wrong direction
   * entirely. The replay response is the throttle that matters: a family dies
   * on the first reuse.
   */
  app.post("/refresh", async (request, reply) => {
    const parsedBody = refreshBody.safeParse(request.body);
    const presented =
      readCookie(request.headers.cookie, REFRESH_COOKIE_NAME) ??
      (parsedBody.success ? parsedBody.data?.refreshToken : undefined);

    if (presented === undefined) {
      return refreshRejected(reply, secure);
    }

    const db = await database();
    const outcome = rotateRefreshToken(db, presented);

    if (outcome.status !== "rotated") {
      /**
       * **Every failure is the same `401` with the same body.** The module knew
       * whether that token was unknown, expired, revoked or replayed; the wire
       * does not say. Telling a caller "already used" confirms the token was
       * genuine, which is a free confirmation handed to whoever stole it.
       *
       * The cookies are cleared on the way out, so a client holding a dead
       * refresh token stops presenting it and lands on the login page instead
       * of looping.
       */
      if (outcome.status === "reuse_detected") {
        // Logged at `warn` because this is the one line in Ward an operator
        // should be alerted on. No token, no hash — the family id is the handle,
        // and `audit_log` already has the row (written inside the rotation's
        // transaction, by `refresh.ts`).
        request.log.warn(
          {
            subject: outcome.subject,
            family: outcome.familyId,
            tokensRevoked: outcome.revoked,
          },
          "refresh token reuse detected; revoked the whole family",
        );
      } else {
        request.log.info({ outcome: outcome.status }, "refresh rejected");
      }
      return refreshRejected(reply, secure);
    }

    const access = await mintAccessToken(outcome.subject);

    setSessionCookies(reply, {
      accessToken: access.token,
      refreshToken: outcome.refreshToken,
      secure,
      refreshMaxAgeSeconds: refreshCookieMaxAge(outcome.row),
    });

    request.log.info(
      { subject: outcome.subject, jti: access.jti, family: outcome.row.family_id },
      "refresh rotated",
    );

    return reply.code(200).send({
      subject: outcome.subject,
      accessTokenExpiresAt: access.expiresAt,
      refreshTokenExpiresAt: outcome.row.expires_at,
    });
  });

  /**
   * `POST /logout` — clear both cookies and kill the family.
   *
   * **Always `204`.** No branch on whether the token was real, present, or
   * already dead: logout answering differently for a valid token would make it
   * a free oracle for testing stolen tokens, and there is nothing a client can
   * usefully do with the distinction anyway. This is also why logout is
   * near-instant in practice — the client then holds nothing at all, and the
   * 30-second introspection window only ever applies to a token that was
   * already stolen.
   */
  app.post("/logout", async (request, reply) => {
    const parsedBody = refreshBody.safeParse(request.body);
    const presented =
      readCookie(request.headers.cookie, REFRESH_COOKIE_NAME) ??
      (parsedBody.success ? parsedBody.data?.refreshToken : undefined);

    if (presented !== undefined) {
      const db = await database();
      const result = endSession(db, presented);
      if (result.ended) {
        request.log.info(
          { subject: result.subject, family: result.familyId, tokensRevoked: result.revoked },
          "logout revoked session family",
        );
      }
    }

    clearSessionCookies(reply, secure);
    return reply.code(204).send();
  });
}

/**
 * The lockout key for a request.
 *
 * One line, but its own function so brief 06's console login can be read
 * side-by-side with this one and be seen to key identically. See
 * `lockoutKeyFor` for why the socket peer alone is not enough (Ward is behind
 * Caddy on loopback, so every peer is `127.0.0.1`) and why the *last*
 * `X-Forwarded-For` element is the one that cannot be spoofed.
 */
function lockoutKey(request: FastifyRequest): string {
  return lockoutKeyFor(request.socket.remoteAddress, request.headers["x-forwarded-for"]);
}

/**
 * `429` with `Retry-After`.
 *
 * **No artificial delay before it.** Holding the connection open is the denial
 * of service the lockout exists to prevent, and Ward is the runtime dependency
 * of all six apps — see the header of `auth/lockout.ts`. `retryAfterSeconds` is
 * repeated in the body because brief 09 renders the wait time and should not
 * have to read a header to do it.
 */
function lockedOut(reply: FastifyReply, retryAfterSeconds: number): FastifyReply {
  reply.header("retry-after", String(retryAfterSeconds));
  return reply.code(429).send({ error: "too_many_attempts", retryAfterSeconds });
}

function refreshRejected(reply: FastifyReply, secure: boolean): FastifyReply {
  clearSessionCookies(reply, secure);
  return reply.code(401).send({ error: "invalid_refresh" });
}

/**
 * Emit two `Set-Cookie` headers.
 *
 * Fastify's `reply.header` special-cases `set-cookie` and accumulates repeated
 * calls into an array rather than overwriting, which is exactly what is needed
 * and is not true of any other header — so this stays a helper rather than
 * being inlined, and `auth.test.ts` asserts against the two headers the
 * response actually carries rather than against this code.
 */
function setSessionCookies(
  reply: FastifyReply,
  params: {
    accessToken: string;
    refreshToken: string;
    secure: boolean;
    refreshMaxAgeSeconds?: number;
  },
): void {
  for (const cookie of sessionCookies(params)) {
    reply.header("set-cookie", cookie);
  }
}

function clearSessionCookies(reply: FastifyReply, secure: boolean): void {
  for (const cookie of clearedSessionCookies({ secure })) {
    reply.header("set-cookie", cookie);
  }
}

/**
 * Re-exported so brief 04 (introspection) and brief 06 (console) import the
 * cookie name from one place, and so nothing else has to reach into
 * `auth/cookie.js` to read the access token off a request.
 */
export { ACCESS_COOKIE_NAME, REFRESH_COOKIE_NAME };
