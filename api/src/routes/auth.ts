import type Database from "better-sqlite3";
import type { FastifyInstance, FastifyReply, FastifyRequest } from "fastify";
import { z } from "zod";

import { recordAudit } from "../db/audit-log.js";
import { getDb } from "../db/connection.js";
import { findUserByUsername, foldUsername } from "../db/users.js";
import { mintAccessToken } from "../tokens/service.js";
import {
  ACCESS_COOKIE_NAME,
  REFRESH_COOKIE_NAME,
  clearedSessionCookies,
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
import { MAX_PASSWORD_LENGTH, spendDummyHash, verifyPassword } from "../auth/password.js";
import {
  endSession,
  issueRefreshToken,
  refreshCookieMaxAge,
  rotateRefreshToken,
  subjectForRefreshToken,
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
 * ## `/logout` and `/refresh` require a same-origin request
 *
 * `SameSite=Lax` stops the cookies being *sent* on a cross-site POST but does
 * nothing about the response *deleting* them. An auto-submitted
 * `<form method="POST" enctype="text/plain" action=".../ward-api/logout">` on any
 * page reached `/logout` — `text/plain` sails past Fastify's content-type parser
 * where `form-urlencoded` and `multipart` earn a `415` — and the `204` plus two
 * clearing `Set-Cookie` headers were honoured first-party, at `Path=/`, across
 * all six apps, with no navigation for the victim to notice. In a loop it meant
 * they could not hold a session at all.
 *
 * Two things close it, and both are needed. The cookies are cleared **only when
 * the request actually presented a refresh token**, which alone defuses the
 * attack above. And both routes additionally require a same-origin request:
 * `Sec-Fetch-Site`, when present, must be `same-origin`, and `Origin`, when
 * present, must match `WARD_PUBLIC_ORIGIN`. **Absent headers are allowed** —
 * brief 08's server-side clients send neither, and rejecting a header-less
 * request would break every non-browser caller to defend against a browser-only
 * attack.
 *
 * `/logout` still answers `204` for every request that presented a token, valid
 * or not; that oracle property is a recorded acceptance criterion. The
 * cross-site refusal is decided on headers alone, before any token is looked at,
 * so it tells a caller nothing about whether their token was real.
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
   * Resolved here for the same reason, and through a **dynamic** import so that
   * merely importing this module does not run `config.ts`'s zod validation (and
   * its `process.exit(1)`). `config.ts` normalises this to a bare origin —
   * `url.origin === value` is one of its own refinements — so a request's
   * `Origin` header can be compared to it after the same normalisation.
   */
  const { WARD_PUBLIC_ORIGIN } = await import("../config.js");

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
    const address = lockoutKey(request);

    /**
     * The gate reads the **address** budget for this surface and nothing else —
     * `checkLockout` ignores `account`, deliberately, so five failures from one
     * address still earn the sixth request a `429` whatever usernames they
     * targeted. The account only matters for `recordFailure` and
     * `clearFailures` below, and it is not known until the body parses.
     */
    const gate = checkLockout({ surface: "login", address });
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

    /**
     * Folded, and folded from the **submitted** name rather than from a row, so
     * that a guess at an account that does not exist still gets its own bucket
     * — an attacker's success on their own account must not forgive it.
     */
    const target: LockoutTarget = { surface: "login", address, account: foldUsername(username) };

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
      recordFailure(target);
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
          detail: { ip: address },
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
      recordFailure(target);
      return reply.code(403).send({ error: "account_disabled" });
    }

    /**
     * Only this account's failures, from this address, on this surface.
     *
     * The old address-wide clear meant one valid account bought unlimited
     * guessing at every other: four wrong guesses at a victim, one correct login
     * as yourself, counter back to zero, repeat — 40 wrong guesses from one
     * address with no `429` at all, at roughly 35 a second. A success explains
     * the failures aimed at *the account it proved* and nothing else.
     */
    clearFailures(target);

    /**
     * **Minted before the refresh row is written, and that order is the fix.**
     *
     * With `issueRefreshToken` first, a mint failure — an unreadable signing
     * key, say — answered `500` after a live 30-day refresh row had already been
     * stored for a client that never received it. Minting first means a failure
     * here leaves nothing behind at all: no row, no cookie, no session the
     * console would list.
     */
    const access = await mintAccessToken(user.subject);
    const issued = issueRefreshToken(db, user.subject);

    recordAudit(db, {
      actorKind: "account",
      actorSubject: user.subject,
      actorLabel: user.username,
      action: "session.login",
      targetKind: "session",
      targetId: issued.row.family_id,
      detail: { jti: access.jti, ip: address },
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
    if (!sameOrigin(request, WARD_PUBLIC_ORIGIN)) {
      return crossSite(reply);
    }

    const parsedBody = refreshBody.safeParse(request.body);
    const presented =
      readCookie(request.headers.cookie, REFRESH_COOKIE_NAME) ??
      (parsedBody.success ? parsedBody.data?.refreshToken : undefined);

    if (presented === undefined) {
      // Nothing presented, so nothing to clear. Clearing here is what let a
      // cross-site POST sign the victim out of all six apps — see the header.
      return reply.code(401).send({ error: "invalid_refresh" });
    }

    const address = lockoutKey(request);
    const db = await database();

    /**
     * **The access token is minted before the rotation transaction opens**, and
     * the ordering is the point.
     *
     * `refresh.ts` guarantees that no state exists in which `R1` is spent but
     * `R2` was never stored — of the *database*. What matters to the person
     * using the app is whether the **client** received `R2`, and minting after
     * the commit had a seam: the claim committed, `mintAccessToken` threw, the
     * response was a `500` with no `Set-Cookie`, and the browser still held
     * `R1`. Its next refresh presented a spent token and burned the family down
     * with a false theft alarm. A dropped response, a client abort or a proxy
     * timeout does the same thing — that is just the ordinary internet, and
     * `REFRESH_RACE_GRACE_SECONDS` covers those within its window. Minting first
     * removes the mint-failure cause outright, at the cost of a wasted signature
     * on the rare rotation that then fails.
     *
     * The subject is peeked off the row rather than taken from the outcome.
     * `subjectForRefreshToken` is not an authorisation check and is not treated
     * as one: `rotateRefreshToken` below still decides everything, and a token
     * whose hash is unknown is refused here without minting anything.
     */
    const subject = subjectForRefreshToken(db, presented);
    if (subject === undefined) {
      request.log.info({ outcome: "unknown" }, "refresh rejected");
      return refreshRejected(reply, secure);
    }

    const access = await mintAccessToken(subject);
    const outcome = rotateRefreshToken(db, presented, new Date(), { presentedBy: address });

    if (outcome.status !== "rotated") {
      /**
       * **Every failure is the same `401` with the same body.** The module knew
       * whether that token was unknown, expired, revoked, raced or replayed; the
       * wire does not say. Telling a caller "already used" confirms the token
       * was genuine, which is a free confirmation handed to whoever stole it —
       * and telling them "that was only a race" confirms it just as well, which
       * is why `refresh_raced` takes this same branch and differs only in
       * `audit_log`.
       *
       * The cookies are cleared on the way out, so a client holding a dead
       * refresh token stops presenting it and lands on the login page instead
       * of looping — **except on the raced branch**, which deliberately clears
       * nothing. See `refreshRejected`'s `clearCookies` parameter for why.
       */
      if (outcome.status === "reuse_detected" && outcome.revoked > 0) {
        // Logged at `warn` because this is the one line in Ward an operator
        // should be alerted on. Gated on `revoked > 0` for the same reason
        // `refresh.ts` gates its audit row: a replay of a family that is already
        // dead did nothing, and on a route with no lockout an ungated `warn`
        // per replay drowns the genuine alarm in noise.
        request.log.warn(
          {
            subject: outcome.subject,
            family: outcome.familyId,
            tokensRevoked: outcome.revoked,
            ip: address,
          },
          "refresh token reuse detected; revoked the whole family",
        );
      } else if (outcome.status === "refresh_raced") {
        // Not an alarm. Two tabs presented the same token at once; the winner's
        // R2 is live in the shared cookie jar and the session is intact.
        request.log.info(
          { subject: outcome.subject, family: outcome.familyId, ip: address },
          "refresh token raced; left the family alive",
        );
      } else {
        request.log.info({ outcome: outcome.status }, "refresh rejected");
      }
      return refreshRejected(reply, secure, {
        clearCookies: outcome.status !== "refresh_raced",
      });
    }

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
    if (!sameOrigin(request, WARD_PUBLIC_ORIGIN)) {
      return crossSite(reply);
    }

    const parsedBody = refreshBody.safeParse(request.body);
    const presented =
      readCookie(request.headers.cookie, REFRESH_COOKIE_NAME) ??
      (parsedBody.success ? parsedBody.data?.refreshToken : undefined);

    if (presented === undefined) {
      /**
       * **Nothing presented, so nothing cleared.**
       *
       * The status is still `204`, so this branch is invisible on the wire and
       * the oracle property is untouched. But emitting the two clearing
       * `Set-Cookie` headers for a request that carried no credential is what
       * made `/logout` a cross-site sign-out for the whole estate: the browser
       * is first-party for Ward on a top-level navigation, honours both
       * deletions, and `Path=/` reaches all six apps at once.
       */
      return reply.code(204).send();
    }

    const db = await database();
    const result = endSession(db, presented);
    if (result.ended) {
      request.log.info(
        { subject: result.subject, family: result.familyId, tokensRevoked: result.revoked },
        "logout revoked session family",
      );
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
  return lockoutKeyFor(request.socket.remoteAddress, request.headers["x-forwarded-for"], {
    // A loopback peer with no forwarded address collapses the whole estate into
    // one shared counter, and the only visible symptom is an innocent third
    // party being answered `429`. `lockoutKeyFor` throttles this to one line per
    // interval per process, so passing the logger cannot itself become a flood.
    warn: (detail, message) => {
      request.log.warn(detail, message);
    },
  });
}

/**
 * Whether the request is same-origin enough to act on the session cookies.
 *
 * **Absent headers pass.** `Sec-Fetch-Site` and `Origin` are set by browsers;
 * brief 08's server-side clients send neither, and refusing a header-less
 * request would break every non-browser caller in order to defend against a
 * browser-only attack. What the check catches is the case that actually exists:
 * a browser that *did* send them and said the request came from somewhere else.
 *
 * `Sec-Fetch-Site` must be exactly `same-origin` — not `same-site`, because the
 * estate is one origin and there is no sibling origin a legitimate request could
 * come from, and not `none`, because nothing navigates directly into these two
 * endpoints. An unparseable `Origin` (including the literal `null` some
 * cross-origin contexts send) is a mismatch, which is the direction to fail in.
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

/**
 * `403`, and deliberately **before** any token is read.
 *
 * Deciding this on headers alone is what keeps `/logout`'s "always 204" oracle
 * property intact: the answer depends on where the request came from and never
 * on whether the credential it carried was real. No cookie is set or cleared.
 */
function crossSite(reply: FastifyReply): FastifyReply {
  return reply.code(403).send({ error: "cross_site" });
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

/**
 * `401` plus the two clearing cookies.
 *
 * Only reached when the request **did** present a refresh token, so the
 * clearing is a response to a credential the caller actually holds and is
 * dead — it stops a client looping on a token Ward has forgotten. The
 * no-token case answers the same `401` without touching any cookie; see the
 * header.
 */
/**
 * The single rejection path for `/refresh`. Status and body are identical for
 * every failure — unknown, expired, revoked, raced or replayed — because the
 * wire must not confirm that a presented token was genuine.
 *
 * `clearCookies` is the one thing that varies, and only for a **race**.
 *
 * Clearing exists to stop a client looping on a token that is dead: it lands
 * them on the login page instead. In a race the session is **not** dead — the
 * winning tab's `R2` is live in the cookie jar this response shares — so
 * clearing here does not tidy up after a dead session, it destroys a live one.
 * Both responses are in flight to one jar at once (the estate is one origin, so
 * every tab and all six apps share it), and if the loser's `401` lands after
 * the winner's `200` the browser drops `ward_session` and `ward_refresh` and
 * signs the person out — which is the exact outcome leaving the family alive
 * was meant to prevent. Clearing on this branch made a certain session loss
 * into a coin flip rather than a fix.
 *
 * The cost is honest and small: the absence of `Set-Cookie` tells a caller that
 * the token they presented was genuine *and* was rotated within
 * `REFRESH_RACE_GRACE_SECONDS`. Anyone able to ask that question is already
 * holding the token, so they already know it was genuine; and they can learn
 * the same thing far more clearly by simply presenting it again after the
 * window, which kills the family. Weigh that against signing someone out every
 * other time two of their tabs wake up together.
 */
function refreshRejected(
  reply: FastifyReply,
  secure: boolean,
  options: { clearCookies?: boolean } = {},
): FastifyReply {
  if (options.clearCookies ?? true) {
    clearSessionCookies(reply, secure);
  }
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
