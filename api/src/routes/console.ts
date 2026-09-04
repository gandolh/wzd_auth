import type Database from "better-sqlite3";
import type { FastifyInstance, FastifyRequest } from "fastify";
import { z } from "zod";

import {
  checkLockout,
  clearFailures,
  lockoutKeyFor,
  recordFailure,
  type LockoutTarget,
} from "../auth/lockout.js";
import { requireConsoleSession, getConsoleSession } from "../auth/console-guard.js";
import {
  checkSuperuserCredentials,
  closeConsoleSession,
  consoleCookieSecure,
  consoleSessionClearCookie,
  consoleSessionSetCookie,
  CONSOLE_SESSION_IDLE_TIMEOUT_SECONDS,
  openConsoleSession,
  readConsoleCookie,
  type ConsoleSession,
} from "../auth/superuser.js";
import { recordAudit, SUPERUSER_LABEL } from "../db/audit-log.js";
import { getDb } from "../db/connection.js";

/**
 * The console **session** routes: `POST /console/login`, `POST /console/logout`,
 * `GET /console/session`.
 *
 * Only the session lives here. Brief 05 owns the console's *admin* routes — apps,
 * grants, accounts — in its own file, and gates them by importing
 * `requireConsoleSession` from `../auth/console-guard.js`. Keeping the two apart
 * matters more than it looks: this file is the one place in Ward that answers an
 * unauthenticated request with a credential comparison, and a reviewer should be
 * able to read all of it at once.
 *
 * Ward is reverse-proxied under `/ward-api/*` with the prefix stripped, so these
 * are `/ward-api/console/login` and friends in the browser — which is why the
 * cookie's `Path` is `/ward-api/console` (see `CONSOLE_COOKIE_PATH`).
 *
 * ## Rotating the superuser password
 *
 * There is no route for it here and there must not be one. Rotation is an edit
 * to `WARD_ADMIN_PASSWORD` in the repo-root `.env` followed by a restart of the
 * Ward process — `decisions-admin.md` records that friction as *correct* for a
 * break-glass credential, and `config.ts` resolves the environment once at import
 * so a running process could not pick up a new value even if something tried.
 * The restart also empties the in-memory console session store, so a rotation
 * ends the sessions the old password opened. `.env.example` says the same thing
 * to the operator.
 *
 * Because the credential cannot be revoked or rotated without a redeploy, the
 * `audit_log` rows this file writes are its **only** observability. Every attempt
 * is recorded, successful or not, before the response is sent.
 */

/**
 * Registered by `api/src/app.ts` — the controller wires this in; this file does
 * not register itself.
 *
 * `options.db` exists for tests, which build their own Fastify instance and pass
 * an `openDatabase(":memory:")` handle. Production passes nothing and the routes
 * fall back to `getDb()`, which is async on purpose and resolves `WARD_DB_PATH`
 * through `config.js`.
 */
export interface ConsoleRoutesOptions {
  db?: Database.Database;
}

/** What `GET /console/session` and a successful login return. Non-secret. */
interface ConsoleSessionView {
  id: string;
  createdAt: string;
  lastSeenAt: string;
  idleExpiresAt: string;
  absoluteExpiresAt: string;
  idleTimeoutSeconds: number;
}

function sessionView(session: ConsoleSession): ConsoleSessionView {
  return {
    id: session.id,
    createdAt: session.createdAt.toISOString(),
    lastSeenAt: session.lastSeenAt.toISOString(),
    idleExpiresAt: session.idleExpiresAt.toISOString(),
    absoluteExpiresAt: session.absoluteExpiresAt.toISOString(),
    idleTimeoutSeconds: CONSOLE_SESSION_IDLE_TIMEOUT_SECONDS,
  };
}

/**
 * The login body. `z.string()` with no `.min()` on either field: length rules
 * belong to whoever *sets* the password (`.env`, validated by `config.ts` as
 * non-empty), and rejecting a short submission early would answer faster than a
 * long one — a length oracle on the way to a constant-time comparison.
 */
const loginBody = z.object({
  username: z.string(),
  password: z.string(),
});

/**
 * The lockout key: brief 03's own derivation, not `request.ip`.
 *
 * `request.ip` would be wrong here for the reason `lockout.ts` documents at
 * length — Ward binds loopback behind Caddy and `buildApp()` sets no
 * `trustProxy`, so Fastify's view of the peer is `127.0.0.1` for the entire
 * internet and the IP-keyed lockout would collapse into one global counter that
 * the sixth failed login anywhere in the estate trips. `lockoutKeyFor` honours
 * `X-Forwarded-For` only when the peer is loopback, and reads its **last**
 * element, which is the address Caddy actually observed.
 *
 * Using brief 03's helper rather than a second derivation is deliberate:
 * `/login` and `/console/login` must agree on what an address is, or an attacker
 * gets two independent budgets from one machine.
 *
 * The **counter**, on the other hand, is namespaced (`surface: "console"`) and
 * must stay that way. Sharing it with `/login` meant five wrong account logins
 * from an address made a *correct* break-glass login from that address answer
 * `429`, and on a one-operator estate behind a home NAT that is the same
 * address. The superuser exists for when things are broken — including when
 * `/login` is being attacked — so it cannot share a budget with the surface
 * under attack. Same reasoning as the malformed-body carve-out below.
 */
function lockoutKey(request: FastifyRequest): string {
  return lockoutKeyFor(request.socket.remoteAddress, request.headers["x-forwarded-for"], {
    warn: (detail, message) => {
      request.log.warn(detail, message);
    },
  });
}

/**
 * The console's own failure budget for one address.
 *
 * No `account`: there is exactly one console credential, so there is no account
 * to name and no cross-account wipe to worry about — a success here proves the
 * operator and clears this address's console failures, which is the whole
 * intent.
 */
function consoleLockoutTarget(address: string): LockoutTarget {
  return { surface: "console", address };
}

export async function consoleRoutes(
  app: FastifyInstance,
  options: ConsoleRoutesOptions = {},
): Promise<void> {
  const resolveDb = async (): Promise<Database.Database> => options.db ?? (await getDb());

  // Encapsulated to this plugin. Everything on the console is administrative,
  // per-operator and stale immediately; a shared cache holding any of it has no
  // upside. `console-guard.ts` sets the same header for brief 05's routes.
  app.addHook("onRequest", async (_request, reply) => {
    reply.header("cache-control", "no-store");
  });

  /**
   * `POST /console/login`
   *
   * The order of operations is the security-relevant part:
   *
   *  1. **Lockout first.** A locked-out caller never reaches the comparison, so
   *     the endpoint costs nothing to refuse. No artificial delay is added
   *     anywhere — brief 03's reasoning holds here too: holding a connection
   *     open *is* the denial of service the measure exists to prevent.
   *  2. **Shape next**, and a malformed body is a 400 that is audited but does
   *     **not** count toward the lockout. It carries no credential guess, and
   *     counting it would let a bug in the console UI lock the operator out of
   *     the one credential that still works when everything else is broken.
   *  3. **Credentials last**, against the environment only. Nothing is read from
   *     the database on this path except the audit insert, and **no row is
   *     created in `users` or `grants` — not on success, not ever.** The
   *     superuser has no account row; that is the decision, and it is asserted
   *     by a test against both tables.
   */
  app.post("/console/login", async (request, reply) => {
    const db = await resolveDb();
    const ip = lockoutKey(request);

    const lockout = checkLockout(consoleLockoutTarget(ip));
    if (!lockout.allowed) {
      recordAudit(db, {
        actorKind: "system",
        actorLabel: "console-login",
        action: "console.login.failed",
        detail: { ip, reason: "locked-out" },
      });
      if (lockout.retryAfterSeconds !== undefined) {
        reply.header("retry-after", String(lockout.retryAfterSeconds));
      }
      return reply.code(429).send({ error: "too many attempts" });
    }

    const body = loginBody.safeParse(request.body);
    if (!body.success) {
      recordAudit(db, {
        actorKind: "system",
        actorLabel: "console-login",
        action: "console.login.failed",
        detail: { ip, reason: "malformed" },
      });
      return reply.code(400).send({ error: "username and password are required" });
    }

    const ok = await checkSuperuserCredentials(body.data.username, body.data.password);

    if (!ok) {
      recordFailure(consoleLockoutTarget(ip));
      /**
       * The submitted username is deliberately **not** recorded. There is
       * exactly one console credential, so "which username was tried" has one
       * interesting answer and the boolean above already gives it; meanwhile a
       * username field is where a mistyped password lands, and `audit_log` is
       * rendered in the console. `reason` is enough to reconstruct the attempt.
       */
      recordAudit(db, {
        actorKind: "system",
        actorLabel: "console-login",
        action: "console.login.failed",
        detail: { ip, reason: "credentials" },
      });
      // Same body as a wrong username and a wrong password. No oracle.
      return reply.code(401).send({ error: "invalid credentials" });
    }

    clearFailures(consoleLockoutTarget(ip));
    const { token, session } = openConsoleSession();

    /**
     * `actorKind: "superuser"` with a null `actor_subject` — the shape
     * `audit-log.ts` documents for exactly this actor, and the reason that table
     * has no foreign keys. Do not invent a sentinel subject to put here; the
     * superuser has none, and a placeholder would be the rejected sentinel
     * arriving through the audit log.
     *
     * A failed attempt above is `system` instead, because nothing has proved the
     * superuser was involved — attributing a wrong password to the superuser
     * would make the log claim an identity the request never established.
     */
    recordAudit(db, {
      actorKind: "superuser",
      actorLabel: SUPERUSER_LABEL,
      action: "console.login",
      targetKind: "session",
      targetId: session.id,
      detail: { ip },
    });

    /**
     * The token goes in the `HttpOnly` cookie and **nowhere else** — never in
     * the response body, which would hand it to any script on the origin and
     * make `HttpOnly` decorative. The body carries only the non-secret session
     * view the console UI needs to show a countdown.
     */
    reply.header(
      "set-cookie",
      consoleSessionSetCookie(token, { secure: await consoleCookieSecure() }),
    );
    return reply.code(200).send({ session: sessionView(session) });
  });

  /**
   * `POST /console/logout`
   *
   * Ungated and idempotent: it clears the cookie whatever happens, so a caller
   * holding a session that expired minutes ago still ends up in a clean state
   * rather than staring at a 401 with a dead cookie it cannot remove. An audit
   * row is written only when a live session was actually closed — an
   * unauthenticated POST here is not an event, and auditing it would hand an
   * anonymous caller a way to fill the log.
   */
  app.post("/console/logout", async (request, reply) => {
    const token = readConsoleCookie(request.headers.cookie);
    const closed = token === undefined ? undefined : closeConsoleSession(token);

    if (closed !== undefined) {
      recordAudit(await resolveDb(), {
        actorKind: "superuser",
        actorLabel: SUPERUSER_LABEL,
        action: "console.logout",
        targetKind: "session",
        targetId: closed.id,
        detail: { ip: lockoutKey(request) },
      });
    }

    reply.header("set-cookie", consoleSessionClearCookie({ secure: await consoleCookieSecure() }));
    return reply.code(204).send();
  });

  /**
   * `GET /console/session` — what the console UI polls to know whether it is
   * still signed in. Gated, so an anonymous caller gets the same opaque 401 as
   * on any other console route, and touching it slides the idle window (which is
   * what "idle" should mean for a UI that is genuinely in use).
   */
  app.get("/console/session", { preHandler: requireConsoleSession }, async (request, reply) => {
    const session = getConsoleSession(request);
    if (session === undefined) {
      // Unreachable: the guard admitted the request. Belt and braces, and it
      // keeps the handler honest about the fact that it has no other identity
      // source to fall back on.
      return reply.code(401).send({ error: "unauthorized" });
    }
    return reply.code(200).send({ session: sessionView(session) });
  });
}
