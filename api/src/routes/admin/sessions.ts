import type Database from "better-sqlite3";
import type { FastifyInstance } from "fastify";
import { z } from "zod";

import { recordConsoleAudit } from "../../audit.js";
import { requireConsoleSession } from "../../auth/console-guard.js";
import {
  listLiveTokensForSubject,
  revokeAllForSubject,
  revokeFamily,
  type RefreshTokenRow,
} from "../../db/refresh-tokens.js";
import { findUserBySubject } from "../../db/users.js";
import { databaseResolver, type AdminRoutesOptions } from "./support.js";

/**
 * The console's session surface: list an account's live sessions, revoke one,
 * revoke them all.
 *
 * - `GET    /console/accounts/:subject/sessions`
 * - `DELETE /console/accounts/:subject/sessions/:familyId`
 * - `POST   /console/accounts/:subject/sessions/revoke`
 *
 * ## Why these are three routes and not a flag on `accounts.ts`
 *
 * `GET /console/accounts/:subject` already reports `liveSessions` as a
 * **count**, which is exactly enough to make "disabling ends live sessions"
 * visible and nothing like enough to act on. Brief 10 rendered the honest
 * consequence: it could tell an operator *that* four devices were signed in and
 * not *which*, and it had to compose "end all sessions" out of **disable →
 * re-enable** — two audit rows for one intent, a window in which the account
 * cannot sign in, and a failure between the two calls leaving it disabled. The
 * acceptance criterion it could not verify at all was the one that matters:
 * *revoking a session from the console ends it in the target app within 30
 * seconds*.
 *
 * ## `token_hash` never leaves the database
 *
 * A live `refresh_tokens` row **is** the credential — `sha256(token)` is the
 * lookup key, so a leaked hash is not a login, but it is still the one column a
 * console screen has no use for whatsoever. `sessionView` below projects four
 * fields and there is no code path here that spreads a row.
 *
 * ## One row per family, not one row per token
 *
 * A family is a device: one sign-in, rotating forward. Rotation revokes the
 * predecessor as it issues the successor, so a family contributes exactly one
 * live row — except inside `REFRESH_RACE_GRACE_SECONDS`, where a raced refresh
 * leaves two. Listing rows rather than families would show one device twice for
 * ten seconds and make an operator believe a session they do not have; so the
 * newest live row per family is what is projected, and the count an operator is
 * given is a count of families.
 */

/** The `:subject` path parameter. Same shape as `accounts.ts`, deliberately. */
const subjectParams = z.object({
  subject: z.string().min(1).max(64),
});

/**
 * `:subject` plus `:familyId`.
 *
 * `newFamilyId()` is 16 random bytes as hex, so 32 characters — but the bound
 * here is loose rather than a `/^[0-9a-f]{32}$/`, because `refresh_tokens`
 * constrains `family_id` only to being non-empty and a row predating any format
 * change must still be revocable. Existence, and ownership, are the real checks.
 */
const familyParams = z.object({
  subject: z.string().min(1).max(64),
  familyId: z.string().min(1).max(128),
});

/** A live session as the console renders it. **No `token_hash`.** */
export interface SessionView {
  /** The device. This is what `DELETE .../sessions/:familyId` takes. */
  familyId: string;
  /**
   * When the **current** token in this family was issued — that is, the last
   * refresh, not the original sign-in. The family's first row carries that, and
   * it is deliberately not fetched: it would be one extra query per device to
   * report a timestamp nobody can act on, and a session that refreshed four
   * minutes ago is the useful fact for deciding whether a device is in use.
   */
  issuedAt: string;
  expiresAt: string;
  /**
   * Non-null only for a token that was spent and somehow left live — which in
   * practice means a refresh raced inside the grace window. Surfaced rather
   * than hidden because a non-null value here on a live row is the one thing on
   * this screen that is worth a second look.
   */
  usedAt: string | null;
}

function sessionView(row: RefreshTokenRow): SessionView {
  return {
    familyId: row.family_id,
    issuedAt: row.issued_at,
    expiresAt: row.expires_at,
    usedAt: row.used_at,
  };
}

/**
 * The live families for an account, newest first, one entry each.
 *
 * `listLiveTokensForSubject` returns rows ordered `issued_at DESC`, so the
 * first row seen for a family is its newest live member and later ones are
 * dropped.
 */
function liveSessions(db: Database.Database, subject: string): SessionView[] {
  const seen = new Set<string>();
  const sessions: SessionView[] = [];

  for (const row of listLiveTokensForSubject(db, subject)) {
    if (seen.has(row.family_id)) continue;
    seen.add(row.family_id);
    sessions.push(sessionView(row));
  }

  return sessions;
}

export async function adminSessionsRoutes(
  app: FastifyInstance,
  options: AdminRoutesOptions = {},
): Promise<void> {
  const database = databaseResolver(options);

  // The gate, for the whole plugin scope — see the note in `apps.ts`.
  app.addHook("preHandler", requireConsoleSession);

  /**
   * `GET /console/accounts/:subject/sessions` — which devices are signed in.
   *
   * `404 account_not_found` for a subject with no row, matching the sibling
   * routes in `accounts.ts`. An account that exists and holds nothing answers
   * `200` with an empty list: "nobody is signed in" and "no such account" are
   * different facts and the console shows both differently.
   */
  app.get("/console/accounts/:subject/sessions", async (request, reply) => {
    const params = subjectParams.safeParse(request.params);
    if (!params.success) {
      return reply.code(400).send({ error: "invalid_request" });
    }

    reply.header("cache-control", "no-store");

    const db = await database();
    const account = findUserBySubject(db, params.data.subject);
    if (account === undefined) {
      return reply.code(404).send({ error: "account_not_found" });
    }

    const sessions = liveSessions(db, account.subject);
    return reply.code(200).send({ sessions, total: sessions.length });
  });

  /**
   * `DELETE /console/accounts/:subject/sessions/:familyId` — end one device.
   *
   * This is the call that makes an operator's answer to a suspected theft real,
   * and it is what brief 10's unverifiable acceptance criterion needs: the
   * family dies here, `/introspect` reports `active: false` for its access
   * token on the next check, and every app stops honouring it within its 30
   * second cache window.
   *
   * ## The subject is verified even though the revoke does not need it
   *
   * `revokeFamily` is keyed on `family_id` alone, so `:subject` is redundant to
   * the write. It is checked anyway, and refusing the mismatch is the point: a
   * console that revokes any family id given any subject is a console whose
   * URLs cannot be trusted in an audit row, a bug report or a log line — the
   * row would name an account that had nothing to do with the session that
   * ended. `hasLiveFamily` in `grants/resolve.ts` makes the same argument for
   * the same pair and calls it "safe to hold wrong rather than merely unlikely
   * to be held wrong".
   *
   * A family that belongs to somebody else answers `404 session_not_found`,
   * identically to one that does not exist. Saying "that family is real but not
   * theirs" would confirm a family id to a caller who guessed it, and the
   * console has no use for the distinction.
   *
   * Idempotent: a family whose rows are all already revoked answers `200` with
   * `revoked: 0` and writes no audit row, matching brief 05's rule that a no-op
   * leaves no row (`changed: false` is how the UI still tells).
   */
  app.delete("/console/accounts/:subject/sessions/:familyId", async (request, reply) => {
    const params = familyParams.safeParse(request.params);
    if (!params.success) {
      return reply.code(400).send({ error: "invalid_request" });
    }

    reply.header("cache-control", "no-store");

    const db = await database();
    const account = findUserBySubject(db, params.data.subject);
    if (account === undefined) {
      return reply.code(404).send({ error: "account_not_found" });
    }

    /**
     * Ownership is decided from the live rows for **this** subject rather than
     * from `listFamily(familyId)`. Same answer, one query, and it cannot be
     * read the wrong way round: there is no path here on which a family id from
     * the URL selects the rows that then vouch for themselves.
     */
    const owned = liveSessions(db, account.subject).some(
      (session) => session.familyId === params.data.familyId,
    );
    if (!owned) {
      return reply.code(404).send({ error: "session_not_found" });
    }

    const revoked = db.transaction((): number => {
      const count = revokeFamily(db, params.data.familyId, "admin");

      if (count > 0) {
        recordConsoleAudit(db, request, {
          action: "session.revoke",
          targetKind: "session",
          targetId: params.data.familyId,
          detail: {
            subject: account.subject,
            username: account.username,
            tokensRevoked: count,
          },
        });
      }

      return count;
    })();

    return reply.code(200).send({
      subject: account.subject,
      familyId: params.data.familyId,
      revoked,
      changed: revoked > 0,
    });
  });

  /**
   * `POST /console/accounts/:subject/sessions/revoke` — end every session, with
   * no side effect.
   *
   * `revokeAllForSubject` has existed since brief 01 and was reachable only
   * through **disable** or **password rotation**, so brief 10 had to compose the
   * intent out of disable → re-enable. It rendered that cost honestly, and it
   * should not have to: two audit rows for one intent, a window where the person
   * cannot sign in, and a failure between the two calls leaving the account
   * disabled with no indication that was not what anybody asked for.
   *
   * The account's `disabled_at`, grants, password and email are untouched. It
   * can sign in again immediately, which is the whole difference from disable.
   *
   * Returns the count of **families** ended, not of rows revoked, so the number
   * an operator reads is a number of devices. Idempotent, and a no-op writes no
   * audit row.
   */
  app.post("/console/accounts/:subject/sessions/revoke", async (request, reply) => {
    const params = subjectParams.safeParse(request.params);
    if (!params.success) {
      return reply.code(400).send({ error: "invalid_request" });
    }

    reply.header("cache-control", "no-store");

    const db = await database();
    const account = findUserBySubject(db, params.data.subject);
    if (account === undefined) {
      return reply.code(404).send({ error: "account_not_found" });
    }

    const result = db.transaction((): { revoked: number; tokensRevoked: number } => {
      // Counted inside the transaction, before the write, so the number
      // reported and the rows revoked cannot describe two different moments.
      const families = liveSessions(db, account.subject).length;
      const tokensRevoked = revokeAllForSubject(db, account.subject, "admin");

      if (tokensRevoked > 0) {
        recordConsoleAudit(db, request, {
          action: "session.revoke_all",
          targetKind: "user",
          targetId: account.subject,
          detail: {
            username: account.username,
            sessionsRevoked: families,
            tokensRevoked,
          },
        });
      }

      return { revoked: families, tokensRevoked };
    })();

    return reply.code(200).send({
      subject: account.subject,
      revoked: result.revoked,
      tokensRevoked: result.tokensRevoked,
      changed: result.tokensRevoked > 0,
    });
  });
}
