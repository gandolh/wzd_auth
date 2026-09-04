import type { FastifyInstance } from "fastify";
import { z } from "zod";

import { consoleActor } from "../../audit.js";
import { requireConsoleSession } from "../../auth/console-guard.js";
import { getApp } from "../../db/apps.js";
import { listGrantsForApp, listGrantsForSubject } from "../../db/grants.js";
import { findUserBySubject } from "../../db/users.js";
import { addGrant, removeAppAccess, removeGrant } from "../../grants/write.js";
import {
  databaseResolver,
  grantView,
  isForeignKeyViolation,
  type AdminRoutesOptions,
} from "./support.js";

/**
 * The grant surface: `GET`, `POST`, `DELETE /console/grants`.
 *
 * A grant is `(subject, app, role)` and it is the estate's actual security
 * boundary. Holding a Ward account confers nothing; without a row here for a
 * given app, a valid account cannot use that app at all
 * (`corpus/wiki/decisions-accounts.md`). This is where those rows are made and
 * unmade, and it is the reason the audit log exists.
 *
 * ## Idempotence, both directions
 *
 * Granting a role someone already holds is a **success**, and so is revoking one
 * they never had. That is not leniency: the console is a page an operator
 * refreshes and double-clicks, and a surface where the second click is an error
 * teaches them to distrust the first. `grants/write.ts` gets it from the
 * database — `ON CONFLICT DO NOTHING` and a `DELETE` that matches nothing — so
 * there is no check-then-write gap for two concurrent clicks to fall through.
 *
 * Every response says whether anything actually changed, and a no-op writes no
 * audit row.
 *
 * ## Roles are opaque and no wildcard exists
 *
 * Nothing here validates a role against a list, because there is no list: Ward
 * knows `(cristian, prm, admin)` and not what an admin may do. And there is no
 * "grant everywhere" — even the owner account holds one explicit row per app, so
 * a newly-registered app is reachable by nobody until someone says otherwise.
 * Six explicit grants are also six auditable rows.
 *
 * ## Why the mutating routes carry a body rather than a path
 *
 * `POST` and `DELETE` both take `{ subject, appSlug, role }` in the body, and
 * the role is deliberately **not** a path segment. A role is an opaque string
 * that may contain `/`, `%` or `:`; putting one in a URL means every caller gets
 * the encoding right forever, and `app.ts` records that Fastify's default
 * request log line includes the URL on every request. A body has neither
 * problem.
 */

/** A subject as it appears in a `sub` claim or a grant row. Opaque, bounded. */
const subject = z.string().min(1).max(64);
/** A slug. Loose here — existence is the check that matters, and the FK makes it. */
const appSlug = z.string().min(1).max(64);
/**
 * A role. **No character class and no allow-list**, by decision: role strings
 * are opaque and Ward never interprets one. Bounded only so a request cannot
 * hand the database a megabyte.
 */
const role = z.string().min(1).max(128);

const grantBody = z.object({ subject, appSlug, role });

/**
 * A revocation names a triple, or omits the role to mean "every role this person
 * holds in this app" — the console's "revoke access" as against "remove this one
 * role". One route rather than two, because it is one question with a narrower
 * and a wider answer.
 */
const revokeBody = z.object({ subject, appSlug, role: role.optional() });

/** Exactly one filter. Listing every grant in the estate is not a question. */
const listQuery = z
  .object({ subject: subject.optional(), app: appSlug.optional() })
  .refine((q) => (q.subject === undefined) !== (q.app === undefined), {
    message: "exactly one of subject or app",
  });

export async function adminGrantsRoutes(
  app: FastifyInstance,
  options: AdminRoutesOptions = {},
): Promise<void> {
  const database = databaseResolver(options);

  // The gate, for the whole plugin scope — see the note in `apps.ts`. Every
  // route in this file changes or reveals who can reach what.
  app.addHook("preHandler", requireConsoleSession);

  /**
   * `GET /console/grants?subject=…` or `?app=…`
   *
   * A missing subject or slug is a `404` rather than an empty list. An empty
   * list is the correct answer for "this person has no grants" and the wrong
   * answer for "you mistyped the subject", and the console cannot tell them
   * apart.
   */
  app.get("/console/grants", async (request, reply) => {
    const query = listQuery.safeParse(request.query);
    if (!query.success) {
      return reply.code(400).send({ error: "invalid_request" });
    }

    const db = await database();

    if (query.data.subject !== undefined) {
      if (findUserBySubject(db, query.data.subject) === undefined) {
        return reply.code(404).send({ error: "account_not_found" });
      }
      return reply
        .code(200)
        .send({ grants: listGrantsForSubject(db, query.data.subject).map(grantView) });
    }

    const slug = query.data.app!;
    if (getApp(db, slug) === undefined) {
      return reply.code(404).send({ error: "app_not_found" });
    }
    return reply.code(200).send({ grants: listGrantsForApp(db, slug).map(grantView) });
  });

  /**
   * `POST /console/grants` — issue one grant.
   *
   * Always `200`, never `201`, and `created` in the body says which happened.
   * A status code that changes on a repeat makes an idempotent retry look like a
   * different outcome, which is precisely what the console must not have to
   * reason about.
   *
   * Both ends are looked up first so a typo answers `404` naming which end was
   * wrong, and the foreign-key violation is still caught: between the lookup and
   * the insert an app can be deleted, and only the database observes both.
   */
  app.post("/console/grants", async (request, reply) => {
    const body = grantBody.safeParse(request.body);
    if (!body.success) {
      return reply.code(400).send({ error: "invalid_request" });
    }

    const db = await database();
    const account = findUserBySubject(db, body.data.subject);
    if (account === undefined) {
      return reply.code(404).send({ error: "account_not_found" });
    }
    if (getApp(db, body.data.appSlug) === undefined) {
      return reply.code(404).send({ error: "app_not_found" });
    }

    /**
     * A **disabled** account may still be granted a role, on purpose. Disabling
     * is a door being locked, not an identity being destroyed: grants survive it
     * so that re-enabling restores exactly what was there. Refusing to edit them
     * meanwhile would mean an operator preparing someone's return has to
     * un-disable the account first, which is the one moment they least want it
     * live.
     */
    try {
      const result = addGrant(db, consoleActor(request), body.data);
      return reply.code(200).send({ grant: grantView(result.grant), created: result.created });
    } catch (error) {
      if (isForeignKeyViolation(error)) {
        // The race the lookups above cannot close.
        return reply.code(404).send({ error: "grant_target_missing" });
      }
      throw error;
    }
  });

  /**
   * `DELETE /console/grants` — remove one role, or all roles in one app.
   *
   * `200` with `removed` (a count) and `roles` (what went) whether or not
   * anything was there. Revoking a grant nobody holds is not an error, and the
   * count is how the console tells "already gone" from "just removed" without
   * having to treat one of them as a failure.
   *
   * No existence check on either end: the answer for a subject that does not
   * exist and for one that holds no such grant is the same — nothing to remove —
   * and a `404` here would be a slower way of saying `removed: 0` while also
   * confirming to a caller whether a given subject exists.
   */
  app.delete("/console/grants", async (request, reply) => {
    const body = revokeBody.safeParse(request.body);
    if (!body.success) {
      return reply.code(400).send({ error: "invalid_request" });
    }

    const db = await database();
    const actor = consoleActor(request);

    if (body.data.role === undefined) {
      const result = removeAppAccess(db, actor, {
        subject: body.data.subject,
        appSlug: body.data.appSlug,
      });
      return reply.code(200).send({ removed: result.removed, roles: result.roles });
    }

    const target = { ...body.data, role: body.data.role };
    const result = removeGrant(db, actor, target);
    return reply
      .code(200)
      .send({ removed: result.removed ? 1 : 0, roles: result.removed ? [target.role] : [] });
  });
}
