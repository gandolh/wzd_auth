import type { FastifyInstance } from "fastify";
import { z } from "zod";

import { recordConsoleAudit } from "../../audit.js";
import { requireConsoleSession } from "../../auth/console-guard.js";
import {
  createApp,
  deleteApp,
  getApp,
  listApps,
  renameApp,
  setPublicRegistration,
  type AppRow,
} from "../../db/apps.js";
import { listGrantsForApp } from "../../db/grants.js";
import {
  appView,
  databaseResolver,
  isCheckViolation,
  isUniqueViolation,
  SLUG_PATTERN,
  type AdminRoutesOptions,
} from "./support.js";

/**
 * The apps registry: `GET`, `POST /console/apps`, and `GET`, `PATCH`,
 * `DELETE /console/apps/:slug`.
 *
 * ## The paths must live under `/console`
 *
 * Not a naming preference — a functional requirement. The console session
 * cookie is scoped `Path=/ward-api/console` (`auth/superuser.ts`), and Caddy
 * serves Ward with `handle_path /ward-api/*`, which strips the prefix. A route
 * mounted anywhere else would simply never receive the cookie, and every request
 * to it would answer `401` no matter who was signed in.
 *
 * ## Creating an app must not require a deploy
 *
 * That is the whole reason this surface exists rather than a seed script. A
 * seventh app joins the estate by one `POST` here, and from that moment it is
 * registered, **closed to strangers, and reachable by nobody** — including the
 * owner account — until grants are issued for it. Nothing about the identity
 * service changes.
 *
 * ## Registration is closed by default, and that default is the decision
 *
 * `publicRegistration` omitted means closed. `db/apps.ts` defaults it to `0`,
 * the column defaults to `0`, and a CHECK refuses an open app with no baseline
 * role — three layers saying the same thing, because a new app being reachable
 * by strangers before anyone remembered to close it is the failure mode the flag
 * was chosen to prevent (`corpus/wiki/decisions-accounts.md`).
 *
 * Opening an app therefore requires naming the baseline role **in the same
 * request**: "open" and "confers what?" are one decision, and the routes below
 * refuse to split them. Closing an app clears the role, so a later reopen cannot
 * silently inherit an answer nobody re-checked. Existing grants are untouched —
 * closing registration stops new strangers, it does not evict the people already
 * inside.
 */

/** The `:slug` path parameter. Validated, because it reaches SQL as a bound value. */
const slugParams = z.object({
  slug: z.string().min(1).max(64),
});

/**
 * Names and roles are capped but otherwise unconstrained; the slug carries the
 * character rule (see `SLUG_PATTERN`).
 *
 * `baselineRole` gets **no** character class, deliberately. Role strings are
 * opaque by decision and Ward never interprets one — `grantTargetId` exists
 * precisely so that a role containing `:` is safe to record.
 */
const appName = z.string().trim().min(1).max(128);
const baselineRole = z.string().min(1).max(128);

const createAppBody = z.object({
  slug: z.string().trim().min(1).max(64).regex(SLUG_PATTERN),
  name: appName,
  publicRegistration: z.boolean().optional(),
  baselineRole: baselineRole.optional(),
});

/**
 * A patch names only what changes. At least one field is required — an empty
 * patch is a client bug, and answering `200` to it would let the console believe
 * a write happened.
 *
 * `baselineRole: null` is distinguishable from an absent `baselineRole` and
 * means "clear it", which is legal only alongside closing the app.
 */
const patchAppBody = z
  .object({
    name: appName.optional(),
    publicRegistration: z.boolean().optional(),
    baselineRole: baselineRole.nullable().optional(),
  })
  .refine((body) => Object.keys(body).length > 0, { message: "no fields to update" });

/** One field that changed, as the audit row records it. */
interface FieldChange {
  from: unknown;
  to: unknown;
}

export async function adminAppsRoutes(
  app: FastifyInstance,
  options: AdminRoutesOptions = {},
): Promise<void> {
  const database = databaseResolver(options);

  /**
   * The gate, for the whole plugin scope, in one line.
   *
   * There is no per-route opt-out and no unauthenticated route in this file. A
   * `preHandler` on the plugin means a route added later is gated by default
   * rather than by whoever remembers — the failure mode of per-route gating is
   * an ungated route, and on this surface an ungated route hands out the
   * estate's authority.
   *
   * Nothing here checks *which* identity got through, because there is only one:
   * `decisions-admin.md` records that console access cannot be delegated. There
   * is no `ward:admin` grant and nothing else opens this surface.
   */
  app.addHook("preHandler", requireConsoleSession);

  /** `GET /console/apps` — every app, slug order. The console's list. */
  app.get("/console/apps", async (_request, reply) => {
    const db = await database();
    return reply.code(200).send({ apps: listApps(db).map(appView) });
  });

  /** `GET /console/apps/:slug` — one app, with everyone who can reach it. */
  app.get("/console/apps/:slug", async (request, reply) => {
    const params = slugParams.safeParse(request.params);
    if (!params.success) {
      return reply.code(400).send({ error: "invalid_request" });
    }

    const db = await database();
    const row = getApp(db, params.data.slug);
    if (row === undefined) {
      return reply.code(404).send({ error: "app_not_found" });
    }

    return reply.code(200).send({
      app: appView(row),
      grantCount: listGrantsForApp(db, row.slug).length,
    });
  });

  /**
   * `POST /console/apps` — register an app.
   *
   * `201` with the stored row. `409` on a slug that is taken, decided by the
   * PRIMARY KEY rather than by a `getApp` first: a check-then-insert has a race
   * between the two statements and the constraint does not.
   */
  app.post("/console/apps", async (request, reply) => {
    const body = createAppBody.safeParse(request.body);
    if (!body.success) {
      return reply.code(400).send({ error: "invalid_request" });
    }

    const { slug, name, publicRegistration = false } = body.data;
    const role = body.data.baselineRole;

    if (publicRegistration && role === undefined) {
      return reply.code(400).send({ error: "baseline_role_required" });
    }
    if (!publicRegistration && role !== undefined) {
      /**
       * Refused rather than ignored. A closed app carrying a baseline role is a
       * row whose reopening confers something nobody reviewed, and silently
       * dropping the field would leave the operator believing they had set it.
       */
      return reply.code(400).send({ error: "baseline_role_requires_open" });
    }

    const db = await database();

    let created: AppRow;
    try {
      created = db.transaction((): AppRow => {
        const row = createApp(db, {
          slug,
          name,
          publicRegistration,
          baselineRole: role ?? null,
        });

        recordConsoleAudit(db, request, {
          action: "app.create",
          targetKind: "app",
          targetId: row.slug,
          detail: {
            name: row.name,
            publicRegistration: row.public_registration === 1,
            baselineRole: row.baseline_role,
          },
        });

        return row;
      })();
    } catch (error) {
      if (isUniqueViolation(error)) {
        return reply.code(409).send({ error: "app_exists" });
      }
      // The CHECKs the validation above does not pre-empt — a name of only
      // whitespace, a slug the pattern let through. A specific 400 rather than
      // the error handler's `500 {"error":"internal"}`.
      if (isCheckViolation(error)) {
        return reply.code(400).send({ error: "invalid_request" });
      }
      throw error;
    }

    return reply.code(201).send({ app: appView(created) });
  });

  /**
   * `PATCH /console/apps/:slug` — rename, and open or close registration.
   *
   * **Two audit actions, not one.** A rename is `app.update`; a change to the
   * registration flag or the baseline role is `app.registration`. A single patch
   * doing both writes both rows, because "who renamed this" and "who opened this
   * to the public" are different questions and `audit_log.action` is how the
   * console asks them. The second is the one that matters: it is the only place
   * in Ward where an app becomes reachable by a stranger.
   *
   * A patch that changes nothing writes no audit row and still answers `200`.
   * The log records changes of authority; a form resubmitted unchanged is not
   * one, and auditing it would bury the rows an operator needs.
   */
  app.patch("/console/apps/:slug", async (request, reply) => {
    const params = slugParams.safeParse(request.params);
    const body = patchAppBody.safeParse(request.body);
    if (!params.success || !body.success) {
      return reply.code(400).send({ error: "invalid_request" });
    }

    const db = await database();
    const before = getApp(db, params.data.slug);
    if (before === undefined) {
      return reply.code(404).send({ error: "app_not_found" });
    }

    const touchesRegistration =
      body.data.publicRegistration !== undefined || body.data.baselineRole !== undefined;

    const open = body.data.publicRegistration ?? before.public_registration === 1;
    const role =
      body.data.baselineRole !== undefined ? body.data.baselineRole : before.baseline_role;

    if (open && role === null) {
      // Either opening with no role named, or clearing the role of an open app.
      // Both leave an app open to strangers that confers nothing, which the
      // schema refuses; this is the same refusal with a code the console can act
      // on.
      return reply.code(400).send({ error: "baseline_role_required" });
    }
    if (!open && body.data.baselineRole != null) {
      return reply.code(400).send({ error: "baseline_role_requires_open" });
    }

    let after: AppRow;
    try {
      after = db.transaction((): AppRow => {
        if (body.data.name !== undefined) {
          renameApp(db, before.slug, body.data.name);
        }
        if (touchesRegistration) {
          // `setPublicRegistration` clears the role when closing, whatever it is
          // handed — one write for both halves of one decision.
          setPublicRegistration(db, before.slug, open, open ? role : null);
        }

        const row = getApp(db, before.slug)!;

        const renamed: Record<string, FieldChange> = {};
        if (row.name !== before.name) {
          renamed["name"] = { from: before.name, to: row.name };
        }

        const registration: Record<string, FieldChange> = {};
        if (row.public_registration !== before.public_registration) {
          registration["publicRegistration"] = {
            from: before.public_registration === 1,
            to: row.public_registration === 1,
          };
        }
        if (row.baseline_role !== before.baseline_role) {
          registration["baselineRole"] = { from: before.baseline_role, to: row.baseline_role };
        }

        if (Object.keys(renamed).length > 0) {
          recordConsoleAudit(db, request, {
            action: "app.update",
            targetKind: "app",
            targetId: row.slug,
            detail: { changed: renamed },
          });
        }
        if (Object.keys(registration).length > 0) {
          recordConsoleAudit(db, request, {
            action: "app.registration",
            targetKind: "app",
            targetId: row.slug,
            detail: { changed: registration },
          });
        }

        return row;
      })();
    } catch (error) {
      if (isCheckViolation(error)) {
        return reply.code(400).send({ error: "invalid_request" });
      }
      throw error;
    }

    return reply.code(200).send({ app: appView(after) });
  });

  /**
   * `DELETE /console/apps/:slug` — remove an app.
   *
   * **This cascades to every grant for it** (`ON DELETE CASCADE`, live because
   * `openDatabase` sets `foreign_keys = ON`), which is the correct meaning —
   * removing an app removes everyone's access to it — and is also why the audit
   * row records how many grants went. Deleting an app is the one write on this
   * surface that silently removes rows the operator did not name, so the count
   * is the only trace left that they existed.
   */
  app.delete("/console/apps/:slug", async (request, reply) => {
    const params = slugParams.safeParse(request.params);
    if (!params.success) {
      return reply.code(400).send({ error: "invalid_request" });
    }

    const db = await database();
    const row = getApp(db, params.data.slug);
    if (row === undefined) {
      return reply.code(404).send({ error: "app_not_found" });
    }

    const grantsRevoked = db.transaction((): number => {
      // Counted before the delete, because the cascade takes the rows with it.
      const count = listGrantsForApp(db, row.slug).length;
      deleteApp(db, row.slug);

      recordConsoleAudit(db, request, {
        action: "app.delete",
        targetKind: "app",
        targetId: row.slug,
        detail: {
          name: row.name,
          publicRegistration: row.public_registration === 1,
          grantsRevoked: count,
        },
      });

      return count;
    })();

    return reply.code(200).send({ deleted: row.slug, grantsRevoked });
  });
}
