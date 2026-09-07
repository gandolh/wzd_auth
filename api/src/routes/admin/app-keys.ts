import type { FastifyInstance } from "fastify";
import { z } from "zod";

import { recordConsoleAudit } from "../../audit.js";
import { requireConsoleSession } from "../../auth/console-guard.js";
import { getApp } from "../../db/apps.js";
import {
  createAppKey,
  getAppKey,
  listAppKeys,
  listAppKeysForApp,
  revokeAppKey,
} from "../../db/app-keys.js";
import { SUPERUSER_LABEL } from "../../db/audit-log.js";
import {
  appKeyView,
  databaseResolver,
  isForeignKeyViolation,
  type AdminRoutesOptions,
} from "./support.js";

/**
 * App keys, from the console: `GET /console/app-keys`,
 * `GET`/`POST /console/apps/:slug/keys`, and
 * `POST /console/app-keys/:id/revoke`.
 *
 * The credential six apps use to reach `POST /introspect`
 * (`auth/app-key.ts`). Everything structural about it is in the migration; what
 * this file adds is the two operator-facing facts.
 *
 * ## The key is shown exactly once
 *
 * `POST .../keys` is the only response in Ward that contains a usable app key,
 * and there is no route that reads one back. The database holds `sha256(key)`
 * and nothing can invert it, so "I lost it" is answered by issuing a second key
 * and revoking the first — which is the same motion as a rotation and is why
 * an app is allowed more than one live key at a time.
 *
 * That plurality is the deliberate part. Rotation across an estate where the
 * apps deploy independently is: issue a new key, roll it out, confirm the old
 * one has stopped being used (`lastUsedAt` on the list), revoke the old one.
 * A one-key-per-app constraint would force that sequence into a window where
 * the app has no working key at all, which is an outage on every rotation, so
 * there is no such constraint and there must not be one.
 *
 * ## Revocation is immediate and unconditional
 *
 * No cache sits in front of `resolveAppKey` — it reads the row on every call —
 * so revoking takes effect on the calling app's very next request, not within
 * the 30 seconds a session revocation takes. That asymmetry is correct: a
 * session revocation is bounded by each app's own introspection cache, which
 * this credential is not part of.
 *
 * Revoking is also the one console action here with estate-visible
 * consequences: the named app stops being able to introspect at all, so every
 * one of its users is refused within seconds. `@ward/client` surfaces that as a
 * `WardConfigurationError` rather than as a signed-out user, which is what makes
 * it diagnosable, but it is still an outage for that app and the console says
 * so before it happens.
 *
 * ## There is no un-revoke and no edit
 *
 * A revoked key stays revoked (`db/app-keys.ts#revokeAppKey`), and a label
 * cannot be changed. Both keep the row honest as an audit anchor: `app_keys.id`
 * appears in `audit_log.target_id`, and a row whose meaning can be edited after
 * the fact is a poor thing to point an audit trail at. Issuing a replacement
 * costs one click.
 */

const slugParams = z.object({ slug: z.string().min(1).max(64) });

/**
 * `app_keys.id` is 32 hex characters. Validated to that exactly, because it
 * reaches SQL as a bound value and because a caller passing a *key* here
 * instead of an id — the mistake this surface most invites — should be refused
 * by shape rather than by a lookup miss, so the key never becomes a `WHERE`
 * argument that could reach a log.
 */
const keyIdParams = z.object({ id: z.string().regex(/^[0-9a-f]{32}$/) });

/**
 * The label. Required, and deliberately not defaulted to the app slug: the
 * whole job of this field is to tell two keys for the same app apart, and a
 * default would make every key read "atrium" at the moment an operator most
 * needs to know which one is the laptop's.
 */
const createKeyBody = z.object({
  label: z.string().trim().min(1).max(128),
});

export async function adminAppKeysRoutes(
  app: FastifyInstance,
  options: AdminRoutesOptions = {},
): Promise<void> {
  const database = databaseResolver(options);

  // The gate for the whole plugin scope, in one line — see `admin/apps.ts` on
  // why this is a plugin-wide `preHandler` and never a per-route opt-in.
  app.addHook("preHandler", requireConsoleSession);

  /** `GET /console/app-keys` — every key in the estate, grouped by app. */
  app.get("/console/app-keys", async (_request, reply) => {
    const db = await database();
    return reply.code(200).send({ keys: listAppKeys(db).map(appKeyView) });
  });

  /** `GET /console/apps/:slug/keys` — one app's keys, newest first. */
  app.get("/console/apps/:slug/keys", async (request, reply) => {
    const params = slugParams.safeParse(request.params);
    if (!params.success) {
      return reply.code(400).send({ error: "invalid_request" });
    }

    const db = await database();
    if (getApp(db, params.data.slug) === undefined) {
      return reply.code(404).send({ error: "app_not_found" });
    }

    return reply.code(200).send({ keys: listAppKeysForApp(db, params.data.slug).map(appKeyView) });
  });

  /**
   * `POST /console/apps/:slug/keys` — issue a key.
   *
   * `201 { key, appKey }`. **`key` is the plaintext and appears here and
   * nowhere else, ever.** `appKey` is the row as every other route renders it,
   * so the console can append it to its list without a refetch.
   */
  app.post("/console/apps/:slug/keys", async (request, reply) => {
    const params = slugParams.safeParse(request.params);
    const body = createKeyBody.safeParse(request.body);
    if (!params.success || !body.success) {
      return reply.code(400).send({ error: "invalid_request" });
    }

    const db = await database();
    if (getApp(db, params.data.slug) === undefined) {
      return reply.code(404).send({ error: "app_not_found" });
    }

    let minted;
    try {
      minted = db.transaction(() => {
        const result = createAppKey(db, {
          appSlug: params.data.slug,
          label: body.data.label,
          // The console has one identity and it has no subject; `grants` records
          // the same sentinel in `granted_by` for the same reason.
          createdBy: SUPERUSER_LABEL,
        });

        recordConsoleAudit(db, request, {
          action: "app_key.create",
          targetKind: "app",
          // The **app**, not the key: an operator scanning the log asks "who
          // gave something the ability to introspect as atrium", and the key id
          // is in `detail` for when they need to follow it to a specific row.
          targetId: params.data.slug,
          detail: { keyId: result.row.id, label: result.row.label },
        });

        return result;
      })();
    } catch (error) {
      // The app was deleted between the lookup above and this insert. The
      // lookup exists for a clean 404; this is the backstop, because the
      // database is the only thing that observes both statements at once.
      if (isForeignKeyViolation(error)) {
        return reply.code(404).send({ error: "app_not_found" });
      }
      throw error;
    }

    /**
     * `no-store`, and this is the one response body in Ward that genuinely must
     * not be cached anywhere: it carries a live credential for a whole app. The
     * console session's other responses are per-person data; this one is worth
     * the explicit header even though nothing in the chain is likely to store a
     * `201`.
     */
    reply.header("cache-control", "no-store");

    return reply.code(201).send({
      key: minted.key,
      appKey: appKeyView(minted.row),
    });
  });

  /**
   * `POST /console/app-keys/:id/revoke` — turn a key off.
   *
   * `200` on success, `404` if there is no such key, `409` if it was already
   * revoked. The 409 is not pedantry: re-revoking is almost always an operator
   * clicking twice on a stale list, and answering `200` would tell them they had
   * just turned off a key that had in fact been off since last week — which is
   * exactly the confusion that gets the *live* key revoked next.
   */
  app.post("/console/app-keys/:id/revoke", async (request, reply) => {
    const params = keyIdParams.safeParse(request.params);
    if (!params.success) {
      return reply.code(400).send({ error: "invalid_request" });
    }

    const db = await database();
    const existing = getAppKey(db, params.data.id);
    if (existing === undefined) {
      return reply.code(404).send({ error: "app_key_not_found" });
    }
    if (existing.revoked_at !== null) {
      return reply.code(409).send({ error: "app_key_already_revoked" });
    }

    const revoked = db.transaction((): boolean => {
      // `revokeAppKey` carries `revoked_at IS NULL` in its own `WHERE`, so the
      // check above is for the status code and this is what actually decides.
      // Between the two a concurrent revoke can win, and then this returns
      // false and the caller gets the 409 it should have got.
      if (!revokeAppKey(db, params.data.id)) return false;

      recordConsoleAudit(db, request, {
        action: "app_key.revoke",
        targetKind: "app",
        targetId: existing.app_slug,
        detail: { keyId: existing.id, label: existing.label },
      });

      return true;
    })();

    if (!revoked) {
      return reply.code(409).send({ error: "app_key_already_revoked" });
    }

    const after = getAppKey(db, params.data.id)!;
    return reply.code(200).send({ appKey: appKeyView(after) });
  });
}
