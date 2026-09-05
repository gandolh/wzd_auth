import type Database from "better-sqlite3";
import type { FastifyInstance } from "fastify";

import { listOpenApps } from "../db/apps.js";
import { getDb } from "../db/connection.js";

/**
 * `GET /apps` — the apps a stranger may sign up at. **Anonymous.**
 *
 * ## Why this is public, stated rather than assumed
 *
 * It exposes nothing a caller could not already discover by posting to
 * `/register` with a slug: an app with `public_registration = 1` is, by
 * definition, inviting strangers, and its name is what a registrant is shown
 * next. The one oracle worth protecting is the *closed* estate — which apps
 * exist but are shut — and this endpoint says nothing about those at all.
 * `/register` is careful in the same direction: `403 registration_closed`
 * covers a closed app and an app that does not exist identically, so it is not
 * an app-discovery oracle either.
 *
 * ## Only `slug` and `name`
 *
 * Not `baselineRole`. That is **authority** — what a stranger is granted by
 * signing up — and an anonymous caller has no use for it. It is readable
 * through `GET /console/apps`, behind the superuser gate, where authority
 * belongs. Not `createdAt` or `updatedAt` either: they say when the operator
 * was working, which is nobody's business, and no caller needs them. The
 * projection is a Fastify serialisation schema rather than a hand-written
 * mapper so a future change returning whole `AppRow`s still could not put a
 * baseline role on the wire.
 *
 * ## What it buys the UI
 *
 * Two things brief 09 could not do without it. `Register` had to name an app
 * from a hard-coded display-name table, because the real `apps.name` was
 * readable only through the superuser-only console; and the estate's one login
 * page carried **no "create an account" link at all**, because most apps are
 * closed and it had no way to tell which. It also lets `Register` say "this app
 * is closed" before a form is filled in rather than after it is submitted.
 *
 * ## A bare array, deliberately
 *
 * The console's list answers `{ apps: [...] }` because it also carries a total
 * and will grow filters. This one is the complete set — a handful of rows, no
 * pagination possible or wanted — and the contract brief 09 wrote its client
 * against is `[{ slug, name }]`.
 *
 * ## The empty answer is a state, not an error
 *
 * A fresh estate has no apps at all: `seedApps` is test support and production
 * seeds nothing, so `[]` is the correct and expected answer until the console
 * creates an app with registration open. brief 07 records the same trap for
 * `/register` ("it looks like a bug"), and the UI must read `[]` as "nowhere is
 * open to strangers", never as a failure.
 */

export interface PublicAppsRoutesOptions {
  db?: Database.Database;
}

/**
 * The response filter. Two fields, and `additionalProperties: false` is what
 * makes that structural — see the header on `baselineRole`.
 */
export const PUBLIC_APPS_RESPONSE_SCHEMA = {
  200: {
    type: "array",
    items: {
      type: "object",
      properties: {
        slug: { type: "string" },
        name: { type: "string" },
      },
      required: ["slug", "name"],
      additionalProperties: false,
    },
  },
} as const;

export async function publicAppsRoutes(
  app: FastifyInstance,
  options: PublicAppsRoutesOptions = {},
): Promise<void> {
  /** Lazy, for the reason `routes/auth.ts` gives. */
  const database = async (): Promise<Database.Database> => options.db ?? (await getDb());

  app.get(
    "/apps",
    { schema: { response: PUBLIC_APPS_RESPONSE_SCHEMA } },
    async (_request, reply) => {
      /**
       * `no-store`, even though the answer is identical for every caller and
       * holds no secret. What it is, is *state an operator changes* — closing an
       * app to strangers must take effect on the next request, not when a proxy's
       * TTL happens to lapse — and the fails-safe direction for a registration
       * flag is that a closed app stops being advertised immediately.
       */
      reply.header("cache-control", "no-store");

      const db = await database();
      return reply
        .code(200)
        .send(listOpenApps(db).map((row) => ({ slug: row.slug, name: row.name })));
    },
  );
}
