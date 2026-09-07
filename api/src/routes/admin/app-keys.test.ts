import type Database from "better-sqlite3";
import Fastify, {
  type FastifyInstance,
  type InjectOptions,
  type LightMyRequestResponse,
} from "fastify";
import { afterEach, beforeEach, describe, expect, it } from "vitest";

import {
  CONSOLE_COOKIE_NAME,
  openConsoleSession,
  resetConsoleSessionsForTests,
} from "../../auth/superuser.js";
import { getAppKey, hashAppKey, listAppKeysForApp } from "../../db/app-keys.js";
import { listAudit } from "../../db/audit-log.js";
import { deleteApp } from "../../db/apps.js";
import { freshDb, seedApps } from "../../db/test-support.js";
import { adminAppKeysRoutes } from "./app-keys.js";

/**
 * `GET /console/app-keys`, `GET`/`POST /console/apps/:slug/keys` and
 * `POST /console/app-keys/:id/revoke`.
 *
 * A bare Fastify instance registering only this plugin, matching `apps.test.ts`
 * — nothing else in the lifecycle can be doing the accepting or the rejecting,
 * and the console session is minted directly rather than through
 * `/console/login`, which has its own tests.
 */

let db: Database.Database;
let app: FastifyInstance;
let cookie: string;
let sessionId: string;

beforeEach(async () => {
  db = freshDb();
  seedApps(db);
  app = Fastify({ logger: false });
  await app.register(adminAppKeysRoutes, { db });
  await app.ready();

  const opened = openConsoleSession();
  cookie = `${CONSOLE_COOKIE_NAME}=${encodeURIComponent(opened.token)}`;
  sessionId = opened.session.id;
});

afterEach(async () => {
  await app.close();
  db.close();
  resetConsoleSessionsForTests();
});

const asConsole = (init: InjectOptions): Promise<LightMyRequestResponse> =>
  app.inject({ ...init, headers: { ...init.headers, cookie } });

async function issue(slug = "atrium", label = "production"): Promise<{ key: string; id: string }> {
  const response = await asConsole({
    method: "POST",
    url: `/console/apps/${slug}/keys`,
    payload: { label },
  });
  expect(response.statusCode).toBe(201);
  const body = response.json<{ key: string; appKey: { id: string } }>();
  return { key: body.key, id: body.appKey.id };
}

describe("the gate", () => {
  it("registers bare, the way app.ts wires it", async () => {
    const bare = Fastify({ logger: false });
    await expect(bare.register(adminAppKeysRoutes)).resolves.toBeDefined();
    await bare.ready();
    await bare.close();
  });

  /**
   * This surface mints credentials for whole apps, so an ungated route here is
   * strictly worse than an ungated route anywhere else in the console.
   */
  it("answers 401 with no console session, on every route", async () => {
    for (const init of [
      { method: "GET" as const, url: "/console/app-keys" },
      { method: "GET" as const, url: "/console/apps/atrium/keys" },
      { method: "POST" as const, url: "/console/apps/atrium/keys", payload: { label: "x" } },
      { method: "POST" as const, url: `/console/app-keys/${"a".repeat(32)}/revoke` },
    ]) {
      const response = await app.inject(init);
      expect(response.statusCode, init.url).toBe(401);
      expect(response.json()).toEqual({ error: "unauthorized" });
    }

    expect(listAudit(db)).toHaveLength(0);
    expect(listAppKeysForApp(db, "atrium")).toEqual([]);
  });
});

describe("issuing a key", () => {
  /**
   * **The headline assertion.** The plaintext is in this response and in no
   * other, ever — there is no route that reads a key back, and the database
   * holds only a digest.
   */
  it("returns the key exactly once, and never again from any route", async () => {
    const { key, id } = await issue();

    expect(key.startsWith("wak_")).toBe(true);
    expect(getAppKey(db, id)!.key_hash).toBe(hashAppKey(key));

    // Every other route that can mention this key: none of them carry it.
    const list = await asConsole({ method: "GET", url: "/console/app-keys" });
    const perApp = await asConsole({ method: "GET", url: "/console/apps/atrium/keys" });
    expect(list.body).not.toContain(key);
    expect(perApp.body).not.toContain(key);

    // Nor does the digest leak into a console payload — it is not a key, but it
    // is not something a console page has any use for either.
    expect(list.body).not.toContain(hashAppKey(key));
  });

  it("records who issued it, against the app rather than the key", async () => {
    const { id } = await issue("newspapper", "np production");

    const audit = listAudit(db);
    expect(audit).toHaveLength(1);
    expect(audit[0]).toMatchObject({
      action: "app_key.create",
      actor_kind: "superuser",
      target_kind: "app",
      target_id: "newspapper",
    });

    // The key id is in `detail`, so an operator scanning for "who let something
    // introspect as newspapper" sees the app, and can still follow it to a row.
    const detail = JSON.parse(audit[0]!.detail!) as Record<string, unknown>;
    expect(detail).toMatchObject({ keyId: id, label: "np production", session: sessionId });
  });

  it("is no-store — this is the one response body carrying a live credential", async () => {
    const response = await asConsole({
      method: "POST",
      url: "/console/apps/atrium/keys",
      payload: { label: "x" },
    });
    expect(response.headers["cache-control"]).toBe("no-store");
  });

  it("requires a label, so two keys for one app can be told apart", async () => {
    for (const payload of [{}, { label: "" }, { label: "   " }]) {
      const response = await asConsole({
        method: "POST",
        url: "/console/apps/atrium/keys",
        payload,
      });
      expect(response.statusCode).toBe(400);
      expect(response.json()).toEqual({ error: "invalid_request" });
    }

    expect(listAppKeysForApp(db, "atrium")).toEqual([]);
  });

  it("404s for an app that does not exist, and writes nothing", async () => {
    const response = await asConsole({
      method: "POST",
      url: "/console/apps/no-such-app/keys",
      payload: { label: "x" },
    });

    expect(response.statusCode).toBe(404);
    expect(response.json()).toEqual({ error: "app_not_found" });
    expect(listAudit(db)).toHaveLength(0);
  });

  it("lets one app hold several live keys, which is what makes rotation safe", async () => {
    await issue("atrium", "current");
    await issue("atrium", "incoming");

    const response = await asConsole({ method: "GET", url: "/console/apps/atrium/keys" });
    const keys = response.json<{ keys: { label: string; revoked: boolean }[] }>().keys;

    expect(keys).toHaveLength(2);
    expect(keys.every((row) => !row.revoked)).toBe(true);
  });
});

describe("listing", () => {
  it("shows every key in the estate, grouped by app", async () => {
    await issue("atrium", "a");
    await issue("sports-app", "b");

    const response = await asConsole({ method: "GET", url: "/console/app-keys" });
    expect(response.statusCode).toBe(200);

    const keys = response.json<{ keys: { appSlug: string }[] }>().keys;
    expect(keys.map((row) => row.appSlug)).toEqual(["atrium", "sports-app"]);
  });

  it("carries the fields the console renders and nothing sensitive", async () => {
    await issue("prm", "prm production");

    const response = await asConsole({ method: "GET", url: "/console/apps/prm/keys" });
    const [key] = response.json<{ keys: Record<string, unknown>[] }>().keys;

    expect(Object.keys(key!).sort()).toEqual([
      "appSlug",
      "createdAt",
      "createdBy",
      "id",
      "label",
      "lastUsedAt",
      "revoked",
      "revokedAt",
    ]);
  });

  it("404s for an unknown app rather than answering an empty list", async () => {
    const response = await asConsole({ method: "GET", url: "/console/apps/nope/keys" });
    expect(response.statusCode).toBe(404);
  });
});

describe("revoking", () => {
  it("turns the key off and audits it against the app", async () => {
    const { id } = await issue("atrium", "leaked");

    const response = await asConsole({ method: "POST", url: `/console/app-keys/${id}/revoke` });
    expect(response.statusCode).toBe(200);
    expect(response.json<{ appKey: { revoked: boolean } }>().appKey.revoked).toBe(true);

    expect(getAppKey(db, id)!.revoked_at).not.toBeNull();
    // `listAudit` is newest-first, so [0] is the revoke that just happened.
    expect(listAudit(db)[0]).toMatchObject({
      action: "app_key.revoke",
      target_kind: "app",
      target_id: "atrium",
    });
  });

  /**
   * Almost always an operator clicking twice on a stale list. Answering `200`
   * would tell them they had just turned off a key that has in fact been off
   * since last week — which is how the *live* key gets revoked next.
   */
  it("409s on a second revoke rather than pretending it did something", async () => {
    const { id } = await issue();
    await asConsole({ method: "POST", url: `/console/app-keys/${id}/revoke` });

    const again = await asConsole({ method: "POST", url: `/console/app-keys/${id}/revoke` });
    expect(again.statusCode).toBe(409);
    expect(again.json()).toEqual({ error: "app_key_already_revoked" });

    // One audit row for the one thing that actually happened.
    expect(listAudit(db).filter((row) => row.action === "app_key.revoke")).toHaveLength(1);
  });

  it("404s for a key that does not exist", async () => {
    const response = await asConsole({
      method: "POST",
      url: `/console/app-keys/${"0".repeat(32)}/revoke`,
    });
    expect(response.statusCode).toBe(404);
    expect(response.json()).toEqual({ error: "app_key_not_found" });
  });

  /**
   * The id is 32 hex characters and a key is `wak_` + 43 base64url characters.
   * Refusing by shape means a key pasted into this path — the mistake this
   * surface most invites — never becomes a `WHERE` argument that could reach a
   * log line.
   */
  it("refuses anything that is not a key id, including an actual key", async () => {
    const { key } = await issue();

    for (const id of [key, "not-hex", "abc", "A".repeat(32)]) {
      const response = await asConsole({
        method: "POST",
        url: `/console/app-keys/${encodeURIComponent(id)}/revoke`,
      });
      expect(response.statusCode, id).toBe(400);
      expect(response.json()).toEqual({ error: "invalid_request" });
    }
  });

  it("there is no un-revoke", async () => {
    const { id } = await issue();
    await asConsole({ method: "POST", url: `/console/app-keys/${id}/revoke` });

    // No route restores it: the fix for "I revoked the wrong one" is a new key,
    // because a key that has been off is a key whose value may have been shared
    // while it was off.
    for (const init of [
      { method: "POST" as const, url: `/console/app-keys/${id}/enable` },
      { method: "PATCH" as const, url: `/console/app-keys/${id}` },
      { method: "DELETE" as const, url: `/console/app-keys/${id}/revoke` },
    ]) {
      expect((await asConsole(init)).statusCode, init.url).toBe(404);
    }

    expect(getAppKey(db, id)!.revoked_at).not.toBeNull();
  });
});

describe("the app cascade", () => {
  it("deleting an app takes its keys with it", async () => {
    const { id } = await issue("sports-app");
    expect(deleteApp(db, "sports-app")).toBe(true);

    expect(getAppKey(db, id)).toBeUndefined();
    expect((await asConsole({ method: "GET", url: "/console/app-keys" })).json()).toEqual({
      keys: [],
    });
  });
});
