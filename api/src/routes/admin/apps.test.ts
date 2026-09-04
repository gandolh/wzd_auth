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
import { listAudit } from "../../db/audit-log.js";
import { getApp } from "../../db/apps.js";
import { grantRole, listGrantsForApp, SUPERUSER_ACTOR } from "../../db/grants.js";
import { freshDb, seedUser } from "../../db/test-support.js";
import { adminAppsRoutes } from "./apps.js";

/**
 * `GET`/`POST /console/apps` and `GET`/`PATCH`/`DELETE /console/apps/:slug`.
 *
 * A bare Fastify instance registering only this plugin, so nothing else in the
 * request lifecycle can be doing the accepting or the rejecting. The console
 * session is minted directly through `openConsoleSession()` rather than by
 * posting to `/console/login`, which keeps this suite independent of brief 06's
 * credential path — that path has its own tests.
 */

let db: Database.Database;
let app: FastifyInstance;
let cookie: string;
let sessionId: string;

beforeEach(async () => {
  db = freshDb();
  app = Fastify({ logger: false });
  await app.register(adminAppsRoutes, { db });
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

describe("the gate", () => {
  it("registers bare, the way app.ts will wire it", async () => {
    const bare = Fastify({ logger: false });
    await expect(bare.register(adminAppsRoutes)).resolves.toBeDefined();
    await bare.ready();
    await bare.close();
  });

  it("answers 401 with no console session, on every route", async () => {
    for (const init of [
      { method: "GET" as const, url: "/console/apps" },
      { method: "POST" as const, url: "/console/apps", payload: { slug: "x", name: "X" } },
      { method: "GET" as const, url: "/console/apps/atrium" },
      { method: "PATCH" as const, url: "/console/apps/atrium", payload: { name: "X" } },
      { method: "DELETE" as const, url: "/console/apps/atrium" },
    ]) {
      const response = await app.inject(init);
      expect(response.statusCode, init.url).toBe(401);
      expect(response.json()).toEqual({ error: "unauthorized" });
    }

    // Nothing reached the database, so nothing was audited.
    expect(listAudit(db)).toHaveLength(0);
  });
});

describe("creating an app", () => {
  /**
   * **The headline assertion of this brief.**
   *
   * A new app is closed to strangers unless the request says otherwise, and it
   * confers nothing. This is the whole reason the flag exists: the rejected
   * alternative — registration open at Ward itself — meant a newly-added app was
   * reachable by strangers until somebody remembered to close it.
   */
  it("defaults to closed registration with no baseline role", async () => {
    const response = await asConsole({
      method: "POST",
      url: "/console/apps",
      payload: { slug: "atrium", name: "Atrium" },
    });

    expect(response.statusCode).toBe(201);
    expect(response.json().app).toMatchObject({
      slug: "atrium",
      name: "Atrium",
      publicRegistration: false,
      baselineRole: null,
    });

    // And in the row, not merely in the response.
    const row = getApp(db, "atrium")!;
    expect(row.public_registration).toBe(0);
    expect(row.baseline_role).toBeNull();
  });

  it("creating an app requires no deploy — a slug nothing in Ward knows works", async () => {
    const response = await asConsole({
      method: "POST",
      url: "/console/apps",
      payload: { slug: "orchard", name: "Orchard", publicRegistration: true, baselineRole: "user" },
    });

    expect(response.statusCode).toBe(201);
    expect(response.json().app).toMatchObject({ publicRegistration: true, baselineRole: "user" });
  });

  /**
   * The schema CHECK `public_registration = 0 OR baseline_role IS NOT NULL`
   * would refuse this anyway. What is asserted is that the *route* refuses it
   * with a code the console can act on, rather than letting a `SqliteError`
   * become the error handler's `500 {"error":"internal"}`.
   */
  it("refuses to open an app with no baseline role, cleanly", async () => {
    const response = await asConsole({
      method: "POST",
      url: "/console/apps",
      payload: { slug: "orchard", name: "Orchard", publicRegistration: true },
    });

    expect(response.statusCode).toBe(400);
    expect(response.json()).toEqual({ error: "baseline_role_required" });
    expect(getApp(db, "orchard")).toBeUndefined();
    expect(listAudit(db)).toHaveLength(0);
  });

  it("refuses a baseline role on a closed app rather than silently dropping it", async () => {
    const response = await asConsole({
      method: "POST",
      url: "/console/apps",
      payload: { slug: "orchard", name: "Orchard", baselineRole: "user" },
    });

    expect(response.statusCode).toBe(400);
    expect(response.json()).toEqual({ error: "baseline_role_requires_open" });
  });

  it("answers 409 on a duplicate slug", async () => {
    const payload = { slug: "atrium", name: "Atrium" };
    expect((await asConsole({ method: "POST", url: "/console/apps", payload })).statusCode).toBe(
      201,
    );

    const again = await asConsole({ method: "POST", url: "/console/apps", payload });
    expect(again.statusCode).toBe(409);
    expect(again.json()).toEqual({ error: "app_exists" });
  });

  it("rejects a slug that is not lower-case-and-hyphens", async () => {
    for (const slug of ["Atrium", "at rium", "atrium:1", "-atrium", "atrium-", ""]) {
      const response = await asConsole({
        method: "POST",
        url: "/console/apps",
        payload: { slug, name: "X" },
      });
      expect(response.statusCode, slug).toBe(400);
      expect(response.json()).toEqual({ error: "invalid_request" });
    }
  });

  it("records app.create naming the actor", async () => {
    await asConsole({
      method: "POST",
      url: "/console/apps",
      payload: { slug: "atrium", name: "Atrium" },
    });

    const [row] = listAudit(db);
    expect(row).toMatchObject({
      actor_kind: "superuser",
      actor_subject: null,
      actor_label: "superuser",
      action: "app.create",
      target_kind: "app",
      target_id: "atrium",
    });
    expect(JSON.parse(row!.detail!)).toEqual({
      session: sessionId,
      name: "Atrium",
      publicRegistration: false,
      baselineRole: null,
    });
  });
});

describe("patching an app", () => {
  beforeEach(async () => {
    await asConsole({
      method: "POST",
      url: "/console/apps",
      payload: { slug: "prm", name: "Public Resource Map" },
    });
    db.exec("DELETE FROM audit_log");
  });

  it("opens registration and records app.registration", async () => {
    const response = await asConsole({
      method: "PATCH",
      url: "/console/apps/prm",
      payload: { publicRegistration: true, baselineRole: "user" },
    });

    expect(response.statusCode).toBe(200);
    expect(response.json().app).toMatchObject({ publicRegistration: true, baselineRole: "user" });

    const [row] = listAudit(db);
    expect(row).toMatchObject({ action: "app.registration", actor_label: "superuser" });
    expect(JSON.parse(row!.detail!).changed).toEqual({
      publicRegistration: { from: false, to: true },
      baselineRole: { from: null, to: "user" },
    });
  });

  it("refuses to open with no baseline role, and refuses to clear one while open", async () => {
    const opening = await asConsole({
      method: "PATCH",
      url: "/console/apps/prm",
      payload: { publicRegistration: true },
    });
    expect(opening.statusCode).toBe(400);
    expect(opening.json()).toEqual({ error: "baseline_role_required" });

    await asConsole({
      method: "PATCH",
      url: "/console/apps/prm",
      payload: { publicRegistration: true, baselineRole: "user" },
    });

    const clearing = await asConsole({
      method: "PATCH",
      url: "/console/apps/prm",
      payload: { baselineRole: null },
    });
    expect(clearing.statusCode).toBe(400);
    expect(clearing.json()).toEqual({ error: "baseline_role_required" });
    expect(getApp(db, "prm")!.baseline_role).toBe("user");
  });

  it("closing clears the baseline role so a reopen cannot inherit it", async () => {
    await asConsole({
      method: "PATCH",
      url: "/console/apps/prm",
      payload: { publicRegistration: true, baselineRole: "user" },
    });

    const closing = await asConsole({
      method: "PATCH",
      url: "/console/apps/prm",
      payload: { publicRegistration: false },
    });

    expect(closing.statusCode).toBe(200);
    expect(closing.json().app).toMatchObject({ publicRegistration: false, baselineRole: null });
  });

  it("leaves existing grants alone when registration closes", async () => {
    grantRole(db, {
      subject: seedUser(db, "cristian").subject,
      appSlug: "prm",
      role: "admin",
      grantedBy: SUPERUSER_ACTOR,
    });

    await asConsole({
      method: "PATCH",
      url: "/console/apps/prm",
      payload: { publicRegistration: true, baselineRole: "user" },
    });
    await asConsole({
      method: "PATCH",
      url: "/console/apps/prm",
      payload: { publicRegistration: false },
    });

    expect(listGrantsForApp(db, "prm")).toHaveLength(1);
  });

  it("renames under app.update, separately from the registration flag", async () => {
    const response = await asConsole({
      method: "PATCH",
      url: "/console/apps/prm",
      payload: { name: "PRM", publicRegistration: true, baselineRole: "user" },
    });

    expect(response.statusCode).toBe(200);
    const actions = listAudit(db).map((row) => row.action);
    expect(actions).toContain("app.update");
    expect(actions).toContain("app.registration");
  });

  it("writes no audit row for a patch that changes nothing", async () => {
    const response = await asConsole({
      method: "PATCH",
      url: "/console/apps/prm",
      payload: { name: "Public Resource Map", publicRegistration: false },
    });

    expect(response.statusCode).toBe(200);
    expect(listAudit(db)).toHaveLength(0);
  });

  it("rejects an empty patch and an unknown slug", async () => {
    const empty = await asConsole({ method: "PATCH", url: "/console/apps/prm", payload: {} });
    expect(empty.statusCode).toBe(400);

    const missing = await asConsole({
      method: "PATCH",
      url: "/console/apps/nope",
      payload: { name: "X" },
    });
    expect(missing.statusCode).toBe(404);
    expect(missing.json()).toEqual({ error: "app_not_found" });
  });
});

describe("reading and deleting", () => {
  it("lists apps and reads one, and 404s on an unknown slug", async () => {
    await asConsole({
      method: "POST",
      url: "/console/apps",
      payload: { slug: "atrium", name: "Atrium" },
    });

    const list = await asConsole({ method: "GET", url: "/console/apps" });
    expect(list.statusCode).toBe(200);
    expect(list.json().apps).toHaveLength(1);

    const one = await asConsole({ method: "GET", url: "/console/apps/atrium" });
    expect(one.statusCode).toBe(200);
    expect(one.json()).toMatchObject({ app: { slug: "atrium" }, grantCount: 0 });

    const missing = await asConsole({ method: "GET", url: "/console/apps/nope" });
    expect(missing.statusCode).toBe(404);
  });

  it("deleting an app takes its grants and records how many", async () => {
    await asConsole({
      method: "POST",
      url: "/console/apps",
      payload: { slug: "atrium", name: "Atrium" },
    });
    const subject = seedUser(db, "cristian").subject;
    for (const role of ["reader", "admin"]) {
      grantRole(db, { subject, appSlug: "atrium", role, grantedBy: SUPERUSER_ACTOR });
    }
    db.exec("DELETE FROM audit_log");

    const response = await asConsole({ method: "DELETE", url: "/console/apps/atrium" });

    expect(response.statusCode).toBe(200);
    expect(response.json()).toEqual({ deleted: "atrium", grantsRevoked: 2 });
    expect(getApp(db, "atrium")).toBeUndefined();
    expect(listGrantsForApp(db, "atrium")).toHaveLength(0);

    const [row] = listAudit(db);
    expect(row).toMatchObject({ action: "app.delete", target_id: "atrium" });
    expect(JSON.parse(row!.detail!)).toMatchObject({ grantsRevoked: 2 });
  });

  it("404s deleting an app that is not there", async () => {
    const response = await asConsole({ method: "DELETE", url: "/console/apps/nope" });
    expect(response.statusCode).toBe(404);
    expect(response.json()).toEqual({ error: "app_not_found" });
  });
});
