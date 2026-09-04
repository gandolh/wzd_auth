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
import { createApp } from "../../db/apps.js";
import { grantTargetId, listAudit, parseGrantTargetId } from "../../db/audit-log.js";
import { listGrantsForSubject, listRolesInApp, SUPERUSER_ACTOR } from "../../db/grants.js";
import { setDisabled } from "../../db/users.js";
import { freshDb, seedApps, seedUser } from "../../db/test-support.js";
import { adminGrantsRoutes } from "./grants.js";

/**
 * `GET`/`POST`/`DELETE /console/grants` — the write side of the estate's
 * security boundary.
 */

let db: Database.Database;
let app: FastifyInstance;
let cookie: string;
let sessionId: string;
let subject: string;

beforeEach(async () => {
  db = freshDb();
  seedApps(db);
  subject = seedUser(db, "cristian").subject;

  app = Fastify({ logger: false });
  await app.register(adminGrantsRoutes, { db });
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

const grant = (payload: Record<string, unknown>) =>
  asConsole({ method: "POST", url: "/console/grants", payload });
const revoke = (payload: Record<string, unknown>) =>
  asConsole({ method: "DELETE", url: "/console/grants", payload });

it("answers 401 with no console session, on every route", async () => {
  for (const init of [
    { method: "GET" as const, url: `/console/grants?subject=${subject}` },
    {
      method: "POST" as const,
      url: "/console/grants",
      payload: { subject, appSlug: "prm", role: "admin" },
    },
    { method: "DELETE" as const, url: "/console/grants", payload: { subject, appSlug: "prm" } },
  ]) {
    const response = await app.inject(init);
    expect(response.statusCode, init.url).toBe(401);
    expect(response.json()).toEqual({ error: "unauthorized" });
  }

  expect(listGrantsForSubject(db, subject)).toHaveLength(0);
  expect(listAudit(db)).toHaveLength(0);
});

describe("issuing grants", () => {
  /**
   * The brief's acceptance criterion. A grant carries a *set* of roles, so two
   * roles in one app is not a special case to support — it is the shape.
   */
  it("grants two roles in one app and both are visible", async () => {
    for (const role of ["user", "admin"]) {
      const response = await grant({ subject, appSlug: "prm", role });
      expect(response.statusCode).toBe(200);
      expect(response.json()).toMatchObject({ created: true, grant: { role } });
    }

    expect(listRolesInApp(db, subject, "prm")).toEqual(["admin", "user"]);

    const listed = await asConsole({ method: "GET", url: `/console/grants?subject=${subject}` });
    expect(listed.json().grants.map((g: { role: string }) => g.role)).toEqual(["admin", "user"]);
  });

  /**
   * Idempotent, not an error. The console is a page an operator refreshes and
   * double-clicks; a surface where the second click fails teaches them to
   * distrust the first.
   */
  it("granting a role someone already holds is a success and writes one audit row", async () => {
    const first = await grant({ subject, appSlug: "prm", role: "admin" });
    expect(first.statusCode).toBe(200);
    expect(first.json().created).toBe(true);

    const second = await grant({ subject, appSlug: "prm", role: "admin" });
    expect(second.statusCode).toBe(200);
    expect(second.json().created).toBe(false);
    // The row it echoes is the original, not this attempt.
    expect(second.json().grant).toEqual(first.json().grant);

    expect(listRolesInApp(db, subject, "prm")).toEqual(["admin"]);
    // The no-op changed no authority, so it is not an event.
    expect(listAudit(db, { action: "grant.create" })).toHaveLength(1);
  });

  it("records grant.create naming the actor, with granted_by as the superuser sentinel", async () => {
    await grant({ subject, appSlug: "prm", role: "admin" });

    const [row] = listAudit(db);
    expect(row).toMatchObject({
      actor_kind: "superuser",
      actor_subject: null,
      actor_label: "superuser",
      action: "grant.create",
      target_kind: "grant",
      target_id: grantTargetId(subject, "prm", "admin"),
    });
    expect(JSON.parse(row!.detail!)).toEqual({
      session: sessionId,
      subject,
      appSlug: "prm",
      role: "admin",
    });

    expect(listGrantsForSubject(db, subject)[0]!.granted_by).toBe(SUPERUSER_ACTOR);
  });

  /**
   * Role strings are opaque and unrestricted by decision, so one may contain the
   * delimiter the audit log joins on. `grantTargetId` percent-encodes each
   * component precisely so that `(s, "atrium", "a:b")` and `(s, "atrium:a", "b")`
   * cannot encode identically — and `target_id` equality is how the console
   * answers "everything that happened to this grant".
   */
  it("stores an opaque role containing a colon without collapsing two triples", async () => {
    createApp(db, { slug: "atrium-a", name: "Atrium A" });

    await grant({ subject, appSlug: "atrium", role: "a:b" });
    await grant({ subject, appSlug: "atrium-a", role: "b" });

    const ids = listAudit(db, { action: "grant.create" }).map((row) => row.target_id!);
    expect(new Set(ids).size).toBe(2);
    expect(ids.map((id) => parseGrantTargetId(id))).toEqual(
      expect.arrayContaining([
        { subject, appSlug: "atrium", role: "a:b" },
        { subject, appSlug: "atrium-a", role: "b" },
      ]),
    );
  });

  it("404s on a subject or a slug that does not exist", async () => {
    const noSubject = await grant({ subject: "deadbeef", appSlug: "prm", role: "admin" });
    expect(noSubject.statusCode).toBe(404);
    expect(noSubject.json()).toEqual({ error: "account_not_found" });

    const noApp = await grant({ subject, appSlug: "orchard", role: "admin" });
    expect(noApp.statusCode).toBe(404);
    expect(noApp.json()).toEqual({ error: "app_not_found" });

    expect(listAudit(db)).toHaveLength(0);
  });

  /**
   * Disabling is a locked door, not a destroyed identity: grants survive it so a
   * re-enable restores what was there. Editing them meanwhile must not require
   * bringing the account back up first.
   */
  it("grants a disabled account, which keeps its grants across the disable", async () => {
    setDisabled(db, subject, true);
    const response = await grant({ subject, appSlug: "prm", role: "admin" });
    expect(response.statusCode).toBe(200);
    expect(listRolesInApp(db, subject, "prm")).toEqual(["admin"]);
  });

  it("rejects a malformed body", async () => {
    for (const payload of [
      {},
      { subject, appSlug: "prm" },
      { subject, appSlug: "prm", role: "" },
    ]) {
      const response = await grant(payload);
      expect(response.statusCode).toBe(400);
      expect(response.json()).toEqual({ error: "invalid_request" });
    }
  });
});

describe("revoking grants", () => {
  beforeEach(async () => {
    await grant({ subject, appSlug: "prm", role: "user" });
    await grant({ subject, appSlug: "prm", role: "admin" });
    await grant({ subject, appSlug: "atrium", role: "reader" });
    db.exec("DELETE FROM audit_log");
  });

  it("removes one role and leaves the other", async () => {
    const response = await revoke({ subject, appSlug: "prm", role: "admin" });

    expect(response.statusCode).toBe(200);
    expect(response.json()).toEqual({ removed: 1, roles: ["admin"] });
    expect(listRolesInApp(db, subject, "prm")).toEqual(["user"]);

    const [row] = listAudit(db);
    expect(row).toMatchObject({
      action: "grant.revoke",
      actor_label: "superuser",
      target_id: grantTargetId(subject, "prm", "admin"),
    });
  });

  /** Not an error, and not an event either. */
  it("revoking a grant nobody holds succeeds and writes no audit row", async () => {
    const response = await revoke({ subject, appSlug: "prm", role: "nobody-holds-this" });

    expect(response.statusCode).toBe(200);
    expect(response.json()).toEqual({ removed: 0, roles: [] });
    expect(listAudit(db)).toHaveLength(0);
  });

  it("revoking with no role removes every role in that app, in one audit row", async () => {
    const response = await revoke({ subject, appSlug: "prm" });

    expect(response.statusCode).toBe(200);
    expect(response.json().removed).toBe(2);
    expect(response.json().roles.sort()).toEqual(["admin", "user"]);
    expect(listRolesInApp(db, subject, "prm")).toEqual([]);
    // Untouched — there is no wildcard here either.
    expect(listRolesInApp(db, subject, "atrium")).toEqual(["reader"]);

    const rows = listAudit(db);
    expect(rows).toHaveLength(1);
    expect(rows[0]).toMatchObject({
      action: "grant.revoke_app",
      target_kind: "app",
      target_id: "prm",
    });
    expect(JSON.parse(rows[0]!.detail!).roles.sort()).toEqual(["admin", "user"]);
  });

  it("revoking every role in an app nobody had access to is a no-op", async () => {
    const response = await revoke({ subject, appSlug: "newspapper" });
    expect(response.statusCode).toBe(200);
    expect(response.json()).toEqual({ removed: 0, roles: [] });
    expect(listAudit(db)).toHaveLength(0);
  });

  /**
   * No existence check, deliberately: "no such subject" and "holds no such
   * grant" have the same answer — nothing to remove — and a 404 would be a
   * slower way of saying `removed: 0` that also confirms whether a subject
   * exists.
   */
  it("answers 200 removed:0 for a subject that does not exist", async () => {
    const response = await revoke({ subject: "deadbeef", appSlug: "prm", role: "admin" });
    expect(response.statusCode).toBe(200);
    expect(response.json()).toEqual({ removed: 0, roles: [] });
  });
});

describe("listing grants", () => {
  it("lists by subject and by app, and needs exactly one filter", async () => {
    await grant({ subject, appSlug: "prm", role: "admin" });

    const bySubject = await asConsole({
      method: "GET",
      url: `/console/grants?subject=${subject}`,
    });
    expect(bySubject.statusCode).toBe(200);
    expect(bySubject.json().grants).toEqual([
      {
        subject,
        appSlug: "prm",
        role: "admin",
        grantedAt: expect.any(String),
        grantedBy: "superuser",
      },
    ]);

    const byApp = await asConsole({ method: "GET", url: "/console/grants?app=prm" });
    expect(byApp.statusCode).toBe(200);
    expect(byApp.json().grants).toHaveLength(1);

    for (const url of ["/console/grants", `/console/grants?subject=${subject}&app=prm`]) {
      const response = await asConsole({ method: "GET", url });
      expect(response.statusCode, url).toBe(400);
    }
  });

  it("404s rather than answering an empty list for a typo", async () => {
    const noSubject = await asConsole({ method: "GET", url: "/console/grants?subject=deadbeef" });
    expect(noSubject.statusCode).toBe(404);
    expect(noSubject.json()).toEqual({ error: "account_not_found" });

    const noApp = await asConsole({ method: "GET", url: "/console/grants?app=orchard" });
    expect(noApp.statusCode).toBe(404);
    expect(noApp.json()).toEqual({ error: "app_not_found" });
  });
});
