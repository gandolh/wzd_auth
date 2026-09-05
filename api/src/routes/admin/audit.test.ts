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
import { grantTargetId, recordAudit, SUPERUSER_LABEL } from "../../db/audit-log.js";
import { freshDb, seedApps, seedUser } from "../../db/test-support.js";
import { adminAuditRoutes } from "./audit.js";

/**
 * `GET /console/audit`.
 *
 * The screen this serves is the **only observability the break-glass
 * credential has** — it cannot be revoked or rotated without a redeploy — so
 * the tests that matter here are the ones about finding a console action, not
 * the ones about pagination arithmetic.
 */

let db: Database.Database;
let app: FastifyInstance;
let cookie: string;

beforeEach(async () => {
  db = freshDb();
  seedApps(db);

  app = Fastify({ logger: false });
  await app.register(adminAuditRoutes, { db });
  await app.ready();

  cookie = `${CONSOLE_COOKIE_NAME}=${encodeURIComponent(openConsoleSession().token)}`;
});

afterEach(async () => {
  await app.close();
  db.close();
  resetConsoleSessionsForTests();
});

const asConsole = (init: InjectOptions): Promise<LightMyRequestResponse> =>
  app.inject({ ...init, headers: { ...init.headers, cookie } });

/** A console action: `actor_kind='superuser'`, `actor_subject=NULL`. */
function consoleRow(action: string, targetId = "atrium"): void {
  recordAudit(db, {
    actorKind: "superuser",
    actorLabel: SUPERUSER_LABEL,
    action,
    targetKind: "app",
    targetId,
    detail: { session: "abcd" },
  });
}

/** An ordinary account's action, which is the only kind with a subject. */
function accountRow(subject: string, username: string, action: string): void {
  recordAudit(db, {
    actorKind: "account",
    actorSubject: subject,
    actorLabel: username,
    action,
    targetKind: "user",
    targetId: subject,
  });
}

it("answers 401 with no console session", async () => {
  consoleRow("app.create");

  const response = await app.inject({ method: "GET", url: "/console/audit" });
  expect(response.statusCode).toBe(401);
  expect(response.json()).toEqual({ error: "unauthorized" });
});

it("camel-cases the row and parses the detail", async () => {
  const user = seedUser(db, "cristian");
  accountRow(user.subject, user.username, "session.login");

  const response = await asConsole({ method: "GET", url: "/console/audit" });
  expect(response.statusCode).toBe(200);
  expect(response.headers["cache-control"]).toBe("no-store");

  const [entry] = response.json().entries as Record<string, unknown>[];
  expect(entry).toMatchObject({
    actorKind: "account",
    actorSubject: user.subject,
    actorLabel: "cristian",
    action: "session.login",
    targetKind: "user",
    targetId: user.subject,
    detail: null,
  });
  // Snake case is the storage layer's, not the wire's.
  expect(Object.keys(entry!)).not.toContain("actor_kind");
  expect(typeof entry!["id"]).toBe("number");
  expect(typeof entry!["at"]).toBe("string");
});

it("parses detail into a value rather than handing back its JSON string", async () => {
  consoleRow("app.registration");

  const response = await asConsole({ method: "GET", url: "/console/audit" });
  expect(response.json().entries[0].detail).toEqual({ session: "abcd" });
});

/**
 * `detail` has no CHECK and is not necessarily written by `recordAudit` — a
 * cutover script or a hand-inserted row could put anything there. One
 * unparseable row must not take the whole screen down, which is the same call
 * `parseGrantTargetId` makes.
 */
it("falls back to the raw string for a detail that is not JSON", async () => {
  db.prepare(
    `INSERT INTO audit_log (actor_kind, actor_label, action, detail) VALUES ('system', 'job', 'sweep.expired', 'not json')`,
  ).run();

  const response = await asConsole({ method: "GET", url: "/console/audit" });
  expect(response.statusCode).toBe(200);
  expect(response.json().entries[0].detail).toBe("not json");
});

/**
 * **The gap this route was built to close.**
 *
 * Every console mutation is `actor_kind='superuser'` with a null
 * `actor_subject`, so the one actor filter `AuditQuery` used to offer could
 * never find one. "Filterable by actor" was unsatisfiable for the actor whose
 * trail is the reason the table exists.
 */
describe("filtering by actor", () => {
  beforeEach(() => {
    const user = seedUser(db, "cristian");
    accountRow(user.subject, user.username, "session.login");
    consoleRow("app.create");
    consoleRow("app.registration");
    recordAudit(db, {
      actorKind: "system",
      actorLabel: "reuse-sweep",
      action: "session.reuse_detected",
      targetKind: "session",
      targetId: "deadbeef",
    });
  });

  it("finds the console's own rows by actorKind, which actorSubject cannot", async () => {
    const byKind = await asConsole({ method: "GET", url: "/console/audit?actorKind=superuser" });
    expect(byKind.statusCode).toBe(200);
    const actions = (byKind.json().entries as { action: string }[]).map((row) => row.action);
    expect(actions.sort()).toEqual(["app.create", "app.registration"]);

    // The pre-existing filter, on the column that is null for exactly these
    // rows. This is the assertion that documents why the new field was needed.
    const bySubject = await asConsole({
      method: "GET",
      url: "/console/audit?actorSubject=superuser",
    });
    expect(bySubject.json().entries).toEqual([]);
  });

  it("filters by actorLabel exactly", async () => {
    const response = await asConsole({ method: "GET", url: "/console/audit?actorLabel=superuser" });
    expect(response.json().entries).toHaveLength(2);

    const partial = await asConsole({ method: "GET", url: "/console/audit?actorLabel=super" });
    expect(partial.json().entries).toEqual([]);
  });

  it("filters by actorKind=system and actorKind=account separately", async () => {
    const system = await asConsole({ method: "GET", url: "/console/audit?actorKind=system" });
    expect(system.json().entries).toHaveLength(1);

    const account = await asConsole({ method: "GET", url: "/console/audit?actorKind=account" });
    expect(account.json().entries).toHaveLength(1);
    expect(account.json().entries[0].actorLabel).toBe("cristian");
  });

  it("combines actor and action filters", async () => {
    const response = await asConsole({
      method: "GET",
      url: "/console/audit?actorKind=superuser&action=app.create",
    });
    expect(response.json().entries).toHaveLength(1);
    expect(response.json().entries[0].action).toBe("app.create");
  });

  /**
   * A typo must not read as "nothing ever happened on this surface", which is
   * the single most misleading answer this screen can give.
   */
  it("refuses an actorKind that is not one", async () => {
    const response = await asConsole({ method: "GET", url: "/console/audit?actorKind=superusers" });
    expect(response.statusCode).toBe(400);
    expect(response.json()).toEqual({ error: "invalid_request" });
  });
});

/**
 * `grantTargetId` percent-encodes, so a role containing `:` still round-trips
 * through the `targetId` equality filter. Asserted here because this route is
 * how the console answers "everything that happened to this grant".
 */
it("filters by a grant target id whose role contains a colon", async () => {
  const user = seedUser(db, "cristian");
  const target = grantTargetId(user.subject, "atrium", "a:b");
  recordAudit(db, {
    actorKind: "superuser",
    actorLabel: SUPERUSER_LABEL,
    action: "grant.create",
    targetKind: "grant",
    targetId: target,
  });
  consoleRow("app.create");

  const response = await asConsole({
    method: "GET",
    url: `/console/audit?targetKind=grant&targetId=${encodeURIComponent(target)}`,
  });
  expect(response.json().entries).toHaveLength(1);
  expect(response.json().entries[0].targetId).toBe(target);
});

describe("paging and the total", () => {
  beforeEach(() => {
    for (let index = 0; index < 7; index += 1) {
      consoleRow("app.create", `app-${String(index)}`);
    }
  });

  it("returns newest first and reports the whole log's size", async () => {
    const response = await asConsole({ method: "GET", url: "/console/audit?limit=3" });
    const entries = response.json().entries as { id: number }[];

    expect(entries).toHaveLength(3);
    expect(entries.map((row) => row.id)).toEqual([7, 6, 5]);
    // `total` is the size of the log, not of the page — that is what answers
    // "am I looking at everything".
    expect(response.json().total).toBe(7);
    expect(response.json().nextBeforeId).toBe(5);
  });

  /**
   * Keyset, not offset: the log grows at the head, so an offset-paged second
   * page shifts under the reader every time anything happens.
   */
  it("pages with the keyset cursor, and a row landing mid-read shifts nothing", async () => {
    const first = await asConsole({ method: "GET", url: "/console/audit?limit=3" });
    const cursor = first.json().nextBeforeId as number;

    // Something happens between the two page reads.
    consoleRow("app.delete", "app-new");

    const second = await asConsole({
      method: "GET",
      url: `/console/audit?limit=3&beforeId=${String(cursor)}`,
    });
    expect((second.json().entries as { id: number }[]).map((row) => row.id)).toEqual([4, 3, 2]);
    // The new row is counted, but it did not push a row off the second page.
    expect(second.json().total).toBe(8);
  });

  it("reports a null cursor on the last page", async () => {
    const response = await asConsole({ method: "GET", url: "/console/audit?limit=50" });
    expect(response.json().entries).toHaveLength(7);
    expect(response.json().nextBeforeId).toBeNull();
  });

  it("refuses a limit past the cap", async () => {
    const response = await asConsole({ method: "GET", url: "/console/audit?limit=5000" });
    expect(response.statusCode).toBe(400);
  });
});

/**
 * Reading the log must not append to it. An operator paging a screen would
 * otherwise bury the rows they came to find under their own scrolling.
 */
it("writes nothing", async () => {
  consoleRow("app.create");
  const before = db.prepare<[], number>(`SELECT count(*) FROM audit_log`).pluck().get();

  await asConsole({ method: "GET", url: "/console/audit" });
  await asConsole({ method: "GET", url: "/console/audit?actorKind=superuser" });

  expect(db.prepare<[], number>(`SELECT count(*) FROM audit_log`).pluck().get()).toBe(before);
});

it("answers an empty log with an empty page rather than a 404", async () => {
  const response = await asConsole({ method: "GET", url: "/console/audit" });
  expect(response.statusCode).toBe(200);
  expect(response.json()).toEqual({ entries: [], total: 0, nextBeforeId: null });
});
