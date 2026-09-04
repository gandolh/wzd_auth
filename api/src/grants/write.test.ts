import type Database from "better-sqlite3";
import { afterEach, beforeEach, expect, it } from "vitest";

import type { AuditActor } from "../audit.js";
import { grantTargetId, listAudit, parseGrantTargetId } from "../db/audit-log.js";
import { hasGrant, listRolesInApp, SUPERUSER_ACTOR } from "../db/grants.js";
import { freshDb, seedApps, seedUser } from "../db/test-support.js";
import { addGrant, removeAppAccess, removeGrant } from "./write.js";

/**
 * `grants/write.ts` on its own, with no HTTP anywhere — the module is
 * deliberately callable without a `FastifyRequest` so that a cutover script or a
 * future job can issue grants and have them audited identically.
 */

const CONSOLE: AuditActor = {
  actorKind: "superuser",
  actorLabel: "superuser",
  detail: { session: "cs_test" },
};

let db: Database.Database;
let subject: string;

beforeEach(() => {
  db = freshDb();
  seedApps(db);
  subject = seedUser(db, "cristian").subject;
});

afterEach(() => {
  db.close();
});

it("issues a grant, audits it, and stamps granted_by with the superuser sentinel", () => {
  const result = addGrant(db, CONSOLE, { subject, appSlug: "prm", role: "admin" });

  expect(result.created).toBe(true);
  expect(result.grant.granted_by).toBe(SUPERUSER_ACTOR);
  expect(hasGrant(db, subject, "prm", "admin")).toBe(true);

  const [row] = listAudit(db);
  expect(row).toMatchObject({
    actor_kind: "superuser",
    actor_subject: null,
    action: "grant.create",
    target_kind: "grant",
    target_id: grantTargetId(subject, "prm", "admin"),
  });
  expect(JSON.parse(row!.detail!)).toMatchObject({ session: "cs_test", role: "admin" });
});

/**
 * `granted_by` is derived from the audit actor rather than passed separately, so
 * the column and the log cannot disagree about who issued a grant.
 */
it("stamps granted_by with an account actor's own subject", () => {
  const owner = seedUser(db, "owner");
  const result = addGrant(
    db,
    { actorKind: "account", actorSubject: owner.subject, actorLabel: owner.username },
    { subject, appSlug: "prm", role: "user" },
  );

  expect(result.grant.granted_by).toBe(owner.subject);
  expect(listAudit(db)[0]!.actor_subject).toBe(owner.subject);
});

it("is idempotent, echoing the original row and writing no second audit event", () => {
  const first = addGrant(db, CONSOLE, { subject, appSlug: "prm", role: "admin" });
  const second = addGrant(db, CONSOLE, { subject, appSlug: "prm", role: "admin" });

  expect(second.created).toBe(false);
  // The original grant's `granted_at` and `granted_by`, not this attempt's.
  expect(second.grant).toEqual(first.grant);
  expect(listAudit(db)).toHaveLength(1);
});

it("holds several roles in one app, because a grant is a set", () => {
  for (const role of ["user", "admin", "curator"]) {
    addGrant(db, CONSOLE, { subject, appSlug: "prm", role });
  }
  expect(listRolesInApp(db, subject, "prm")).toEqual(["admin", "curator", "user"]);
});

/**
 * Roles are opaque and may contain the delimiter the audit log joins on, so the
 * two triples below encode to two distinct `target_id`s. A hand-built
 * `subject:app:role` string collapses them, and `target_id` equality is how the
 * console answers "everything that happened to this grant".
 */
it("keeps two triples distinct when a role contains a colon", () => {
  addGrant(db, CONSOLE, { subject, appSlug: "atrium", role: "a:b" });
  const ids = listAudit(db).map((row) => row.target_id!);
  expect(parseGrantTargetId(ids[0]!)).toEqual({ subject, appSlug: "atrium", role: "a:b" });
  expect(ids[0]).not.toBe(`${subject}:atrium:a:b`);
});

it("throws a foreign-key error for a subject or a slug that does not exist", () => {
  expect(() => addGrant(db, CONSOLE, { subject: "nope", appSlug: "prm", role: "admin" })).toThrow();
  expect(() => addGrant(db, CONSOLE, { subject, appSlug: "nope", role: "admin" })).toThrow();
  expect(listAudit(db)).toHaveLength(0);
});

/**
 * The audit row is written **inside the transaction that makes the change**, so
 * a failure to record rolls the change back. Forced here with an actor the
 * `audit_log` CHECK refuses — `actor_kind = 'account'` with a null subject.
 */
it("rolls the grant back if its audit row cannot be written", () => {
  const broken: AuditActor = { actorKind: "account", actorSubject: null, actorLabel: "broken" };

  expect(() => addGrant(db, broken, { subject, appSlug: "prm", role: "admin" })).toThrow();
  expect(hasGrant(db, subject, "prm", "admin")).toBe(false);
  expect(listAudit(db)).toHaveLength(0);
});

it("removes one role and audits it", () => {
  addGrant(db, CONSOLE, { subject, appSlug: "prm", role: "user" });
  addGrant(db, CONSOLE, { subject, appSlug: "prm", role: "admin" });
  db.exec("DELETE FROM audit_log");

  expect(removeGrant(db, CONSOLE, { subject, appSlug: "prm", role: "admin" })).toEqual({
    removed: true,
  });
  expect(listRolesInApp(db, subject, "prm")).toEqual(["user"]);
  expect(listAudit(db)[0]).toMatchObject({
    action: "grant.revoke",
    target_id: grantTargetId(subject, "prm", "admin"),
  });
});

it("removing a role nobody holds is a success and not an event", () => {
  expect(removeGrant(db, CONSOLE, { subject, appSlug: "prm", role: "ghost" })).toEqual({
    removed: false,
  });
  expect(listAudit(db)).toHaveLength(0);
});

it("removes every role in one app under a single audit row", () => {
  addGrant(db, CONSOLE, { subject, appSlug: "prm", role: "user" });
  addGrant(db, CONSOLE, { subject, appSlug: "prm", role: "admin" });
  addGrant(db, CONSOLE, { subject, appSlug: "atrium", role: "reader" });
  db.exec("DELETE FROM audit_log");

  const result = removeAppAccess(db, CONSOLE, { subject, appSlug: "prm" });

  expect(result.removed).toBe(2);
  expect([...result.roles].sort()).toEqual(["admin", "user"]);
  expect(listRolesInApp(db, subject, "prm")).toEqual([]);
  // No wildcard, in either direction: another app's grant is untouched.
  expect(listRolesInApp(db, subject, "atrium")).toEqual(["reader"]);

  const rows = listAudit(db);
  expect(rows).toHaveLength(1);
  expect(rows[0]).toMatchObject({
    action: "grant.revoke_app",
    target_kind: "app",
    target_id: "prm",
  });
});

it("removing access nobody had is a success and not an event", () => {
  expect(removeAppAccess(db, CONSOLE, { subject, appSlug: "prm" })).toEqual({
    removed: 0,
    roles: [],
  });
  expect(listAudit(db)).toHaveLength(0);
});
