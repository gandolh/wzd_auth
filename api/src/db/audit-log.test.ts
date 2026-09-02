import { afterEach, beforeEach, describe, expect, it } from "vitest";
import type Database from "better-sqlite3";
import { freshDb, seedApps, seedUser } from "./test-support.js";
import { SUPERUSER_ACTOR, grantRole } from "./grants.js";
import { SUPERUSER_LABEL, countAudit, grantTargetId, listAudit, recordAudit } from "./audit-log.js";

let db: Database.Database;

beforeEach(() => {
  db = freshDb();
  seedApps(db);
});

afterEach(() => {
  db.close();
});

describe("audit_log answers 'who granted this and when'", () => {
  it("records the grant, its actor, its target and its time", () => {
    const owner = seedUser(db, "cristian");
    grantRole(db, {
      subject: owner.subject,
      appSlug: "atrium",
      role: "admin",
      grantedBy: SUPERUSER_ACTOR,
    });

    const row = recordAudit(db, {
      actorKind: "superuser",
      actorLabel: SUPERUSER_LABEL,
      action: "grant.create",
      targetKind: "grant",
      targetId: grantTargetId(owner.subject, "atrium", "admin"),
      detail: { subject: owner.subject, app: "atrium", role: "admin" },
    });

    expect(row.id).toBeGreaterThan(0);
    expect(row.at).toMatch(/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/);
    expect(row.actor_kind).toBe("superuser");
    expect(row.actor_subject).toBeNull();
    expect(row.target_id).toBe(`${owner.subject}:atrium:admin`);
    expect(JSON.parse(row.detail!)).toEqual({
      subject: owner.subject,
      app: "atrium",
      role: "admin",
    });
  });

  it("carries a subject only for an account actor — the superuser has none", () => {
    const owner = seedUser(db, "cristian");

    expect(
      recordAudit(db, {
        actorKind: "account",
        actorSubject: owner.subject,
        actorLabel: "cristian",
        action: "user.create",
        targetKind: "user",
        targetId: "someone",
      }).actor_subject,
    ).toBe(owner.subject);

    // A superuser row claiming a subject would assert an account exists for an
    // identity that deliberately has none. The schema refuses it.
    expect(() =>
      recordAudit(db, {
        actorKind: "superuser",
        actorSubject: owner.subject,
        actorLabel: SUPERUSER_LABEL,
        action: "user.create",
      }),
    ).toThrowError(/CHECK constraint failed/);

    // And an account actor with no subject is equally refused.
    expect(() =>
      recordAudit(db, { actorKind: "account", actorLabel: "cristian", action: "user.create" }),
    ).toThrowError(/CHECK constraint failed/);
  });

  it("refuses a half-filled target", () => {
    expect(() =>
      recordAudit(db, {
        actorKind: "system",
        actorLabel: "sweep",
        action: "token.expire",
        targetKind: "token",
      }),
    ).toThrowError(/CHECK constraint failed/);
  });

  it("outlives what it describes — no foreign keys, no cascade", () => {
    const alice = seedUser(db, "alice");
    recordAudit(db, {
      actorKind: "superuser",
      actorLabel: SUPERUSER_LABEL,
      action: "user.delete",
      targetKind: "user",
      targetId: alice.subject,
    });

    db.prepare("DELETE FROM users WHERE subject = ?").run(alice.subject);

    // Grants cascaded away; the record of the deletion did not.
    const surviving = listAudit(db, { targetKind: "user", targetId: alice.subject });
    expect(surviving).toHaveLength(1);
    expect(surviving[0]!.action).toBe("user.delete");
  });

  it("records an actor that has no users row at all", () => {
    // The superuser is the obvious case; a `system` actor is the other.
    expect(() =>
      recordAudit(db, {
        actorKind: "system",
        actorLabel: "reuse-detection",
        action: "session.revoke_family",
        targetKind: "session",
        targetId: "family-abc",
      }),
    ).not.toThrow();
  });

  it("accepts any action verb without a migration", () => {
    recordAudit(db, {
      actorKind: "system",
      actorLabel: "something-new",
      action: "an.action.nobody.foresaw",
    });

    expect(listAudit(db)[0]!.action).toBe("an.action.nobody.foresaw");
  });
});

describe("reading the log", () => {
  beforeEach(() => {
    for (let i = 0; i < 5; i += 1) {
      recordAudit(db, {
        actorKind: "superuser",
        actorLabel: SUPERUSER_LABEL,
        action: "grant.create",
        targetKind: "grant",
        targetId: `s:atrium:role-${i}`,
      });
    }
  });

  it("comes back newest first", () => {
    const rows = listAudit(db);
    expect(rows).toHaveLength(5);
    expect(rows.map((row) => row.id)).toEqual([...rows.map((row) => row.id)].sort((a, b) => b - a));
  });

  it("pages on the id, so a new event does not shift the second page", () => {
    const firstPage = listAudit(db, { limit: 2 });
    const secondPage = listAudit(db, { limit: 2, beforeId: firstPage.at(-1)!.id });

    recordAudit(db, { actorKind: "system", actorLabel: "noise", action: "noise" });

    const secondPageAgain = listAudit(db, { limit: 2, beforeId: firstPage.at(-1)!.id });
    expect(secondPageAgain.map((row) => row.id)).toEqual(secondPage.map((row) => row.id));
  });

  it("filters, and binds every value rather than interpolating it", () => {
    const owner = seedUser(db, "cristian");
    recordAudit(db, {
      actorKind: "account",
      actorSubject: owner.subject,
      actorLabel: "cristian",
      action: "user.disable",
      targetKind: "user",
      targetId: "victim",
    });

    expect(listAudit(db, { actorSubject: owner.subject })).toHaveLength(1);
    expect(listAudit(db, { action: "grant.create" })).toHaveLength(5);
    expect(listAudit(db, { targetKind: "grant", targetId: "s:atrium:role-3" })).toHaveLength(1);

    // A value that would be a SQL injection if it were interpolated.
    expect(listAudit(db, { action: "'; DROP TABLE audit_log; --" })).toEqual([]);
    expect(countAudit(db)).toBe(6);
  });
});
