import { afterEach, beforeEach, describe, expect, it } from "vitest";
import type Database from "better-sqlite3";
import { freshDb, seedApps, seedUser } from "./test-support.js";
import { SUPERUSER_ACTOR, grantRole } from "./grants.js";
import {
  SUPERUSER_LABEL,
  countAudit,
  grantTargetId,
  listAudit,
  parseGrantTargetId,
  recordAudit,
} from "./audit-log.js";

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

describe("grantTargetId identifies exactly one triple", () => {
  /**
   * The collision this encoding exists to prevent.
   *
   * Role strings are opaque and unrestricted — `grants.test.ts` deliberately
   * grants one containing `:`, and `apps.slug` has no CHECK forbidding one
   * either — so joining the triple on a bare `:` made
   * `(s, "atrium", "a:b")` and `(s, "atrium:a", "b")` the same string.
   * `AuditQuery.targetId` is an equality filter and it is how the console
   * answers "everything that happened to this grant", so that collision broke
   * the one job `audit_log` exists to do.
   */
  it("does not collide when a component contains the delimiter", () => {
    const subject = "e5b0c44298fc1c149afbf4c8996fb924";

    const a = grantTargetId(subject, "atrium", "a:b");
    const b = grantTargetId(subject, "atrium:a", "b");

    expect(a).not.toBe(b);
    expect(parseGrantTargetId(a)).toEqual({ subject, appSlug: "atrium", role: "a:b" });
    expect(parseGrantTargetId(b)).toEqual({ subject, appSlug: "atrium:a", role: "b" });
  });

  it("round-trips arbitrary component strings", () => {
    const nasty = [
      "a:b",
      "100%",
      "%3A",
      "with spaces",
      "",
      "rôle-ăî-日本語",
      "some.app/role:with-punctuation and spaces",
      ":::",
      "%zz",
    ];

    const seen = new Set<string>();
    for (const subject of nasty) {
      for (const appSlug of nasty) {
        for (const role of nasty) {
          const id = grantTargetId(subject, appSlug, role);
          expect(parseGrantTargetId(id)).toEqual({ subject, appSlug, role });
          // Distinct triples, distinct ids — the property that failed before.
          expect(seen.has(id)).toBe(false);
          seen.add(id);
        }
      }
    }
    expect(seen.size).toBe(nasty.length ** 3);
  });

  it("stays the console's equality filter, colons and all", () => {
    const owner = seedUser(db, "cristian");
    const role = "a:b";
    const targetId = grantTargetId(owner.subject, "atrium", role);

    recordAudit(db, {
      actorKind: "superuser",
      actorLabel: SUPERUSER_LABEL,
      action: "grant.create",
      targetKind: "grant",
      targetId,
    });
    // The triple that used to encode identically, recorded as a separate event.
    recordAudit(db, {
      actorKind: "superuser",
      actorLabel: SUPERUSER_LABEL,
      action: "grant.revoke",
      targetKind: "grant",
      targetId: grantTargetId(owner.subject, "atrium:a", "b"),
    });

    const rows = listAudit(db, { targetKind: "grant", targetId });
    expect(rows).toHaveLength(1);
    expect(rows[0]!.action).toBe("grant.create");
  });

  it("declines to decode something that is not a grant target id", () => {
    expect(parseGrantTargetId("just-a-subject")).toBeUndefined();
    expect(parseGrantTargetId("a:b:c:d")).toBeUndefined();
    // A malformed percent escape: URIError, surfaced as `undefined` rather than
    // thrown, because the console must render an unknown row without dying.
    expect(parseGrantTargetId("a:%zz:c")).toBeUndefined();
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

  /**
   * **`actorSubject` alone cannot express "what did the console do".**
   *
   * A CHECK ties `actor_subject IS NOT NULL` to `actor_kind = 'account'`, so
   * every row the console writes has a null subject — and the console is the
   * only surface where authority changes, which is the one thing this table
   * exists to record. `actorKind` and `actorLabel` are what make that trail
   * findable; `GET /console/audit` is built on them.
   */
  describe("filtering by actor kind and label", () => {
    beforeEach(() => {
      recordAudit(db, {
        actorKind: "superuser",
        actorLabel: SUPERUSER_LABEL,
        action: "app.registration",
        targetKind: "app",
        targetId: "prm",
      });
      recordAudit(db, {
        actorKind: "system",
        actorLabel: "reuse-sweep",
        action: "session.reuse_detected",
        targetKind: "session",
        targetId: "family-1",
      });
    });

    it("finds the console's rows, which no subject filter can", () => {
      const superuserRows = listAudit(db, { actorKind: "superuser" });
      expect(superuserRows.map((row) => row.action)).toEqual([
        "app.registration",
        ...Array.from({ length: 5 }, () => "grant.create"),
      ]);
      expect(superuserRows.every((row) => row.actor_subject === null)).toBe(true);

      // The filter that existed before, against the column that is null for
      // exactly these rows.
      expect(listAudit(db, { actorSubject: SUPERUSER_LABEL })).toEqual([]);
    });

    it("separates system rows from superuser rows", () => {
      expect(listAudit(db, { actorKind: "system" }).map((row) => row.actor_label)).toEqual([
        "reuse-sweep",
      ]);
    });

    it("matches actor_label exactly, never as a prefix", () => {
      expect(listAudit(db, { actorLabel: "reuse-sweep" })).toHaveLength(1);
      expect(listAudit(db, { actorLabel: "reuse" })).toEqual([]);
    });

    it("binds both new values rather than interpolating them", () => {
      expect(listAudit(db, { actorLabel: "'; DROP TABLE audit_log; --" })).toEqual([]);
      // The table is still there.
      expect(countAudit(db)).toBe(7);
    });

    it("combines with the existing filters", () => {
      expect(listAudit(db, { actorKind: "superuser", action: "app.registration" })).toHaveLength(1);
      expect(listAudit(db, { actorKind: "system", action: "app.registration" })).toEqual([]);
    });
  });
});
