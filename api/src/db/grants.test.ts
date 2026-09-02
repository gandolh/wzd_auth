import { afterEach, beforeEach, describe, expect, it } from "vitest";
import type Database from "better-sqlite3";
import { freshDb, seedApps, seedUser } from "./test-support.js";
import { createApp, getApp, listApps, listOpenApps, setPublicRegistration } from "./apps.js";
import {
  SUPERUSER_ACTOR,
  ensureGrant,
  grantRole,
  grantsBySlug,
  hasGrant,
  listGrantsForApp,
  listGrantsForSubject,
  listRolesInApp,
  revokeAllGrants,
  revokeAppAccess,
  revokeGrant,
} from "./grants.js";

let db: Database.Database;

beforeEach(() => {
  db = freshDb();
  seedApps(db);
});

afterEach(() => {
  db.close();
});

describe("grants are a set of (subject, app, role)", () => {
  it("one person holds several roles in one app", () => {
    const alice = seedUser(db, "alice");

    grantRole(db, {
      subject: alice.subject,
      appSlug: "prm",
      role: "user",
      grantedBy: SUPERUSER_ACTOR,
    });
    grantRole(db, {
      subject: alice.subject,
      appSlug: "prm",
      role: "admin",
      grantedBy: SUPERUSER_ACTOR,
    });
    grantRole(db, {
      subject: alice.subject,
      appSlug: "prm",
      role: "moderator",
      grantedBy: SUPERUSER_ACTOR,
    });

    expect(listRolesInApp(db, alice.subject, "prm")).toEqual(["admin", "moderator", "user"]);
    expect(hasGrant(db, alice.subject, "prm", "moderator")).toBe(true);
  });

  // The acceptance criterion. The assertion is on the SQLite error, which is
  // the proof that it is the PRIMARY KEY refusing and not a guard in the module
  // above it — a guard could be forgotten by the next caller, or raced past
  // between a SELECT and an INSERT.
  it("rejects a duplicate triple in the database, not in application code", () => {
    const alice = seedUser(db, "alice");
    grantRole(db, {
      subject: alice.subject,
      appSlug: "prm",
      role: "admin",
      grantedBy: SUPERUSER_ACTOR,
    });

    expect(() =>
      grantRole(db, {
        subject: alice.subject,
        appSlug: "prm",
        role: "admin",
        grantedBy: SUPERUSER_ACTOR,
      }),
    ).toThrowError(/UNIQUE constraint failed: grants\.subject, grants\.app_slug, grants\.role/);

    expect(listRolesInApp(db, alice.subject, "prm")).toEqual(["admin"]);
  });

  it("rejects the duplicate even on a raw INSERT that bypasses this module", () => {
    const alice = seedUser(db, "alice");
    const insert = db.prepare(
      "INSERT INTO grants (subject, app_slug, role, granted_by) VALUES (?, ?, ?, ?)",
    );

    insert.run(alice.subject, "atrium", "user", SUPERUSER_ACTOR);

    expect(() => insert.run(alice.subject, "atrium", "user", SUPERUSER_ACTOR)).toThrowError(
      /UNIQUE constraint failed/,
    );
  });

  it("is unique on all three columns together, not on (subject, app)", () => {
    const alice = seedUser(db, "alice");
    const bob = seedUser(db, "bob");

    // Same subject + app, different role: allowed.
    grantRole(db, {
      subject: alice.subject,
      appSlug: "atrium",
      role: "user",
      grantedBy: SUPERUSER_ACTOR,
    });
    grantRole(db, {
      subject: alice.subject,
      appSlug: "atrium",
      role: "admin",
      grantedBy: SUPERUSER_ACTOR,
    });
    // Same app + role, different subject: allowed.
    grantRole(db, {
      subject: bob.subject,
      appSlug: "atrium",
      role: "user",
      grantedBy: SUPERUSER_ACTOR,
    });

    expect(listGrantsForApp(db, "atrium")).toHaveLength(3);
  });

  it("ensureGrant is idempotent where grantRole throws", () => {
    const alice = seedUser(db, "alice");

    expect(
      ensureGrant(db, {
        subject: alice.subject,
        appSlug: "prm",
        role: "user",
        grantedBy: SUPERUSER_ACTOR,
      }),
    ).toBeDefined();
    expect(
      ensureGrant(db, {
        subject: alice.subject,
        appSlug: "prm",
        role: "user",
        grantedBy: SUPERUSER_ACTOR,
      }),
    ).toBeUndefined();

    expect(listRolesInApp(db, alice.subject, "prm")).toEqual(["user"]);
  });

  it("treats role strings as opaque — Ward never interprets them", () => {
    const alice = seedUser(db, "alice");
    const odd = "some.app/role:with-punctuation and spaces";

    grantRole(db, {
      subject: alice.subject,
      appSlug: "atrium",
      role: odd,
      grantedBy: SUPERUSER_ACTOR,
    });

    expect(hasGrant(db, alice.subject, "atrium", odd)).toBe(true);
  });
});

describe("grants are the security boundary", () => {
  it("an account with no grants reaches nothing", () => {
    const stranger = seedUser(db, "stranger");

    expect(listGrantsForSubject(db, stranger.subject)).toEqual([]);
    expect(grantsBySlug(db, stranger.subject)).toEqual({});
    expect(hasGrant(db, stranger.subject, "atrium", "user")).toBe(false);
  });

  it("there is no wildcard — the owner holds one explicit row per app", () => {
    const owner = seedUser(db, "cristian");

    for (const app of listApps(db)) {
      grantRole(db, {
        subject: owner.subject,
        appSlug: app.slug,
        role: "admin",
        grantedBy: SUPERUSER_ACTOR,
      });
    }

    expect(listGrantsForSubject(db, owner.subject)).toHaveLength(3);

    // A newly added app is reachable by nobody until someone says otherwise.
    createApp(db, { slug: "trips", name: "Trips" });
    expect(hasGrant(db, owner.subject, "trips", "admin")).toBe(false);
    expect(listGrantsForApp(db, "trips")).toEqual([]);
  });

  it("groups grants by app for the introspection response", () => {
    const alice = seedUser(db, "alice");
    grantRole(db, {
      subject: alice.subject,
      appSlug: "prm",
      role: "user",
      grantedBy: SUPERUSER_ACTOR,
    });
    grantRole(db, {
      subject: alice.subject,
      appSlug: "prm",
      role: "admin",
      grantedBy: SUPERUSER_ACTOR,
    });
    grantRole(db, {
      subject: alice.subject,
      appSlug: "atrium",
      role: "user",
      grantedBy: SUPERUSER_ACTOR,
    });

    expect(grantsBySlug(db, alice.subject)).toEqual({
      atrium: ["user"],
      prm: ["admin", "user"],
    });
  });

  it("revokes one role, one app, or everything", () => {
    const alice = seedUser(db, "alice");
    grantRole(db, {
      subject: alice.subject,
      appSlug: "prm",
      role: "user",
      grantedBy: SUPERUSER_ACTOR,
    });
    grantRole(db, {
      subject: alice.subject,
      appSlug: "prm",
      role: "admin",
      grantedBy: SUPERUSER_ACTOR,
    });
    grantRole(db, {
      subject: alice.subject,
      appSlug: "atrium",
      role: "user",
      grantedBy: SUPERUSER_ACTOR,
    });

    expect(revokeGrant(db, alice.subject, "prm", "admin")).toBe(true);
    expect(revokeGrant(db, alice.subject, "prm", "admin")).toBe(false);
    expect(listRolesInApp(db, alice.subject, "prm")).toEqual(["user"]);

    expect(revokeAppAccess(db, alice.subject, "prm")).toBe(1);
    expect(revokeAllGrants(db, alice.subject)).toBe(1);
    expect(listGrantsForSubject(db, alice.subject)).toEqual([]);
  });
});

describe("foreign keys actually enforce", () => {
  it("an orphan grant — unknown subject — is refused", () => {
    expect(() =>
      db
        .prepare("INSERT INTO grants (subject, app_slug, role, granted_by) VALUES (?, ?, ?, ?)")
        .run("nobody-has-this-subject", "atrium", "user", SUPERUSER_ACTOR),
    ).toThrowError(/FOREIGN KEY constraint failed/);
  });

  it("an orphan grant — unknown app — is refused", () => {
    const alice = seedUser(db, "alice");

    expect(() =>
      grantRole(db, {
        subject: alice.subject,
        appSlug: "not-an-app",
        role: "user",
        grantedBy: SUPERUSER_ACTOR,
      }),
    ).toThrowError(/FOREIGN KEY constraint failed/);
  });

  it("deleting an account takes its grants with it", () => {
    const alice = seedUser(db, "alice");
    grantRole(db, {
      subject: alice.subject,
      appSlug: "prm",
      role: "user",
      grantedBy: SUPERUSER_ACTOR,
    });

    db.prepare("DELETE FROM users WHERE subject = ?").run(alice.subject);

    expect(listGrantsForApp(db, "prm")).toEqual([]);
  });

  it("deleting an app takes everyone's access to it", () => {
    const alice = seedUser(db, "alice");
    grantRole(db, {
      subject: alice.subject,
      appSlug: "prm",
      role: "user",
      grantedBy: SUPERUSER_ACTOR,
    });
    grantRole(db, {
      subject: alice.subject,
      appSlug: "atrium",
      role: "user",
      grantedBy: SUPERUSER_ACTOR,
    });

    db.prepare("DELETE FROM apps WHERE slug = ?").run("prm");

    expect(listGrantsForSubject(db, alice.subject).map((g) => g.app_slug)).toEqual(["atrium"]);
  });

  it("granted_by is deliberately not a foreign key, because the superuser has no row", () => {
    const alice = seedUser(db, "alice");

    const grant = grantRole(db, {
      subject: alice.subject,
      appSlug: "atrium",
      role: "admin",
      grantedBy: SUPERUSER_ACTOR,
    });

    expect(grant.granted_by).toBe("superuser");
    // And there is no users row for it, now or ever.
    expect(
      db
        .prepare<[], number>("SELECT count(*) FROM users WHERE username_folded = 'superuser'")
        .pluck()
        .get(),
    ).toBe(0);
  });

  // No foreign key does not mean no constraint. The column exists so that "who
  // granted this and when" survives even a pruned audit log, and a NULL answers
  // that question with nothing — so it is the *schema* that refuses, not
  // `grants.ts`. `NewGrant.grantedBy` being required is the compile-time half
  // of the same rule; this is the half a raw INSERT cannot get around.
  it("the schema itself refuses a NULL granted_by", () => {
    const alice = seedUser(db, "alice");

    expect(() =>
      db
        .prepare("INSERT INTO grants (subject, app_slug, role, granted_by) VALUES (?, ?, ?, ?)")
        .run(alice.subject, "atrium", "user", null),
    ).toThrowError(/NOT NULL constraint failed: grants\.granted_by/);

    // And omitting the column entirely is the same refusal — there is no
    // default to fall back to, deliberately.
    expect(() =>
      db
        .prepare("INSERT INTO grants (subject, app_slug, role) VALUES (?, ?, ?)")
        .run(alice.subject, "atrium", "user"),
    ).toThrowError(/NOT NULL constraint failed: grants\.granted_by/);

    expect(listGrantsForApp(db, "atrium")).toEqual([]);
  });
});

describe("apps: registration is closed by default", () => {
  it("a new app is closed and confers nothing unless told otherwise", () => {
    const app = createApp(db, { slug: "trips", name: "Trips" });

    expect(app.public_registration).toBe(0);
    expect(app.baseline_role).toBeNull();
    expect(listOpenApps(db).map((a) => a.slug)).toEqual(["prm"]);
  });

  it("cannot be opened to the public without naming what a stranger gets", () => {
    expect(() =>
      createApp(db, { slug: "trips", name: "Trips", publicRegistration: true }),
    ).toThrowError(/CHECK constraint failed/);

    expect(() =>
      db.prepare("UPDATE apps SET public_registration = 1 WHERE slug = ?").run("atrium"),
    ).toThrowError(/CHECK constraint failed/);
  });

  it("opening and closing carries the baseline role with it", () => {
    setPublicRegistration(db, "atrium", true, "user");
    expect(getApp(db, "atrium")).toMatchObject({ public_registration: 1, baseline_role: "user" });

    setPublicRegistration(db, "atrium", false);
    expect(getApp(db, "atrium")).toMatchObject({
      public_registration: 0,
      baseline_role: null,
    });
  });

  it("keeps slugs lower case so one app cannot become two", () => {
    expect(() => createApp(db, { slug: "Trips", name: "Trips" })).toThrowError(
      /CHECK constraint failed/,
    );
  });
});
