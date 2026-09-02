import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import { openDatabase } from "../connection.js";
import { runMigrations } from "../migrate.js";
import { MIGRATIONS } from "./index.js";
import { freshDb, seedApps, seedUser } from "../test-support.js";

/** Names + DDL of every table and index, as one comparable snapshot. */
function schemaSnapshot(db: ReturnType<typeof openDatabase>): { name: string; sql: string }[] {
  return db
    .prepare<[], { name: string; sql: string }>(
      `SELECT name, coalesce(sql, '') AS sql
         FROM sqlite_master
        WHERE name NOT LIKE 'sqlite_%'
        ORDER BY type, name`,
    )
    .all();
}

function tableNames(db: ReturnType<typeof openDatabase>): string[] {
  return db
    .prepare<[], string>(
      `SELECT name FROM sqlite_master
        WHERE type = 'table' AND name NOT LIKE 'sqlite_%'
        ORDER BY name`,
    )
    .pluck()
    .all();
}

describe("baseline migration", () => {
  it("creates every table the estate needs on a fresh database", () => {
    const db = freshDb();

    expect(tableNames(db)).toEqual([
      "apps",
      "audit_log",
      "grants",
      "refresh_tokens",
      "users",
      "verification_tokens",
      "ward_migrations",
    ]);

    db.close();
  });

  it("records itself in ward_migrations exactly once", () => {
    const db = freshDb();

    const applied = db
      .prepare<[], string>("SELECT name FROM ward_migrations ORDER BY name")
      .pluck()
      .all();

    expect(applied).toEqual(MIGRATIONS.map((migration) => migration.name));
    expect(applied).toContain("20260902000000-baseline");

    db.close();
  });

  // The acceptance criterion, and the property that keeps every boot after the
  // first from being a gamble: the runner is called on every start.
  it("is safe to run twice — the second run applies nothing and changes nothing", () => {
    const db = openDatabase(":memory:");

    runMigrations(db);
    const afterFirst = schemaSnapshot(db);
    const appliedFirst = db.prepare("SELECT * FROM ward_migrations").all();

    expect(() => {
      runMigrations(db);
    }).not.toThrow();

    expect(schemaSnapshot(db)).toEqual(afterFirst);
    expect(db.prepare("SELECT * FROM ward_migrations").all()).toEqual(appliedFirst);

    db.close();
  });

  it("survives a third run, and one that follows real data being written", () => {
    const db = freshDb();
    seedApps(db);
    seedUser(db, "cristian");

    const before = schemaSnapshot(db);
    runMigrations(db);
    runMigrations(db);

    expect(schemaSnapshot(db)).toEqual(before);
    expect(db.prepare<[], number>("SELECT count(*) FROM users").pluck().get()).toBe(1);

    db.close();
  });

  it("enforces foreign keys — every connection, not just the first", () => {
    const db = freshDb();
    expect(db.pragma("foreign_keys", { simple: true })).toBe(1);
    db.close();
  });

  it("leaves the superuser with no row anywhere", () => {
    // decisions-admin.md: WARD_ADMIN_USERNAME is break-glass, lives only in the
    // environment, and is deliberately not seeded. A migration that "helpfully"
    // creates a first admin would break the one property that makes it a
    // recovery mechanism: a row can be disabled, revoked or deleted.
    const db = freshDb();

    for (const table of ["users", "apps", "grants", "refresh_tokens", "verification_tokens"]) {
      expect(
        db.prepare<[], number>(`SELECT count(*) FROM ${table}`).pluck().get(),
        `${table} should be empty on a fresh database`,
      ).toBe(0);
    }

    db.close();
  });

  it("says in the schema why the superuser has no row", () => {
    // The acceptance criterion is about the comment surviving, so assert on it.
    // A future migration that seeds an admin has to delete this text first,
    // which is the point at which someone has to read decisions-admin.md.
    const source = readBaselineSource();

    expect(source).toContain("WHY THE SUPERUSER HAS NO ROW IN ANY TABLE BELOW");
    expect(source).toMatch(/break-glass/i);
    expect(source).toContain("decisions-admin.md");
  });
});

function readBaselineSource(): string {
  const here = fileURLToPath(new URL(".", import.meta.url));
  return readFileSync(`${here}20260902000000-baseline.ts`, "utf8");
}
