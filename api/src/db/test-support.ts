import type Database from "better-sqlite3";
import { openDatabase } from "./connection.js";
import { runMigrations } from "./migrate.js";
import { createApp } from "./apps.js";
import { createUser, type UserRow } from "./users.js";

/**
 * Fixtures for the database tests.
 *
 * **`openDatabase(":memory:")`, never `getDb()`.** `openDatabase` is pure and
 * never imports `../config.js`, so a test opening one needs no environment set;
 * `getDb()` resolves `WARD_DB_PATH` and would open the real database on disk.
 * That distinction is the reason `connection.ts` goes out of its way to keep
 * its config import dynamic, and it is worth not undoing here.
 *
 * This module is not test code itself — it has no `.test.ts` suffix — so that
 * later briefs can import it for their own fixtures without depending on a file
 * the test runner owns.
 */

/** A fresh, fully migrated, private database. Dies with the test. */
export function freshDb(): Database.Database {
  const db = openDatabase(":memory:");
  runMigrations(db);
  return db;
}

/** The estate's apps, as the cutover will seed them. `prm` is the open one. */
export function seedApps(db: Database.Database): void {
  createApp(db, { slug: "atrium", name: "Atrium" });
  createApp(db, { slug: "newspapper", name: "Newspapper" });
  createApp(db, {
    slug: "prm",
    name: "Public Resource Map",
    publicRegistration: true,
    baselineRole: "user",
  });
}

/** An account with a throwaway password hash. */
export function seedUser(db: Database.Database, username: string, email?: string): UserRow {
  return createUser(db, {
    username,
    passwordHash: `scrypt$not-a-real-hash$${username}`,
    email: email ?? null,
  });
}
