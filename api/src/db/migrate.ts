import type Database from "better-sqlite3";
import { MIGRATIONS, type Migration } from "./migrations/index.js";

/**
 * The bookkeeping table. One row per applied migration, keyed by the `name`
 * from the `MIGRATIONS` array — which is why that name is immutable once it has
 * run anywhere (see `./migrations/index.ts`).
 *
 * `applied_at` is an ISO-8601 UTC string rather than a numeric epoch because
 * the only consumer of this table is a human with the sqlite3 CLI open,
 * reconstructing what a given deploy did and when. Nothing in the service reads
 * it.
 */
const APPLIED_TABLE_DDL = `
  CREATE TABLE IF NOT EXISTS ward_migrations (
    name       TEXT PRIMARY KEY,
    applied_at TEXT NOT NULL
  )
`;

/**
 * Apply every migration in `MIGRATIONS` that this database has not seen.
 *
 * Called once at boot, before the server starts listening. Safe to call on an
 * already-current database: the second run finds every name present in
 * `ward_migrations`, applies nothing, and returns.
 *
 * **One transaction per migration, not one around the whole run.** A failure
 * therefore leaves the migrations before it applied, the failing one rolled
 * back whole, and the ones after it untouched — so the fix is to repair the
 * broken migration and boot again, rather than to reason about a half-applied
 * schema. Wrapping the entire sequence would instead make every earlier success
 * hostage to a later failure, which is the wrong trade when migrations are
 * forward-only. `better-sqlite3`'s `db.transaction()` is synchronous, so the
 * boundary really is the function call and there is no await between the schema
 * change and the row that records it.
 *
 * The insert is inside that transaction deliberately: if recording the
 * migration were a separate statement, a crash in the gap would leave a
 * database whose schema has changed but whose bookkeeping says otherwise, and
 * the next boot would re-run the migration against its own output.
 */
export function runMigrations(db: Database.Database): void {
  db.exec(APPLIED_TABLE_DDL);

  assertNamesAreUnique(MIGRATIONS);

  const applied = new Set(db.prepare("SELECT name FROM ward_migrations").pluck().all() as string[]);

  assertNoAppliedNameIsMissing(applied, MIGRATIONS);

  const record = db.prepare("INSERT INTO ward_migrations (name, applied_at) VALUES (?, ?)");

  for (const migration of MIGRATIONS) {
    if (applied.has(migration.name)) continue;

    const apply = db.transaction(() => {
      migration.up(db);
      record.run(migration.name, new Date().toISOString());
    });
    apply();
  }
}

/**
 * A duplicated `name` would otherwise surface as a primary-key violation from
 * the insert above, halfway through a run, pointing at the bookkeeping table
 * instead of at the copy-paste in the array that caused it. Checking up front
 * costs nothing and names the actual mistake.
 */
function assertNamesAreUnique(migrations: Migration[]): void {
  const seen = new Set<string>();
  for (const { name } of migrations) {
    if (seen.has(name)) {
      throw new Error(
        `Duplicate migration name "${name}" in MIGRATIONS. Names are the ` +
          `identity recorded in ward_migrations and must be unique.`,
      );
    }
    seen.add(name);
  }
}

/**
 * The reverse of `assertNamesAreUnique`: every name already recorded in
 * `ward_migrations` must still exist in `MIGRATIONS`. `migrations/index.ts`
 * documents renaming or reordering an applied entry as forbidden, but until
 * this check existed nothing enforced it. Without it, a renamed entry simply
 * disappears from `applied` and the loop below treats it as a brand-new
 * migration — loud and merely wasteful for a `CREATE TABLE` (it fails on the
 * conflicting schema), silent and destructive for anything data-shaped, such
 * as a backfill re-applied against its own output.
 */
function assertNoAppliedNameIsMissing(applied: Set<string>, migrations: Migration[]): void {
  const known = new Set(migrations.map((migration) => migration.name));
  for (const name of applied) {
    if (!known.has(name)) {
      throw new Error(
        `Migration "${name}" is recorded in ward_migrations but no longer appears in ` +
          `MIGRATIONS. It was renamed, reordered, or deleted — the name recorded in ` +
          `ward_migrations is the identity and must never change once a migration has run.`,
      );
    }
  }
}
