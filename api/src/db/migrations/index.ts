import type Database from "better-sqlite3";

// The `.js` suffix is required: this package is ESM under NodeNext, so a
// relative specifier carries the *emitted* extension even in `.ts` source.
import * as baseline from "./20260902000000-baseline.js";
import * as appKeys from "./20260906000000-app-keys.js";

/**
 * The migration list, as **static imports** rather than a directory the runner
 * scans at startup.
 *
 * A directory-scanning migration source reads files off disk at runtime and
 * picks a loader by file extension. That does not survive this build: in dev
 * the migrations are `.ts` executed by tsx, in production they are `.js` under
 * `dist/`, and `tsc` does not copy `.ts` sources into the output — so a
 * directory scan finds a different set of files (or none at all) depending on
 * how the process was started, and the failure mode is a production boot that
 * quietly believes it has no migrations to run. Listing them here means the
 * compiler resolves every one of them, they land in `dist/` like any other
 * module, and dev and production run byte-identical migration code. This is
 * atrium's D47 carried over; the driver differs, the argument does not.
 *
 * **Adding a migration.** Create the file beside this one, named
 * `<UTC timestamp>-<slug>.ts` (e.g. `20260902000000-baseline.ts`), exporting
 * `export function up(db: Database.Database): void`. Then import it at the top
 * of this file and append an entry to `MIGRATIONS` below:
 *
 * ```ts
 * import * as baseline from "./20260902000000-baseline.js";
 * // ...
 * export const MIGRATIONS: Migration[] = [
 *   { name: "20260902000000-baseline", up: baseline.up },
 * ];
 * ```
 *
 * Note the `.js` suffix on the import — this package is ESM under NodeNext, so
 * relative specifiers carry the *emitted* extension even in `.ts` source.
 *
 * **Order in this array IS the run order.** A new migration goes at the END.
 * Never reorder and never rename an existing entry: the runner records `name`
 * in `ward_migrations` and matches on it, so a rename presents an
 * already-applied migration as a new one and re-runs it against a database that
 * already has its changes — which for a `CREATE TABLE` means a hard failure and
 * for anything data-shaped means silent corruption.
 *
 * **There is no `down`.** Rolling a migration back on a live database is a
 * repair operation that wants a human looking at the data, not a code path that
 * exists to be invoked; forward-only migrations plus the file backup taken
 * before a deploy cover the same ground without pretending the reverse of a
 * destructive change is recoverable. Add one only when something actually needs
 * it, and say what.
 *
 * Brief 00 owns the runner mechanism; the baseline schema — `users`, `apps`,
 * `grants`, `refresh_tokens`, `verification_tokens`, `audit_log` — is brief
 * 01's and is the first entry below.
 */

export interface Migration {
  /**
   * The identifier recorded in `ward_migrations`. Immutable once the migration
   * has run anywhere — see the rename warning above.
   */
  name: string;
  /**
   * Applies the migration. Called inside a transaction the runner owns. A
   * nested `db.transaction()` inside `up()` is safe — `better-sqlite3`
   * implements nested transactions as a SAVEPOINT, not a real `BEGIN`, so an
   * outer-calling-inner transaction succeeds. What is never safe is a raw
   * `db.exec("BEGIN ...")` / `COMMIT` / `ROLLBACK`: a stray `COMMIT` closes
   * the runner's own transaction early, so a later failure in the same
   * `up()` no longer rolls back what already ran, and `ward_migrations` ends
   * up recording a half-applied migration as done. Must not swallow errors —
   * throwing is still how `up()` asks to be rolled back.
   *
   * One consequence worth knowing before writing a table rebuild: `PRAGMA
   * foreign_keys` is a no-op inside a transaction, so a migration that needs
   * enforcement off for a legacy-style rebuild cannot get it here. Prefer
   * `PRAGMA legacy_alter_table` or a rebuild ordered so the constraints hold
   * throughout; if neither works, change the runner deliberately rather than
   * working around it in a migration.
   */
  up(db: Database.Database): void;
}

export const MIGRATIONS: Migration[] = [
  { name: "20260902000000-baseline", up: baseline.up },
  { name: "20260906000000-app-keys", up: appKeys.up },
];
