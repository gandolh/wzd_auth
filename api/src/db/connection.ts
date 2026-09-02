import { mkdirSync } from "node:fs";
import { dirname } from "node:path";
import Database from "better-sqlite3";

/**
 * The single `better-sqlite3` handle every module in Ward queries through.
 *
 * WHY A RAW DRIVER AND NOT KNEX. Atrium layered Knex over this same driver and
 * its D47 records the bill: three correctness properties in that codebase held
 * only because `better-sqlite3`'s synchronous statements could not interleave,
 * and all three broke once a query builder with an async connection pool sat in
 * front of them. Ward's hot path is session lookup under concurrency — the
 * exact shape where an interleaving that "almost never" happens starts
 * happening several times a day. A synchronous driver makes non-interleaving a
 * property of the language rather than of a pool configuration nobody re-reads,
 * so it is the default here and a move to a query builder would have to argue
 * its way past this comment.
 *
 * The same reasoning is why there is one connection and not a pool. SQLite is a
 * file, not a server: a second connection buys no write parallelism (writes
 * serialise on the database lock and surface as SQLITE_BUSY) while costing the
 * per-connection pragma guarantee below.
 */

/**
 * Open a database at `dbPath` with Ward's pragmas applied.
 *
 * Pure: takes the path as a parameter and never reads `../config.js`, so
 * calling it directly — a migration test opening `:memory:`, a one-shot
 * fixture builder — never triggers the environment validation that module
 * runs at import time. That guarantee only holds because nothing in this
 * function, or anywhere else at this module's top level, imports `config.js`
 * statically; see `getDb()` below for why the process-wide handle has to go
 * out of its way to preserve it.
 */
export function openDatabase(dbPath: string): Database.Database {
  // The driver opens the file but will not create the directory holding it, and
  // the first boot on a clean checkout has no data directory at all. `:memory:`
  // and other special paths resolve to a harmless relative dirname, so this is
  // safe to run unconditionally.
  mkdirSync(dirname(dbPath), { recursive: true });

  const connection = new Database(dbPath);

  // WAL is a property of the file rather than of the connection, so it only
  // genuinely takes effect once — but it is set on every open so a brand-new
  // database gets it on its first boot instead of on whatever later boot
  // happens to notice. It matters here because readers do not block the writer,
  // which is what keeps session lookups responsive while a token rotation or a
  // grant write is in flight.
  connection.pragma("journal_mode = WAL");

  // SQLite defaults foreign key enforcement OFF, per connection, every time.
  // Ward's schema is FK-heavy — grants, refresh tokens and the audit log all
  // hang off `users.subject` — so without this line every `REFERENCES` clause
  // in the schema is decoration and an orphaned grant row is accepted silently.
  // Being per-connection is also why nothing here should grow into a pool: the
  // pragma would then be a property of whichever connection you happened to
  // draw, which is precisely the class of bug D47 is about.
  connection.pragma("foreign_keys = ON");

  return connection;
}

let singleton: Database.Database | undefined;

/**
 * The process-wide handle, opened lazily from the validated `WARD_DB_PATH` on
 * first call and memoized for every call after.
 *
 * This used to be `export const db = openDatabase(WARD_DB_PATH)`, evaluated
 * at module top level. That made importing *anything* from this module —
 * including `openDatabase` alone, needed by a test that never wants the
 * singleton — evaluate `../config.js` as a side effect of the import graph,
 * which can `process.exit(1)` on a missing env var before the importer's own
 * code runs, or otherwise open the real production database on disk. Making
 * `getDb` a function fixes half of that: the module body no longer touches
 * `WARD_DB_PATH` at all. The other half is the `import("../config.js")`
 * below being dynamic rather than a static top-level import — a static
 * import is hoisted and evaluated the moment this module loads, so it would
 * still run config's module-level validation on a bare `import { getDb }`,
 * before `getDb` was ever called. Confirmed empirically: with a static
 * import in place, a script that imported only `openDatabase` and never
 * called `getDb` still printed the config banner and exited when required
 * env vars were unset. Only the dynamic import here actually defers
 * evaluation to the first real call.
 */
export async function getDb(): Promise<Database.Database> {
  if (!singleton) {
    const { WARD_DB_PATH } = await import("../config.js");
    singleton = openDatabase(WARD_DB_PATH);
  }
  return singleton;
}

/**
 * Close the process-wide handle, if one was ever opened, and forget it so a
 * later `getDb()` call opens a fresh one.
 *
 * Two callers need this. `index.ts`'s `shutdown()` calls it so SQLite gets to
 * run its close-time WAL checkpoint before the process exits — without it the
 * committed data can be left sitting in `ward.db-wal` instead of the main
 * database file. A test suite calls it between cases to reset the singleton.
 * `Database#close()` is synchronous and throws if the handle is already
 * closed, so this checks `.open` first to stay safe to call more than once —
 * `shutdown()` in particular must be able to reach this on both its success
 * and its error path without that ever being the thing that throws.
 */
export function closeDb(): void {
  if (singleton?.open) {
    singleton.close();
  }
  singleton = undefined;
}
