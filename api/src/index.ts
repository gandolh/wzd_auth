/**
 * Ward's entry point: validate the environment, migrate, build the app,
 * listen — in that order, and each step gated on the one before it.
 *
 * `./config.js` is imported first, and for its own sake: importing it runs
 * zod validation against `process.env` and can call `process.exit(1)`, and
 * that has to happen before anything below opens a socket or a database
 * handle. `./db/connection.js`'s `getDb()` also reads `config.js`, but only
 * lazily, on its own first call — it no longer runs config validation just
 * by being imported (see `connection.ts`) — so the explicit top-level import
 * here is what keeps the environment check happening first and visibly,
 * rather than resting on `getDb()` being called before anything else.
 */
import { HOST, PORT } from "./config.js";
import { getDb, closeDb } from "./db/connection.js";
import { runMigrations } from "./db/migrate.js";
import { buildApp } from "./app.js";

/**
 * Migrations run synchronously, to completion, before `buildApp` is even
 * called — let alone before the listener binds. `runMigrations` is
 * synchronous by design (see `db/migrate.ts`), so there is no `await` to get
 * wrong here once `db` itself is in hand; the ordering after that point is
 * enforced by plain statement order. A server that starts accepting requests
 * against a half-migrated database is the failure this sequencing exists to
 * rule out.
 */
const db = await getDb();
runMigrations(db);

const app = await buildApp();

/**
 * `HOST` defaults to `127.0.0.1` (see `config.ts`), so this listens on
 * loopback unless an operator has explicitly opted into something wider.
 * Caddy reverse-proxies to Ward over loopback on the same box; nothing here
 * should ever need to bind `0.0.0.0` outside a container.
 */
await app.listen({ host: HOST, port: PORT });

/**
 * pm2 manages Ward alongside five other apps and restarts a process that
 * exits cleanly; a process that hangs on shutdown just gets SIGKILLed after
 * pm2's grace period, dropping in-flight requests. `app.close()` waits for
 * Fastify's connections to drain and its `onClose` hooks to run before this
 * resolves, so both signals get a real chance at a clean stop before pm2's
 * timeout would force one.
 */
async function shutdown(signal: NodeJS.Signals): Promise<void> {
  app.log.info({ signal }, "shutting down");
  try {
    await app.close();
    // Closing the database here — after Fastify has drained, so no in-flight
    // request can still be using it — is what makes SQLite run its close-time
    // WAL checkpoint. Skip this and the process still exits cleanly, but the
    // data committed during this run stays sitting in `ward.db-wal` instead
    // of landing in `ward.db` itself: a reproduced boot→serve→SIGTERM cycle
    // without this call left `ward.db` at 4096 bytes with zero tables, not
    // even `ward_migrations`. This is not tidiness before exit; a backup that
    // copies `ward.db` alone depends on this having run. `closeDb()` is safe
    // to call whether or not `db` was ever opened, so it belongs on both the
    // success and the error path below.
    closeDb();
    process.exit(0);
  } catch (err) {
    app.log.error({ err }, "error during shutdown");
    closeDb();
    process.exit(1);
  }
}

process.on("SIGINT", () => {
  void shutdown("SIGINT");
});
process.on("SIGTERM", () => {
  void shutdown("SIGTERM");
});
