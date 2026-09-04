import Fastify, { type FastifyInstance } from "fastify";
import { healthRoutes } from "./routes/health.js";
import { jwksRoutes } from "./routes/jwks.js";
import { authRoutes } from "./routes/auth.js";
import { consoleRoutes } from "./routes/console.js";

/**
 * Construct and configure the Fastify instance — nothing more.
 *
 * Deliberately free of side effects beyond that: no `listen()`, no
 * `runMigrations()`, no reach into `db`. Two reasons. First, `index.ts` needs
 * migrations to finish (see there) strictly before the listener binds, and
 * that ordering is easiest to get right when this function cannot itself open
 * a socket. Second, brief 00's own acceptance test — and anything later briefs
 * write — wants to build an app in-process (e.g. with `app.inject()`) without
 * a live port or a real database on disk. Keep it that way: briefs 02–06
 * register their route plugins into the instance this returns, they do not
 * add their own `listen()` calls.
 */
export async function buildApp(): Promise<FastifyInstance> {
  const app = Fastify({
    logger: true,
    // Fastify's default request log line uses the built-in `req` serializer,
    // which logs only method, url, host, remoteAddress, remotePort and the
    // accept-version header. General request headers — a future
    // `Authorization`, say — are NOT logged, and neither is the body, which
    // is what we want: later briefs carry credentials (passwords, refresh
    // tokens) in POST bodies, and those must never reach the log. But `url`
    // does carry the query string, so every info-level log line contains
    // whatever query parameters the request had — brief 03 (login/refresh)
    // needs to keep that in mind when deciding what is allowed to travel in
    // a URL. Nothing here overrides the default; naming it so a future
    // change to `logger` doesn't casually turn body or header logging on.
  });

  await app.register(healthRoutes);
  await app.register(jwksRoutes);
  await app.register(authRoutes);
  await app.register(consoleRoutes);

  // Registration order carries no meaning — these plugins share no state and
  // no route prefix, and each declares its own paths. It is alphabetical-ish by
  // brief number only so a reader can find the brief that owns a route.
  //
  // Both `authRoutes` and `consoleRoutes` accept an options object with a `db`
  // for tests; neither is given one here, so both resolve the process-wide
  // handle lazily on first request rather than at registration. That is what
  // keeps `buildApp()` callable with no database on disk.

  return app;
}
