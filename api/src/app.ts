import Fastify, { type FastifyError, type FastifyInstance } from "fastify";
import { healthRoutes } from "./routes/health.js";
import { jwksRoutes } from "./routes/jwks.js";
import { authRoutes } from "./routes/auth.js";
import { consoleRoutes } from "./routes/console.js";
import { introspectRoutes } from "./routes/introspect.js";
import { adminAppsRoutes } from "./routes/admin/apps.js";
import { adminGrantsRoutes } from "./routes/admin/grants.js";
import { adminAccountsRoutes } from "./routes/admin/accounts.js";
import { adminSessionsRoutes } from "./routes/admin/sessions.js";
import { adminAuditRoutes } from "./routes/admin/audit.js";
import { accountRoutes } from "./routes/account.js";
import { publicAppsRoutes } from "./routes/public-apps.js";
import { registerRoutes } from "./routes/register.js";

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

  /**
   * One generic body for every unhandled throw. **The default is a leak.**
   *
   * With no error handler Fastify's default reply puts `err.message` in the
   * body, and the reproduction was as bad as that sounds: a missing signing key
   * plus *correct* credentials answered `500` with the absolute on-disk path of
   * the estate's signing key and the shape of the deploy layout, from the one
   * route the whole internet can reach unauthenticated. A `SqliteError` would
   * hand out a column name the same way.
   *
   * Deliberate client errors are **not** flattened. Routes send their own 4xx
   * bodies with `reply.code(...).send(...)`, which never reaches an error
   * handler at all; what does reach it with a `statusCode` set is Fastify's own
   * client-error machinery — a `415` on an unsupported content type, a `400` on
   * an unparseable body, a `404`. Those messages are about the request the
   * caller sent, not about this server, and brief 09 renders some of them, so
   * they pass through unchanged. Only a throw with no client-error status — or
   * one claiming a 5xx — becomes `{"error":"internal"}`.
   *
   * The real error is logged server-side first, at `error`, with the request
   * bound to it, so nothing is lost to the operator.
   */
  // The `<FastifyError>` is load-bearing: Fastify types the error parameter as
  // `unknown` by default, and `statusCode` is the property that tells a
  // deliberate client error from a genuine fault.
  app.setErrorHandler<FastifyError>((error, request, reply) => {
    const status = typeof error.statusCode === "number" ? error.statusCode : 500;

    if (status >= 400 && status < 500) {
      request.log.info({ err: error, statusCode: status }, "request rejected");
      return reply.code(status).send({
        statusCode: status,
        error: error.name,
        message: error.message,
      });
    }

    request.log.error({ err: error }, "unhandled error");
    return reply.code(500).send({ error: "internal" });
  });

  await app.register(healthRoutes);
  await app.register(jwksRoutes);
  await app.register(authRoutes);
  await app.register(consoleRoutes);
  await app.register(introspectRoutes);

  // The five admin plugins each attach `requireConsoleSession` as a
  // plugin-scope preHandler, so registering them here does not open anything —
  // they gate themselves. Their paths all sit under `/console/` and that is
  // functional rather than cosmetic: the `ward_console` cookie is scoped to
  // `Path=/ward-api/console`, so a route mounted anywhere else would simply
  // never receive it.
  //
  // `adminSessionsRoutes` adds paths *under* `/console/accounts/:subject`,
  // which `adminAccountsRoutes` already claims. That is not a conflict — the
  // parameter is named `:subject` in both, so find-my-way merges the two into
  // one radix tree — but the two plugins must keep agreeing on that name, or
  // Fastify refuses to boot with a parametric-conflict error rather than
  // failing at request time.
  await app.register(adminAppsRoutes);
  await app.register(adminGrantsRoutes);
  await app.register(adminAccountsRoutes);
  await app.register(adminSessionsRoutes);
  await app.register(adminAuditRoutes);

  /**
   * The self-service surface, authenticated as an **ordinary account** from the
   * `ward_session` cookie — emphatically not through the console, which is
   * superuser-only by decision and has no second path into it. See the header
   * of `routes/account.ts`.
   */
  await app.register(accountRoutes);

  /**
   * `GET /apps` — the only **anonymous read** in the estate.
   *
   * Registered next to the anonymous write below so that what an
   * unauthenticated caller can reach is visible in one place. It answers the
   * apps whose `public_registration` flag is on, and nothing about the ones it
   * is off for.
   */
  await app.register(publicAppsRoutes);

  /**
   * Public registration and email verification, last because it is the only
   * anonymous *write* surface in the estate — worth being able to find in one
   * place when reasoning about what an unauthenticated caller can reach.
   *
   * It registers `/verify` inside its own encapsulated scope with a `req` log
   * serializer that redacts the whole query string. That is load-bearing rather
   * than tidy: the verification link has to be clickable from a mail client, so
   * the token travels in a URL, and Fastify writes its `incoming request` line
   * before any `onRequest` hook could scrub it.
   */
  await app.register(registerRoutes);

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
