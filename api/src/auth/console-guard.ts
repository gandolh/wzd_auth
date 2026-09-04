import type { FastifyReply, FastifyRequest } from "fastify";
import { readConsoleCookie, resolveConsoleSession, type ConsoleSession } from "./superuser.js";

/**
 * The gate on Ward's console. Brief 05's admin routes — apps, grants, accounts —
 * import `requireConsoleSession` from here and nothing else opens that surface.
 *
 * ## What this is NOT
 *
 * It is not an authorization check and it grants nothing. There is no
 * `if (isSuperuser)` anywhere in Ward, and there must not be: the superuser
 * reaching the console **and nothing else** falls out of it having no grants at
 * all (`decisions-admin.md`), so the only thing this hook establishes is "the
 * caller presented a live console session". Everything else in the estate keeps
 * asking the same question it already asks — does this subject hold a grant —
 * and the superuser, having no subject, is simply never an answer to it.
 *
 * If a future brief finds itself wanting a branch here that hands the superuser
 * an implicit grant, a subject, or a bypass in `/introspect`, that is the design
 * failing rather than a missing feature. `decisions-admin.md` rejected the
 * bypass explicitly, on the grounds that it is extra code whose only effect is
 * to let a break-glass credential read the library and the notes.
 *
 * ## Why it cannot accept an access token
 *
 * It reads exactly one cookie (`ward_console`) and looks the value up in an
 * in-process map of opaque session tokens. An ordinary account's access token is
 * a signed JWT that appears in a *different* cookie at `Path=/`; this hook never
 * looks there, and a JWT pasted into `ward_console` would simply not be in the
 * map. There is no signature to verify, no claim to read and no `sub` to trust,
 * so the rejection is structural rather than a check that could be forgotten.
 *
 * The mirror direction holds for the same reason and is asserted in
 * `superuser.test.ts`: a console token presented to the token layer's verify
 * fails, because it is not a JWT and nothing signed it.
 */

/**
 * The session belonging to the request being handled, if the guard let it
 * through.
 *
 * A `WeakMap` rather than `request.consoleSession`, on purpose. Decorating the
 * request would need a `declare module "fastify"` augmentation, which is global:
 * every file in the project would then see the property, including brief 03's
 * and brief 04's route handlers, where a console session has no business
 * existing and an `if (request.consoleSession)` would be one autocomplete away.
 * A `WeakMap` keyed on the request object gives the same lookup to whoever
 * imports this module and nothing at all to whoever does not, and it releases
 * with the request.
 */
const attached = new WeakMap<FastifyRequest, ConsoleSession>();

/**
 * The console session for this request, or `undefined` if the guard did not run
 * or did not admit it. Brief 05 needs this only to name the session in an audit
 * row — there is nothing else in it, by design (no subject, no grants).
 */
export function getConsoleSession(request: FastifyRequest): ConsoleSession | undefined {
  return attached.get(request);
}

/**
 * Fastify `preHandler` hook: admit a live console session, or answer 401.
 *
 * Attach it either way round, whichever suits the plugin:
 *
 * ```ts
 * // every route in this plugin scope
 * app.addHook("preHandler", requireConsoleSession);
 *
 * // or one route at a time
 * app.post("/console/apps", { preHandler: requireConsoleSession }, handler);
 * ```
 *
 * ## The failure mode leaks nothing
 *
 * One status, one body, for every reason: no cookie, an unparseable cookie, an
 * unknown token, an expired token, a token from before the last restart, an
 * access token in the wrong cookie. The caller cannot tell whether a console
 * credential exists, whether a session ever existed, or whether one just timed
 * out — and it deliberately does not send `WWW-Authenticate`, both because there
 * is no HTTP auth scheme in play and because a browser would answer it with a
 * native credential prompt on a service whose login is a form.
 *
 * `no-store` goes on the response either way: everything behind this gate is
 * administrative, per-operator and stale the moment it is written, and a shared
 * cache holding any of it is a bug with no upside.
 */
export async function requireConsoleSession(
  request: FastifyRequest,
  reply: FastifyReply,
): Promise<FastifyReply | undefined> {
  reply.header("cache-control", "no-store");

  const token = readConsoleCookie(request.headers.cookie);
  const session = token === undefined ? undefined : resolveConsoleSession(token);

  if (session === undefined) {
    // `return reply` is what stops the Fastify lifecycle from an async hook;
    // returning `undefined` here would run the route handler anyway.
    return reply.code(401).send({ error: "unauthorized" });
  }

  attached.set(request, session);
  return undefined;
}
