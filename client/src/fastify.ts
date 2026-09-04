import type { FastifyInstance, FastifyReply, FastifyRequest } from "fastify";
import type { WardClient } from "./client.js";
import { requireGrant } from "./client.js";
import type { ActiveSession } from "./session.js";

/**
 * The thin Fastify layer over the framework-agnostic core (`./index`, or
 * `client.js` directly). Five of the six apps this package serves are
 * Fastify; the core itself imports nothing from Fastify, and this is the only
 * file in the package that does.
 *
 * Usage:
 *
 *     import { createWardClient } from "@ward/client";
 *     import { wardFastifyPlugin } from "@ward/client/fastify";
 *
 *     const ward = createWardClient({ publicOrigin: "https://gandolh.ro", apiBasePath: "/ward-api" });
 *     await app.register(wardFastifyPlugin, { client: ward });
 *
 *     app.get("/dashboard", { preHandler: app.wardAuthenticate }, handler);
 *     app.get("/admin", {
 *       preHandler: [app.wardAuthenticate, app.wardRequireGrant("atrium", "admin")],
 *     }, handler);
 *
 * `request.ward` is set by `wardAuthenticate` and holds `{ subject, username,
 * grants }` — never a raw token, never anything to re-parse.
 */

declare module "fastify" {
  interface FastifyRequest {
    /** Set by `wardAuthenticate` once it succeeds. Absent on a route that never ran it. */
    ward?: ActiveSession;
  }

  interface FastifyInstance {
    /**
     * A preHandler: reads the `ward_session` cookie, verifies it locally,
     * asks Ward for liveness and authority, and sets `request.ward`.
     *
     * Throws `WardAuthenticationError` (401) when there is no cookie, the
     * token does not verify, or the session is not active; throws
     * `WardUnavailableError` (503) when Ward could not be reached — **the
     * request is rejected, not allowed through** on an unreachable Ward, per
     * `corpus/wiki/decisions-tokens.md`. Both errors carry `statusCode`, so
     * Fastify's default error handler already answers correctly with no
     * further wiring.
     */
    wardAuthenticate: (request: FastifyRequest, reply: FastifyReply) => Promise<void>;

    /**
     * A preHandler factory: `app.wardRequireGrant("atrium", "admin")`. Runs
     * `wardAuthenticate` itself if `request.ward` is not already set (so it
     * is safe to use alone, without listing `wardAuthenticate` first), then
     * throws `WardForbiddenError` (403) if the session does not hold the
     * given role in the given app. **The negative case — a role the person
     * does not hold — is refused**, and that is the test that matters.
     */
    wardRequireGrant: (
      app: string,
      role: string,
    ) => (request: FastifyRequest, reply: FastifyReply) => Promise<void>;
  }
}

export interface WardFastifyPluginOptions {
  /** The `@ward/client` instance this Fastify app authenticates against. */
  client: WardClient;
}

/**
 * Registers `wardAuthenticate` and `wardRequireGrant` on the Fastify
 * instance.
 *
 * Implemented without the `fastify-plugin` package (avoiding an otherwise
 * unnecessary dependency): Fastify's own encapsulation model looks for a
 * `Symbol.for("skip-override")` flag on a plugin function to decide whether
 * to give it a new encapsulated child context or apply its decorations to the
 * instance it was handed — `fastify-plugin` is a small wrapper that sets
 * exactly this flag, and setting it directly below is the same mechanism with
 * one less dependency to pin.
 */
async function wardFastifyPluginImpl(
  app: FastifyInstance,
  options: WardFastifyPluginOptions,
): Promise<void> {
  const { client } = options;

  app.decorateRequest("ward", undefined);

  const wardAuthenticate = async (request: FastifyRequest, _reply: FastifyReply): Promise<void> => {
    // Errors thrown here (WardAuthenticationError, WardUnavailableError) are
    // left to propagate to Fastify's error handler, which reads their
    // `statusCode` — see the ambient-type doc comment above for why that is
    // sufficient with no extra error handler wiring.
    request.ward = await client.authenticate(request.headers.cookie);
  };

  app.decorate("wardAuthenticate", wardAuthenticate);

  app.decorate("wardRequireGrant", (grantApp: string, role: string) => {
    return async (request: FastifyRequest, reply: FastifyReply): Promise<void> => {
      if (!request.ward) {
        await wardAuthenticate(request, reply);
      }
      // request.ward is set by wardAuthenticate above, or this throws before
      // reaching here — so the assertion is safe.
      requireGrant(request.ward!, grantApp, role);
    };
  });
}

(wardFastifyPluginImpl as unknown as Record<symbol, boolean>)[Symbol.for("skip-override")] = true;

export const wardFastifyPlugin = wardFastifyPluginImpl;
export default wardFastifyPlugin;
