import type { FastifyInstance } from "fastify";
import { getPublicJwks } from "../tokens/service.js";

/**
 * `GET /.well-known/jwks.json` — the one route the other five apps fetch.
 *
 * ## The private key cannot get out through here
 *
 * The handler closes over a **string** that was serialised once at boot from a
 * key set built out of a public-only `node:crypto` `KeyObject` (see
 * `tokens/keys.ts`). It has no reference to a `WardSigningKey`, no reference to
 * a `KeyObject`, and nothing to filter — there is no code path from this file to
 * private key material to get wrong later. That is deliberate: serving Ward's
 * private key is the single worst outcome available in this brief, and "we are
 * careful about which fields we pick" is not a control, it is an intention.
 *
 * ## Loading at registration is what makes a missing key a boot failure
 *
 * `getPublicJwks()` is awaited here, during `buildApp()`, which brief 00 places
 * after migrations and before `listen()` — the outcome note names "loading the
 * signing key, warming JWKS" as exactly what belongs at that point. So a
 * missing, unreadable or wrong-type key file rejects here, `buildApp()` rejects,
 * `index.ts` never binds a port, and pm2 logs a message that names
 * `npm run keygen`. Ward does not start without a key, and it never invents one.
 *
 * Note the consequence for other briefs: a test that calls `buildApp()` needs a
 * signing key on disk. Two lines — `generateSigningKeyFile()` from
 * `tokens/keygen.ts` into a temp directory, with `WARD_SIGNING_KEY_PATH` set
 * before `config.js` is first imported. Cheaper than the alternative, which is
 * a service that boots into a state where nobody can log in.
 */
export async function jwksRoutes(app: FastifyInstance): Promise<void> {
  const jwks = await getPublicJwks();

  // Serialised once. Fastify would otherwise re-serialise the same immutable
  // object on every request, and this endpoint is hit by six apps.
  const body = JSON.stringify(jwks);

  app.log.info(
    { kids: jwks.keys.map((key) => key.kid) },
    "signing keys loaded; JWKS ready to publish",
  );

  app.get("/.well-known/jwks.json", async (_request, reply) => {
    /**
     * Cacheable, but not for long.
     *
     * Five minutes is the compromise between the two failure modes. Too short
     * and six apps refetch constantly for a document that changes about once a
     * year. Too long and a rotation takes hours to propagate — and while the
     * two-key JWKS means a slow-to-refresh app keeps *verifying* fine, it also
     * means an app that has never seen the new `kid` rejects every fresh token
     * until its cache turns over. `@ward/client` (brief 08) refetches on an
     * unknown `kid` anyway, so this is the backstop rather than the mechanism.
     *
     * `public` is correct and intended: this is a public key. Nothing here is
     * per-user, so a shared cache holding it is fine.
     */
    reply.header("cache-control", "public, max-age=300");
    // RFC 7517's registered media type. `jose`'s remote key set sends
    // `Accept: application/json, application/jwk-set+json`, and so does every
    // other JWKS client worth supporting.
    reply.type("application/jwk-set+json");
    return body;
  });
}
