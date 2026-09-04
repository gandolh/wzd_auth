import type { FastifyInstance } from "fastify";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterAll, beforeAll, describe, expect, it } from "vitest";

/**
 * `buildApp()`'s error handler.
 *
 * The finding: with no `setErrorHandler`, Fastify's default reply puts
 * `err.message` in the body. Reproduced with a missing signing key and
 * **correct** credentials — a `500` whose body named the absolute on-disk path
 * of the estate's signing key and the shape of the deploy layout, from the one
 * route the whole internet can reach unauthenticated. Any future `SqliteError`
 * would hand out a column name the same way.
 *
 * Every import of `../config.js` and its dependents is dynamic and inside
 * `beforeAll`: `config.ts` validates at import time and calls `process.exit(1)`,
 * so a hoisted static import would take the worker with it.
 */

let dir: string;
let app: FastifyInstance;

/** Stands in for anything that throws with a message worth not publishing. */
const SECRET_MESSAGE = "/srv/ward/secrets/signing-key.pem is unreadable";

beforeAll(async () => {
  dir = await mkdtemp(join(tmpdir(), "ward-app-"));

  process.env["PORT"] = "8797";
  process.env["HOST"] = "127.0.0.1";
  process.env["WARD_DB_PATH"] = join(dir, "unused.db");
  process.env["WARD_ADMIN_USERNAME"] = "test-superuser";
  process.env["WARD_ADMIN_PASSWORD"] = "test-superuser-password";
  process.env["WARD_SIGNING_KEY_PATH"] = join(dir, "signing-key.pem");
  process.env["WARD_PUBLIC_ORIGIN"] = "https://ward.test";

  const config = await import("./config.js");
  const { generateSigningKeyFile } = await import("./tokens/keygen.js");
  // `jwksRoutes` awaits the key set at registration, so `buildApp()` genuinely
  // does not start without one.
  await generateSigningKeyFile(config.WARD_SIGNING_KEY_PATH);

  const { buildApp } = await import("./app.js");
  app = await buildApp();

  // Registered on the root instance, so it inherits the root error handler —
  // which is the thing under test.
  app.get("/test-only-throws", async () => {
    throw new Error(SECRET_MESSAGE);
  });
  await app.ready();
});

afterAll(async () => {
  await app?.close();
  await rm(dir, { recursive: true, force: true });
});

describe("the error handler", () => {
  it("answers a fixed generic body and never the thrown message", async () => {
    const response = await app.inject({ method: "GET", url: "/test-only-throws" });

    expect(response.statusCode).toBe(500);
    expect(response.json()).toEqual({ error: "internal" });

    // The whole point: nothing about this server's filesystem, schema or
    // internals reaches an unauthenticated caller.
    expect(response.body).not.toContain(SECRET_MESSAGE);
    expect(response.body).not.toContain("signing-key");
    expect(response.body).not.toContain(dir);
  });

  it("does not flatten Fastify's own client errors", async () => {
    /**
     * Routes send their own 4xx bodies with `reply.code(...).send(...)` and
     * never reach an error handler at all. What does reach it with a
     * `statusCode` is Fastify's client-error machinery — a `415` here — and
     * those messages describe the request the caller sent rather than this
     * server, so they pass through. Brief 09 renders some of them.
     */
    const response = await app.inject({
      method: "POST",
      url: "/login",
      headers: { "content-type": "application/x-www-form-urlencoded" },
      payload: "username=alice&password=nope",
    });

    expect(response.statusCode).toBe(415);
    expect(response.json()).not.toEqual({ error: "internal" });
    expect(response.json<{ message: string }>().message).toContain("Unsupported Media Type");
  });

  it("leaves a route's own deliberate 4xx exactly as the route wrote it", async () => {
    const response = await app.inject({ method: "POST", url: "/login", payload: {} });

    expect(response.statusCode).toBe(400);
    // The route's body, not the handler's, and not Fastify's client-error shape.
    expect(response.json()).toEqual({ error: "invalid_request" });
  });

  it("still serves the routes it wraps", async () => {
    // A generic error handler that swallowed working responses would be a
    // worse bug than the leak.
    const health = await app.inject({ method: "GET", url: "/health" });
    expect(health.statusCode).toBe(200);

    const jwks = await app.inject({ method: "GET", url: "/.well-known/jwks.json" });
    expect(jwks.statusCode).toBe(200);
    expect(jwks.json<{ keys: unknown[] }>().keys.length).toBeGreaterThan(0);
  });
});
