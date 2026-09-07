import { afterEach, beforeEach, describe, expect, it } from "vitest";
import Fastify, { type FastifyInstance } from "fastify";

import { createWardClient } from "./client.js";
import { wardFastifyPlugin } from "./fastify.js";
import { startFakeWard, type FakeWard } from "./testing/fakeWard.js";

/**
 * The app key every client in this file presents. Ward refuses `/introspect`
 * without one, so a fixture that omitted it would be testing a call the real
 * service never answers.
 */
const TEST_APP_KEY = "wak_test_key_for_this_suite";

/**
 * The thin Fastify layer, exercised through `app.inject` (no real socket) —
 * this is what briefs 13/14/15 actually wire up in five of the six apps.
 */

let ward: FakeWard;
let app: FastifyInstance;

beforeEach(async () => {
  ward = await startFakeWard();

  const client = createWardClient({
    publicOrigin: ward.origin,
    apiBasePath: "",
    jwksEndpoint: ward.jwksEndpoint,
    introspectEndpoint: ward.introspectEndpoint,
    appKey: TEST_APP_KEY,
  });

  app = Fastify();
  await app.register(wardFastifyPlugin, { client });

  app.get("/dashboard", { preHandler: app.wardAuthenticate }, async (request) => {
    return request.ward;
  });

  app.get(
    "/admin",
    { preHandler: [app.wardAuthenticate, app.wardRequireGrant("atrium", "admin")] },
    async (request) => {
      return request.ward;
    },
  );

  // Exercises wardRequireGrant running wardAuthenticate itself, for a route
  // that never lists wardAuthenticate explicitly.
  app.get(
    "/admin-solo",
    { preHandler: app.wardRequireGrant("atrium", "admin") },
    async (request) => {
      return request.ward;
    },
  );

  await app.ready();
});

afterEach(async () => {
  await app.close();
  await ward.close().catch(() => undefined);
});

describe("wardFastifyPlugin", () => {
  it("sets request.ward for a live session and lets the route through", async () => {
    ward.setSession("family_1", {
      active: true,
      subject: "sub_alice",
      username: "alice",
      grants: { atrium: ["member"] },
    });
    const token = await ward.mintToken({ subject: "sub_alice", sessionId: "family_1" });

    const response = await app.inject({
      method: "GET",
      url: "/dashboard",
      headers: { cookie: `ward_session=${token}` },
    });

    expect(response.statusCode).toBe(200);
    expect(response.json()).toEqual({
      active: true,
      subject: "sub_alice",
      username: "alice",
      grants: { atrium: ["member"] },
    });
  });

  it("rejects with 401 when there is no cookie", async () => {
    const response = await app.inject({ method: "GET", url: "/dashboard" });
    expect(response.statusCode).toBe(401);
  });

  it("wardRequireGrant refuses a role the person does not hold — the test that matters", async () => {
    ward.setSession("family_1", {
      active: true,
      subject: "sub_alice",
      username: "alice",
      // Holds membership, not admin.
      grants: { atrium: ["member"] },
    });
    const token = await ward.mintToken({ subject: "sub_alice", sessionId: "family_1" });

    const response = await app.inject({
      method: "GET",
      url: "/admin",
      headers: { cookie: `ward_session=${token}` },
    });

    expect(response.statusCode).toBe(403);
  });

  it("wardRequireGrant lets a held role through, running wardAuthenticate itself when needed", async () => {
    ward.setSession("family_1", {
      active: true,
      subject: "sub_alice",
      username: "alice",
      grants: { atrium: ["admin"] },
    });
    const token = await ward.mintToken({ subject: "sub_alice", sessionId: "family_1" });

    const response = await app.inject({
      method: "GET",
      url: "/admin-solo",
      headers: { cookie: `ward_session=${token}` },
    });

    expect(response.statusCode).toBe(200);
    expect(response.json()).toMatchObject({ subject: "sub_alice" });
  });

  it("fails closed — 503, not 200 — when Ward is unreachable", async () => {
    ward.setSession("family_1", {
      active: true,
      subject: "sub_alice",
      username: "alice",
      grants: {},
    });

    // Warm the local JWKS cache first — see client.test.ts's identical
    // comment for why an untouched key store would otherwise make this test
    // pass for the wrong reason (a 401 from failed local verification rather
    // than a 503 from failed introspection).
    const warmToken = await ward.mintToken({ subject: "sub_alice", sessionId: "family_1" });
    const warm = await app.inject({
      method: "GET",
      url: "/dashboard",
      headers: { cookie: `ward_session=${warmToken}` },
    });
    expect(warm.statusCode).toBe(200);

    const coldToken = await ward.mintToken({ subject: "sub_alice", sessionId: "family_2" });

    await ward.close();

    const response = await app.inject({
      method: "GET",
      url: "/dashboard",
      headers: { cookie: `ward_session=${coldToken}` },
    });

    expect(response.statusCode).toBe(503);

    // Prevent the afterEach's `ward.close()` from erroring on an
    // already-closed server; the test's own client is done with it.
    ward = await startFakeWard();
  });
});
