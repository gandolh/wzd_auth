import { afterEach, beforeEach, describe, expect, it } from "vitest";

import { createWardClient, requireGrant } from "./client.js";
import { WardAuthenticationError, WardForbiddenError, WardUnavailableError } from "./errors.js";
import { startFakeWard, type FakeWard } from "./testing/fakeWard.js";

/**
 * The end-to-end surface: cookie in, resolved identity and authority out (or
 * a thrown, typed error). This is what `./fastify` and any other framework
 * layer is built on.
 */

let ward: FakeWard;

beforeEach(async () => {
  ward = await startFakeWard();
});

afterEach(async () => {
  await ward.close();
});

function client(overrides: Partial<Parameters<typeof createWardClient>[0]> = {}) {
  return createWardClient({
    publicOrigin: ward.origin,
    apiBasePath: "",
    jwksEndpoint: ward.jwksEndpoint,
    introspectEndpoint: ward.introspectEndpoint,
    ...overrides,
  });
}

describe("createWardClient — authenticate", () => {
  it("resolves subject, username and grants from a live session's cookie", async () => {
    ward.setSession("family_1", {
      active: true,
      subject: "sub_alice",
      username: "alice",
      grants: { atrium: ["member"] },
    });
    const token = await ward.mintToken({ subject: "sub_alice", sessionId: "family_1" });
    const c = client();

    const session = await c.authenticate(`ward_session=${token}`);

    expect(session).toEqual({
      active: true,
      subject: "sub_alice",
      username: "alice",
      grants: { atrium: ["member"] },
    });
  });

  it("rejects when there is no cookie at all", async () => {
    const c = client();
    await expect(c.authenticate(undefined)).rejects.toBeInstanceOf(WardAuthenticationError);
  });

  it("rejects a syntactically valid but unverifiable token", async () => {
    const c = client();
    await expect(c.authenticate("ward_session=not.a.real.token")).rejects.toBeInstanceOf(
      WardAuthenticationError,
    );
  });

  it("rejects a verified token whose session Ward reports inactive", async () => {
    // No session registered for this family — introspection answers false.
    const token = await ward.mintToken({ subject: "sub_alice", sessionId: "family_ghost" });
    const c = client();

    await expect(c.authenticate(`ward_session=${token}`)).rejects.toBeInstanceOf(
      WardAuthenticationError,
    );
  });

  it("fails closed — rejects rather than allowing — when Ward is unreachable", async () => {
    ward.setSession("family_1", {
      active: true,
      subject: "sub_alice",
      username: "alice",
      grants: {},
    });
    const c = client();

    // Warm the local JWKS cache with one successful call while Ward is still
    // up — otherwise a total outage would make *local verification* fail too
    // (no key to fetch), and this test would pass for the wrong reason (a 401
    // from a bad signature) instead of the one it is actually checking (a
    // live-but-uncached session that cannot be introspected).
    const warmToken = await ward.mintToken({ subject: "sub_alice", sessionId: "family_1" });
    await c.authenticate(`ward_session=${warmToken}`);

    // A second token, signed with the same (now-cached) key, for a session
    // that has never been introspected — so this call cannot be served from
    // this package's own 30-second cache either.
    const coldToken = await ward.mintToken({ subject: "sub_alice", sessionId: "family_2" });

    await ward.close();

    await expect(c.authenticate(`ward_session=${coldToken}`)).rejects.toBeInstanceOf(
      WardUnavailableError,
    );

    // Restore for the shared afterEach.
    ward = await startFakeWard();
  });
});

describe("requireGrant", () => {
  it("passes for a role the person holds", () => {
    expect(() =>
      requireGrant(
        { active: true, subject: "s", username: "u", grants: { atrium: ["admin"] } },
        "atrium",
        "admin",
      ),
    ).not.toThrow();
  });

  it("refuses a role the person does not hold — the test that matters", () => {
    expect(() =>
      requireGrant(
        { active: true, subject: "s", username: "u", grants: { atrium: ["member"] } },
        "atrium",
        "admin",
      ),
    ).toThrow(WardForbiddenError);
  });
});
