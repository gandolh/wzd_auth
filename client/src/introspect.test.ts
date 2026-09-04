import { afterEach, beforeEach, describe, expect, it } from "vitest";

import { createIntrospector } from "./introspect.js";
import { WardUnavailableError } from "./errors.js";
import { startFakeWard, type FakeWard } from "./testing/fakeWard.js";

/**
 * The 30-second cache and the stampede collapse are the two properties this
 * brief calls out as the acceptance tests that matter, and both are tested
 * against a real local HTTP server (`startFakeWard`) rather than a mocked
 * `fetch`, so the request-counting is honest.
 *
 * **Clock:** `createIntrospector` takes an injectable `now` rather than
 * relying on `vi.useFakeTimers()` here. Vitest's global fake timers patch
 * `setTimeout` process-wide, which is exactly what Node's real `fetch`
 * (undici) needs for its own socket handling — mixing the two is a well-known
 * way to hang a test that makes a genuine network call. A manually advanced
 * logical clock gets the same "timed, not slept" property with none of that
 * risk, and it is the same seam a consumer never needs (real time) but a test
 * does.
 */

let ward: FakeWard;

beforeEach(async () => {
  ward = await startFakeWard();
});

afterEach(async () => {
  await ward.close();
});

/** A clock a test can advance by hand, with no real timer involved. */
function fakeClock(startMs = 1_700_000_000_000): {
  now: () => number;
  advance: (ms: number) => void;
} {
  let current = startMs;
  return {
    now: () => current,
    advance: (ms: number) => {
      current += ms;
    },
  };
}

describe("createIntrospector — the 30-second cache", () => {
  it("returns the same answer for 30 seconds, then re-asks Ward", async () => {
    ward.setSession("family_1", {
      active: true,
      subject: "sub_alice",
      username: "alice",
      grants: { atrium: ["member"] },
    });
    const token = await ward.mintToken({ subject: "sub_alice", sessionId: "family_1" });

    const clock = fakeClock();
    const introspect = createIntrospector({
      introspectUrl: ward.introspectEndpoint,
      now: clock.now,
    });

    const first = await introspect(token);
    expect(first).toEqual({
      active: true,
      subject: "sub_alice",
      username: "alice",
      grants: { atrium: ["member"] },
    });
    expect(ward.introspectCallCount).toBe(1);

    // Still within the window: cached, no new call, even though the session
    // has since been revoked underneath it.
    ward.setSession("family_1", undefined);
    clock.advance(29_000);
    const stillCached = await introspect(token);
    expect(stillCached.active).toBe(true);
    expect(ward.introspectCallCount).toBe(1);
  });

  it("a revoked session stops being accepted within the 30-second window — timed, not slept", async () => {
    ward.setSession("family_1", {
      active: true,
      subject: "sub_alice",
      username: "alice",
      grants: { atrium: ["member"] },
    });
    const token = await ward.mintToken({ subject: "sub_alice", sessionId: "family_1" });
    const clock = fakeClock();
    const introspect = createIntrospector({
      introspectUrl: ward.introspectEndpoint,
      now: clock.now,
    });

    const first = await introspect(token);
    expect(first.active).toBe(true);
    expect(ward.introspectCallCount).toBe(1);

    // The session is revoked — the shape a "sign out" or "disable account"
    // takes underneath the client, which has no way to know synchronously.
    ward.setSession("family_1", undefined);

    // Cross the 30-second boundary on the logical clock. No sleep, no
    // real timer — just the injected `now` advancing past the TTL.
    clock.advance(30_001);

    const afterWindow = await introspect(token);
    expect(afterWindow).toEqual({ active: false });
    expect(ward.introspectCallCount).toBe(2);
  });

  it("two different tokens never share a cache entry", async () => {
    ward.setSession("family_1", {
      active: true,
      subject: "sub_alice",
      username: "alice",
      grants: {},
    });
    ward.setSession("family_2", {
      active: true,
      subject: "sub_bob",
      username: "bob",
      grants: { atrium: ["admin"] },
    });
    const tokenA = await ward.mintToken({ subject: "sub_alice", sessionId: "family_1" });
    const tokenB = await ward.mintToken({ subject: "sub_bob", sessionId: "family_2" });

    const introspect = createIntrospector({ introspectUrl: ward.introspectEndpoint });

    const resultA = await introspect(tokenA);
    const resultB = await introspect(tokenB);

    expect(resultA).toMatchObject({ subject: "sub_alice" });
    expect(resultB).toMatchObject({ subject: "sub_bob" });
    expect(ward.introspectCallCount).toBe(2);
  });
});

describe("createIntrospector — stampede collapse", () => {
  it("fifty concurrent requests on one cold token produce exactly one introspection call", async () => {
    ward.setSession("family_1", {
      active: true,
      subject: "sub_alice",
      username: "alice",
      grants: { atrium: ["member"] },
    });
    const token = await ward.mintToken({ subject: "sub_alice", sessionId: "family_1" });
    const introspect = createIntrospector({ introspectUrl: ward.introspectEndpoint });

    const results = await Promise.all(Array.from({ length: 50 }, () => introspect(token)));

    expect(ward.introspectCallCount).toBe(1);
    for (const result of results) {
      expect(result).toEqual({
        active: true,
        subject: "sub_alice",
        username: "alice",
        grants: { atrium: ["member"] },
      });
    }
  });
});

describe("createIntrospector — fail closed", () => {
  it("throws WardUnavailableError, not {active:false}, on a 500 from Ward", async () => {
    ward.forceIntrospectStatus(500);
    const introspect = createIntrospector({ introspectUrl: ward.introspectEndpoint });

    await expect(introspect("irrelevant-token")).rejects.toBeInstanceOf(WardUnavailableError);
  });

  it("throws WardUnavailableError when Ward is unreachable (connection refused)", async () => {
    const deadUrl = ward.introspectEndpoint;
    await ward.close();

    const introspect = createIntrospector({ introspectUrl: deadUrl, timeoutMs: 500 });

    await expect(introspect("irrelevant-token")).rejects.toBeInstanceOf(WardUnavailableError);

    // Prevent the shared afterEach from trying to close an already-closed
    // server.
    ward = await startFakeWard();
  });

  it("does not fall back to an expired cache entry when Ward is down", async () => {
    ward.setSession("family_1", {
      active: true,
      subject: "sub_alice",
      username: "alice",
      grants: {},
    });
    const token = await ward.mintToken({ subject: "sub_alice", sessionId: "family_1" });
    const clock = fakeClock();
    const introspect = createIntrospector({
      introspectUrl: ward.introspectEndpoint,
      now: clock.now,
    });

    const first = await introspect(token);
    expect(first.active).toBe(true);

    clock.advance(30_001);
    ward.forceIntrospectStatus(500);

    // The cache entry has expired and the only way to answer is a call that
    // fails — this must reject, never resolve with the stale "active: true"
    // it cached thirty seconds ago.
    await expect(introspect(token)).rejects.toBeInstanceOf(WardUnavailableError);
  });
});
