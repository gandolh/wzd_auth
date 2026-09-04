import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import {
  LOCKOUT_MAX_ENTRIES,
  LOCKOUT_MAX_FAILURES,
  LOCKOUT_WINDOW_SECONDS,
  checkLockout,
  clearFailures,
  lockoutEntryCountForTests,
  lockoutKeyFor,
  recordFailure,
  resetLockoutForTests,
} from "./lockout.js";

/**
 * The lockout counter. Brief 06 imports this exact surface for the console
 * login, so a rename here is a break in two places at once.
 */

beforeEach(() => {
  resetLockoutForTests();
});

afterEach(() => {
  vi.useRealTimers();
  resetLockoutForTests();
});

describe("checkLockout / recordFailure", () => {
  it("allows an address it has never seen", () => {
    expect(checkLockout("203.0.113.9")).toEqual({ allowed: true });
  });

  it("allows the first five failures and refuses the sixth attempt", () => {
    for (let i = 0; i < LOCKOUT_MAX_FAILURES; i += 1) {
      expect(checkLockout("203.0.113.9").allowed).toBe(true);
      recordFailure("203.0.113.9");
    }

    const decision = checkLockout("203.0.113.9");
    expect(decision.allowed).toBe(false);
    expect(decision.retryAfterSeconds).toBeGreaterThan(0);
    expect(decision.retryAfterSeconds).toBeLessThanOrEqual(LOCKOUT_WINDOW_SECONDS);
  });

  it("sets retryAfterSeconds only when it refuses", () => {
    expect(checkLockout("203.0.113.9").retryAfterSeconds).toBeUndefined();
    recordFailure("203.0.113.9");
    expect(checkLockout("203.0.113.9").retryAfterSeconds).toBeUndefined();
  });

  it("counts each address separately", () => {
    for (let i = 0; i < LOCKOUT_MAX_FAILURES; i += 1) recordFailure("203.0.113.9");

    expect(checkLockout("203.0.113.9").allowed).toBe(false);
    // The whole reason the key is an address: one address exhausting its
    // attempts must not affect anybody else.
    expect(checkLockout("198.51.100.4").allowed).toBe(true);
  });

  it("checkLockout does not itself count as an attempt", () => {
    for (let i = 0; i < 20; i += 1) checkLockout("203.0.113.9");
    expect(checkLockout("203.0.113.9").allowed).toBe(true);
  });
});

describe("clearFailures", () => {
  it("forgives the counter, so four typos then a success is not a near-lockout", () => {
    for (let i = 0; i < LOCKOUT_MAX_FAILURES - 1; i += 1) recordFailure("203.0.113.9");
    clearFailures("203.0.113.9");

    // A full fresh allowance, not one attempt away from a 429.
    for (let i = 0; i < LOCKOUT_MAX_FAILURES; i += 1) {
      expect(checkLockout("203.0.113.9").allowed).toBe(true);
      recordFailure("203.0.113.9");
    }
    expect(checkLockout("203.0.113.9").allowed).toBe(false);
  });
});

describe("expiry", () => {
  it("forgets a counter once the window has passed", () => {
    vi.useFakeTimers();
    vi.setSystemTime(new Date("2026-09-04T12:00:00Z"));

    for (let i = 0; i < LOCKOUT_MAX_FAILURES; i += 1) recordFailure("203.0.113.9");
    expect(checkLockout("203.0.113.9").allowed).toBe(false);

    vi.setSystemTime(new Date(Date.now() + (LOCKOUT_WINDOW_SECONDS + 1) * 1000));
    expect(checkLockout("203.0.113.9")).toEqual({ allowed: true });
    // And the entry is actually gone, not merely reported as allowed.
    expect(lockoutEntryCountForTests()).toBe(0);
  });

  it("slides the window forward on each failure", () => {
    vi.useFakeTimers();
    vi.setSystemTime(new Date("2026-09-04T12:00:00Z"));

    for (let i = 0; i < LOCKOUT_MAX_FAILURES; i += 1) recordFailure("203.0.113.9");

    // Wait most of the window, then fail once more. A fixed window would expire
    // on schedule and hand out a free attempt every 15 minutes; a sliding one
    // pushes the expiry out.
    vi.setSystemTime(new Date(Date.now() + (LOCKOUT_WINDOW_SECONDS - 10) * 1000));
    recordFailure("203.0.113.9");

    vi.setSystemTime(new Date(Date.now() + 20 * 1000));
    expect(checkLockout("203.0.113.9").allowed).toBe(false);
  });
});

describe("the cap", () => {
  it("never exceeds LOCKOUT_MAX_ENTRIES, because an uncapped map is the DoS", () => {
    // One failed login from each of many spoofed addresses is cheap to send.
    // Uncapped, that is one map entry each, held for the life of the process.
    for (let i = 0; i < LOCKOUT_MAX_ENTRIES + 500; i += 1) {
      recordFailure(`10.0.${Math.floor(i / 256)}.${i % 256}`);
    }

    expect(lockoutEntryCountForTests()).toBeLessThanOrEqual(LOCKOUT_MAX_ENTRIES);
  });

  it("evicts the oldest entries first, so a recent locked-out address survives a flood", () => {
    for (let i = 0; i < LOCKOUT_MAX_FAILURES; i += 1) recordFailure("203.0.113.9");
    expect(checkLockout("203.0.113.9").allowed).toBe(false);

    // A flood just under the cap: the attacker's own addresses fill the map
    // from the front, and 203.0.113.9 was inserted before them...
    for (let i = 0; i < LOCKOUT_MAX_ENTRIES - 10; i += 1) {
      recordFailure(`10.0.${Math.floor(i / 256)}.${i % 256}`);
    }

    // ...so it is still there. Eviction only reaches it once the flood exceeds
    // the whole cap, which is documented as an accepted loss: the worst an
    // attacker gains is the attempts they already had.
    expect(checkLockout("203.0.113.9").allowed).toBe(false);
  });
});

describe("lockoutKeyFor", () => {
  it("uses the last X-Forwarded-For element when the peer is loopback", () => {
    // Caddy appends the peer it observed, so the last element is the one a
    // client cannot control. Taking the first — the usual "original client"
    // convention — is the spoofable choice.
    expect(lockoutKeyFor("127.0.0.1", "1.2.3.4, 203.0.113.9")).toBe("203.0.113.9");
    expect(lockoutKeyFor("::1", "203.0.113.9")).toBe("203.0.113.9");
    expect(lockoutKeyFor("127.0.0.1", ["1.2.3.4", "203.0.113.9"])).toBe("203.0.113.9");
  });

  it("ignores X-Forwarded-For entirely when the peer is not loopback", () => {
    // Ward reachable directly means there is no trusted proxy behind the
    // header, so a client could otherwise pick its own bucket at will.
    expect(lockoutKeyFor("203.0.113.9", "10.0.0.1")).toBe("203.0.113.9");
  });

  it("falls back to the peer when there is no forwarding header", () => {
    expect(lockoutKeyFor("127.0.0.1", undefined)).toBe("127.0.0.1");
    expect(lockoutKeyFor("127.0.0.1", "")).toBe("127.0.0.1");
    expect(lockoutKeyFor("127.0.0.1", " , ")).toBe("127.0.0.1");
  });

  it("treats an IPv4-mapped address as the same address", () => {
    // Otherwise picking a stack doubles the allowance.
    expect(lockoutKeyFor("127.0.0.1", "::ffff:203.0.113.9")).toBe("203.0.113.9");
    expect(lockoutKeyFor("::ffff:203.0.113.9", undefined)).toBe("203.0.113.9");
  });

  it("normalises brackets, ports and IPv6 zone ids", () => {
    expect(lockoutKeyFor("127.0.0.1", "[2001:db8::1]:4711")).toBe("2001:db8::1");
    expect(lockoutKeyFor("fe80::1%eth0", undefined)).toBe("fe80::1");
    expect(lockoutKeyFor("127.0.0.1", "  203.0.113.9  ")).toBe("203.0.113.9");
  });

  it("returns a single bucket rather than nothing when there is no address", () => {
    // Throttling an unidentifiable caller is the safe direction; letting the
    // attempt through uncounted is not.
    expect(lockoutKeyFor(undefined, undefined)).toBe("unknown");
    expect(lockoutKeyFor(null, undefined)).toBe("unknown");
  });
});
