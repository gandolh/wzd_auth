import { describe, expect, it } from "vitest";

import { onceByKey } from "./once.js";

/**
 * The guard on `GET /verify`'s single-use token.
 *
 * The behaviour being pinned is what `StrictMode` would otherwise break: two
 * invocations in one page load, back to back, against an endpoint where the
 * second one fails *because* the first one succeeded. The endpoint's
 * single-use behaviour is real and was verified over a socket — a replayed
 * token answers `400 invalid_token` — so a page that calls twice reports a
 * working link as broken.
 */
describe("onceByKey", () => {
  it("runs the operation once for a repeated key and shares the result", async () => {
    let calls = 0;
    const spend = onceByKey(async (token: string) => {
      calls += 1;
      // A real single-use endpoint: the second call would fail. Modelled here so
      // the test fails loudly rather than merely counting.
      if (calls > 1) throw new Error("invalid_token");
      return `verified:${token}`;
    });

    const first = await spend("abc");
    const second = await spend("abc");

    expect(calls).toBe(1);
    expect(first).toBe("verified:abc");
    expect(second).toBe(first);
  });

  it("shares one in-flight promise between simultaneous callers", async () => {
    // The StrictMode shape exactly: both effect invocations start before either
    // resolves, so a memo written only on completion would let both through.
    let calls = 0;
    const spend = onceByKey(async (token: string) => {
      calls += 1;
      await Promise.resolve();
      return token.toUpperCase();
    });

    const [a, b] = await Promise.all([spend("t"), spend("t")]);
    expect(calls).toBe(1);
    expect(a).toBe("T");
    expect(b).toBe("T");
  });

  it("memoises a failure, so a spent token is not retried", async () => {
    // Retrying cannot succeed — the token is gone — and a retry would spend
    // another attempt against an endpoint fed by whatever was in a URL bar.
    let calls = 0;
    const spend = onceByKey(async (_token: string) => {
      calls += 1;
      throw new Error("invalid_token");
    });

    await expect(spend("x")).rejects.toThrow("invalid_token");
    await expect(spend("x")).rejects.toThrow("invalid_token");
    expect(calls).toBe(1);
  });

  it("treats a different key as a different operation", async () => {
    // A second, genuinely different link in the same page session must still be
    // spent. Keying on the token rather than on a boolean is what allows that.
    const seen: string[] = [];
    const spend = onceByKey(async (token: string) => {
      seen.push(token);
      return token;
    });

    await spend("one");
    await spend("two");
    await spend("one");

    expect(seen).toEqual(["one", "two"]);
  });
});
