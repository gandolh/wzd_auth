import { describe, expect, it } from "vitest";

import {
  DUMMY_STORED_HASH,
  MAX_PASSWORD_LENGTH,
  MIN_PASSWORD_LENGTH,
  PasswordPolicyError,
  hashPassword,
  spendDummyHash,
  verifyPassword,
} from "./password.js";

/**
 * The password primitive. Nothing here needs an environment or a database —
 * `password.ts` imports only `node:crypto`, which is what lets brief 07 use it
 * from a registration route without dragging config validation along.
 */

describe("hashPassword", () => {
  it("stores saltHex:hashHex and nothing else", async () => {
    const stored = await hashPassword("correct horse battery");

    const parts = stored.split(":");
    expect(parts).toHaveLength(2);
    // 16-byte salt, 64-byte digest, both hex.
    expect(parts[0]).toMatch(/^[0-9a-f]{32}$/);
    expect(parts[1]).toMatch(/^[0-9a-f]{128}$/);
  });

  it("salts per password, so the same password hashes to two different values", async () => {
    const a = await hashPassword("correct horse battery");
    const b = await hashPassword("correct horse battery");

    expect(a).not.toBe(b);
    // Different salts, therefore different digests — one precomputed table
    // cannot attack two accounts at once.
    expect(a.split(":")[0]).not.toBe(b.split(":")[0]);
    expect(a.split(":")[1]).not.toBe(b.split(":")[1]);

    // Both still verify.
    expect(await verifyPassword("correct horse battery", a)).toBe(true);
    expect(await verifyPassword("correct horse battery", b)).toBe(true);
  });

  it("refuses a password shorter than the minimum", async () => {
    const short = "a".repeat(MIN_PASSWORD_LENGTH - 1);

    await expect(hashPassword(short)).rejects.toThrow(PasswordPolicyError);
    await expect(hashPassword(short)).rejects.toMatchObject({ code: "password_too_short" });
  });

  it("accepts exactly the minimum length", async () => {
    const stored = await hashPassword("a".repeat(MIN_PASSWORD_LENGTH));
    expect(await verifyPassword("a".repeat(MIN_PASSWORD_LENGTH), stored)).toBe(true);
  });

  it("refuses an absurdly long password rather than hashing it", async () => {
    await expect(hashPassword("a".repeat(MAX_PASSWORD_LENGTH + 1))).rejects.toMatchObject({
      code: "password_too_long",
    });
  });
});

describe("verifyPassword", () => {
  it("accepts the right password and rejects a wrong one", async () => {
    const stored = await hashPassword("hunter2hunter2");

    expect(await verifyPassword("hunter2hunter2", stored)).toBe(true);
    expect(await verifyPassword("hunter2hunter3", stored)).toBe(false);
    expect(await verifyPassword("", stored)).toBe(false);
  });

  it("is case- and whitespace-sensitive", async () => {
    const stored = await hashPassword("Hunter Two");

    expect(await verifyPassword("hunter two", stored)).toBe(false);
    expect(await verifyPassword("Hunter Two ", stored)).toBe(false);
    expect(await verifyPassword("Hunter Two", stored)).toBe(true);
  });

  it("rejects rather than throws on a stored value it did not produce", async () => {
    // `db/test-support.ts` seeds exactly this shape, and a hand-edited row or a
    // future versioned format would be others. None of them may throw: a login
    // route wants an answer, not an exception it then has to keep out of a log.
    for (const junk of [
      "scrypt$not-a-real-hash$alice",
      "",
      ":",
      "deadbeef",
      "deadbeef:",
      ":deadbeef",
      "deadbeef:deadbeef:deadbeef",
      "zz:zz",
      "deadbeef:notevenhex",
    ]) {
      expect(await verifyPassword("anything at all", junk)).toBe(false);
    }
  });

  it("does NOT accept every password when the stored value parses to empty buffers", async () => {
    // The regression this guards: `Buffer.from("z", "hex")` is an empty buffer,
    // and `timingSafeEqual(empty, empty)` returns **true**. Without the
    // round-trip length check in `parseStored`, a stored value of `"z:z"` would
    // make every password on that account correct.
    expect(await verifyPassword("literally anything", "z:z")).toBe(false);
    expect(await verifyPassword("", "z:z")).toBe(false);
  });

  it("rejects a digest of the wrong length", async () => {
    const stored = await hashPassword("hunter2hunter2");
    const [salt, hash] = stored.split(":") as [string, string];

    // Truncated digest — the right salt, the right prefix, the wrong length.
    expect(await verifyPassword("hunter2hunter2", `${salt}:${hash.slice(0, 64)}`)).toBe(false);
  });
});

describe("spendDummyHash", () => {
  it("always returns false", async () => {
    expect(await spendDummyHash("anything")).toBe(false);
    expect(await spendDummyHash("")).toBe(false);
  });

  /**
   * The **structural** half of the enumeration-timing defence, asserted here so
   * that the route-level timing test is a corroboration rather than the only
   * evidence. `DUMMY_STORED_HASH` being a well-formed stored value is what
   * makes `verifyPassword` run the full KDF and then fail the comparison on
   * content rather than bailing out early on a parse failure — the two paths
   * differ only in the digest they compare against.
   */
  it("compares against a well-formed stored value, so the full KDF runs", async () => {
    const parts = DUMMY_STORED_HASH.split(":");
    expect(parts).toHaveLength(2);
    expect(parts[0]).toMatch(/^[0-9a-f]{32}$/);
    expect(parts[1]).toMatch(/^[0-9a-f]{128}$/);

    // Same shape as a real one, so nothing about the comparison is shorter.
    const real = await hashPassword("a real password");
    expect(DUMMY_STORED_HASH.length).toBe(real.length);
  });

  it("costs about as much as a real verification", async () => {
    const stored = await hashPassword("a real password");

    // Warm the KDF so the first-call cost of loading OpenSSL's scrypt does not
    // land inside a measurement.
    await verifyPassword("wrong", stored);
    await spendDummyHash("wrong");

    const realStart = performance.now();
    await verifyPassword("wrong", stored);
    const real = performance.now() - realStart;

    const dummyStart = performance.now();
    await spendDummyHash("wrong");
    const dummy = performance.now() - dummyStart;

    // A one-sided floor rather than a two-sided band: a loaded machine makes
    // both slower, never faster, so this cannot flake upward. A missing dummy
    // hash would be sub-millisecond against a ~40 ms real verify — two orders
    // of magnitude below this bound.
    expect(dummy).toBeGreaterThan(real / 4);
  });
});
