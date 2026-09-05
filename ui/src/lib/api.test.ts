import { describe, expect, it } from "vitest";

import { errorCodeFrom, retryAfterFrom } from "./api.js";

/**
 * The error mapping, which is the part of `api.ts` that has to stay in step
 * with the API and the part with no DOM in it.
 *
 * The property under test is not "codes are copied correctly" — a test cannot
 * check that against a file it does not import. It is that **an unrecognised
 * code becomes `unexpected`** rather than being passed through, because a page
 * that renders whatever string arrived would eventually render
 * `{"error":"SQLITE_CONSTRAINT_UNIQUE"}` at a person.
 */
describe("errorCodeFrom", () => {
  const known = [
    "invalid_request",
    "invalid_credentials",
    "account_disabled",
    "too_many_attempts",
    "invalid_refresh",
    "cross_site",
    "registration_closed",
    "username_taken",
    "password_too_short",
    "password_too_long",
    "expired_token",
    "invalid_token",
    "unauthorized",
  ] as const;

  for (const code of known) {
    it(`passes ${code} through`, () => {
      expect(errorCodeFrom({ error: code })).toBe(code);
    });
  }

  const junk: ReadonlyArray<{ body: unknown; why: string }> = [
    { body: undefined, why: "an empty body — a 502 from a proxy, or a 204" },
    { body: null, why: "a literal null body" },
    { body: {}, why: "an object with no error field" },
    { body: { error: "something_new" }, why: "a code this UI has never heard of" },
    { body: { error: 42 }, why: "a non-string error field" },
    { body: { error: null }, why: "an explicitly null error field" },
    { body: "invalid_credentials", why: "the code as a bare string, not in an object" },
    { body: ["invalid_credentials"], why: "an array" },
    // The prototype-pollution shape, in case a body ever reaches this from
    // somewhere less trusted than Ward.
    { body: { __proto__: { error: "invalid_credentials" } }, why: "an inherited error field" },
  ];

  for (const row of junk) {
    it(`answers unexpected for ${row.why}`, () => {
      expect(errorCodeFrom(row.body)).toBe("unexpected");
    });
  }
});

/**
 * `retryAfterSeconds` drives a disabled submit button, so a bad value either
 * unlocks the form immediately or locks it for a week. Both are worse than the
 * API's real ceiling, which is minutes.
 */
describe("retryAfterFrom", () => {
  const rows: ReadonlyArray<{ body: unknown; expected: number; why: string }> = [
    { body: { retryAfterSeconds: 42 }, expected: 42, why: "the ordinary case" },
    { body: { retryAfterSeconds: 1 }, expected: 1, why: "the shortest real wait" },
    { body: { retryAfterSeconds: 0.4 }, expected: 1, why: "a fraction rounds up, never to zero" },
    { body: { retryAfterSeconds: 300 }, expected: 300, why: "five minutes passes through" },
    { body: {}, expected: 1, why: "missing — never unlock on a 429" },
    { body: undefined, expected: 1, why: "no body at all" },
    { body: { retryAfterSeconds: 0 }, expected: 1, why: "zero would unlock immediately" },
    { body: { retryAfterSeconds: -5 }, expected: 1, why: "negative" },
    { body: { retryAfterSeconds: "60" }, expected: 1, why: "a string, not a number" },
    { body: { retryAfterSeconds: Number.NaN }, expected: 1, why: "NaN" },
    {
      body: { retryAfterSeconds: Number.POSITIVE_INFINITY },
      expected: 1,
      why: "Infinity — not finite, so not a wait",
    },
    { body: { retryAfterSeconds: 999_999 }, expected: 3600, why: "clamped to an hour" },
  ];

  for (const row of rows) {
    it(`${JSON.stringify(row.body)} → ${String(row.expected)} (${row.why})`, () => {
      expect(retryAfterFrom(row.body)).toBe(row.expected);
    });
  }
});
