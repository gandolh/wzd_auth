import { describe, expect, it } from "vitest";

import { formatWait } from "./wait.js";

/**
 * The lockout is the one login failure with a concrete next step, and the step
 * is "wait this long". Brief 09 exists partly because six apps each rendered
 * this differently, so the string is worth pinning.
 */
describe("formatWait", () => {
  const rows: ReadonlyArray<[number, string]> = [
    [0, "0 s"],
    [1, "1 s"],
    [59, "59 s"],
    [60, "1 min"],
    [61, "1 min 1 s"],
    [95, "1 min 35 s"],
    [120, "2 min"],
    [299, "4 min 59 s"],
    [300, "5 min"],
    // A fraction rounds up: telling somebody 4 seconds when 4.2 remain leaves
    // the button disabled after the number reaches zero, which reads as broken.
    [4.2, "5 s"],
    [59.1, "1 min"],
    // Never a negative wait. A clock skew between the API's `Retry-After` and
    // the browser is enough to produce one.
    [-1, "0 s"],
    [-3600, "0 s"],
  ];

  for (const [seconds, expected] of rows) {
    it(`${String(seconds)} → ${expected}`, () => {
      expect(formatWait(seconds)).toBe(expected);
    });
  }
});
