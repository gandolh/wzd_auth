import { describe, expect, it } from "vitest";

import { readAccessCookie } from "./cookie.js";

describe("readAccessCookie", () => {
  it("reads ward_session out of a Cookie header among others", () => {
    expect(readAccessCookie("foo=bar; ward_session=abc.def.ghi; other=1")).toBe("abc.def.ghi");
  });

  it("returns undefined when the header is absent", () => {
    expect(readAccessCookie(undefined)).toBeUndefined();
  });

  it("returns undefined when ward_session is not present", () => {
    expect(readAccessCookie("foo=bar; other=1")).toBeUndefined();
  });

  it("treats an empty value as absent, not as an empty token", () => {
    expect(readAccessCookie("ward_session=; other=1")).toBeUndefined();
  });

  it("never returns the refresh cookie for the access token", () => {
    expect(readAccessCookie("ward_refresh=should-not-be-returned")).toBeUndefined();
  });

  it("handles the header arriving as an array of lines", () => {
    expect(readAccessCookie(["foo=bar", "ward_session=xyz"])).toBe("xyz");
  });
});
