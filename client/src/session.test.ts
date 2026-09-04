import { describe, expect, it } from "vitest";

import { hasGrant, type GrantsByApp } from "./session.js";

describe("hasGrant", () => {
  const grants: GrantsByApp = {
    atrium: ["member", "moderator"],
    newspapper: ["editor"],
  };

  it("is true when the role is held for that app", () => {
    expect(hasGrant(grants, "atrium", "member")).toBe(true);
    expect(hasGrant(grants, "atrium", "moderator")).toBe(true);
  });

  it("refuses a role the person does not hold — the test that matters", () => {
    expect(hasGrant(grants, "atrium", "admin")).toBe(false);
  });

  it("is false for an app absent from the map entirely — no access, not 'unknown'", () => {
    expect(hasGrant(grants, "prm", "anything")).toBe(false);
  });

  it("tests set membership, not array equality or ordering", () => {
    // A person can hold several roles in one app; a naive `grants[app][0] ===
    // role` check would silently refuse everyone but the first-listed role.
    expect(hasGrant(grants, "atrium", "moderator")).toBe(true);
  });
});
