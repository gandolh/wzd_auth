import { describe, expect, it } from "vitest";

import { ESTATE_APPS, ESTATE_ROOTS, appName, rootName } from "./estate.js";

/**
 * The estate registry is data, so the tests are consistency checks rather than
 * behaviour: the two things this file is for have to agree with each other, or
 * a redirect the allowlist accepts renders a heading nobody wrote.
 */
describe("estate", () => {
  it("names every root it allows, so no destination renders as a slug", () => {
    // If a root is an accepted `?next=` target, the login page needs a sentence
    // to put in its heading. A row with a root and no proper name renders
    // "Continue to imbatranim-os".
    for (const app of ESTATE_APPS) {
      if (app.root === null) continue;
      expect(rootName(app.root)).toBe(app.name);
      expect(app.name).not.toBe(app.root);
    }
  });

  it("derives the allowlist from the rows, with no API roots in it", () => {
    expect(ESTATE_ROOTS.size).toBe(ESTATE_APPS.filter((app) => app.root !== null).length);
    // `?next=` puts somebody back where they were, and nobody was reading an
    // API endpoint. An `-api` root in this set would widen the redirect surface
    // to a target no legitimate flow asks for.
    for (const root of ESTATE_ROOTS) expect(root.endsWith("-api")).toBe(false);
  });

  it("has unique slugs and unique roots", () => {
    // A duplicate slug makes `appName` return whichever row came first, which
    // is the sort of bug that shows up as one app wearing another's name.
    expect(new Set(ESTATE_APPS.map((app) => app.slug)).size).toBe(ESTATE_APPS.length);
  });

  it("falls back to the raw slug for an app it has never heard of", () => {
    // The ordinary case, not an edge case: apps are rows an operator creates,
    // so a slug missing from this table is expected. Showing the slug is more
    // use to somebody signing up than "Unknown app".
    expect(appName("some-new-app")).toBe("some-new-app");
    expect(rootName("some-new-app")).toBe("some-new-app");
  });
});
