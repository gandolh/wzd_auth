/**
 * The console's pure logic: path parsing, the audit classification, the grant
 * set, and formatting.
 *
 * No DOM is configured for Vitest in this repo, so the components themselves
 * are not rendered here. Everything a component could get *wrong* has been
 * pushed out into these four modules for that reason — most of all the
 * benign-versus-alarm distinction on refresh tokens, which is the single
 * judgement the audit screen exists to make.
 */

import { describe, expect, it } from "vitest";

import { AUDIT_ACTION_GROUPS, parseGrantTarget, presentAuditAction } from "./audit-actions.js";
import { consoleHref, parseConsoleLocation, railSectionFor } from "./nav.js";
import {
  appsWithoutGrants,
  describeGrantRevoke,
  describeGrantWrite,
  groupGrantsByApp,
  roleSuggestions,
} from "./grant-set.js";
import { formatDetail, formatRemaining, formatWhen, plural, sessionRemaining } from "./format.js";
import type { GrantView } from "../../console-api.js";

/* ==========================================================================
 * The distinction the audit screen exists for
 * ======================================================================= */

describe("a raced refresh is not a stolen cookie", () => {
  it("marks session.reuse_detected as the alarm and nothing else", () => {
    const alarms = AUDIT_ACTION_GROUPS.flatMap((group) => group.actions).filter(
      (action) => presentAuditAction(action).isAlarm,
    );
    expect(alarms).toEqual(["session.reuse_detected"]);
  });

  it("presents reuse as an alarm with the family revoked", () => {
    const presented = presentAuditAction("session.reuse_detected");
    expect(presented.severity).toBe("alarm");
    expect(presented.isAlarm).toBe(true);
    expect(presented.explanation).toContain("stolen-cookie");
  });

  it("presents a race as benign and says so in words", () => {
    const presented = presentAuditAction("session.refresh_raced");
    expect(presented.severity).toBe("benign");
    expect(presented.isAlarm).toBe(false);
    // An operator who reads this row should stop looking.
    expect(presented.explanation).toContain("not a theft signal");
  });

  it("gives the two of them different severities and different labels", () => {
    const raced = presentAuditAction("session.refresh_raced");
    const reuse = presentAuditAction("session.reuse_detected");
    expect(raced.severity).not.toBe(reuse.severity);
    expect(raced.label).not.toBe(reuse.label);
  });
});

describe("the audit vocabulary", () => {
  it("treats app.registration as a notice, because it is the only public opening", () => {
    expect(presentAuditAction("app.registration").severity).toBe("notice");
  });

  it("treats grant writes as changes of authority", () => {
    for (const action of ["grant.create", "grant.revoke", "grant.revoke_app"]) {
      expect(presentAuditAction(action).severity).toBe("authority");
    }
  });

  it("keeps an unrecognised action visible rather than hiding or throwing", () => {
    // The log is append-only and outlives the vocabulary that wrote it.
    const presented = presentAuditAction("something.invented.in.2028");
    expect(presented.label).toBe("something.invented.in.2028");
    expect(presented.severity).toBe("benign");
  });

  it("classifies every action it offers as a filter", () => {
    for (const group of AUDIT_ACTION_GROUPS) {
      for (const action of group.actions) {
        // A filter option whose label is the raw action means the vocabulary
        // and the picker have drifted apart.
        expect(presentAuditAction(action).label).not.toBe(action);
      }
    }
  });
});

describe("a grant target id is percent-encoded, not colon-split", () => {
  it("decodes the three parts", () => {
    const encoded = ["u_1", "prm", "admin"].map(encodeURIComponent).join(":");
    expect(parseGrantTarget(encoded)).toEqual({ subject: "u_1", appSlug: "prm", role: "admin" });
  });

  it("round-trips a role containing a colon, which is why the encoding exists", () => {
    const role = "resource:write";
    const encoded = ["u_1", "prm", role].map(encodeURIComponent).join(":");
    expect(parseGrantTarget(encoded)?.role).toBe(role);
  });

  it("refuses a malformed id rather than rendering a wrong triple", () => {
    expect(parseGrantTarget("only:two")).toBeUndefined();
    expect(parseGrantTarget("a:b:%zz")).toBeUndefined();
  });
});

/* ==========================================================================
 * Where in the console we are
 * ======================================================================= */

describe("parseConsoleLocation", () => {
  it("finds the mount prefix whether or not the /ward base is in the path", () => {
    expect(parseConsoleLocation("/console/apps").basePath).toBe("/console");
    expect(parseConsoleLocation("/ward/console/apps").basePath).toBe("/ward/console");
  });

  it("treats the bare console path as the accounts index", () => {
    expect(parseConsoleLocation("/console").view).toEqual({ kind: "accounts" });
    expect(parseConsoleLocation("/console/").view).toEqual({ kind: "accounts" });
  });

  it("reads a subject and a slug out of a detail path", () => {
    expect(parseConsoleLocation("/console/accounts/u_1").view).toEqual({
      kind: "account",
      subject: "u_1",
    });
    expect(parseConsoleLocation("/ward/console/apps/prm").view).toEqual({
      kind: "app",
      slug: "prm",
    });
  });

  it("decodes an escaped subject", () => {
    expect(parseConsoleLocation("/console/accounts/weird%2Fsubject").view).toEqual({
      kind: "account",
      subject: "weird/subject",
    });
  });

  it("names an unknown path rather than rendering a blank screen", () => {
    expect(parseConsoleLocation("/console/nope/deeper").view).toEqual({
      kind: "unknown",
      rest: ["nope", "deeper"],
    });
  });

  it("still renders the index if the parent mounted it somewhere unexpected", () => {
    // The parent router decided this URL belongs to the console; refusing to
    // render would turn a mounting choice we do not control into a blank page.
    expect(parseConsoleLocation("/").view).toEqual({ kind: "accounts" });
  });

  it("round-trips every view through consoleHref", () => {
    const base = "/ward/console";
    for (const view of [
      { kind: "accounts" } as const,
      { kind: "apps" } as const,
      { kind: "audit" } as const,
      { kind: "account", subject: "u_1" } as const,
      { kind: "app", slug: "prm" } as const,
    ]) {
      const parsed = parseConsoleLocation(consoleHref(base, view));
      expect(parsed.basePath).toBe(base);
      expect(parsed.view).toEqual(view);
    }
  });

  it("puts a detail page under its own rail section", () => {
    expect(railSectionFor({ kind: "account", subject: "u_1" })).toBe("accounts");
    expect(railSectionFor({ kind: "app", slug: "prm" })).toBe("apps");
    expect(railSectionFor({ kind: "unknown", rest: [] })).toBeNull();
  });
});

/* ==========================================================================
 * Grants as a set
 * ======================================================================= */

function grant(appSlug: string, role: string, at = "2026-09-04T10:00:00.000Z"): GrantView {
  return { subject: "u_1", appSlug, role, grantedAt: at, grantedBy: "superuser" };
}

describe("groupGrantsByApp", () => {
  it("collapses a flat list into one row per app with the roles as a set", () => {
    const grouped = groupGrantsByApp([
      grant("prm", "reader"),
      grant("atrium", "admin"),
      grant("prm", "admin"),
    ]);
    expect(grouped.map((entry) => entry.appSlug)).toEqual(["atrium", "prm"]);
    expect(grouped[1]?.roles).toEqual(["admin", "reader"]);
  });

  it("returns an empty list for an account with no grants, not a placeholder row", () => {
    // The console renders this as a designed empty state; a fake row would be
    // indistinguishable from real access.
    expect(groupGrantsByApp([])).toEqual([]);
  });

  it("orders opaque identifiers without a collator", () => {
    const grouped = groupGrantsByApp([grant("b", "x"), grant("A", "y")]);
    // Byte order: an uppercase slug sorts before a lowercase one. Deliberate —
    // these are identifiers, not words in a language.
    expect(grouped.map((entry) => entry.appSlug)).toEqual(["A", "b"]);
  });
});

describe("roleSuggestions", () => {
  it("offers the roles already in use, most-used first", () => {
    const suggestions = roleSuggestions([
      grant("prm", "admin"),
      grant("atrium", "admin"),
      grant("atrium", "reader"),
    ]);
    expect(suggestions).toEqual(["admin", "reader"]);
  });

  it("is a suggestion list and not a constraint, so it can be empty", () => {
    expect(roleSuggestions([])).toEqual([]);
  });
});

describe("appsWithoutGrants", () => {
  it("keeps the registry's own order rather than re-sorting", () => {
    expect(appsWithoutGrants(["atrium", "prm", "newspapper"], [grant("prm", "admin")])).toEqual([
      "atrium",
      "newspapper",
    ]);
  });
});

describe("a no-op is reported as a no-op", () => {
  it("does not dress a duplicate grant as a success", () => {
    const message = describeGrantWrite("admin", "prm", false);
    expect(message).toContain("already held");
    // The API writes no audit row for a no-op; the UI must not imply one.
    expect(message).toContain("no audit row");
  });

  it("names what was granted when something did change", () => {
    expect(describeGrantWrite("admin", "prm", true)).toBe("Granted admin in prm.");
  });

  it("says nothing changed when a revoke removed nothing", () => {
    expect(describeGrantRevoke("prm", 0, [])).toContain("No roles held");
  });

  it("names the role that went, so it can be put back verbatim", () => {
    expect(describeGrantRevoke("prm", 1, ["resource:write"])).toBe(
      "Revoked resource:write in prm.",
    );
  });

  it("lists every role a wider revoke took", () => {
    expect(describeGrantRevoke("prm", 2, ["admin", "reader"])).toContain("admin, reader");
  });
});

/* ==========================================================================
 * Formatting
 * ======================================================================= */

describe("formatting never throws and never over-promises", () => {
  it("returns the raw value for an unparseable timestamp", () => {
    expect(formatWhen("not a date")).toBe("not a date");
  });

  it("formats a real timestamp as local wall-clock", () => {
    const formatted = formatWhen("2026-09-04T10:00:00.000Z");
    expect(formatted).toMatch(/^\d{4}-\d{2}-\d{2} \d{2}:\d{2}$/);
  });

  it("rounds a countdown down, so it never promises time the server will not honour", () => {
    expect(formatRemaining(119)).toBe("1 min");
    expect(formatRemaining(59)).toBe("59 sec");
    expect(formatRemaining(0)).toBe("expired");
    expect(formatRemaining(-5)).toBe("expired");
    expect(formatRemaining(3720)).toBe("1 h 2 min");
  });

  it("reports the nearer of the two session deadlines", () => {
    const now = Date.parse("2026-09-04T10:00:00.000Z");
    // Idle window has 15 minutes left, but the absolute ceiling is 2 away.
    const remaining = sessionRemaining(
      {
        idleExpiresAt: "2026-09-04T10:15:00.000Z",
        absoluteExpiresAt: "2026-09-04T10:02:00.000Z",
      },
      now,
    );
    expect(remaining.seconds).toBe(120);
    expect(remaining.low).toBe(true);
  });

  it("flattens a detail object into key=value pairs", () => {
    expect(formatDetail({ username: "cristian", sessionsRevoked: 2 })).toBe(
      "username=cristian  sessionsRevoked=2",
    );
  });

  it("renders a nested detail as JSON rather than [object Object]", () => {
    expect(formatDetail({ changed: { name: { from: "a", to: "b" } } })).toBe(
      'changed={"name":{"from":"a","to":"b"}}',
    );
  });

  it("bounds a runaway detail so it cannot push a row off the screen", () => {
    const long = formatDetail({ note: "x".repeat(500) });
    expect(long.length).toBeLessThanOrEqual(240);
    expect(long.endsWith("…")).toBe(true);
  });

  it("renders an absent detail as nothing at all", () => {
    expect(formatDetail(null)).toBe("");
    expect(formatDetail(undefined)).toBe("");
  });

  it("counts correctly, which matters in a security list", () => {
    expect(plural(0, "grant", "grants")).toBe("0 grants");
    expect(plural(1, "grant", "grants")).toBe("1 grant");
    expect(plural(6, "grant", "grants")).toBe("6 grants");
  });
});
