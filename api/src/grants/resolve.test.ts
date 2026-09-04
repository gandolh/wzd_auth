import { beforeEach, afterEach, describe, expect, it } from "vitest";
import type Database from "better-sqlite3";

import { freshDb, seedApps, seedUser } from "../db/test-support.js";
import { grantRole, SUPERUSER_ACTOR } from "../db/grants.js";
import {
  generateRefreshToken,
  hashRefreshToken,
  insertRefreshToken,
  newFamilyId,
  revokeAllForSubject,
  revokeFamily,
} from "../db/refresh-tokens.js";
import { setDisabled } from "../db/users.js";
import { INACTIVE, hasLiveSession, resolveSession } from "./resolve.js";

/**
 * `resolveSession` — the one code path behind `active`.
 *
 * Static imports throughout: nothing reached from here touches `../config.js`
 * (`openDatabase` is pure and `connection.ts` keeps its config import dynamic),
 * so these run with no environment set at all. `freshDb()` is
 * `openDatabase(":memory:")` plus `runMigrations`, never `getDb()`.
 *
 * The route-level file next door asserts the same properties over HTTP with a
 * real login; these assert them against the database directly, which is where
 * the linkability limitation documented in `resolve.ts` is visible.
 */

let db: Database.Database;
let subject: string;

const FUTURE = "2099-01-01T00:00:00.000Z";
const PAST = "2000-01-01T00:00:00.000Z";

/** A live refresh row for `subject`, in its own family. Returns the family id. */
function login(expiresAt = FUTURE, forSubject = subject): string {
  const familyId = newFamilyId();
  insertRefreshToken(db, {
    tokenHash: hashRefreshToken(generateRefreshToken()),
    subject: forSubject,
    familyId,
    expiresAt,
  });
  return familyId;
}

beforeEach(() => {
  db = freshDb();
  seedApps(db);
  subject = seedUser(db, "Alice", "alice@example.test").subject;
});

afterEach(() => {
  db.close();
});

describe("a live session", () => {
  it("returns active with the identity and the grants, grouped by app", () => {
    login();
    grantRole(db, { subject, appSlug: "atrium", role: "admin", grantedBy: SUPERUSER_ACTOR });
    grantRole(db, { subject, appSlug: "atrium", role: "editor", grantedBy: SUPERUSER_ACTOR });
    grantRole(db, { subject, appSlug: "newspapper", role: "reader", grantedBy: SUPERUSER_ACTOR });

    expect(resolveSession(db, subject)).toEqual({
      active: true,
      subject,
      username: "Alice",
      // Several roles in one app is representable and comes back as a set —
      // `grants`' primary key is the whole triple for exactly this reason.
      grants: { atrium: ["admin", "editor"], newspapper: ["reader"] },
    });
  });

  it("is active with no grants at all — an account confers nothing on its own", () => {
    login();

    // Authenticated everywhere, authorised nowhere. This is the shape a freshly
    // created account has before the console grants it anything, and an app
    // absent from the map means no access to that app.
    expect(resolveSession(db, subject)).toEqual({
      active: true,
      subject,
      username: "Alice",
      grants: {},
    });
  });

  /**
   * The acceptance criterion about permission changes. Brief 05 owns the console
   * route that issues a grant and is landing in parallel, so this asserts
   * against the database write it performs; the integration chunk asserts it
   * through the route later.
   *
   * This is the whole reason grants ride in the response instead of in the
   * token: nothing was reissued and no cookie changed, and the new authority is
   * already visible.
   */
  it("shows a grant added directly to the database on the very next call", () => {
    login();
    expect(resolveSession(db, subject)).toMatchObject({ grants: {} });

    grantRole(db, { subject, appSlug: "prm", role: "admin", grantedBy: SUPERUSER_ACTOR });

    expect(resolveSession(db, subject)).toMatchObject({ grants: { prm: ["admin"] } });
  });

  it("shows a revoked grant disappearing just as fast", () => {
    login();
    grantRole(db, { subject, appSlug: "prm", role: "admin", grantedBy: SUPERUSER_ACTOR });
    expect(resolveSession(db, subject)).toMatchObject({ grants: { prm: ["admin"] } });

    db.prepare(`DELETE FROM grants WHERE subject = ?`).run(subject);

    expect(resolveSession(db, subject)).toMatchObject({ grants: {} });
  });
});

describe("the response carries nothing an app cannot justify", () => {
  it("has exactly four fields and none of the account's private columns", () => {
    login();
    grantRole(db, { subject, appSlug: "atrium", role: "admin", grantedBy: SUPERUSER_ACTOR });

    const result = resolveSession(db, subject);

    expect(Object.keys(result).sort()).toEqual(["active", "grants", "subject", "username"]);

    // Named individually rather than by the key count alone, so that adding one
    // of them back fails this test by name.
    for (const forbidden of [
      "password_hash",
      "passwordHash",
      "email",
      "email_verified",
      "created_at",
      "updated_at",
      "disabled_at",
      "username_folded",
      "familyId",
      "family_id",
      "jti",
    ]) {
      expect(result).not.toHaveProperty(forbidden);
    }

    // Belt and braces: the serialised form must not contain the hash or the
    // address even nested somewhere unexpected.
    const serialised = JSON.stringify(result);
    expect(serialised).not.toContain("alice@example.test");
    expect(serialised).not.toContain("scrypt");
  });
});

describe("active is false, with one identical answer every time", () => {
  it("for an account with no refresh row at all", () => {
    // Never signed in, or signed out and swept. Either way, no live session.
    expect(resolveSession(db, subject)).toBe(INACTIVE);
  });

  it("for an account whose only family was revoked", () => {
    const familyId = login();
    expect(resolveSession(db, subject)).toMatchObject({ active: true });

    revokeFamily(db, familyId, "logout");

    expect(resolveSession(db, subject)).toBe(INACTIVE);
  });

  it("for an account swept by a reuse-detection family burn", () => {
    const familyId = login();
    revokeFamily(db, familyId, "reuse_detected");

    expect(resolveSession(db, subject)).toBe(INACTIVE);
  });

  it("for an account revoked estate-wide by an administrator", () => {
    login();
    login();
    revokeAllForSubject(db, subject, "admin");

    expect(resolveSession(db, subject)).toBe(INACTIVE);
  });

  it("for a family that lapsed rather than being revoked", () => {
    login(PAST);

    expect(resolveSession(db, subject)).toBe(INACTIVE);
  });

  /**
   * The acceptance criterion, at the unit level. `setDisabled` deliberately
   * does **not** revoke refresh rows — `db/users.ts` documents that as a
   * separate write — so the account below still holds a live family, and the
   * `disabled_at` check is the only thing standing between it and six apps.
   */
  it("for a disabled account that still holds a live family", () => {
    login();
    expect(resolveSession(db, subject)).toMatchObject({ active: true });

    setDisabled(db, subject, true);

    expect(resolveSession(db, subject)).toBe(INACTIVE);
    expect(hasLiveSession(db, subject)).toBe(true);
  });

  it("and re-enabling the account brings it back with its grants intact", () => {
    login();
    grantRole(db, { subject, appSlug: "atrium", role: "admin", grantedBy: SUPERUSER_ACTOR });
    setDisabled(db, subject, true);
    expect(resolveSession(db, subject)).toBe(INACTIVE);

    setDisabled(db, subject, false);

    // A disable is a door locked, not an identity destroyed.
    expect(resolveSession(db, subject)).toEqual({
      active: true,
      subject,
      username: "Alice",
      grants: { atrium: ["admin"] },
    });
  });

  it("for a subject that has no row — a deleted account, or one that never existed", () => {
    expect(resolveSession(db, "0".repeat(32))).toBe(INACTIVE);
  });

  it("for the superuser, which has no row anywhere and therefore no grants", () => {
    // There is no `isSuperuser` branch to exercise; that is the point.
    // `decisions-admin.md` makes "console only" a consequence of having no
    // account row, so the ordinary unknown-subject path is the whole mechanism.
    expect(resolveSession(db, "superuser")).toBe(INACTIVE);
    expect(db.prepare(`SELECT count(*) FROM users`).pluck().get()).toBe(1);
  });

  it("answers with one shared frozen object, so no branch can add a reason", () => {
    const answers = [
      resolveSession(db, subject),
      resolveSession(db, "0".repeat(32)),
      resolveSession(db, "superuser"),
    ];

    for (const answer of answers) expect(answer).toBe(INACTIVE);
    expect(Object.isFrozen(INACTIVE)).toBe(true);
    expect(Object.keys(INACTIVE)).toEqual(["active"]);
  });
});

describe("what liveness can and cannot be established from", () => {
  /**
   * The documented residual gap, asserted so it is a known property rather than
   * a surprise. An access token carries `sub` and `jti` and **no family id**,
   * and `jti` is never persisted, so from a subject alone one revoked family
   * among two is invisible.
   *
   * If a future brief writes a `jti`-to-family link at mint time, this is the
   * test that should start failing.
   */
  it("cannot tell one revoked family from a second live one on the same account", () => {
    const laptop = login();
    login(); // the phone, still signed in

    revokeFamily(db, laptop, "logout");

    // Honest and deliberate: the laptop's access token still introspects as
    // live until it expires, because the account still has a live session and
    // nothing links the token to the family that ended.
    expect(resolveSession(db, subject)).toMatchObject({ active: true });
    expect(hasLiveSession(db, subject)).toBe(true);
  });

  it("goes inactive once the last family is gone, not before", () => {
    const first = login();
    const second = login();

    revokeFamily(db, first, "logout");
    expect(hasLiveSession(db, subject)).toBe(true);

    revokeFamily(db, second, "logout");
    expect(hasLiveSession(db, subject)).toBe(false);
    expect(resolveSession(db, subject)).toBe(INACTIVE);
  });

  it("is scoped to the account — another person's live session does not help", () => {
    const other = seedUser(db, "Bob").subject;
    login(FUTURE, other);

    expect(hasLiveSession(db, other)).toBe(true);
    expect(resolveSession(db, subject)).toBe(INACTIVE);
  });

  it("takes the caller's `now`, so liveness is evaluated at one instant", () => {
    login("2030-01-01T00:00:00.000Z");

    expect(resolveSession(db, subject, "2029-12-31T23:59:59.999Z")).toMatchObject({
      active: true,
    });
    expect(resolveSession(db, subject, "2030-01-01T00:00:00.001Z")).toBe(INACTIVE);
  });
});
