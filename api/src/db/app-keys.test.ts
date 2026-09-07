import type Database from "better-sqlite3";
import { afterEach, beforeEach, describe, expect, it } from "vitest";

import {
  createAppKey,
  getAppKey,
  hashAppKey,
  findAppKeyByHash,
  listAppKeys,
  listAppKeysForApp,
  looksLikeAppKey,
  mintAppKeyValue,
  revokeAppKey,
  touchAppKey,
} from "./app-keys.js";
import { deleteApp } from "./apps.js";
import { freshDb, seedApps } from "./test-support.js";

/**
 * The `app_keys` storage layer.
 *
 * The property under test throughout is that **the key is never recoverable**.
 * Everything else here — revocation, cascade, the coarse stamp — is ordinary
 * table behaviour; that one is the reason the table is shaped the way it is.
 */

let db: Database.Database;

beforeEach(() => {
  db = freshDb();
  seedApps(db);
});

afterEach(() => {
  db.close();
});

describe("minting", () => {
  it("produces a wak_ prefixed key with 256 bits behind it", () => {
    const key = mintAppKeyValue();

    expect(key.startsWith("wak_")).toBe(true);
    // 32 random bytes, base64url: 43 characters, no padding.
    expect(key.slice("wak_".length)).toHaveLength(43);
    expect(looksLikeAppKey(key)).toBe(true);
  });

  it("never repeats", () => {
    const keys = new Set(Array.from({ length: 500 }, () => mintAppKeyValue()));
    expect(keys.size).toBe(500);
  });

  it("rejects anything without the prefix, before a hash is ever computed", () => {
    expect(looksLikeAppKey("")).toBe(false);
    expect(looksLikeAppKey("wak_")).toBe(false);
    expect(looksLikeAppKey("wcs_looks-like-a-console-token")).toBe(false);
    expect(looksLikeAppKey("Bearer wak_something")).toBe(false);
  });
});

describe("storage", () => {
  it("stores the digest and never the key", () => {
    const { row, key } = createAppKey(db, {
      appSlug: "atrium",
      label: "atrium production",
      createdBy: "superuser",
    });

    expect(row.key_hash).toBe(hashAppKey(key));
    expect(row.key_hash).not.toBe(key);

    // The whole row, as text: the key must not appear anywhere in it.
    expect(JSON.stringify(row)).not.toContain(key);

    // Nor anywhere in the table. This is the assertion that a leaked `ward.db`
    // is not six working credentials.
    const dump = db
      .prepare<[], { text: string }>(
        `SELECT group_concat(id || label || key_hash) AS text FROM app_keys`,
      )
      .get()!;
    expect(dump.text).not.toContain(key);
  });

  it("gives every key a distinct non-secret handle", () => {
    const first = createAppKey(db, { appSlug: "atrium", label: "one", createdBy: "superuser" });
    const second = createAppKey(db, { appSlug: "atrium", label: "two", createdBy: "superuser" });

    expect(first.row.id).not.toBe(second.row.id);
    expect(first.row.id).toMatch(/^[0-9a-f]{32}$/);
  });

  it("finds a key by the digest of what was presented", () => {
    const { row, key } = createAppKey(db, {
      appSlug: "newspapper",
      label: "np",
      createdBy: "superuser",
    });

    expect(findAppKeyByHash(db, hashAppKey(key))?.id).toBe(row.id);
    expect(findAppKeyByHash(db, hashAppKey("wak_something-else"))).toBeUndefined();
  });

  /**
   * More than one live key per app, deliberately. Rotation across
   * independently deployed apps is issue → roll out → confirm → revoke, and a
   * one-key constraint would force a window with no working key at all — an
   * outage on every rotation.
   */
  it("allows an app to hold several live keys at once", () => {
    createAppKey(db, { appSlug: "atrium", label: "current", createdBy: "superuser" });
    createAppKey(db, { appSlug: "atrium", label: "incoming", createdBy: "superuser" });

    const live = listAppKeysForApp(db, "atrium").filter((row) => row.revoked_at === null);
    expect(live).toHaveLength(2);
  });

  it("refuses a key for an app that does not exist", () => {
    expect(() =>
      createAppKey(db, { appSlug: "no-such-app", label: "x", createdBy: "superuser" }),
    ).toThrow(/FOREIGN KEY/i);
  });

  it("refuses an empty label, so a console list cannot become unreadable", () => {
    expect(() =>
      createAppKey(db, { appSlug: "atrium", label: "", createdBy: "superuser" }),
    ).toThrow(/CHECK/i);
  });
});

describe("revocation", () => {
  it("stamps revoked_at and keeps the row", () => {
    const { row } = createAppKey(db, {
      appSlug: "atrium",
      label: "leaked",
      createdBy: "superuser",
    });

    expect(revokeAppKey(db, row.id)).toBe(true);

    const after = getAppKey(db, row.id)!;
    expect(after.revoked_at).not.toBeNull();
    // Kept rather than deleted: `audit_log.detail` points at this id, and an
    // audit trail wants something to point at.
    expect(after.label).toBe("leaked");
  });

  it("is idempotent in the sense that matters — the first time stays the recorded time", () => {
    const { row } = createAppKey(db, { appSlug: "atrium", label: "x", createdBy: "superuser" });

    expect(revokeAppKey(db, row.id)).toBe(true);
    const first = getAppKey(db, row.id)!.revoked_at;

    // False, not true: there was nothing live to revoke. And the timestamp is
    // untouched, so "when was this turned off" keeps its honest answer.
    expect(revokeAppKey(db, row.id)).toBe(false);
    expect(getAppKey(db, row.id)!.revoked_at).toBe(first);
  });

  it("reports false for a key that never existed", () => {
    expect(revokeAppKey(db, "0".repeat(32))).toBe(false);
  });
});

describe("the app cascade", () => {
  it("deleting an app deletes its keys", () => {
    createAppKey(db, { appSlug: "sports-app", label: "a", createdBy: "superuser" });
    createAppKey(db, { appSlug: "sports-app", label: "b", createdBy: "superuser" });
    expect(listAppKeysForApp(db, "sports-app")).toHaveLength(2);

    expect(deleteApp(db, "sports-app")).toBe(true);

    // A credential authenticating as an app that no longer exists would have no
    // owner and no console page to find it on.
    expect(listAppKeysForApp(db, "sports-app")).toEqual([]);
    expect(listAppKeys(db).some((row) => row.app_slug === "sports-app")).toBe(false);
  });
});

describe("last_used_at", () => {
  it("starts null and holds whatever the caller stamps", () => {
    const { row } = createAppKey(db, { appSlug: "prm", label: "x", createdBy: "superuser" });
    expect(row.last_used_at).toBeNull();

    touchAppKey(db, row.id, "2026-09-06T12:00:00.000Z");
    expect(getAppKey(db, row.id)!.last_used_at).toBe("2026-09-06T12:00:00.000Z");
  });
});
