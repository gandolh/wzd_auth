import type Database from "better-sqlite3";
import { afterEach, beforeEach, describe, expect, it } from "vitest";

import {
  APP_KEY_HEADER,
  readAppKeyHeader,
  resetAppKeyTouchThrottle,
  resolveAppKey,
} from "./app-key.js";
import { createAppKey, getAppKey, hashAppKey, revokeAppKey } from "../db/app-keys.js";
import { freshDb, seedApps } from "../db/test-support.js";
import type { FastifyRequest } from "fastify";

/**
 * The app-key guard.
 *
 * `resolveAppKey` is what stands between the public internet and every
 * signature verification `/introspect` would otherwise do on an anonymous
 * caller's behalf, so what is tested here is mostly the **refusal** side.
 */

let db: Database.Database;

beforeEach(() => {
  db = freshDb();
  seedApps(db);
  resetAppKeyTouchThrottle();
});

afterEach(() => {
  db.close();
});

/** Just enough of a request for `readAppKeyHeader`. */
function request(headers: Record<string, string | string[] | undefined>): FastifyRequest {
  return { headers } as unknown as FastifyRequest;
}

function issue(appSlug = "atrium"): string {
  return createAppKey(db, { appSlug, label: `${appSlug} key`, createdBy: "superuser" }).key;
}

describe("reading the header", () => {
  it("takes the value of x-ward-app-key", () => {
    expect(readAppKeyHeader(request({ [APP_KEY_HEADER]: "wak_abc" }))).toBe("wak_abc");
  });

  it("is undefined when the header is absent or empty", () => {
    expect(readAppKeyHeader(request({}))).toBeUndefined();
    expect(readAppKeyHeader(request({ [APP_KEY_HEADER]: "" }))).toBeUndefined();
  });

  /**
   * A repeated header arrives as an array. Taking the first would silently
   * decide which app a request is attributed to, which is the one thing this
   * function exists to establish.
   */
  it("refuses a repeated header rather than picking one", () => {
    expect(readAppKeyHeader(request({ [APP_KEY_HEADER]: ["wak_one", "wak_two"] }))).toBeUndefined();
  });
});

describe("resolving", () => {
  it("names the app a live key belongs to", () => {
    const key = issue("newspapper");
    const resolution = resolveAppKey(db, key);

    expect(resolution.ok).toBe(true);
    if (!resolution.ok) throw new Error("unreachable");
    expect(resolution.app.appSlug).toBe("newspapper");
    expect(resolution.app.keyId).toMatch(/^[0-9a-f]{32}$/);
  });

  it("says absent for no key at all", () => {
    expect(resolveAppKey(db, undefined)).toEqual({ ok: false, reason: "absent" });
  });

  /**
   * Shape before hash before read. A header full of junk must cost neither a
   * `sha256` nor an index seek — that ordering is the DoS argument for the
   * whole feature.
   */
  it("says malformed for anything that is not wak_-prefixed", () => {
    expect(resolveAppKey(db, "hello")).toEqual({ ok: false, reason: "malformed" });
    expect(resolveAppKey(db, "wak_")).toEqual({ ok: false, reason: "malformed" });
    // A console token is the credential most likely to be pasted here by
    // mistake, and it is refused on shape alone.
    expect(resolveAppKey(db, "wcs_abcdef")).toEqual({ ok: false, reason: "malformed" });
  });

  it("says unknown for a well-shaped key nobody issued", () => {
    expect(resolveAppKey(db, `wak_${"a".repeat(43)}`)).toEqual({ ok: false, reason: "unknown" });
  });

  it("says revoked for a key that was turned off, distinctly from unknown", () => {
    const key = issue();
    const row = resolveAppKey(db, key);
    if (!row.ok) throw new Error("expected the fresh key to resolve");

    expect(revokeAppKey(db, row.app.keyId)).toBe(true);

    // Distinct in the *resolution* so the log can tell an operator which
    // problem they have. The route collapses both to one response.
    expect(resolveAppKey(db, key)).toEqual({ ok: false, reason: "revoked" });
  });

  it("takes effect immediately on revocation — nothing is memoised", () => {
    const key = issue();
    const first = resolveAppKey(db, key);
    if (!first.ok) throw new Error("expected the fresh key to resolve");

    revokeAppKey(db, first.app.keyId);
    expect(resolveAppKey(db, key).ok).toBe(false);
  });

  it("does not confuse two apps' keys", () => {
    const atrium = issue("atrium");
    const sports = issue("sports-app");

    const a = resolveAppKey(db, atrium);
    const s = resolveAppKey(db, sports);
    if (!a.ok || !s.ok) throw new Error("both keys should resolve");

    expect(a.app.appSlug).toBe("atrium");
    expect(s.app.appSlug).toBe("sports-app");
  });
});

describe("the last_used_at throttle", () => {
  function keyRowFor(key: string) {
    const resolved = resolveAppKey(db, key);
    if (!resolved.ok) throw new Error("expected a live key");
    return getAppKey(db, resolved.app.keyId)!;
  }

  it("stamps on first use", () => {
    const key = issue();
    expect(keyRowFor(key).last_used_at).not.toBeNull();
  });

  it("writes at most once an hour, however many calls arrive", () => {
    const key = issue();
    const start = Date.UTC(2026, 8, 6, 12, 0, 0);

    resolveAppKey(db, key, start);
    const stamped = getAppKey(db, hashLookup(key))!.last_used_at;

    // Fifty-nine minutes of traffic: no further writes. `/introspect` is the
    // estate's hot path and must not write per request.
    for (let minute = 1; minute < 60; minute += 1) {
      resolveAppKey(db, key, start + minute * 60_000);
    }
    expect(getAppKey(db, hashLookup(key))!.last_used_at).toBe(stamped);

    // Past the hour: one more write, so a rotation can still see the key is in
    // use.
    resolveAppKey(db, key, start + 61 * 60_000);
    expect(getAppKey(db, hashLookup(key))!.last_used_at).not.toBe(stamped);
  });

  /** The digest lookup, so the test does not depend on `resolveAppKey` itself. */
  function hashLookup(key: string): string {
    const row = db
      .prepare<[string], { id: string }>(`SELECT id FROM app_keys WHERE key_hash = ?`)
      .get(hashAppKey(key));
    if (row === undefined) throw new Error("no such key");
    return row.id;
  }

  /**
   * The stamp is bookkeeping. If the database cannot take the write — a locked
   * writer, a read-only file — the request must still be authenticated, because
   * the alternative is the whole estate signing out over a stats column.
   */
  it("still authenticates when the stamp cannot be written", () => {
    const key = issue();
    resetAppKeyTouchThrottle();

    db.prepare(`DROP TABLE app_keys`).run();
    // The lookup itself now fails, which is a different thing — so rebuild just
    // enough to prove the point: a fresh db, a fresh key, then make the write
    // fail by removing the column the update targets.
    db.exec(`
      CREATE TABLE app_keys (
        id TEXT PRIMARY KEY, app_slug TEXT NOT NULL, label TEXT NOT NULL,
        key_hash TEXT NOT NULL UNIQUE, created_at TEXT NOT NULL, created_by TEXT NOT NULL,
        revoked_at TEXT
      )
    `);
    db.prepare(
      `INSERT INTO app_keys (id, app_slug, label, key_hash, created_at, created_by)
       VALUES (?, 'atrium', 'x', ?, '2026-09-06T00:00:00.000Z', 'superuser')`,
    ).run("f".repeat(32), hashAppKey(key));

    // `last_used_at` does not exist on this table, so the UPDATE throws — and
    // is swallowed.
    const resolution = resolveAppKey(db, key);
    expect(resolution.ok).toBe(true);
  });
});
