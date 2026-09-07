import { createHash, randomBytes } from "node:crypto";
import type Database from "better-sqlite3";
import { prepareOnce } from "./prepared.js";

/**
 * The `app_keys` table — one service credential per consuming app.
 *
 * The migration (`migrations/20260906000000-app-keys.ts`) carries the design;
 * this is the storage layer. Two rules hold throughout and are the reason the
 * mint/hash pair lives here rather than at a call site:
 *
 *  - **The key itself never enters this module's return values except once**,
 *    from `createAppKey`, which is the only moment it exists in Ward at all.
 *    Everything else deals in `id` (a non-secret handle) and `key_hash`.
 *  - **Lookup is by hash**, so a caller cannot accidentally write a query that
 *    compares plaintext.
 */

/** An `app_keys` row exactly as SQLite returns it. */
export interface AppKeyRow {
  /** 16 random bytes as hex. The non-secret handle the console renders. */
  id: string;
  app_slug: string;
  label: string;
  /** `sha256(key)` in hex. The key itself is never stored. */
  key_hash: string;
  created_at: string;
  /** A subject, or the `superuser` sentinel. No foreign key — see the migration. */
  created_by: string;
  /** Coarse: stamped at most hourly. Null until the key's first use. */
  last_used_at: string | null;
  /** Null while live. Set once, never cleared — a revoked key stays revoked. */
  revoked_at: string | null;
}

export interface NewAppKey {
  appSlug: string;
  label: string;
  createdBy: string;
}

/**
 * A freshly minted key, returned exactly once.
 *
 * `key` is the only copy that will ever exist outside the operator's clipboard:
 * the database holds its digest, and there is no code path anywhere in Ward that
 * can reproduce it. That is deliberate and is what makes a leaked `ward.db`
 * useless as a credential.
 */
export interface MintedAppKey {
  row: AppKeyRow;
  /** `wak_` + 32 random bytes, base64url. Shown once. */
  key: string;
}

/**
 * The prefix. `wak_` — Ward App Key — chosen to be greppable in a config file
 * and distinguishable at a glance from `wcs_` (the console session token), which
 * is the other opaque `w`-prefixed credential in this estate. A person pasting
 * the wrong one into the wrong box should be able to see it.
 */
const KEY_PREFIX = "wak_";

/**
 * Mint a key: 256 bits of `randomBytes`, base64url, behind the prefix.
 *
 * The same entropy budget as a refresh token and as the console token, and for
 * the same reason — this is a bearer credential that authenticates an app to the
 * estate's identity service, and it is never rate limited (see
 * `auth/app-key.ts`), so brute force must be arithmetically hopeless rather than
 * merely slowed down.
 */
export function mintAppKeyValue(): string {
  return `${KEY_PREFIX}${randomBytes(32).toString("base64url")}`;
}

/**
 * `sha256(key)`, hex.
 *
 * **Not a password hash, and deliberately not scrypt.** The input is 256 bits of
 * `randomBytes`, so there is no dictionary to attack and a slow KDF buys nothing
 * — while costing something real here, because this runs on the hot path of
 * every app's every request. `db/refresh-tokens.ts#hashRefreshToken` makes the
 * identical call for the identical reason. Passwords are the opposite case and
 * stay on scrypt in `auth/password.ts`.
 */
export function hashAppKey(key: string): string {
  return createHash("sha256").update(key, "utf8").digest("hex");
}

/** A cheap shape check, so a malformed header never reaches the database. */
export function looksLikeAppKey(value: string): boolean {
  return value.startsWith(KEY_PREFIX) && value.length > KEY_PREFIX.length;
}

const stmts = prepareOnce((db: Database.Database) => ({
  insert: db.prepare<[string, string, string, string, string], AppKeyRow>(
    `INSERT INTO app_keys (id, app_slug, label, key_hash, created_by)
     VALUES (?, ?, ?, ?, ?)
     RETURNING *`,
  ),

  byHash: db.prepare<[string], AppKeyRow>(`SELECT * FROM app_keys WHERE key_hash = ?`),

  byId: db.prepare<[string], AppKeyRow>(`SELECT * FROM app_keys WHERE id = ?`),

  listForApp: db.prepare<[string], AppKeyRow>(
    `SELECT * FROM app_keys WHERE app_slug = ? ORDER BY created_at DESC, id`,
  ),

  list: db.prepare<[], AppKeyRow>(`SELECT * FROM app_keys ORDER BY app_slug, created_at DESC, id`),

  revoke: db.prepare<[string]>(
    `UPDATE app_keys
        SET revoked_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now')
      WHERE id = ? AND revoked_at IS NULL`,
  ),

  touch: db.prepare<[string, string]>(`UPDATE app_keys SET last_used_at = ? WHERE id = ?`),
}));

/**
 * Register a key for an app and hand back the one copy of it.
 *
 * Throws `SQLITE_CONSTRAINT_FOREIGNKEY` if the app does not exist — the route
 * looks the app up first for a clean `404`, and this is the backstop for the
 * window between that lookup and this insert, in which the app can be deleted.
 */
export function createAppKey(db: Database.Database, input: NewAppKey): MintedAppKey {
  const key = mintAppKeyValue();
  const row = stmts(db).insert.get(
    randomBytes(16).toString("hex"),
    input.appSlug,
    input.label,
    hashAppKey(key),
    input.createdBy,
  )!;

  return { row, key };
}

/**
 * The presentation lookup, by digest — an index seek on the UNIQUE column.
 *
 * Returns the row whether or not it is revoked. Deciding what a revoked key
 * means is `auth/app-key.ts`'s job, and keeping that decision out of the data
 * layer is what stops "revoked" from being silently equivalent to "unknown" in
 * one caller and not another.
 */
export function findAppKeyByHash(db: Database.Database, keyHash: string): AppKeyRow | undefined {
  return stmts(db).byHash.get(keyHash);
}

export function getAppKey(db: Database.Database, id: string): AppKeyRow | undefined {
  return stmts(db).byId.get(id);
}

/** Every key for one app, newest first. The console's per-app view. */
export function listAppKeysForApp(db: Database.Database, appSlug: string): AppKeyRow[] {
  return stmts(db).listForApp.all(appSlug);
}

/** Every key in the estate, grouped by app. The console's index. */
export function listAppKeys(db: Database.Database): AppKeyRow[] {
  return stmts(db).list.all();
}

/**
 * Revoke a key. Returns false if it does not exist **or was already revoked** —
 * the `revoked_at IS NULL` in the `WHERE` makes re-revoking a no-op rather than
 * a re-stamp, so the recorded time stays the time it actually happened.
 *
 * There is no un-revoke, by decision. A key that has been off is a key whose
 * value may have been shared while it was off; the fix is a new key, which costs
 * one console click.
 */
export function revokeAppKey(db: Database.Database, id: string): boolean {
  return stmts(db).revoke.run(id).changes === 1;
}

/**
 * Stamp `last_used_at`. Called by the throttle in `auth/app-key.ts` and **not**
 * by request handling directly — see the migration on why this column is coarse.
 */
export function touchAppKey(db: Database.Database, id: string, at: string): void {
  stmts(db).touch.run(at, id);
}
