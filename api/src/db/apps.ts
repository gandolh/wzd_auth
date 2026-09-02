import type Database from "better-sqlite3";
import { prepareOnce } from "./prepared.js";

/**
 * The `apps` table — the estate's relying parties and their registration flags.
 *
 * Ward knows a slug, a display name, whether strangers may register, and which
 * single role a stranger gets if they do. It knows nothing about what any app
 * *does* with a role.
 */

/** An `apps` row exactly as SQLite returns it. */
export interface AppRow {
  /** `atrium`, `newspapper`, `prm`, … Lower case, enforced by a CHECK. */
  slug: string;
  name: string;
  /** 0 or 1. **Defaults to 0** — closed until someone deliberately opens it. */
  public_registration: 0 | 1;
  /**
   * The one role a self-registering stranger receives, and nothing else.
   * Non-null whenever `public_registration` is 1, enforced by a CHECK.
   */
  baseline_role: string | null;
  created_at: string;
  updated_at: string;
}

export interface NewApp {
  slug: string;
  name: string;
  /**
   * Omitted means **closed**, and that default is the decision rather than a
   * convenience: an app added to the estate must be unreachable by strangers
   * until someone says otherwise, so forgetting this argument fails safe.
   */
  publicRegistration?: boolean;
  /** Required when `publicRegistration` is true; the schema refuses otherwise. */
  baselineRole?: string | null;
}

const stmts = prepareOnce((db: Database.Database) => ({
  insert: db.prepare<[string, string, number, string | null], AppRow>(
    `INSERT INTO apps (slug, name, public_registration, baseline_role)
     VALUES (?, ?, ?, ?)
     RETURNING *`,
  ),

  bySlug: db.prepare<[string], AppRow>(`SELECT * FROM apps WHERE slug = ?`),

  list: db.prepare<[], AppRow>(`SELECT * FROM apps ORDER BY slug`),

  listOpen: db.prepare<[], AppRow>(
    `SELECT * FROM apps WHERE public_registration = 1 ORDER BY slug`,
  ),

  rename: db.prepare<[string, string]>(
    `UPDATE apps
        SET name = ?, updated_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now')
      WHERE slug = ?`,
  ),

  setRegistration: db.prepare<[number, string | null, string]>(
    `UPDATE apps
        SET public_registration = ?, baseline_role = ?,
            updated_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now')
      WHERE slug = ?`,
  ),

  delete: db.prepare<[string]>(`DELETE FROM apps WHERE slug = ?`),
}));

/**
 * Register an app. Throws on a duplicate slug (PRIMARY KEY) and on an app
 * opened to the public with no baseline role (CHECK).
 */
export function createApp(db: Database.Database, input: NewApp): AppRow {
  const open = input.publicRegistration === true;
  return stmts(db).insert.get(input.slug, input.name, open ? 1 : 0, input.baselineRole ?? null)!;
}

export function getApp(db: Database.Database, slug: string): AppRow | undefined {
  return stmts(db).bySlug.get(slug);
}

/** Every app, slug order. The console's list and the grant editor's options. */
export function listApps(db: Database.Database): AppRow[] {
  return stmts(db).list.all();
}

/**
 * The apps a stranger may sign up at — today, `public-resource-map` and nothing
 * else. The login/registration UI reads this to decide whether to offer a
 * "create an account" link at all.
 */
export function listOpenApps(db: Database.Database): AppRow[] {
  return stmts(db).listOpen.all();
}

/**
 * The registration gate, as one write.
 *
 * Opening an app requires naming the baseline role in the same call, because
 * "open" and "confers what?" are one decision and splitting them across two
 * statements leaves a window where an app is open and grants nothing (or, worse,
 * still carries a baseline role from the last time it was open). Closing an app
 * clears the role; the schema permits a closed app to keep one, but keeping it
 * would mean a reopen silently inherits an answer nobody re-checked.
 *
 * Existing grants are untouched: closing registration stops new strangers, it
 * does not evict the people already inside.
 */
export function setPublicRegistration(
  db: Database.Database,
  slug: string,
  open: boolean,
  baselineRole: string | null = null,
): boolean {
  return (
    stmts(db).setRegistration.run(open ? 1 : 0, open ? baselineRole : null, slug).changes === 1
  );
}

export function renameApp(db: Database.Database, slug: string, name: string): boolean {
  return stmts(db).rename.run(name, slug).changes === 1;
}

/**
 * Remove an app. **Cascades to every grant for it** — removing an app removes
 * everyone's access to it, which is the correct meaning and is also why this is
 * not a routine operation.
 */
export function deleteApp(db: Database.Database, slug: string): boolean {
  return stmts(db).delete.run(slug).changes === 1;
}
