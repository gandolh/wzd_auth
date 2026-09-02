import type Database from "better-sqlite3";
import { prepareOnce } from "./prepared.js";

/**
 * The `grants` table — `(subject, app_slug, role)`, the security boundary of
 * the estate.
 *
 * Holding a Ward account confers nothing. Without a row here for a given app, a
 * valid account cannot use that app at all — which is what lets one app run
 * public registration without exposing the other five.
 *
 * **Grants are a set, not a mapping.** One person holds several roles in one
 * app, so every question this module answers about "what may they do" comes
 * back as a set to test membership against, never as a single role to compare.
 *
 * **Role strings are opaque and nothing here interprets them.** Ward knows the
 * triple `(cristian, prm, admin)`; what an admin may do is prm's business. No
 * function in this file branches on the value of a role, and none should — the
 * moment one does, adding a capability to any of six apps means redeploying the
 * identity service.
 */

/** A `grants` row exactly as SQLite returns it. */
export interface GrantRow {
  subject: string;
  app_slug: string;
  role: string;
  granted_at: string;
  /**
   * A subject, or the sentinel `"superuser"`. **No foreign key**: the identity
   * that issues the estate's first grants is the break-glass superuser, which
   * has no `users` row to point at.
   */
  granted_by: string | null;
}

/**
 * The value `granted_by` carries when the console — authenticated as the
 * environment-only superuser — issued the grant.
 *
 * It is deliberately not a subject and deliberately not resolvable to one. The
 * superuser has no account row, and `corpus/wiki/decisions-admin.md` explains
 * why giving it one would be wrong. A `users.username_folded` can never equal
 * this string in a way that matters, because nothing ever joins this column to
 * `users`.
 */
export const SUPERUSER_ACTOR = "superuser";

export interface NewGrant {
  subject: string;
  appSlug: string;
  role: string;
  /** A subject, or `SUPERUSER_ACTOR`. */
  grantedBy?: string | null;
}

const stmts = prepareOnce((db: Database.Database) => ({
  insert: db.prepare<[string, string, string, string | null], GrantRow>(
    `INSERT INTO grants (subject, app_slug, role, granted_by)
     VALUES (?, ?, ?, ?)
     RETURNING *`,
  ),

  insertIfAbsent: db.prepare<[string, string, string, string | null], GrantRow>(
    `INSERT INTO grants (subject, app_slug, role, granted_by)
     VALUES (?, ?, ?, ?)
     ON CONFLICT (subject, app_slug, role) DO NOTHING
     RETURNING *`,
  ),

  delete: db.prepare<[string, string, string]>(
    `DELETE FROM grants WHERE subject = ? AND app_slug = ? AND role = ?`,
  ),

  deleteForSubjectInApp: db.prepare<[string, string]>(
    `DELETE FROM grants WHERE subject = ? AND app_slug = ?`,
  ),

  deleteForSubject: db.prepare<[string]>(`DELETE FROM grants WHERE subject = ?`),

  forSubject: db.prepare<[string], GrantRow>(
    `SELECT * FROM grants WHERE subject = ? ORDER BY app_slug, role`,
  ),

  rolesInApp: db.prepare<[string, string], string>(
    `SELECT role FROM grants WHERE subject = ? AND app_slug = ? ORDER BY role`,
  ),

  forApp: db.prepare<[string], GrantRow>(
    `SELECT * FROM grants WHERE app_slug = ? ORDER BY role, subject`,
  ),

  exists: db.prepare<[string, string, string], number>(
    `SELECT 1 FROM grants WHERE subject = ? AND app_slug = ? AND role = ?`,
  ),
}));

/**
 * Issue a grant, returning the stored row.
 *
 * **Throws `SqliteError: UNIQUE constraint failed` on a duplicate triple**, and
 * that is the intended behaviour rather than an inconvenience: the PRIMARY KEY
 * `(subject, app_slug, role)` is what makes a duplicate grant impossible, so
 * two console clicks racing each other cannot produce two identical rows the
 * way a check-then-insert in application code would.
 *
 * Also throws on a subject or slug that does not exist — those are real foreign
 * keys, enforced because `openDatabase` sets `foreign_keys = ON`.
 *
 * Use `ensureGrant` where "they already have it" is a success, not an error.
 */
export function grantRole(db: Database.Database, input: NewGrant): GrantRow {
  return stmts(db).insert.get(input.subject, input.appSlug, input.role, input.grantedBy ?? null)!;
}

/**
 * Issue a grant unless the person already holds it.
 *
 * Returns the row when it was created and `undefined` when it was already
 * there. Still one statement, so it is still the database deciding — the
 * `ON CONFLICT DO NOTHING` suppresses the error without introducing a gap
 * between a check and a write.
 *
 * This is the right call for the self-registration path, where re-running a
 * signup should be harmless. `grantRole` is the right call for the console,
 * where a duplicate means the operator is looking at a stale page.
 */
export function ensureGrant(db: Database.Database, input: NewGrant): GrantRow | undefined {
  return stmts(db).insertIfAbsent.get(
    input.subject,
    input.appSlug,
    input.role,
    input.grantedBy ?? null,
  );
}

/** Remove one role. False if they did not hold it. */
export function revokeGrant(
  db: Database.Database,
  subject: string,
  appSlug: string,
  role: string,
): boolean {
  return stmts(db).delete.run(subject, appSlug, role).changes === 1;
}

/** Remove every role this person holds in one app. Returns how many went. */
export function revokeAppAccess(db: Database.Database, subject: string, appSlug: string): number {
  return stmts(db).deleteForSubjectInApp.run(subject, appSlug).changes;
}

/**
 * Remove every grant this person holds, estate-wide. Returns how many went.
 *
 * Deleting the account does this anyway via `ON DELETE CASCADE`; this exists
 * for the case where the account stays and only its access goes.
 */
export function revokeAllGrants(db: Database.Database, subject: string): number {
  return stmts(db).deleteForSubject.run(subject).changes;
}

/** Every grant this person holds, across every app. */
export function listGrantsForSubject(db: Database.Database, subject: string): GrantRow[] {
  return stmts(db).forSubject.all(subject);
}

/** Everyone who can reach one app. The console's per-app view. */
export function listGrantsForApp(db: Database.Database, appSlug: string): GrantRow[] {
  return stmts(db).forApp.all(appSlug);
}

/**
 * The roles this person holds in one app — **possibly several**, possibly none.
 * An empty array means no access to that app at all.
 */
export function listRolesInApp(db: Database.Database, subject: string, appSlug: string): string[] {
  return stmts(db).rolesInApp.pluck().all(subject, appSlug);
}

/** Exactly this triple, or not. */
export function hasGrant(
  db: Database.Database,
  subject: string,
  appSlug: string,
  role: string,
): boolean {
  return stmts(db).exists.pluck().get(subject, appSlug, role) !== undefined;
}

/**
 * Every grant this person holds, grouped by app slug — the shape the
 * introspection response carries.
 *
 * Grouped in JavaScript rather than with `json_group_array` because the row
 * count per account is single digits and the SQL stays readable; the query
 * itself is the indexed one (`subject` leads the primary key), which is the
 * part that runs on every request from every app.
 *
 * An app absent from the map means no access. An app present with an empty
 * array cannot occur — a grant row always carries a role.
 */
export function grantsBySlug(db: Database.Database, subject: string): Record<string, string[]> {
  const grouped: Record<string, string[]> = Object.create(null) as Record<string, string[]>;

  for (const grant of listGrantsForSubject(db, subject)) {
    (grouped[grant.app_slug] ??= []).push(grant.role);
  }

  return grouped;
}
