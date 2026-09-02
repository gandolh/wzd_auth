import type Database from "better-sqlite3";
import { prepareOnce } from "./prepared.js";

/**
 * The `audit_log` table — who did what to whom, and when. Append-only.
 *
 * The console (brief 10) renders it, and the question it exists to answer is
 * "who granted this, and when". Nothing in this module updates or deletes a
 * row, and nothing should: an audit trail that can be edited by the code it
 * audits is decoration.
 *
 * **No column here is a foreign key**, for two separate reasons that a later
 * "let's tighten the schema" migration would undo together:
 *
 *  1. The most important actor in this table is the **superuser**, which has no
 *     `users` row to reference. It is an environment-only break-glass
 *     credential with no subject and no grants
 *     (`corpus/wiki/decisions-admin.md`); an FK on `actor_subject` makes the
 *     console's own actions unrecordable.
 *  2. An audit row must outlive what it describes. Grants and refresh tokens
 *     cascade away when an account is deleted; the record that the account
 *     *was* deleted, and by whom, is the one row that must survive it.
 */

/**
 * Who acted.
 *
 * - `superuser` — the environment-only console credential. **Always carries a
 *   null `actor_subject`**, because no row exists for it.
 * - `account` — an ordinary Ward account, identified by its subject. The owner
 *   account issuing grants is this, not `superuser`.
 * - `system` — Ward itself: an expiry sweep, a family burned down by reuse
 *   detection, a migration. Also null-subject.
 */
export type ActorKind = "superuser" | "account" | "system";

/** What was acted on. Constrained by a CHECK; paired with `target_id`. */
export type TargetKind = "user" | "app" | "grant" | "session" | "token";

/** An `audit_log` row exactly as SQLite returns it. */
export interface AuditLogRow {
  /** Rowid alias. Monotonic, so it orders two events in the same millisecond. */
  id: number;
  at: string;
  actor_kind: ActorKind;
  /** Non-null if and only if `actor_kind` is `account`. Enforced by a CHECK. */
  actor_subject: string | null;
  /** What the console renders: a username, or `superuser`, or a job name. */
  actor_label: string;
  /** An opaque dotted verb — `grant.create`, `user.disable`, `session.revoke`. */
  action: string;
  target_kind: TargetKind | null;
  /**
   * A subject, a slug, or — for a grant — the triple as `grantTargetId` encodes
   * it. Never a foreign key.
   */
  target_id: string | null;
  /** JSON, or null. Whatever context the event needs, without a migration. */
  detail: string | null;
}

/** The `actor_label` the console writes for the break-glass credential. */
export const SUPERUSER_LABEL = "superuser";

export interface AuditEvent {
  actorKind: ActorKind;
  /** Required for `account`; must be omitted for `superuser` and `system`. */
  actorSubject?: string | null;
  actorLabel: string;
  action: string;
  targetKind?: TargetKind | null;
  targetId?: string | null;
  /** Serialised with `JSON.stringify`. Keep it small and free of secrets. */
  detail?: unknown;
}

const stmts = prepareOnce((db: Database.Database) => ({
  insert: db.prepare<
    [string, string | null, string, string, string | null, string | null, string | null],
    AuditLogRow
  >(`INSERT INTO audit_log (actor_kind, actor_subject, actor_label, action, target_kind, target_id, detail)
     VALUES (?, ?, ?, ?, ?, ?, ?)
     RETURNING *`),

  count: db.prepare<[], number>(`SELECT count(*) FROM audit_log`),
}));

/**
 * Append one event and return the stored row.
 *
 * Throws if `actor_subject` and `actor_kind` disagree, or if `target_kind` and
 * `target_id` are not both present or both absent — CHECK constraints, because
 * a half-filled audit row is worse than no row: it looks like a record and
 * answers nothing.
 *
 * Call this **inside the same transaction as the change it records**. A grant
 * written outside the audit insert's transaction can succeed while its record
 * does not, and the log then quietly disagrees with the data.
 */
export function recordAudit(db: Database.Database, event: AuditEvent): AuditLogRow {
  return stmts(db).insert.get(
    event.actorKind,
    event.actorSubject ?? null,
    event.actorLabel,
    event.action,
    event.targetKind ?? null,
    event.targetId ?? null,
    event.detail === undefined ? null : JSON.stringify(event.detail),
  )!;
}

/**
 * The canonical `target_id` for a grant: the triple that identifies it, encoded
 * so that **no two distinct triples can ever produce the same string**.
 *
 * It used to be a bare `` `${subject}:${appSlug}:${role}` ``, which collided.
 * Role strings are explicitly opaque and unrestricted — `grants.test.ts`
 * deliberately grants one containing `:`, and `apps.slug` has no CHECK
 * forbidding one either — so `(subject, "atrium", "a:b")` and
 * `(subject, "atrium:a", "b")` encoded identically. `AuditQuery.targetId` is an
 * equality filter, and it is how the console answers "everything that happened
 * to this grant", so a colon in a role silently broke the one job `audit_log`
 * exists to do.
 *
 * The fix is the encoding, **not** a restriction on what a role may contain:
 * role opacity is locked in `corpus/wiki/decisions-accounts.md`, and narrowing
 * it here to make a delimiter safe would be solving the wrong problem.
 *
 * `encodeURIComponent` per component, joined on `:`. Percent-encoding escapes
 * `:` (to `%3A`) and `%` itself (to `%25`), which is what makes the join
 * unambiguous and the split exact; a JSON array would work equally well but
 * this stays readable in a console table and greppable in a log. Round-trips
 * through `parseGrantTargetId` for every possible component string, including
 * empty ones.
 */
export function grantTargetId(subject: string, appSlug: string, role: string): string {
  return [subject, appSlug, role].map(encodeURIComponent).join(":");
}

/** The three components of a grant `target_id`, decoded. */
export interface GrantTarget {
  subject: string;
  appSlug: string;
  role: string;
}

/**
 * The inverse of `grantTargetId`. `undefined` when the string is not one —
 * wrong number of components, or an invalid percent escape.
 *
 * It returns rather than throws because the caller is the console rendering a
 * row someone else wrote: `target_id` is a free-text column with no CHECK, and
 * an old or hand-inserted value should render as opaque rather than take the
 * page down.
 */
export function parseGrantTargetId(targetId: string): GrantTarget | undefined {
  const parts = targetId.split(":");
  if (parts.length !== 3) return undefined;
  try {
    const [subject, appSlug, role] = parts.map(decodeURIComponent) as [string, string, string];
    return { subject, appSlug, role };
  } catch {
    // decodeURIComponent throws URIError on a malformed escape such as "%zz".
    return undefined;
  }
}

/** Filters the console offers. Every field is optional; omitted means unfiltered. */
export interface AuditQuery {
  actorSubject?: string;
  targetKind?: TargetKind;
  targetId?: string;
  action?: string;
  /** Keyset pagination: return rows with `id` strictly below this one. */
  beforeId?: number;
  limit?: number;
}

/**
 * Read the log newest-first.
 *
 * The SQL is assembled per call rather than cached through `prepareOnce`,
 * because the shape genuinely varies with which filters are set and the
 * alternative — one statement per filter combination, or a `WHERE (? IS NULL OR
 * col = ?)` chain that defeats the indexes — is worse. This is the console's
 * query, run at human speed, so a `prepare` per call costs nothing that
 * matters. **Every value is still bound, never interpolated**; only the fixed
 * SQL fragments are concatenated.
 *
 * Pagination is keyset on `id`, not `OFFSET`: the log grows at the head, so an
 * offset-paged second page shifts under the reader every time a new event
 * lands.
 */
export function listAudit(db: Database.Database, query: AuditQuery = {}): AuditLogRow[] {
  const clauses: string[] = [];
  const params: (string | number)[] = [];

  if (query.actorSubject !== undefined) {
    clauses.push("actor_subject = ?");
    params.push(query.actorSubject);
  }
  if (query.targetKind !== undefined) {
    clauses.push("target_kind = ?");
    params.push(query.targetKind);
  }
  if (query.targetId !== undefined) {
    clauses.push("target_id = ?");
    params.push(query.targetId);
  }
  if (query.action !== undefined) {
    clauses.push("action = ?");
    params.push(query.action);
  }
  if (query.beforeId !== undefined) {
    clauses.push("id < ?");
    params.push(query.beforeId);
  }

  const where = clauses.length > 0 ? `WHERE ${clauses.join(" AND ")}` : "";
  params.push(query.limit ?? 100);

  return db
    .prepare<(string | number)[], AuditLogRow>(
      `SELECT * FROM audit_log ${where} ORDER BY id DESC LIMIT ?`,
    )
    .all(...params);
}

export function countAudit(db: Database.Database): number {
  return stmts(db).count.pluck().get()!;
}
