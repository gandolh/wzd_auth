import type Database from "better-sqlite3";

import { getDb } from "../../db/connection.js";
import type { AppRow } from "../../db/apps.js";
import type { GrantRow } from "../../db/grants.js";
import type { UserRow } from "../../db/users.js";

/**
 * Shared plumbing for the three console admin plugins — `apps.ts`, `grants.ts`
 * and `accounts.ts`.
 *
 * Two things live here and nothing else should. The **response shapes** brief
 * 10's console UI builds against, so that "what does an app look like over the
 * wire" has one answer rather than three that drift; and the **constraint
 * translation** that turns a `SqliteError` into a status code, so that a schema
 * CHECK doing its job never reaches the caller as a `500` carrying a column
 * name.
 *
 * There are no routes in this file. It registers nothing.
 */

/**
 * Every admin plugin takes the same option, for the same reason: a test builds
 * its own Fastify instance and hands it an `openDatabase(":memory:")` handle,
 * while production passes nothing and the handlers resolve the process-wide
 * singleton lazily on first request.
 *
 * Lazily, specifically — never at registration. `app.ts` is deliberately free of
 * any reach into the database, because `index.ts` runs migrations strictly
 * before `buildApp()`, and a registration-time `getDb()` would open the file
 * from inside `buildApp` and blur that ordering.
 */
export interface AdminRoutesOptions {
  db?: Database.Database;
}

/** The per-request database resolver each plugin closes over. */
export function databaseResolver(options: AdminRoutesOptions): () => Promise<Database.Database> {
  return async () => options.db ?? (await getDb());
}

/**
 * The `code` better-sqlite3 puts on a constraint failure, or `undefined` for
 * anything that is not one.
 *
 * Matched on `code` rather than on the message. The messages name columns —
 * `UNIQUE constraint failed: users.username_folded` — and a route that branches
 * on that string both leaks the schema when it echoes it and breaks silently the
 * next time a migration renames anything.
 */
function constraintCode(error: unknown): string | undefined {
  if (typeof error !== "object" || error === null) return undefined;
  const code: unknown = (error as { code?: unknown }).code;
  return typeof code === "string" && code.startsWith("SQLITE_CONSTRAINT_") ? code : undefined;
}

/** A PRIMARY KEY or UNIQUE collision — a duplicate slug, a taken username. */
export function isUniqueViolation(error: unknown): boolean {
  const code = constraintCode(error);
  return code === "SQLITE_CONSTRAINT_UNIQUE" || code === "SQLITE_CONSTRAINT_PRIMARYKEY";
}

/**
 * A CHECK refusing the row — most importantly `public_registration = 0 OR
 * baseline_role IS NOT NULL`, the schema half of "an app cannot be open to
 * strangers without saying what that confers".
 *
 * The routes validate for this *before* writing so the caller gets a specific
 * code; this is the backstop that keeps the schema from ever surfacing as a
 * `500`, and it also catches the CHECKs the routes do not pre-empt (a slug that
 * is not lower case, an empty name).
 */
export function isCheckViolation(error: unknown): boolean {
  return constraintCode(error) === "SQLITE_CONSTRAINT_CHECK";
}

/**
 * A foreign key with nothing to point at — a grant naming a subject or a slug
 * that does not exist.
 *
 * The grant routes look both up first for a clean 404, and still catch this:
 * between the lookup and the insert an app can be deleted, and the database is
 * the only thing that observes both at once.
 */
export function isForeignKeyViolation(error: unknown): boolean {
  return constraintCode(error) === "SQLITE_CONSTRAINT_FOREIGNKEY";
}

/** An `apps` row as JSON. `publicRegistration` is a boolean, not SQLite's 0/1. */
export interface AppView {
  slug: string;
  name: string;
  publicRegistration: boolean;
  /** Null whenever registration is closed — closing clears it, deliberately. */
  baselineRole: string | null;
  createdAt: string;
  updatedAt: string;
}

export function appView(row: AppRow): AppView {
  return {
    slug: row.slug,
    name: row.name,
    publicRegistration: row.public_registration === 1,
    baselineRole: row.baseline_role,
    createdAt: row.created_at,
    updatedAt: row.updated_at,
  };
}

/**
 * A `users` row as JSON. **No `password_hash`**, and that omission is the reason
 * this mapper exists rather than the route spreading the row.
 */
export interface AccountView {
  subject: string;
  username: string;
  email: string | null;
  emailVerified: boolean;
  /** The question a console list actually asks; `disabledAt` says when. */
  disabled: boolean;
  disabledAt: string | null;
  createdAt: string;
  updatedAt: string;
}

export function accountView(row: UserRow): AccountView {
  return {
    subject: row.subject,
    username: row.username,
    email: row.email,
    emailVerified: row.email_verified === 1,
    disabled: row.disabled_at !== null,
    disabledAt: row.disabled_at,
    createdAt: row.created_at,
    updatedAt: row.updated_at,
  };
}

/**
 * A `grants` row as JSON.
 *
 * `grantedBy` is a subject **or** the string `superuser`, and is deliberately
 * not resolvable to an account: the identity that issues the estate's first
 * grants has no `users` row. Brief 10 renders it as-is.
 */
export interface GrantView {
  subject: string;
  appSlug: string;
  role: string;
  grantedAt: string;
  grantedBy: string;
}

export function grantView(row: GrantRow): GrantView {
  return {
    subject: row.subject,
    appSlug: row.app_slug,
    role: row.role,
    grantedAt: row.granted_at,
    grantedBy: row.granted_by,
  };
}

/**
 * The slug rule.
 *
 * The schema requires only `slug <> '' AND slug = lower(slug)`, which a slug
 * containing a space or a `:` would satisfy. This is stricter on purpose: a slug
 * appears in six apps' configuration, in `audit_log.target_id`, and in URLs, and
 * `grantTargetId` percent-encodes it precisely because nothing forbids a colon.
 * Keeping new slugs to `[a-z0-9]` groups joined by single hyphens means none of
 * that ever has to be thought about again — and `atrium`, `newspapper`, `prm`
 * and `public-resource-map` all already conform.
 *
 * **Roles get no equivalent rule**, and must not: role strings are opaque by
 * decision, and narrowing what one may contain to make a delimiter safe would be
 * solving the wrong problem.
 */
export const SLUG_PATTERN = /^[a-z0-9]+(?:-[a-z0-9]+)*$/;
