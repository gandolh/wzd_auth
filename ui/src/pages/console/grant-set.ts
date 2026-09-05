/**
 * Grants, arranged the way an operator reads them.
 *
 * The API returns a flat list of `(subject, appSlug, role)` rows. The question
 * on the screen is "which apps can this account reach, and as what" — one row
 * per app, with the roles as a **set**. That reshaping is here rather than in a
 * component so it can be tested without a DOM.
 *
 * Roles are **opaque**: Ward stores the string and never interprets it, and
 * neither does this console. There is no known-role list anywhere in the UI, no
 * validation of what a role may mean, and no dropdown implying a fixed set — a
 * dropdown would quietly become the schema Ward deliberately does not have. The
 * roles already in use are offered as *suggestions* beside a free-text field,
 * which is what {@link roleSuggestions} is for.
 */

import type { GrantView } from "../../console-api.js";

/** Every role one account holds in one app. */
export interface AppRoleSet {
  appSlug: string;
  /** Sorted, so the set reads the same on every render. */
  roles: string[];
  /** The rows themselves, for `grantedAt` / `grantedBy` on each role. */
  grants: GrantView[];
}

/**
 * Group a flat grant list by app.
 *
 * Sorted by slug, and roles sorted within each app, because an operator scans
 * this list to decide who to trust and an order that shifts between renders
 * makes that harder than it needs to be. Locale-independent comparison
 * (`< `/`>`) on purpose: these are opaque identifiers, not words in a language.
 */
export function groupGrantsByApp(grants: GrantView[]): AppRoleSet[] {
  const byApp = new Map<string, GrantView[]>();
  for (const grant of grants) {
    const existing = byApp.get(grant.appSlug);
    if (existing === undefined) byApp.set(grant.appSlug, [grant]);
    else existing.push(grant);
  }

  return [...byApp.entries()]
    .map(([appSlug, rows]) => ({
      appSlug,
      roles: rows.map((row) => row.role).sort(compareOpaque),
      grants: [...rows].sort((a, b) => compareOpaque(a.role, b.role)),
    }))
    .sort((a, b) => compareOpaque(a.appSlug, b.appSlug));
}

/** Byte-order comparison. Opaque strings are not prose and get no collator. */
function compareOpaque(a: string, b: string): number {
  return a < b ? -1 : a > b ? 1 : 0;
}

/**
 * Roles already in use across the estate, most-used first, for a `<datalist>`.
 *
 * Suggestions, never a constraint. The field they hang off accepts anything.
 */
export function roleSuggestions(grants: GrantView[], limit = 12): string[] {
  const counts = new Map<string, number>();
  for (const grant of grants) {
    counts.set(grant.role, (counts.get(grant.role) ?? 0) + 1);
  }
  return [...counts.entries()]
    .sort((a, b) => b[1] - a[1] || compareOpaque(a[0], b[0]))
    .slice(0, limit)
    .map(([role]) => role);
}

/**
 * The apps this account holds no grant in — the "add access" shortlist.
 *
 * Given as slugs in the order the apps registry returned them, so the shortlist
 * matches the apps screen rather than re-sorting behind the operator's back.
 */
export function appsWithoutGrants(appSlugs: string[], grants: GrantView[]): string[] {
  const held = new Set(grants.map((grant) => grant.appSlug));
  return appSlugs.filter((slug) => !held.has(slug));
}

/**
 * What actually happened, for the line the operator reads after a write.
 *
 * The API is idempotent both ways and reports a no-op honestly: `created:false`
 * on a grant that was already there, `removed:0` on one that was not. A no-op
 * also writes **no audit row**, deliberately — auditing double-clicks buries
 * the rows an operator needs. So the console must not dress a no-op up as a
 * success: it says "already", which is true, and does not claim the log now
 * contains something it does not.
 */
export function describeGrantWrite(role: string, appSlug: string, created: boolean): string {
  return created
    ? `Granted ${role} in ${appSlug}.`
    : `${role} in ${appSlug} was already held. Nothing changed and no audit row was written.`;
}

/** The same honesty for a revoke, which reports a count rather than a flag. */
export function describeGrantRevoke(appSlug: string, removed: number, roles: string[]): string {
  if (removed === 0) {
    return `No roles held in ${appSlug}. Nothing changed and no audit row was written.`;
  }
  if (removed === 1) return `Revoked ${roles[0] ?? "one role"} in ${appSlug}.`;
  return `Revoked ${String(removed)} roles in ${appSlug}: ${roles.join(", ")}.`;
}
