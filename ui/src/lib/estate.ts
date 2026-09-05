/**
 * The estate, as this UI needs to know it.
 *
 * Two questions are answered here and nowhere else, because they are the same
 * question asked twice: **which first path segments on this origin are real
 * apps**, and **what does a person call each one**.
 *
 * - `lib/next.ts` builds the `?next=` allowlist from `root`.
 * - `Login` names the destination it is about to hand somebody back to.
 * - `Register` names the app somebody is signing up for.
 * - `Account` names the apps a grant refers to.
 *
 * Adding an app to the estate is therefore **one line here**. That is a
 * deliberate cost: a redirect allowlist that grows by itself is not an
 * allowlist, and the failure mode of forgetting a line is a redirect that
 * lands on `/` instead of the app — visible, harmless, and fixed in one place.
 *
 * ## Why the roots are pages and never APIs
 *
 * `/atrium-api`, `/prm-api` and `/sports-app-api` are deliberately absent.
 * `?next=` exists to put a person back where they were, and nobody was
 * reading an API endpoint. Listing one would only widen the redirect surface
 * to a target no legitimate flow ever asks for.
 *
 * ## Slugs are not roots
 *
 * Ward's app **slug** (`apps.slug`, what `POST /register` takes) and the app's
 * **path root** on the origin are different strings for the same app — `prm` is
 * served at `/prm`, but the pairing is coincidence rather than a rule, and
 * `imbatranim-os` is one row where a naive derivation would be wrong. Both are
 * spelled out.
 */
export interface EstateApp {
  /** `apps.slug` in Ward's database — what `POST /register` takes as `app`. */
  readonly slug: string;
  /**
   * The first path segment the app is served under, with no slashes. `null`
   * for an app that has no page of its own on the origin, which is still a
   * valid registration target but never a valid `?next=`.
   */
  readonly root: string | null;
  /** What a person calls it. Used in prose; never matched on. */
  readonly name: string;
}

/**
 * Surveyed from `corpus/wiki/estate.md`. `design-study` and `saloon` are static
 * sites with no accounts — they carry no slug, but they are legitimate places
 * to be sent back to, so they hold a root and an empty slug is impossible to
 * express. They are listed with their own slug value because nothing keys on a
 * slug that Ward has no row for: `POST /register` would answer
 * `registration_closed`, which is the correct answer for a site with no
 * accounts.
 */
export const ESTATE_APPS: readonly EstateApp[] = [
  { slug: "atrium", root: "atrium", name: "Atrium" },
  { slug: "newspapper", root: "newspapper", name: "Newspapper" },
  { slug: "prm", root: "prm", name: "Public Resource Map" },
  { slug: "imbatranim-os", root: "imbatranim-os", name: "ImbatranimOS" },
  { slug: "sports-app", root: "sports-app", name: "Sports" },
  { slug: "trips", root: "trips", name: "Trips" },
  { slug: "design-study", root: "design-study", name: "Design Study" },
  { slug: "saloon", root: "saloon", name: "Saloon" },
  { slug: "ward", root: "ward", name: "Ward" },
] as const;

/**
 * The path roots `?next=` may name, as a set for exact segment matching.
 *
 * Exact, not prefix. Prefix matching would accept `/atriumX/` — same origin, so
 * not an open redirect, but a 404 the person cannot diagnose — and it invites
 * the next reader to relax it one step further to something that is.
 */
export const ESTATE_ROOTS: ReadonlySet<string> = new Set(
  ESTATE_APPS.map((app) => app.root).filter((root): root is string => root !== null),
);

/**
 * A display name for an app slug, or the slug itself.
 *
 * The fallback is the point. Ward's apps are rows an operator creates, not a
 * constant in this file, so a slug this UI has never heard of is **ordinary**
 * rather than an error — and showing the raw slug is more use to somebody
 * signing up than "Unknown app" would be. There is no public endpoint that
 * returns `apps.name`, so this is the best available answer; see the brief's
 * handoff notes.
 */
export function appName(slug: string): string {
  return ESTATE_APPS.find((app) => app.slug === slug)?.name ?? slug;
}

/**
 * A display name for a path root, or the root itself.
 *
 * Used for the destination line on the login page, where the input is a
 * validated `?next=` path rather than a slug.
 */
export function rootName(root: string): string {
  return ESTATE_APPS.find((app) => app.root === root)?.name ?? root;
}
