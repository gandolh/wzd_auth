/**
 * The introspection answer, mirrored from `api/src/grants/resolve.ts`'s public
 * shape. `@ward/client` consumes `POST /introspect`'s response verbatim.
 */

/**
 * Every role an account holds, keyed by app slug — `{ atrium: ["admin"] }`.
 *
 * An app absent from the map means **no access to that app at all**. Roles are
 * an opaque **set**: test membership with `hasGrant`, never equality, and
 * never interpret what a role string means — that meaning belongs to the app
 * that defined the role, not to this package or to Ward.
 */
export type GrantsByApp = Record<string, string[]>;

/** A live session, with the identity and authority an app is entitled to. */
export interface ActiveSession {
  readonly active: true;
  readonly subject: string;
  readonly username: string;
  readonly grants: GrantsByApp;
}

/**
 * Not live — and that is the entire answer. Expired, revoked, disabled,
 * unknown, and a console token all produce this identical shape; Ward never
 * says which, and this package must not try to guess.
 */
export interface InactiveSession {
  readonly active: false;
}

/** The introspection answer. */
export type SessionResolution = ActiveSession | InactiveSession;

/**
 * Whether `grants` includes `role` for `app`. **Always use this** — never
 * `grants[app] === [role]` or any other equality check, and never branch on
 * what a role string means beyond "does the caller hold it".
 */
export function hasGrant(grants: GrantsByApp, app: string, role: string): boolean {
  return grants[app]?.includes(role) ?? false;
}
