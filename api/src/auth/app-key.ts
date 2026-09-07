import type Database from "better-sqlite3";
import type { FastifyRequest } from "fastify";

import {
  findAppKeyByHash,
  hashAppKey,
  looksLikeAppKey,
  touchAppKey,
  type AppKeyRow,
} from "../db/app-keys.js";

/**
 * The app-key guard — what stands in front of `POST /introspect`.
 *
 * ## The header, and why it is not `Authorization`
 *
 * `x-ward-app-key`. A dedicated header rather than `Authorization: Bearer`,
 * because `/introspect` already carries a bearer credential in its body (the
 * access token being introspected) and, on the browser path that used to exist,
 * in a cookie. Three credentials in one request is confusing enough without two
 * of them sharing a header name — and a `Bearer` scheme would invite exactly the
 * mistake the endpoint most needs to avoid, an app putting the **user's** token
 * where the **app's** key goes and getting an answer that looks plausible.
 *
 * ## The check runs before anything expensive
 *
 * `resolveAppKey` is a shape test, one `sha256`, and one indexed read. It is
 * ordered ahead of token verification in the route deliberately: the endpoint is
 * published on the public origin (`vps-deploy/stacks/ward.ts` serves
 * `handle_path /ward-api/*`), so an unauthenticated caller must be refused
 * before Ward does any Ed25519 work or any grant resolution on their behalf.
 * That ordering is the whole DoS argument for this feature; reversing it for
 * tidiness would give it away.
 *
 * ## There is still no rate limit here, and that is still deliberate
 *
 * `routes/introspect.ts` argues at length that a lockout on this surface takes
 * the estate down rather than degrading an attacker, because every app reads a
 * `429` as "not live". That argument survives this change and is not weakened by
 * it — what changes is that the surface is no longer anonymous, so a limit *can*
 * now be applied per key, without estate-wide blast radius, if one is ever
 * wanted. Nothing here counts anything today.
 *
 * The brute-force question the missing limit raises is answered by arithmetic
 * rather than by counting: a key is 256 bits of `randomBytes`
 * (`db/app-keys.ts#mintAppKeyValue`), so guessing is not a threat a counter
 * would help with.
 *
 * ## Failure is one answer
 *
 * Absent, malformed, unknown and revoked all produce the same refusal at the
 * route. The distinction is in the server log for an operator, not in the
 * response — the same rule `/login` and `/introspect` already follow, and here it
 * additionally means a caller cannot use the endpoint to discover whether a key
 * they hold has been revoked or never existed.
 */

/** The header an app presents its key in. Lower case: Fastify normalises. */
export const APP_KEY_HEADER = "x-ward-app-key";

/** Why a presented key was refused. For the log, never for the response body. */
export type AppKeyRejection = "absent" | "malformed" | "unknown" | "revoked";

/** A key that authenticated. The route puts `appSlug` on the log line. */
export interface AuthenticatedApp {
  /** `app_keys.id` — the non-secret handle, safe to log and to render. */
  keyId: string;
  appSlug: string;
}

export type AppKeyResolution =
  | { readonly ok: true; readonly app: AuthenticatedApp }
  | { readonly ok: false; readonly reason: AppKeyRejection };

/**
 * Pull the key out of the request headers.
 *
 * A repeated header arrives as an array. That is rejected rather than resolved
 * by taking the first: two different keys in one request is a caller bug or an
 * injection attempt, and picking one of them silently decides which app the
 * request is attributed to.
 */
export function readAppKeyHeader(request: FastifyRequest): string | undefined {
  const value: unknown = request.headers[APP_KEY_HEADER];
  return typeof value === "string" && value.length > 0 ? value : undefined;
}

/**
 * The `last_used_at` throttle.
 *
 * Keyed by `app_keys.id`, holding the epoch millisecond of the last stamp this
 * **process** wrote. Module-level and unbounded in principle; bounded in
 * practice by the number of keys in the estate, which is a handful — one per
 * app, plus whatever is mid-rotation. It is not a cache of anything and holds no
 * credential: losing it on restart costs one extra `UPDATE` per key.
 *
 * An hour is the window because the question this column answers is "has this
 * key been used recently enough that revoking it will break something", and that
 * question does not get a better answer from a finer stamp. See the migration.
 */
const TOUCH_INTERVAL_MS = 60 * 60 * 1000;
const lastTouched = new Map<string, number>();

/** Test seam: the throttle is process state, so a test must be able to clear it. */
export function resetAppKeyTouchThrottle(): void {
  lastTouched.clear();
}

/**
 * Record use, at most once per hour per key.
 *
 * Never throws into the caller's path. This is bookkeeping for a human reading
 * the console, and a failure to write it must not turn an authenticated request
 * into a refused one — the estate's every request depends on this endpoint
 * answering.
 */
function recordUse(db: Database.Database, row: AppKeyRow, now: number): void {
  const previous = lastTouched.get(row.id);
  if (previous !== undefined && now - previous < TOUCH_INTERVAL_MS) return;

  lastTouched.set(row.id, now);
  try {
    touchAppKey(db, row.id, new Date(now).toISOString());
  } catch {
    // Swallowed on purpose, and the only `catch` in this file that is. A
    // read-only database or a locked writer must not sign the estate out.
  }
}

/**
 * Resolve a presented key to the app it authenticates, or say why not.
 *
 * Pure apart from the throttled `last_used_at` write. Takes the raw header value
 * so the route can log a rejection without the value ever being formatted into
 * a message.
 */
export function resolveAppKey(
  db: Database.Database,
  presented: string | undefined,
  now: number = Date.now(),
): AppKeyResolution {
  if (presented === undefined) return { ok: false, reason: "absent" };

  // Shape first, so a header full of junk costs no hash and no read.
  if (!looksLikeAppKey(presented)) return { ok: false, reason: "malformed" };

  const row = findAppKeyByHash(db, hashAppKey(presented));
  if (row === undefined) return { ok: false, reason: "unknown" };

  // A revoked key is a known row that authenticates nothing. Kept distinct from
  // `unknown` for the log — "the key you rotated last week is still deployed
  // somewhere" is a different operator problem from "somebody is guessing".
  if (row.revoked_at !== null) return { ok: false, reason: "revoked" };

  recordUse(db, row, now);

  return { ok: true, app: { keyId: row.id, appSlug: row.app_slug } };
}
