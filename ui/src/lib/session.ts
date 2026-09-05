import { introspect, refresh, type IntrospectResult } from "./api.js";

/**
 * Who is signed in, and the one piece of state this UI keeps.
 *
 * ## Reading the session is two calls, not one
 *
 * The access cookie lives fifteen minutes. So "am I signed in" is:
 * introspect → if `active`, done; if not, **rotate once** and introspect again;
 * if it is still not active, the session is over. That second attempt is what
 * makes a fifteen-minute cookie invisible to somebody who left a tab open over
 * lunch, and without it self-service would sign people out every quarter of an
 * hour.
 *
 * One rotation and no more. `/refresh` answers `401 invalid_refresh` for every
 * failure there is, so a retry loop cannot learn anything from a second
 * attempt — and a client that loops on a dead refresh token against a service
 * six apps depend on is a denial of service with good intentions.
 *
 * ## Why the calls are de-duplicated at module level
 *
 * `main.tsx` runs under `StrictMode`, which double-invokes effects in
 * development precisely to surface this class of bug — and the bug is real
 * here, not theoretical. Two `/refresh` calls firing at the same moment is the
 * multi-tab race that cost brief 03 two review rounds to get right: the loser
 * of the single-use `UPDATE` used to sweep the winner's brand-new token and
 * destroy a live session. The API now survives it (a used token with a live
 * successor inside a ten-second grace is a race, not a theft), but *relying* on
 * that grace from inside one page would be spending somebody else's safety
 * margin. So the in-flight promise is shared: two callers, one request.
 *
 * The map is module-level rather than a ref, because the point is to be shared
 * across component instances — a `StrictMode` remount, two components mounting
 * together, a route change — and a ref is per instance.
 */

export type Session =
  | { readonly status: "loading" }
  | {
      readonly status: "signed-in";
      readonly subject: string;
      readonly username: string;
      /** `{ atrium: ["admin"], … }`, possibly empty — most accounts hold none. */
      readonly grants: Record<string, string[]>;
    }
  | { readonly status: "signed-out" }
  /** Ward did not answer. Distinct from signed-out: retrying is the fix. */
  | { readonly status: "unreachable" };

/** The single in-flight read, shared by every caller. */
let inFlight: Promise<Session> | undefined;

function fromIntrospection(result: IntrospectResult): Session | undefined {
  if (!result.active) return undefined;
  // `active: true` always carries the other three, but the response type says
  // "optional" because a dead session carries none of them. Treating a missing
  // subject as signed-out rather than asserting it means a schema change cannot
  // turn into a page rendering `undefined` at somebody.
  if (result.subject === undefined || result.username === undefined) return undefined;
  return {
    status: "signed-in",
    subject: result.subject,
    username: result.username,
    grants: result.grants ?? {},
  };
}

async function read(): Promise<Session> {
  let first: IntrospectResult;
  try {
    first = await introspect();
  } catch {
    // `/introspect` always answers `200`, so a throw here is the network and
    // never a credential. Saying "Ward isn't answering" is the honest reading;
    // saying "you are signed out" would be a lie that also loses the person's
    // place.
    return { status: "unreachable" };
  }

  const live = fromIntrospection(first);
  if (live !== undefined) return live;

  // The access token is expired or its family is gone. One rotation decides
  // which.
  try {
    await refresh();
  } catch {
    // `401 invalid_refresh` and a network failure both land here. They are
    // told apart by asking again below rather than by inspecting the error:
    // if Ward is unreachable the second introspect fails too, and if the
    // session is genuinely over it answers `active: false`.
    try {
      await introspect();
    } catch {
      return { status: "unreachable" };
    }
    return { status: "signed-out" };
  }

  try {
    const second = await introspect();
    return fromIntrospection(second) ?? { status: "signed-out" };
  } catch {
    return { status: "unreachable" };
  }
}

/**
 * Read the session, sharing one request with any concurrent caller.
 *
 * The promise is cleared once it settles, so the next call is a fresh read —
 * this is de-duplication, not a cache. Caching an authorisation answer in the
 * browser is how a revoked grant stays usable for a page's lifetime.
 */
export function readSession(): Promise<Session> {
  inFlight ??= read().finally(() => {
    inFlight = undefined;
  });
  return inFlight;
}
