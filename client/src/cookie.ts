/**
 * Reading Ward's access cookie.
 *
 * **This is the package's job, not an app's.** No consumer of `@ward/client`
 * should know the cookie is named `ward_session`, or that it lives at
 * `Path=/` — that is Ward's implementation detail, reimplemented here from
 * `api/src/auth/cookie.ts` (this package may not import `api/`). If Ward ever
 * renamed the cookie, exactly one file in this package would need to change
 * and no consuming app would notice.
 *
 * The refresh cookie (`ward_refresh`, `Path=/ward-api/refresh`) is
 * deliberately absent from this package: refreshing is the browser talking to
 * Ward directly, never an app's business.
 */

/** Ward's access-token cookie name. Not exported — see the header. */
const ACCESS_COOKIE_NAME = "ward_session";

/**
 * Parse one named cookie out of a raw `Cookie` request header.
 *
 * Handles the header arriving as a single joined string or (as some HTTP
 * libraries expose it) an array of header lines, and treats an empty value —
 * a cleared cookie a client presented anyway — as absent rather than as an
 * empty token.
 */
function readCookie(header: string | string[] | undefined, name: string): string | undefined {
  if (header === undefined) return undefined;

  const flat = Array.isArray(header) ? header.join("; ") : header;

  for (const pair of flat.split(";")) {
    const eq = pair.indexOf("=");
    if (eq === -1) continue;
    if (pair.slice(0, eq).trim() !== name) continue;

    const value = pair.slice(eq + 1).trim();
    return value.length > 0 ? value : undefined;
  }

  return undefined;
}

/**
 * Read Ward's access token out of a raw `Cookie` header.
 *
 * Returns `undefined` when the header is absent or the cookie is not present
 * — never throws for a missing token, since "no token" is an ordinary,
 * expected case (an anonymous request) rather than an error.
 */
export function readAccessCookie(header: string | string[] | undefined): string | undefined {
  return readCookie(header, ACCESS_COOKIE_NAME);
}
