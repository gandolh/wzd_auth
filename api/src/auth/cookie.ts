import { ACCESS_TOKEN_TTL_SECONDS } from "../tokens/claims.js";

/**
 * Ward's session cookies: their names, their scopes, and the serialisation.
 *
 * No `@fastify/cookie`. Two cookies with fixed attributes is about forty lines
 * of `Set-Cookie` assembly, and the brief forbids adding a dependency — but the
 * better reason is that the attributes here are the security boundary, and
 * having them written out where they can be read beats having them spread
 * across a plugin's option bag.
 *
 * ## Two cookies with deliberately different scopes
 *
 * | | name | path | lifetime |
 * |---|---|---|---|
 * | access | `ward_session` | `/` | 15 minutes |
 * | refresh | `ward_refresh` | `/ward-api/refresh` | 30 days |
 *
 * The **access** cookie is at `Path=/` because that is the whole SSO mechanism:
 * the estate is one origin (`corpus/wiki/decisions.md`), so a `Path=/` cookie
 * reaches atrium, newspapper, prm and everything else with no redirect dance.
 * Its name is fixed by decision — `ward_session`, recorded in decisions.md
 * alongside the `/ward-api` deploy path.
 *
 * The **refresh** cookie is scoped to `Path=/ward-api/refresh` and this is the
 * point of having two. A 30-day credential that can mint fresh access tokens is
 * the most valuable thing Ward hands out; sending it on every image request in
 * six apps would put it in front of every logging, caching and proxy layer in
 * the estate for no benefit at all. Scoped to one path, the browser only ever
 * discloses it to the one endpoint that consumes it.
 *
 * ## `/ward-api/refresh` is the *browser's* path, not Fastify's
 *
 * Caddy serves Ward with `handle_path /ward-api/*`, which strips the prefix, so
 * the route is registered at `/refresh` inside Fastify while the browser sees
 * `/ward-api/refresh`. A cookie `Path` is matched by the browser against the
 * URL it is requesting, so it must carry the *public* path. Getting this
 * backwards produces a cookie that is never sent, which surfaces as "refresh
 * always 401s in production and works fine in tests".
 *
 * ## `SameSite=Lax` is also the CSRF defence
 *
 * `/refresh` and `/logout` are state-changing `POST`s with no CSRF token. They
 * do not need one: `Lax` means the browser withholds these cookies from any
 * cross-site `POST`, so a form on `evil.example` cannot reach either endpoint
 * with credentials attached. `Strict` was not chosen because it also withholds
 * the access cookie on the top-level navigation that returns a person from the
 * login page to `?next=`, which would break SSO on the first hop. Do not
 * relax this to `None` — that reintroduces the CSRF surface *and* requires
 * `Secure` unconditionally.
 */

/**
 * The access-token cookie. **Brief 04 reads this**, and brief 08's
 * `@ward/client` is the only thing that should teach an app the name — no app
 * hard-codes it.
 */
export const ACCESS_COOKIE_NAME = "ward_session";

/** The refresh-token cookie. Only `POST /ward-api/refresh` and `/logout` see it. */
export const REFRESH_COOKIE_NAME = "ward_refresh";

/** `Path=/` — the estate is one origin, so this reaches every app. */
export const ACCESS_COOKIE_PATH = "/";

/**
 * `Path=/ward-api/refresh` — the browser-visible path, prefix included.
 * See the note above about `handle_path` stripping it before Fastify sees it.
 */
export const REFRESH_COOKIE_PATH = "/ward-api/refresh";

/**
 * Refresh-token lifetime: **30 days**, per `corpus/wiki/decisions-tokens.md`
 * ("15-minute access tokens, 30-second introspection cache").
 *
 * This is both the cookie's `Max-Age` and the row's `expires_at`, and they are
 * the same constant on purpose — a cookie that outlives its row produces a
 * client that keeps presenting a credential Ward has already forgotten.
 */
export const REFRESH_TOKEN_TTL_SECONDS = 30 * 24 * 60 * 60;

/** The access cookie's `Max-Age`, kept equal to the token's own `exp`. */
export const ACCESS_COOKIE_MAX_AGE_SECONDS = ACCESS_TOKEN_TTL_SECONDS;

/** The attributes this module will emit. Not general-purpose; Ward's set only. */
export interface CookieOptions {
  name: string;
  value: string;
  path: string;
  /** Omitted entirely for a session cookie; `0` to expire immediately. */
  maxAgeSeconds?: number;
  /** See `secureCookiesFor` — never hard-code `true` at a call site. */
  secure: boolean;
}

/**
 * A cookie name must be an RFC 6265 token and a value must avoid the separator
 * set. Both of Ward's values are already safe — a compact JWS is
 * base64url-with-dots and a refresh token is hex — so this exists to make a
 * future value that *is not* safe fail loudly here rather than emit a header
 * that a browser silently truncates at the first stray character.
 */
const COOKIE_NAME_PATTERN = /^[!#$%&'*+\-.^_`|~0-9A-Za-z]+$/;
const COOKIE_VALUE_PATTERN = /^[!#-+\--:<-[\]-~]*$/;

/**
 * Build one `Set-Cookie` value.
 *
 * `HttpOnly` and `SameSite=Lax` are unconditional — there is no parameter for
 * them, because there is no Ward cookie that should be readable from JavaScript
 * or sent on a cross-site POST, and an option is an invitation to set it wrong.
 */
export function serializeCookie(options: CookieOptions): string {
  if (!COOKIE_NAME_PATTERN.test(options.name)) {
    throw new TypeError(`serializeCookie: unsafe cookie name ${JSON.stringify(options.name)}`);
  }
  if (!COOKIE_VALUE_PATTERN.test(options.value)) {
    // Deliberately does NOT include the value in the message: this function is
    // only ever called with a token, and the message ends up in a log.
    throw new TypeError(`serializeCookie: unsafe cookie value for ${options.name}`);
  }

  const parts = [
    `${options.name}=${options.value}`,
    `Path=${options.path}`,
    "HttpOnly",
    "SameSite=Lax",
  ];

  if (options.secure) parts.push("Secure");

  if (options.maxAgeSeconds !== undefined) {
    parts.push(`Max-Age=${Math.trunc(options.maxAgeSeconds)}`);
    // `Expires` alongside `Max-Age` is redundant for every browser in use, and
    // is emitted only for the clearing case below where an ancient date is the
    // most compatible way to say "drop this now".
  }

  return parts.join("; ");
}

/**
 * The pair of `Set-Cookie` values that establish a session.
 *
 * `refreshMaxAgeSeconds` defaults to the full 30 days and is overridden on a
 * rotation, where `R2` inherits its family's absolute expiry and therefore has
 * less than 30 days left (see `refresh.ts`). A cookie outliving its row means
 * the client keeps presenting a credential Ward has already forgotten.
 */
export function sessionCookies(params: {
  accessToken: string;
  refreshToken: string;
  secure: boolean;
  refreshMaxAgeSeconds?: number;
}): [string, string] {
  return [
    serializeCookie({
      name: ACCESS_COOKIE_NAME,
      value: params.accessToken,
      path: ACCESS_COOKIE_PATH,
      maxAgeSeconds: ACCESS_COOKIE_MAX_AGE_SECONDS,
      secure: params.secure,
    }),
    serializeCookie({
      name: REFRESH_COOKIE_NAME,
      value: params.refreshToken,
      path: REFRESH_COOKIE_PATH,
      maxAgeSeconds: params.refreshMaxAgeSeconds ?? REFRESH_TOKEN_TTL_SECONDS,
      secure: params.secure,
    }),
  ];
}

/**
 * The pair of `Set-Cookie` values that destroy a session.
 *
 * **`Path` and `Secure` must match what was set**, or the browser treats these
 * as two *different* cookies and leaves the originals in place — the classic
 * "logout doesn't log out" bug. That is why this takes `secure` rather than
 * omitting it: a cleared cookie emitted without `Secure` where the original had
 * it can be shadowed rather than replaced.
 *
 * Both an empty value and `Max-Age=0` are sent, plus a 1970 `Expires` for the
 * benefit of anything that ignores `Max-Age`.
 */
export function clearedSessionCookies(params: { secure: boolean }): [string, string] {
  return [
    clearCookie(ACCESS_COOKIE_NAME, ACCESS_COOKIE_PATH, params.secure),
    clearCookie(REFRESH_COOKIE_NAME, REFRESH_COOKIE_PATH, params.secure),
  ];
}

function clearCookie(name: string, path: string, secure: boolean): string {
  return `${serializeCookie({ name, value: "", path, maxAgeSeconds: 0, secure })}; Expires=Thu, 01 Jan 1970 00:00:00 GMT`;
}

/**
 * Read one cookie out of a `Cookie` request header.
 *
 * Returns the **first** occurrence. A duplicate cookie name is either a client
 * bug or a cookie-shadowing attempt (setting `ward_session` on a parent domain
 * to sit in front of the real one); the browser sends the more specific path
 * first, and taking the first match is the conventional and safer of the two
 * readings.
 *
 * Brief 04 needs exactly this to pull the access token out of a request:
 * `readCookie(request.headers.cookie, ACCESS_COOKIE_NAME)`.
 */
export function readCookie(
  header: string | string[] | undefined,
  name: string,
): string | undefined {
  if (header === undefined) return undefined;

  const flat = Array.isArray(header) ? header.join("; ") : header;

  for (const pair of flat.split(";")) {
    const eq = pair.indexOf("=");
    if (eq === -1) continue;
    if (pair.slice(0, eq).trim() !== name) continue;

    const value = pair.slice(eq + 1).trim();
    // A cleared cookie can still be presented by a client that ignored the
    // expiry. Treat an empty value as absent rather than as a token.
    return value.length > 0 ? value : undefined;
  }

  return undefined;
}

/**
 * Whether Ward's cookies carry `Secure`, derived from `WARD_PUBLIC_ORIGIN`.
 *
 * `Secure` **unless** the public origin is plain HTTP on loopback. The
 * exception exists because a `Secure` cookie is not stored at all over
 * `http://127.0.0.1`, so without it nobody could run the login flow locally
 * without terminating TLS first — and the workaround people reach for instead
 * is dropping `Secure` everywhere.
 *
 * Note the shape of the failure this cannot produce: the condition is
 * `http:` **and** loopback, so a plain-HTTP origin on a real hostname — the
 * genuinely dangerous case, a session cookie crossing a network in the clear —
 * still gets `Secure` and simply does not work. That is the correct direction
 * to fail in. There is no environment flag and no `NODE_ENV` branch, matching
 * brief 00's decision that the environment contract has no environment branch.
 */
export function secureCookiesFor(publicOrigin: string): boolean {
  let url: URL;
  try {
    url = new URL(publicOrigin);
  } catch {
    // `config.ts` already validated this as a bare origin, so an unparseable
    // value means something bypassed config. Fail closed.
    return true;
  }

  if (url.protocol !== "http:") return true;

  const host = url.hostname.toLowerCase();
  const isLoopback =
    host === "localhost" ||
    host === "127.0.0.1" ||
    host === "[::1]" ||
    host === "::1" ||
    host.startsWith("127.");

  return !isLoopback;
}

let secureCookiesPromise: Promise<boolean> | undefined;

/**
 * `secureCookiesFor(WARD_PUBLIC_ORIGIN)`, resolved once per process.
 *
 * The `config.js` import is **dynamic** for the reason `db/connection.ts`
 * documents at length: a static import is hoisted, so it would run zod
 * validation — and its `process.exit(1)` — merely because something imported
 * `serializeCookie`. Keeping it dynamic is what lets a cookie test run with no
 * environment set at all.
 */
export async function wardSecureCookies(): Promise<boolean> {
  secureCookiesPromise ??= (async () => {
    const { WARD_PUBLIC_ORIGIN } = await import("../config.js");
    return secureCookiesFor(WARD_PUBLIC_ORIGIN);
  })();
  return secureCookiesPromise;
}

/** Drop the memoised value. Tests only. */
export function resetCookieConfigForTests(): void {
  secureCookiesPromise = undefined;
}
