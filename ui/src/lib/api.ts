/**
 * The browser's side of Ward's API.
 *
 * ## The paths are browser-side, and that is the whole trap
 *
 * Caddy serves Ward under `handle_path /ward-api/*`, which **strips** the
 * prefix, so `POST /ward-api/login` here is `POST /login` in Fastify. Vite's
 * dev proxy is configured to do exactly the same rewrite, so the code below
 * works unchanged in both — and the cookie `ward_refresh` is scoped
 * `Path=/ward-api/refresh`, meaning a path spelled the Fastify way would
 * produce a cookie the browser never sends. The symptom is "refresh always
 * 401s in production and works in tests", and it costs an afternoon.
 *
 * ## Everything comes back as a code, never as a sentence
 *
 * Ward answers `{ "error": "invalid_credentials" }` and never a message,
 * deliberately: the wording of an error belongs to the surface showing it, and
 * a server that ships prose ships six versions of it. So this module's job is
 * to turn a response into a `WardApiError` carrying a **stable code**, and each
 * page owns the sentence. That is also why `unreachable` is a code like any
 * other: a page has to say something when Ward is down, and having it arrive
 * through the same channel as `invalid_credentials` means no page can forget.
 */

/**
 * `Accept: application/json`, on every request.
 *
 * Not decoration. `GET /verify` content-negotiates — it answers a
 * server-rendered HTML page when `Accept` mentions `text/html`, because it is
 * the one endpoint a person reaches by clicking a link in a mail client. A
 * `fetch` that inherited the browser's default `Accept` would get that page
 * and `response.json()` would throw on `<!doctype html>`.
 */
const JSON_HEADERS: Readonly<Record<string, string>> = { accept: "application/json" };

/** Where Ward's API lives from the browser's point of view. See the header. */
export const WARD_API = "/ward-api";

/**
 * Every failure this UI knows how to say something about.
 *
 * The first group is Ward's own `error` strings, copied from the routes
 * (`api/src/routes/auth.ts` and `register.ts`). The last two are this module's:
 * `unreachable` for a fetch that never got an answer, and `unexpected` for a
 * status or body shape nothing here anticipated — which is a bug, and is
 * rendered as one rather than silently mapped onto a plausible neighbour.
 */
export type WardErrorCode =
  // /login
  | "invalid_request"
  | "invalid_credentials"
  | "account_disabled"
  | "too_many_attempts"
  // /refresh, /logout
  | "invalid_refresh"
  | "cross_site"
  // /register
  | "registration_closed"
  | "username_taken"
  | "password_too_short"
  | "password_too_long"
  // /verify
  | "expired_token"
  | "invalid_token"
  // /account, /account/password, /account/sessions/revoke-others — a dead
  // session, distinctly from `invalid_credentials` (a wrong *current*
  // password) and from `unexpected` (a bug). Rendered as "you were signed
  // out", never as a failure to explain.
  | "unauthorized"
  // this module's own
  | "unreachable"
  | "unexpected";

export class WardApiError extends Error {
  readonly code: WardErrorCode;
  /** The HTTP status, or `0` when the request never completed. */
  readonly status: number;
  /**
   * From a `429`'s body. Ward repeats it there as well as in `Retry-After`
   * specifically so a browser client can render the wait without reading a
   * header — see `lockedOut` in `api/src/routes/auth.ts`.
   */
  readonly retryAfterSeconds?: number;

  constructor(code: WardErrorCode, status: number, retryAfterSeconds?: number) {
    super(`ward: ${code} (${String(status)})`);
    this.name = "WardApiError";
    this.code = code;
    this.status = status;
    this.retryAfterSeconds = retryAfterSeconds;
  }
}

const ERROR_CODES: ReadonlySet<string> = new Set<WardErrorCode>([
  "invalid_request",
  "invalid_credentials",
  "account_disabled",
  "too_many_attempts",
  "invalid_refresh",
  "cross_site",
  "registration_closed",
  "username_taken",
  "password_too_short",
  "password_too_long",
  "expired_token",
  "invalid_token",
  "unauthorized",
]);

/**
 * Pull a known code out of an error body, or say `unexpected`.
 *
 * Exported for its own test: the mapping is the part of this module that has
 * to stay in step with the API, and an unrecognised code becoming
 * `unexpected` rather than being passed through as a string is what stops a
 * page rendering `{"error":"whatever"}` at somebody.
 */
export function errorCodeFrom(body: unknown): WardErrorCode {
  if (typeof body !== "object" || body === null) return "unexpected";
  // `Object.hasOwn`, not a plain read. `JSON.parse` never sets a prototype, so
  // a body straight off the wire cannot inherit an `error` — but this function
  // takes `unknown` and is exported, and "the code came from somewhere up the
  // prototype chain" is not a sentence anything here should be able to say.
  if (!Object.hasOwn(body, "error")) return "unexpected";
  const code: unknown = (body as { error?: unknown }).error;
  if (typeof code !== "string" || !ERROR_CODES.has(code)) return "unexpected";
  return code as WardErrorCode;
}

/**
 * The `retryAfterSeconds` from a `429` body, clamped into something a
 * countdown can render.
 *
 * Clamped rather than trusted because the value drives a disabled submit
 * button: a missing or absurd number would either unlock the form immediately
 * or lock it for a week, and both are worse than the API's own five-minute
 * ceiling. One hour is a bound no legitimate lockout reaches.
 */
export function retryAfterFrom(body: unknown): number {
  const raw: unknown =
    typeof body === "object" && body !== null && Object.hasOwn(body, "retryAfterSeconds")
      ? (body as { retryAfterSeconds?: unknown }).retryAfterSeconds
      : undefined;
  if (typeof raw !== "number" || !Number.isFinite(raw) || raw <= 0) return 1;
  return Math.min(Math.ceil(raw), 3600);
}

async function parseBody(response: Response): Promise<unknown> {
  // A `204` has no body, and `.json()` on an empty one throws. So does an HTML
  // error page from a proxy, which is what a `502` looks like in production.
  if (response.status === 204) return undefined;
  try {
    return await response.json();
  } catch {
    return undefined;
  }
}

/**
 * One request, one of two outcomes: the parsed body, or a thrown
 * `WardApiError`.
 *
 * `credentials: "same-origin"` is stated rather than left to the default. It
 * *is* the default for a same-origin request, but the estate's whole session
 * model is "one cookie at `Path=/` on one origin", and the line that carries
 * the cookie should be visible in the file rather than implied.
 */
async function request<T>(path: string, init: RequestInit): Promise<T> {
  let response: Response;
  try {
    response = await fetch(`${WARD_API}${path}`, {
      credentials: "same-origin",
      ...init,
      headers: { ...JSON_HEADERS, ...init.headers },
    });
  } catch {
    // A network failure, a DNS failure, an aborted request, Ward being down.
    // Indistinguishable from here and identical in treatment.
    throw new WardApiError("unreachable", 0);
  }

  const body = await parseBody(response);
  if (!response.ok) {
    const code = errorCodeFrom(body);
    throw new WardApiError(
      code,
      response.status,
      code === "too_many_attempts" ? retryAfterFrom(body) : undefined,
    );
  }
  return body as T;
}

function postJson<T>(path: string, body?: unknown): Promise<T> {
  return request<T>(path, {
    method: "POST",
    headers: body === undefined ? {} : { "content-type": "application/json" },
    body: body === undefined ? undefined : JSON.stringify(body),
  });
}

// ---------------------------------------------------------------------------
// The routes, one function each. Shapes copied from the briefs that built them.
// ---------------------------------------------------------------------------

export interface LoginResult {
  subject: string;
  username: string;
  emailVerified: boolean;
  accessTokenExpiresAt: string;
  refreshTokenExpiresAt: string;
}

/**
 * `POST /ward-api/login`. Sets both cookies; returns the identity and never a
 * token — the access token is `HttpOnly`, which is the point.
 *
 * `401 invalid_credentials` is **identical for an unknown username and a wrong
 * password**, by design, and the caller must render it as one thing.
 * `403 account_disabled` only ever arrives *after* the password verified, so
 * the person holding the response is the account holder and it is safe to say
 * plainly.
 */
export function login(username: string, password: string): Promise<LoginResult> {
  return postJson<LoginResult>("/login", { username, password });
}

export interface RefreshResult {
  subject: string;
  accessTokenExpiresAt: string;
  refreshTokenExpiresAt: string;
}

/**
 * `POST /ward-api/refresh`. Rotates: the presented token dies, a new one
 * arrives in the cookie.
 *
 * **Every failure is `401 invalid_refresh`** whatever went wrong — unknown,
 * expired, revoked, replayed or raced — so there is exactly one treatment:
 * send the person to login. Do not branch on it.
 */
export function refresh(): Promise<RefreshResult> {
  return postJson<RefreshResult>("/refresh");
}

/**
 * `POST /ward-api/logout`. Always `204`.
 *
 * Kills the presented token's family only, so signing out here leaves the same
 * person's other devices signed in. That is why "sign out my other devices" is
 * a separate thing and not this call with a flag.
 *
 * Must be a `fetch` and not a form POST: the route refuses a request whose
 * `Sec-Fetch-Site` or `Origin` says cross-site, and a form navigation from
 * another origin is precisely the shape it is refusing.
 */
export async function logout(): Promise<void> {
  await postJson<undefined>("/logout");
}

export interface IntrospectResult {
  active: boolean;
  subject?: string;
  username?: string;
  /** `{ atrium: ["admin"], … }`. Absent when `active` is false. */
  grants?: Record<string, string[]>;
}

/**
 * `POST /ward-api/introspect`. **Always `200`**, even for a dead session — the
 * answer is in `active`, and there is deliberately no 4xx for a credential
 * problem, so `catch` here means the network broke and nothing else.
 *
 * This is the only endpoint that reads back a person's own grants, which is
 * what the self-service grants view is built on.
 */
export function introspect(): Promise<IntrospectResult> {
  return postJson<IntrospectResult>("/introspect");
}

export interface RegisterInput {
  app: string;
  username: string;
  email: string;
  password: string;
}

export interface RegisterResult {
  subject: string;
  username: string;
  email: string;
  emailVerified: boolean;
  app: string;
  role: string;
  /** `false` means the account is real and the mail did not go out. */
  verificationSent: boolean;
  verificationExpiresAt: string;
}

/**
 * `POST /ward-api/register`. `201` and **no cookie**: registering does not sign
 * anybody in, so the caller's next move is the login form.
 *
 * `403 registration_closed` covers a closed app *and* an app that does not
 * exist, identically, so `/register` is not also an app-discovery oracle. A
 * fresh estate answers it to everything until the console creates an app, which
 * means it is a **state**, not an error, and must not be rendered as a failure.
 */
export function register(input: RegisterInput): Promise<RegisterResult> {
  return postJson<RegisterResult>("/register", input);
}

export interface AccountResult {
  subject: string;
  username: string;
  /** `null` for an owner-issued account — it was never given an address. */
  email: string | null;
  emailVerified: boolean;
  createdAt: string;
}

/**
 * `GET /ward-api/account` — the caller's own record, including the two fields
 * `/introspect` deliberately never carries: `email` and `emailVerified`.
 *
 * Cookie-authenticated the same way as the two mutations below — verify, then
 * `resolveSession` for liveness — so a **`401 unauthorized`** means the session
 * is dead, not that something broke. There is no statusless answer here the
 * way there is on `/introspect`: this is a person's own browser reading their
 * own record, and there is no third party for a status code to leak anything
 * to.
 */
export function getAccount(): Promise<AccountResult> {
  return request<AccountResult>("/account", { method: "GET" });
}

export interface ChangePasswordResult {
  subject: string;
  /**
   * How many refresh families this change ended, **including the caller's own
   * previous one** — it was revoked and replaced by the fresh pair that
   * arrived in this response's cookies, not left alive alongside them. A
   * person with exactly one device sees `1` here, and that is not "one other
   * device was found and signed out" — it is "the credential you were holding
   * a moment ago is dead", which the new cookies already fixed. Never render
   * this number as a device count; see `Account.tsx`.
   */
  sessionsRevoked: number;
  accessTokenExpiresAt: string;
  refreshTokenExpiresAt: string;
}

/**
 * `POST /ward-api/account/password` — change my own password.
 *
 * The current password is verified server-side before anything else; a
 * self-service change that skipped that check would be an account takeover
 * one XSS or one borrowed laptop away, with no recovery channel behind it for
 * an owner-issued account. On success every refresh family for the account is
 * revoked and one fresh pair is issued to the caller, so the response's
 * cookies keep this browser signed in while every other holder of the old
 * credential — including this browser's own previous session — is signed out.
 *
 * Errors: `401 invalid_credentials` for a wrong current password (the same
 * code `/login` uses for a wrong password generally); `400
 * password_too_short` / `password_too_long` for the new one;
 * `429 too_many_attempts` on **its own lockout budget**, independent of
 * `/login`'s — a person locked out here can still sign in, and the copy must
 * not imply otherwise; `401 unauthorized` for a dead session.
 */
export function changeOwnPassword(
  currentPassword: string,
  newPassword: string,
): Promise<ChangePasswordResult> {
  return postJson<ChangePasswordResult>("/account/password", { currentPassword, newPassword });
}

export interface RevokeOthersResult {
  /** Families (devices) ended. Rendered — this is the number that reassures. */
  revoked: number;
  /** Rows revoked, which can exceed `revoked` inside a refresh race. Not rendered. */
  tokensRevoked: number;
  /** This session's own family, spared by the call. An implementation detail. */
  spared: string;
}

/**
 * `POST /ward-api/account/sessions/revoke-others` — sign out my other
 * devices, and the feature the self-service page exists for: owner-issued
 * accounts carry no verified email and therefore no recovery channel, so this
 * is the only self-serve response to a suspected stolen session.
 *
 * Ends every refresh family for the account **except** the one the caller's
 * own access token names, so the browser that made the request stays signed
 * in throughout. `401 unauthorized` for a dead session; `403 cross_site` for
 * a cross-site POST, refused the same way `/logout` and `/refresh` are.
 */
export function revokeOtherSessions(): Promise<RevokeOthersResult> {
  return postJson<RevokeOthersResult>("/account/sessions/revoke-others");
}

export interface OpenAppView {
  slug: string;
  name: string;
}

/**
 * `GET /ward-api/apps` — the apps a stranger may register at. **Anonymous**,
 * and a bare array: the console's list carries a total and filters because it
 * is superuser-only and can grow; this one is the estate's complete set of
 * open apps, a handful of rows at most.
 *
 * `[]` is a state, not a failure — a fresh estate has none, until the console
 * opens one. It exposes nothing an anonymous caller could not already learn by
 * posting to `/register` with a slug, and it says nothing at all about a
 * *closed* app, including whether one exists — see `api/src/routes/public-apps.ts`.
 */
export function listOpenApps(): Promise<OpenAppView[]> {
  return request<OpenAppView[]>("/apps", { method: "GET" });
}

/**
 * `GET /ward-api/verify?token=…`. Single-use and time-limited.
 *
 * `400 expired_token` is its own code because it is the one a person can act
 * on; unknown, already-used and wrong-purpose all collapse to `invalid_token`,
 * so "I clicked twice" and "this was never a token" read the same.
 */
export async function verifyEmail(token: string): Promise<void> {
  await request<{ verified: true }>(`/verify?token=${encodeURIComponent(token)}`, {
    method: "GET",
  });
}
