/**
 * The console's HTTP client. Every call in the admin console goes through here.
 *
 * ## The one thing to get right: the base path
 *
 * `CONSOLE_API_BASE` is `/ward-api/console` and **every** request is built from
 * it. That is not tidiness, it is the reason the console works in a browser at
 * all. The `ward_console` cookie is issued with `Path=/ward-api/console`
 * (`api/src/auth/superuser.ts`), so the browser sends it only to URLs beneath
 * that prefix. Caddy's `handle_path /ward-api/*` strips the prefix before
 * Fastify sees it, which is why the server-side routes read `/console/...` —
 * the two are the same path seen from opposite sides.
 *
 * Build a request against `/console/...` or `/ward-api/...` instead and the
 * cookie is silently never sent: the call passes any test that stubs `fetch`,
 * and returns `401` forever in a real browser. `console-api.test.ts` asserts the
 * prefix on every method for exactly that reason.
 *
 * ## No credential ever leaves this module in a URL
 *
 * Passwords travel in a JSON body and nowhere else — never a query string,
 * never a path segment, never a log line. Fastify's default request log records
 * the URL of every request, so a password in a URL is a password in the server
 * log. There is also no response on this surface that echoes one back.
 *
 * ## Errors
 *
 * Ward answers `{"error":"<code>"}` on the admin routes and short prose on
 * `/console/login` (that route predates the convention and is left alone).
 * Everything here throws {@link ConsoleApiError}, which carries the status, the
 * raw code, and a sentence for the operator from {@link describeConsoleError}.
 * Callers render `error.message`; nothing renders a raw code.
 */

/** The browser-side prefix. See the note above before changing this. */
export const CONSOLE_API_BASE = "/ward-api/console";

/** `GET /console/session` and the body of a successful `POST /console/login`. */
export interface ConsoleSessionView {
  id: string;
  createdAt: string;
  lastSeenAt: string;
  /** Slides forward on every console request. The countdown the UI shows. */
  idleExpiresAt: string;
  /** Fixed at login. No amount of activity moves it. */
  absoluteExpiresAt: string;
  idleTimeoutSeconds: number;
}

/** An `apps` row. `baselineRole` is null whenever registration is closed. */
export interface AppView {
  slug: string;
  name: string;
  publicRegistration: boolean;
  baselineRole: string | null;
  createdAt: string;
  updatedAt: string;
}

/** A `users` row, without the password hash — the API never sends one. */
export interface AccountView {
  subject: string;
  username: string;
  email: string | null;
  emailVerified: boolean;
  disabled: boolean;
  disabledAt: string | null;
  createdAt: string;
  updatedAt: string;
}

/**
 * A `grants` row.
 *
 * `grantedBy` is a subject **or** the literal `"superuser"` or
 * `"self-registration"`. It is not a foreign key and must never be rendered as
 * a link to an account: the identity that issues the estate's first grants has
 * no `users` row to link to.
 */
export interface GrantView {
  subject: string;
  appSlug: string;
  role: string;
  grantedAt: string;
  grantedBy: string;
}

/** `GET /console/accounts` */
export interface AccountListResult {
  accounts: AccountView[];
  total: number;
}

/** `GET /console/accounts/:subject`. `liveSessions` is a count, not a list. */
export interface AccountDetailResult {
  account: AccountView;
  grants: GrantView[];
  liveSessions: number;
}

/** `GET /console/apps/:slug` */
export interface AppDetailResult {
  app: AppView;
  grantCount: number;
}

/** `POST /console/grants` — always `200`; `created` says whether it changed. */
export interface GrantWriteResult {
  grant: GrantView;
  created: boolean;
}

/** `DELETE /console/grants` — always `200`; `removed` is a count. */
export interface GrantRevokeResult {
  removed: number;
  roles: string[];
}

/** `POST /console/accounts/:subject/disable` */
export interface DisableResult {
  account: AccountView;
  sessionsRevoked: number;
}

/** `POST /console/accounts/:subject/enable` */
export interface EnableResult {
  account: AccountView;
  changed: boolean;
}

/** `POST /console/accounts/:subject/password`. Never echoes the password. */
export interface PasswordRotateResult {
  subject: string;
  sessionsRevoked: number;
}

/** A patch names only what changes; `baselineRole: null` means "clear it". */
export interface AppPatch {
  name?: string;
  publicRegistration?: boolean;
  baselineRole?: string | null;
}

/** A new app. Opening registration requires naming the baseline role here. */
export interface NewApp {
  slug: string;
  name: string;
  publicRegistration?: boolean;
  baselineRole?: string;
}

/**
 * One `audit_log` row as this client expects it.
 *
 * **The endpoint that would serve this does not exist yet** — see
 * {@link ConsoleApi.listAudit}. The shape mirrors `api/src/db/audit-log.ts`'s
 * `AuditLogRow` with the column names camel-cased the way every other console
 * view is, and `detail` already parsed from its JSON string.
 */
export interface AuditRowView {
  id: number;
  at: string;
  actorKind: "superuser" | "account" | "system";
  actorSubject: string | null;
  actorLabel: string;
  action: string;
  targetKind: "user" | "app" | "grant" | "session" | "token" | null;
  targetId: string | null;
  detail: unknown;
}

/** The filters the audit screen offers. Every field optional. */
export interface AuditQuery {
  /** Only rows for an ordinary account actor. Null-subject rows are excluded. */
  actorSubject?: string;
  /** `superuser` | `account` | `system` — the only way to filter console rows. */
  actorKind?: string;
  /** Matches `actor_label` exactly — a username, or `superuser`. */
  actorLabel?: string;
  targetKind?: string;
  targetId?: string;
  action?: string;
  /** Keyset pagination: rows with `id` strictly below this one. */
  beforeId?: number;
  limit?: number;
}

/** `GET /console/audit` — the proposed shape. */
export interface AuditListResult {
  entries: AuditRowView[];
  total: number;
}

/**
 * Any non-2xx answer from the console API, plus a network failure.
 *
 * `code` is Ward's machine-readable `error` field where there is one, or
 * `"network"` / `"malformed_response"` for the two failures that never reach the
 * server's error vocabulary. Branch on `code`; render `message`.
 */
export class ConsoleApiError extends Error {
  /** `0` when the request never got an answer. */
  readonly status: number;
  readonly code: string;
  /** Seconds, from `Retry-After`, on a `429` only. */
  readonly retryAfterSeconds?: number;

  constructor(status: number, code: string, message: string, retryAfterSeconds?: number) {
    super(message);
    this.name = "ConsoleApiError";
    this.status = status;
    this.code = code;
    if (retryAfterSeconds !== undefined) this.retryAfterSeconds = retryAfterSeconds;
  }

  /** The session is gone or was never there. Drop to the login screen. */
  get isUnauthorized(): boolean {
    return this.status === 401;
  }

  /** The route is not deployed. Distinguishes "missing endpoint" from "no row". */
  get isMissingEndpoint(): boolean {
    return this.status === 404 && this.code === "not_found";
  }
}

/**
 * A sentence for the operator, from a status and Ward's error code.
 *
 * Pure and exported so it is tested directly. Every message says what Ward
 * refused and what to do about it; none of them apologise, and none of them
 * echo a value the caller sent — a password can be the thing that was too
 * short, and the error must not quote it.
 */
export function describeConsoleError(status: number, code: string): string {
  switch (code) {
    // Apps.
    case "app_exists":
      return "That slug is already registered. Slugs are permanent — pick another.";
    case "app_not_found":
      return "No app is registered under that slug.";
    case "baseline_role_required":
      return "An app open to public registration has to say what a stranger gets. Name a baseline role in the same step.";
    case "baseline_role_requires_open":
      return "A baseline role only means something on an app that is open to public registration. Open the app in the same step, or leave the role unset.";

    // Grants.
    case "grant_target_missing":
      return "The account or the app was removed while the grant was being written. Reload and check both ends.";

    // Accounts.
    case "account_not_found":
      return "No account exists with that subject.";
    case "username_taken":
      return "That username is taken, in any casing. Ward folds case and Unicode form before comparing.";
    case "password_too_short":
      return "The password is shorter than Ward's minimum of 8 characters.";
    case "password_too_long":
      return "The password is longer than Ward accepts.";

    // Shared.
    case "invalid_request":
      return "Ward refused the request as malformed. Check the fields and try again.";
    case "unauthorized":
      return "The console session is not valid any more. Sign in again.";
    case "internal":
      return "Ward failed while handling the request. Check the service log.";
    case "network":
      return "The request never reached Ward. Check that the service is running.";
    case "malformed_response":
      return "Ward answered with something this console could not read.";
    default:
      break;
  }

  // `/console/login` predates the `{error:"<code>"}` convention and answers
  // prose. Its three statuses are the only ones that reach here, and each has
  // exactly one meaning on that route.
  switch (status) {
    case 400:
      return "Both a username and a password are required.";
    case 401:
      return "Those credentials were refused.";
    case 404:
      return "Ward has no route at that address. This console expects a newer version of the API.";
    case 429:
      return "Too many failed attempts from this address. Wait for the lockout to clear.";
    default:
      return `Ward answered ${String(status)} and this console does not recognise the reason.`;
  }
}

/** `fetch`, narrowed to what this module uses, so a test can supply one. */
export type FetchLike = (input: string, init?: RequestInit) => Promise<Response>;

/** Every console call, one method each. See {@link createConsoleApi}. */
export interface ConsoleApi {
  login(credentials: { username: string; password: string }): Promise<ConsoleSessionView>;
  logout(): Promise<void>;
  session(): Promise<ConsoleSessionView>;

  listApps(): Promise<AppView[]>;
  getApp(slug: string): Promise<AppDetailResult>;
  createApp(input: NewApp): Promise<AppView>;
  patchApp(slug: string, patch: AppPatch): Promise<AppView>;
  deleteApp(slug: string): Promise<{ slug: string; grantsRevoked: number }>;

  grantsForSubject(subject: string): Promise<GrantView[]>;
  grantsForApp(slug: string): Promise<GrantView[]>;
  addGrant(target: { subject: string; appSlug: string; role: string }): Promise<GrantWriteResult>;
  revokeGrant(target: {
    subject: string;
    appSlug: string;
    role?: string;
  }): Promise<GrantRevokeResult>;

  listAccounts(page?: { limit?: number; offset?: number }): Promise<AccountListResult>;
  getAccount(subject: string): Promise<AccountDetailResult>;
  createAccount(input: { username: string; password: string }): Promise<AccountView>;
  disableAccount(subject: string): Promise<DisableResult>;
  enableAccount(subject: string): Promise<EnableResult>;
  setPassword(subject: string, password: string): Promise<PasswordRotateResult>;

  listAudit(query?: AuditQuery): Promise<AuditListResult>;
}

/** Serialise a query object, dropping empty values so `?action=` never appears. */
function queryString(query: Record<string, string | number | undefined>): string {
  const params = new URLSearchParams();
  for (const [key, value] of Object.entries(query)) {
    if (value === undefined) continue;
    const text = String(value);
    if (text === "") continue;
    params.set(key, text);
  }
  const encoded = params.toString();
  return encoded === "" ? "" : `?${encoded}`;
}

/** `Retry-After` in seconds, or undefined when it is absent or a date. */
function retryAfter(response: Response): number | undefined {
  const header = response.headers.get("retry-after");
  if (header === null) return undefined;
  const seconds = Number(header.trim());
  return Number.isFinite(seconds) && seconds >= 0 ? seconds : undefined;
}

/** Ward's `error` field, or a stand-in derived from the status. */
function errorCode(body: unknown, status: number): string {
  if (typeof body === "object" && body !== null) {
    const field: unknown = (body as { error?: unknown }).error;
    // `/console/login` sends prose here rather than a code. Anything with a
    // space is prose, and mapping it by status says more than echoing it.
    if (typeof field === "string" && field !== "" && !field.includes(" ")) return field;
  }
  return status === 404 ? "not_found" : `http_${String(status)}`;
}

/**
 * Build a client over a given `fetch`.
 *
 * Every method funnels through one `call`, which is the single place the base
 * path, the credentials mode, the `no-store` and the error translation live.
 * Adding a method must not add a second place any of those are decided.
 */
export function createConsoleApi(fetchImpl?: FetchLike): ConsoleApi {
  const doFetch: FetchLike =
    fetchImpl ?? ((input, init) => globalThis.fetch(input, init) as Promise<Response>);

  // `body` is widened deliberately: every caller hands over a plain object and
  // this function is the single place it becomes JSON, so no method can forget
  // the content-type header or serialise it a second, different way.
  async function call<T>(
    path: string,
    init: Omit<RequestInit, "body"> & { body?: unknown } = {},
  ): Promise<T> {
    const { body, ...rest } = init;
    const headers: Record<string, string> = { accept: "application/json" };
    if (body !== undefined) headers["content-type"] = "application/json";

    let response: Response;
    try {
      response = await doFetch(`${CONSOLE_API_BASE}${path}`, {
        ...rest,
        headers,
        // The console cookie is same-origin by construction; sending it is the
        // entire point of the call, and `omit` here would 401 everything.
        credentials: "same-origin",
        cache: "no-store",
        ...(body === undefined ? {} : { body: JSON.stringify(body) }),
      });
    } catch {
      throw new ConsoleApiError(0, "network", describeConsoleError(0, "network"), undefined);
    }

    if (response.status === 204) return undefined as T;

    let parsed: unknown;
    const text = await response.text();
    if (text === "") {
      parsed = undefined;
    } else {
      try {
        parsed = JSON.parse(text);
      } catch {
        if (response.ok) {
          throw new ConsoleApiError(
            response.status,
            "malformed_response",
            describeConsoleError(response.status, "malformed_response"),
          );
        }
        parsed = undefined;
      }
    }

    if (!response.ok) {
      const code = errorCode(parsed, response.status);
      throw new ConsoleApiError(
        response.status,
        code,
        describeConsoleError(response.status, code),
        retryAfter(response),
      );
    }

    return parsed as T;
  }

  return {
    async login(credentials) {
      // The password is in the body. It is not in the path, and this is the
      // only method that receives one alongside a username.
      const result = await call<{ session: ConsoleSessionView }>("/login", {
        method: "POST",
        body: credentials,
      });
      return result.session;
    },

    async logout() {
      // Ungated and idempotent server-side, so a dead session still ends up in
      // a clean state rather than a 401 with a cookie it cannot remove.
      await call<void>("/logout", { method: "POST" });
    },

    async session() {
      const result = await call<{ session: ConsoleSessionView }>("/session");
      return result.session;
    },

    async listApps() {
      const result = await call<{ apps: AppView[] }>("/apps");
      return result.apps;
    },

    getApp(slug) {
      return call<AppDetailResult>(`/apps/${encodeURIComponent(slug)}`);
    },

    async createApp(input) {
      const result = await call<{ app: AppView }>("/apps", { method: "POST", body: input });
      return result.app;
    },

    async patchApp(slug, patch) {
      const result = await call<{ app: AppView }>(`/apps/${encodeURIComponent(slug)}`, {
        method: "PATCH",
        body: patch,
      });
      return result.app;
    },

    deleteApp(slug) {
      return call<{ slug: string; grantsRevoked: number }>(`/apps/${encodeURIComponent(slug)}`, {
        method: "DELETE",
      });
    },

    async grantsForSubject(subject) {
      const result = await call<{ grants: GrantView[] }>(`/grants${queryString({ subject })}`);
      return result.grants;
    },

    async grantsForApp(slug) {
      const result = await call<{ grants: GrantView[] }>(`/grants${queryString({ app: slug })}`);
      return result.grants;
    },

    addGrant(target) {
      return call<GrantWriteResult>("/grants", { method: "POST", body: target });
    },

    revokeGrant(target) {
      /**
       * A JSON body on a DELETE, deliberately. A role is opaque and may contain
       * `/`, `%` or `:`, so it cannot be a path segment — and Fastify logs the
       * URL of every request, so a role in a URL is a role in the log. Omitting
       * `role` means "every role this account holds in this app".
       */
      return call<GrantRevokeResult>("/grants", { method: "DELETE", body: target });
    },

    listAccounts(page = {}) {
      return call<AccountListResult>(`/accounts${queryString({ ...page })}`);
    },

    getAccount(subject) {
      return call<AccountDetailResult>(`/accounts/${encodeURIComponent(subject)}`);
    },

    async createAccount(input) {
      // No email field on this path: an owner-issued account has no address and
      // therefore no reset link. Rotating the password is the recovery channel.
      const result = await call<{ account: AccountView }>("/accounts", {
        method: "POST",
        body: input,
      });
      return result.account;
    },

    disableAccount(subject) {
      return call<DisableResult>(`/accounts/${encodeURIComponent(subject)}/disable`, {
        method: "POST",
      });
    },

    enableAccount(subject) {
      return call<EnableResult>(`/accounts/${encodeURIComponent(subject)}/enable`, {
        method: "POST",
      });
    },

    setPassword(subject, password) {
      // The password is in the body; the subject is the only thing in the path.
      return call<PasswordRotateResult>(`/accounts/${encodeURIComponent(subject)}/password`, {
        method: "POST",
        body: { password },
      });
    },

    /**
     * `GET /console/audit` — **this route does not exist in the API yet.**
     *
     * It is written here rather than omitted because everything behind it does
     * exist: `api/src/db/audit-log.ts` already has `listAudit`, `countAudit`,
     * keyset pagination and an `AuditQuery`. What is missing is a Fastify route
     * behind the console guard, plus two fields on `AuditQuery` —
     * `actorKind` and `actorLabel` — because every console mutation is written
     * with `actor_subject = NULL` and is otherwise unfilterable by actor.
     *
     * Until it lands this throws a `404` whose `isMissingEndpoint` is true, and
     * the audit screen says so precisely instead of showing an empty log.
     */
    listAudit(query = {}) {
      return call<AuditListResult>(`/audit${queryString({ ...query })}`);
    },
  };
}

/** The client the console uses. Tests build their own with `createConsoleApi`. */
export const consoleApi: ConsoleApi = createConsoleApi();
