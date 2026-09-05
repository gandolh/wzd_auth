/**
 * Tests for the console's HTTP client.
 *
 * There is **no DOM environment configured** for Vitest in this repo, on
 * purpose (see `vitest.config.ts`), so nothing here renders a component. What
 * is tested is what can go wrong without one, and the list is not short: the
 * base path, the method, where the body goes, how an error becomes a sentence,
 * and the two behaviours the API deliberately does not express in its status
 * code.
 *
 * The first of those is the one worth the file existing. **Every console call
 * must be built against `/ward-api/console`**, because the `ward_console`
 * cookie is scoped to exactly that path — get it wrong and the cookie is never
 * sent, which looks like a passing test suite and a console that returns `401`
 * forever in a browser. A stubbed `fetch` cannot notice that on its own, so the
 * prefix is asserted for every method by name.
 */

import { describe, expect, it } from "vitest";

import {
  CONSOLE_API_BASE,
  ConsoleApiError,
  createConsoleApi,
  describeConsoleError,
  type ConsoleApi,
  type FetchLike,
} from "./console-api.js";

/** One recorded request. */
interface Call {
  url: string;
  method: string;
  body: string | undefined;
  headers: Record<string, string>;
  credentials: string | undefined;
  cache: string | undefined;
}

/** A `fetch` that records what it was asked and answers what it was told to. */
function recorder(
  reply: { status?: number; body?: unknown; headers?: Record<string, string> } = {},
): { api: ConsoleApi; calls: Call[] } {
  const calls: Call[] = [];
  const fetchImpl: FetchLike = (url, init = {}) => {
    calls.push({
      url,
      method: init.method ?? "GET",
      body: typeof init.body === "string" ? init.body : undefined,
      headers: (init.headers ?? {}) as Record<string, string>,
      credentials: init.credentials,
      cache: init.cache,
    });
    const status = reply.status ?? 200;
    const text = reply.body === undefined ? "" : JSON.stringify(reply.body);
    return Promise.resolve(
      new Response(status === 204 ? null : text, {
        status,
        headers: { "content-type": "application/json", ...reply.headers },
      }),
    );
  };
  return { api: createConsoleApi(fetchImpl), calls };
}

/** The single call a `recorder` made. Fails loudly rather than returning undefined. */
function only(calls: Call[]): Call {
  expect(calls).toHaveLength(1);
  const call = calls[0];
  if (call === undefined) throw new Error("no call recorded");
  return call;
}

describe("the base path", () => {
  it("is the browser-side prefix the console cookie is scoped to", () => {
    // Not `/console` and not `/ward-api`. Caddy's `handle_path` strips
    // `/ward-api`, which is why the Fastify routes read `/console/...`; the
    // browser only sends `ward_console` to URLs under the full prefix.
    expect(CONSOLE_API_BASE).toBe("/ward-api/console");
  });

  /**
   * Every method, by name, because a new one added later that forgets the
   * prefix is exactly the bug this file exists to catch — and it would pass
   * every other test in the suite.
   */
  const methods: { name: string; run: (api: ConsoleApi) => Promise<unknown>; body?: unknown }[] = [
    {
      name: "login",
      run: (api) => api.login({ username: "u", password: "p" }),
      body: { session: {} },
    },
    { name: "logout", run: (api) => api.logout(), body: undefined },
    { name: "session", run: (api) => api.session(), body: { session: {} } },
    { name: "listApps", run: (api) => api.listApps(), body: { apps: [] } },
    { name: "getApp", run: (api) => api.getApp("prm"), body: { app: {}, grantCount: 0 } },
    { name: "createApp", run: (api) => api.createApp({ slug: "s", name: "n" }), body: { app: {} } },
    { name: "patchApp", run: (api) => api.patchApp("prm", { name: "n" }), body: { app: {} } },
    {
      name: "deleteApp",
      run: (api) => api.deleteApp("prm"),
      body: { slug: "prm", grantsRevoked: 0 },
    },
    { name: "grantsForSubject", run: (api) => api.grantsForSubject("s"), body: { grants: [] } },
    { name: "grantsForApp", run: (api) => api.grantsForApp("prm"), body: { grants: [] } },
    {
      name: "addGrant",
      run: (api) => api.addGrant({ subject: "s", appSlug: "prm", role: "admin" }),
      body: { grant: {}, created: true },
    },
    {
      name: "revokeGrant",
      run: (api) => api.revokeGrant({ subject: "s", appSlug: "prm" }),
      body: { removed: 0, roles: [] },
    },
    { name: "listAccounts", run: (api) => api.listAccounts(), body: { accounts: [], total: 0 } },
    {
      name: "getAccount",
      run: (api) => api.getAccount("s"),
      body: { account: {}, grants: [], liveSessions: 0 },
    },
    {
      name: "createAccount",
      run: (api) => api.createAccount({ username: "u", password: "p" }),
      body: { account: {} },
    },
    {
      name: "disableAccount",
      run: (api) => api.disableAccount("s"),
      body: { account: {}, sessionsRevoked: 0 },
    },
    {
      name: "enableAccount",
      run: (api) => api.enableAccount("s"),
      body: { account: {}, changed: false },
    },
    {
      name: "setPassword",
      run: (api) => api.setPassword("s", "p"),
      body: { subject: "s", sessionsRevoked: 0 },
    },
    { name: "listSessions", run: (api) => api.listSessions("s"), body: { sessions: [], total: 0 } },
    {
      name: "revokeSession",
      run: (api) => api.revokeSession("s", "f_1"),
      body: { subject: "s", familyId: "f_1", revoked: 1, changed: true },
    },
    {
      name: "revokeAllSessions",
      run: (api) => api.revokeAllSessions("s"),
      body: { subject: "s", revoked: 0, tokensRevoked: 0, changed: false },
    },
    {
      name: "listAudit",
      run: (api) => api.listAudit(),
      body: { entries: [], total: 0, nextBeforeId: null },
    },
  ];

  for (const method of methods) {
    it(`${method.name} targets /ward-api/console/...`, async () => {
      const { api, calls } = recorder({
        status: method.body === undefined ? 204 : 200,
        body: method.body,
      });
      await method.run(api);
      const call = only(calls);
      expect(call.url.startsWith("/ward-api/console/")).toBe(true);
      // Sends the cookie, and never caches an answer about who can reach what.
      expect(call.credentials).toBe("same-origin");
      expect(call.cache).toBe("no-store");
    });
  }
});

describe("passwords never appear in a URL", () => {
  const secret = "correct-horse-battery-staple";

  it("keeps the console credential in the body on login", async () => {
    const { api, calls } = recorder({ body: { session: {} } });
    await api.login({ username: "root", password: secret });
    const call = only(calls);
    expect(call.url).not.toContain(secret);
    expect(call.url).toBe("/ward-api/console/login");
    expect(call.body).toBe(JSON.stringify({ username: "root", password: secret }));
  });

  it("keeps a new account's password in the body", async () => {
    const { api, calls } = recorder({ status: 201, body: { account: {} } });
    await api.createAccount({ username: "cristian", password: secret });
    const call = only(calls);
    expect(call.url).toBe("/ward-api/console/accounts");
    expect(call.url).not.toContain(secret);
    expect(call.body).toContain(secret);
  });

  it("keeps a rotated password in the body, with only the subject in the path", async () => {
    const { api, calls } = recorder({ body: { subject: "u_1", sessionsRevoked: 2 } });
    await api.setPassword("u_1", secret);
    const call = only(calls);
    expect(call.url).toBe("/ward-api/console/accounts/u_1/password");
    expect(call.url).not.toContain(secret);
    expect(call.body).toBe(JSON.stringify({ password: secret }));
  });
});

describe("request building", () => {
  it("puts a JSON body on DELETE /grants, because a role cannot be a path segment", async () => {
    // A role is opaque and may contain `/`, `%` or `:`. This is the shape the
    // API chose for exactly that reason.
    const { api, calls } = recorder({ body: { removed: 1, roles: ["a/b:c"] } });
    await api.revokeGrant({ subject: "u_1", appSlug: "prm", role: "a/b:c" });
    const call = only(calls);
    expect(call.method).toBe("DELETE");
    expect(call.url).toBe("/ward-api/console/grants");
    expect(call.body).toBe(JSON.stringify({ subject: "u_1", appSlug: "prm", role: "a/b:c" }));
    expect(call.headers["content-type"]).toBe("application/json");
  });

  it("omits the role from a DELETE body to mean every role in the app", async () => {
    const { api, calls } = recorder({ body: { removed: 2, roles: ["admin", "reader"] } });
    await api.revokeGrant({ subject: "u_1", appSlug: "prm" });
    expect(only(calls).body).toBe(JSON.stringify({ subject: "u_1", appSlug: "prm" }));
  });

  it("percent-encodes a subject in a path", async () => {
    const { api, calls } = recorder({ body: { account: {}, grants: [], liveSessions: 0 } });
    await api.getAccount("weird/subject");
    expect(only(calls).url).toBe("/ward-api/console/accounts/weird%2Fsubject");
  });

  it("percent-encodes both the subject and the family id in a session revoke", async () => {
    const { api, calls } = recorder({
      body: { subject: "weird/subject", familyId: "f/1", revoked: 1, changed: true },
    });
    await api.revokeSession("weird/subject", "f/1");
    const call = only(calls);
    expect(call.method).toBe("DELETE");
    expect(call.url).toBe("/ward-api/console/accounts/weird%2Fsubject/sessions/f%2F1");
  });

  it("puts exactly one filter on GET /grants", async () => {
    const bySubject = recorder({ body: { grants: [] } });
    await bySubject.api.grantsForSubject("u_1");
    expect(only(bySubject.calls).url).toBe("/ward-api/console/grants?subject=u_1");

    const byApp = recorder({ body: { grants: [] } });
    await byApp.api.grantsForApp("prm");
    expect(only(byApp.calls).url).toBe("/ward-api/console/grants?app=prm");
  });

  it("drops empty query values rather than sending ?action=", async () => {
    const { api, calls } = recorder({ body: { entries: [], total: 0 } });
    await api.listAudit({ action: "", actorLabel: "superuser", limit: 50 });
    expect(only(calls).url).toBe("/ward-api/console/audit?actorLabel=superuser&limit=50");
  });

  it("sends no content-type on a GET, because there is no body", async () => {
    const { api, calls } = recorder({ body: { apps: [] } });
    await api.listApps();
    const call = only(calls);
    expect(call.headers["content-type"]).toBeUndefined();
    expect(call.headers["accept"]).toBe("application/json");
  });

  it("handles a 204 with no body", async () => {
    const { api, calls } = recorder({ status: 204 });
    await expect(api.logout()).resolves.toBeUndefined();
    expect(only(calls).method).toBe("POST");
  });
});

describe("the behaviours the status code deliberately does not carry", () => {
  it("reads `created` from a 200 on POST /grants rather than expecting a 201", async () => {
    // The API is always 200 here: a status that changed on a repeat would make
    // an idempotent retry look like a different outcome.
    const { api } = recorder({
      status: 200,
      body: { grant: { subject: "u_1", appSlug: "prm", role: "admin" }, created: false },
    });
    const result = await api.addGrant({ subject: "u_1", appSlug: "prm", role: "admin" });
    expect(result.created).toBe(false);
  });

  it("reads `removed: 0` from a successful revoke of nothing", async () => {
    const { api } = recorder({ status: 200, body: { removed: 0, roles: [] } });
    const result = await api.revokeGrant({ subject: "u_1", appSlug: "prm", role: "ghost" });
    expect(result.removed).toBe(0);
    expect(result.roles).toEqual([]);
  });

  it("reads `changed: false` from a second enable", async () => {
    const { api } = recorder({ status: 200, body: { account: {}, changed: false } });
    const result = await api.enableAccount("u_1");
    expect(result.changed).toBe(false);
  });
});

describe("error mapping", () => {
  it("throws a ConsoleApiError carrying the status and Ward's code", async () => {
    const { api } = recorder({ status: 409, body: { error: "username_taken" } });
    const error = await api
      .createAccount({ username: "u", password: "p" })
      .catch((e: unknown) => e);
    expect(error).toBeInstanceOf(ConsoleApiError);
    const typed = error as ConsoleApiError;
    expect(typed.status).toBe(409);
    expect(typed.code).toBe("username_taken");
    expect(typed.message).toContain("taken");
  });

  it("flags a 401 so the console can drop to its sign-in screen", async () => {
    const { api } = recorder({ status: 401, body: { error: "unauthorized" } });
    const error = (await api.listApps().catch((e: unknown) => e)) as ConsoleApiError;
    expect(error.isUnauthorized).toBe(true);
  });

  it("reads Retry-After off a 429, since the login body carries no seconds", async () => {
    // `/console/login` answers `{"error":"too many attempts"}` and puts the
    // number in the header. Anything that reads it from the body gets nothing.
    const { api } = recorder({
      status: 429,
      body: { error: "too many attempts" },
      headers: { "retry-after": "90" },
    });
    const error = (await api
      .login({ username: "u", password: "p" })
      .catch((e: unknown) => e)) as ConsoleApiError;
    expect(error.status).toBe(429);
    expect(error.retryAfterSeconds).toBe(90);
    expect(error.message).toContain("Too many failed attempts");
  });

  it("ignores a Retry-After that is an HTTP date rather than seconds", async () => {
    const { api } = recorder({
      status: 429,
      body: { error: "too many attempts" },
      headers: { "retry-after": "Wed, 21 Oct 2026 07:28:00 GMT" },
    });
    const error = (await api
      .login({ username: "u", password: "p" })
      .catch((e: unknown) => e)) as ConsoleApiError;
    expect(error.retryAfterSeconds).toBeUndefined();
  });

  it("maps /console/login's prose bodies by status instead of echoing them", async () => {
    const { api } = recorder({ status: 401, body: { error: "invalid credentials" } });
    const error = (await api
      .login({ username: "u", password: "p" })
      .catch((e: unknown) => e)) as ConsoleApiError;
    // The prose is not treated as a code, and not shown raw.
    expect(error.code).toBe("http_401");
    expect(error.message).toBe("Those credentials were refused.");
  });

  it("distinguishes a missing route from a missing row", async () => {
    const missing = recorder({ status: 404, body: undefined });
    const routeError = (await missing.api.listAudit().catch((e: unknown) => e)) as ConsoleApiError;
    expect(routeError.isMissingEndpoint).toBe(true);

    const noRow = recorder({ status: 404, body: { error: "app_not_found" } });
    const rowError = (await noRow.api.getApp("nope").catch((e: unknown) => e)) as ConsoleApiError;
    expect(rowError.isMissingEndpoint).toBe(false);
    expect(rowError.code).toBe("app_not_found");
  });

  it("turns a network failure into a sentence rather than a TypeError", async () => {
    const api = createConsoleApi(() => Promise.reject(new Error("ECONNREFUSED")));
    const error = (await api.listApps().catch((e: unknown) => e)) as ConsoleApiError;
    expect(error.status).toBe(0);
    expect(error.code).toBe("network");
    expect(error.message).toContain("never reached Ward");
  });

  it("refuses a 200 that is not JSON rather than returning undefined", async () => {
    const api = createConsoleApi(() =>
      Promise.resolve(new Response("<html>nope</html>", { status: 200 })),
    );
    const error = (await api.listApps().catch((e: unknown) => e)) as ConsoleApiError;
    expect(error.code).toBe("malformed_response");
  });
});

describe("describeConsoleError", () => {
  it("explains the coupled registration errors as one decision", () => {
    expect(describeConsoleError(400, "baseline_role_required")).toContain("in the same step");
    expect(describeConsoleError(400, "baseline_role_requires_open")).toContain("open");
  });

  it("never echoes a value the caller sent", () => {
    // A password can be the thing that was too short, so the message must not
    // quote whatever was submitted.
    expect(describeConsoleError(400, "password_too_short")).toBe(
      "The password is shorter than Ward's minimum of 8 characters.",
    );
  });

  it("still says something for a code it has never seen", () => {
    const message = describeConsoleError(418, "brand_new_code");
    expect(message).toContain("418");
    expect(message.length).toBeGreaterThan(10);
  });
});
