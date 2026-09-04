import type { FastifyInstance, LightMyRequestResponse } from "fastify";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterAll, beforeAll, describe, expect, it } from "vitest";

/**
 * The cross-layer integration suite `corpus/wiki/status.md` names as the
 * repo's biggest gap: "No integration test crosses the layers... Every test
 * builds its own Fastify instance or opens `:memory:` directly. Nothing
 * exercises the real `buildApp()` against a real database and a real key
 * through a full sign-in → introspect → revoke cycle."
 *
 * Every other test file in this repo either builds a bare Fastify instance
 * with one plugin registered, or opens `openDatabase(":memory:")` directly.
 * Both choices are correct for a unit test and both are exactly what this
 * file must NOT do: the whole point here is to catch what registering every
 * plugin together, against a real on-disk SQLite file and a real generated
 * Ed25519 key, can break that no single module's test can see. Concretely,
 * this suite is what actually exercises:
 *
 *  - `buildApp()` itself — the wiring in `app.ts`, not a stand-in for it;
 *  - the real JWKS load at registration (`routes/jwks.ts` awaits
 *    `getKeySet()` while `buildApp()` runs), which needs a key genuinely on
 *    disk rather than one handed to a test fixture;
 *  - a real `WARD_DB_PATH` file, migrated with `runMigrations`, exactly the
 *    way `index.ts` boots it — not `:memory:`;
 *  - the console's bring-up sequence end to end: brief 04's "a grant added
 *    through the console appears in the next introspection" and brief 05's
 *    "disabling an account ends its live sessions... verified end to end"
 *    are acceptance criteria neither brief could satisfy alone, because each
 *    needed the other's endpoint. This is the first place both run together.
 *
 * ## `app.inject()`, never a bound port
 *
 * `app.inject()` exercises the full Fastify request lifecycle — routing,
 * hooks, serialization, the error handler — with no socket and no port to
 * conflict on. A stray `app.listen()` in an earlier verification run this
 * session invalidated the whole thing; nothing in this file calls `listen`.
 *
 * ## Every import of `../config.js` and its dependents is dynamic
 *
 * `config.ts` validates the environment at import time and calls
 * `process.exit(1)` on anything missing. A static import here would be
 * hoisted above the `process.env` assignments in `beforeAll` and take the
 * whole test worker with it — the same trap `routes/auth.test.ts` and
 * `tokens/jwks-route.test.ts` document, and the one this file's own header
 * repeats because getting it wrong here kills every test in the suite at
 * once rather than just one file's worth.
 *
 * ## Cookies are carried by hand between hops
 *
 * There is no cookie jar here — each `app.inject()` call is independent, so
 * every hop that needs a cookie a previous response set has to read it back
 * out of that response's `set-cookie` headers and forward it explicitly.
 * Three cookies exist in this estate and they carry three different `Path`
 * attributes (`ward_session` at `Path=/`, `ward_refresh` at
 * `Path=/ward-api/refresh`, `ward_console` at `Path=/ward-api/console`) —
 * meaningless to `app.inject()`, which never filters by path, but real
 * browser behaviour this suite otherwise wants to mirror. `cookieValue`
 * below reads the raw `name=value` pair out of a `set-cookie` header and
 * nothing else, so what gets forwarded is exactly the bytes a browser would
 * have stored and resent.
 */

const ORIGIN = "https://ward.test";
const ADMIN_USERNAME = "break-glass";
const ADMIN_PASSWORD = "a-long-random-break-glass-password";
const PASSWORD = "correct-horse-battery-staple";

let dir: string;
let app: FastifyInstance;

let mod: {
  cookie: typeof import("../auth/cookie.js");
  superuser: typeof import("../auth/superuser.js");
  connection: {
    getDb: typeof import("../db/connection.js").getDb;
    closeDb: typeof import("../db/connection.js").closeDb;
  };
  auditLog: typeof import("../db/audit-log.js");
};

beforeAll(async () => {
  dir = await mkdtemp(join(tmpdir(), "ward-integration-"));

  // Set BEFORE anything imports `config.js` — see the file header.
  process.env["PORT"] = "8798";
  process.env["HOST"] = "127.0.0.1";
  // A real on-disk file, not `:memory:`. `index.ts`'s own boot sequence — the
  // one this suite exists to reproduce — opens exactly this kind of path.
  process.env["WARD_DB_PATH"] = join(dir, "ward.db");
  process.env["WARD_ADMIN_USERNAME"] = ADMIN_USERNAME;
  process.env["WARD_ADMIN_PASSWORD"] = ADMIN_PASSWORD;
  process.env["WARD_SIGNING_KEY_PATH"] = join(dir, "signing-key.pem");
  process.env["WARD_PUBLIC_ORIGIN"] = ORIGIN;

  const config = await import("../config.js");

  // A real generated Ed25519 key on disk. `buildApp()` registers
  // `routes/jwks.ts`, which awaits `getKeySet()` at registration — so
  // `buildApp()` below genuinely does not start without this existing first.
  const { generateSigningKeyFile } = await import("../tokens/keygen.js");
  await generateSigningKeyFile(config.WARD_SIGNING_KEY_PATH);

  // Migrations run against the real file, exactly the order `index.ts` uses:
  // open the handle, migrate it, only then build the app.
  const { getDb, closeDb } = await import("../db/connection.js");
  const { runMigrations } = await import("../db/migrate.js");
  const db = await getDb();
  runMigrations(db);

  mod = {
    cookie: await import("../auth/cookie.js"),
    superuser: await import("../auth/superuser.js"),
    connection: { getDb, closeDb },
    auditLog: await import("../db/audit-log.js"),
  };

  const { buildApp } = await import("../app.js");
  app = await buildApp();
  await app.ready();
});

afterAll(async () => {
  await app?.close();
  mod?.connection.closeDb();
  await rm(dir, { recursive: true, force: true });
});

// ---------------------------------------------------------------------------
// Cookie plumbing
// ---------------------------------------------------------------------------

/** Every `set-cookie` header on a response, as raw strings. */
function setCookieHeaders(response: LightMyRequestResponse): string[] {
  const raw = response.headers["set-cookie"];
  return raw === undefined ? [] : Array.isArray(raw) ? raw : [String(raw)];
}

/**
 * The raw `name=value` pair for one cookie out of a response's `set-cookie`
 * headers — attributes (`Path`, `HttpOnly`, ...) stripped, encoding
 * untouched. This is exactly what a browser would store and resend, which is
 * why nothing here calls `decodeURIComponent`: `readConsoleCookie` and
 * `readCookie` both decode (or don't) on the receiving end, and round-
 * tripping the raw bytes is what proves the whole path, not a shortcut.
 */
function cookieValue(response: LightMyRequestResponse, name: string): string | undefined {
  for (const header of setCookieHeaders(response)) {
    const eq = header.indexOf("=");
    if (eq === -1) continue;
    if (header.slice(0, eq).trim() !== name) continue;
    const rest = header.slice(eq + 1);
    const end = rest.indexOf(";");
    return end === -1 ? rest : rest.slice(0, end);
  }
  return undefined;
}

function cookieHeader(pairs: Record<string, string>): string {
  return Object.entries(pairs)
    .map(([name, value]) => `${name}=${value}`)
    .join("; ");
}

// ---------------------------------------------------------------------------
// HTTP helpers — one per hop, each naming what it does on failure
// ---------------------------------------------------------------------------

async function loginAs(
  username: string,
  password: string,
  device: string,
): Promise<{ accessToken: string; refreshToken: string; body: Record<string, unknown> }> {
  const response = await app.inject({
    method: "POST",
    url: "/login",
    headers: { "x-forwarded-for": device },
    payload: { username, password },
  });
  expect(response.statusCode, `POST /login as ${username} (${device})`).toBe(200);

  const accessToken = cookieValue(response, mod.cookie.ACCESS_COOKIE_NAME);
  const refreshToken = cookieValue(response, mod.cookie.REFRESH_COOKIE_NAME);
  expect(accessToken, `POST /login as ${username} set an access cookie`).toBeDefined();
  expect(refreshToken, `POST /login as ${username} set a refresh cookie`).toBeDefined();

  return {
    accessToken: accessToken!,
    refreshToken: refreshToken!,
    body: response.json<Record<string, unknown>>(),
  };
}

async function introspectByCookie(accessToken: string): Promise<LightMyRequestResponse> {
  return app.inject({
    method: "POST",
    url: "/introspect",
    headers: { cookie: cookieHeader({ [mod.cookie.ACCESS_COOKIE_NAME]: accessToken }) },
    payload: {},
  });
}

async function refreshWith(refreshToken: string): Promise<LightMyRequestResponse> {
  return app.inject({
    method: "POST",
    url: "/refresh",
    headers: { cookie: cookieHeader({ [mod.cookie.REFRESH_COOKIE_NAME]: refreshToken }) },
    payload: {},
  });
}

async function logoutWith(refreshToken: string): Promise<LightMyRequestResponse> {
  return app.inject({
    method: "POST",
    url: "/logout",
    headers: { cookie: cookieHeader({ [mod.cookie.REFRESH_COOKIE_NAME]: refreshToken }) },
  });
}

async function consoleLogin(): Promise<string> {
  const response = await app.inject({
    method: "POST",
    url: "/console/login",
    headers: { "x-forwarded-for": "203.0.113.1" },
    payload: { username: ADMIN_USERNAME, password: ADMIN_PASSWORD },
  });
  expect(response.statusCode, "POST /console/login with the break-glass credential").toBe(200);

  const cookie = cookieValue(response, mod.superuser.CONSOLE_COOKIE_NAME);
  expect(cookie, "POST /console/login set a console cookie").toBeDefined();
  return cookie!;
}

function withConsole(consoleCookie: string): { cookie: string } {
  return { cookie: cookieHeader({ [mod.superuser.CONSOLE_COOKIE_NAME]: consoleCookie }) };
}

async function createApp(
  consoleCookie: string,
  slug: string,
  name: string,
): Promise<{ slug: string }> {
  const response = await app.inject({
    method: "POST",
    url: "/console/apps",
    headers: withConsole(consoleCookie),
    payload: { slug, name },
  });
  expect(response.statusCode, `POST /console/apps to register "${slug}"`).toBe(201);
  return response.json<{ app: { slug: string } }>().app;
}

async function createAccount(
  consoleCookie: string,
  username: string,
  password: string,
): Promise<{ subject: string }> {
  const response = await app.inject({
    method: "POST",
    url: "/console/accounts",
    headers: withConsole(consoleCookie),
    payload: { username, password },
  });
  expect(response.statusCode, `POST /console/accounts to create "${username}"`).toBe(201);
  return response.json<{ account: { subject: string } }>().account;
}

async function grantRoleViaConsole(
  consoleCookie: string,
  subject: string,
  appSlug: string,
  role: string,
): Promise<void> {
  const response = await app.inject({
    method: "POST",
    url: "/console/grants",
    headers: withConsole(consoleCookie),
    payload: { subject, appSlug, role },
  });
  expect(
    response.statusCode,
    `POST /console/grants — grant "${role}" on "${appSlug}" to ${subject}`,
  ).toBe(200);
}

async function revokeRoleViaConsole(
  consoleCookie: string,
  subject: string,
  appSlug: string,
  role: string,
): Promise<void> {
  const response = await app.inject({
    method: "DELETE",
    url: "/console/grants",
    headers: withConsole(consoleCookie),
    payload: { subject, appSlug, role },
  });
  expect(
    response.statusCode,
    `DELETE /console/grants — revoke "${role}" on "${appSlug}" from ${subject}`,
  ).toBe(200);
}

async function disableAccountViaConsole(consoleCookie: string, subject: string): Promise<void> {
  const response = await app.inject({
    method: "POST",
    url: `/console/accounts/${subject}/disable`,
    headers: withConsole(consoleCookie),
    payload: {},
  });
  expect(response.statusCode, `POST /console/accounts/${subject}/disable`).toBe(200);
}

// ---------------------------------------------------------------------------
// Flow 1 + 2 + 3 — the estate's real bring-up sequence, chained on one cookie
// ---------------------------------------------------------------------------

describe("flow 1 — the console bootstraps the estate", () => {
  let consoleCookie: string;
  let subject: string;
  let accessToken: string;

  it("logs into the console, registers an app, creates an account and grants two roles", async () => {
    consoleCookie = await consoleLogin();

    const registered = await createApp(consoleCookie, "atrium", "Atrium");
    expect(registered.slug, "the app just registered is named atrium").toBe("atrium");

    const account = await createAccount(consoleCookie, "alice", PASSWORD);
    subject = account.subject;

    await grantRoleViaConsole(consoleCookie, subject, "atrium", "editor");
    await grantRoleViaConsole(consoleCookie, subject, "atrium", "viewer");

    const session = await loginAs("alice", PASSWORD, "203.0.113.10");
    accessToken = session.accessToken;

    const introspected = await introspectByCookie(accessToken);
    expect(introspected.statusCode, "POST /introspect for alice's fresh login").toBe(200);
    expect(
      introspected.json(),
      "the estate's bring-up sequence: register → create → grant twice → login → introspect",
    ).toEqual({
      active: true,
      subject,
      username: "alice",
      grants: { atrium: ["editor", "viewer"] },
    });
  });

  /**
   * Brief 04's owed acceptance criterion: "a grant added through the console
   * appears in the next introspection response." Neither brief 04
   * (introspection) nor brief 05 (the console) could assert this alone —
   * each needed the other's endpoint, which is exactly why it landed here and
   * nowhere else. Same cookie as the test above: no re-login.
   */
  it("shows a grant added through the console on the very next introspection — no re-login", async () => {
    await grantRoleViaConsole(consoleCookie, subject, "atrium", "admin");

    const introspected = await introspectByCookie(accessToken);
    expect(
      introspected.json(),
      "the same access token, unchanged, after POST /console/grants added admin",
    ).toEqual({
      active: true,
      subject,
      username: "alice",
      grants: { atrium: ["admin", "editor", "viewer"] },
    });
  });

  /** The mirror: a grant taken away disappears on the next call, same cookie. */
  it("shows a grant revoked through the console disappearing on the very next introspection", async () => {
    await revokeRoleViaConsole(consoleCookie, subject, "atrium", "viewer");

    const introspected = await introspectByCookie(accessToken);
    expect(
      introspected.json(),
      "the same access token, unchanged, after DELETE /console/grants removed viewer",
    ).toEqual({
      active: true,
      subject,
      username: "alice",
      grants: { atrium: ["admin", "editor"] },
    });
  });
});

// ---------------------------------------------------------------------------
// Flow 4 — disabling an account ends its live session, verified through
// /introspect and /refresh rather than by inspecting rows (brief 05's owed
// criterion).
// ---------------------------------------------------------------------------

describe("flow 4 — disabling an account ends its live session end to end", () => {
  it("logs in, confirms active, disables the account, and both /introspect and /refresh refuse the same still-valid credentials", async () => {
    const consoleCookie = await consoleLogin();
    const { subject } = await createAccount(consoleCookie, "diana", PASSWORD);

    const session = await loginAs("diana", PASSWORD, "203.0.113.20");

    const before = await introspectByCookie(session.accessToken);
    expect(before.json(), "diana's freshly-minted token introspects live").toMatchObject({
      active: true,
    });

    await disableAccountViaConsole(consoleCookie, subject);

    // The signature is untouched — this is the same access token, byte for
    // byte, that just introspected active. Nothing expired and nothing was
    // revoked at the token layer; only `users.disabled_at` changed.
    const after = await introspectByCookie(session.accessToken);
    expect(
      after.json(),
      "the SAME still-cryptographically-valid access token, after POST /console/accounts/:subject/disable",
    ).toEqual({ active: false });

    // And the refresh token behind it is refused too — an app that never
    // introspects but does try to refresh gets the same lockout.
    const refreshed = await refreshWith(session.refreshToken);
    expect(
      refreshed.statusCode,
      "POST /refresh with a disabled account's still-unexpired refresh token",
    ).toBe(401);
    expect(refreshed.json()).toEqual({ error: "invalid_refresh" });
  });
});

// ---------------------------------------------------------------------------
// Flow 5 — rotation across the wire, and a replay killing the family
// ---------------------------------------------------------------------------

describe("flow 5 — refresh rotation, and reuse killing the family, over real HTTP", () => {
  it("rotates twice, then a replay of the ORIGINAL refresh token kills the whole family", async () => {
    const consoleCookie = await consoleLogin();
    await createAccount(consoleCookie, "erin", PASSWORD);

    const login = await loginAs("erin", PASSWORD, "203.0.113.30");
    expect(
      (await introspectByCookie(login.accessToken)).json(),
      "erin's freshly-minted access token introspects live",
    ).toMatchObject({ active: true });

    // R1 → R2. The new access token must introspect live.
    const first = await refreshWith(login.refreshToken);
    expect(first.statusCode, "POST /refresh with R1 (first rotation)").toBe(200);
    const secondAccessToken = cookieValue(first, mod.cookie.ACCESS_COOKIE_NAME)!;
    const secondRefreshToken = cookieValue(first, mod.cookie.REFRESH_COOKIE_NAME)!;
    expect(
      (await introspectByCookie(secondAccessToken)).json(),
      "the access token minted on rotation #1 introspects live",
    ).toMatchObject({ active: true });

    /**
     * A second, genuine rotation — R2 → R3 — has to happen BEFORE the replay
     * below, and this is the subtlety a unit test on `refresh.ts` alone
     * cannot surface: `auth/refresh.ts` carves out a
     * `REFRESH_RACE_GRACE_SECONDS` (10s) window in which re-presenting a
     * just-rotated token is treated as two tabs racing, not as theft — and a
     * race intentionally revokes nothing. Replaying R1 immediately after only
     * rotation #1 would land in that carve-out (R2 is still the live,
     * unrotated tip) and the family would survive, which is the OPPOSITE of
     * what this test is trying to prove. Rotating R2 → R3 first means that by
     * the time R1 is replayed, a family member newer than R1 (R2) has itself
     * already been used — `raceSuccessor`'s condition (1) — so the replay is
     * unambiguously reuse, not a race, and the whole family dies.
     */
    const second = await refreshWith(secondRefreshToken);
    expect(second.statusCode, "POST /refresh with R2 (second rotation)").toBe(200);
    const thirdAccessToken = cookieValue(second, mod.cookie.ACCESS_COOKIE_NAME)!;
    expect(
      (await introspectByCookie(thirdAccessToken)).json(),
      "the access token minted on rotation #2 introspects live",
    ).toMatchObject({ active: true });

    // Replay the ORIGINAL R1 — already spent twice over now.
    const replay = await refreshWith(login.refreshToken);
    expect(replay.statusCode, "POST /refresh replaying the original R1").toBe(401);
    expect(replay.json()).toEqual({ error: "invalid_refresh" });

    // The reuse alarm kills the WHOLE family — including R3, which was live
    // and legitimate a moment ago. This is the theft-response contract: a
    // stolen family dies in full rather than only the specific token reused.
    const afterReplay = await introspectByCookie(thirdAccessToken);
    expect(
      afterReplay.json(),
      "the current, legitimately-rotated access token, after R1 was replayed",
    ).toEqual({ active: false });
  });
});

// ---------------------------------------------------------------------------
// Flow 6 — THE PAYOFF: per-device revocation. This is the test the `sid`
// claim exists for.
// ---------------------------------------------------------------------------

describe("flow 6 — per-device revocation: the reason the sid claim exists", () => {
  it("signing out one device leaves that device's token dead and the OTHER device's token live", async () => {
    const consoleCookie = await consoleLogin();
    await createAccount(consoleCookie, "frank", PASSWORD);

    // Two independent logins for ONE account — two refresh families, exactly
    // the "laptop" and "phone" scenario `grants/resolve.ts`'s header names.
    const laptop = await loginAs("frank", PASSWORD, "203.0.113.40");
    const phone = await loginAs("frank", PASSWORD, "203.0.113.41");

    const laptopBefore = await introspectByCookie(laptop.accessToken);
    const phoneBefore = await introspectByCookie(phone.accessToken);
    expect(laptopBefore.json(), "the laptop's token, before any logout").toMatchObject({
      active: true,
    });
    expect(phoneBefore.json(), "the phone's token, before any logout").toMatchObject({
      active: true,
    });

    // Sign out ONE device: POST /logout presenting only the laptop's refresh
    // cookie. The phone's session is never touched.
    const loggedOut = await logoutWith(laptop.refreshToken);
    expect(loggedOut.statusCode, "POST /logout with the laptop's refresh cookie").toBe(204);

    const laptopAfter = await introspectByCookie(laptop.accessToken);
    const phoneAfter = await introspectByCookie(phone.accessToken);

    /**
     * **This is the one result the controller most needs to see.**
     *
     * Before the `sid` claim existed, `resolveSession` (then `resolveSession
     * (db, subject)`, no session id) could only ask "does this account have
     * any live session at all" — and with the phone's family still live, that
     * question's answer was `true` for the laptop's token too, for the full
     * 15-minute access-token lifetime. `grants/resolve.ts`'s own header names
     * this exactly: "signing out one device leaves that device's access
     * token introspecting as live... against an attacker who by hypothesis
     * is actively using the token." `sid` closes it: introspection is now
     * scoped to the family the presented token was minted under, not to the
     * account.
     */
    console.log("flow 6 — per-device revocation, over real HTTP:");
    console.log("  laptop (logged out) introspects:", JSON.stringify(laptopAfter.json()));
    console.log("  phone  (still signed in) introspects:", JSON.stringify(phoneAfter.json()));

    expect(
      laptopAfter.json(),
      "the LOGGED-OUT device's access token — before sid, this was `active: true` for its remaining 15 minutes",
    ).toEqual({ active: false });
    expect(
      phoneAfter.json(),
      "the OTHER device's access token — untouched by the laptop's logout",
    ).toMatchObject({ active: true });
  });
});

// ---------------------------------------------------------------------------
// Flow 7 — the superuser is confined, in both directions
// ---------------------------------------------------------------------------

describe("flow 7 — the superuser console session cannot open an app, and an app account cannot open the console", () => {
  it("a real console session presented to /introspect is active: false, in the cookie and in the body", async () => {
    const consoleCookie = await consoleLogin();

    const byCookie = await app.inject({
      method: "POST",
      url: "/introspect",
      headers: { cookie: cookieHeader({ [mod.superuser.CONSOLE_COOKIE_NAME]: consoleCookie }) },
      payload: {},
    });
    const byBody = await app.inject({
      method: "POST",
      url: "/introspect",
      payload: { accessToken: consoleCookie },
    });

    expect(byCookie.json(), "a real console token in the console cookie, to /introspect").toEqual({
      active: false,
    });
    expect(byBody.json(), "the same console token in the introspect body").toEqual({
      active: false,
    });
  });

  it("an ordinary account's access token cannot open an admin route, however many grants it holds", async () => {
    const consoleCookie = await consoleLogin();

    // As much authority as this estate can express short of the console
    // itself: every role in three separate apps.
    await createApp(consoleCookie, "prm", "PRM");
    await createApp(consoleCookie, "newspapper", "Newspapper");
    const { subject } = await createAccount(consoleCookie, "grace", PASSWORD);
    for (const [appSlug, role] of [
      ["atrium", "owner"],
      ["prm", "owner"],
      ["newspapper", "owner"],
    ] as const) {
      await grantRoleViaConsole(consoleCookie, subject, appSlug, role);
    }

    const session = await loginAs("grace", PASSWORD, "203.0.113.50");

    // /introspect confirms the authority is real, before trying to abuse it.
    expect(
      (await introspectByCookie(session.accessToken)).json(),
      "grace's token genuinely carries owner in three apps",
    ).toMatchObject({
      active: true,
      grants: { atrium: ["owner"], prm: ["owner"], newspapper: ["owner"] },
    });

    const asConsoleCookie = await app.inject({
      method: "GET",
      url: "/console/accounts",
      headers: {
        cookie: cookieHeader({ [mod.superuser.CONSOLE_COOKIE_NAME]: session.accessToken }),
      },
    });
    const asSessionCookie = await app.inject({
      method: "GET",
      url: "/console/accounts",
      headers: { cookie: cookieHeader({ [mod.cookie.ACCESS_COOKIE_NAME]: session.accessToken }) },
    });
    const asBearer = await app.inject({
      method: "GET",
      url: "/console/accounts",
      headers: { authorization: `Bearer ${session.accessToken}` },
    });

    expect(
      asConsoleCookie.statusCode,
      "grace's access token in the ward_console cookie, on an admin route",
    ).toBe(401);
    expect(
      asSessionCookie.statusCode,
      "grace's access token in its OWN cookie, on an admin route the guard never reads it from",
    ).toBe(401);
    expect(asBearer.statusCode, "grace's access token as a bearer header, on an admin route").toBe(
      401,
    );
  });
});

// ---------------------------------------------------------------------------
// Flow 8 — the audit trail reads back coherently
// ---------------------------------------------------------------------------

describe("flow 8 — the audit trail, read back after everything above", () => {
  it("holds the console actions and session events above with actors named correctly", async () => {
    const db = await mod.connection.getDb();
    const rows = mod.auditLog.listAudit(db, { limit: 1000 });

    const actionsSeen = new Set(rows.map((row) => row.action));
    /**
     * Notably absent from this list: `session.refresh_denied`. That action is
     * written inside `rotateRefreshToken`'s `completeRotation`, for the narrow
     * race where an account is disabled *between* a refresh token being
     * claimed and the disabled check running inside that same transaction.
     * Flow 4's ordinary case — the account was already disabled well before
     * `/refresh` is ever called — never reaches that code at all:
     * `routes/auth.ts`'s `/refresh` handler calls `sessionForRefreshToken`
     * first, which itself excludes a disabled account's session, so the
     * request short-circuits to the generic "unknown" outcome and no audit
     * row is written for it specifically. Finding that distinction — that
     * disabling-then-refreshing produces no audit trail of its own, only the
     * `user.disable` row from the disable itself — is exactly the kind of
     * thing a per-module unit test cannot surface, because `refresh.test.ts`
     * tests `rotateRefreshToken` directly and never goes through the route
     * that peeks ahead of it.
     */
    for (const expected of [
      "console.login",
      "app.create",
      "user.create",
      "grant.create",
      "grant.revoke",
      "session.login",
      "user.disable",
      "session.reuse_detected",
      "session.logout",
    ]) {
      expect(actionsSeen, `audit_log contains at least one "${expected}" row`).toContain(expected);
    }

    // Every console action is attributed to the superuser, with NO subject —
    // there is no account row to point at, and the CHECK in `audit-log.ts`
    // ties a non-null `actor_subject` to `actorKind: "account"`.
    const consoleRows = rows.filter(
      (row) => row.action.startsWith("console.") || row.action === "app.create",
    );
    expect(consoleRows.length, "at least one console-attributed row exists").toBeGreaterThan(0);
    for (const row of consoleRows) {
      expect(row.actor_kind, `row "${row.action}" is attributed to the superuser`).toBe(
        "superuser",
      );
      expect(row.actor_subject, `row "${row.action}" carries no actor subject`).toBeNull();
    }

    // Account-driven events (a real login) are attributed to that account.
    const loginRows = rows.filter(
      (row) => row.action === "session.login" && row.actor_label === "alice",
    );
    expect(loginRows.length, 'alice\'s "session.login" row exists').toBeGreaterThan(0);
    expect(loginRows[0]!.actor_kind).toBe("account");
    expect(loginRows[0]!.actor_subject).not.toBeNull();

    // `parseGrantTargetId` round-trips a grant target written by a REAL
    // route (flow 1's `POST /console/grants` for alice/atrium — admin,
    // editor or viewer), not a value constructed by the test itself. Flow 7
    // also grants "owner" on atrium to a different account, so the row is
    // picked out by role, not just by app slug, to land on alice's grant
    // specifically rather than whichever atrium row happens to be newest.
    const grantRow = rows.find((row) => {
      if (row.action !== "grant.create" || row.target_id === null) return false;
      const target = mod.auditLog.parseGrantTargetId(row.target_id);
      return target?.appSlug === "atrium" && ["admin", "editor", "viewer"].includes(target.role);
    });
    expect(grantRow, "one of alice's grant.create rows for atrium exists in the log").toBeDefined();
    const parsed = mod.auditLog.parseGrantTargetId(grantRow!.target_id!);
    expect(parsed, "the real target_id parses back into its triple").toBeDefined();
    expect(parsed!.appSlug).toBe("atrium");
    expect(["admin", "editor", "viewer"]).toContain(parsed!.role);
    expect(
      mod.auditLog.grantTargetId(parsed!.subject, parsed!.appSlug, parsed!.role),
      "re-encoding the parsed triple reproduces the exact stored target_id",
    ).toBe(grantRow!.target_id);
  });
});
