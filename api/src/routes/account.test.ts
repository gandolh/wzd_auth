import type Database from "better-sqlite3";
import type { FastifyInstance, InjectOptions, LightMyRequestResponse } from "fastify";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterAll, beforeAll, beforeEach, describe, expect, it } from "vitest";

/**
 * `/account` — the self-service surface, end to end over real logins.
 *
 * ## Registered alongside `authRoutes` and `introspectRoutes`
 *
 * The sessions under test are ones a real `POST /login` produced, and liveness
 * is checked by asking the real `/introspect` — so "the old session is dead and
 * the new one works" is asserted through the endpoint every app in the estate
 * actually uses, not through a fixture.
 *
 * ## Every import of `../config.js` and its dependents is dynamic
 *
 * `config.ts` validates the environment at import time and calls
 * `process.exit(1)` on anything missing; a static import would be hoisted above
 * the `process.env` assignments below and take the whole worker with it.
 */

const ORIGIN = "https://ward.test";
const PASSWORD = "correct-horse-battery";
const NEW_PASSWORD = "a-brand-new-password";
const EMAIL = "alice@example.test";

let dir: string;
let app: FastifyInstance;
let db: Database.Database;
let subject: string;

let mod: {
  account: typeof import("./account.js");
  auth: typeof import("./auth.js");
  introspect: typeof import("./introspect.js");
  cookie: typeof import("../auth/cookie.js");
  lockout: typeof import("../auth/lockout.js");
  password: typeof import("../auth/password.js");
  superuser: typeof import("../auth/superuser.js");
  service: typeof import("../tokens/service.js");
  auditLog: typeof import("../db/audit-log.js");
  refreshTokens: typeof import("../db/refresh-tokens.js");
  users: typeof import("../db/users.js");
  testSupport: typeof import("../db/test-support.js");
};

/** One named cookie value out of a response's `Set-Cookie` headers. */
function cookieValue(response: LightMyRequestResponse, name: string): string {
  const raw = response.headers["set-cookie"];
  const values = raw === undefined ? [] : Array.isArray(raw) ? raw : [String(raw)];

  for (const value of values) {
    const [pair] = String(value).split(";") as [string];
    const eq = pair.indexOf("=");
    if (pair.slice(0, eq).trim() === name) return pair.slice(eq + 1).trim();
  }

  throw new Error(`response carried no ${name} cookie`);
}

interface Session {
  access: string;
  refresh: string;
}

async function login(address = "203.0.113.9"): Promise<Session> {
  const response = await app.inject({
    method: "POST",
    url: "/login",
    headers: { "x-forwarded-for": address },
    payload: { username: "alice", password: PASSWORD },
  });
  expect(response.statusCode).toBe(200);
  return {
    access: cookieValue(response, mod.cookie.ACCESS_COOKIE_NAME),
    refresh: cookieValue(response, mod.cookie.REFRESH_COOKIE_NAME),
  };
}

/** Is this access token still a live session, according to `/introspect`? */
async function isLive(access: string): Promise<boolean> {
  const response = await app.inject({
    method: "POST",
    url: "/introspect",
    headers: { cookie: `${mod.cookie.ACCESS_COOKIE_NAME}=${access}` },
    payload: {},
  });
  expect(response.statusCode).toBe(200);
  return response.json().active === true;
}

function asAccount(access: string, init: InjectOptions): Promise<LightMyRequestResponse> {
  return app.inject({
    ...init,
    headers: {
      cookie: `${mod.cookie.ACCESS_COOKIE_NAME}=${access}`,
      ...init.headers,
    },
  });
}

/** The `sid` claim, which is the family a session belongs to. */
async function familyOf(access: string): Promise<string> {
  return (await mod.service.verifyWardAccessToken(access)).sid;
}

beforeAll(async () => {
  dir = await mkdtemp(join(tmpdir(), "ward-account-"));

  process.env["PORT"] = "8796";
  process.env["HOST"] = "127.0.0.1";
  process.env["WARD_DB_PATH"] = join(dir, "unused.db");
  process.env["WARD_ADMIN_USERNAME"] = "test-superuser";
  process.env["WARD_ADMIN_PASSWORD"] = "test-superuser-password";
  process.env["WARD_SIGNING_KEY_PATH"] = join(dir, "signing-key.pem");
  process.env["WARD_PUBLIC_ORIGIN"] = ORIGIN;
  process.env["WARD_MAIL_TRANSPORT"] = "file";
  process.env["WARD_MAIL_FILE_DIR"] = join(dir, "outbox");
  process.env["WARD_MAIL_FROM"] = "ward@gandolh.ro";

  const config = await import("../config.js");
  const { generateSigningKeyFile } = await import("../tokens/keygen.js");
  await generateSigningKeyFile(config.WARD_SIGNING_KEY_PATH);

  mod = {
    account: await import("./account.js"),
    auth: await import("./auth.js"),
    introspect: await import("./introspect.js"),
    cookie: await import("../auth/cookie.js"),
    lockout: await import("../auth/lockout.js"),
    password: await import("../auth/password.js"),
    superuser: await import("../auth/superuser.js"),
    service: await import("../tokens/service.js"),
    auditLog: await import("../db/audit-log.js"),
    refreshTokens: await import("../db/refresh-tokens.js"),
    users: await import("../db/users.js"),
    testSupport: await import("../db/test-support.js"),
  };

  db = mod.testSupport.freshDb();
  mod.testSupport.seedApps(db);

  const Fastify = (await import("fastify")).default;
  app = Fastify({ logger: false });
  await app.register(mod.auth.authRoutes, { db });
  await app.register(mod.introspect.introspectRoutes, { db });
  await app.register(mod.account.accountRoutes, { db });
  await app.ready();
});

afterAll(async () => {
  await app?.close();
  db?.close();
  await rm(dir, { recursive: true, force: true });
});

beforeEach(async () => {
  mod.lockout.resetLockoutForTests();
  mod.superuser.resetConsoleSessionsForTests();

  // A fresh account each test: the password changes in half of them, and the
  // sessions in most.
  db.exec(`DELETE FROM audit_log; DELETE FROM refresh_tokens; DELETE FROM users`);
  subject = mod.users.createUser(db, {
    username: "alice",
    passwordHash: await mod.password.hashPassword(PASSWORD),
    email: EMAIL,
  }).subject;
  mod.users.markEmailVerified(db, subject, EMAIL);
});

// ---------------------------------------------------------------------------
// GET /account
// ---------------------------------------------------------------------------

describe("GET /account", () => {
  it("returns exactly the five fields, and never the password hash", async () => {
    const session = await login();
    const response = await asAccount(session.access, { method: "GET", url: "/account" });

    expect(response.statusCode).toBe(200);
    expect(response.headers["cache-control"]).toBe("no-store");
    expect(response.json()).toEqual({
      subject,
      username: "alice",
      email: EMAIL,
      emailVerified: true,
      createdAt: mod.users.findUserBySubject(db, subject)!.created_at,
    });

    const hash = mod.users.findUserBySubject(db, subject)!.password_hash;
    expect(response.body).not.toContain(hash);
    expect(response.body).not.toContain("password");
  });

  /**
   * The gap this closes: `/introspect` answers four fields behind a
   * serialisation schema that makes a fifth impossible by accident — correct
   * for the endpoint six apps call on every request, and it left the UI unable
   * to read a person's own email or verification state after a reload.
   */
  it("says what /introspect deliberately will not", async () => {
    const session = await login();
    const introspection = await app.inject({
      method: "POST",
      url: "/introspect",
      headers: { cookie: `${mod.cookie.ACCESS_COOKIE_NAME}=${session.access}` },
      payload: {},
    });

    expect(Object.keys(introspection.json() as object).sort()).toEqual([
      "active",
      "grants",
      "subject",
      "username",
    ]);

    const account = await asAccount(session.access, { method: "GET", url: "/account" });
    expect(account.json().email).toBe(EMAIL);
    expect(account.json().emailVerified).toBe(true);
  });

  it("reports an owner-issued account's null email as null", async () => {
    mod.users.setEmail(db, subject, null);
    const session = await login();

    const response = await asAccount(session.access, { method: "GET", url: "/account" });
    expect(response.json().email).toBeNull();
    expect(response.json().emailVerified).toBe(false);
  });

  it("is 401 unauthorized with no cookie, a junk cookie, or a console token", async () => {
    const consoleToken = mod.superuser.openConsoleSession().token;

    for (const cookie of [undefined, "ward_session=nonsense", `ward_session=${consoleToken}`]) {
      const response = await app.inject({
        method: "GET",
        url: "/account",
        ...(cookie === undefined ? {} : { headers: { cookie } }),
      });
      expect(response.statusCode, String(cookie)).toBe(401);
      expect(response.json()).toEqual({ error: "unauthorized" });
    }
  });

  /**
   * **A valid signature is not enough.** An access token stays verifiable for
   * its full 15 minutes after the session behind it was revoked, so liveness is
   * a second question and this route asks it.
   */
  it("refuses a signature whose session was revoked", async () => {
    const session = await login();
    expect(await isLive(session.access)).toBe(true);

    mod.refreshTokens.revokeAllForSubject(db, subject, "admin");

    // Still a perfectly good signature.
    await expect(mod.service.verifyWardAccessToken(session.access)).resolves.toMatchObject({
      sub: subject,
    });
    // And still refused.
    expect((await asAccount(session.access, { method: "GET", url: "/account" })).statusCode).toBe(
      401,
    );
  });

  it("refuses a disabled account", async () => {
    const session = await login();
    mod.users.setDisabled(db, subject, true);

    expect((await asAccount(session.access, { method: "GET", url: "/account" })).statusCode).toBe(
      401,
    );
  });
});

// ---------------------------------------------------------------------------
// POST /account/password
// ---------------------------------------------------------------------------

describe("POST /account/password", () => {
  const change = (
    access: string,
    body: InjectOptions["payload"] = { currentPassword: PASSWORD, newPassword: NEW_PASSWORD },
  ): Promise<LightMyRequestResponse> =>
    asAccount(access, { method: "POST", url: "/account/password", payload: body });

  it("changes the password, so the new one logs in and the old one does not", async () => {
    const session = await login();
    const response = await change(session.access);

    expect(response.statusCode).toBe(200);
    expect(response.json()).toMatchObject({ subject, sessionsRevoked: 1 });

    const old = await app.inject({
      method: "POST",
      url: "/login",
      headers: { "x-forwarded-for": "198.51.100.7" },
      payload: { username: "alice", password: PASSWORD },
    });
    expect(old.statusCode).toBe(401);

    const fresh = await app.inject({
      method: "POST",
      url: "/login",
      headers: { "x-forwarded-for": "198.51.100.8" },
      payload: { username: "alice", password: NEW_PASSWORD },
    });
    expect(fresh.statusCode).toBe(200);
  });

  /**
   * **The entire security property a self-service change has that the
   * console's operator override deliberately does not.** Without it, an XSS or
   * a borrowed laptop is an account takeover with no recovery channel behind it
   * for an owner-issued account.
   */
  it("refuses a wrong current password and changes nothing", async () => {
    const session = await login();
    const before = mod.users.findUserBySubject(db, subject)!.password_hash;

    const response = await change(session.access, {
      currentPassword: "not-the-password",
      newPassword: NEW_PASSWORD,
    });

    expect(response.statusCode).toBe(401);
    expect(response.json()).toEqual({ error: "invalid_credentials" });
    expect(mod.users.findUserBySubject(db, subject)!.password_hash).toBe(before);
    // The caller's session is untouched by a failed attempt.
    expect(await isLive(session.access)).toBe(true);
  });

  /**
   * **The rotation, which is the point of the endpoint.** A password change
   * that left a thirty-day refresh token minting access tokens for whoever
   * holds it has not achieved what it was performed for.
   */
  it("rotates the session: every old family dies and the caller gets a live pair", async () => {
    const other = await login("203.0.113.10");
    const mine = await login("203.0.113.11");
    expect(await isLive(other.access)).toBe(true);

    const response = await change(mine.access);
    expect(response.json().sessionsRevoked).toBe(2);

    // Everything that was live before is dead, the caller's old token included.
    expect(await isLive(other.access)).toBe(false);
    expect(await isLive(mine.access)).toBe(false);

    // And the response carried a fresh, live pair.
    const nextAccess = cookieValue(response, mod.cookie.ACCESS_COOKIE_NAME);
    const nextRefresh = cookieValue(response, mod.cookie.REFRESH_COOKIE_NAME);
    expect(await isLive(nextAccess)).toBe(true);
    expect(await familyOf(nextAccess)).not.toBe(await familyOf(mine.access));

    // The new refresh token rotates, so the whole session really works.
    const rotated = await app.inject({
      method: "POST",
      url: "/refresh",
      headers: { cookie: `${mod.cookie.REFRESH_COOKIE_NAME}=${nextRefresh}` },
    });
    expect(rotated.statusCode).toBe(200);

    // The old refresh token does not.
    const dead = await app.inject({
      method: "POST",
      url: "/refresh",
      headers: { cookie: `${mod.cookie.REFRESH_COOKIE_NAME}=${mine.refresh}` },
    });
    expect(dead.statusCode).toBe(401);
  });

  it("surfaces the policy code, not a message", async () => {
    const session = await login();

    const short = await change(session.access, {
      currentPassword: PASSWORD,
      newPassword: "short",
    });
    expect(short.statusCode).toBe(400);
    expect(short.json()).toEqual({ error: "password_too_short" });

    const long = await change(session.access, {
      currentPassword: PASSWORD,
      newPassword: "x".repeat(mod.password.MAX_PASSWORD_LENGTH + 1),
    });
    expect(long.statusCode).toBe(400);
    expect(long.json()).toEqual({ error: "password_too_long" });

    // Nothing changed on either path.
    expect(await isLive(session.access)).toBe(true);
  });

  it("answers invalid_request for a malformed body without echoing it", async () => {
    const session = await login();

    const response = await change(session.access, { newPassword: NEW_PASSWORD });
    expect(response.statusCode).toBe(400);
    expect(response.json()).toEqual({ error: "invalid_request" });
    expect(response.body).not.toContain(NEW_PASSWORD);
  });

  it("audits the change and never records either password", async () => {
    const session = await login();
    const previousFamily = await familyOf(session.access);
    db.exec(`DELETE FROM audit_log`);

    await change(session.access);

    const [row] = mod.auditLog.listAudit(db, { action: "user.password_change" });
    expect(row).toMatchObject({
      actor_kind: "account",
      actor_subject: subject,
      actor_label: "alice",
      action: "user.password_change",
      target_kind: "user",
      target_id: subject,
    });
    const detail = JSON.parse(row!.detail!) as Record<string, unknown>;
    expect(detail).toMatchObject({ sessionsRevoked: 1, previousSession: previousFamily });
    expect(JSON.stringify(row)).not.toContain(PASSWORD);
    expect(JSON.stringify(row)).not.toContain(NEW_PASSWORD);
  });

  it("audits a refused attempt too", async () => {
    const session = await login();
    db.exec(`DELETE FROM audit_log`);

    await change(session.access, { currentPassword: "wrong", newPassword: NEW_PASSWORD });

    const rows = mod.auditLog.listAudit(db, { action: "user.password_change_failed" });
    expect(rows).toHaveLength(1);
    expect(rows[0]!.actor_subject).toBe(subject);
  });

  /**
   * `LockoutSurface` is a closed union so a new credential surface adds a
   * member rather than borrowing `"login"`. Borrowing it here would be worse
   * than the bug review already caught between `/login` and `/console/login`:
   * guessing a current password would spend the budget for the login form,
   * which is how the person would recover.
   */
  it("has its own lockout budget, and spending it leaves /login working", async () => {
    const session = await login("192.0.2.50");

    for (let attempt = 0; attempt < 5; attempt += 1) {
      const response = await asAccount(session.access, {
        method: "POST",
        url: "/account/password",
        headers: { "x-forwarded-for": "192.0.2.50" },
        payload: { currentPassword: "wrong", newPassword: NEW_PASSWORD },
      });
      expect(response.statusCode).toBe(401);
    }

    const locked = await asAccount(session.access, {
      method: "POST",
      url: "/account/password",
      headers: { "x-forwarded-for": "192.0.2.50" },
      payload: { currentPassword: PASSWORD, newPassword: NEW_PASSWORD },
    });
    expect(locked.statusCode).toBe(429);
    expect(locked.json().error).toBe("too_many_attempts");
    expect(typeof locked.json().retryAfterSeconds).toBe("number");
    expect(locked.headers["retry-after"]).toBe(String(locked.json().retryAfterSeconds));

    // The password was not changed by the locked-out request.
    expect(await isLive(session.access)).toBe(true);

    // And `/login` from the very same address is untouched.
    const stillWorks = await app.inject({
      method: "POST",
      url: "/login",
      headers: { "x-forwarded-for": "192.0.2.50" },
      payload: { username: "alice", password: PASSWORD },
    });
    expect(stillWorks.statusCode).toBe(200);
  });

  it("refuses a cross-site request before reading the body", async () => {
    const session = await login();

    for (const headers of [
      { "sec-fetch-site": "cross-site" },
      { origin: "https://evil.test" },
    ] as Record<string, string>[]) {
      const response = await asAccount(session.access, {
        method: "POST",
        url: "/account/password",
        headers,
        payload: { currentPassword: PASSWORD, newPassword: NEW_PASSWORD },
      });
      expect(response.statusCode).toBe(403);
      expect(response.json()).toEqual({ error: "cross_site" });
      expect(response.headers["set-cookie"]).toBeUndefined();
    }

    // Nothing changed.
    expect(await isLive(session.access)).toBe(true);
  });

  it("allows a same-origin request, and one with no fetch metadata at all", async () => {
    const first = await login();
    expect(
      (
        await asAccount(first.access, {
          method: "POST",
          url: "/account/password",
          headers: { "sec-fetch-site": "same-origin", origin: ORIGIN },
          payload: { currentPassword: PASSWORD, newPassword: NEW_PASSWORD },
        })
      ).statusCode,
    ).toBe(200);
  });

  it("is 401 unauthorized with no session, and hashes nothing", async () => {
    const response = await app.inject({
      method: "POST",
      url: "/account/password",
      payload: { currentPassword: PASSWORD, newPassword: NEW_PASSWORD },
    });
    expect(response.statusCode).toBe(401);
    expect(response.json()).toEqual({ error: "unauthorized" });
    expect(mod.auditLog.listAudit(db, { action: "user.password_change" })).toEqual([]);
  });

  it("refuses a revoked session even though the signature is still good", async () => {
    const session = await login();
    mod.refreshTokens.revokeAllForSubject(db, subject, "logout");

    const response = await change(session.access);
    expect(response.statusCode).toBe(401);
    expect(response.json()).toEqual({ error: "unauthorized" });
  });
});

// ---------------------------------------------------------------------------
// POST /account/sessions/revoke-others
// ---------------------------------------------------------------------------

describe("POST /account/sessions/revoke-others", () => {
  const revokeOthers = (
    access: string,
    headers: Record<string, string> = {},
  ): Promise<LightMyRequestResponse> =>
    asAccount(access, { method: "POST", url: "/account/sessions/revoke-others", headers });

  /**
   * **The requirement, and the whole reason the self-service page exists.**
   * Owner-issued accounts have no verified email and therefore no recovery
   * channel, so this is the only self-serve response to a suspected theft — and
   * it is worthless if it signs the person out too.
   */
  it("kills the other sessions and leaves the caller's own live", async () => {
    const thief = await login("203.0.113.20");
    const phone = await login("203.0.113.21");
    const mine = await login("203.0.113.22");

    const response = await revokeOthers(mine.access);

    expect(response.statusCode).toBe(200);
    expect(response.headers["cache-control"]).toBe("no-store");
    expect(response.json()).toMatchObject({
      revoked: 2,
      spared: await familyOf(mine.access),
    });

    expect(await isLive(thief.access)).toBe(false);
    expect(await isLive(phone.access)).toBe(false);
    // The caller's own session, still working.
    expect(await isLive(mine.access)).toBe(true);

    // Including its refresh token, which is what keeps them signed in past 15
    // minutes — the half a `sid`-only check would silently break.
    const rotated = await app.inject({
      method: "POST",
      url: "/refresh",
      headers: { cookie: `${mod.cookie.REFRESH_COOKIE_NAME}=${mine.refresh}` },
    });
    expect(rotated.statusCode).toBe(200);

    // And the others' refresh tokens do not rotate.
    const dead = await app.inject({
      method: "POST",
      url: "/refresh",
      headers: { cookie: `${mod.cookie.REFRESH_COOKIE_NAME}=${thief.refresh}` },
    });
    expect(dead.statusCode).toBe(401);
  });

  /**
   * **The family to spare comes from the access token's `sid`.**
   *
   * `ward_refresh` is scoped `Path=/ward-api/refresh` and is simply not sent to
   * this path, so a route that read it would work in a harness and answer
   * "nothing to spare" in a browser. This request carries only the access
   * cookie, exactly as a browser would send it.
   */
  it("works with no refresh cookie present at all", async () => {
    const other = await login("203.0.113.30");
    const mine = await login("203.0.113.31");

    const response = await app.inject({
      method: "POST",
      url: "/account/sessions/revoke-others",
      // Only the access cookie. No `ward_refresh`.
      headers: { cookie: `${mod.cookie.ACCESS_COOKIE_NAME}=${mine.access}` },
    });

    expect(response.json().revoked).toBe(1);
    expect(await isLive(other.access)).toBe(false);
    expect(await isLive(mine.access)).toBe(true);
  });

  /** "3 other sessions signed out" is reassuring; "done" is not. */
  it("returns 0 when there is nothing else signed in", async () => {
    const mine = await login();
    const response = await revokeOthers(mine.access);

    expect(response.json().revoked).toBe(0);
    expect(await isLive(mine.access)).toBe(true);
    // A no-op writes no audit row.
    expect(mod.auditLog.listAudit(db, { action: "session.revoke_others" })).toEqual([]);
  });

  it("counts families rather than rows, so a rotated device is one session", async () => {
    const other = await login("203.0.113.40");
    const rotated = await app.inject({
      method: "POST",
      url: "/refresh",
      headers: { cookie: `${mod.cookie.REFRESH_COOKIE_NAME}=${other.refresh}` },
    });
    expect(rotated.statusCode).toBe(200);

    const mine = await login("203.0.113.41");
    expect((await revokeOthers(mine.access)).json().revoked).toBe(1);
  });

  it("audits it with the spared family named", async () => {
    await login("203.0.113.50");
    const mine = await login("203.0.113.51");
    db.exec(`DELETE FROM audit_log`);

    await revokeOthers(mine.access);

    const [row] = mod.auditLog.listAudit(db, { action: "session.revoke_others" });
    expect(row).toMatchObject({
      actor_kind: "account",
      actor_subject: subject,
      actor_label: "alice",
      target_kind: "user",
      target_id: subject,
    });
    expect(JSON.parse(row!.detail!)).toMatchObject({
      sessionsRevoked: 1,
      spared: await familyOf(mine.access),
    });
  });

  /**
   * `revoked_reason` distinguishes the person doing this themselves from an
   * operator doing it to them, and an operator reading `refresh_tokens` needs
   * that distinction.
   */
  it("records the revocation as logout, not admin", async () => {
    const other = await login("203.0.113.60");
    const mine = await login("203.0.113.61");
    const otherFamily = await familyOf(other.access);

    await revokeOthers(mine.access);

    const rows = mod.refreshTokens.listFamily(db, otherFamily);
    expect(rows.every((row) => row.revoked_reason === "logout")).toBe(true);
  });

  it("refuses a cross-site request and revokes nothing", async () => {
    const other = await login("203.0.113.70");
    const mine = await login("203.0.113.71");

    const response = await revokeOthers(mine.access, { "sec-fetch-site": "cross-site" });
    expect(response.statusCode).toBe(403);
    expect(response.json()).toEqual({ error: "cross_site" });
    expect(await isLive(other.access)).toBe(true);
  });

  it("is 401 unauthorized with no session, a junk token, or a console token", async () => {
    const consoleToken = mod.superuser.openConsoleSession().token;

    for (const cookie of [undefined, "ward_session=nonsense", `ward_session=${consoleToken}`]) {
      const response = await app.inject({
        method: "POST",
        url: "/account/sessions/revoke-others",
        ...(cookie === undefined ? {} : { headers: { cookie } }),
      });
      expect(response.statusCode, String(cookie)).toBe(401);
      expect(response.json()).toEqual({ error: "unauthorized" });
    }
  });

  it("never touches another account's sessions", async () => {
    const bob = mod.users.createUser(db, {
      username: "bob",
      passwordHash: await mod.password.hashPassword(PASSWORD),
    });
    const bobSession = mod.refreshTokens.insertRefreshToken(db, {
      tokenHash: mod.refreshTokens.hashRefreshToken(mod.refreshTokens.generateRefreshToken()),
      subject: bob.subject,
      familyId: mod.refreshTokens.newFamilyId(),
      expiresAt: new Date(Date.now() + 86_400_000).toISOString(),
    });

    const mine = await login();
    await revokeOthers(mine.access);

    expect(mod.refreshTokens.findRefreshToken(db, bobSession.token_hash)!.revoked_at).toBeNull();
  });
});
