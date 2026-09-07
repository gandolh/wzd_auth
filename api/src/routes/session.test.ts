import type Database from "better-sqlite3";
import type { FastifyInstance, LightMyRequestResponse } from "fastify";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterAll, beforeAll, beforeEach, describe, expect, it } from "vitest";

/**
 * `GET /session` — the cookie half of introspection, over a real login.
 *
 * These are the tests that used to live in `introspect.test.ts` under "a
 * cookie-only caller", plus the ones that pin what makes this route safe to
 * leave unkeyed. The split happened when `POST /introspect` grew a mandatory
 * `x-ward-app-key`: a key in Ward's own Vite bundle would be a published
 * string, so the browser caller needed a route that authenticates with the
 * cookie it already has.
 *
 * Every import of `../config.js` and its dependents is dynamic, for the reason
 * `introspect.test.ts` documents: `config.ts` validates the environment at
 * import time and would be hoisted above the `process.env` assignments below.
 */

const ORIGIN = "https://ward.test";
const PASSWORD = "correct-horse-battery";

let dir: string;
let app: FastifyInstance;
let db: Database.Database;
let subject: string;

let mod: {
  session: typeof import("./session.js");
  auth: typeof import("./auth.js");
  cookie: typeof import("../auth/cookie.js");
  lockout: typeof import("../auth/lockout.js");
  password: typeof import("../auth/password.js");
  superuser: typeof import("../auth/superuser.js");
  service: typeof import("../tokens/service.js");
  mint: typeof import("../tokens/mint.js");
  grants: typeof import("../db/grants.js");
  refreshTokens: typeof import("../db/refresh-tokens.js");
  users: typeof import("../db/users.js");
  testSupport: typeof import("../db/test-support.js");
};

function cookieValue(response: LightMyRequestResponse, name: string): string {
  const raw = response.headers["set-cookie"];
  const values = raw === undefined ? [] : Array.isArray(raw) ? raw : [String(raw)];

  for (const value of values) {
    const [pair] = String(value).split(";") as [string];
    const eq = pair.indexOf("=");
    if (pair.slice(0, eq).trim() === name) return pair.slice(eq + 1).trim();
  }

  throw new Error(`login response carried no ${name} cookie`);
}

async function login(username = "alice"): Promise<LightMyRequestResponse> {
  const response = await app.inject({
    method: "POST",
    url: "/login",
    headers: { "x-forwarded-for": "203.0.113.9" },
    payload: { username, password: PASSWORD },
  });
  expect(response.statusCode).toBe(200);
  return response;
}

/** Read the session the way the UI does: `GET`, cookie, nothing else. */
async function readSession(token: string | undefined): Promise<LightMyRequestResponse> {
  return app.inject({
    method: "GET",
    url: "/session",
    headers: token === undefined ? {} : { cookie: `${mod.cookie.ACCESS_COOKIE_NAME}=${token}` },
  });
}

beforeAll(async () => {
  dir = await mkdtemp(join(tmpdir(), "ward-session-"));

  process.env["PORT"] = "8798";
  process.env["HOST"] = "127.0.0.1";
  process.env["WARD_DB_PATH"] = join(dir, "unused.db");
  process.env["WARD_ADMIN_USERNAME"] = "test-superuser";
  process.env["WARD_ADMIN_PASSWORD"] = "test-superuser-password";
  process.env["WARD_SIGNING_KEY_PATH"] = join(dir, "signing-key.pem");
  process.env["WARD_PUBLIC_ORIGIN"] = ORIGIN;
  process.env["WARD_MAIL_TRANSPORT"] = "file";
  process.env["WARD_MAIL_FILE_DIR"] = "api/mail-outbox";
  process.env["WARD_MAIL_FROM"] = "ward@gandolh.ro";

  const config = await import("../config.js");
  const { generateSigningKeyFile } = await import("../tokens/keygen.js");
  await generateSigningKeyFile(config.WARD_SIGNING_KEY_PATH);

  mod = {
    session: await import("./session.js"),
    auth: await import("./auth.js"),
    cookie: await import("../auth/cookie.js"),
    lockout: await import("../auth/lockout.js"),
    password: await import("../auth/password.js"),
    superuser: await import("../auth/superuser.js"),
    service: await import("../tokens/service.js"),
    mint: await import("../tokens/mint.js"),
    grants: await import("../db/grants.js"),
    refreshTokens: await import("../db/refresh-tokens.js"),
    users: await import("../db/users.js"),
    testSupport: await import("../db/test-support.js"),
  };

  db = mod.testSupport.freshDb();
  mod.testSupport.seedApps(db);

  const Fastify = (await import("fastify")).default;
  app = Fastify({ logger: false });
  await app.register(mod.auth.authRoutes, { db });
  await app.register(mod.session.sessionRoutes, { db });
  await app.ready();
});

afterAll(async () => {
  await app?.close();
  db?.close();
  await rm(dir, { recursive: true, force: true });
});

beforeEach(async () => {
  mod.lockout.resetLockoutForTests();
  db.exec(`DELETE FROM refresh_tokens; DELETE FROM grants; DELETE FROM users`);
  subject = mod.users.createUser(db, {
    username: "Alice",
    passwordHash: await mod.password.hashPassword(PASSWORD),
    email: "alice@example.test",
  }).subject;
});

function grant(appSlug: string, role: string): void {
  mod.grants.grantRole(db, {
    subject,
    appSlug,
    role,
    grantedBy: mod.grants.SUPERUSER_ACTOR,
  });
}

describe("a live session", () => {
  it("answers the subject, the username and the whole grant map", async () => {
    grant("atrium", "admin");
    grant("prm", "user");

    const response = await readSession(cookieValue(await login(), mod.cookie.ACCESS_COOKIE_NAME));

    expect(response.statusCode).toBe(200);
    expect(response.json()).toEqual({
      active: true,
      subject,
      username: "Alice",
      grants: { atrium: ["admin"], prm: ["user"] },
    });
  });

  /**
   * The reason the split was cheap: `ui/src/lib/session.ts` was written against
   * `/introspect`'s body and its "always 200" contract, and only its URL had to
   * change. If these two shapes ever drift, that file breaks silently.
   */
  it("returns exactly the shape /introspect returns, field for field", async () => {
    grant("newspapper", "reader");
    const live = await readSession(cookieValue(await login(), mod.cookie.ACCESS_COOKIE_NAME));

    expect(Object.keys(live.json() as object).sort()).toEqual([
      "active",
      "grants",
      "subject",
      "username",
    ]);
  });

  it("is never cached by anything in the chain", async () => {
    const response = await readSession(cookieValue(await login(), mod.cookie.ACCESS_COOKIE_NAME));
    expect(response.headers["cache-control"]).toBe("no-store");
  });
});

describe("active is false", () => {
  const inactive = JSON.stringify({ active: false });

  it("for a request with no cookie at all", async () => {
    const response = await readSession(undefined);
    expect(response.statusCode).toBe(200);
    expect(response.body).toBe(inactive);
  });

  it("for a token that is not a JWS", async () => {
    expect((await readSession("not-a-token")).body).toBe(inactive);
  });

  it("for a console token, which is how the superuser has no self-service page", async () => {
    const opened = mod.superuser.openConsoleSession();
    expect(mod.superuser.resolveConsoleSession(opened.token)).toBeDefined();
    expect((await readSession(opened.token)).body).toBe(inactive);
  });

  it("after a logout, even though the access token still verifies", async () => {
    const session = await login();
    const access = cookieValue(session, mod.cookie.ACCESS_COOKIE_NAME);
    const refresh = cookieValue(session, mod.cookie.REFRESH_COOKIE_NAME);

    expect((await readSession(access)).json()).toMatchObject({ active: true });

    const out = await app.inject({
      method: "POST",
      url: "/logout",
      headers: {
        cookie: `${mod.cookie.REFRESH_COOKIE_NAME}=${refresh}`,
        "sec-fetch-site": "same-origin",
      },
    });
    expect(out.statusCode).toBe(204);

    // The signature is still perfectly good — liveness is a separate question,
    // and it is the one this route answers.
    await expect(mod.service.verifyWardAccessToken(access)).resolves.toBeDefined();
    expect((await readSession(access)).body).toBe(inactive);
  });

  it("as soon as the account is disabled", async () => {
    const access = cookieValue(await login(), mod.cookie.ACCESS_COOKIE_NAME);
    expect((await readSession(access)).json()).toMatchObject({ active: true });

    mod.users.setDisabled(db, subject, true);
    expect((await readSession(access)).body).toBe(inactive);
  });
});

/**
 * The property that made splitting this route worthwhile rather than exempting
 * cookie-bearing requests on `/introspect`.
 *
 * The exemption would have been worthless because an attacker chooses their own
 * headers — moving a token from a body into a `Cookie:` header is a one-line
 * change to a `curl` command. What makes *this* route acceptable unkeyed is
 * narrower: the token can come from the cookie and from nowhere else, so the
 * route grants no capability that setting the cookie did not already grant.
 */
describe("the token comes from the cookie and nowhere else", () => {
  it("ignores an access token offered in the query string", async () => {
    const access = cookieValue(await login(), mod.cookie.ACCESS_COOKIE_NAME);

    const response = await app.inject({
      method: "GET",
      url: `/session?accessToken=${encodeURIComponent(access)}`,
    });

    // No cookie header, so: not signed in — despite a live token being right
    // there in the URL. This also keeps the token out of Fastify's request log
    // line from ever being *useful*, which is the constraint `introspect.ts`
    // records about query strings.
    expect(response.body).toBe(JSON.stringify({ active: false }));
  });

  it("ignores an access token offered in a header", async () => {
    const access = cookieValue(await login(), mod.cookie.ACCESS_COOKIE_NAME);

    const response = await app.inject({
      method: "GET",
      url: "/session",
      headers: { authorization: `Bearer ${access}` },
    });

    expect(response.body).toBe(JSON.stringify({ active: false }));
  });
});
