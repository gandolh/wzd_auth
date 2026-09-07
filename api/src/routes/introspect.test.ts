import type Database from "better-sqlite3";
import type { FastifyInstance, LightMyRequestResponse } from "fastify";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterAll, beforeAll, beforeEach, describe, expect, it } from "vitest";

/**
 * `POST /introspect` end to end, over a real login.
 *
 * ## Registered directly, not through `buildApp()`
 *
 * `app.ts` belongs to the controller and wires this brief's plugin in after it
 * lands, so this file builds its own Fastify instance and registers
 * `introspectRoutes` into it — alongside brief 03's `authRoutes`, which is
 * landed and stable, so the "live session" under test is one a real `POST
 * /login` produced rather than one a fixture faked. That also keeps these tests
 * clear of brief 05's routes, which are landing in parallel.
 *
 * ## Every import of `../config.js` and its dependents is dynamic
 *
 * `config.ts` validates the environment at import time and calls
 * `process.exit(1)` on anything missing. A static import here would be hoisted
 * above the `process.env` assignments in `beforeAll` and take the whole test
 * worker with it — the trap `routes/auth.test.ts` and `tokens/jwks-route.test.ts`
 * both document.
 */

const ORIGIN = "https://ward.test";
const PASSWORD = "correct-horse-battery";
const EMAIL = "alice@example.test";

let dir: string;
let app: FastifyInstance;
let db: Database.Database;
let subject: string;
/** The plaintext app key every keyed request in this file presents. */
let appKey: string;

let mod: {
  introspect: typeof import("./introspect.js");
  appKey: typeof import("../auth/app-key.js");
  appKeys: typeof import("../db/app-keys.js");
  auth: typeof import("./auth.js");
  resolve: typeof import("../grants/resolve.js");
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

/** The `ward_session` value from a login response's `Set-Cookie` headers. */
function accessCookie(response: LightMyRequestResponse): string {
  const raw = response.headers["set-cookie"];
  const values = raw === undefined ? [] : Array.isArray(raw) ? raw : [String(raw)];

  for (const value of values) {
    const [pair] = String(value).split(";") as [string];
    const eq = pair.indexOf("=");
    if (pair.slice(0, eq).trim() === mod.cookie.ACCESS_COOKIE_NAME) {
      return pair.slice(eq + 1).trim();
    }
  }

  throw new Error("login response carried no ward_session cookie");
}

/** The `ward_refresh` value, for driving `/logout`. */
function refreshCookie(response: LightMyRequestResponse): string {
  const raw = response.headers["set-cookie"];
  const values = raw === undefined ? [] : Array.isArray(raw) ? raw : [String(raw)];

  for (const value of values) {
    const [pair] = String(value).split(";") as [string];
    const eq = pair.indexOf("=");
    if (pair.slice(0, eq).trim() === mod.cookie.REFRESH_COOKIE_NAME) {
      return pair.slice(eq + 1).trim();
    }
  }

  throw new Error("login response carried no ward_refresh cookie");
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

/**
 * Introspect the way every consuming app does: the token in the body, this
 * app's key in `x-ward-app-key`.
 *
 * There is no cookie variant any more. The cookie path moved to `GET /session`
 * (`session.test.ts`) when the key requirement made a browser caller
 * impossible — see `routes/session.ts` on why a cookie-shaped exemption would
 * have protected nothing.
 */
async function introspect(accessToken: string): Promise<LightMyRequestResponse> {
  return app.inject({
    method: "POST",
    url: "/introspect",
    headers: { [mod.appKey.APP_KEY_HEADER]: appKey },
    payload: { accessToken },
  });
}

/** Introspect with a caller-chosen key — or none, when `key` is undefined. */
async function introspectWithKey(
  accessToken: string,
  key: string | undefined,
): Promise<LightMyRequestResponse> {
  return app.inject({
    method: "POST",
    url: "/introspect",
    headers: key === undefined ? {} : { [mod.appKey.APP_KEY_HEADER]: key },
    payload: { accessToken },
  });
}

/** A correctly-signed token for any subject, optionally already expired. */
async function mintFor(forSubject: string, issuedAt?: Date): Promise<string> {
  const keys = await mod.service.getKeySet();
  const minted = await mod.mint.signAccessToken({
    subject: forSubject,
    // No real refresh row backs this session — these tokens exist to probe
    // rejection paths (no account, expired, tampered) that never reach the
    // family-liveness check, so a fresh unregistered family id is honest here.
    sessionId: mod.refreshTokens.newFamilyId(),
    signingKey: keys.current,
    issuer: ORIGIN,
    ...(issuedAt ? { now: issuedAt } : {}),
  });
  return minted.token;
}

beforeAll(async () => {
  dir = await mkdtemp(join(tmpdir(), "ward-introspect-"));

  process.env["PORT"] = "8794";
  process.env["HOST"] = "127.0.0.1";
  process.env["WARD_DB_PATH"] = join(dir, "unused.db");
  process.env["WARD_ADMIN_USERNAME"] = "test-superuser";
  process.env["WARD_ADMIN_PASSWORD"] = "test-superuser-password";
  process.env["WARD_SIGNING_KEY_PATH"] = join(dir, "signing-key.pem");
  process.env["WARD_PUBLIC_ORIGIN"] = ORIGIN;
  // Mail is part of the required environment contract (brief 07). `file`
  // transport needs no SMTP credentials, which is the point of having a mode.
  process.env["WARD_MAIL_TRANSPORT"] = "file";
  process.env["WARD_MAIL_FILE_DIR"] = "api/mail-outbox";
  process.env["WARD_MAIL_FROM"] = "ward@gandolh.ro";

  const config = await import("../config.js");
  const { generateSigningKeyFile } = await import("../tokens/keygen.js");
  await generateSigningKeyFile(config.WARD_SIGNING_KEY_PATH);

  mod = {
    introspect: await import("./introspect.js"),
    appKey: await import("../auth/app-key.js"),
    appKeys: await import("../db/app-keys.js"),
    auth: await import("./auth.js"),
    resolve: await import("../grants/resolve.js"),
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

  // `openDatabase(":memory:")`, never `getDb()` — `WARD_DB_PATH` above names a
  // file that is deliberately never created.
  db = mod.testSupport.freshDb();
  mod.testSupport.seedApps(db);
  appKey = mod.testSupport.seedAppKey(db, "atrium");

  const Fastify = (await import("fastify")).default;
  app = Fastify({ logger: false });
  await app.register(mod.auth.authRoutes, { db });
  await app.register(mod.introspect.introspectRoutes, { db });
  await app.ready();
});

afterAll(async () => {
  await app?.close();
  db?.close();
  await rm(dir, { recursive: true, force: true });
});

beforeEach(async () => {
  mod.lockout.resetLockoutForTests();

  // A clean account per test: these tests disable it, revoke its families and
  // change its grants, and none of that should reach the next one.
  db.exec(`DELETE FROM refresh_tokens; DELETE FROM grants; DELETE FROM users`);
  subject = mod.users.createUser(db, {
    username: "Alice",
    passwordHash: await mod.password.hashPassword(PASSWORD),
    email: EMAIL,
  }).subject;
});

/** Grant a role the way brief 05's console will: a row in `grants`. */
function grant(appSlug: string, role: string): void {
  mod.grants.grantRole(db, {
    subject,
    appSlug,
    role,
    grantedBy: mod.grants.SUPERUSER_ACTOR,
  });
}

describe("a live session", () => {
  it("returns active with the subject, the username and the grants", async () => {
    grant("atrium", "admin");
    grant("atrium", "editor");
    grant("newspapper", "reader");

    const session = await login();
    const response = await introspect(accessCookie(session));

    expect(response.statusCode).toBe(200);
    expect(response.json()).toEqual({
      active: true,
      subject,
      username: "Alice",
      grants: { atrium: ["admin", "editor"], newspapper: ["reader"] },
    });
  });

  it("accepts the token in the body, for a server-to-server caller with no cookie jar", async () => {
    grant("prm", "user");
    const session = await login();

    const response = await introspect(accessCookie(session));

    expect(response.statusCode).toBe(200);
    expect(response.json()).toMatchObject({ active: true, subject, grants: { prm: ["user"] } });
  });

  /**
   * The cookie used to win over the body here. It now does nothing at all, and
   * that is worth an explicit test rather than an absence: an implementation
   * that still read the cookie would pass every other test in this file while
   * quietly answering for the wrong person.
   */
  it("ignores the ward_session cookie entirely and answers for the body's token", async () => {
    const session = await login();
    const mine = accessCookie(session);
    const somebodyElse = await mintFor("0".repeat(32));

    const response = await app.inject({
      method: "POST",
      url: "/introspect",
      headers: {
        [mod.appKey.APP_KEY_HEADER]: appKey,
        cookie: `${mod.cookie.ACCESS_COOKIE_NAME}=${mine}`,
      },
      payload: { accessToken: somebodyElse },
    });

    // The body's token names a subject with no account, so: not live. If the
    // cookie were still consulted this would come back active as `subject`.
    expect(response.json()).toEqual({ active: false });
  });

  it("answers inactive for a cookie-only caller that posts no body at all", async () => {
    const session = await login();

    const response = await app.inject({
      method: "POST",
      url: "/introspect",
      headers: {
        [mod.appKey.APP_KEY_HEADER]: appKey,
        cookie: `${mod.cookie.ACCESS_COOKIE_NAME}=${accessCookie(session)}`,
      },
    });

    // A live session, presented the way a browser would — and refused, because
    // this route no longer has a browser path. `GET /session` is where that
    // caller went.
    expect(response.statusCode).toBe(200);
    expect(response.json()).toEqual({ active: false });
  });

  it("is never cached by anything in the chain", async () => {
    const session = await login();
    const response = await introspect(accessCookie(session));

    // The 30-second cache is the calling app's own in-process one, keyed per
    // session. A per-person authorisation answer in a shared HTTP cache is one
    // person's grants served to the next caller.
    expect(response.headers["cache-control"]).toBe("no-store");
  });

  /**
   * The acceptance criterion about permission changes landing in the same
   * window a revocation does. Brief 05 owns the console route that writes the
   * grant and is running in parallel, so this asserts the database write; the
   * controller's integration chunk asserts it through that route later.
   */
  it("shows a grant added directly to the database on the next call, with no reissue", async () => {
    const session = await login();
    const token = accessCookie(session);

    expect((await introspect(token)).json()).toMatchObject({ grants: {} });

    grant("prm", "admin");

    // Same cookie, same token, new authority. This is why grants ride in the
    // response rather than in the claims.
    expect((await introspect(token)).json()).toMatchObject({
      active: true,
      grants: { prm: ["admin"] },
    });
  });
});

describe("the response carries nothing an app cannot justify", () => {
  it("has exactly four fields, and never the hash or the address", async () => {
    grant("atrium", "admin");
    const session = await login();

    const response = await introspect(accessCookie(session));
    const body = response.json<Record<string, unknown>>();

    expect(Object.keys(body).sort()).toEqual(["active", "grants", "subject", "username"]);

    const row = mod.users.findUserBySubject(db, subject)!;
    expect(response.body).not.toContain(EMAIL);
    expect(response.body).not.toContain(row.password_hash);
    // The scrypt salt on its own is not a secret, but it has no business here
    // either — asserting on it catches a partial leak of the credential field.
    expect(response.body).not.toContain(row.password_hash.split(":")[0]!);
    expect(response.body).not.toContain("disabled_at");
  });

  it("serialises a live session to exactly the documented body and nothing more", async () => {
    const token = accessCookie(await login());

    expect((await introspect(token)).body).toBe(
      JSON.stringify({ active: true, subject, username: "Alice", grants: {} }),
    );
  });

  it("strips any field the response schema does not name, structurally", async () => {
    /**
     * The schema is a **filter**, not documentation: `fast-json-stringify`
     * emits only the named properties, so a future change that returned a whole
     * `UserRow` from `resolveSession` still could not put `password_hash` or
     * `email` on the wire.
     *
     * Proven by pushing exactly that through the real exported schema on a
     * throwaway instance, rather than by trusting the comment.
     */
    const row = mod.users.findUserBySubject(db, subject)!;
    // Sanity: the row genuinely holds what must not travel — `saltHex:hashHex`
    // from `auth/password.ts`, and the address.
    expect(row.password_hash).toMatch(/^[0-9a-f]+:[0-9a-f]+$/);
    expect(row.email).toBe(EMAIL);

    const Fastify = (await import("fastify")).default;
    const probe = Fastify({ logger: false });
    probe.post(
      "/probe",
      { schema: { response: mod.introspect.INTROSPECT_RESPONSE_SCHEMA } },
      // The whole `UserRow` — hash, address, timestamps — plus the two
      // fields the answer legitimately adds.
      async () => ({ ...row, active: true, grants: {} }),
    );
    await probe.ready();

    const response = await probe.inject({ method: "POST", url: "/probe" });
    await probe.close();

    expect(Object.keys(response.json<Record<string, unknown>>()).sort()).toEqual([
      "active",
      "grants",
      "subject",
      "username",
    ]);
    expect(response.body).not.toContain(row.password_hash);
    expect(response.body).not.toContain(EMAIL);
  });
});

describe("active is false", () => {
  /** Every inactive cause, as an exact response body, collected in one place. */
  const inactive = JSON.stringify({ active: false });

  it("for a request with no token anywhere", async () => {
    const response = await app.inject({
      method: "POST",
      url: "/introspect",
      headers: { [mod.appKey.APP_KEY_HEADER]: appKey },
      payload: {},
    });

    expect(response.statusCode).toBe(200);
    expect(response.body).toBe(inactive);
  });

  it("for an unparseable body", async () => {
    // An integration bug — `{ token }` instead of `{ accessToken }` — reads as
    // "signed out" rather than as a second failure mode for an app to handle.
    const response = await app.inject({
      method: "POST",
      url: "/introspect",
      headers: { [mod.appKey.APP_KEY_HEADER]: appKey },
      payload: { token: "wrong-field-name" },
    });

    expect(response.statusCode).toBe(200);
    expect(response.body).toBe(inactive);
  });

  it("for a token that is not a JWS at all", async () => {
    expect((await introspect("not-a-token")).body).toBe(inactive);
  });

  it("for a token whose signature has been tampered with", async () => {
    const token = accessCookie(await login());
    const [header, payload, signature] = token.split(".") as [string, string, string];

    /**
     * Flipped in the **middle**, not at the end.
     *
     * An earlier version of this test rewrote the last two characters, and was
     * flaky at roughly 1 run in 256. An Ed25519 signature is 64 bytes, which is
     * 86 base64url characters, and the final character carries only 2 significant
     * bits — its other 4 are ignored on decode. So `"AA"` and `"AB"` decode to
     * byte-identical signatures, and whenever the original happened to end in a
     * character pair that collapsed the same way, the "tampered" token was in
     * fact the untampered one and verified perfectly.
     *
     * A character in the middle has all 6 bits significant, so changing it
     * always changes the bytes.
     */
    const at = Math.floor(signature.length / 2);
    const tampered =
      signature.slice(0, at) + (signature[at] === "A" ? "B" : "A") + signature.slice(at + 1);
    expect(tampered).not.toBe(signature);

    expect((await introspect(`${header}.${payload}.${tampered}`)).body).toBe(inactive);
  });

  it("for an expired token, however recently the session was live", async () => {
    await login(); // a live family exists, so only `exp` can be the reason
    const stale = await mintFor(subject, new Date(Date.now() - 20 * 60_000));

    expect((await introspect(stale)).body).toBe(inactive);
  });

  it("for a correctly-signed token naming a subject with no account", async () => {
    expect((await introspect(await mintFor("0".repeat(32)))).body).toBe(inactive);
  });

  it("for an account with a valid token but no live refresh family", async () => {
    // Signature fine, `exp` fine, account fine — the session is simply over.
    const token = accessCookie(await login());
    mod.refreshTokens.revokeAllForSubject(db, subject, "admin");

    expect((await introspect(token)).body).toBe(inactive);
  });

  it("for a family swept by reuse detection", async () => {
    const token = accessCookie(await login());
    const [live] = mod.refreshTokens.listLiveTokensForSubject(db, subject);
    mod.refreshTokens.revokeFamily(db, live!.family_id, "reuse_detected");

    expect((await introspect(token)).body).toBe(inactive);
  });

  /**
   * Revocation, demonstrated over the two routes rather than asserted against
   * the table: log in, log out, then present the access token the client was
   * still holding. It verifies perfectly — the signature is good for the full
   * 15 minutes — and it is not live. This is the property the whole endpoint
   * exists for.
   */
  it("after a real logout, even though the access token still verifies", async () => {
    const session = await login();
    const token = accessCookie(session);
    expect((await introspect(token)).json()).toMatchObject({ active: true });

    const loggedOut = await app.inject({
      method: "POST",
      url: "/logout",
      headers: { cookie: `${mod.cookie.REFRESH_COOKIE_NAME}=${refreshCookie(session)}` },
    });
    expect(loggedOut.statusCode).toBe(204);

    // The signature is still valid; Ward's answer is not.
    await expect(mod.service.verifyWardAccessToken(token)).resolves.toMatchObject({ sub: subject });
    expect((await introspect(token)).body).toBe(inactive);
  });

  /**
   * The brief's headline acceptance criterion, end to end rather than at the
   * unit level: a real login, a live introspection, a disable, and the very
   * next introspection is dead. Every app in the estate reaches this endpoint
   * for the same answer, so this is what "every app rejects it" means.
   */
  it("as soon as the account is disabled — every app rejects it on its next call", async () => {
    grant("atrium", "admin");
    const token = accessCookie(await login());

    expect((await introspect(token)).json()).toMatchObject({
      active: true,
      grants: { atrium: ["admin"] },
    });

    mod.users.setDisabled(db, subject, true);

    // Nothing was revoked and nothing expired: the family is still live and the
    // token still verifies. The account being disabled is the whole reason.
    expect(mod.refreshTokens.listLiveTokensForSubject(db, subject)).toHaveLength(1);
    expect((await introspect(token)).body).toBe(inactive);
    expect((await introspect(token)).body).toBe(inactive);

    // And re-enabling restores it, grants intact.
    mod.users.setDisabled(db, subject, false);
    expect((await introspect(token)).json()).toMatchObject({
      active: true,
      grants: { atrium: ["admin"] },
    });
  });

  it("and never says which of those it was", async () => {
    // Collected from genuinely different causes and compared as raw bodies:
    // no `reason`, no `error`, no status-code difference to read as an oracle.
    const token = accessCookie(await login());
    mod.users.setDisabled(db, subject, true);

    const bodies = await Promise.all([
      app.inject({
        method: "POST",
        url: "/introspect",
        headers: { [mod.appKey.APP_KEY_HEADER]: appKey },
        payload: {},
      }),
      introspect("not-a-token"),
      introspect(await mintFor("0".repeat(32))),
      introspect(await mintFor(subject, new Date(Date.now() - 20 * 60_000))),
      introspect(token),
      introspect(mod.superuser.openConsoleSession().token),
    ]);

    for (const response of bodies) {
      expect(response.statusCode).toBe(200);
      expect(response.body).toBe(inactive);
      expect(response.headers["cache-control"]).toBe("no-store");
    }
  });
});

/**
 * The test brief 06 owed forward and could not write, because `/introspect` did
 * not exist in wave 3. It is the single most important test in that brief: it
 * proves the break-glass credential cannot open atrium.
 *
 * **There is nothing implemented for it here.** `active: false` falls out of two
 * facts and no code — a console token is `wcs_` + base64url random, so it has
 * one dot-separated segment where a compact JWS has three and cannot verify;
 * and the superuser has no account row and therefore no grants, so even a
 * hypothetical valid token would resolve to nothing. There is no `isSuperuser`
 * branch in `routes/introspect.ts` or `grants/resolve.ts`, and
 * `decisions-admin.md` rejects that branch by name — it would be extra code
 * whose only effect is to let a credential with no revocation path read the
 * library and the notes.
 */
describe("the superuser console token cannot open an app", () => {
  it("returns active: false when presented to POST /introspect", async () => {
    const opened = mod.superuser.openConsoleSession();

    // A genuinely live console session: it resolves on the console surface.
    expect(mod.superuser.resolveConsoleSession(opened.token)).toBeDefined();

    expect((await introspect(opened.token)).body).toBe(JSON.stringify({ active: false }));
    expect((await introspect(opened.token)).body).toBe(JSON.stringify({ active: false }));
  });

  it("because it is not the same kind of thing, and because it has no grants", async () => {
    const opened = mod.superuser.openConsoleSession();

    // One segment, not three. This is the structural half.
    expect(opened.token.split(".")).toHaveLength(1);
    expect(opened.token.startsWith("wcs_")).toBe(true);
    await expect(mod.service.verifyWardAccessToken(opened.token)).rejects.toThrow(/not valid/);

    // And the model half: no row anywhere to resolve, so nothing to authorise.
    expect(mod.users.findUserBySubject(db, "superuser")).toBeUndefined();
    expect(mod.grants.listGrantsForSubject(db, "superuser")).toEqual([]);
    // No account row exists for "superuser", so resolveSession returns INACTIVE
    // before it ever looks at the session id — any non-empty string will do.
    expect(mod.resolve.resolveSession(db, "superuser", "unused-session")).toBe(
      mod.resolve.INACTIVE,
    );

    mod.superuser.closeConsoleSession(opened.token);
  });
});

describe("the endpoint's shape", () => {
  it("has no GET variant, so a token can never travel in a logged query string", async () => {
    const response = await app.inject({ method: "GET", url: "/introspect" });

    expect(response.statusCode).toBe(404);
  });

  it("refuses an oversized token instead of hashing it", async () => {
    // The zod cap, not a lockout: this route deliberately has no failure
    // budget, so the only bound on an anonymous caller is the size of what it
    // may hand over.
    const response = await introspect("x".repeat(5000));

    expect(response.statusCode).toBe(200);
    expect(response.body).toBe(JSON.stringify({ active: false }));
  });

  it("has no rate limit and never answers 429, however many times it is called", async () => {
    // Six apps call this on every request they serve. A lockout here would not
    // degrade an attacker, it would sign the estate out — every app reads a
    // 429 as "not live".
    const responses = await Promise.all(
      Array.from({ length: 30 }, () => introspect("not-a-token")),
    );

    for (const response of responses) {
      expect(response.statusCode).toBe(200);
    }

    // And it did not spend brief 03's login budget either: `LockoutSurface` is
    // a closed union, and this route does not borrow `"login"`.
    const session = await login();
    expect((await introspect(accessCookie(session))).json()).toMatchObject({
      active: true,
    });
  });
});

/**
 * The app key guard.
 *
 * The endpoint is published on the public origin — `vps-deploy/stacks/ward.ts`
 * serves the whole API under `handle_path /ward-api/*` — so "who is allowed to
 * ask" is a real question here and not a formality. These tests pin the two
 * properties that make the answer useful: the refusal is uniform, and it is
 * **not** `{"active":false}`.
 */
describe("the app key", () => {
  const refusal = JSON.stringify({ error: "invalid_app_key" });

  it("refuses a request with no key at all", async () => {
    const session = await login();
    const response = await introspectWithKey(accessCookie(session), undefined);

    expect(response.statusCode).toBe(401);
    expect(response.body).toBe(refusal);
  });

  /**
   * The single most important assertion in this file.
   *
   * If a rejected key answered `{"active":false}`, a mistyped `WARD_APP_KEY`
   * would present as every one of that app's users being signed out —
   * simultaneously, silently, with a clean server log. It has to be a status
   * code, so `@ward/client` can raise `WardConfigurationError` and an operator
   * can tell "my deployment is broken" from "Ward is down".
   */
  it("refuses with 401, never with active: false", async () => {
    const session = await login();
    const live = accessCookie(session);

    // The identical token, keyed, is unambiguously live — so the 401 above is
    // about the key and nothing else.
    expect((await introspect(live)).json()).toMatchObject({ active: true, subject });

    const unkeyed = await introspectWithKey(live, undefined);
    expect(unkeyed.statusCode).toBe(401);
    expect(unkeyed.json()).not.toMatchObject({ active: false });
  });

  it("gives one answer to absent, malformed, unknown and revoked", async () => {
    const session = await login();
    const live = accessCookie(session);

    const revoked = mod.testSupport.seedAppKey(db, "newspapper");
    const revokedRow = mod.appKeys
      .listAppKeysForApp(db, "newspapper")
      .find((row) => row.key_hash === mod.appKeys.hashAppKey(revoked))!;
    expect(mod.appKeys.revokeAppKey(db, revokedRow.id)).toBe(true);

    const answers = await Promise.all([
      introspectWithKey(live, undefined),
      introspectWithKey(live, "not-even-the-right-shape"),
      introspectWithKey(live, `wak_${"z".repeat(43)}`),
      introspectWithKey(live, revoked),
    ]);

    // Byte for byte, all four. A caller must not be able to learn whether a key
    // they hold was revoked or never existed.
    for (const answer of answers) {
      expect(answer.statusCode).toBe(401);
      expect(answer.body).toBe(refusal);
    }
  });

  it("accepts a key issued for any app — the key says who is asking, not what they may see", async () => {
    grant("atrium", "admin");
    const session = await login();

    // Deliberate: a key authenticates the caller. It does not scope the answer,
    // so newspapper's key gets atrium's grants back. That is the decision as
    // taken — "key authenticates only" — and if it is ever revisited, this test
    // is the one that has to change first.
    const response = await introspectWithKey(
      accessCookie(session),
      mod.testSupport.seedAppKey(db, "newspapper"),
    );

    expect(response.statusCode).toBe(200);
    expect(response.json()).toMatchObject({ active: true, grants: { atrium: ["admin"] } });
  });

  it("stops working the moment the key is revoked, with no cache in between", async () => {
    const scratch = mod.testSupport.seedAppKey(db, "sports-app");
    const session = await login();
    const live = accessCookie(session);

    expect((await introspectWithKey(live, scratch)).statusCode).toBe(200);

    const row = mod.appKeys
      .listAppKeysForApp(db, "sports-app")
      .find((candidate) => candidate.key_hash === mod.appKeys.hashAppKey(scratch))!;
    expect(mod.appKeys.revokeAppKey(db, row.id)).toBe(true);

    // The very next call, not 30 seconds later: `resolveAppKey` reads the row
    // every time. Session revocation is the thing bounded by the client's
    // introspection cache; this credential is not part of that cache.
    expect((await introspectWithKey(live, scratch)).statusCode).toBe(401);
  });

  it("records use coarsely — a stamp, not a row per request", async () => {
    mod.appKey.resetAppKeyTouchThrottle();
    const scratch = mod.testSupport.seedAppKey(db, "prm");
    const row = () =>
      mod.appKeys
        .listAppKeysForApp(db, "prm")
        .find((candidate) => candidate.key_hash === mod.appKeys.hashAppKey(scratch))!;

    expect(row().last_used_at).toBeNull();

    await Promise.all(Array.from({ length: 10 }, () => introspectWithKey("not-a-token", scratch)));

    const stamped = row().last_used_at;
    expect(stamped).not.toBeNull();

    // Ten calls, one stamp — the throttle is what keeps `/introspect` from
    // becoming a write on the estate's hot path.
    await introspectWithKey("not-a-token", scratch);
    expect(row().last_used_at).toBe(stamped);
  });
});
