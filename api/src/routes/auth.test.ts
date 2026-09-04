import type Database from "better-sqlite3";
import type { FastifyInstance } from "fastify";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterAll, beforeAll, beforeEach, describe, expect, it } from "vitest";

/**
 * `POST /login`, `/refresh`, `/logout` end to end.
 *
 * ## Registered directly, not through `buildApp()`
 *
 * `app.ts` belongs to the controller and wires this brief's plugin in after it
 * lands, so these tests build their own Fastify instance and register
 * `authRoutes` into it. That also keeps them isolated from brief 06's routes,
 * which are landing in parallel.
 *
 * ## Every import of `../config.js` and its dependents is dynamic
 *
 * `config.ts` validates the environment at import time and calls
 * `process.exit(1)` on anything missing. A static import here would be hoisted
 * above the `process.env` assignments in `beforeAll` and take the whole test
 * worker with it — the same trap `tokens/jwks-route.test.ts` documents.
 *
 * The origin is `https://ward.test` so the cookies are asserted **with**
 * `Secure`. The plain-HTTP-loopback exception is asserted in its own file,
 * `auth-loopback.test.ts`, because `config.ts` resolves its constants once per
 * module registry and vitest gives each test file its own.
 */

const ORIGIN = "https://ward.test";
const PASSWORD = "correct-horse-battery";

let dir: string;
let app: FastifyInstance;
let db: Database.Database;
let subject: string;

/** Loaded dynamically in `beforeAll`; typed through `typeof import(...)`. */
let mod: {
  auth: typeof import("./auth.js");
  cookie: typeof import("../auth/cookie.js");
  lockout: typeof import("../auth/lockout.js");
  password: typeof import("../auth/password.js");
  refreshTokens: typeof import("../db/refresh-tokens.js");
  auditLog: typeof import("../db/audit-log.js");
  users: typeof import("../db/users.js");
  testSupport: typeof import("../db/test-support.js");
};

/** One `Set-Cookie` value, split into a name, a value and its attributes. */
interface ParsedCookie {
  name: string;
  value: string;
  path?: string;
  httpOnly: boolean;
  sameSite?: string;
  secure: boolean;
  maxAge?: string;
  expires?: string;
}

function parseSetCookie(header: string): ParsedCookie {
  const [pair, ...rest] = header.split(";") as [string, ...string[]];
  const eq = pair.indexOf("=");
  const parsed: ParsedCookie = {
    name: pair.slice(0, eq).trim(),
    value: pair.slice(eq + 1).trim(),
    httpOnly: false,
    secure: false,
  };

  for (const part of rest) {
    const trimmed = part.trim();
    const at = trimmed.indexOf("=");
    const key = (at === -1 ? trimmed : trimmed.slice(0, at)).toLowerCase();
    const value = at === -1 ? "" : trimmed.slice(at + 1);

    if (key === "path") parsed.path = value;
    else if (key === "httponly") parsed.httpOnly = true;
    else if (key === "samesite") parsed.sameSite = value;
    else if (key === "secure") parsed.secure = true;
    else if (key === "max-age") parsed.maxAge = value;
    else if (key === "expires") parsed.expires = value;
  }

  return parsed;
}

/** Every `Set-Cookie` on a response, by name. */
function setCookies(headers: Record<string, unknown>): Map<string, ParsedCookie> {
  const raw = headers["set-cookie"];
  const values = raw === undefined ? [] : Array.isArray(raw) ? raw : [raw];
  const byName = new Map<string, ParsedCookie>();

  for (const value of values) {
    const parsed = parseSetCookie(String(value));
    byName.set(parsed.name, parsed);
  }

  return byName;
}

/** A `Cookie` request header carrying whatever a response just set. */
function cookieHeader(headers: Record<string, unknown>): string {
  return [...setCookies(headers).values()]
    .filter((cookie) => cookie.value.length > 0)
    .map((cookie) => `${cookie.name}=${cookie.value}`)
    .join("; ");
}

async function login(
  body: { username: string; password: string },
  ip = "203.0.113.9",
): Promise<Awaited<ReturnType<FastifyInstance["inject"]>>> {
  return app.inject({
    method: "POST",
    url: "/login",
    headers: { "x-forwarded-for": ip },
    payload: body,
  });
}

beforeAll(async () => {
  dir = await mkdtemp(join(tmpdir(), "ward-auth-route-"));

  process.env["PORT"] = "8791";
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
    auth: await import("./auth.js"),
    cookie: await import("../auth/cookie.js"),
    lockout: await import("../auth/lockout.js"),
    password: await import("../auth/password.js"),
    refreshTokens: await import("../db/refresh-tokens.js"),
    auditLog: await import("../db/audit-log.js"),
    users: await import("../db/users.js"),
    testSupport: await import("../db/test-support.js"),
  };

  // `openDatabase(":memory:")`, never `getDb()` — `WARD_DB_PATH` above points
  // at a file that is deliberately never created.
  db = mod.testSupport.freshDb();
  subject = mod.users.createUser(db, {
    username: "Alice",
    passwordHash: await mod.password.hashPassword(PASSWORD),
  }).subject;

  const Fastify = (await import("fastify")).default;
  app = Fastify({ logger: false });
  await app.register(mod.auth.authRoutes, { db });
  await app.ready();
});

afterAll(async () => {
  await app?.close();
  db?.close();
  await rm(dir, { recursive: true, force: true });
});

beforeEach(() => {
  // The counter is module-level, so without this a test that earns a 429 locks
  // out every test after it in this worker.
  mod.lockout.resetLockoutForTests();
});

describe("POST /login", () => {
  /**
   * The acceptance criterion, asserted against the response headers rather than
   * against the code that produced them.
   */
  it("sets both cookies with exactly the documented attributes", async () => {
    const response = await login({ username: "alice", password: PASSWORD });
    expect(response.statusCode).toBe(200);

    const cookies = setCookies(response.headers);
    expect([...cookies.keys()].sort()).toEqual(["ward_refresh", "ward_session"]);

    const access = cookies.get("ward_session")!;
    expect(access.path).toBe("/");
    expect(access.httpOnly).toBe(true);
    expect(access.sameSite).toBe("Lax");
    expect(access.secure).toBe(true);
    expect(access.maxAge).toBe(String(15 * 60));
    // A compact JWS: three base64url segments.
    expect(access.value.split(".")).toHaveLength(3);

    const refresh = cookies.get("ward_refresh")!;
    // Scoped to one endpoint so a 30-day credential is not sent on every image
    // request in six apps. This is the BROWSER path — Caddy strips `/ward-api`
    // before Fastify sees it.
    expect(refresh.path).toBe("/ward-api/refresh");
    expect(refresh.httpOnly).toBe(true);
    expect(refresh.sameSite).toBe("Lax");
    expect(refresh.secure).toBe(true);
    expect(refresh.maxAge).toBe(String(30 * 24 * 60 * 60));
    expect(refresh.value).toMatch(/^[0-9a-f]{64}$/);
  });

  it("returns the identity and no token in the body", async () => {
    const response = await login({ username: "alice", password: PASSWORD });
    const body = response.json<Record<string, unknown>>();

    expect(body).toEqual({
      subject,
      username: "Alice",
      emailVerified: false,
      accessTokenExpiresAt: expect.any(Number),
      refreshTokenExpiresAt: expect.any(String),
    });

    // A body carrying the access token would put it within reach of any script
    // on the page, which is the entire point of HttpOnly.
    const cookies = setCookies(response.headers);
    expect(response.body).not.toContain(cookies.get("ward_session")!.value);
    expect(response.body).not.toContain(cookies.get("ward_refresh")!.value);
  });

  it("mints a token that verifies against Ward's own key set", async () => {
    const response = await login({ username: "alice", password: PASSWORD });
    const token = setCookies(response.headers).get("ward_session")!.value;

    const { verifyWardAccessToken } = await import("../tokens/service.js");
    const claims = await verifyWardAccessToken(token);

    expect(claims.sub).toBe(subject);
    expect(claims.iss).toBe(ORIGIN);
    expect(claims.exp - claims.iat).toBe(15 * 60);
  });

  it("stores the refresh token only as a hash", async () => {
    const response = await login({ username: "alice", password: PASSWORD });
    const presented = setCookies(response.headers).get("ward_refresh")!.value;

    const dump = JSON.stringify(db.prepare("SELECT * FROM refresh_tokens").all());
    expect(dump).not.toContain(presented);
    expect(
      mod.refreshTokens.findRefreshToken(db, mod.refreshTokens.hashRefreshToken(presented)),
    ).toBeDefined();
  });

  it("accepts any casing of the username", async () => {
    for (const username of ["alice", "ALICE", "AlIcE"]) {
      const response = await login({ username, password: PASSWORD });
      expect(response.statusCode).toBe(200);
    }
  });

  it("answers 401 identically for an unknown username and a wrong password", async () => {
    const unknown = await login({ username: "nobody", password: PASSWORD });
    const wrong = await login({ username: "alice", password: "wrong-password" });

    expect(unknown.statusCode).toBe(401);
    expect(wrong.statusCode).toBe(401);
    expect(unknown.json()).toEqual({ error: "invalid_credentials" });
    expect(wrong.json()).toEqual({ error: "invalid_credentials" });
    // Nothing is set on a failure.
    expect(unknown.headers["set-cookie"]).toBeUndefined();
    expect(wrong.headers["set-cookie"]).toBeUndefined();
  });

  it("rejects a malformed body without counting it toward the lockout", async () => {
    for (let i = 0; i < 10; i += 1) {
      const response = await app.inject({
        method: "POST",
        url: "/login",
        headers: { "x-forwarded-for": "203.0.113.50" },
        payload: { username: "alice" },
      });
      expect(response.statusCode).toBe(400);
      expect(response.json()).toEqual({ error: "invalid_request" });
    }

    // A broken integration must not lock its own users out.
    const good = await login({ username: "alice", password: PASSWORD }, "203.0.113.50");
    expect(good.statusCode).toBe(200);
  });

  it("does not echo the submitted password back in a validation error", async () => {
    const response = await app.inject({
      method: "POST",
      url: "/login",
      headers: { "x-forwarded-for": "203.0.113.51" },
      payload: { username: "alice", password: 12345 },
    });

    expect(response.statusCode).toBe(400);
    expect(response.body).not.toContain("12345");
  });

  it("refuses a disabled account only after the password has been proved", async () => {
    const disabled = mod.users.createUser(db, {
      username: "dormant",
      passwordHash: await mod.password.hashPassword(PASSWORD),
    });
    mod.users.setDisabled(db, disabled.subject, true);

    // A wrong password on a disabled account is indistinguishable from a wrong
    // password anywhere — otherwise the endpoint confirms the account exists.
    const wrong = await login({ username: "dormant", password: "nope" }, "203.0.113.60");
    expect(wrong.statusCode).toBe(401);
    expect(wrong.json()).toEqual({ error: "invalid_credentials" });

    // The right password proves the caller is the account holder, so telling
    // them plainly leaks nothing and saves them retyping a correct password.
    const right = await login({ username: "dormant", password: PASSWORD }, "203.0.113.61");
    expect(right.statusCode).toBe(403);
    expect(right.json()).toEqual({ error: "account_disabled" });
    expect(right.headers["set-cookie"]).toBeUndefined();
    expect(mod.refreshTokens.listLiveTokensForSubject(db, disabled.subject)).toEqual([]);
  });

  it("audits a success, and a failure only for an account that exists", async () => {
    // The database is shared across this file's cases, so count the delta
    // rather than the total.
    const before = mod.auditLog.countAudit(db);

    await login({ username: "alice", password: PASSWORD }, "203.0.113.70");
    await login({ username: "alice", password: "wrong" }, "203.0.113.71");
    await login({ username: "no-such-person", password: "wrong" }, "203.0.113.72");

    // Three attempts, but only two rows: nothing is written for the unknown
    // username, or this table becomes a write amplifier driven entirely by
    // anonymous input.
    expect(mod.auditLog.countAudit(db) - before).toBe(2);

    const added = mod.auditLog.listAudit(db, { limit: 2 });
    const actions = added.map((row) => row.action).sort();
    expect(actions).toEqual(["session.login", "session.login_failed"]);

    const failure = added.find((row) => row.action === "session.login_failed")!;
    expect(failure.actor_subject).toBe(subject);
    expect(failure.detail).toContain("203.0.113.71");
  });
});

describe("the IP lockout", () => {
  /**
   * The acceptance criterion, both halves.
   */
  it("gives the sixth failure from one address a 429, and a different address still works", async () => {
    const attacker = "198.51.100.7";

    for (let i = 0; i < 5; i += 1) {
      const response = await login({ username: "alice", password: "wrong" }, attacker);
      expect(response.statusCode).toBe(401);
    }

    const sixth = await login({ username: "alice", password: "wrong" }, attacker);
    expect(sixth.statusCode).toBe(429);
    expect(sixth.json()).toEqual({
      error: "too_many_attempts",
      retryAfterSeconds: expect.any(Number),
    });
    expect(Number(sixth.headers["retry-after"])).toBeGreaterThan(0);
    expect(Number(sixth.headers["retry-after"])).toBeLessThanOrEqual(15 * 60);

    // Even the CORRECT password is refused from that address now.
    const correctButLocked = await login({ username: "alice", password: PASSWORD }, attacker);
    expect(correctButLocked.statusCode).toBe(429);

    // The seventh attempt, from a different address: the lockout is keyed on
    // the address, never on the username. A username-keyed counter would let a
    // stranger lock alice out of her own account indefinitely.
    const elsewhere = await login({ username: "alice", password: PASSWORD }, "198.51.100.99");
    expect(elsewhere.statusCode).toBe(200);
  });

  it("a success clears the counter", async () => {
    const ip = "198.51.100.8";

    for (let i = 0; i < 4; i += 1) {
      expect((await login({ username: "alice", password: "wrong" }, ip)).statusCode).toBe(401);
    }
    expect((await login({ username: "alice", password: PASSWORD }, ip)).statusCode).toBe(200);

    // A full fresh allowance, not one attempt away from a 429.
    for (let i = 0; i < 5; i += 1) {
      expect((await login({ username: "alice", password: "wrong" }, ip)).statusCode).toBe(401);
    }
    expect((await login({ username: "alice", password: "wrong" }, ip)).statusCode).toBe(429);
  });

  it("does not delay the refusal", async () => {
    const ip = "198.51.100.9";
    for (let i = 0; i < 5; i += 1) await login({ username: "alice", password: "wrong" }, ip);

    const start = performance.now();
    const response = await login({ username: "alice", password: "wrong" }, ip);
    const elapsed = performance.now() - start;

    expect(response.statusCode).toBe(429);
    // Holding the connection open IS the denial of service the lockout exists
    // to prevent, and Ward is the runtime dependency of all six apps. A refused
    // attempt must not even reach the KDF, let alone sleep.
    expect(elapsed).toBeLessThan(20);
  });

  it("keys on the last X-Forwarded-For element, which a client cannot spoof", async () => {
    const ip = "198.51.100.10";
    for (let i = 0; i < 5; i += 1) await login({ username: "alice", password: "wrong" }, ip);

    // Caddy appends the peer it observed, so a client prepending its own value
    // only adds an element nobody reads.
    const spoofed = await app.inject({
      method: "POST",
      url: "/login",
      headers: { "x-forwarded-for": `1.2.3.4, ${ip}` },
      payload: { username: "alice", password: "wrong" },
    });

    expect(spoofed.statusCode).toBe(429);
  });
});

describe("timing: an unknown username costs the same as a wrong password", () => {
  /**
   * The dummy hash is asserted **structurally** in `auth/password.test.ts`
   * (`DUMMY_STORED_HASH` is a well-formed value, so the full KDF runs and the
   * comparison fails on content rather than bailing out on a parse error).
   * This is the corroborating end-to-end measurement, and it is deliberately
   * one-sided plus very wide: a loaded machine makes every sample slower, never
   * faster, so a floor cannot flake upward, and a missing dummy hash is two
   * orders of magnitude below the bound rather than a few percent.
   */
  it("both paths pay the KDF, within an order of magnitude of each other", async () => {
    const samples = 5;
    const measure = async (username: string, ipBase: string): Promise<number[]> => {
      const durations: number[] = [];
      for (let i = 0; i < samples; i += 1) {
        mod.lockout.resetLockoutForTests();
        const start = performance.now();
        await login({ username, password: "definitely-not-the-password" }, `${ipBase}.${i}`);
        durations.push(performance.now() - start);
      }
      return durations.sort((a, b) => a - b);
    };

    // Warm everything: the first scrypt call in a process pays for loading it.
    await login({ username: "alice", password: "wrong" }, "203.0.113.200");
    mod.lockout.resetLockoutForTests();

    const wrongPassword = await measure("alice", "192.0.2.1");
    const unknownUser = await measure("definitely-no-such-account", "192.0.2.2");

    const median = (values: number[]): number => values[Math.floor(values.length / 2)]!;
    const wrong = median(wrongPassword);
    const unknown = median(unknownUser);

    // The assertion that catches a missing dummy hash: the unknown-username
    // path must have done real KDF work. Without `spendDummyHash` it is a
    // sub-millisecond database miss against a ~40 ms verify.
    expect(unknown).toBeGreaterThan(wrong / 4);

    // And the symmetric direction, equally wide.
    expect(wrong).toBeGreaterThan(unknown / 4);
  });
});

describe("POST /refresh", () => {
  it("rotates: a new access token, a new refresh token, both cookies reset", async () => {
    const loggedIn = await login({ username: "alice", password: PASSWORD }, "203.0.113.100");
    const first = setCookies(loggedIn.headers);

    const refreshed = await app.inject({
      method: "POST",
      url: "/refresh",
      headers: { cookie: cookieHeader(loggedIn.headers) },
    });

    expect(refreshed.statusCode).toBe(200);
    const second = setCookies(refreshed.headers);

    expect(second.get("ward_session")!.value).not.toBe(first.get("ward_session")!.value);
    expect(second.get("ward_refresh")!.value).not.toBe(first.get("ward_refresh")!.value);

    // Same attributes as login's, or the browser stores a second cookie.
    expect(second.get("ward_session")!.path).toBe("/");
    expect(second.get("ward_refresh")!.path).toBe("/ward-api/refresh");
    expect(second.get("ward_refresh")!.httpOnly).toBe(true);
    expect(second.get("ward_refresh")!.secure).toBe(true);

    // R2 inherits the family's absolute expiry, so its Max-Age is at most the
    // remaining life rather than a fresh 30 days.
    expect(Number(second.get("ward_refresh")!.maxAge)).toBeLessThanOrEqual(30 * 24 * 60 * 60);

    expect(refreshed.json<Record<string, unknown>>()).toEqual({
      subject,
      accessTokenExpiresAt: expect.any(Number),
      refreshTokenExpiresAt: expect.any(String),
    });
  });

  it("reads the token from the cookie, and from a body field for a non-browser client", async () => {
    const loggedIn = await login({ username: "alice", password: PASSWORD }, "203.0.113.101");
    const token = setCookies(loggedIn.headers).get("ward_refresh")!.value;

    const response = await app.inject({
      method: "POST",
      url: "/refresh",
      payload: { refreshToken: token },
    });

    expect(response.statusCode).toBe(200);
  });

  /**
   * The most important test in the brief, at the HTTP level.
   *
   * `R1 → R2 → R3`, then a replay of `R1`. Two rotations deep is what separates
   * theft from the same-token race the grace window now forgives: the family
   * does have a live tip, but `R1` is not its parent, so whoever is presenting
   * `R1` is arriving with a copy rather than losing a coin flip against their
   * own other tab. The race is asserted directly in the next block.
   */
  it("replaying a token whose family has moved on revokes the family", async () => {
    const loggedIn = await login({ username: "alice", password: PASSWORD }, "203.0.113.102");
    const r1 = setCookies(loggedIn.headers).get("ward_refresh")!.value;
    const familyId = mod.refreshTokens.findRefreshToken(
      db,
      mod.refreshTokens.hashRefreshToken(r1),
    )!.family_id;

    const first = await app.inject({
      method: "POST",
      url: "/refresh",
      payload: { refreshToken: r1 },
    });
    expect(first.statusCode).toBe(200);
    const r2 = setCookies(first.headers).get("ward_refresh")!.value;

    // R2 is spent in its turn, so R1's successor is no longer the live tip.
    const second = await app.inject({
      method: "POST",
      url: "/refresh",
      payload: { refreshToken: r2 },
    });
    expect(second.statusCode).toBe(200);
    const r3 = setCookies(second.headers).get("ward_refresh")!.value;

    // The replay.
    const replay = await app.inject({
      method: "POST",
      url: "/refresh",
      payload: { refreshToken: r1 },
    });

    expect(replay.statusCode).toBe(401);
    // The same body as every other refresh failure: telling a caller "already
    // used" confirms the token was genuine, which is a free confirmation handed
    // to whoever stole it.
    expect(replay.json()).toEqual({ error: "invalid_refresh" });

    // Both cookies are cleared, so the client stops presenting a dead token.
    const cleared = setCookies(replay.headers);
    expect(cleared.get("ward_session")!.value).toBe("");
    expect(cleared.get("ward_session")!.maxAge).toBe("0");
    expect(cleared.get("ward_refresh")!.value).toBe("");
    expect(cleared.get("ward_refresh")!.maxAge).toBe("0");

    // R3 — which the legitimate client was holding — is dead too. Revoking only
    // the replayed token would leave whoever stole it holding a live one.
    const withR3 = await app.inject({
      method: "POST",
      url: "/refresh",
      payload: { refreshToken: r3 },
    });
    expect(withR3.statusCode).toBe(401);

    // Scoped to this family: `alice` has other live sessions from other cases
    // in this file, and killing those would be the bug rather than the fix.
    const family = mod.refreshTokens.listFamily(db, familyId);
    expect(family).toHaveLength(3);
    for (const member of family) {
      expect(member.revoked_at).not.toBeNull();
    }
    expect(
      mod.refreshTokens
        .listLiveTokensForSubject(db, subject)
        .filter((row) => row.family_id === familyId),
    ).toEqual([]);

    // And it is on the record.
    const audit = mod.auditLog.listAudit(db, { action: "session.reuse_detected" });
    expect(audit.some((row) => row.target_id === familyId)).toBe(true);
  });

  it("refuses an expired refresh token", async () => {
    const expired = mod.refreshTokens.generateRefreshToken();
    mod.refreshTokens.insertRefreshToken(db, {
      tokenHash: mod.refreshTokens.hashRefreshToken(expired),
      subject,
      familyId: mod.refreshTokens.newFamilyId(),
      expiresAt: new Date(Date.now() - 1000).toISOString(),
    });

    const response = await app.inject({
      method: "POST",
      url: "/refresh",
      payload: { refreshToken: expired },
    });

    expect(response.statusCode).toBe(401);
    expect(response.json()).toEqual({ error: "invalid_refresh" });
  });

  it("refuses a refresh token for a disabled account", async () => {
    const dormant = mod.users.createUser(db, {
      username: "sleeper",
      passwordHash: await mod.password.hashPassword(PASSWORD),
    });

    const loggedIn = await login({ username: "sleeper", password: PASSWORD }, "203.0.113.103");
    const token = setCookies(loggedIn.headers).get("ward_refresh")!.value;

    mod.users.setDisabled(db, dormant.subject, true);

    const response = await app.inject({
      method: "POST",
      url: "/refresh",
      payload: { refreshToken: token },
    });

    expect(response.statusCode).toBe(401);
    // The family is gone, not merely refused this once.
    expect(mod.refreshTokens.listLiveTokensForSubject(db, dormant.subject)).toEqual([]);
  });

  it("refuses an unknown token and clears the cookies", async () => {
    const response = await app.inject({
      method: "POST",
      url: "/refresh",
      payload: { refreshToken: "f".repeat(64) },
    });

    expect(response.statusCode).toBe(401);
    expect(setCookies(response.headers).get("ward_refresh")!.maxAge).toBe("0");
  });

  it("refuses a request with no refresh token at all", async () => {
    const response = await app.inject({ method: "POST", url: "/refresh" });

    expect(response.statusCode).toBe(401);
    expect(response.json()).toEqual({ error: "invalid_refresh" });
  });

  it("ignores a cleared cookie rather than treating the empty string as a token", async () => {
    const response = await app.inject({
      method: "POST",
      url: "/refresh",
      headers: { cookie: "ward_refresh=; ward_session=" },
    });

    expect(response.statusCode).toBe(401);
  });
});

describe("POST /logout", () => {
  /**
   * The acceptance criterion: no usable row and no usable cookie.
   */
  it("leaves no live refresh row and no usable cookie", async () => {
    const loggedIn = await login({ username: "alice", password: PASSWORD }, "203.0.113.110");
    const token = setCookies(loggedIn.headers).get("ward_refresh")!.value;

    const response = await app.inject({
      method: "POST",
      url: "/logout",
      headers: { cookie: cookieHeader(loggedIn.headers) },
    });

    expect(response.statusCode).toBe(204);

    // No usable cookie: both cleared, with the same Path and Secure they were
    // set with — a mismatch on either makes the browser keep the original.
    const cleared = setCookies(response.headers);
    expect(cleared.get("ward_session")!.value).toBe("");
    expect(cleared.get("ward_session")!.path).toBe("/");
    expect(cleared.get("ward_session")!.secure).toBe(true);
    expect(cleared.get("ward_session")!.maxAge).toBe("0");
    expect(cleared.get("ward_session")!.expires).toContain("1970");
    expect(cleared.get("ward_refresh")!.value).toBe("");
    expect(cleared.get("ward_refresh")!.path).toBe("/ward-api/refresh");
    expect(cleared.get("ward_refresh")!.secure).toBe(true);
    expect(cleared.get("ward_refresh")!.maxAge).toBe("0");

    // No usable row. The row survives as `revoked_reason = 'logout'` on
    // purpose — that column exists so the console can tell a logout from a
    // rotation from a theft signal, and DELETE erases exactly what an operator
    // investigating a stolen session needs.
    const row = mod.refreshTokens.findRefreshToken(db, mod.refreshTokens.hashRefreshToken(token));
    expect(row?.revoked_reason).toBe("logout");
    // Scoped to this family — other cases in this file leave `alice` other live
    // sessions, and logging out one device must not touch them.
    expect(
      mod.refreshTokens
        .listLiveTokensForSubject(db, subject)
        .filter((live) => live.family_id === row!.family_id),
    ).toEqual([]);

    // And the token is inert.
    const after = await app.inject({
      method: "POST",
      url: "/refresh",
      payload: { refreshToken: token },
    });
    expect(after.statusCode).toBe(401);
  });

  it("answers 204 whether or not the presented token was real", async () => {
    // Logout must never be an oracle for testing a stolen token — same status
    // and the same two clearing cookies for a token that was real, one that was
    // never issued, and one that is not even a token.
    const loggedIn = await login({ username: "alice", password: PASSWORD }, "203.0.113.113");
    const real = setCookies(loggedIn.headers).get("ward_refresh")!.value;

    for (const payload of [
      { refreshToken: real },
      { refreshToken: "f".repeat(64) },
      { refreshToken: "not-a-token" },
    ]) {
      const response = await app.inject({ method: "POST", url: "/logout", payload });
      expect(response.statusCode).toBe(204);
      expect(setCookies(response.headers).size).toBe(2);
    }
  });

  it("signs out this device only", async () => {
    const laptop = await login({ username: "alice", password: PASSWORD }, "203.0.113.111");
    const phone = await login({ username: "alice", password: PASSWORD }, "203.0.113.112");

    await app.inject({
      method: "POST",
      url: "/logout",
      headers: { cookie: cookieHeader(laptop.headers) },
    });

    const phoneToken = setCookies(phone.headers).get("ward_refresh")!.value;
    const stillWorks = await app.inject({
      method: "POST",
      url: "/refresh",
      payload: { refreshToken: phoneToken },
    });

    expect(stillWorks.statusCode).toBe(200);
  });
});

describe("the same-token refresh race", () => {
  /**
   * The reviewers' own reproduction, at the HTTP level.
   *
   * Two `/refresh` calls carrying the same `R1`, fired together. Before the fix
   * this answered `200` and `401`, ended the family
   * `[{used:true,reason:'rotated'},{used:false,reason:'reuse_detected'}]`, and
   * left `listLiveTokensForSubject` at **zero** — so the `200` had handed the
   * client cookies for an `R2` that was revoked microseconds later, and the
   * client was dead on its next refresh believing it held a fresh 30-day
   * credential.
   */
  it("leaves the session alive, with the winner's R2 still usable", async () => {
    const loggedIn = await login({ username: "alice", password: PASSWORD }, "203.0.113.130");
    const r1 = setCookies(loggedIn.headers).get("ward_refresh")!.value;
    const familyId = mod.refreshTokens.findRefreshToken(
      db,
      mod.refreshTokens.hashRefreshToken(r1),
    )!.family_id;

    const [a, b] = await Promise.all([
      app.inject({ method: "POST", url: "/refresh", payload: { refreshToken: r1 } }),
      app.inject({ method: "POST", url: "/refresh", payload: { refreshToken: r1 } }),
    ]);

    // Exactly one winner: `claimRefreshToken`'s single statement was never the
    // problem, and it still holds.
    expect([a.statusCode, b.statusCode].sort()).toEqual([200, 401]);

    const winner = a.statusCode === 200 ? a : b;
    const loser = a.statusCode === 200 ? b : a;

    // The loser is told nothing. Byte-identical to every other refresh failure:
    // "that was only a race" confirms the token was genuine just as surely as
    // "already used" does.
    expect(loser.json()).toEqual({ error: "invalid_refresh" });

    const r2 = setCookies(winner.headers).get("ward_refresh")!.value;

    // The family is ALIVE, with exactly one live token: the R2 the winning tab
    // wrote into the jar the two tabs share.
    const live = mod.refreshTokens
      .listLiveTokensForSubject(db, subject)
      .filter((row) => row.family_id === familyId);
    expect(live).toHaveLength(1);
    expect(live[0]!.token_hash).toBe(mod.refreshTokens.hashRefreshToken(r2));

    // And it rotates, which is the property the client is relying on.
    const next = await app.inject({
      method: "POST",
      url: "/refresh",
      payload: { refreshToken: r2 },
    });
    expect(next.statusCode).toBe(200);
  });

  it("records session.refresh_raced with the presenter's address, and no theft alarm", async () => {
    const loggedIn = await login({ username: "alice", password: PASSWORD }, "203.0.113.131");
    const r1 = setCookies(loggedIn.headers).get("ward_refresh")!.value;
    const familyId = mod.refreshTokens.findRefreshToken(
      db,
      mod.refreshTokens.hashRefreshToken(r1),
    )!.family_id;

    const [first, second] = await Promise.all([
      app.inject({
        method: "POST",
        url: "/refresh",
        headers: { "x-forwarded-for": "203.0.113.131" },
        payload: { refreshToken: r1 },
      }),
      app.inject({
        method: "POST",
        url: "/refresh",
        headers: { "x-forwarded-for": "203.0.113.131" },
        payload: { refreshToken: r1 },
      }),
    ]);

    /**
     * The loser must not carry cookie-clearing headers.
     *
     * This is the whole point of leaving the family alive. Both responses are in
     * flight to ONE cookie jar — the estate is a single origin, so every tab and
     * all six apps share it — and if the loser's 401 lands after the winner's
     * 200, a clearing `Set-Cookie` drops `ward_session` and `ward_refresh` and
     * signs the person out anyway. Keeping the family alive server-side while
     * telling the browser to throw its tokens away is a fix that works half the
     * time, decided by response ordering.
     *
     * Status and body stay identical to every other refresh failure; only the
     * absence of `Set-Cookie` differs. See `refreshRejected` for what that
     * concedes and why it is worth it.
     */
    const winner = first!.statusCode === 200 ? first! : second!;
    const loser = first!.statusCode === 200 ? second! : first!;
    expect([winner.statusCode, loser.statusCode]).toEqual([200, 401]);
    expect(loser.headers["set-cookie"]).toBeUndefined();
    expect(loser.json()).toEqual({ error: "invalid_refresh" });

    // And the winner's R2 is genuinely usable — the session survived.
    const r2 = setCookies(winner.headers).get("ward_refresh")!.value;
    const afterRace = await app.inject({
      method: "POST",
      url: "/refresh",
      headers: { "x-forwarded-for": "203.0.113.131" },
      payload: { refreshToken: r2 },
    });
    expect(afterRace.statusCode).toBe(200);

    const raced = mod.auditLog
      .listAudit(db, { action: "session.refresh_raced" })
      .filter((row) => row.target_id === familyId);
    expect(raced).toHaveLength(1);
    expect(JSON.parse(raced[0]!.detail!)).toMatchObject({ ip: "203.0.113.131" });

    // An operator paging on the theft alarm must not be woken by two tabs.
    expect(
      mod.auditLog
        .listAudit(db, { action: "session.reuse_detected" })
        .filter((row) => row.target_id === familyId),
    ).toEqual([]);
  });

  it("records the presenter's address on a genuine reuse too", async () => {
    // The one row an operator is meant to act on used to name subject, family
    // and timestamps but not who presented the replayed token.
    const loggedIn = await login({ username: "alice", password: PASSWORD }, "203.0.113.132");
    const r1 = setCookies(loggedIn.headers).get("ward_refresh")!.value;
    const familyId = mod.refreshTokens.findRefreshToken(
      db,
      mod.refreshTokens.hashRefreshToken(r1),
    )!.family_id;

    const first = await app.inject({
      method: "POST",
      url: "/refresh",
      payload: { refreshToken: r1 },
    });
    const r2 = setCookies(first.headers).get("ward_refresh")!.value;
    await app.inject({ method: "POST", url: "/refresh", payload: { refreshToken: r2 } });

    // A thief, from somewhere else entirely.
    await app.inject({
      method: "POST",
      url: "/refresh",
      headers: { "x-forwarded-for": "185.220.101.99" },
      payload: { refreshToken: r1 },
    });

    const rows = mod.auditLog
      .listAudit(db, { action: "session.reuse_detected" })
      .filter((row) => row.target_id === familyId);
    expect(rows).toHaveLength(1);
    expect(JSON.parse(rows[0]!.detail!)).toMatchObject({ ip: "185.220.101.99" });
  });

  it("writes one reuse row per family however many times the token is replayed", async () => {
    // `/refresh` is exempt from the lockout, so an ungated audit write here is
    // unbounded growth of `audit_log` by an unauthenticated caller — and it
    // drowns the operator's only alert channel.
    const loggedIn = await login({ username: "alice", password: PASSWORD }, "203.0.113.133");
    const r1 = setCookies(loggedIn.headers).get("ward_refresh")!.value;
    const familyId = mod.refreshTokens.findRefreshToken(
      db,
      mod.refreshTokens.hashRefreshToken(r1),
    )!.family_id;

    const first = await app.inject({
      method: "POST",
      url: "/refresh",
      payload: { refreshToken: r1 },
    });
    const r2 = setCookies(first.headers).get("ward_refresh")!.value;
    await app.inject({ method: "POST", url: "/refresh", payload: { refreshToken: r2 } });

    for (let i = 0; i < 25; i += 1) {
      const replay = await app.inject({
        method: "POST",
        url: "/refresh",
        payload: { refreshToken: r1 },
      });
      expect(replay.statusCode).toBe(401);
    }

    expect(
      mod.auditLog
        .listAudit(db, { action: "session.reuse_detected" })
        .filter((row) => row.target_id === familyId),
    ).toHaveLength(1);
  });
});

describe("a success only forgives its own account's failures", () => {
  /**
   * The reviewers' own reproduction. `clearFailures` was keyed on the address
   * alone, so a successful login wiped the failures accumulated against *other*
   * accounts: four wrong guesses at a victim, one correct login as the
   * attacker's own account, counter back to zero, repeat — **40 wrong guesses
   * from one address with no `429` at all**, measured at ~35 a second. `prm` is
   * seeded `publicRegistration: true`, so brief 07 makes obtaining that one
   * valid account self-service.
   */
  it("does not let one valid account buy unlimited guessing at another", async () => {
    const ip = "198.51.100.40";
    await mod.users.createUser(db, {
      username: "attacker",
      passwordHash: await mod.password.hashPassword(PASSWORD),
    });

    let accepted = 0;
    let refused = false;

    // Ten rounds of the attack: four guesses at `alice`, then one correct login
    // as `attacker` to launder the counter.
    for (let round = 0; round < 10 && !refused; round += 1) {
      for (let guess = 0; guess < 4; guess += 1) {
        const attempt = await login({ username: "alice", password: `guess-${round}-${guess}` }, ip);
        if (attempt.statusCode === 429) {
          refused = true;
          break;
        }
        expect(attempt.statusCode).toBe(401);
        accepted += 1;
      }
      if (refused) break;

      const own = await login({ username: "attacker", password: PASSWORD }, ip);
      if (own.statusCode === 429) {
        refused = true;
        break;
      }
      // The attacker's own login still works — the fix must not break the
      // legitimate case it is protecting.
      expect(own.statusCode).toBe(200);
    }

    expect(refused, "the guessing loop must reach a 429").toBe(true);
    // Five, the whole budget, and not one more.
    expect(accepted).toBeLessThanOrEqual(mod.lockout.LOCKOUT_MAX_FAILURES);
  });

  it("still clears the counter for the account that authenticated", async () => {
    const ip = "198.51.100.41";

    for (let i = 0; i < 4; i += 1) {
      expect((await login({ username: "alice", password: "wrong" }, ip)).statusCode).toBe(401);
    }
    expect((await login({ username: "alice", password: PASSWORD }, ip)).statusCode).toBe(200);

    // A full fresh allowance, not one attempt away from a 429.
    for (let i = 0; i < 5; i += 1) {
      expect((await login({ username: "alice", password: "wrong" }, ip)).statusCode).toBe(401);
    }
    expect((await login({ username: "alice", password: "wrong" }, ip)).statusCode).toBe(429);
  });
});

describe("a mint failure leaves nothing behind", () => {
  /**
   * `issueRefreshToken` used to run before `mintAccessToken`, so a signing-key
   * failure answered `500` with a live 30-day refresh row already stored for a
   * client that never received it — a session the console would list and nobody
   * could ever use or revoke. Minting first means the failure leaves no row.
   */
  it("writes no refresh row when the access token cannot be minted", async () => {
    const { rename } = await import("node:fs/promises");
    const tokens = await import("../tokens/service.js");
    const keyPath = process.env["WARD_SIGNING_KEY_PATH"]!;
    const stashed = `${keyPath}.stashed`;

    const victim = mod.users.createUser(db, {
      username: "mint-failure",
      passwordHash: await mod.password.hashPassword(PASSWORD),
    });

    await rename(keyPath, stashed);
    tokens.resetTokenServiceForTests();

    try {
      const response = await login(
        { username: "mint-failure", password: PASSWORD },
        "198.51.100.50",
      );

      // The route throws rather than lying about success.
      expect(response.statusCode).toBe(500);
      // And nothing was stored for a client that received nothing.
      expect(mod.refreshTokens.listLiveTokensForSubject(db, victim.subject)).toEqual([]);
      expect(response.headers["set-cookie"]).toBeUndefined();
    } finally {
      await rename(stashed, keyPath);
      tokens.resetTokenServiceForTests();
    }

    // And the key being back means the ordinary path works again, so the rest
    // of this file is unaffected.
    const after = await login({ username: "mint-failure", password: PASSWORD }, "198.51.100.51");
    expect(after.statusCode).toBe(200);
  });
});

describe("cross-site requests cannot touch the session cookies", () => {
  /**
   * The reviewers' own reproduction. `SameSite=Lax` stops the cookies being
   * *sent* cross-site but not the response *deleting* them, and `text/plain` is
   * not rejected by Fastify's content-type parser the way `form-urlencoded` and
   * `multipart` are. So an auto-submitted
   * `<form method="POST" enctype="text/plain" action=".../ward-api/logout">` on
   * any page got a `204` with two clearing `Set-Cookie` headers, which the
   * browser honoured first-party at `Path=/` across all six apps — invisibly,
   * because a `204` does not navigate.
   */
  const crossSiteForm = {
    "content-type": "text/plain",
    "sec-fetch-site": "cross-site",
    origin: "https://evil.example",
  };

  it("emits no Set-Cookie for a cross-site text/plain POST to /logout", async () => {
    const response = await app.inject({
      method: "POST",
      url: "/logout",
      headers: crossSiteForm,
      payload: "refreshToken=whatever",
    });

    expect(response.headers["set-cookie"]).toBeUndefined();
    expect(response.statusCode).toBe(403);
    expect(response.json()).toEqual({ error: "cross_site" });
  });

  it("emits no Set-Cookie for a cross-site POST to /refresh", async () => {
    const response = await app.inject({
      method: "POST",
      url: "/refresh",
      headers: crossSiteForm,
      payload: "refreshToken=whatever",
    });

    expect(response.headers["set-cookie"]).toBeUndefined();
    expect(response.statusCode).toBe(403);
  });

  it("refuses on Sec-Fetch-Site alone, and on a mismatched Origin alone", async () => {
    // Either header is enough. `same-site` is not `same-origin`: the estate is
    // one origin and nothing legitimate arrives from a sibling.
    for (const headers of [
      { "sec-fetch-site": "cross-site" },
      { "sec-fetch-site": "same-site" },
      { "sec-fetch-site": "none" },
      { origin: "https://evil.example" },
      // A literal `null` origin — what some cross-origin contexts send — does
      // not parse, and an unparseable origin is a mismatch.
      { origin: "null" },
    ]) {
      const response = await app.inject({ method: "POST", url: "/logout", headers });
      expect(response.statusCode, JSON.stringify(headers)).toBe(403);
      expect(response.headers["set-cookie"]).toBeUndefined();
    }
  });

  it("still clears both cookies for a same-origin logout with a real token", async () => {
    const loggedIn = await login({ username: "alice", password: PASSWORD }, "203.0.113.140");

    const response = await app.inject({
      method: "POST",
      url: "/logout",
      headers: {
        cookie: cookieHeader(loggedIn.headers),
        "sec-fetch-site": "same-origin",
        origin: ORIGIN,
      },
    });

    expect(response.statusCode).toBe(204);
    const cleared = setCookies(response.headers);
    expect(cleared.get("ward_session")!.maxAge).toBe("0");
    expect(cleared.get("ward_refresh")!.maxAge).toBe("0");
  });

  it("still serves a header-less non-browser client", async () => {
    // Brief 08's server-side clients send neither header, so an absent header
    // must pass. Rejecting them would break every non-browser caller in order
    // to defend against a browser-only attack.
    const loggedIn = await login({ username: "alice", password: PASSWORD }, "203.0.113.141");
    const token = setCookies(loggedIn.headers).get("ward_refresh")!.value;

    const refreshed = await app.inject({
      method: "POST",
      url: "/refresh",
      payload: { refreshToken: token },
    });
    expect(refreshed.statusCode).toBe(200);

    const rotated = setCookies(refreshed.headers).get("ward_refresh")!.value;
    const loggedOut = await app.inject({
      method: "POST",
      url: "/logout",
      payload: { refreshToken: rotated },
    });
    expect(loggedOut.statusCode).toBe(204);
  });

  it("clears nothing when the request presented no token at all", async () => {
    /**
     * The half of the fix that does not depend on any header, and the one that
     * actually defuses the attack: a request carrying no credential gets no
     * cookie instructions. The status is still `204`, so the oracle property is
     * untouched — nothing on the wire distinguishes this from a logout that
     * killed a real family except the absence of headers for cookies the caller
     * never sent.
     */
    const logout = await app.inject({ method: "POST", url: "/logout" });
    expect(logout.statusCode).toBe(204);
    expect(logout.headers["set-cookie"]).toBeUndefined();

    const refresh = await app.inject({ method: "POST", url: "/refresh" });
    expect(refresh.statusCode).toBe(401);
    expect(refresh.json()).toEqual({ error: "invalid_refresh" });
    expect(refresh.headers["set-cookie"]).toBeUndefined();
  });
});

describe("the exported surface other briefs consume", () => {
  it("registers with no options at all — the shape app.ts will use", async () => {
    // The controller pastes `await app.register(authRoutes)`. This asserts that
    // works, and that it does NOT open the database at registration time:
    // `WARD_DB_PATH` points at a file that is never created, so a
    // registration-time `getDb()` would leave one behind.
    const { existsSync } = await import("node:fs");
    const Fastify = (await import("fastify")).default;

    const bare = Fastify({ logger: false });
    await bare.register(mod.auth.authRoutes);
    await bare.ready();

    for (const url of ["/login", "/refresh", "/logout"]) {
      expect(bare.hasRoute({ method: "POST", url })).toBe(true);
      // No GET variant of any of them: Fastify's default request log carries
      // the query string, so a credential must never be able to travel in a URL.
      expect(bare.hasRoute({ method: "GET", url })).toBe(false);
    }
    expect(existsSync(process.env["WARD_DB_PATH"]!)).toBe(false);

    await bare.close();
  });

  it("re-exports the cookie names, so nothing hard-codes them", () => {
    expect(mod.auth.ACCESS_COOKIE_NAME).toBe(mod.cookie.ACCESS_COOKIE_NAME);
    expect(mod.auth.REFRESH_COOKIE_NAME).toBe(mod.cookie.REFRESH_COOKIE_NAME);
  });

  it("brief 04 can read the access token off a request with readCookie", async () => {
    const loggedIn = await login({ username: "alice", password: PASSWORD }, "203.0.113.120");
    const header = cookieHeader(loggedIn.headers);

    const token = mod.cookie.readCookie(header, mod.cookie.ACCESS_COOKIE_NAME);
    expect(token).toBeDefined();

    const { verifyWardAccessToken } = await import("../tokens/service.js");
    expect((await verifyWardAccessToken(token!)).sub).toBe(subject);
  });
});
