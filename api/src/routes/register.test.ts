import { mkdtemp, readFile, readdir, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { Writable } from "node:stream";
import type Database from "better-sqlite3";
import Fastify, { type FastifyInstance, type LightMyRequestResponse } from "fastify";
import { afterAll, beforeAll, beforeEach, describe, expect, it } from "vitest";

/**
 * `POST /register` and `GET /verify`, against a Fastify instance this file
 * builds itself.
 *
 * **Not via `buildApp()`**, deliberately: `app.ts` is not this brief's to edit
 * and brief 08 is writing `client/` in parallel, so registering the plugin
 * directly is what keeps this suite from depending on either.
 *
 * The environment is set before anything imports `config.ts`, and
 * `WARD_MAIL_TRANSPORT=file` with an outbox in the OS temp directory is the
 * acceptance criterion itself: **no SMTP credentials anywhere in this file**,
 * and the whole flow — register, read the message off disk, follow its link,
 * replay it — runs end to end.
 */

const ORIGIN = "https://ward.test";
const PASSWORD = "a-long-enough-password";
const ADMIN_USERNAME = "test-superuser";

let dir: string;
let outbox: string;
let db: Database.Database;
let app: FastifyInstance;

let mod: {
  register: typeof import("./register.js");
  auth: typeof import("./auth.js");
  lockout: typeof import("../auth/lockout.js");
  verification: typeof import("../auth/verification.js");
  password: typeof import("../auth/password.js");
  apps: typeof import("../db/apps.js");
  auditLog: typeof import("../db/audit-log.js");
  grants: typeof import("../db/grants.js");
  users: typeof import("../db/users.js");
  testSupport: typeof import("../db/test-support.js");
};

beforeAll(async () => {
  dir = await mkdtemp(join(tmpdir(), "ward-register-route-"));
  outbox = join(dir, "outbox");

  process.env["PORT"] = "8797";
  process.env["HOST"] = "127.0.0.1";
  process.env["WARD_DB_PATH"] = join(dir, "unused.db");
  process.env["WARD_ADMIN_USERNAME"] = ADMIN_USERNAME;
  process.env["WARD_ADMIN_PASSWORD"] = "test-superuser-password";
  process.env["WARD_SIGNING_KEY_PATH"] = join(dir, "signing-key.pem");
  process.env["WARD_PUBLIC_ORIGIN"] = ORIGIN;
  // The point of the whole exercise: `file` mode, an absolute path in the OS
  // temp directory, and nothing else set. No WARD_SMTP_* variable appears in
  // this file at all.
  process.env["WARD_MAIL_TRANSPORT"] = "file";
  process.env["WARD_MAIL_FILE_DIR"] = outbox;
  process.env["WARD_MAIL_FROM"] = "Ward <ward@gandolh.ro>";

  const config = await import("../config.js");
  const { generateSigningKeyFile } = await import("../tokens/keygen.js");
  // `/login` mints an access token, and the surface-independence test below
  // drives the real route rather than the lockout module.
  await generateSigningKeyFile(config.WARD_SIGNING_KEY_PATH);

  mod = {
    register: await import("./register.js"),
    auth: await import("./auth.js"),
    lockout: await import("../auth/lockout.js"),
    verification: await import("../auth/verification.js"),
    password: await import("../auth/password.js"),
    apps: await import("../db/apps.js"),
    auditLog: await import("../db/audit-log.js"),
    grants: await import("../db/grants.js"),
    users: await import("../db/users.js"),
    testSupport: await import("../db/test-support.js"),
  };

  // `openDatabase(":memory:")` via `freshDb()`, never `getDb()` —
  // `WARD_DB_PATH` above names a file that is deliberately never created.
  db = mod.testSupport.freshDb();
  mod.testSupport.seedApps(db);

  app = Fastify({ logger: false });
  await app.register(mod.register.registerRoutes, { db });
  await app.register(mod.auth.authRoutes, { db });
  await app.ready();
});

afterAll(async () => {
  await app?.close();
  db?.close();
  await rm(dir, { recursive: true, force: true });
});

beforeEach(async () => {
  // The lockout counter is module-level, so without this a test that earns a
  // 429 locks out every test after it in this worker.
  mod.lockout.resetLockoutForTests();
  await rm(outbox, { recursive: true, force: true });
  // Every test registers its own usernames, and `users` persists across them
  // in this shared database. Anything that needs a clean table says so.
  db.exec("DELETE FROM users; DELETE FROM audit_log;");
});

/** `POST /register`, always with an address so the lockout key is per test. */
async function register(
  body: Record<string, unknown>,
  ip = "203.0.113.7",
): Promise<LightMyRequestResponse> {
  return app.inject({
    method: "POST",
    url: "/register",
    headers: { "x-forwarded-for": ip },
    payload: body,
  });
}

const goodBody = (overrides: Record<string, unknown> = {}): Record<string, unknown> => ({
  app: "prm",
  username: "Alice",
  email: "alice@example.com",
  password: PASSWORD,
  ...overrides,
});

/**
 * The single message in the outbox, decoded.
 *
 * The body arrives **quoted-printable**, with `=` escaped as `=3D` and a soft
 * line break before column 76 — which is not an inconvenience but the evidence
 * that this file is a real MIME message from the same builder the SMTP
 * transport uses, rather than something hand-written that only looks like one.
 * A mail client decodes it; so does this.
 */
async function outboxMessage(): Promise<{ raw: string; body: string }> {
  const files = await readdir(outbox);
  expect(files).toHaveLength(1);
  const raw = await readFile(join(outbox, files[0]!), "utf8");
  const body = raw
    .replace(/=\r?\n/g, "")
    .replace(/=3D/g, "=")
    .replace(/=3F/g, "?");
  return { raw, body };
}

/** The verification URL out of the message, exactly as a mail client would see it. */
async function linkFromOutbox(): Promise<string> {
  const { body } = await outboxMessage();
  const match = /https:\/\/\S+/.exec(body);
  expect(match, body).not.toBeNull();
  return match![0];
}

/**
 * Follow a mailed link, doing to it exactly what Caddy does.
 *
 * The link is the **browser-visible** URL and therefore carries the
 * `/ward-api` prefix; `handle_path /ward-api/*` strips it before Ward sees the
 * request, so the Fastify route is `/verify`. Asserting the prefix was there
 * and then removing it is the only way an `app.inject()` test can catch the
 * mistake of mailing a link without it — which would 404 in production while
 * every test passed.
 */
async function follow(
  link: string,
  headers: Record<string, string> = {},
): Promise<LightMyRequestResponse> {
  const url = new URL(link);
  expect(url.origin).toBe(ORIGIN);
  expect(url.pathname.startsWith("/ward-api/")).toBe(true);
  const stripped = url.pathname.slice("/ward-api".length);
  return app.inject({ method: "GET", url: `${stripped}${url.search}`, headers });
}

describe("the public_registration flag", () => {
  /**
   * The acceptance criterion, and the whole point of the feature: a new app is
   * closed until somebody deliberately opens it.
   */
  it("refuses an app whose flag is off", async () => {
    const response = await register(goodBody({ app: "atrium" }));

    expect(response.statusCode).toBe(403);
    expect(response.json()).toEqual({ error: "registration_closed" });
    expect(mod.users.countUsers(db)).toBe(0);
    expect(mod.auditLog.listAudit(db)).toHaveLength(0);
  });

  /**
   * The same answer for an app that does not exist. There is no reason for the
   * anonymous signup endpoint to be the thing that confirms which apps the
   * estate runs.
   */
  it("answers identically for an app that does not exist", async () => {
    const closed = await register(goodBody({ app: "atrium" }));
    const missing = await register(goodBody({ app: "no-such-app" }), "203.0.113.8");

    expect(missing.statusCode).toBe(closed.statusCode);
    expect(missing.json()).toEqual(closed.json());
  });

  it("accepts an app after the console opens it", async () => {
    mod.apps.setPublicRegistration(db, "newspapper", true, "reader");
    const response = await register(goodBody({ app: "newspapper", username: "Bob" }));

    expect(response.statusCode).toBe(201);
    expect(response.json().role).toBe("reader");
    mod.apps.setPublicRegistration(db, "newspapper", false);
  });
});

describe("a successful registration", () => {
  it("returns the account, the app and the one role it confers", async () => {
    const response = await register(goodBody());

    expect(response.statusCode).toBe(201);
    expect(response.headers["cache-control"]).toBe("no-store");

    const body = response.json();
    expect(body).toMatchObject({
      username: "Alice",
      email: "alice@example.com",
      emailVerified: false,
      app: "prm",
      role: "user",
      verificationSent: true,
    });
    expect(body.subject).toMatch(/^[0-9a-f]{32}$/);
    expect(typeof body.verificationExpiresAt).toBe("string");

    // No session: registering does not sign you in, and no token of any kind
    // travels in the body.
    expect(response.headers["set-cookie"]).toBeUndefined();
    expect(Object.keys(body).sort()).toEqual([
      "app",
      "email",
      "emailVerified",
      "role",
      "subject",
      "username",
      "verificationExpiresAt",
      "verificationSent",
    ]);
  });

  it("creates the account unverified, with the address stored", async () => {
    await register(goodBody());
    const user = mod.users.findUserByUsername(db, "alice")!;

    expect(user.email).toBe("alice@example.com");
    expect(user.email_verified).toBe(0);
    expect(user.disabled_at).toBeNull();
    // A real hash, not the password.
    expect(user.password_hash).not.toContain(PASSWORD);
    expect(await mod.password.verifyPassword(PASSWORD, user.password_hash)).toBe(true);
  });

  /**
   * The acceptance criterion that matters most: **exactly one grant**, and
   * nothing anywhere else in the estate. The security boundary is the grant,
   * not the signup form.
   */
  it("holds exactly one grant — that app's baseline role — and nothing in any other app", async () => {
    const subject = (await register(goodBody())).json().subject as string;

    const grants = mod.grants.listGrantsForSubject(db, subject);
    expect(grants).toHaveLength(1);
    expect(grants[0]).toMatchObject({ app_slug: "prm", role: "user" });

    // What an app's introspection reads. Only `prm` is there at all.
    const bySlug = mod.grants.grantsBySlug(db, subject);
    expect(bySlug).toEqual({ prm: ["user"] });
    expect(mod.grants.listRolesInApp(db, subject, "atrium")).toEqual([]);
    expect(mod.grants.listRolesInApp(db, subject, "newspapper")).toEqual([]);
  });

  /**
   * `granted_by` is NOT NULL and answers "who granted this" even if the audit
   * log is pruned. It is not the superuser — claiming that would put a lie in
   * the trail — and not the registrant, who holds no authority to grant
   * themselves anything.
   */
  it("records the grant as issued by self-registration, not by the superuser", async () => {
    const subject = (await register(goodBody())).json().subject as string;
    const grant = mod.grants.listGrantsForSubject(db, subject)[0]!;

    // Lives in `db/grants.ts` beside `SUPERUSER_ACTOR`: both are sentinels this
    // column may carry, and keeping them together is what stops a third one
    // being invented somewhere else.
    expect(mod.grants.SELF_REGISTRATION_ACTOR).toBe("self-registration");
    expect(grant.granted_by).toBe(mod.grants.SELF_REGISTRATION_ACTOR);
    expect(grant.granted_by).not.toBe(mod.grants.SUPERUSER_ACTOR);
    // Cannot be mistaken for a subject, which is always 32 hex characters.
    expect(grant.granted_by).not.toMatch(/^[0-9a-f]{32}$/);
  });

  it("writes both audit rows: where the account came from, and who granted it", async () => {
    const subject = (await register(goodBody())).json().subject as string;
    const audit = mod.auditLog.listAudit(db);

    const registered = audit.find((row) => row.action === "user.register")!;
    expect(registered).toMatchObject({
      actor_kind: "account",
      actor_subject: subject,
      actor_label: "Alice",
      target_kind: "user",
      target_id: subject,
    });
    expect(JSON.parse(registered.detail!)).toMatchObject({ app: "prm", role: "user" });

    const granted = audit.find((row) => row.action === "grant.create")!;
    expect(granted).toMatchObject({
      // Ward conferred this, acting on the flag — the person did not.
      actor_kind: "system",
      actor_subject: null,
      actor_label: "registration",
      target_kind: "grant",
      target_id: mod.auditLog.grantTargetId(subject, "prm", "user"),
    });
    // Parsed with the percent-decoding helper, never by splitting on `:`.
    expect(mod.auditLog.parseGrantTargetId(granted.target_id!)).toEqual({
      subject,
      appSlug: "prm",
      role: "user",
    });
  });
});

describe("refusals that are not the flag", () => {
  it("answers password_too_short below MIN_PASSWORD_LENGTH, not a generic error", async () => {
    const response = await register(goodBody({ password: "short" }));

    expect(mod.password.MIN_PASSWORD_LENGTH).toBe(8);
    expect(response.statusCode).toBe(400);
    expect(response.json()).toEqual({ error: "password_too_short" });
    expect(mod.users.countUsers(db)).toBe(0);
  });

  it("answers password_too_long above the ceiling", async () => {
    const response = await register(goodBody({ password: "x".repeat(2000) }));
    expect(response.statusCode).toBe(400);
    expect(response.json()).toEqual({ error: "password_too_long" });
  });

  it("answers invalid_request for a malformed body, and does not spend budget", async () => {
    for (const body of [
      {},
      { app: "prm", username: "Alice", password: PASSWORD },
      { app: "prm", username: "Alice", email: "not-an-address", password: PASSWORD },
      { app: "prm", username: "  ", email: "a@b.co", password: PASSWORD },
      { app: "prm", username: "bad\u200bname", email: "a@b.co", password: PASSWORD },
    ]) {
      const response = await register(body, "198.51.100.4");
      expect(response.statusCode, JSON.stringify(body)).toBe(400);
      expect(response.json()).toEqual({ error: "invalid_request" });
    }

    // Six malformed bodies would have earned a 429 if they counted. A broken
    // integration must not throttle its own users out of signing up.
    const good = await register(goodBody(), "198.51.100.4");
    expect(good.statusCode).toBe(201);
  });
});

describe("username collisions — the ordinary case, not an edge case", () => {
  it("answers 409 username_taken, in any casing", async () => {
    expect((await register(goodBody())).statusCode).toBe(201);

    const again = await register(goodBody({ username: "ALICE", email: "other@example.com" }));
    expect(again.statusCode).toBe(409);
    expect(again.json()).toEqual({ error: "username_taken" });
    expect(mod.users.countUsers(db)).toBe(1);
  });

  /**
   * The same answer whatever is true of the account that holds the name. None
   * of it is the caller's business, and varying the response is how a
   * collision error becomes a profile of somebody else's account.
   */
  it("answers identically whether the holder is verified, disabled or owner-issued", async () => {
    const owner = mod.testSupport.seedUser(db, "Owner");
    mod.users.setDisabled(db, owner.subject, true);
    const verified = mod.testSupport.seedUser(db, "Verified", "v@example.com");
    mod.users.markEmailVerified(db, verified.subject, "v@example.com");

    const answers = await Promise.all(
      ["Owner", "Verified"].map((name, index) =>
        register(goodBody({ username: name }), `198.51.100.${20 + index}`),
      ),
    );

    for (const response of answers) {
      expect(response.statusCode).toBe(409);
      expect(response.json()).toEqual({ error: "username_taken" });
    }
  });

  /**
   * The break-glass username is refused, with the **same** body — so this
   * cannot be used to discover `WARD_ADMIN_USERNAME`: a prober cannot tell
   * "that is the superuser's name" from "somebody already has it".
   */
  it("refuses the break-glass username without admitting that is why", async () => {
    const response = await register(goodBody({ username: ADMIN_USERNAME }));
    expect(response.statusCode).toBe(409);
    expect(response.json()).toEqual({ error: "username_taken" });
    expect(mod.users.findUserByUsername(db, ADMIN_USERNAME)).toBeUndefined();
  });

  /**
   * The enumeration Ward does **not** offer. `users.email` has no uniqueness
   * constraint — username is the canonical identifier — so registration never
   * confirms or denies that an address is known to the estate. prm answers
   * `409 EMAIL_TAKEN` today because email is its primary key; Ward's is not.
   */
  it("never says an email is already registered", async () => {
    expect((await register(goodBody())).statusCode).toBe(201);

    const second = await register(
      goodBody({ username: "Bob", email: "alice@example.com" }),
      "198.51.100.5",
    );
    expect(second.statusCode).toBe(201);
    expect(mod.users.findUsersByEmail(db, "alice@example.com")).toHaveLength(2);
  });
});

describe("the file transport, end to end, with no SMTP credentials", () => {
  it("writes a real message whose link verifies the address exactly once", async () => {
    const subject = (await register(goodBody())).json().subject as string;

    // A genuine message on disk, From: included.
    const { raw } = await outboxMessage();
    expect(raw).toContain("From: Ward <ward@gandolh.ro>");
    expect(raw).toContain("To: alice@example.com");
    expect(raw).toContain("Subject: Confirm your email address for Public Resource Map");

    // ...carrying the clickable link, prefix and all.
    const link = await linkFromOutbox();
    expect(link.startsWith(`${ORIGIN}/ward-api/verify?token=`)).toBe(true);
    expect(new URL(link).searchParams.get("token")).toMatch(/^[0-9a-f]{64}$/);

    // Following it verifies the address.
    const first = await follow(link);
    expect(first.statusCode).toBe(200);
    expect(first.json()).toEqual({ verified: true });
    expect(first.headers["cache-control"]).toBe("no-store");
    expect(first.headers["referrer-policy"]).toBe("no-referrer");

    const user = mod.users.findUserBySubject(db, subject)!;
    expect(user.email_verified).toBe(1);
    expect(user.email).toBe("alice@example.com");

    // The acceptance criterion: replaying it fails.
    const replay = await follow(link);
    expect(replay.statusCode).toBe(400);
    expect(replay.json()).toEqual({ error: "invalid_token" });
    // And the account stays verified — a replay must not undo anything.
    expect(mod.users.findUserBySubject(db, subject)!.email_verified).toBe(1);
  });

  it("refuses an expired link and says so, distinctly", async () => {
    const subject = (await register(goodBody())).json().subject as string;

    // Re-issued in the past, which also retires the link that was just mailed.
    const stale = mod.verification.issueEmailVerification(db, {
      subject,
      email: "alice@example.com",
      now: new Date(Date.now() - 25 * 60 * 60 * 1000),
    });

    const response = await follow(`${ORIGIN}/ward-api/verify?token=${stale.token}`);
    expect(response.statusCode).toBe(400);
    expect(response.json()).toEqual({ error: "expired_token" });
    expect(mod.users.findUserBySubject(db, subject)!.email_verified).toBe(0);
  });

  it("refuses a token that is not one at all", async () => {
    for (const query of ["", "?token=", "?token=nope", `?token=${"z".repeat(64)}`]) {
      const response = await app.inject({ method: "GET", url: `/verify${query}` });
      expect(response.statusCode, query).toBe(400);
      expect(response.json()).toEqual({ error: "invalid_request" });
    }
  });

  /**
   * Fastify exposes a HEAD route for every GET by default, running the same
   * handler — and this handler spends a single-use token. A link previewer
   * issuing HEAD would burn the verification before the person clicked.
   */
  it("has no HEAD route, so a link previewer cannot burn the token", async () => {
    const subject = (await register(goodBody())).json().subject as string;
    const link = await linkFromOutbox();
    const url = new URL(link);

    const head = await app.inject({
      method: "HEAD",
      url: `${url.pathname.slice("/ward-api".length)}${url.search}`,
    });
    expect(head.statusCode).toBe(404);
    expect(mod.users.findUserBySubject(db, subject)!.email_verified).toBe(0);

    // Still usable afterwards.
    expect((await follow(link)).statusCode).toBe(200);
  });

  it("answers a browser with a page and an API client with JSON", async () => {
    await register(goodBody());
    const link = await linkFromOutbox();

    const page = await follow(link, {
      accept: "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    });
    expect(page.statusCode).toBe(200);
    expect(page.headers["content-type"]).toContain("text/html");
    expect(page.body).toContain("<h1>Email confirmed</h1>");
    // The page interpolates nothing, so no address or token can reach it.
    expect(page.body).not.toContain("alice@example.com");
    expect(page.body).not.toContain(new URL(link).searchParams.get("token")!);
  });
});

describe("the verification token never reaches the log", () => {
  /**
   * `GET /verify?token=` is the one deliberate credential-in-a-URL in Ward, and
   * Fastify's default request line logs `url` at info level. Asserted against a
   * **real pino stream** rather than against the code that configures it,
   * because the mechanism is subtle: the line is written before any hook runs,
   * so only the route's own log serializer is early enough.
   */
  it("redacts the query string from the incoming-request line", async () => {
    const subject = (await register(goodBody())).json().subject as string;
    const link = await linkFromOutbox();
    const token = new URL(link).searchParams.get("token")!;

    const lines: string[] = [];
    const stream = new Writable({
      write(chunk: Buffer, _encoding, callback): void {
        lines.push(chunk.toString("utf8"));
        callback();
      },
    });

    const logged = Fastify({ logger: { level: "info", stream } });
    await logged.register(mod.register.registerRoutes, { db });
    await logged.ready();

    const response = await logged.inject({ method: "GET", url: `/verify?token=${token}` });
    expect(response.statusCode).toBe(200);
    await logged.close();

    const output = lines.join("");
    // The line exists — the route is not simply silent, which would trade one
    // problem for a blind spot.
    expect(output).toContain("incoming request");
    expect(output).toContain('"url":"/verify?<redacted>"');
    // And the token is nowhere in any line, at any level.
    expect(output).not.toContain(token);
    expect(mod.users.findUserBySubject(db, subject)!.email_verified).toBe(1);
  });
});

describe("rate limiting", () => {
  /**
   * The acceptance criterion. Note what is being counted: **attempts**, not
   * failures. Every one of these succeeds, and the sixth is still refused —
   * because the abuse this endpoint has to survive is a flood of successful
   * registrations, so a success cannot buy the next attempt.
   */
  it("throttles a registration flood from one address", async () => {
    const flood = "198.51.100.77";

    for (let i = 0; i < mod.lockout.LOCKOUT_MAX_FAILURES; i += 1) {
      const response = await register(
        goodBody({ username: `flood-${i}`, email: `flood-${i}@example.com` }),
        flood,
      );
      expect(response.statusCode, `attempt ${i}`).toBe(201);
    }

    const refused = await register(
      goodBody({ username: "flood-last", email: "last@example.com" }),
      flood,
    );
    expect(refused.statusCode).toBe(429);
    expect(refused.json()).toMatchObject({ error: "too_many_attempts" });
    expect(Number(refused.headers["retry-after"])).toBeGreaterThan(0);
    expect(mod.users.findUserByUsername(db, "flood-last")).toBeUndefined();

    // Another address is unaffected — the counter is per address, not global.
    const elsewhere = await register(
      goodBody({ username: "elsewhere", email: "e@example.com" }),
      "198.51.100.78",
    );
    expect(elsewhere.statusCode).toBe(201);
  });

  /**
   * The reason `"register"` exists as its own `LockoutSurface` member. A
   * registration flood must not stop the people who already have accounts from
   * signing in — and on a one-operator estate behind a home NAT, "another
   * address" is not available.
   */
  it("does not spend the /login budget", async () => {
    const shared = "198.51.100.99";
    mod.users.createUser(db, {
      username: "Existing",
      passwordHash: await mod.password.hashPassword(PASSWORD),
    });

    for (let i = 0; i <= mod.lockout.LOCKOUT_MAX_FAILURES; i += 1) {
      await register(goodBody({ username: `f${i}`, email: `f${i}@example.com` }), shared);
    }
    // Registration from that address is now refused...
    expect((await register(goodBody({ username: "z" }), shared)).statusCode).toBe(429);

    // ...and signing in from the very same address still works.
    const login = await app.inject({
      method: "POST",
      url: "/login",
      headers: { "x-forwarded-for": shared },
      payload: { username: "existing", password: PASSWORD },
    });
    expect(login.statusCode).toBe(200);
    expect(login.json().username).toBe("Existing");
  });
});
