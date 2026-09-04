import { afterAll, afterEach, beforeAll, describe, expect, it, vi } from "vitest";
import type Database from "better-sqlite3";
import Fastify, { type FastifyInstance } from "fastify";
import { existsSync } from "node:fs";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import { listAudit } from "../db/audit-log.js";
import { freshDb } from "../db/test-support.js";
import { generateSigningKeyFile } from "../tokens/keygen.js";

/**
 * `POST /console/login`, `POST /console/logout`, `GET /console/session`.
 *
 * ## Why this whole file is gated on a file existing
 *
 * `routes/console.ts` imports brief 03's `api/src/auth/lockout.ts` — the IP
 * lockout, which the brief requires this endpoint to apply. Brief 03 is writing
 * that module **in parallel with brief 06** and it is not on disk yet. The
 * contract was pinned by the controller and is written against exactly:
 *
 * ```ts
 * export interface LockoutDecision { allowed: boolean; retryAfterSeconds?: number }
 * export function checkLockout(key: string): LockoutDecision;
 * export function recordFailure(key: string): void;
 * export function clearFailures(key: string): void;
 * export function resetLockoutForTests(): void;
 * ```
 *
 * Rather than stub it — a stub would be worse than a skip, because it can
 * survive into the merged tree and quietly replace the real lockout — this suite
 * skips itself while the file is absent and activates the moment brief 03 lands
 * it. Nothing here needs changing at that point.
 *
 * The properties that do not depend on the lockout are asserted today, without a
 * gate, in `../auth/superuser.test.ts` and `../auth/console-guard.test.ts` —
 * including "no row in `users` or `grants` for the superuser", the audit shape,
 * and both rejection directions.
 */

const HERE = dirname(fileURLToPath(import.meta.url)); // api/src/routes
const LOCKOUT_MODULE = resolve(HERE, "../auth/lockout.ts");
const HAVE_LOCKOUT = existsSync(LOCKOUT_MODULE);

const ORIGIN = "https://gandolh.ro";
const ADMIN_USERNAME = "break-glass";
const ADMIN_PASSWORD = "a-long-random-break-glass-password";

describe.skipIf(!HAVE_LOCKOUT)("the console session routes", () => {
  let dir: string;
  let app: FastifyInstance;
  let db: Database.Database;
  let superuser: typeof import("../auth/superuser.js");
  let resetLockout: () => void;

  beforeAll(async () => {
    dir = await mkdtemp(join(tmpdir(), "ward-console-routes-"));

    process.env["PORT"] = "8799";
    process.env["HOST"] = "127.0.0.1";
    process.env["WARD_DB_PATH"] = join(dir, "ward.db");
    process.env["WARD_ADMIN_USERNAME"] = ADMIN_USERNAME;
    process.env["WARD_ADMIN_PASSWORD"] = ADMIN_PASSWORD;
    process.env["WARD_SIGNING_KEY_PATH"] = join(dir, "signing-key.pem");
    process.env["WARD_PUBLIC_ORIGIN"] = ORIGIN;

    const config = await import("../config.js");
    await generateSigningKeyFile(config.WARD_SIGNING_KEY_PATH);

    superuser = await import("../auth/superuser.js");
    ({ resetLockoutForTests: resetLockout } = await import("../auth/lockout.js"));

    // A private, fully migrated in-memory database, handed to the plugin. Never
    // `getDb()` — that resolves `WARD_DB_PATH` and opens the real file.
    db = freshDb();

    const { consoleRoutes } = await import("./console.js");
    app = Fastify({ logger: false });
    // Registered the way the controller will register it, options aside.
    await app.register(consoleRoutes, { db });
    await app.ready();
  });

  afterEach(() => {
    vi.useRealTimers();
    superuser.resetConsoleSessionsForTests();
    resetLockout();
    db.exec("DELETE FROM audit_log");
  });

  afterAll(async () => {
    await app?.close();
    db?.close();
    await rm(dir, { recursive: true, force: true });
  });

  const login = (body: Record<string, unknown>, remoteAddress = "203.0.113.7") =>
    app.inject({ method: "POST", url: "/console/login", payload: body, remoteAddress });

  type Injected = Awaited<ReturnType<typeof login>>;

  function consoleCookie(response: Injected): string | undefined {
    const header = response.headers["set-cookie"];
    if (header === undefined) return undefined;
    return Array.isArray(header) ? header[0] : String(header);
  }

  it("registers with no options at all, the way app.ts will wire it", async () => {
    /**
     * The controller wires this in as `app.register(consoleRoutes)` — the
     * `options.db` parameter exists only for the suites above. This asserts the
     * pinned export shape still registers bare, and that registration itself
     * opens no database (`getDb()` is reached lazily, per request, so a bare
     * registration cannot touch `WARD_DB_PATH` at boot).
     */
    const { consoleRoutes } = await import("./console.js");
    const bare = Fastify({ logger: false });

    await expect(bare.register(consoleRoutes)).resolves.toBeDefined();
    await bare.ready();
    expect(bare.hasRoute({ method: "POST", url: "/console/login" })).toBe(true);
    await bare.close();
  });

  describe("POST /console/login", () => {
    it("accepts the environment credential and sets the console cookie", async () => {
      const response = await login({ username: ADMIN_USERNAME, password: ADMIN_PASSWORD });

      expect(response.statusCode).toBe(200);

      const cookie = consoleCookie(response)!;
      expect(cookie).toContain("ward_console=wcs_");
      expect(cookie).toContain("Path=/ward-api/console");
      expect(cookie).toContain("HttpOnly");
      expect(cookie).toContain("SameSite=Strict");
      expect(cookie).toContain("Secure");
      expect(cookie).not.toContain("Max-Age");

      // The token is in the cookie and nowhere else — a body copy would make
      // HttpOnly decorative.
      expect(response.body).not.toContain("wcs_");
      const payload = response.json() as { session: { id: string; idleTimeoutSeconds: number } };
      expect(payload.session.id).toMatch(/^[0-9a-f]{32}$/);
      expect(payload.session.idleTimeoutSeconds).toBe(
        superuser.CONSOLE_SESSION_IDLE_TIMEOUT_SECONDS,
      );
      expect(payload.session).not.toHaveProperty("subject");
    });

    it("creates no row in users or grants — the superuser has none", async () => {
      const response = await login({ username: ADMIN_USERNAME, password: ADMIN_PASSWORD });
      expect(response.statusCode).toBe(200);

      expect(db.prepare("SELECT count(*) FROM users").pluck().get()).toBe(0);
      expect(db.prepare("SELECT count(*) FROM grants").pluck().get()).toBe(0);
      expect(db.prepare("SELECT count(*) FROM refresh_tokens").pluck().get()).toBe(0);
    });

    it("logs a successful login to the audit trail", async () => {
      await login({ username: ADMIN_USERNAME, password: ADMIN_PASSWORD });

      const rows = listAudit(db);
      expect(rows).toHaveLength(1);
      expect(rows[0]!.action).toBe("console.login");
      expect(rows[0]!.actor_kind).toBe("superuser");
      expect(rows[0]!.actor_subject).toBeNull();
      expect(rows[0]!.actor_label).toBe("superuser");
      expect(rows[0]!.target_kind).toBe("session");
      expect(JSON.parse(rows[0]!.detail!)).toEqual({ ip: "203.0.113.7" });
    });

    it("logs a failed login too, without recording the submitted username", async () => {
      const response = await login({ username: ADMIN_USERNAME, password: "wrong" });

      expect(response.statusCode).toBe(401);
      expect(response.json()).toEqual({ error: "invalid credentials" });
      expect(consoleCookie(response)).toBeUndefined();

      const rows = listAudit(db);
      expect(rows).toHaveLength(1);
      expect(rows[0]!.action).toBe("console.login.failed");
      // `system`, not `superuser`: nothing proved the superuser was involved.
      expect(rows[0]!.actor_kind).toBe("system");
      expect(rows[0]!.actor_subject).toBeNull();
      expect(JSON.parse(rows[0]!.detail!)).toEqual({ ip: "203.0.113.7", reason: "credentials" });
      expect(rows[0]!.detail).not.toContain(ADMIN_USERNAME);
    });

    it("answers a wrong username and a wrong password identically", async () => {
      const wrongUser = await login({ username: "someone-else", password: ADMIN_PASSWORD });
      resetLockout();
      const wrongPassword = await login({ username: ADMIN_USERNAME, password: "wrong" });

      expect(wrongUser.statusCode).toBe(401);
      expect(wrongPassword.statusCode).toBe(401);
      expect(wrongUser.body).toBe(wrongPassword.body);
    });

    it("rejects a malformed body with a 400 that does not count toward the lockout", async () => {
      const response = await login({ username: ADMIN_USERNAME });

      expect(response.statusCode).toBe(400);
      expect(listAudit(db)[0]!.action).toBe("console.login.failed");
      expect(JSON.parse(listAudit(db)[0]!.detail!)).toMatchObject({ reason: "malformed" });

      // Twenty malformed submissions, then the real credential still works: a
      // buggy console UI must not lock the operator out of the break-glass
      // credential.
      for (let i = 0; i < 20; i += 1) await login({ nonsense: true });
      const good = await login({ username: ADMIN_USERNAME, password: ADMIN_PASSWORD });
      expect(good.statusCode).toBe(200);
    });

    it("applies the IP lockout, and only to the offending address", async () => {
      let locked: Injected | undefined;
      let attempts = 0;

      while (attempts < 10) {
        attempts += 1;
        const response = await login({ username: ADMIN_USERNAME, password: "wrong" });
        if (response.statusCode === 429) {
          locked = response;
          break;
        }
        expect(response.statusCode).toBe(401);
      }

      expect(locked, "repeated failures from one address must earn a 429").toBeDefined();
      expect(locked!.headers["retry-after"]).toBeDefined();
      // The lockout itself is audited, so the trail shows the refusal as well as
      // the attempts that caused it.
      expect(listAudit(db).map((row) => JSON.parse(row.detail!).reason)).toContain("locked-out");

      // A different address is unaffected — the key is the IP, and it is the
      // whole reason the lockout is not keyed on the username.
      const elsewhere = await login(
        { username: ADMIN_USERNAME, password: ADMIN_PASSWORD },
        "198.51.100.9",
      );
      expect(elsewhere.statusCode).toBe(200);
    });

    it("clears the failure counter on a success", async () => {
      await login({ username: ADMIN_USERNAME, password: "wrong" });
      await login({ username: ADMIN_USERNAME, password: "wrong" });
      expect((await login({ username: ADMIN_USERNAME, password: ADMIN_PASSWORD })).statusCode).toBe(
        200,
      );

      for (let i = 0; i < 3; i += 1) {
        const response = await login({ username: ADMIN_USERNAME, password: "wrong" });
        expect(response.statusCode).toBe(401);
      }
    });
  });

  describe("the console session is usable and expires", () => {
    async function openSession(): Promise<string> {
      const response = await login({ username: ADMIN_USERNAME, password: ADMIN_PASSWORD });
      expect(response.statusCode).toBe(200);
      return consoleCookie(response)!.split(";")[0]!;
    }

    it("GET /console/session is reachable with the cookie and 401 without it", async () => {
      const cookie = await openSession();

      const authorized = await app.inject({
        method: "GET",
        url: "/console/session",
        headers: { cookie },
      });
      expect(authorized.statusCode).toBe(200);
      expect((authorized.json() as { session: { id: string } }).session.id).toMatch(
        /^[0-9a-f]{32}$/,
      );

      const anonymous = await app.inject({ method: "GET", url: "/console/session" });
      expect(anonymous.statusCode).toBe(401);
      expect(anonymous.json()).toEqual({ error: "unauthorized" });
    });

    it("expires when idle", async () => {
      const cookie = await openSession();

      vi.useFakeTimers();
      vi.advanceTimersByTime(superuser.CONSOLE_SESSION_IDLE_TIMEOUT_SECONDS * 1000 + 1_000);

      const response = await app.inject({
        method: "GET",
        url: "/console/session",
        headers: { cookie },
      });
      expect(response.statusCode).toBe(401);
      expect(response.json()).toEqual({ error: "unauthorized" });
    });

    it("logs out, revoking the session and clearing the cookie", async () => {
      const cookie = await openSession();
      db.exec("DELETE FROM audit_log");

      const response = await app.inject({
        method: "POST",
        url: "/console/logout",
        headers: { cookie },
      });

      expect(response.statusCode).toBe(204);
      const cleared = consoleCookie(response)!;
      expect(cleared).toContain("ward_console=;");
      expect(cleared).toContain("Max-Age=0");
      expect(cleared).toContain("Path=/ward-api/console");

      expect(listAudit(db).map((row) => row.action)).toEqual(["console.logout"]);
      expect(superuser.activeConsoleSessionCount()).toBe(0);

      const after = await app.inject({
        method: "GET",
        url: "/console/session",
        headers: { cookie },
      });
      expect(after.statusCode).toBe(401);
    });

    it("logs out idempotently without auditing an anonymous caller", async () => {
      const response = await app.inject({ method: "POST", url: "/console/logout" });

      expect(response.statusCode).toBe(204);
      expect(consoleCookie(response)).toContain("Max-Age=0");
      expect(listAudit(db)).toHaveLength(0);
    });
  });

  describe("no console route is reachable with an ordinary account's token", () => {
    it("refuses a valid Ward access token on the console", async () => {
      const { mintAccessToken } = await import("../tokens/service.js");
      const { token } = await mintAccessToken("c".repeat(32));

      for (const headers of [
        { cookie: `ward_console=${token}` },
        { cookie: `ward_session=${token}` },
        { authorization: `Bearer ${token}` },
      ]) {
        const response = await app.inject({ method: "GET", url: "/console/session", headers });
        expect(response.statusCode).toBe(401);
        expect(response.json()).toEqual({ error: "unauthorized" });
      }
    });
  });
});
