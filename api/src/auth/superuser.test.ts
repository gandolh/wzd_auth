import { afterAll, afterEach, beforeAll, describe, expect, it, vi } from "vitest";
import { execFile } from "node:child_process";
import { existsSync } from "node:fs";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { promisify } from "node:util";

import { generateSigningKeyFile } from "../tokens/keygen.js";
import { countAudit, listAudit, recordAudit, SUPERUSER_LABEL } from "../db/audit-log.js";
import { newFamilyId } from "../db/refresh-tokens.js";
import { freshDb } from "../db/test-support.js";

/**
 * The break-glass superuser: the credential comparison, the console session, and
 * the two properties `decisions-admin.md` exists to protect.
 *
 * **The token layer is imported here on purpose, and only here.** Production
 * code in `superuser.ts` must never touch `../tokens/` — the console session is
 * not a JWT and must not go near it. A test is the right place to *prove* that
 * negative, which is what the "not a JWT" block below does: it hands a console
 * token to `verifyWardAccessToken` and asserts the rejection.
 *
 * Every import of `../config.js` is dynamic and inside `beforeAll`, because
 * `config.ts` validates the environment at import time and calls
 * `process.exit(1)` on anything missing — a static import would be hoisted above
 * the `process.env` assignments and take the worker with it.
 */

const ORIGIN = "https://gandolh.ro";
const ADMIN_USERNAME = "break-glass";
const ADMIN_PASSWORD = "a-long-random-break-glass-password";

const HERE = dirname(fileURLToPath(import.meta.url)); // api/src/auth
const REPO_ROOT = resolve(HERE, "../../..");

let dir: string;
let superuser: typeof import("./superuser.js");
let tokens: typeof import("../tokens/service.js");

beforeAll(async () => {
  dir = await mkdtemp(join(tmpdir(), "ward-superuser-"));

  process.env["PORT"] = "8799";
  process.env["HOST"] = "127.0.0.1";
  process.env["WARD_DB_PATH"] = join(dir, "ward.db");
  process.env["WARD_ADMIN_USERNAME"] = ADMIN_USERNAME;
  process.env["WARD_ADMIN_PASSWORD"] = ADMIN_PASSWORD;
  process.env["WARD_SIGNING_KEY_PATH"] = join(dir, "signing-key.pem");
  process.env["WARD_PUBLIC_ORIGIN"] = ORIGIN;
  // Mail is part of the required environment contract (brief 07). `file`
  // transport needs no SMTP credentials, which is the point of having a mode.
  process.env["WARD_MAIL_TRANSPORT"] = "file";
  process.env["WARD_MAIL_FILE_DIR"] = "api/mail-outbox";
  process.env["WARD_MAIL_FROM"] = "ward@gandolh.ro";

  const config = await import("../config.js");
  await generateSigningKeyFile(config.WARD_SIGNING_KEY_PATH);

  superuser = await import("./superuser.js");
  tokens = await import("../tokens/service.js");
});

afterEach(() => {
  vi.useRealTimers();
  superuser.resetConsoleSessionsForTests();
});

afterAll(async () => {
  await rm(dir, { recursive: true, force: true });
});

describe("the superuser credential", () => {
  it("accepts the pair configured in the environment", async () => {
    await expect(superuser.checkSuperuserCredentials(ADMIN_USERNAME, ADMIN_PASSWORD)).resolves.toBe(
      true,
    );
  });

  it("rejects a wrong password, a wrong username, and both", async () => {
    await expect(superuser.checkSuperuserCredentials(ADMIN_USERNAME, "nope")).resolves.toBe(false);
    await expect(superuser.checkSuperuserCredentials("nope", ADMIN_PASSWORD)).resolves.toBe(false);
    await expect(superuser.checkSuperuserCredentials("nope", "nope")).resolves.toBe(false);
  });

  it("rejects the empty string, a prefix, and an over-long value without throwing", async () => {
    /**
     * The length cases are the point of this test. `timingSafeEqual` throws on a
     * length mismatch, so a naive implementation either crashes on a
     * wrong-length password (a 500 that tells the caller the length was wrong)
     * or guards with a length check that is itself the timing oracle. Both sides
     * are hashed to 32 bytes first, so none of these is a special case.
     */
    await expect(superuser.checkSuperuserCredentials("", "")).resolves.toBe(false);
    await expect(
      superuser.checkSuperuserCredentials(ADMIN_USERNAME, ADMIN_PASSWORD.slice(0, 5)),
    ).resolves.toBe(false);
    await expect(
      superuser.checkSuperuserCredentials(ADMIN_USERNAME, `${ADMIN_PASSWORD}x`),
    ).resolves.toBe(false);
    await expect(
      superuser.checkSuperuserCredentials(ADMIN_USERNAME, "x".repeat(100_000)),
    ).resolves.toBe(false);
  });

  it("reads nothing from the database — the superuser has no row to read", async () => {
    /**
     * The whole credential path against a database that has never been written
     * to. `users` and `grants` stay empty, which they could not do if anything
     * here looked the superuser up or mirrored it into a table.
     */
    const db = freshDb();
    try {
      await expect(
        superuser.checkSuperuserCredentials(ADMIN_USERNAME, ADMIN_PASSWORD),
      ).resolves.toBe(true);
      superuser.openConsoleSession();

      expect(db.prepare("SELECT count(*) FROM users").pluck().get()).toBe(0);
      expect(db.prepare("SELECT count(*) FROM grants").pluck().get()).toBe(0);
      expect(countAudit(db)).toBe(0);
    } finally {
      db.close();
    }
  });
});

describe("a console session is not a JWT", () => {
  it("is an opaque prefixed random string with no JWS structure", () => {
    const { token } = superuser.openConsoleSession();

    expect(token.startsWith("wcs_")).toBe(true);
    // A compact JWS is three base64url segments joined by two dots. Neither the
    // prefix nor the base64url alphabet contains a dot, so this can never parse
    // as one — the property is structural, not a rule to remember.
    expect(token).not.toContain(".");
    expect(token.split(".")).toHaveLength(1);
    expect(token.length).toBeGreaterThan(40);
  });

  it("is rejected by the access-token verify path", async () => {
    /**
     * The direction brief 04 owns end to end (`/introspect` must answer
     * `active: false`), asserted here structurally at the token layer instead:
     * a console token is not verifiable by Ward's own key set, so there is no
     * `active: true` for `/introspect` to reach. See the handoff note — the
     * `/introspect` test itself is owed by brief 04.
     */
    const { token } = superuser.openConsoleSession();

    await expect(tokens.verifyWardAccessToken(token)).rejects.toThrow(/access token is not valid/);
  });

  it("carries no subject, username or grants for an app to consume", () => {
    const { session } = superuser.openConsoleSession();

    expect(Object.keys(session).sort()).toEqual([
      "absoluteExpiresAt",
      "createdAt",
      "id",
      "idleExpiresAt",
      "lastSeenAt",
    ]);
    // Named explicitly, because a `sub` appearing here would be exactly the
    // sentinel subject `decisions-admin.md` rejected, arriving by accident.
    expect(session).not.toHaveProperty("subject");
    expect(session).not.toHaveProperty("sub");
    expect(session).not.toHaveProperty("grants");
  });

  it("does not verify a real access token as a console session, either", async () => {
    const minted = await tokens.mintAccessToken("a".repeat(32), newFamilyId());

    expect(superuser.resolveConsoleSession(minted.token)).toBeUndefined();
  });
});

describe("the console session store", () => {
  it("resolves a live token and slides the idle window", () => {
    vi.useFakeTimers();
    const { token, session } = superuser.openConsoleSession();

    vi.advanceTimersByTime(60_000);
    const resolved = superuser.resolveConsoleSession(token);

    expect(resolved?.id).toBe(session.id);
    expect(resolved!.lastSeenAt.getTime()).toBe(session.lastSeenAt.getTime() + 60_000);
    expect(resolved!.idleExpiresAt.getTime()).toBeGreaterThan(session.idleExpiresAt.getTime());
  });

  it("expires an idle session", () => {
    vi.useFakeTimers();
    const { token } = superuser.openConsoleSession();

    // One second short of the timeout: still alive, and the touch resets it.
    vi.advanceTimersByTime(superuser.CONSOLE_SESSION_IDLE_TIMEOUT_SECONDS * 1000 - 1_000);
    expect(superuser.resolveConsoleSession(token)).toBeDefined();

    vi.advanceTimersByTime(superuser.CONSOLE_SESSION_IDLE_TIMEOUT_SECONDS * 1000);
    expect(superuser.resolveConsoleSession(token)).toBeUndefined();
    // Gone from the store, not merely refused.
    expect(superuser.activeConsoleSessionCount()).toBe(0);
  });

  it("expires an actively used session at the absolute cap", () => {
    vi.useFakeTimers();
    const { token } = superuser.openConsoleSession();

    // Busy the whole time: a request every ten minutes, so the idle window
    // never lapses. The absolute deadline still ends it.
    const step = 10 * 60 * 1000;
    const steps = Math.floor((superuser.CONSOLE_SESSION_ABSOLUTE_LIFETIME_SECONDS * 1000) / step);
    // One step short of the deadline: still alive on every touch.
    for (let i = 0; i < steps - 1; i += 1) {
      vi.advanceTimersByTime(step);
      expect(superuser.resolveConsoleSession(token)).toBeDefined();
    }

    vi.advanceTimersByTime(step);
    expect(superuser.resolveConsoleSession(token)).toBeUndefined();
  });

  it("closes a session once, idempotently", () => {
    const { token, session } = superuser.openConsoleSession();

    expect(superuser.closeConsoleSession(token)?.id).toBe(session.id);
    expect(superuser.closeConsoleSession(token)).toBeUndefined();
    expect(superuser.resolveConsoleSession(token)).toBeUndefined();
  });

  it("issues a distinct token every time and never reuses one", () => {
    const tokenSet = new Set<string>();
    const ids = new Set<string>();
    for (let i = 0; i < 8; i += 1) {
      const opened = superuser.openConsoleSession();
      tokenSet.add(opened.token);
      ids.add(opened.session.id);
    }
    expect(tokenSet.size).toBe(8);
    expect(ids.size).toBe(8);
  });

  it("caps the store, evicting the least recently seen", () => {
    vi.useFakeTimers();
    const first = superuser.openConsoleSession();

    // Keep the first one warm while filling the store past its cap.
    for (let i = 0; i < 40; i += 1) {
      vi.advanceTimersByTime(1_000);
      superuser.resolveConsoleSession(first.token);
      superuser.openConsoleSession();
    }

    expect(superuser.activeConsoleSessionCount()).toBeLessThanOrEqual(16);
    // The session in front of the operator survives; a bounded store must not
    // sign out the person using it.
    expect(superuser.resolveConsoleSession(first.token)).toBeDefined();
  });
});

describe("the reported deadlines", () => {
  /**
   * The finding: `idleExpiresAt` was computed from `lastSeenAt` with no clamp,
   * so a busy session near its four-hour cap reported an idle deadline *past*
   * its own absolute one — measured at `absoluteExpiresAt: 18:23:57` with
   * `idleExpiresAt: 18:28:57`. Enforcement was always right (`expired()` checks
   * both bounds), but that value flows into `GET /console/session` and the login
   * response, so the console UI would have counted down to a moment the session
   * does not reach — during what is, by construction, an incident.
   */
  it("never reports an idle deadline past the absolute one", () => {
    vi.useFakeTimers();
    vi.setSystemTime(new Date("2026-09-04T14:00:00.000Z"));

    const opened = superuser.openConsoleSession();
    // Comfortably inside the cap: idle is the binding deadline and is reported
    // as itself.
    expect(opened.session.idleExpiresAt.getTime()).toBe(
      opened.session.lastSeenAt.getTime() + superuser.CONSOLE_SESSION_IDLE_TIMEOUT_SECONDS * 1000,
    );

    /**
     * Kept warm — a page left open polling something — to within five minutes
     * of the absolute cap, where the 15-minute idle window would otherwise
     * overshoot it by ten. Advanced in steps with a touch each time, because a
     * single jump would idle the session out and prove nothing.
     */
    const step = 5 * 60;
    const target =
      superuser.CONSOLE_SESSION_ABSOLUTE_LIFETIME_SECONDS -
      superuser.CONSOLE_SESSION_IDLE_TIMEOUT_SECONDS / 3;
    for (let elapsed = 0; elapsed < target; elapsed += step) {
      vi.advanceTimersByTime(step * 1000);
      expect(superuser.resolveConsoleSession(opened.token)).toBeDefined();
    }

    const resolved = superuser.resolveConsoleSession(opened.token);
    expect(resolved).toBeDefined();
    expect(resolved!.idleExpiresAt.getTime()).toBe(resolved!.absoluteExpiresAt.getTime());
    expect(resolved!.idleExpiresAt.getTime()).toBeLessThanOrEqual(
      resolved!.absoluteExpiresAt.getTime(),
    );
  });
});

describe("the console cookie", () => {
  it("is scoped to the console subtree, HttpOnly, SameSite=Strict and Secure", async () => {
    expect(superuser.CONSOLE_COOKIE_NAME).toBe("ward_console");
    expect(superuser.CONSOLE_COOKIE_PATH).toBe("/ward-api/console");
    // Delegated to `cookie.ts`'s `secureCookiesFor` rather than reimplemented —
    // see `superuser-origin.test.ts` for the boundary it used to fail open on.
    await expect(superuser.consoleCookieSecure()).resolves.toBe(true);

    const cookie = superuser.consoleSessionSetCookie("wcs_abc", { secure: true });

    expect(cookie).toBe(
      "ward_console=wcs_abc; Path=/ward-api/console; HttpOnly; SameSite=Strict; Secure",
    );
    // A session cookie: the server-side idle timeout is the only deadline.
    expect(cookie).not.toContain("Max-Age");
    expect(cookie).not.toContain("Expires");
    // Never `Path=/` — that is the scope every app on this single origin
    // receives, and the console session must not travel to any of them.
    expect(cookie).not.toContain("Path=/;");
  });

  it("drops Secure only when the public origin is plain HTTP", () => {
    expect(superuser.consoleSessionSetCookie("wcs_abc", { secure: false })).not.toContain("Secure");
  });

  it("clears itself with matching attributes", () => {
    const cleared = superuser.consoleSessionClearCookie({ secure: true });

    expect(cleared).toContain("Path=/ward-api/console");
    expect(cleared).toContain("Max-Age=0");
    expect(cleared).toContain("HttpOnly");
    expect(cleared).toContain("SameSite=Strict");
  });

  it("reads its own cookie and ignores every other one on the header", () => {
    expect(
      superuser.readConsoleCookie("ward_session=a.jwt.value; ward_console=wcs_x; other=1"),
    ).toBe("wcs_x");
    expect(superuser.readConsoleCookie("ward_session=a.jwt.value; ward_refresh=r")).toBeUndefined();
    expect(superuser.readConsoleCookie(undefined)).toBeUndefined();
    expect(superuser.readConsoleCookie("")).toBeUndefined();
    expect(superuser.readConsoleCookie("ward_console=%zz")).toBeUndefined();
    expect(superuser.readConsoleCookie("ward_console=wcs%5Fx")).toBe("wcs_x");
  });
});

describe("the audit shape for a console event", () => {
  it("records the superuser with a null subject and creates no row in users or grants", () => {
    /**
     * The audit half of `POST /console/login`, written exactly as the route
     * writes it, against a database the console has never otherwise touched.
     * This is the acceptance criterion "no row exists in `users` for the
     * superuser after a console login" asserted at the level that does not
     * depend on brief 03's lockout module; `console.test.ts` asserts the same
     * thing end to end through the route.
     */
    const db = freshDb();
    try {
      const { session } = superuser.openConsoleSession();

      recordAudit(db, {
        actorKind: "superuser",
        actorLabel: SUPERUSER_LABEL,
        action: "console.login",
        targetKind: "session",
        targetId: session.id,
        detail: { ip: "203.0.113.7" },
      });
      recordAudit(db, {
        actorKind: "system",
        actorLabel: "console-login",
        action: "console.login.failed",
        detail: { ip: "203.0.113.7", reason: "credentials" },
      });

      const rows = listAudit(db);
      expect(rows.map((row) => row.action)).toEqual(["console.login.failed", "console.login"]);

      const success = rows[1]!;
      expect(success.actor_kind).toBe("superuser");
      // No sentinel subject. The superuser has none, and inventing one here
      // would be the rejected design arriving through the audit log.
      expect(success.actor_subject).toBeNull();
      expect(success.actor_label).toBe("superuser");
      expect(success.target_kind).toBe("session");
      expect(success.target_id).toBe(session.id);

      const failure = rows[0]!;
      expect(failure.actor_kind).toBe("system");
      expect(failure.actor_subject).toBeNull();
      // The submitted username is never recorded — see the route.
      expect(failure.detail).not.toContain("password");
      expect(JSON.parse(failure.detail!)).toEqual({ ip: "203.0.113.7", reason: "credentials" });

      // The whole point: an audit trail exists and the account tables do not
      // know the superuser at all.
      expect(db.prepare("SELECT count(*) FROM users").pluck().get()).toBe(0);
      expect(db.prepare("SELECT count(*) FROM grants").pluck().get()).toBe(0);
    } finally {
      db.close();
    }
  });
});

/**
 * Point 5 of the brief: `WARD_ADMIN_USERNAME` and `WARD_ADMIN_PASSWORD` are
 * required and Ward refuses to start without them.
 *
 * **Unconditionally, with no development exemption.** Brief 00 deliberately gave
 * `config.ts` no `NODE_ENV` and made both variables required outright, and brief
 * 02 resolved the same ambiguity the same way for the signing key. So this
 * asserts the unconditional behaviour rather than an environment-dependent one,
 * and nothing here adds an environment check.
 *
 * Run in a child process, because the assertion *is* `process.exit(1)`: a
 * failing import inside the test worker would take the worker down with it.
 * `config.ts` is imported as the child's entry point, which is enough to run its
 * module-level validation.
 */
describe("the service refuses to start without the superuser credential", () => {
  const CLI_CANDIDATES = [
    join(REPO_ROOT, "node_modules/tsx/dist/cli.mjs"),
    join(REPO_ROOT, "api/node_modules/tsx/dist/cli.mjs"),
  ];
  const tsxCli = CLI_CANDIDATES.find((candidate) => existsSync(candidate));
  const configPath = join(REPO_ROOT, "api/src/config.ts");

  /** A complete, valid environment — the control against which each case is one edit. */
  function validEnv(): Record<string, string> {
    return {
      PATH: process.env["PATH"] ?? "",
      PORT: "8799",
      HOST: "127.0.0.1",
      WARD_DB_PATH: join(dir, "child.db"),
      WARD_ADMIN_USERNAME: ADMIN_USERNAME,
      WARD_ADMIN_PASSWORD: ADMIN_PASSWORD,
      WARD_SIGNING_KEY_PATH: join(dir, "signing-key.pem"),
      WARD_PUBLIC_ORIGIN: ORIGIN,
      // Mail is part of the required contract (brief 07). `file` transport
      // needs no SMTP credentials, which is why the mode exists.
      WARD_MAIL_TRANSPORT: "file",
      WARD_MAIL_FILE_DIR: join(dir, "mail-outbox"),
      WARD_MAIL_FROM: "ward@gandolh.ro",
    };
  }

  async function importConfig(env: Record<string, string>): Promise<{
    code: number;
    stderr: string;
  }> {
    try {
      const { stderr } = await promisify(execFile)(process.execPath, [tsxCli!, configPath], {
        env,
        cwd: REPO_ROOT,
      });
      return { code: 0, stderr };
    } catch (error) {
      const failure = error as { code?: number; stderr?: string };
      return { code: failure.code ?? -1, stderr: failure.stderr ?? "" };
    }
  }

  it.skipIf(tsxCli === undefined)("starts when both are present", async () => {
    const result = await importConfig(validEnv());
    expect(result.code).toBe(0);
  });

  it.skipIf(tsxCli === undefined)("exits non-zero on an empty password", async () => {
    /**
     * The empty string rather than an unset variable, so the case is
     * deterministic whether or not the machine running the suite has a
     * repo-root `.env`: an environment variable takes precedence over the file
     * `process.loadEnvFile` reads. It exercises the same `.min(1)` branch, and
     * `config.ts`'s own comment names `WARD_ADMIN_PASSWORD=` as the mistake only
     * the length check catches.
     */
    const result = await importConfig({ ...validEnv(), WARD_ADMIN_PASSWORD: "" });

    expect(result.code).toBe(1);
    expect(result.stderr).toContain("WARD_ADMIN_PASSWORD");
    expect(result.stderr).toContain("invalid or missing environment configuration");
  });

  it.skipIf(tsxCli === undefined)("exits non-zero on an empty username", async () => {
    const result = await importConfig({ ...validEnv(), WARD_ADMIN_USERNAME: "" });

    expect(result.code).toBe(1);
    expect(result.stderr).toContain("WARD_ADMIN_USERNAME");
  });

  it.skipIf(tsxCli === undefined || existsSync(join(REPO_ROOT, ".env")))(
    "exits non-zero when both are absent entirely",
    async () => {
      // Skipped when a repo-root `.env` exists, since `config.ts` would load the
      // values from it and the case would no longer be "absent".
      const env = validEnv();
      delete env["WARD_ADMIN_USERNAME"];
      delete env["WARD_ADMIN_PASSWORD"];

      const result = await importConfig(env);

      expect(result.code).toBe(1);
      expect(result.stderr).toContain("WARD_ADMIN_USERNAME");
      expect(result.stderr).toContain("WARD_ADMIN_PASSWORD");
    },
  );
});
