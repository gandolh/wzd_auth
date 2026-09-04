import type Database from "better-sqlite3";
import type { FastifyInstance } from "fastify";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterAll, beforeAll, describe, expect, it } from "vitest";

/**
 * The `Secure` exception, asserted against real response headers.
 *
 * `WARD_PUBLIC_ORIGIN` here is `http://127.0.0.1:8792`, and this is a **separate
 * test file on purpose**: `config.ts` resolves its constants once per module
 * registry, and vitest gives each test file its own — so this is the only way
 * to exercise a second origin without reaching into config's internals.
 * `auth.test.ts` covers the ordinary `https` case, where both cookies carry
 * `Secure`.
 *
 * Why the exception exists at all: a browser does not store a `Secure` cookie
 * over `http://127.0.0.1`, so without it nobody could run the login flow
 * locally without terminating TLS first — and the workaround people reach for
 * instead is dropping `Secure` everywhere. The condition is `http:` **and**
 * loopback, so plain HTTP on a real hostname — the genuinely dangerous case —
 * still gets `Secure` and simply does not work, which is the correct direction
 * to fail in. `auth/cookie.test.ts` asserts that boundary directly.
 */

const PASSWORD = "correct-horse-battery";

let dir: string;
let app: FastifyInstance;
let db: Database.Database;

function setCookieAttributes(header: string): { name: string; attributes: Set<string> } {
  const parts = header.split(";").map((part) => part.trim());
  const [pair, ...rest] = parts as [string, ...string[]];

  return {
    name: pair.slice(0, pair.indexOf("=")),
    attributes: new Set(rest.map((part) => part.split("=")[0]!.toLowerCase())),
  };
}

beforeAll(async () => {
  dir = await mkdtemp(join(tmpdir(), "ward-auth-loopback-"));

  process.env["PORT"] = "8792";
  process.env["HOST"] = "127.0.0.1";
  process.env["WARD_DB_PATH"] = join(dir, "unused.db");
  process.env["WARD_ADMIN_USERNAME"] = "test-superuser";
  process.env["WARD_ADMIN_PASSWORD"] = "test-superuser-password";
  process.env["WARD_SIGNING_KEY_PATH"] = join(dir, "signing-key.pem");
  process.env["WARD_PUBLIC_ORIGIN"] = "http://127.0.0.1:8792";
  // Mail is part of the required environment contract (brief 07). `file`
  // transport needs no SMTP credentials, which is the point of having a mode.
  process.env["WARD_MAIL_TRANSPORT"] = "file";
  process.env["WARD_MAIL_FILE_DIR"] = "api/mail-outbox";
  process.env["WARD_MAIL_FROM"] = "ward@gandolh.ro";

  const config = await import("../config.js");
  const { generateSigningKeyFile } = await import("../tokens/keygen.js");
  await generateSigningKeyFile(config.WARD_SIGNING_KEY_PATH);

  const { freshDb } = await import("../db/test-support.js");
  const { createUser } = await import("../db/users.js");
  const { hashPassword } = await import("../auth/password.js");

  db = freshDb();
  createUser(db, { username: "alice", passwordHash: await hashPassword(PASSWORD) });

  const { authRoutes } = await import("./auth.js");
  const Fastify = (await import("fastify")).default;
  app = Fastify({ logger: false });
  await app.register(authRoutes, { db });
  await app.ready();
});

afterAll(async () => {
  await app?.close();
  db?.close();
  await rm(dir, { recursive: true, force: true });
});

describe("plain HTTP on loopback", () => {
  it("omits Secure on both cookies and keeps every other attribute", async () => {
    const response = await app.inject({
      method: "POST",
      url: "/login",
      headers: { "x-forwarded-for": "203.0.113.9" },
      payload: { username: "alice", password: PASSWORD },
    });

    expect(response.statusCode).toBe(200);

    const raw = response.headers["set-cookie"];
    const headers = Array.isArray(raw) ? raw : [String(raw)];
    expect(headers).toHaveLength(2);

    const byName = new Map(
      headers.map((header) => {
        const parsed = setCookieAttributes(header);
        return [parsed.name, parsed.attributes] as const;
      }),
    );

    for (const name of ["ward_session", "ward_refresh"]) {
      const attributes = byName.get(name)!;
      expect(attributes.has("secure")).toBe(false);
      // Everything else is unconditional — `Secure` is the only attribute the
      // origin decides.
      expect(attributes.has("httponly")).toBe(true);
      expect(attributes.has("samesite")).toBe(true);
      expect(attributes.has("path")).toBe(true);
      expect(attributes.has("max-age")).toBe(true);
    }
  });

  it("clears cookies without Secure too, so the browser replaces rather than shadows", async () => {
    // A token has to be PRESENTED: `/logout` no longer emits cookie
    // instructions for a request that carried no credential, because doing so
    // let a cross-site POST sign the victim out of the whole estate.
    const loggedIn = await app.inject({
      method: "POST",
      url: "/login",
      headers: { "x-forwarded-for": "203.0.113.10" },
      payload: { username: "alice", password: PASSWORD },
    });
    const raw0 = loggedIn.headers["set-cookie"];
    const cookie = (Array.isArray(raw0) ? raw0 : [String(raw0)])
      .map((header) => header.split(";")[0]!)
      .join("; ");

    const response = await app.inject({ method: "POST", url: "/logout", headers: { cookie } });

    expect(response.statusCode).toBe(204);

    const raw = response.headers["set-cookie"];
    const headers = Array.isArray(raw) ? raw : [String(raw)];
    expect(headers).toHaveLength(2);

    for (const header of headers) {
      // A cleared cookie whose `Secure` differs from the original's is a
      // DIFFERENT cookie to the browser, and the original survives.
      expect(setCookieAttributes(header).attributes.has("secure")).toBe(false);
    }
  });
});

describe("a loopback caller with no X-Forwarded-For", () => {
  /**
   * The finding: `lockoutKeyFor("127.0.0.1", undefined)` returns `"127.0.0.1"`
   * and every caller lands in that one bucket, so three wrong logins for one
   * user plus three for another earned the sixth request a `429` — and so did a
   * correct login from an innocent third party. That is the estate-wide outage
   * the recorded decision claims to avoid, and it happened with no log line,
   * metric or assertion to explain it. It still fails closed into a shared
   * bucket, which is the right direction; what it must not do is fail closed
   * *quietly*.
   *
   * `app.inject` defaults its peer to `127.0.0.1`, so a request with no
   * forwarding header here is exactly the shape brief 08's server-side
   * `@ward/client` would produce.
   */
  it("says so in the log, once", async () => {
    const lines: string[] = [];
    const stream = {
      write(chunk: string) {
        lines.push(chunk);
      },
    };

    const { authRoutes } = await import("./auth.js");
    const { resetLockoutForTests } = await import("../auth/lockout.js");
    const Fastify = (await import("fastify")).default;

    resetLockoutForTests();
    const loud = Fastify({ logger: { level: "warn", stream } });
    await loud.register(authRoutes, { db });
    await loud.ready();

    try {
      for (let i = 0; i < 5; i += 1) {
        await loud.inject({
          method: "POST",
          url: "/login",
          payload: { username: "alice", password: "wrong" },
        });
      }

      const warnings = lines.filter((line) => line.includes("no client address available"));
      // Once, not once per request: the warning must not become the flood it is
      // warning about.
      expect(warnings).toHaveLength(1);
      expect(warnings[0]).toContain("X-Forwarded-For");
      expect(warnings[0]).toContain("429");
    } finally {
      await loud.close();
      resetLockoutForTests();
    }
  });
});
