import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import type Database from "better-sqlite3";
import Fastify, { type FastifyInstance } from "fastify";
import { afterAll, beforeAll, expect, it } from "vitest";

/**
 * What happens when the mail cannot be sent.
 *
 * Its own file because `config.ts` validates and freezes `MAIL` at first
 * import, so a suite cannot hold two transports at once — the same reason
 * `auth-loopback.test.ts` stands apart from `auth.test.ts`.
 *
 * The failure is arranged honestly rather than mocked: `WARD_MAIL_FILE_DIR`
 * points at a path **underneath a regular file**, so `mkdir` cannot create it
 * and the write fails with `ENOTDIR` for reasons the code under test knows
 * nothing about. No permission games, so this behaves the same run as root.
 *
 * ## The decision being asserted
 *
 * Registration **succeeds**. The alternative — answer `500` when the mail
 * fails — is the worst outcome available: the account exists and the username
 * is taken, so the person retries, is told the name is unavailable, and
 * concludes somebody beat them to it. What went wrong is reported in a field
 * instead, and audited so it is still discoverable after the log rotates.
 */

const PASSWORD = "a-long-enough-password";

let dir: string;
let db: Database.Database;
let app: FastifyInstance;
let mod: {
  register: typeof import("./register.js");
  auditLog: typeof import("../db/audit-log.js");
  grants: typeof import("../db/grants.js");
  users: typeof import("../db/users.js");
  testSupport: typeof import("../db/test-support.js");
};

beforeAll(async () => {
  dir = await mkdtemp(join(tmpdir(), "ward-register-mailfail-"));

  // A regular file where the outbox's parent directory would have to be.
  const blocker = join(dir, "not-a-directory");
  await writeFile(blocker, "");

  process.env["PORT"] = "8798";
  process.env["HOST"] = "127.0.0.1";
  process.env["WARD_DB_PATH"] = join(dir, "unused.db");
  process.env["WARD_ADMIN_USERNAME"] = "test-superuser";
  process.env["WARD_ADMIN_PASSWORD"] = "test-superuser-password";
  process.env["WARD_SIGNING_KEY_PATH"] = join(dir, "signing-key.pem");
  process.env["WARD_PUBLIC_ORIGIN"] = "https://ward.test";
  process.env["WARD_MAIL_TRANSPORT"] = "file";
  process.env["WARD_MAIL_FILE_DIR"] = join(blocker, "outbox");
  process.env["WARD_MAIL_FROM"] = "ward@gandolh.ro";

  mod = {
    register: await import("./register.js"),
    auditLog: await import("../db/audit-log.js"),
    grants: await import("../db/grants.js"),
    users: await import("../db/users.js"),
    testSupport: await import("../db/test-support.js"),
  };

  db = mod.testSupport.freshDb();
  mod.testSupport.seedApps(db);

  // `logger: false`, so the `error` line this path writes is a no-op here. It
  // is asserted where it matters — the audit row below outlives any log.
  app = Fastify({ logger: false });
  await app.register(mod.register.registerRoutes, { db });
  await app.ready();
});

afterAll(async () => {
  await app?.close();
  db?.close();
  await rm(dir, { recursive: true, force: true });
});

it("still registers the account, reports that the mail did not go, and audits it", async () => {
  const response = await app.inject({
    method: "POST",
    url: "/register",
    headers: { "x-forwarded-for": "203.0.113.44" },
    payload: {
      app: "prm",
      username: "Alice",
      email: "alice@example.com",
      password: PASSWORD,
    },
  });

  expect(response.statusCode).toBe(201);
  expect(response.json()).toMatchObject({
    username: "Alice",
    emailVerified: false,
    app: "prm",
    role: "user",
    // The one field that differs from a healthy registration.
    verificationSent: false,
  });

  // The account and its single grant are real: the person can sign in, they
  // simply have an unconfirmed address — which blocks nothing in Ward.
  const user = mod.users.findUserByUsername(db, "alice")!;
  expect(user.email_verified).toBe(0);
  expect(mod.grants.grantsBySlug(db, user.subject)).toEqual({ prm: ["user"] });

  const failure = mod.auditLog
    .listAudit(db)
    .find((row) => row.action === "user.verification_mail_failed")!;
  expect(failure).toMatchObject({
    actor_kind: "system",
    actor_subject: null,
    actor_label: "registration",
    target_kind: "user",
    target_id: user.subject,
  });
  // Names the transport and nothing else: `audit_log` is append-only and never
  // pruned, and an SMTP failure message arrives with a hostname in it.
  expect(JSON.parse(failure.detail!)).toEqual({ transport: "file" });
});
