import type Database from "better-sqlite3";
import Fastify, { type FastifyInstance } from "fastify";
import { afterAll, beforeAll, expect, it } from "vitest";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { listApps } from "../../db/apps.js";
import { listAudit } from "../../db/audit-log.js";
import { grantRole, listGrantsForSubject, SUPERUSER_ACTOR } from "../../db/grants.js";
import { newFamilyId } from "../../db/refresh-tokens.js";
import { findUserByUsername } from "../../db/users.js";
import { freshDb, seedApps, seedUser } from "../../db/test-support.js";
import { generateSigningKeyFile } from "../../tokens/keygen.js";
import { adminAccountsRoutes } from "./accounts.js";
import { adminAppsRoutes } from "./apps.js";
import { adminGrantsRoutes } from "./grants.js";

/**
 * **The single most important test in this brief.**
 *
 * No route on the admin surface is reachable with an ordinary account's access
 * token, however many grants it holds. There is no `ward:admin` grant and
 * nothing replaces it: `decisions-admin.md` records that console access cannot
 * be delegated, and that `ward:admin` as an ordinary grant was rejected
 * precisely because it leaves the estate one bad revoke away from nobody being
 * able to grant anything.
 *
 * The token minted here is **real** — signed with a real key by
 * `mintAccessToken`, for an account holding admin grants in every seeded app.
 * A test that fabricated a string would prove only that a fabricated string is
 * rejected.
 *
 * The rejection is structural rather than a check that could be forgotten. The
 * guard reads exactly one cookie (`ward_console`) and looks the value up in an
 * in-process map of opaque session tokens; a JWT is not in that map, there is no
 * signature to verify and no `sub` to trust. So every presentation below fails
 * for the same reason and answers the same bytes.
 */

let dir: string;
let db: Database.Database;
let app: FastifyInstance;
let accessToken: string;
let subject: string;

beforeAll(async () => {
  dir = await mkdtemp(join(tmpdir(), "ward-admin-gate-"));

  process.env["PORT"] = "8799";
  process.env["HOST"] = "127.0.0.1";
  process.env["WARD_DB_PATH"] = join(dir, "ward.db");
  process.env["WARD_ADMIN_USERNAME"] = "break-glass";
  process.env["WARD_ADMIN_PASSWORD"] = "a-long-random-break-glass-password";
  process.env["WARD_SIGNING_KEY_PATH"] = join(dir, "signing-key.pem");
  process.env["WARD_PUBLIC_ORIGIN"] = "https://gandolh.ro";
  // Mail is part of the required environment contract (brief 07). `file`
  // transport needs no SMTP credentials, which is the point of having a mode.
  process.env["WARD_MAIL_TRANSPORT"] = "file";
  process.env["WARD_MAIL_FILE_DIR"] = "api/mail-outbox";
  process.env["WARD_MAIL_FROM"] = "ward@gandolh.ro";

  const config = await import("../../config.js");
  await generateSigningKeyFile(config.WARD_SIGNING_KEY_PATH);

  db = freshDb();
  seedApps(db);

  // An account with as much authority as this estate can express: every role in
  // every app. It still cannot reach the console.
  subject = seedUser(db, "cristian").subject;
  const roles = ["user", "admin", "owner"];
  const seeded = listApps(db);
  for (const row of seeded) {
    for (const role of roles) {
      grantRole(db, { subject, appSlug: row.slug, role, grantedBy: SUPERUSER_ACTOR });
    }
  }
  // Derived, not hardcoded — the point of the fixture is "every role in every
  // app", and that should not need editing each time the estate gains one.
  expect(listGrantsForSubject(db, subject)).toHaveLength(seeded.length * roles.length);

  const { mintAccessToken } = await import("../../tokens/service.js");
  ({ token: accessToken } = await mintAccessToken(subject, newFamilyId()));

  app = Fastify({ logger: false });
  await app.register(adminAppsRoutes, { db });
  await app.register(adminGrantsRoutes, { db });
  await app.register(adminAccountsRoutes, { db });
  await app.ready();

  db.exec("DELETE FROM audit_log");
});

afterAll(async () => {
  await app?.close();
  db?.close();
  await rm(dir, { recursive: true, force: true });
});

/** Every write on this surface, and every read. */
const routes = [
  { method: "GET" as const, url: "/console/apps" },
  { method: "POST" as const, url: "/console/apps", payload: { slug: "orchard", name: "Orchard" } },
  { method: "GET" as const, url: "/console/apps/prm" },
  {
    method: "PATCH" as const,
    url: "/console/apps/prm",
    payload: { publicRegistration: true, baselineRole: "user" },
  },
  { method: "DELETE" as const, url: "/console/apps/prm" },
  { method: "GET" as const, url: "/console/grants?app=prm" },
  {
    method: "POST" as const,
    url: "/console/grants",
    payload: { subject: "any", appSlug: "prm", role: "admin" },
  },
  {
    method: "DELETE" as const,
    url: "/console/grants",
    payload: { subject: "any", appSlug: "prm", role: "admin" },
  },
  { method: "GET" as const, url: "/console/accounts" },
  {
    method: "POST" as const,
    url: "/console/accounts",
    payload: { username: "intruder", password: "a-long-enough-password" },
  },
  { method: "POST" as const, url: "/console/accounts/any/disable" },
  { method: "POST" as const, url: "/console/accounts/any/enable" },
  {
    method: "POST" as const,
    url: "/console/accounts/any/password",
    payload: { password: "a-long-enough-password" },
  },
];

it("refuses an ordinary account's real access token, however it is presented", async () => {
  for (const route of routes) {
    /**
     * Four presentations, all of which a plausible attacker would try: the
     * session cookie the token actually lives in, a `Bearer` header, the token
     * stuffed into the console cookie, and both cookies at once.
     */
    const presentations = [
      { cookie: `ward_session=${accessToken}` },
      { authorization: `Bearer ${accessToken}` },
      { cookie: `ward_console=${accessToken}` },
      { cookie: `ward_session=${accessToken}; ward_console=${accessToken}` },
    ];

    for (const headers of presentations) {
      const response = await app.inject({ ...route, headers });

      expect(response.statusCode, `${route.method} ${route.url}`).toBe(401);
      // Byte-identical to a request with no credential at all.
      expect(response.json()).toEqual({ error: "unauthorized" });
      expect(response.headers["cache-control"]).toBe("no-store");
      // No `WWW-Authenticate`: there is no HTTP auth scheme in play, and a
      // browser would answer one with a native credential prompt.
      expect(response.headers["www-authenticate"]).toBeUndefined();
    }
  }

  // And nothing happened. Not one app created, not one grant issued, not one
  // account made, not one audit row written.
  expect(listApps(db).map((row) => row.slug)).toEqual([
    "atrium",
    "imbatranimos",
    "newspapper",
    "prm",
    "sports-app",
  ]);
  // Unchanged from the fixture: the refused requests wrote nothing.
  expect(listGrantsForSubject(db, subject)).toHaveLength(listApps(db).length * 3);
  expect(findUserByUsername(db, "intruder")).toBeUndefined();
  expect(listAudit(db)).toHaveLength(0);
});

it("answers the same 401 for a request with no credential at all", async () => {
  for (const route of routes) {
    const response = await app.inject(route);
    expect(response.statusCode, `${route.method} ${route.url}`).toBe(401);
    expect(response.json()).toEqual({ error: "unauthorized" });
  }
});
