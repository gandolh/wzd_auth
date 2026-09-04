import type Database from "better-sqlite3";
import Fastify, {
  type FastifyInstance,
  type InjectOptions,
  type LightMyRequestResponse,
} from "fastify";
import { afterEach, beforeEach, describe, expect, it } from "vitest";

import { verifyPassword } from "../../auth/password.js";
import { issueRefreshToken, rotateRefreshToken, usableAccount } from "../../auth/refresh.js";
import {
  CONSOLE_COOKIE_NAME,
  openConsoleSession,
  resetConsoleSessionsForTests,
} from "../../auth/superuser.js";
import { listAudit } from "../../db/audit-log.js";
import { grantRole, listGrantsForSubject, SUPERUSER_ACTOR } from "../../db/grants.js";
import { listFamily, listLiveTokensForSubject } from "../../db/refresh-tokens.js";
import { findUserBySubject, findUserByUsername } from "../../db/users.js";
import { freshDb, seedApps } from "../../db/test-support.js";
import { adminAccountsRoutes } from "./accounts.js";

/**
 * `/console/accounts` — create, read, disable, re-enable, rotate a password.
 *
 * This is the surface the **owner account** is born on, so the suite asserts
 * both halves of that: a created account exists, and it can reach nothing until
 * a grant is issued for it.
 */

const PASSWORD = "a-long-enough-password";

let db: Database.Database;
let app: FastifyInstance;
let cookie: string;
let sessionId: string;

beforeEach(async () => {
  db = freshDb();
  seedApps(db);

  app = Fastify({ logger: false });
  await app.register(adminAccountsRoutes, { db });
  await app.ready();

  const opened = openConsoleSession();
  cookie = `${CONSOLE_COOKIE_NAME}=${encodeURIComponent(opened.token)}`;
  sessionId = opened.session.id;
});

afterEach(async () => {
  await app.close();
  db.close();
  resetConsoleSessionsForTests();
});

const asConsole = (init: InjectOptions): Promise<LightMyRequestResponse> =>
  app.inject({ ...init, headers: { ...init.headers, cookie } });

async function createAccount(username = "cristian", password = PASSWORD): Promise<string> {
  const response = await asConsole({
    method: "POST",
    url: "/console/accounts",
    payload: { username, password },
  });
  expect(response.statusCode).toBe(201);
  return response.json().account.subject as string;
}

it("answers 401 with no console session, on every route", async () => {
  for (const init of [
    { method: "GET" as const, url: "/console/accounts" },
    {
      method: "POST" as const,
      url: "/console/accounts",
      payload: { username: "x", password: PASSWORD },
    },
    { method: "GET" as const, url: "/console/accounts/deadbeef" },
    { method: "POST" as const, url: "/console/accounts/deadbeef/disable" },
    { method: "POST" as const, url: "/console/accounts/deadbeef/enable" },
    {
      method: "POST" as const,
      url: "/console/accounts/deadbeef/password",
      payload: { password: PASSWORD },
    },
  ]) {
    const response = await app.inject(init);
    expect(response.statusCode, init.url).toBe(401);
    expect(response.json()).toEqual({ error: "unauthorized" });
  }

  expect(findUserByUsername(db, "x")).toBeUndefined();
  expect(listAudit(db)).toHaveLength(0);
});

describe("creating an account", () => {
  it("stores the account with no email, a real hash, and no grants at all", async () => {
    const response = await asConsole({
      method: "POST",
      url: "/console/accounts",
      payload: { username: "cristian", password: PASSWORD },
    });

    expect(response.statusCode).toBe(201);
    expect(response.json().account).toMatchObject({
      username: "cristian",
      email: null,
      emailVerified: false,
      disabled: false,
      disabledAt: null,
    });
    // The hash never leaves the database.
    expect(JSON.stringify(response.json())).not.toContain("password");

    const row = findUserByUsername(db, "cristian")!;
    expect(row.email).toBeNull();
    await expect(verifyPassword(PASSWORD, row.password_hash)).resolves.toBe(true);

    /**
     * **Registration confers nothing.** Not even for the account that will
     * become the owner: there is no wildcard grant and no implicit baseline on
     * this path, so a newly created account reaches no app until someone says
     * otherwise.
     */
    expect(listGrantsForSubject(db, row.subject)).toEqual([]);
  });

  it("records user.create naming the actor", async () => {
    const subject = await createAccount();

    const [row] = listAudit(db);
    expect(row).toMatchObject({
      actor_kind: "superuser",
      actor_subject: null,
      actor_label: "superuser",
      action: "user.create",
      target_kind: "user",
      target_id: subject,
    });
    expect(JSON.parse(row!.detail!)).toEqual({ session: sessionId, username: "cristian" });
  });

  it("answers 409 for a username taken in any casing", async () => {
    await createAccount("cristian");

    const again = await asConsole({
      method: "POST",
      url: "/console/accounts",
      payload: { username: "CRISTIAN", password: PASSWORD },
    });
    expect(again.statusCode).toBe(409);
    expect(again.json()).toEqual({ error: "username_taken" });
  });

  /** The brief: surface `PasswordPolicyError.code`, not its message. */
  it("surfaces the password policy code rather than a message", async () => {
    const short = await asConsole({
      method: "POST",
      url: "/console/accounts",
      payload: { username: "cristian", password: "short" },
    });
    expect(short.statusCode).toBe(400);
    expect(short.json()).toEqual({ error: "password_too_short" });

    const long = await asConsole({
      method: "POST",
      url: "/console/accounts",
      payload: { username: "cristian", password: "x".repeat(1025) },
    });
    expect(long.statusCode).toBe(400);
    expect(long.json()).toEqual({ error: "password_too_long" });

    expect(findUserByUsername(db, "cristian")).toBeUndefined();
    expect(listAudit(db)).toHaveLength(0);
  });

  /**
   * Two accounts that render identically in the console's list are a way to
   * grant the wrong person's access by clicking the wrong row, and
   * `foldUsername` collapses case and Unicode form but not whitespace.
   */
  it("rejects a username that cannot be read back reliably", async () => {
    const rejected = [
      "", // empty
      "   ", // whitespace only, empty after the trim
      "bad\nname", // a control character
      "zero\u200bwidth", // a zero-width format character
      "no\u00a0break", // a no-break space that renders as a space
      "double  space", // two spaces render as one
    ];

    for (const username of rejected) {
      const response = await asConsole({
        method: "POST",
        url: "/console/accounts",
        payload: { username, password: PASSWORD },
      });
      expect(response.statusCode, JSON.stringify(username)).toBe(400);
      expect(response.json()).toEqual({ error: "invalid_request" });
    }

    // A single internal space is fine — a username is what a person typed.
    const ok = await asConsole({
      method: "POST",
      url: "/console/accounts",
      payload: { username: "cristian g", password: PASSWORD },
    });
    expect(ok.statusCode).toBe(201);
  });
});

describe("disabling an account", () => {
  /**
   * **The acceptance criterion.** `disabled_at` alone blocks only *future*
   * logins: the refresh token behind a live session would keep minting access
   * tokens for thirty days. Disabling therefore revokes the refresh families in
   * the same transaction.
   *
   * Brief 04's `/introspect` is what proves this end to end within the cache
   * window; that endpoint is being written in parallel, so what is asserted here
   * is the state it reads — no live token remains, and every family member is
   * revoked with reason `admin`.
   */
  it("ends live sessions: every refresh family is revoked with reason admin", async () => {
    const subject = await createAccount();
    grantRole(db, { subject, appSlug: "prm", role: "admin", grantedBy: SUPERUSER_ACTOR });

    // Two independent sessions — a laptop and a phone, say.
    const laptop = issueRefreshToken(db, subject);
    const phone = issueRefreshToken(db, subject);
    expect(listLiveTokensForSubject(db, subject)).toHaveLength(2);
    expect(usableAccount(db, subject)?.subject).toBe(subject);

    const response = await asConsole({
      method: "POST",
      url: `/console/accounts/${subject}/disable`,
    });

    expect(response.statusCode).toBe(200);
    expect(response.json()).toMatchObject({
      account: { disabled: true },
      sessionsRevoked: 2,
    });

    // Nothing live is left for this subject.
    expect(listLiveTokensForSubject(db, subject)).toEqual([]);

    // And every family member carries the console's reason, not a generic one.
    for (const issued of [laptop, phone]) {
      const family = listFamily(db, issued.row.family_id);
      expect(family).toHaveLength(1);
      expect(family[0]!.revoked_at).not.toBeNull();
      expect(family[0]!.revoked_reason).toBe("admin");
    }

    /**
     * And the strongest statement available without brief 04's `/introspect`:
     * presenting the refresh token no longer buys a session. `disabled_at`
     * alone would have left this rotating happily for thirty days.
     */
    expect(rotateRefreshToken(db, laptop.token).status).not.toBe("rotated");
    expect(usableAccount(db, subject)).toBeUndefined();

    // Grants and subject survive — a locked door, not a destroyed identity.
    expect(listGrantsForSubject(db, subject)).toHaveLength(1);
    expect(findUserBySubject(db, subject)!.disabled_at).not.toBeNull();
  });

  it("records user.disable naming the actor and how many sessions it ended", async () => {
    const subject = await createAccount();
    issueRefreshToken(db, subject);
    db.exec("DELETE FROM audit_log");

    await asConsole({ method: "POST", url: `/console/accounts/${subject}/disable` });

    const [row] = listAudit(db, { action: "user.disable" });
    expect(row).toMatchObject({
      actor_kind: "superuser",
      actor_subject: null,
      actor_label: "superuser",
      target_kind: "user",
      target_id: subject,
    });
    expect(JSON.parse(row!.detail!)).toEqual({
      session: sessionId,
      username: "cristian",
      sessionsRevoked: 1,
      alreadyDisabled: false,
    });
  });

  it("is idempotent and does not rewrite when the disable happened", async () => {
    const subject = await createAccount();
    const first = await asConsole({ method: "POST", url: `/console/accounts/${subject}/disable` });
    const disabledAt = first.json().account.disabledAt as string;

    const second = await asConsole({ method: "POST", url: `/console/accounts/${subject}/disable` });
    expect(second.statusCode).toBe(200);
    expect(second.json().account.disabledAt).toBe(disabledAt);
    expect(second.json().sessionsRevoked).toBe(0);

    // The second click changed nothing, so it is not an event.
    expect(listAudit(db, { action: "user.disable" })).toHaveLength(1);
  });

  it("404s on a subject that does not exist", async () => {
    const response = await asConsole({ method: "POST", url: "/console/accounts/deadbeef/disable" });
    expect(response.statusCode).toBe(404);
    expect(response.json()).toEqual({ error: "account_not_found" });
  });
});

describe("re-enabling an account", () => {
  it("restores the account and its grants but not its revoked sessions", async () => {
    const subject = await createAccount();
    grantRole(db, { subject, appSlug: "prm", role: "admin", grantedBy: SUPERUSER_ACTOR });
    issueRefreshToken(db, subject);
    await asConsole({ method: "POST", url: `/console/accounts/${subject}/disable` });
    db.exec("DELETE FROM audit_log");

    const response = await asConsole({
      method: "POST",
      url: `/console/accounts/${subject}/enable`,
    });

    expect(response.statusCode).toBe(200);
    expect(response.json()).toMatchObject({
      account: { disabled: false, disabledAt: null },
      changed: true,
    });
    expect(listGrantsForSubject(db, subject)).toHaveLength(1);
    // A revoked refresh token stays revoked. The person signs in again.
    expect(listLiveTokensForSubject(db, subject)).toEqual([]);

    const [row] = listAudit(db);
    expect(row).toMatchObject({
      action: "user.enable",
      actor_label: "superuser",
      target_id: subject,
    });
  });

  it("is a no-op on an account that is already enabled", async () => {
    const subject = await createAccount();
    db.exec("DELETE FROM audit_log");

    const response = await asConsole({
      method: "POST",
      url: `/console/accounts/${subject}/enable`,
    });
    expect(response.statusCode).toBe(200);
    expect(response.json().changed).toBe(false);
    expect(listAudit(db)).toHaveLength(0);
  });
});

describe("rotating a password", () => {
  it("replaces the hash and ends the sessions the old password opened", async () => {
    const subject = await createAccount();
    issueRefreshToken(db, subject);
    db.exec("DELETE FROM audit_log");

    const response = await asConsole({
      method: "POST",
      url: `/console/accounts/${subject}/password`,
      payload: { password: "an-entirely-different-password" },
    });

    expect(response.statusCode).toBe(200);
    expect(response.json()).toEqual({ subject, sessionsRevoked: 1 });

    const row = findUserBySubject(db, subject)!;
    await expect(verifyPassword("an-entirely-different-password", row.password_hash)).resolves.toBe(
      true,
    );
    await expect(verifyPassword(PASSWORD, row.password_hash)).resolves.toBe(false);
    expect(listLiveTokensForSubject(db, subject)).toEqual([]);

    const [audit] = listAudit(db);
    expect(audit).toMatchObject({
      action: "user.password_rotate",
      actor_label: "superuser",
      target_id: subject,
    });
    // The new password is never audited.
    expect(audit!.detail).not.toContain("an-entirely-different-password");
  });

  it("surfaces the policy code and changes nothing on a rejected password", async () => {
    const subject = await createAccount();
    const before = findUserBySubject(db, subject)!.password_hash;
    db.exec("DELETE FROM audit_log");

    const response = await asConsole({
      method: "POST",
      url: `/console/accounts/${subject}/password`,
      payload: { password: "tiny" },
    });

    expect(response.statusCode).toBe(400);
    expect(response.json()).toEqual({ error: "password_too_short" });
    expect(findUserBySubject(db, subject)!.password_hash).toBe(before);
    expect(listAudit(db)).toHaveLength(0);
  });

  it("404s on a subject that does not exist", async () => {
    const response = await asConsole({
      method: "POST",
      url: "/console/accounts/deadbeef/password",
      payload: { password: PASSWORD },
    });
    expect(response.statusCode).toBe(404);
    expect(response.json()).toEqual({ error: "account_not_found" });
  });
});

describe("reading accounts", () => {
  it("lists accounts with a total, and never a hash", async () => {
    await createAccount("cristian");
    await createAccount("guest");

    const response = await asConsole({ method: "GET", url: "/console/accounts" });
    expect(response.statusCode).toBe(200);
    expect(response.json().total).toBe(2);
    expect(response.json().accounts.map((a: { username: string }) => a.username)).toEqual([
      "cristian",
      "guest",
    ]);
    // The stored hash is `saltHex:hashHex`; none of it reaches the wire.
    for (const username of ["cristian", "guest"]) {
      const hash = findUserByUsername(db, username)!.password_hash;
      expect(JSON.stringify(response.json())).not.toContain(hash);
    }
  });

  it("reads one account with its grants and its live session count", async () => {
    const subject = await createAccount();
    grantRole(db, { subject, appSlug: "prm", role: "admin", grantedBy: SUPERUSER_ACTOR });
    issueRefreshToken(db, subject);

    const response = await asConsole({ method: "GET", url: `/console/accounts/${subject}` });
    expect(response.statusCode).toBe(200);
    expect(response.json()).toMatchObject({
      account: { subject, username: "cristian" },
      grants: [{ appSlug: "prm", role: "admin", grantedBy: "superuser" }],
      liveSessions: 1,
    });
  });

  it("404s on a subject that does not exist", async () => {
    const response = await asConsole({ method: "GET", url: "/console/accounts/deadbeef" });
    expect(response.statusCode).toBe(404);
    expect(response.json()).toEqual({ error: "account_not_found" });
  });
});
