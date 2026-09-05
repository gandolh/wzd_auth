import type Database from "better-sqlite3";
import Fastify, {
  type FastifyInstance,
  type InjectOptions,
  type LightMyRequestResponse,
} from "fastify";
import { afterEach, beforeEach, describe, expect, it } from "vitest";

import { issueRefreshToken, rotateRefreshToken } from "../../auth/refresh.js";
import {
  CONSOLE_COOKIE_NAME,
  openConsoleSession,
  resetConsoleSessionsForTests,
} from "../../auth/superuser.js";
import { listAudit } from "../../db/audit-log.js";
import { listFamily, listLiveTokensForSubject } from "../../db/refresh-tokens.js";
import { findUserBySubject, setDisabled } from "../../db/users.js";
import { freshDb, seedApps, seedUser } from "../../db/test-support.js";
import { adminSessionsRoutes } from "./sessions.js";

/**
 * `/console/accounts/:subject/sessions` — list, revoke one, revoke all.
 *
 * The three assertions worth reading are: `token_hash` never leaves the
 * database; a family id from the URL cannot revoke a session belonging to
 * somebody else; and revoking all of them leaves the account enabled, which is
 * the whole difference from the disable → re-enable dance brief 10 had to use.
 */

let db: Database.Database;
let app: FastifyInstance;
let cookie: string;
let subject: string;

beforeEach(async () => {
  db = freshDb();
  seedApps(db);
  subject = seedUser(db, "cristian").subject;

  app = Fastify({ logger: false });
  await app.register(adminSessionsRoutes, { db });
  await app.ready();

  cookie = `${CONSOLE_COOKIE_NAME}=${encodeURIComponent(openConsoleSession().token)}`;
});

afterEach(async () => {
  await app.close();
  db.close();
  resetConsoleSessionsForTests();
});

const asConsole = (init: InjectOptions): Promise<LightMyRequestResponse> =>
  app.inject({ ...init, headers: { ...init.headers, cookie } });

/** One sign-in: a fresh family with one live token. */
function signIn(forSubject = subject): { token: string; familyId: string } {
  const issued = issueRefreshToken(db, forSubject);
  return { token: issued.token, familyId: issued.row.family_id };
}

it("answers 401 with no console session, on every route", async () => {
  const { familyId } = signIn();

  for (const init of [
    { method: "GET" as const, url: `/console/accounts/${subject}/sessions` },
    { method: "DELETE" as const, url: `/console/accounts/${subject}/sessions/${familyId}` },
    { method: "POST" as const, url: `/console/accounts/${subject}/sessions/revoke` },
  ]) {
    const response = await app.inject(init);
    expect(response.statusCode, init.url).toBe(401);
    expect(response.json()).toEqual({ error: "unauthorized" });
  }

  // Nothing happened.
  expect(listLiveTokensForSubject(db, subject)).toHaveLength(1);
  expect(listAudit(db)).toHaveLength(0);
});

describe("GET .../sessions", () => {
  it("projects one row per family with no token hash anywhere", async () => {
    const first = signIn();
    const second = signIn();

    const response = await asConsole({
      method: "GET",
      url: `/console/accounts/${subject}/sessions`,
    });

    expect(response.statusCode).toBe(200);
    expect(response.headers["cache-control"]).toBe("no-store");

    const body = response.json() as {
      sessions: Record<string, unknown>[];
      total: number;
    };
    expect(body.total).toBe(2);
    expect(body.sessions.map((session) => session.familyId).sort()).toEqual(
      [first.familyId, second.familyId].sort(),
    );

    for (const session of body.sessions) {
      expect(Object.keys(session).sort()).toEqual(["expiresAt", "familyId", "issuedAt", "usedAt"]);
    }

    /**
     * **The credential never leaves the database.** Asserted against the raw
     * body rather than against the mapper, and against the actual stored hash
     * rather than against the word "hash", so a future change that spread a row
     * would fail here.
     */
    const stored = listLiveTokensForSubject(db, subject);
    for (const row of stored) {
      expect(response.body).not.toContain(row.token_hash);
    }
    expect(response.body).not.toContain("token_hash");
    expect(response.body).not.toContain("tokenHash");
  });

  /**
   * A rotation revokes the predecessor as it issues the successor, so a family
   * stays one entry. Inside `REFRESH_RACE_GRACE_SECONDS` a raced refresh can
   * leave two live rows in one family, and listing rows would show one device
   * twice — an operator believing in a session that does not exist.
   */
  it("collapses a rotated family to one entry, newest first", async () => {
    const first = signIn();
    const rotated = rotateRefreshToken(db, first.token);
    expect(rotated.status).toBe("rotated");

    const response = await asConsole({
      method: "GET",
      url: `/console/accounts/${subject}/sessions`,
    });

    const sessions = response.json().sessions as { familyId: string; issuedAt: string }[];
    expect(sessions).toHaveLength(1);
    expect(sessions[0]!.familyId).toBe(first.familyId);
    // The current member's issuance, not the family's root — documented on
    // `SessionView.issuedAt`.
    const live = listLiveTokensForSubject(db, subject);
    expect(sessions[0]!.issuedAt).toBe(live[0]!.issued_at);
  });

  it("omits a revoked family", async () => {
    const kept = signIn();
    const gone = signIn();
    await asConsole({
      method: "DELETE",
      url: `/console/accounts/${subject}/sessions/${gone.familyId}`,
    });

    const response = await asConsole({
      method: "GET",
      url: `/console/accounts/${subject}/sessions`,
    });
    expect((response.json().sessions as { familyId: string }[]).map((s) => s.familyId)).toEqual([
      kept.familyId,
    ]);
  });

  it("distinguishes an account with no sessions from an account that does not exist", async () => {
    const empty = await asConsole({
      method: "GET",
      url: `/console/accounts/${subject}/sessions`,
    });
    expect(empty.statusCode).toBe(200);
    expect(empty.json()).toEqual({ sessions: [], total: 0 });

    const missing = await asConsole({
      method: "GET",
      url: "/console/accounts/deadbeef/sessions",
    });
    expect(missing.statusCode).toBe(404);
    expect(missing.json()).toEqual({ error: "account_not_found" });
  });
});

describe("DELETE .../sessions/:familyId", () => {
  it("revokes that family with reason admin and leaves the others alone", async () => {
    const kept = signIn();
    const doomed = signIn();

    const response = await asConsole({
      method: "DELETE",
      url: `/console/accounts/${subject}/sessions/${doomed.familyId}`,
    });

    expect(response.statusCode).toBe(200);
    expect(response.json()).toEqual({
      subject,
      familyId: doomed.familyId,
      revoked: 1,
      changed: true,
    });

    const dead = listFamily(db, doomed.familyId);
    expect(dead.every((row) => row.revoked_reason === "admin")).toBe(true);
    expect(listLiveTokensForSubject(db, subject).map((row) => row.family_id)).toEqual([
      kept.familyId,
    ]);
  });

  it("audits it as the superuser, naming the family and the account", async () => {
    const { familyId } = signIn();

    await asConsole({
      method: "DELETE",
      url: `/console/accounts/${subject}/sessions/${familyId}`,
    });

    const [row] = listAudit(db);
    expect(row).toMatchObject({
      actor_kind: "superuser",
      actor_subject: null,
      actor_label: "superuser",
      action: "session.revoke",
      target_kind: "session",
      target_id: familyId,
    });
    expect(JSON.parse(row!.detail!)).toMatchObject({
      subject,
      username: "cristian",
      tokensRevoked: 1,
    });
  });

  /**
   * **The whole reason `:subject` is in the path at all.**
   *
   * The revoke itself is keyed on `family_id`, so the subject is redundant to
   * the write. A console that revokes any family given any subject is a console
   * whose URLs cannot be trusted in an audit row or a bug report — the row
   * would name an account that had nothing to do with the session that ended.
   */
  it("refuses a family belonging to another account, and revokes nothing", async () => {
    const other = seedUser(db, "someone-else");
    const theirs = signIn(other.subject);

    const response = await asConsole({
      method: "DELETE",
      url: `/console/accounts/${subject}/sessions/${theirs.familyId}`,
    });

    expect(response.statusCode).toBe(404);
    // Identical to a family that does not exist: saying "real, but not theirs"
    // would confirm a guessed family id.
    expect(response.json()).toEqual({ error: "session_not_found" });

    expect(listLiveTokensForSubject(db, other.subject)).toHaveLength(1);
    expect(listAudit(db)).toHaveLength(0);
  });

  it("answers session_not_found for a family that never existed", async () => {
    signIn();
    const response = await asConsole({
      method: "DELETE",
      url: `/console/accounts/${subject}/sessions/nope`,
    });
    expect(response.statusCode).toBe(404);
    expect(response.json()).toEqual({ error: "session_not_found" });
  });

  it("answers account_not_found for an unknown subject", async () => {
    const response = await asConsole({
      method: "DELETE",
      url: "/console/accounts/deadbeef/sessions/whatever",
    });
    expect(response.statusCode).toBe(404);
    expect(response.json()).toEqual({ error: "account_not_found" });
  });

  /** A no-op writes no audit row — brief 05's rule, and `changed` still tells. */
  it("is idempotent, and the repeat leaves no second audit row", async () => {
    const { familyId } = signIn();
    const url = `/console/accounts/${subject}/sessions/${familyId}`;

    expect((await asConsole({ method: "DELETE", url })).json().revoked).toBe(1);
    const repeat = await asConsole({ method: "DELETE", url });

    // The family is no longer live, so it is no longer listed.
    expect(repeat.statusCode).toBe(404);
    expect(listAudit(db)).toHaveLength(1);
  });
});

describe("POST .../sessions/revoke", () => {
  /**
   * The point of the route. Brief 10 had to compose this out of disable →
   * re-enable: two audit rows, a window where the account cannot sign in, and a
   * failure between the calls leaving it disabled.
   */
  it("ends every session and leaves the account enabled, with one audit row", async () => {
    signIn();
    signIn();
    signIn();

    const response = await asConsole({
      method: "POST",
      url: `/console/accounts/${subject}/sessions/revoke`,
    });

    expect(response.statusCode).toBe(200);
    expect(response.json()).toEqual({
      subject,
      revoked: 3,
      tokensRevoked: 3,
      changed: true,
    });

    expect(listLiveTokensForSubject(db, subject)).toEqual([]);
    // No side effect: not disabled, and exactly one row rather than two.
    expect(findUserBySubject(db, subject)!.disabled_at).toBeNull();

    const rows = listAudit(db);
    expect(rows).toHaveLength(1);
    expect(rows[0]).toMatchObject({
      actor_kind: "superuser",
      action: "session.revoke_all",
      target_kind: "user",
      target_id: subject,
    });
    expect(JSON.parse(rows[0]!.detail!)).toMatchObject({
      username: "cristian",
      sessionsRevoked: 3,
    });
  });

  it("counts families rather than rows, so a rotated family is one session", async () => {
    const first = signIn();
    rotateRefreshToken(db, first.token);
    signIn();

    const response = await asConsole({
      method: "POST",
      url: `/console/accounts/${subject}/sessions/revoke`,
    });
    expect(response.json().revoked).toBe(2);
  });

  it("leaves the password, grants and disabled state untouched", async () => {
    const before = findUserBySubject(db, subject)!;
    signIn();

    await asConsole({ method: "POST", url: `/console/accounts/${subject}/sessions/revoke` });

    const after = findUserBySubject(db, subject)!;
    expect(after.password_hash).toBe(before.password_hash);
    expect(after.disabled_at).toBeNull();
  });

  it("is a 200 no-op with no audit row when nothing is live", async () => {
    const response = await asConsole({
      method: "POST",
      url: `/console/accounts/${subject}/sessions/revoke`,
    });
    expect(response.statusCode).toBe(200);
    expect(response.json()).toEqual({ subject, revoked: 0, tokensRevoked: 0, changed: false });
    expect(listAudit(db)).toHaveLength(0);
  });

  it("works on a disabled account without re-enabling it", async () => {
    signIn();
    setDisabled(db, subject, true);

    const response = await asConsole({
      method: "POST",
      url: `/console/accounts/${subject}/sessions/revoke`,
    });
    expect(response.json().revoked).toBe(1);
    expect(findUserBySubject(db, subject)!.disabled_at).not.toBeNull();
  });

  it("answers account_not_found for an unknown subject", async () => {
    const response = await asConsole({
      method: "POST",
      url: "/console/accounts/deadbeef/sessions/revoke",
    });
    expect(response.statusCode).toBe(404);
    expect(response.json()).toEqual({ error: "account_not_found" });
  });
});
