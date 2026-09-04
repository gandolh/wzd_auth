import type Database from "better-sqlite3";
import { afterEach, beforeEach, describe, expect, it } from "vitest";

import { listAudit } from "../db/audit-log.js";
import {
  findRefreshToken,
  hashRefreshToken,
  listFamily,
  listLiveTokensForSubject,
} from "../db/refresh-tokens.js";
import { freshDb, seedUser } from "../db/test-support.js";
import { setDisabled } from "../db/users.js";
import {
  REFRESH_TOKEN_TTL_SECONDS,
  endSession,
  issueRefreshToken,
  refreshCookieMaxAge,
  rotateRefreshToken,
  usableAccount,
} from "./refresh.js";

/**
 * The rotation protocol against a real `:memory:` database.
 *
 * `openDatabase(":memory:")` via `freshDb()`, never `getDb()` — `getDb`
 * resolves `WARD_DB_PATH` and would open the real database on disk.
 */

let db: Database.Database;
let subject: string;

beforeEach(() => {
  db = freshDb();
  subject = seedUser(db, "alice").subject;
});

afterEach(() => {
  db.close();
});

describe("issueRefreshToken", () => {
  it("stores only the hash, never the token", () => {
    const issued = issueRefreshToken(db, subject);

    expect(issued.token).toMatch(/^[0-9a-f]{64}$/); // 32 random bytes, hex
    expect(issued.row.token_hash).toBe(hashRefreshToken(issued.token));

    // The plaintext appears nowhere in the table.
    const dump = JSON.stringify(db.prepare("SELECT * FROM refresh_tokens").all());
    expect(dump).not.toContain(issued.token);
    expect(dump).toContain(issued.row.token_hash);
  });

  it("gives each login its own family", () => {
    const a = issueRefreshToken(db, subject);
    const b = issueRefreshToken(db, subject);

    expect(a.row.family_id).not.toBe(b.row.family_id);
  });

  it("expires 30 days out", () => {
    const now = new Date("2026-09-04T12:00:00.000Z");
    const issued = issueRefreshToken(db, subject, { now });

    expect(Date.parse(issued.row.expires_at) - now.getTime()).toBe(
      REFRESH_TOKEN_TTL_SECONDS * 1000,
    );
  });
});

describe("rotateRefreshToken — the happy path", () => {
  it("returns R2, invalidates R1, and keeps the family", () => {
    const r1 = issueRefreshToken(db, subject);
    const outcome = rotateRefreshToken(db, r1.token);

    expect(outcome.status).toBe("rotated");
    if (outcome.status !== "rotated") return;

    expect(outcome.subject).toBe(subject);
    expect(outcome.refreshToken).not.toBe(r1.token);
    expect(outcome.row.family_id).toBe(r1.row.family_id);

    // R1 is spent AND marked, so the console can tell an ordinary rotation
    // from a logout from a theft signal.
    const spent = findRefreshToken(db, r1.row.token_hash);
    expect(spent?.used_at).not.toBeNull();
    expect(spent?.revoked_reason).toBe("rotated");

    // Exactly one live token in the family: the new one.
    const live = listLiveTokensForSubject(db, subject);
    expect(live).toHaveLength(1);
    expect(live[0]?.token_hash).toBe(hashRefreshToken(outcome.refreshToken));
  });

  it("R2 works, and rotating it again chains within the same family", () => {
    const r1 = issueRefreshToken(db, subject);
    const first = rotateRefreshToken(db, r1.token);
    expect(first.status).toBe("rotated");
    if (first.status !== "rotated") return;

    const second = rotateRefreshToken(db, first.refreshToken);
    expect(second.status).toBe("rotated");
    if (second.status !== "rotated") return;

    expect(second.row.family_id).toBe(r1.row.family_id);
    expect(listFamily(db, r1.row.family_id)).toHaveLength(3);
    expect(listLiveTokensForSubject(db, subject)).toHaveLength(1);
  });

  it("R2 inherits the family's absolute expiry rather than sliding 30 days out", () => {
    // 30 days is a lifetime for the family, counted from the login that created
    // it. A sliding expiry would make a family immortal for as long as anybody
    // keeps rotating it, and the party most likely to rotate quietly forever is
    // a thief. See the note in `completeRotation`.
    const r1 = issueRefreshToken(db, subject);
    const outcome = rotateRefreshToken(db, r1.token);
    if (outcome.status !== "rotated") return expect.unreachable();

    expect(outcome.row.expires_at).toBe(r1.row.expires_at);
  });

  it("writes no audit row for an ordinary rotation", () => {
    // A refresh every 15 minutes for 30 days is ~2900 rotations per session.
    // Auditing them would bury the one event an operator needs to see.
    const r1 = issueRefreshToken(db, subject);
    rotateRefreshToken(db, r1.token);

    expect(listAudit(db)).toHaveLength(0);
  });
});

describe("rotateRefreshToken — reuse detection", () => {
  /**
   * The most important test in the brief.
   */
  it("refreshing twice with the same token revokes the whole family", () => {
    const r1 = issueRefreshToken(db, subject);

    const first = rotateRefreshToken(db, r1.token);
    expect(first.status).toBe("rotated");
    if (first.status !== "rotated") return;

    // The replay. Whoever sent it — the victim retrying a lost response, or a
    // thief with a copy — there is no information anywhere that tells them
    // apart, so both lose the session.
    const replay = rotateRefreshToken(db, r1.token);

    expect(replay.status).toBe("reuse_detected");
    if (replay.status !== "reuse_detected") return;
    expect(replay.familyId).toBe(r1.row.family_id);
    expect(replay.subject).toBe(subject);
    // R2 was the one live token, and it is gone.
    expect(replay.revoked).toBe(1);

    expect(listLiveTokensForSubject(db, subject)).toEqual([]);

    // R2 specifically no longer works: the thief is not left holding a live
    // token, which is the entire point of killing the family rather than the
    // presented token.
    expect(rotateRefreshToken(db, first.refreshToken).status).toBe("revoked");

    // Every member of the family is dead.
    for (const member of listFamily(db, r1.row.family_id)) {
      expect(member.revoked_at).not.toBeNull();
    }
  });

  it("records the reuse to audit_log with the family, and no token or hash", () => {
    const r1 = issueRefreshToken(db, subject);
    rotateRefreshToken(db, r1.token);
    rotateRefreshToken(db, r1.token);

    const rows = listAudit(db, { action: "session.reuse_detected" });
    expect(rows).toHaveLength(1);

    const row = rows[0]!;
    expect(row.actor_kind).toBe("system");
    // `actor_subject` is null because the actor is Ward's own detection, and the
    // schema's CHECK ties a non-null subject to `actor_kind = 'account'`.
    expect(row.actor_subject).toBeNull();
    expect(row.target_kind).toBe("session");
    expect(row.target_id).toBe(r1.row.family_id);

    const detail = JSON.parse(row.detail!) as { subject: string; tokensRevoked: number };
    expect(detail.subject).toBe(subject);
    expect(detail.tokensRevoked).toBe(1);

    // The one thing that must not be in a table designed to be read at leisure.
    expect(row.detail).not.toContain(r1.token);
    expect(row.detail).not.toContain(r1.row.token_hash);
  });

  it("a revoked family cannot be revived", () => {
    const r1 = issueRefreshToken(db, subject);
    const first = rotateRefreshToken(db, r1.token);
    if (first.status !== "rotated") return expect.unreachable();

    rotateRefreshToken(db, r1.token); // burn it down

    const beforeCount = listFamily(db, r1.row.family_id).length;

    // Every member, replayed again in every order, mints nothing.
    expect(rotateRefreshToken(db, first.refreshToken).status).toBe("revoked");
    expect(rotateRefreshToken(db, r1.token).status).toBe("reuse_detected");

    expect(listFamily(db, r1.row.family_id)).toHaveLength(beforeCount);
    expect(listLiveTokensForSubject(db, subject)).toEqual([]);
  });

  it("preserves the reason that killed a row first", () => {
    const r1 = issueRefreshToken(db, subject);
    rotateRefreshToken(db, r1.token);
    rotateRefreshToken(db, r1.token);

    // R1 died as `rotated` before the sweep ran; the sweep must not relabel it,
    // or the console loses the distinction between the two events.
    expect(findRefreshToken(db, r1.row.token_hash)?.revoked_reason).toBe("rotated");
  });

  it("leaves other families alone", () => {
    const laptop = issueRefreshToken(db, subject);
    const phone = issueRefreshToken(db, subject);

    rotateRefreshToken(db, laptop.token);
    rotateRefreshToken(db, laptop.token); // reuse on the laptop family

    // The phone is a separate login and a separate family. Killing it too would
    // make one lost response anywhere sign a person out everywhere.
    expect(rotateRefreshToken(db, phone.token).status).toBe("rotated");
  });
});

describe("rotateRefreshToken — the other refusals", () => {
  it("refuses an unknown token without touching anything", () => {
    const outcome = rotateRefreshToken(db, "f".repeat(64));

    expect(outcome).toEqual({ status: "unknown" });
    expect(listAudit(db)).toHaveLength(0);
  });

  it("refuses an expired token", () => {
    const past = new Date(Date.now() - 60_000).toISOString();
    const expired = issueRefreshToken(db, subject, { expiresAt: past });

    const outcome = rotateRefreshToken(db, expired.token);

    expect(outcome.status).toBe("expired");
    // Not spent, so a later presentation is still reported as expired rather
    // than being misread as a replay.
    expect(findRefreshToken(db, expired.row.token_hash)?.used_at).toBeNull();
    expect(listLiveTokensForSubject(db, subject)).toEqual([]);
  });

  it("refuses a token for a disabled account, and kills the family", () => {
    const issued = issueRefreshToken(db, subject);
    setDisabled(db, subject, true);

    const outcome = rotateRefreshToken(db, issued.token);

    expect(outcome.status).toBe("account_unusable");
    if (outcome.status !== "account_unusable") return;
    expect(outcome.subject).toBe(subject);

    // A live family for an account that cannot sign in is a door left open.
    expect(listLiveTokensForSubject(db, subject)).toEqual([]);

    const rows = listAudit(db, { action: "session.refresh_denied" });
    expect(rows).toHaveLength(1);
    expect(JSON.parse(rows[0]!.detail!)).toMatchObject({ reason: "account_disabled" });

    // And re-enabling does not resurrect it — the person logs in again.
    setDisabled(db, subject, false);
    expect(listLiveTokensForSubject(db, subject)).toEqual([]);
  });

  it("refuses a token whose family a logout already killed", () => {
    const issued = issueRefreshToken(db, subject);
    endSession(db, issued.token);

    expect(rotateRefreshToken(db, issued.token).status).toBe("revoked");
  });
});

describe("endSession", () => {
  it("kills the presented token's family and audits it", () => {
    const issued = issueRefreshToken(db, subject);

    const result = endSession(db, issued.token);

    expect(result.ended).toBe(true);
    expect(result.familyId).toBe(issued.row.family_id);
    expect(listLiveTokensForSubject(db, subject)).toEqual([]);
    expect(findRefreshToken(db, issued.row.token_hash)?.revoked_reason).toBe("logout");

    const rows = listAudit(db, { action: "session.logout" });
    expect(rows).toHaveLength(1);
    expect(rows[0]?.actor_subject).toBe(subject);
  });

  it("kills only this device's family", () => {
    const laptop = issueRefreshToken(db, subject);
    const phone = issueRefreshToken(db, subject);

    endSession(db, laptop.token);

    const live = listLiveTokensForSubject(db, subject);
    expect(live).toHaveLength(1);
    expect(live[0]?.family_id).toBe(phone.row.family_id);
  });

  it("kills the whole chain, not just the presented token", () => {
    const r1 = issueRefreshToken(db, subject);
    const rotated = rotateRefreshToken(db, r1.token);
    if (rotated.status !== "rotated") return expect.unreachable();

    // Logging out with R2 must not leave R1's family partly alive.
    endSession(db, rotated.refreshToken);

    expect(listLiveTokensForSubject(db, subject)).toEqual([]);
  });

  it("is silent and idempotent for a token it does not know", () => {
    expect(endSession(db, undefined)).toEqual({ ended: false, revoked: 0 });
    expect(endSession(db, "")).toEqual({ ended: false, revoked: 0 });
    expect(endSession(db, "f".repeat(64))).toEqual({ ended: false, revoked: 0 });

    const issued = issueRefreshToken(db, subject);
    expect(endSession(db, issued.token).ended).toBe(true);
    // A second logout writes no second audit row.
    expect(endSession(db, issued.token).ended).toBe(false);
    expect(listAudit(db, { action: "session.logout" })).toHaveLength(1);
  });
});

describe("refreshCookieMaxAge", () => {
  it("is the row's remaining life, so the cookie cannot outlive it", () => {
    const now = new Date("2026-09-04T12:00:00.000Z");
    const issued = issueRefreshToken(db, subject, { now });

    expect(refreshCookieMaxAge(issued.row, now)).toBe(REFRESH_TOKEN_TTL_SECONDS);

    const later = new Date(now.getTime() + 10 * 24 * 3600 * 1000);
    expect(refreshCookieMaxAge(issued.row, later)).toBe(20 * 24 * 3600);
  });

  it("floors at zero rather than going negative", () => {
    const issued = issueRefreshToken(db, subject, {
      expiresAt: new Date(Date.now() - 60_000).toISOString(),
    });

    expect(refreshCookieMaxAge(issued.row)).toBe(0);
  });
});

describe("usableAccount", () => {
  it("is the account unless it is disabled or gone", () => {
    expect(usableAccount(db, subject)?.username).toBe("alice");
    expect(usableAccount(db, "0".repeat(32))).toBeUndefined();

    setDisabled(db, subject, true);
    expect(usableAccount(db, subject)).toBeUndefined();
  });
});
