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
  REFRESH_RACE_GRACE_SECONDS,
  REFRESH_TOKEN_TTL_SECONDS,
  endSession,
  issueRefreshToken,
  refreshCookieMaxAge,
  rotateRefreshToken,
  subjectForRefreshToken,
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

/**
 * A clock past the race grace window.
 *
 * A replay is only read as theft once the family's live tip is older than
 * `REFRESH_RACE_GRACE_SECONDS` — inside that window it is two tabs firing at
 * once, and killing the family there is the bug this constant exists to fix. So
 * every theft case below presents its stale token from a moment *after* the
 * window, which is also what a real thief does: nobody steals a cookie and uses
 * it in the same tick as its owner.
 */
function afterGrace(): Date {
  return new Date(Date.now() + (REFRESH_RACE_GRACE_SECONDS + 1) * 1000);
}

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

    // The replay, from after the race window. Whoever sent it — the victim
    // retrying a response lost minutes ago, or a thief with a copy — there is no
    // information anywhere that tells them apart, so both lose the session.
    const replay = rotateRefreshToken(db, r1.token, afterGrace());

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
    expect(rotateRefreshToken(db, first.refreshToken, afterGrace()).status).toBe("revoked");

    // Every member of the family is dead.
    for (const member of listFamily(db, r1.row.family_id)) {
      expect(member.revoked_at).not.toBeNull();
    }
  });

  it("records the reuse to audit_log with the family, and no token or hash", () => {
    const r1 = issueRefreshToken(db, subject);
    rotateRefreshToken(db, r1.token);
    rotateRefreshToken(db, r1.token, afterGrace(), { presentedBy: "185.220.101.99" });

    const rows = listAudit(db, { action: "session.reuse_detected" });
    expect(rows).toHaveLength(1);

    const row = rows[0]!;
    expect(row.actor_kind).toBe("system");
    // `actor_subject` is null because the actor is Ward's own detection, and the
    // schema's CHECK ties a non-null subject to `actor_kind = 'account'`.
    expect(row.actor_subject).toBeNull();
    expect(row.target_kind).toBe("session");
    expect(row.target_id).toBe(r1.row.family_id);

    const detail = JSON.parse(row.detail!) as {
      subject: string;
      tokensRevoked: number;
      ip: string | null;
    };
    expect(detail.subject).toBe(subject);
    expect(detail.tokensRevoked).toBe(1);
    /**
     * The presenter's address. The one row an operator is meant to act on used
     * to carry subject, family and timestamps but **not** who presented the
     * replayed token — while the far less interesting `session.login_failed`
     * carried `detail.ip` all along. Without it the owner cannot tell a stranger
     * abroad from their own laptop double-firing a refresh.
     */
    expect(detail.ip).toBe("185.220.101.99");

    // The one thing that must not be in a table designed to be read at leisure.
    expect(row.detail).not.toContain(r1.token);
    expect(row.detail).not.toContain(r1.row.token_hash);
  });

  it("a revoked family cannot be revived", () => {
    const r1 = issueRefreshToken(db, subject);
    const first = rotateRefreshToken(db, r1.token);
    if (first.status !== "rotated") return expect.unreachable();

    rotateRefreshToken(db, r1.token, afterGrace()); // burn it down

    const beforeCount = listFamily(db, r1.row.family_id).length;

    // Every member, replayed again in every order, mints nothing.
    expect(rotateRefreshToken(db, first.refreshToken, afterGrace()).status).toBe("revoked");
    expect(rotateRefreshToken(db, r1.token, afterGrace()).status).toBe("reuse_detected");

    expect(listFamily(db, r1.row.family_id)).toHaveLength(beforeCount);
    expect(listLiveTokensForSubject(db, subject)).toEqual([]);
  });

  it("preserves the reason that killed a row first", () => {
    const r1 = issueRefreshToken(db, subject);
    rotateRefreshToken(db, r1.token);
    rotateRefreshToken(db, r1.token, afterGrace());

    // R1 died as `rotated` before the sweep ran; the sweep must not relabel it,
    // or the console loses the distinction between the two events.
    expect(findRefreshToken(db, r1.row.token_hash)?.revoked_reason).toBe("rotated");
  });

  it("leaves other families alone", () => {
    const laptop = issueRefreshToken(db, subject);
    const phone = issueRefreshToken(db, subject);

    rotateRefreshToken(db, laptop.token);
    rotateRefreshToken(db, laptop.token, afterGrace()); // reuse on the laptop family

    // The phone is a separate login and a separate family. Killing it too would
    // make one lost response anywhere sign a person out everywhere.
    expect(rotateRefreshToken(db, phone.token).status).toBe("rotated");
  });
});

describe("rotateRefreshToken — the same-token race is not theft", () => {
  /**
   * The finding this whole carve-out exists for.
   *
   * Two tabs of one app fire `/refresh` in the same tick with the same `R1`.
   * `claimRefreshToken` is atomic, so exactly one wins — that part was never
   * broken. What was broken is the *response* to the loser: it burned the family
   * down microseconds after the winner had written `R2` into the cookie jar the
   * two tabs share, leaving the client holding a credential that was revoked on
   * arrival and dead on its next use. Reproduced as `200` + `401` with zero live
   * tokens left for the subject.
   */
  it("leaves the family alive, with the winner's R2 still usable", () => {
    const r1 = issueRefreshToken(db, subject);

    const winner = rotateRefreshToken(db, r1.token);
    expect(winner.status).toBe("rotated");
    if (winner.status !== "rotated") return;

    // The losing tab, presenting the same R1 in the same instant.
    const loser = rotateRefreshToken(db, r1.token, new Date(), { presentedBy: "203.0.113.9" });

    expect(loser.status).toBe("refresh_raced");
    if (loser.status !== "refresh_raced") return;
    expect(loser.familyId).toBe(r1.row.family_id);
    expect(loser.subject).toBe(subject);

    // Nothing was revoked: the session is intact and R2 is exactly as live as
    // the winning tab was told it is.
    const live = listLiveTokensForSubject(db, subject);
    expect(live).toHaveLength(1);
    expect(live[0]?.token_hash).toBe(hashRefreshToken(winner.refreshToken));

    // And it still rotates, which is the property the client is relying on.
    expect(rotateRefreshToken(db, winner.refreshToken).status).toBe("rotated");
  });

  it("records session.refresh_raced — a distinct action, with the presenter's address", () => {
    const r1 = issueRefreshToken(db, subject);
    rotateRefreshToken(db, r1.token);
    rotateRefreshToken(db, r1.token, new Date(), { presentedBy: "203.0.113.9" });

    // No theft alarm at all: an operator paging on `session.reuse_detected`
    // must not be woken by two tabs.
    expect(listAudit(db, { action: "session.reuse_detected" })).toHaveLength(0);

    const rows = listAudit(db, { action: "session.refresh_raced" });
    expect(rows).toHaveLength(1);
    expect(rows[0]!.target_id).toBe(r1.row.family_id);

    const detail = JSON.parse(rows[0]!.detail!) as { subject: string; ip: string | null };
    expect(detail.subject).toBe(subject);
    expect(detail.ip).toBe("203.0.113.9");

    // Same discipline as every other row this module writes.
    expect(rows[0]!.detail).not.toContain(r1.token);
    expect(rows[0]!.detail).not.toContain(r1.row.token_hash);
  });

  it("still kills the family for a replay after the grace window", () => {
    const r1 = issueRefreshToken(db, subject);
    rotateRefreshToken(db, r1.token);

    // Same shape as the race above, one second past the window. A thief does
    // not present a stolen cookie in the same tick as its owner.
    const replay = rotateRefreshToken(db, r1.token, afterGrace());

    expect(replay.status).toBe("reuse_detected");
    if (replay.status !== "reuse_detected") return;
    expect(replay.revoked).toBe(1);
    expect(listLiveTokensForSubject(db, subject)).toEqual([]);
    expect(listAudit(db, { action: "session.reuse_detected" })).toHaveLength(1);
    expect(listAudit(db, { action: "session.refresh_raced" })).toHaveLength(0);
  });

  it("still kills the family when the successor was already spent", () => {
    /**
     * The narrowness of the carve-out. `R1 → R2 → R3` and then a replay of `R1`:
     * the family does have a live, fresh tip (`R3`), but it belongs to a *later*
     * rotation — `R1` is not its parent. That is a token arriving two rotations
     * late, which is theft, and it is caught inside the grace window with no
     * clock trickery at all.
     */
    const r1 = issueRefreshToken(db, subject);
    const second = rotateRefreshToken(db, r1.token);
    if (second.status !== "rotated") return expect.unreachable();
    const third = rotateRefreshToken(db, second.refreshToken);
    if (third.status !== "rotated") return expect.unreachable();

    const replay = rotateRefreshToken(db, r1.token);

    expect(replay.status).toBe("reuse_detected");
    if (replay.status !== "reuse_detected") return;
    expect(replay.revoked).toBe(1);

    // R3 — the tip the legitimate client was holding — is dead too.
    expect(listLiveTokensForSubject(db, subject)).toEqual([]);
    expect(rotateRefreshToken(db, third.refreshToken).status).toBe("revoked");
    expect(listAudit(db, { action: "session.refresh_raced" })).toHaveLength(0);
  });

  it("treats a replay in a family with no live tip as theft, not a race", () => {
    // Logged out, so there is no session left to protect and nothing the grace
    // window could be protecting.
    const r1 = issueRefreshToken(db, subject);
    rotateRefreshToken(db, r1.token);
    endSession(db, r1.token);

    expect(rotateRefreshToken(db, r1.token).status).toBe("reuse_detected");
    expect(listAudit(db, { action: "session.refresh_raced" })).toHaveLength(0);
  });
});

describe("the reuse alarm is bounded", () => {
  /**
   * `/refresh` is deliberately exempt from the IP lockout, so an unguarded audit
   * write on this path is an unauthenticated, unbounded growth of `audit_log`:
   * 25 replays of one spent token measured 25 rows and 25 `warn` lines. Worse
   * than the disk, it drowns the operator's only alert channel, so a genuine
   * theft becomes indistinguishable from a flood. One row per family is the
   * whole signal — the second replay of an already-dead family did nothing and
   * is therefore not an event.
   */
  it("writes one row per family however many times a spent token is replayed", () => {
    const r1 = issueRefreshToken(db, subject);
    rotateRefreshToken(db, r1.token);

    for (let i = 0; i < 25; i += 1) {
      const outcome = rotateRefreshToken(db, r1.token, afterGrace());
      expect(outcome.status).toBe("reuse_detected");
    }

    expect(listAudit(db, { action: "session.reuse_detected" })).toHaveLength(1);
  });

  it("reports revoked: 0 for the replays that did nothing", () => {
    const r1 = issueRefreshToken(db, subject);
    rotateRefreshToken(db, r1.token);

    const first = rotateRefreshToken(db, r1.token, afterGrace());
    const second = rotateRefreshToken(db, r1.token, afterGrace());

    if (first.status !== "reuse_detected") return expect.unreachable();
    if (second.status !== "reuse_detected") return expect.unreachable();
    expect(first.revoked).toBe(1);
    // The handle the route uses to decide whether to log a `warn`.
    expect(second.revoked).toBe(0);
  });
});

describe("subjectForRefreshToken", () => {
  /**
   * Exists so the route can mint the access token before opening the rotation
   * transaction. It is a lookup, **not** an authorisation check: it answers for
   * a spent, revoked or expired row too, and only `rotateRefreshToken` decides
   * whether a token may be used.
   */
  it("names the subject for any row, and nothing for an unknown hash", () => {
    const issued = issueRefreshToken(db, subject);
    expect(subjectForRefreshToken(db, issued.token)).toBe(subject);

    endSession(db, issued.token);
    expect(subjectForRefreshToken(db, issued.token)).toBe(subject);

    expect(subjectForRefreshToken(db, "f".repeat(64))).toBeUndefined();
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

  it("floors at one rather than at zero, because Max-Age=0 DELETES the cookie", () => {
    /**
     * `Math.floor` on sub-second remaining life yields `0`, and `Max-Age=0` is
     * the exact instruction used to delete a cookie rather than to let it lapse.
     * `Math.max(1, …)`, matching what `checkLockout` already does to
     * `Retry-After`.
     */
    const nearlyOver = issueRefreshToken(db, subject, {
      expiresAt: new Date(Date.now() + 400).toISOString(),
    });
    expect(refreshCookieMaxAge(nearlyOver.row)).toBe(1);

    const past = issueRefreshToken(db, subject, {
      expiresAt: new Date(Date.now() - 60_000).toISOString(),
    });
    expect(refreshCookieMaxAge(past.row)).toBe(1);
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
