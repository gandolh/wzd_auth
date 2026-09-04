import type Database from "better-sqlite3";
import { afterEach, beforeEach, describe, expect, it } from "vitest";

import { listAudit } from "../db/audit-log.js";
import { freshDb, seedUser } from "../db/test-support.js";
import { findUserBySubject } from "../db/users.js";
import {
  findVerificationToken,
  hashVerificationToken,
  insertVerificationToken,
  listVerificationTokens,
} from "../db/verification-tokens.js";
import {
  consumeEmailVerification,
  EMAIL_VERIFICATION_TTL_HOURS,
  EMAIL_VERIFICATION_TTL_SECONDS,
  issueEmailVerification,
} from "./verification.js";

/**
 * Issuing and spending an email-verification token, with no HTTP anywhere.
 *
 * `openDatabase(":memory:")` via `freshDb()`, never `getDb()` — this module
 * imports no config and these tests keep it that way.
 */

let db: Database.Database;
let subject: string;

beforeEach(() => {
  db = freshDb();
  subject = seedUser(db, "Alice").subject;
});

afterEach(() => {
  db.close();
});

describe("issueEmailVerification", () => {
  it("stores a hash, never the token, and expires it a day out", () => {
    const now = new Date("2026-09-04T10:00:00.000Z");
    const issued = issueEmailVerification(db, { subject, email: "alice@example.com", now });

    expect(EMAIL_VERIFICATION_TTL_HOURS).toBe(24);
    expect(EMAIL_VERIFICATION_TTL_SECONDS).toBe(86_400);
    expect(issued.row.expires_at).toBe("2026-09-05T10:00:00.000Z");
    expect(issued.row.purpose).toBe("email_verify");
    expect(issued.row.email).toBe("alice@example.com");
    expect(issued.row.consumed_at).toBeNull();

    // The plaintext is not in the row and is not recoverable from it.
    expect(issued.row.token_hash).not.toBe(issued.token);
    expect(issued.row.token_hash).toBe(hashVerificationToken(issued.token));
  });

  /**
   * Without the delete, every link ever mailed keeps working until its own
   * expiry — three links means three live credentials to the account sitting in
   * three mailboxes, and retiring one means nothing.
   */
  it("retires the previous outstanding token", () => {
    const first = issueEmailVerification(db, { subject, email: "alice@example.com" });
    const second = issueEmailVerification(db, { subject, email: "alice@example.com" });

    expect(listVerificationTokens(db, subject, "email_verify")).toHaveLength(1);
    expect(findVerificationToken(db, hashVerificationToken(first.token))).toBeUndefined();
    expect(consumeEmailVerification(db, first.token).status).toBe("invalid");
    expect(consumeEmailVerification(db, second.token).status).toBe("verified");
  });
});

describe("consumeEmailVerification", () => {
  it("marks the address verified and audits it, once", () => {
    const issued = issueEmailVerification(db, { subject, email: "alice@example.com" });

    const first = consumeEmailVerification(db, issued.token);
    expect(first).toEqual({
      status: "verified",
      subject,
      username: "Alice",
      email: "alice@example.com",
    });

    const user = findUserBySubject(db, subject)!;
    expect(user.email).toBe("alice@example.com");
    expect(user.email_verified).toBe(1);

    const audit = listAudit(db);
    expect(audit).toHaveLength(1);
    expect(audit[0]).toMatchObject({
      actor_kind: "account",
      actor_subject: subject,
      actor_label: "Alice",
      action: "user.email_verified",
      target_kind: "user",
      target_id: subject,
    });
    // The address is on the row this event describes; a second copy in an
    // append-only table that is never pruned buys nothing.
    expect(audit[0]!.detail).not.toContain("alice@example.com");

    // The acceptance criterion: replaying it fails.
    expect(consumeEmailVerification(db, issued.token).status).toBe("invalid");
    // And the replay audits nothing — this endpoint is fed by anonymous input.
    expect(listAudit(db)).toHaveLength(1);
  });

  it("answers `expired` for a link that aged out, and consumes nothing", () => {
    const issued = issueEmailVerification(db, {
      subject,
      email: "alice@example.com",
      now: new Date(Date.now() - (EMAIL_VERIFICATION_TTL_SECONDS + 60) * 1000),
    });

    expect(consumeEmailVerification(db, issued.token).status).toBe("expired");

    // Not spent: the row is untouched, so nothing has been silently burned.
    const row = findVerificationToken(db, hashVerificationToken(issued.token))!;
    expect(row.consumed_at).toBeNull();
    expect(findUserBySubject(db, subject)!.email_verified).toBe(0);
    expect(listAudit(db)).toHaveLength(0);
  });

  it("answers `invalid` for a token nobody ever issued", () => {
    expect(consumeEmailVerification(db, "0".repeat(64)).status).toBe("invalid");
    expect(consumeEmailVerification(db, "").status).toBe("invalid");
    expect(consumeEmailVerification(db, "not-hex").status).toBe("invalid");
    expect(listAudit(db)).toHaveLength(0);
  });

  /**
   * `password_reset` is a purpose this brief deliberately does not build. If a
   * later brief does, its tokens must not be spendable through the verification
   * path — so the purpose is asserted here rather than assumed from the fact
   * that nothing writes one today.
   */
  it("refuses a password_reset token", () => {
    const token = "f".repeat(64);
    insertVerificationToken(db, {
      subject,
      purpose: "password_reset",
      email: "alice@example.com",
      tokenHash: hashVerificationToken(token),
      expiresAt: new Date(Date.now() + 600_000).toISOString(),
    });

    expect(consumeEmailVerification(db, token).status).toBe("invalid");
    expect(findUserBySubject(db, subject)!.email_verified).toBe(0);
    // Still unspent — refusing it must not burn it either.
    expect(findVerificationToken(db, hashVerificationToken(token))!.consumed_at).toBeNull();
  });

  /**
   * The token carries the address that was proved, which for a change of
   * address is not the one on the account yet. That is why `markEmailVerified`
   * takes an address rather than reading one back off the row.
   */
  it("verifies the address the token was issued for, not the account's current one", () => {
    const withOld = seedUser(db, "Bob", "old@example.com").subject;
    const issued = issueEmailVerification(db, { subject: withOld, email: "new@example.com" });

    expect(consumeEmailVerification(db, issued.token).status).toBe("verified");
    const user = findUserBySubject(db, withOld)!;
    expect(user.email).toBe("new@example.com");
    expect(user.email_verified).toBe(1);
  });
});
