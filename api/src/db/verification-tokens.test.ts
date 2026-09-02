import { afterEach, beforeEach, describe, expect, it } from "vitest";
import type Database from "better-sqlite3";
import { freshDb, seedUser } from "./test-support.js";
import { findUserBySubject, markEmailVerified } from "./users.js";
import {
  consumeVerificationToken,
  deleteExpiredVerificationTokens,
  deleteVerificationTokens,
  findVerificationToken,
  generateVerificationToken,
  hashVerificationToken,
  insertVerificationToken,
  listVerificationTokens,
  type VerificationPurpose,
} from "./verification-tokens.js";

let db: Database.Database;
let subject: string;

beforeEach(() => {
  db = freshDb();
  subject = seedUser(db, "alice", "alice@example.test").subject;
});

afterEach(() => {
  db.close();
});

const inAnHour = () => new Date(Date.now() + 3_600_000).toISOString();
const yesterday = () => new Date(Date.now() - 86_400_000).toISOString();

function issue(
  purpose: VerificationPurpose = "email_verify",
  email = "alice@example.test",
  expiresAt = inAnHour(),
): { token: string; hash: string } {
  const token = generateVerificationToken();
  const hash = hashVerificationToken(token);
  insertVerificationToken(db, { subject, purpose, email, tokenHash: hash, expiresAt });
  return { token, hash };
}

describe("verification tokens", () => {
  it("store a hash, never the token that was mailed", () => {
    const { token, hash } = issue();

    const dump = JSON.stringify(db.prepare("SELECT * FROM verification_tokens").all());
    expect(dump).not.toContain(token);
    expect(dump).toContain(hash);
  });

  it("are single use — two clicks on the same link, one success", () => {
    const { hash } = issue();

    expect(consumeVerificationToken(db, hash)).toBeDefined();
    expect(consumeVerificationToken(db, hash)).toBeUndefined();
    expect(findVerificationToken(db, hash)?.consumed_at).not.toBeNull();
  });

  it("expire", () => {
    const { hash } = issue("email_verify", "alice@example.test", yesterday());

    expect(consumeVerificationToken(db, hash)).toBeUndefined();
    // The row is still readable, so a route can say "this link has expired"
    // rather than "this link was never real".
    expect(findVerificationToken(db, hash)).toBeDefined();
  });

  it("carry the address that was proved, which may not be the account's", () => {
    const { hash } = issue("email_verify", "new-address@example.test");

    const consumed = consumeVerificationToken(db, hash);
    expect(consumed?.email).toBe("new-address@example.test");

    markEmailVerified(db, consumed!.subject, consumed!.email);
    const user = findUserBySubject(db, subject);
    expect(user?.email).toBe("new-address@example.test");
    expect(user?.email_verified).toBe(1);
  });

  it("separate the two purposes", () => {
    issue("email_verify");
    issue("password_reset");
    issue("password_reset");

    expect(listVerificationTokens(db, subject, "password_reset")).toHaveLength(2);
    expect(deleteVerificationTokens(db, subject, "password_reset")).toBe(2);
    expect(listVerificationTokens(db, subject, "email_verify")).toHaveLength(1);
  });

  it("reject a purpose the schema does not know", () => {
    expect(() =>
      db
        .prepare(
          `INSERT INTO verification_tokens (id, subject, purpose, email, token_hash, expires_at)
           VALUES (?, ?, ?, ?, ?, ?)`,
        )
        .run("id-1", subject, "make-me-admin", "a@b.test", "hash", inAnHour()),
    ).toThrowError(/CHECK constraint failed/);
  });

  it("reject two rows sharing one token hash", () => {
    const { hash } = issue();

    expect(() =>
      db
        .prepare(
          `INSERT INTO verification_tokens (id, subject, purpose, email, token_hash, expires_at)
           VALUES (?, ?, ?, ?, ?, ?)`,
        )
        .run("id-2", subject, "email_verify", "a@b.test", hash, inAnHour()),
    ).toThrowError(/UNIQUE constraint failed: verification_tokens\.token_hash/);
  });

  it("belong to a real account, and go when it does", () => {
    issue();

    expect(() =>
      insertVerificationToken(db, {
        subject: "nobody",
        purpose: "email_verify",
        email: "a@b.test",
        tokenHash: hashVerificationToken(generateVerificationToken()),
        expiresAt: inAnHour(),
      }),
    ).toThrowError(/FOREIGN KEY constraint failed/);

    db.prepare("DELETE FROM users WHERE subject = ?").run(subject);
    expect(db.prepare<[], number>("SELECT count(*) FROM verification_tokens").pluck().get()).toBe(
      0,
    );
  });

  it("sweep away expired rows", () => {
    issue();
    issue("password_reset", "alice@example.test", yesterday());

    expect(deleteExpiredVerificationTokens(db)).toBe(1);
    expect(db.prepare<[], number>("SELECT count(*) FROM verification_tokens").pluck().get()).toBe(
      1,
    );
  });
});
