import { createHash, randomBytes } from "node:crypto";
import type Database from "better-sqlite3";
import { prepareOnce } from "./prepared.js";

/**
 * The `verification_tokens` table — single-use, expiring tokens mailed to an
 * address, for the public registration and recovery paths (brief 07).
 *
 * Shape cribbed from `public-resource-map`'s `verification_token` /
 * `reset_token` pair, which already ships this flow, with two deliberate
 * departures recorded in the migration: the token is **hashed**, and the two
 * near-identical tables are collapsed into one with a `purpose`.
 *
 * Only the public path uses this. Accounts the owner issues have no address and
 * therefore no recovery channel — an accepted gap, not an oversight.
 */

export type VerificationPurpose = "email_verify" | "password_reset";

/** A `verification_tokens` row exactly as SQLite returns it. */
export interface VerificationTokenRow {
  id: string;
  subject: string;
  purpose: VerificationPurpose;
  /**
   * The address this token was actually sent to — which for a change-of-address
   * flow is not yet `users.email`. That is what makes the new address
   * verifiable before it replaces the old one.
   */
  email: string;
  token_hash: string;
  expires_at: string;
  /** Non-null once spent. Single use. */
  consumed_at: string | null;
  created_at: string;
}

export interface NewVerificationToken {
  subject: string;
  purpose: VerificationPurpose;
  email: string;
  /** From `hashVerificationToken(token)`. Never the token. */
  tokenHash: string;
  /** ISO-8601 UTC. Hours for a verification, minutes for a reset. */
  expiresAt: string;
}

/**
 * A new opaque token: 256 bits from the OS CSPRNG, hex.
 *
 * This goes in a link in an email, so it is URL-safe as-is. The plaintext
 * exists only long enough to be rendered into that link.
 */
export function generateVerificationToken(): string {
  return randomBytes(32).toString("hex");
}

/**
 * `sha256(token)`, hex — the same reasoning as `refresh-tokens.ts`.
 *
 * A `password_reset` token *is* a login for anyone holding it, so there is no
 * argument for Ward's copy being the weaker one. prm keeps the raw token in the
 * row; this does not.
 */
export function hashVerificationToken(token: string): string {
  return createHash("sha256").update(token, "utf8").digest("hex");
}

const stmts = prepareOnce((db: Database.Database) => ({
  insert: db.prepare<
    [string, string, string, string, string, string],
    VerificationTokenRow
  >(`INSERT INTO verification_tokens (id, subject, purpose, email, token_hash, expires_at)
     VALUES (?, ?, ?, ?, ?, ?)
     RETURNING *`),

  byHash: db.prepare<[string], VerificationTokenRow>(
    `SELECT * FROM verification_tokens WHERE token_hash = ?`,
  ),

  consume: db.prepare<[string, string, string], VerificationTokenRow>(
    `UPDATE verification_tokens
        SET consumed_at = ?
      WHERE token_hash = ?
        AND consumed_at IS NULL
        AND expires_at > ?
      RETURNING *`,
  ),

  forSubject: db.prepare<[string, string], VerificationTokenRow>(
    `SELECT * FROM verification_tokens
      WHERE subject = ? AND purpose = ?
      ORDER BY created_at DESC`,
  ),

  deleteForSubject: db.prepare<[string, string]>(
    `DELETE FROM verification_tokens WHERE subject = ? AND purpose = ?`,
  ),

  deleteExpired: db.prepare<[string]>(`DELETE FROM verification_tokens WHERE expires_at <= ?`),
}));

/** Store a freshly minted token's hash. Throws if the subject does not exist. */
export function insertVerificationToken(
  db: Database.Database,
  input: NewVerificationToken,
): VerificationTokenRow {
  return stmts(db).insert.get(
    randomBytes(16).toString("hex"),
    input.subject,
    input.purpose,
    input.email,
    input.tokenHash,
    input.expiresAt,
  )!;
}

/**
 * The row for a presented token, whatever state it is in — including spent and
 * expired, so a route can tell "this link is old" from "this link was never
 * real" without a second query.
 */
export function findVerificationToken(
  db: Database.Database,
  tokenHash: string,
): VerificationTokenRow | undefined {
  return stmts(db).byHash.get(tokenHash);
}

/**
 * Spend a token, atomically. Returns the row if this call was the one that
 * spent it, `undefined` if it was already consumed, expired or unknown.
 *
 * Same single-statement guarantee as `claimRefreshToken`: the `consumed_at IS
 * NULL` lives in the UPDATE, so two clicks on the same emailed link cannot both
 * succeed. The caller then acts on the returned row — `markEmailVerified(db,
 * row.subject, row.email)` for an `email_verify`, a password write for a
 * `password_reset` — and should do so in the same transaction, so a crash
 * between the two does not burn the token without applying its effect.
 */
export function consumeVerificationToken(
  db: Database.Database,
  tokenHash: string,
  now: string = new Date().toISOString(),
): VerificationTokenRow | undefined {
  return stmts(db).consume.get(now, tokenHash, now);
}

/**
 * Every token of one purpose for one account, newest first — how a route
 * answers "have they already asked for this in the last minute", which is the
 * cheap half of not turning the mail sender into an amplifier.
 */
export function listVerificationTokens(
  db: Database.Database,
  subject: string,
  purpose: VerificationPurpose,
): VerificationTokenRow[] {
  return stmts(db).forSubject.all(subject, purpose);
}

/**
 * Invalidate every outstanding token of one purpose, returning how many went.
 *
 * Issuing a new reset link should retire the previous ones; leaving them live
 * means every link ever mailed keeps working until it expires.
 */
export function deleteVerificationTokens(
  db: Database.Database,
  subject: string,
  purpose: VerificationPurpose,
): number {
  return stmts(db).deleteForSubject.run(subject, purpose).changes;
}

/** Delete rows past their expiry, returning how many went. Same sweep note as refresh tokens. */
export function deleteExpiredVerificationTokens(
  db: Database.Database,
  now: string = new Date().toISOString(),
): number {
  return stmts(db).deleteExpired.run(now).changes;
}
