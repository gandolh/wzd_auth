import { createHash, randomBytes } from "node:crypto";
import type Database from "better-sqlite3";
import { prepareOnce } from "./prepared.js";

/**
 * The `refresh_tokens` table — one row per issued refresh token, grouped into
 * rotation families.
 *
 * A refresh token is **opaque and is a row**, which is what makes revoking it
 * mean something: revocation is this row's absence or its `revoked_at`, not an
 * entry on a denylist every app has to consult. Ward never stores the token
 * itself, only `sha256(token)`.
 *
 * The rotation protocol this table is shaped for (brief 03 implements it):
 *
 *  1. Login mints a token with a fresh `family_id` and inserts it.
 *  2. A refresh presents `R1`. `claimRefreshToken` stamps `used_at` **only if
 *     it was unset**, atomically, and returns the row. If it returns
 *     `undefined` while the row exists, `R1` was already spent — see step 4.
 *  3. On success, mint `R2` carrying `R1.family_id`, insert it, and mark `R1`
 *     revoked with reason `rotated`.
 *  4. On a replay, call `revokeFamily(db, family, "reuse_detected")`. Both the
 *     legitimate client and the thief hold descendants of the same root and
 *     there is no way to tell which is which, so the whole family dies and
 *     everyone re-authenticates. Revoking only the replayed token would leave
 *     the thief holding a live one.
 */

/** A `refresh_tokens` row exactly as SQLite returns it. */
export interface RefreshTokenRow {
  /** `sha256(token)` in hex. The lookup key. The token itself is never here. */
  token_hash: string;
  subject: string;
  /** Shared by every token descended from one login. */
  family_id: string;
  issued_at: string;
  expires_at: string;
  /** Non-null once spent in a rotation. A second presentation is the theft signal. */
  used_at: string | null;
  /** Non-null once killed, for any of the reasons below. */
  revoked_at: string | null;
  revoked_reason: RevokedReason | null;
}

/**
 * Why a token died. Constrained by a CHECK, and the distinction that matters is
 * `rotated` (the ordinary case, every refresh produces one) versus
 * `reuse_detected` (a replay burned the family down) — without it the console
 * cannot show an operator the one event they need to see.
 */
export type RevokedReason = "rotated" | "logout" | "reuse_detected" | "admin" | "expired";

export interface NewRefreshToken {
  /** From `hashRefreshToken(token)`. Never the token. */
  tokenHash: string;
  subject: string;
  /** `newFamilyId()` at login; the presented token's family on a rotation. */
  familyId: string;
  /** ISO-8601 UTC. */
  expiresAt: string;
}

/**
 * A new opaque refresh token: 256 bits from the OS CSPRNG, hex.
 *
 * The return value is the **only** time the plaintext exists on this side — it
 * goes straight into the response and is never written anywhere. Hash it with
 * `hashRefreshToken` before it touches the database.
 */
export function generateRefreshToken(): string {
  return randomBytes(32).toString("hex");
}

/**
 * `sha256(token)`, hex.
 *
 * **Unsalted, unstretched SHA-256 is the correct primitive here and not a
 * shortcut.** The input is 256 bits of `randomBytes`, so there is no dictionary
 * to attack and no low-entropy guess a slow KDF would be buying time against;
 * what hashing buys is that a leaked backup of `ward.db` is not a login as
 * every account with a live session. Passwords are the opposite case — low
 * entropy, guessable — and use scrypt.
 *
 * Deterministic on purpose: presentation looks the row up by this value, so a
 * per-row salt would mean scanning the table.
 */
export function hashRefreshToken(token: string): string {
  return createHash("sha256").update(token, "utf8").digest("hex");
}

/** A new rotation family. One per login; inherited by every rotation after. */
export function newFamilyId(): string {
  return randomBytes(16).toString("hex");
}

const stmts = prepareOnce((db: Database.Database) => ({
  insert: db.prepare<[string, string, string, string], RefreshTokenRow>(
    `INSERT INTO refresh_tokens (token_hash, subject, family_id, expires_at)
     VALUES (?, ?, ?, ?)
     RETURNING *`,
  ),

  byHash: db.prepare<[string], RefreshTokenRow>(
    `SELECT * FROM refresh_tokens WHERE token_hash = ?`,
  ),

  claim: db.prepare<[string, string, string], RefreshTokenRow>(
    `UPDATE refresh_tokens
        SET used_at = ?
      WHERE token_hash = ?
        AND used_at IS NULL
        AND revoked_at IS NULL
        AND expires_at > ?
      RETURNING *`,
  ),

  revokeOne: db.prepare<[string, string, string]>(
    `UPDATE refresh_tokens
        SET revoked_at = ?, revoked_reason = ?
      WHERE token_hash = ? AND revoked_at IS NULL`,
  ),

  revokeFamily: db.prepare<[string, string, string]>(
    `UPDATE refresh_tokens
        SET revoked_at = ?, revoked_reason = ?
      WHERE family_id = ? AND revoked_at IS NULL`,
  ),

  revokeSubject: db.prepare<[string, string, string]>(
    `UPDATE refresh_tokens
        SET revoked_at = ?, revoked_reason = ?
      WHERE subject = ? AND revoked_at IS NULL`,
  ),

  revokeSubjectExceptFamily: db.prepare<[string, string, string, string]>(
    `UPDATE refresh_tokens
        SET revoked_at = ?, revoked_reason = ?
      WHERE subject = ? AND family_id <> ? AND revoked_at IS NULL`,
  ),

  liveForSubject: db.prepare<[string, string], RefreshTokenRow>(
    `SELECT * FROM refresh_tokens
      WHERE subject = ? AND revoked_at IS NULL AND expires_at > ?
      ORDER BY issued_at DESC`,
  ),

  familyMembers: db.prepare<[string], RefreshTokenRow>(
    `SELECT * FROM refresh_tokens WHERE family_id = ? ORDER BY issued_at`,
  ),

  deleteExpired: db.prepare<[string]>(`DELETE FROM refresh_tokens WHERE expires_at <= ?`),
}));

/**
 * Store a freshly minted token's hash. Throws if the subject does not exist, or
 * (impossibly, at 256 bits) if the hash is already present.
 */
export function insertRefreshToken(db: Database.Database, input: NewRefreshToken): RefreshTokenRow {
  return stmts(db).insert.get(input.tokenHash, input.subject, input.familyId, input.expiresAt)!;
}

/**
 * The row for a presented token, whatever state it is in.
 *
 * Returns spent, revoked and expired rows too — that is the point. A refresh
 * that fails needs to know *why*, and specifically needs the `family_id` of a
 * replayed token so it can burn the family down.
 */
export function findRefreshToken(
  db: Database.Database,
  tokenHash: string,
): RefreshTokenRow | undefined {
  return stmts(db).byHash.get(tokenHash);
}

/**
 * Spend a token, atomically. Returns the row if this call was the one that
 * spent it, `undefined` otherwise.
 *
 * The single-use guarantee lives in this statement's `WHERE used_at IS NULL`,
 * not in the caller: two concurrent refreshes with the same token both run this
 * UPDATE, exactly one matches a row, and the loser gets `undefined`. Checking
 * `used_at` with a SELECT and then updating would leave a window between the
 * two where both requests see an unspent token, which is precisely the case
 * reuse detection exists to catch and would therefore misreport.
 *
 * `undefined` alone does not mean theft — the token may simply not exist, or be
 * revoked, or be expired. Follow up with `findRefreshToken`: a row whose
 * `used_at` is already set is the replay.
 */
export function claimRefreshToken(
  db: Database.Database,
  tokenHash: string,
  now: string = new Date().toISOString(),
): RefreshTokenRow | undefined {
  return stmts(db).claim.get(now, tokenHash, now);
}

/** Kill one token. Used for the ordinary `rotated` marking. */
export function revokeRefreshToken(
  db: Database.Database,
  tokenHash: string,
  reason: RevokedReason,
  now: string = new Date().toISOString(),
): boolean {
  return stmts(db).revokeOne.run(now, reason, tokenHash).changes === 1;
}

/**
 * Kill a whole rotation family in one indexed write, returning how many live
 * tokens it took.
 *
 * This is the reuse-detection response and the logout path both. Already-dead
 * rows are left alone so the reason that killed them first is preserved — a
 * token revoked as `rotated` an hour ago should not be relabelled
 * `reuse_detected` by the sweep that follows.
 */
export function revokeFamily(
  db: Database.Database,
  familyId: string,
  reason: RevokedReason,
  now: string = new Date().toISOString(),
): number {
  return stmts(db).revokeFamily.run(now, reason, familyId).changes;
}

/**
 * Kill every live token for an account — "sign out everywhere", and what a
 * disable or a password change should do alongside its own write.
 */
export function revokeAllForSubject(
  db: Database.Database,
  subject: string,
  reason: RevokedReason,
  now: string = new Date().toISOString(),
): number {
  return stmts(db).revokeSubject.run(now, reason, subject).changes;
}

/**
 * Kill every live token for an account **except** the one family named — "sign
 * out my other devices", and the only self-serve response available to someone
 * who suspects their session was stolen (`corpus/wiki/decisions.md`).
 *
 * The same single-statement shape as `revokeAllForSubject`, and that matters
 * rather than being tidy: rotation depends on this table's writes being atomic
 * against a concurrent `claimRefreshToken`. A read-then-loop version would open
 * a window in which a family the caller decided to spare has already rotated,
 * so the successor's hash is not in the list being revoked and the "other"
 * device survives the sweep it was the point of.
 *
 * `family_id <> ?` is spelled with SQL's inequality operator, not `!=`, and
 * NULL is not a concern: `family_id` is `NOT NULL` in the schema, so the
 * comparison is never unknown and no live row can escape the predicate by
 * being null.
 *
 * Returns how many **rows** it revoked. A family contributes exactly one live
 * row in normal operation — rotation revokes the predecessor as it issues the
 * successor — but a raced refresh can leave two live rows in one family inside
 * `REFRESH_RACE_GRACE_SECONDS`, so a caller reporting "how many other sessions
 * ended" to a person must count distinct families rather than trusting this
 * number to be one per device.
 */
export function revokeAllForSubjectExceptFamily(
  db: Database.Database,
  subject: string,
  familyId: string,
  reason: RevokedReason,
  now: string = new Date().toISOString(),
): number {
  return stmts(db).revokeSubjectExceptFamily.run(now, reason, subject, familyId).changes;
}

/** Live sessions for an account, newest first. The console's session list. */
export function listLiveTokensForSubject(
  db: Database.Database,
  subject: string,
  now: string = new Date().toISOString(),
): RefreshTokenRow[] {
  return stmts(db).liveForSubject.all(subject, now);
}

/** Every token in one family, oldest first — the rotation chain, for debugging. */
export function listFamily(db: Database.Database, familyId: string): RefreshTokenRow[] {
  return stmts(db).familyMembers.all(familyId);
}

/**
 * Delete rows past their expiry, returning how many went.
 *
 * A 30-day token that is never presented again is otherwise immortal, and this
 * table is the only one in the schema that grows with traffic rather than with
 * the number of people. Nothing calls this on a schedule yet; deployment
 * (brief 11) is where that belongs.
 */
export function deleteExpiredRefreshTokens(
  db: Database.Database,
  now: string = new Date().toISOString(),
): number {
  return stmts(db).deleteExpired.run(now).changes;
}
