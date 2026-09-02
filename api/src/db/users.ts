import { randomBytes } from "node:crypto";
import type Database from "better-sqlite3";
import { prepareOnce } from "./prepared.js";

/**
 * The `users` table — one row per account.
 *
 * Thin by design: prepared statements and row shapes, no policy. Whether a
 * password is strong enough, whether an address needs verifying and who is
 * allowed to disable whom are all decisions for the routes above this layer.
 *
 * **No row here is ever the superuser.** `WARD_ADMIN_USERNAME` is a break-glass
 * credential that lives only in the environment and deliberately has no
 * account, no subject and no grants — see the header of
 * `./migrations/20260902000000-baseline.ts` and `corpus/wiki/decisions-admin.md`
 * before adding anything that seeds one.
 */

/** A `users` row exactly as SQLite returns it. Column names, not camelCase. */
export interface UserRow {
  /** Opaque, stable forever, never recycled. The contract with every app. */
  subject: string;
  /** As the person typed it. Display uses this; nothing keys on it. */
  username: string;
  /** `foldUsername(username)`. Carries the uniqueness constraint. */
  username_folded: string;
  /** scrypt, per `corpus/wiki/decisions-implementation.md`. Opaque here. */
  password_hash: string;
  /** Null for owner-issued accounts; those have no recovery channel by design. */
  email: string | null;
  /** SQLite has no boolean. 0 or 1, enforced by a CHECK. */
  email_verified: 0 | 1;
  created_at: string;
  updated_at: string;
  /** Non-null means the account is disabled, and says when it happened. */
  disabled_at: string | null;
}

/** What `createUser` needs. `subject` is generated unless one is supplied. */
export interface NewUser {
  username: string;
  passwordHash: string;
  email?: string | null;
  /**
   * Only for a caller that must control the value — a fixture, or a cutover
   * script re-creating a known account. Ordinary registration omits it and
   * takes `generateSubject()`.
   */
  subject?: string;
}

/**
 * 128 bits from the OS CSPRNG, hex-encoded. **Not a counter, and not a hash of
 * anything about the account.**
 *
 * The subject is the identifier six apps store to mean "this person", and their
 * rows outlive everything else about the account. Two consequences follow, and
 * both are why this is `randomBytes` rather than an autoincrement:
 *
 *  - **It must never be recycled.** A sequential id reissued after a delete
 *    silently hands one person's reading history, notes and favourites to
 *    another, in six databases at once, with nothing anywhere able to detect
 *    it. At 128 bits, a repeat is not a case to handle; `users.subject` is
 *    additionally the PRIMARY KEY, so a broken generator fails the insert
 *    loudly rather than colliding quietly.
 *  - **It must be opaque.** A counter leaks how many accounts exist and lets
 *    anyone holding one subject guess a neighbouring valid one.
 *
 * 16 bytes rather than 32 because 128 bits is already past any birthday bound
 * this estate could reach, and a 32-character subject stays readable in a URL,
 * a log line and a `sub` claim.
 */
export function generateSubject(): string {
  return randomBytes(16).toString("hex");
}

/**
 * The case- and form-insensitive key a username is unique on.
 *
 * NFKC first, then lower case. JavaScript's `toLowerCase()` rather than
 * SQLite's `lower()` or a `COLLATE NOCASE` index because both of those fold
 * only ASCII A–Z: with either one, `Alice` and `alice` collide correctly but
 * `Ä` and `ä` register as two accounts. NFKC additionally collapses the
 * compatibility forms — a full-width `ａlice` folds onto `alice` — which is the
 * cheap half of not letting two accounts look identical in a console listing.
 *
 * This is the only fold in Ward. Anything that writes `users` directly must
 * call it; `username_folded` is NOT NULL precisely so that forgetting fails at
 * the insert instead of quietly switching the uniqueness constraint off.
 */
export function foldUsername(username: string): string {
  return username.normalize("NFKC").toLowerCase();
}

const stmts = prepareOnce((db: Database.Database) => ({
  insert: db.prepare<
    [string, string, string, string, string | null, number],
    UserRow
  >(`INSERT INTO users (subject, username, username_folded, password_hash, email, email_verified)
     VALUES (?, ?, ?, ?, ?, ?)
     RETURNING *`),

  bySubject: db.prepare<[string], UserRow>(`SELECT * FROM users WHERE subject = ?`),

  byFolded: db.prepare<[string], UserRow>(`SELECT * FROM users WHERE username_folded = ?`),

  byEmail: db.prepare<[string], UserRow>(
    `SELECT * FROM users WHERE email = ? ORDER BY created_at, subject`,
  ),

  setPasswordHash: db.prepare<[string, string]>(
    `UPDATE users
        SET password_hash = ?, updated_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now')
      WHERE subject = ?`,
  ),

  setUsername: db.prepare<[string, string, string], UserRow>(
    `UPDATE users
        SET username = ?, username_folded = ?,
            updated_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now')
      WHERE subject = ?
      RETURNING *`,
  ),

  setEmail: db.prepare<[string | null, string]>(
    `UPDATE users
        SET email = ?, email_verified = 0,
            updated_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now')
      WHERE subject = ?`,
  ),

  markEmailVerified: db.prepare<[string, string]>(
    `UPDATE users
        SET email = ?, email_verified = 1,
            updated_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now')
      WHERE subject = ?`,
  ),

  setDisabledAt: db.prepare<[string | null, string]>(
    `UPDATE users
        SET disabled_at = ?, updated_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now')
      WHERE subject = ?`,
  ),

  delete: db.prepare<[string]>(`DELETE FROM users WHERE subject = ?`),

  list: db.prepare<[number, number], UserRow>(
    `SELECT * FROM users ORDER BY username_folded LIMIT ? OFFSET ?`,
  ),

  count: db.prepare<[], number>(`SELECT count(*) FROM users`),
}));

/**
 * Insert an account and return the stored row.
 *
 * Throws `SqliteError: UNIQUE constraint failed: users.username_folded` if the
 * username is taken in any casing. Callers translate that into a 409 rather
 * than checking first — a SELECT-then-INSERT has a race between the two
 * statements, and the constraint does not.
 */
export function createUser(db: Database.Database, input: NewUser): UserRow {
  const subject = input.subject ?? generateSubject();
  const email = input.email ?? null;

  return stmts(db).insert.get(
    subject,
    input.username,
    foldUsername(input.username),
    input.passwordHash,
    email,
    0,
  )!;
}

/** The account a `sub` claim or a grant row points at. */
export function findUserBySubject(db: Database.Database, subject: string): UserRow | undefined {
  return stmts(db).bySubject.get(subject);
}

/** Login's lookup. Folds first, so any casing of a registered name resolves. */
export function findUserByUsername(db: Database.Database, username: string): UserRow | undefined {
  return stmts(db).byFolded.get(foldUsername(username));
}

/**
 * Every account carrying this address — an array because **email is not
 * unique** in this schema. Username is the canonical identifier and email is an
 * optional attribute, so nothing has ever forbidden two accounts sharing one.
 *
 * A password-reset flow therefore has to decide what to do with more than one
 * hit; that policy is brief 07's, not this layer's.
 */
export function findUsersByEmail(db: Database.Database, email: string): UserRow[] {
  return stmts(db).byEmail.all(email);
}

/** False if no such subject. */
export function setPasswordHash(
  db: Database.Database,
  subject: string,
  passwordHash: string,
): boolean {
  return stmts(db).setPasswordHash.run(passwordHash, subject).changes === 1;
}

/**
 * Rename an account. **The subject does not change**, which is the entire point
 * of having one: every app's rows stay attached across a rename.
 *
 * Throws on a collision, exactly like `createUser`.
 */
export function setUsername(
  db: Database.Database,
  subject: string,
  username: string,
): UserRow | undefined {
  return stmts(db).setUsername.get(username, foldUsername(username), subject);
}

/**
 * Set or clear the address. **Always resets `email_verified` to 0** — a new
 * address has not been proved, and carrying the old flag forward would let a
 * change of address inherit the previous one's trust.
 */
export function setEmail(db: Database.Database, subject: string, email: string | null): boolean {
  return stmts(db).setEmail.run(email, subject).changes === 1;
}

/**
 * Consume a verified address: store it and flag it in one statement.
 *
 * Takes the address rather than reading it back from the row because the token
 * carries the address that was actually proved
 * (`verification_tokens.email`) — which for a change-of-address flow is not yet
 * the one on the account.
 */
export function markEmailVerified(db: Database.Database, subject: string, email: string): boolean {
  return stmts(db).markEmailVerified.run(email, subject).changes === 1;
}

/**
 * Disable or re-enable an account. Disabling stamps the time; re-enabling
 * clears it.
 *
 * A disabled account keeps its grants and its subject — this is a door being
 * locked, not an identity being destroyed, so re-enabling restores exactly what
 * was there. It does **not** revoke live sessions; that is a separate write
 * against `refresh_tokens`, and any route that disables an account should do
 * both.
 */
export function setDisabled(db: Database.Database, subject: string, disabled: boolean): boolean {
  const at = disabled ? new Date().toISOString() : null;
  return stmts(db).setDisabledAt.run(at, subject).changes === 1;
}

/**
 * Delete an account outright.
 *
 * Cascades to `grants`, `refresh_tokens` and `verification_tokens` — the
 * `REFERENCES ... ON DELETE CASCADE` clauses fire only because
 * `openDatabase` sets `foreign_keys = ON` per connection. It does **not**
 * cascade to `audit_log`, which carries no foreign keys so that the record of
 * the deletion outlives the thing deleted.
 *
 * Prefer `setDisabled` for anything reversible. Deleting frees the username for
 * re-registration but never the subject, which is retired permanently.
 */
export function deleteUser(db: Database.Database, subject: string): boolean {
  return stmts(db).delete.run(subject).changes === 1;
}

/** The console's account list, ordered the way a human scans it. */
export function listUsers(db: Database.Database, limit = 100, offset = 0): UserRow[] {
  return stmts(db).list.all(limit, offset);
}

export function countUsers(db: Database.Database): number {
  return stmts(db).count.pluck().get()!;
}
