import { randomBytes, timingSafeEqual } from "node:crypto";
import type Database from "better-sqlite3";

import { recordAudit } from "../db/audit-log.js";
import { findUserBySubject, markEmailVerified } from "../db/users.js";
import {
  consumeVerificationToken,
  deleteVerificationTokens,
  findVerificationToken,
  generateVerificationToken,
  hashVerificationToken,
  insertVerificationToken,
  type VerificationTokenRow,
} from "../db/verification-tokens.js";

/**
 * Email verification: minting a token, and spending it exactly once.
 *
 * The policy layer between `db/verification-tokens.ts` (statements, no rules)
 * and `routes/register.ts` (HTTP). Split out for the same reason
 * `auth/refresh.ts` is: the rules about lifetime, single use and what a spent
 * token *does* are worth reading without a Fastify handler around them, and a
 * later resend endpoint or a change-of-address flow will want them without
 * copying them.
 *
 * **Fastify-free on purpose.** Nothing here imports the framework, `config.ts`
 * or the mail sender. It takes a `db` and returns a value; the caller decides
 * what to send and what to say.
 *
 * ## Only `email_verify`. Password reset is deliberately not built.
 *
 * `verification_tokens.purpose` already has a `password_reset` member and this
 * module never writes it. Owner-issued accounts have no address and therefore
 * no recovery channel *by decision*
 * ([decisions-accounts.md](../../../corpus/wiki/decisions-accounts.md)), so
 * reset is only meaningful for the verified-email population and is a separate,
 * later question. Every function below asserts the purpose it expects, so a
 * `password_reset` token can never be spent through the verification path if
 * somebody builds the other half later.
 */

/**
 * How long a verification link lives. Twenty-four hours.
 *
 * The trade is entirely about the ordinary case rather than the attack: the
 * token is 256 bits of CSPRNG output, so its lifetime does not meaningfully
 * change an attacker's odds — twenty-four hours and twenty-four minutes are
 * both "never". What the window has to survive is a person who signs up on a
 * phone at midnight and opens their mail on a laptop the next morning. Shorter
 * windows are for tokens that are *equivalent to a login* (a password reset,
 * which is why prm gives that one minutes); confirming an address is not.
 */
export const EMAIL_VERIFICATION_TTL_HOURS = 24;
export const EMAIL_VERIFICATION_TTL_SECONDS = EMAIL_VERIFICATION_TTL_HOURS * 60 * 60;

/** A freshly minted token and the row that will recognise it. */
export interface IssuedVerification {
  /**
   * The plaintext token, which exists **only** long enough to be rendered into
   * a link. It is not in the row, it is not recoverable from the row, and
   * nothing should log it.
   */
  token: string;
  row: VerificationTokenRow;
}

/**
 * Mint a verification token for `email` on `subject`, retiring any earlier
 * outstanding one.
 *
 * **The delete is not tidiness.** Without it every link ever mailed keeps
 * working until its own expiry, so a person who asks for three links has three
 * live credentials to their account sitting in three mailboxes, and revoking
 * one means nothing. `db/verification-tokens.ts` makes the same point about
 * reset links; it applies identically here.
 *
 * `email` is the address being *proved*, which for a change-of-address flow is
 * not yet `users.email` — that is the whole reason the column exists on the
 * token row rather than being read back off the account when the token is
 * spent.
 *
 * Runs as one transaction so a crash between the delete and the insert cannot
 * leave an account with no outstanding link and no record that one was asked
 * for. Safe to call inside a caller's transaction: better-sqlite3 nests these
 * as savepoints.
 */
export function issueEmailVerification(
  db: Database.Database,
  params: { subject: string; email: string; now?: Date },
): IssuedVerification {
  const now = params.now ?? new Date();
  const expiresAt = new Date(now.getTime() + EMAIL_VERIFICATION_TTL_SECONDS * 1000).toISOString();
  const token = generateVerificationToken();

  const row = db.transaction((): VerificationTokenRow => {
    deleteVerificationTokens(db, params.subject, "email_verify");
    return insertVerificationToken(db, {
      subject: params.subject,
      purpose: "email_verify",
      email: params.email,
      tokenHash: hashVerificationToken(token),
      expiresAt,
    });
  })();

  return { token, row };
}

/**
 * What happened when a presented token was spent.
 *
 * `expired` is separated from `invalid` and the rest are not, which is a
 * deliberate line rather than an oversight — see `consumeEmailVerification`.
 */
export type VerificationOutcome =
  | { status: "verified"; subject: string; username: string; email: string }
  | { status: "expired" }
  | { status: "invalid" };

/**
 * A stored hash to compare against when there is no row, so that the
 * comparison below runs on every call.
 *
 * The same idea as `DUMMY_STORED_HASH` in `auth/password.ts`: a branch that
 * returns before doing the work turns an endpoint into an oracle. Random per
 * process, and it can never match a real token because no token hashes to it.
 */
const ABSENT_TOKEN_HASH = randomBytes(32).toString("hex");

/**
 * Spend a presented token: mark the address verified and consume the token,
 * atomically, once.
 *
 * ## Where the constant-time comparison actually matters
 *
 * The row is found by `token_hash`, so the indexed lookup SQLite performs is on
 * the **hash** and not on the token. That is the real defence and it is the
 * reason the table stores a hash at all: a timing signal that leaks a prefix of
 * `sha256(token)` is useless to an attacker who has to submit the preimage.
 *
 * The `timingSafeEqual` below is the second layer, and it is there for the
 * property that survives refactoring: it is the only comparison in this file,
 * it runs on every call including the no-such-token call, and it means nobody
 * can later "simplify" this into a `row.token_hash === presentedHash` and
 * reintroduce the leak. Both operands are fixed-length hex from the same
 * function, so the length check can never fail for a genuine token — it is
 * present because `timingSafeEqual` throws on a length mismatch and a thrown
 * error is itself a timing signal.
 *
 * ## Single use is the database's guarantee, not this function's
 *
 * `consumeVerificationToken` is one `UPDATE ... WHERE consumed_at IS NULL AND
 * expires_at > ? RETURNING *`. Two clicks on the same emailed link cannot both
 * come back with a row, whatever this code does around it, and with one
 * synchronous connection they cannot even interleave. The classification pass
 * before it exists only to tell an expired link from an unknown one for the
 * caller's benefit; it is not the check that enforces anything.
 *
 * ## Why `expired` is told apart and "already used" is not
 *
 * Reaching either answer requires holding a genuine 256-bit token, so neither
 * is an enumeration oracle in the way `/login`'s "no such user" would be. The
 * difference is what the person on the other end can do about it. "Your link
 * has expired" is actionable — ask for another. "This link was already used"
 * is not actionable, is indistinguishable to them from "this link is nonsense",
 * and confirms to anyone who found a token in a mail archive that it was real
 * and worked. So the used, unknown and wrong-purpose cases collapse into one
 * answer and the expired one stands alone.
 *
 * The audit row is written **inside** the transaction, per
 * `db/audit-log.ts`: a verification that commits without its record leaves the
 * log quietly disagreeing with the data. Nothing is audited for a token that
 * did not verify anything — same reasoning as `session.login_failed` only being
 * written for accounts that exist, since this endpoint is anonymous input and
 * an audit row per bad guess is a write amplifier.
 */
export function consumeEmailVerification(
  db: Database.Database,
  presented: string,
  now: Date = new Date(),
): VerificationOutcome {
  const presentedHash = hashVerificationToken(presented);
  const row = findVerificationToken(db, presentedHash);

  if (!hashesMatch(presentedHash, row?.token_hash ?? ABSENT_TOKEN_HASH)) {
    return { status: "invalid" };
  }
  // `hashesMatch` returning true implies a row was found, but the compiler
  // cannot see that through the `??`, and asserting it would let a future edit
  // that changes the fallback type-check.
  if (row === undefined) return { status: "invalid" };

  // A `password_reset` token must never be spendable here, however it was
  // obtained. Collapsed into `invalid` because the caller has no use for the
  // distinction and the wire must not describe Ward's token purposes.
  if (row.purpose !== "email_verify") return { status: "invalid" };
  if (row.consumed_at !== null) return { status: "invalid" };

  const nowIso = now.toISOString();
  if (row.expires_at <= nowIso) return { status: "expired" };

  /**
   * Thrown to roll the transaction back when the account behind a live token
   * has gone. `verification_tokens.subject` is a foreign key with
   * `ON DELETE CASCADE`, so deleting the account takes its tokens with it and
   * this is unreachable in practice — but "unreachable" is a claim about today's
   * schema, and burning the token while verifying nothing is the one outcome
   * that has no recovery path. Rolling back keeps the link usable.
   */
  class AccountVanished extends Error {}

  try {
    return db.transaction((): VerificationOutcome => {
      const consumed = consumeVerificationToken(db, presentedHash, nowIso);
      // Lost a race, or the expiry passed between the classification above and
      // this statement. The UPDATE is the authority; this branch is why.
      if (consumed === undefined) return { status: "invalid" };

      const user = findUserBySubject(db, consumed.subject);
      if (user === undefined) throw new AccountVanished();

      if (!markEmailVerified(db, consumed.subject, consumed.email)) {
        throw new AccountVanished();
      }

      recordAudit(db, {
        actorKind: "account",
        actorSubject: user.subject,
        actorLabel: user.username,
        action: "user.email_verified",
        targetKind: "user",
        targetId: user.subject,
        // The address is already on the row this event describes; repeating it
        // here would put a second copy of somebody's email in a table that is
        // append-only and never pruned.
        detail: { purpose: "email_verify" },
      });

      return {
        status: "verified",
        subject: user.subject,
        username: user.username,
        email: consumed.email,
      };
    })();
  } catch (error) {
    if (error instanceof AccountVanished) return { status: "invalid" };
    throw error;
  }
}

/**
 * `timingSafeEqual` over two hex hashes, with the length guard that keeps it
 * from throwing. See the note in `consumeEmailVerification`.
 */
function hashesMatch(a: string, b: string): boolean {
  const left = Buffer.from(a, "hex");
  const right = Buffer.from(b, "hex");
  if (left.length === 0 || left.length !== right.length) return false;
  return timingSafeEqual(left, right);
}
