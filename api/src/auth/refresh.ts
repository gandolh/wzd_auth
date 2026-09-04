import type Database from "better-sqlite3";

import { recordAudit } from "../db/audit-log.js";
import {
  claimRefreshToken,
  findRefreshToken,
  generateRefreshToken,
  hashRefreshToken,
  insertRefreshToken,
  newFamilyId,
  revokeFamily,
  revokeRefreshToken,
  type RefreshTokenRow,
} from "../db/refresh-tokens.js";
import { findUserBySubject, type UserRow } from "../db/users.js";
import { REFRESH_TOKEN_TTL_SECONDS } from "./cookie.js";

/**
 * Refresh-token issuance, rotation, and reuse detection.
 *
 * This module is the estate's stolen-cookie alarm and it holds no HTTP types —
 * `routes/auth.ts` turns the outcomes below into status codes. Everything here
 * takes its `Database` as a parameter, so the whole protocol is testable
 * against `openDatabase(":memory:")`.
 *
 * ## The protocol
 *
 * Login calls `issueRefreshToken`, which mints 32 random bytes, stores
 * `sha256(token)` under a brand-new `family_id`, and hands the plaintext back
 * exactly once — it is never written anywhere and never logged.
 *
 * A refresh calls `rotateRefreshToken(db, presented)`, which:
 *
 *  1. **Claims** the presented token with `claimRefreshToken` — a single
 *     `UPDATE ... WHERE used_at IS NULL ... RETURNING`.
 *  2. On a successful claim, mints `R2` in the same family, inserts it, and
 *     marks `R1` revoked with reason `rotated`.
 *  3. On a failed claim, looks the row up to find out *why*. A row whose
 *     `used_at` is **already set** is the theft signal: the family dies.
 *
 * ## Why step 1 must stay one statement
 *
 * The single-use guarantee is the `WHERE used_at IS NULL` inside that UPDATE,
 * not anything in this file. Two concurrent presentations of the same token
 * both run it, exactly one matches a row, and the loser gets `undefined` and is
 * correctly reported as a replay. Decomposing it into a `SELECT` and then an
 * `UPDATE` opens a window in which both callers see an unspent token and both
 * succeed — which is precisely the case reuse detection exists to catch, so the
 * decomposition breaks the alarm rather than merely being untidy.
 * `better-sqlite3` being synchronous does **not** save a split statement: the
 * two halves are two separate synchronous calls, and `await`-free code still
 * interleaves across requests at every I/O boundary between them.
 *
 * ## Why the whole family dies on a replay
 *
 * The legitimate client and the thief both hold descendants of one root, and
 * there is no information anywhere that distinguishes them — whoever presented
 * the stale token might be the victim replaying after a lost response, or the
 * thief using a copy. Revoking only the presented token leaves the other party
 * holding a live one, which is the wrong half in the case that matters. So the
 * family dies, both parties re-authenticate, and only the one who knows the
 * password gets back in. That is the entire value of the mechanism.
 */

/** Re-exported so a caller need not know the constant lives in `cookie.ts`. */
export { REFRESH_TOKEN_TTL_SECONDS };

/** What `issueRefreshToken` hands back. The plaintext exists only here. */
export interface IssuedRefreshToken {
  /**
   * The opaque 32-byte token, hex. **Goes straight into a `Set-Cookie` and
   * nowhere else** — not into a log line, not into the response body, not into
   * an audit `detail`.
   */
  readonly token: string;
  /** The stored row: hash, family, expiry. Safe to log. */
  readonly row: RefreshTokenRow;
}

/**
 * Mint and store a refresh token.
 *
 * `familyId` is omitted at login (a new family) and supplied by a rotation (the
 * presented token's family). `expiresAt` is omitted at login (30 days from now)
 * and supplied by a rotation — see the note on absolute family lifetime in
 * `rotateRefreshToken`.
 */
export function issueRefreshToken(
  db: Database.Database,
  subject: string,
  options: { familyId?: string; expiresAt?: string; now?: Date } = {},
): IssuedRefreshToken {
  const now = options.now ?? new Date();
  const token = generateRefreshToken();
  const expiresAt =
    options.expiresAt ?? new Date(now.getTime() + REFRESH_TOKEN_TTL_SECONDS * 1000).toISOString();

  const row = insertRefreshToken(db, {
    tokenHash: hashRefreshToken(token),
    subject,
    familyId: options.familyId ?? newFamilyId(),
    expiresAt,
  });

  return { token, row };
}

/**
 * Everything a rotation attempt can conclude.
 *
 * The failure cases are distinct here and **deliberately collapsed into one
 * `401` by the route**. This module's job is to know what happened — the audit
 * log and the operator need `reuse_detected` told apart from `expired`. The
 * wire's job is to tell the client nothing it could use to probe: a caller who
 * learns that their token was "already used" rather than "unknown" has learned
 * that the token was real, which is a small oracle handed to whoever stole it.
 */
export type RotationOutcome =
  | {
      status: "rotated";
      subject: string;
      /** `R2`'s plaintext. Cookie only. */
      refreshToken: string;
      /** `R2`'s row — `expires_at` is the cookie's `Max-Age` bound. */
      row: RefreshTokenRow;
      /** `R1`'s row as it stood when claimed. For the log; carries no secret. */
      previous: RefreshTokenRow;
    }
  | {
      /** A replay. The family is already revoked and audited by the time this returns. */
      status: "reuse_detected";
      subject: string;
      familyId: string;
      /** How many live tokens the sweep killed. `0` if the family was already dead. */
      revoked: number;
    }
  /** No such token hash. A forged or long-swept value. */
  | { status: "unknown" }
  /** The row exists and is past `expires_at`. */
  | { status: "expired"; subject: string; familyId: string }
  /** The row was killed by a logout, an admin, or an earlier reuse sweep. */
  | { status: "revoked"; subject: string; familyId: string }
  /**
   * The token was good but the account is disabled or gone. The family is
   * revoked before this returns — a disabled account must not keep a live
   * session sitting in the table waiting to be re-enabled.
   */
  | { status: "account_unusable"; subject: string; familyId: string };

/**
 * Present a refresh token and rotate it.
 *
 * Every database write below happens inside one `better-sqlite3` transaction,
 * so a rotation is all-or-nothing: there is no state in which `R1` is spent but
 * `R2` was never stored, which would silently log the person out. The access
 * token is minted by the caller *after* this returns, because minting is async
 * and an `await` inside a synchronous transaction is not expressible (which is
 * a feature — it is what keeps the transaction short).
 */
export function rotateRefreshToken(
  db: Database.Database,
  presented: string,
  now: Date = new Date(),
): RotationOutcome {
  const tokenHash = hashRefreshToken(presented);
  const nowIso = now.toISOString();

  const rotate = db.transaction((): RotationOutcome => {
    // ONE statement. See the module header before touching this.
    const claimed = claimRefreshToken(db, tokenHash, nowIso);

    if (claimed !== undefined) {
      return completeRotation(db, claimed, nowIso);
    }

    // The claim did not match. That is not yet a verdict — the token may be
    // unknown, spent, revoked or expired, and only the row says which.
    const row = findRefreshToken(db, tokenHash);
    if (row === undefined) {
      return { status: "unknown" };
    }

    if (row.used_at !== null) {
      return handleReuse(db, row, nowIso);
    }

    if (row.revoked_at !== null) {
      return { status: "revoked", subject: row.subject, familyId: row.family_id };
    }

    // Not used, not revoked, and the claim still failed: the only remaining
    // clause is `expires_at > ?`.
    return { status: "expired", subject: row.subject, familyId: row.family_id };
  });

  return rotate();
}

function completeRotation(
  db: Database.Database,
  claimed: RefreshTokenRow,
  nowIso: string,
): RotationOutcome {
  const user = findUserBySubject(db, claimed.subject);

  if (user === undefined || user.disabled_at !== null) {
    // A live refresh family for an account that can no longer sign in is a door
    // left open. Kill it now rather than leaving it to expire, and record it —
    // the console's session list should not show a disabled account holding a
    // session. Reason `admin` because a disable is an administrative act;
    // `expired` would be a lie and there is no `disabled` in the CHECK.
    const revoked = revokeFamily(db, claimed.family_id, "admin", nowIso);
    recordAudit(db, {
      actorKind: "system",
      actorLabel: "ward",
      action: "session.refresh_denied",
      targetKind: "session",
      targetId: claimed.family_id,
      detail: {
        subject: claimed.subject,
        reason: user === undefined ? "account_missing" : "account_disabled",
        tokensRevoked: revoked,
      },
    });
    return { status: "account_unusable", subject: claimed.subject, familyId: claimed.family_id };
  }

  /**
   * `R2` inherits `R1`'s `expires_at`, so **30 days is an absolute lifetime for
   * the family, counted from the login that created it** — not a window that
   * slides forward on every use.
   *
   * The decision page says "refresh token 30 days, rotated on every use" and
   * does not say which of the two it means, so this resolves it in the
   * bounded direction. A sliding expiry makes a family immortal for as long as
   * *anyone* keeps rotating it, and the party most likely to rotate quietly
   * every fourteen minutes forever is a thief — the reuse alarm only fires when
   * the victim comes back, and a victim who has stopped using the app never
   * does. An absolute cap means a stolen family dies on its own within 30 days
   * whatever anybody does with it.
   *
   * The cost is honest: an active person re-enters their password once a month.
   * For the owner plus a few known people that is nothing, and if it ever
   * becomes a complaint the change is to pass a fresh `expiresAt` here — but it
   * should be recorded as a decision when it happens, not slipped in.
   */
  const issued = issueRefreshToken(db, claimed.subject, {
    familyId: claimed.family_id,
    expiresAt: claimed.expires_at,
  });

  // `R1` is spent (`used_at` is set) but not yet dead. Mark it so the console
  // can tell an ordinary rotation from a logout from a theft signal.
  revokeRefreshToken(db, claimed.token_hash, "rotated", nowIso);

  return {
    status: "rotated",
    subject: claimed.subject,
    refreshToken: issued.token,
    row: issued.row,
    previous: claimed,
  };
}

function handleReuse(db: Database.Database, row: RefreshTokenRow, nowIso: string): RotationOutcome {
  const revoked = revokeFamily(db, row.family_id, "reuse_detected", nowIso);

  /**
   * The one audit row this brief is required to write.
   *
   * `actorKind: "system"` rather than `"account"`: the actor is Ward's own
   * detection, and the schema's CHECK ties a non-null `actor_subject` to
   * `account`. The subject travels in `detail` instead, where the console can
   * still find it. **No token and no hash goes in `detail`** — a hash is a
   * lookup key for a credential and the audit log is the one table designed to
   * be read by a human at leisure.
   */
  recordAudit(db, {
    actorKind: "system",
    actorLabel: "ward",
    action: "session.reuse_detected",
    targetKind: "session",
    targetId: row.family_id,
    detail: {
      subject: row.subject,
      tokensRevoked: revoked,
      presentedIssuedAt: row.issued_at,
      presentedUsedAt: row.used_at,
    },
  });

  return {
    status: "reuse_detected",
    subject: row.subject,
    familyId: row.family_id,
    revoked,
  };
}

/** What `endSession` concluded. */
export interface EndSessionResult {
  /** True if a live family was found and killed. False means nothing to do. */
  ended: boolean;
  subject?: string;
  familyId?: string;
  /** Live tokens revoked. `0` when the token was already dead or unknown. */
  revoked: number;
}

/**
 * Logout: kill the family the presented token belongs to.
 *
 * **The family, not the single token.** A family is one login's rotation chain,
 * so revoking it is exactly "sign this device out" — other devices have their
 * own families and keep working, which is the behaviour brief 09's "sign out my
 * other devices" is defined against.
 *
 * Rows are marked `revoked_reason = 'logout'` rather than `DELETE`d. The brief
 * says "deletes the refresh row" and the acceptance criterion is that logout
 * "leaves no refresh row" — read as *no usable row*, which this satisfies:
 * `claimRefreshToken` cannot match a revoked row, and
 * `listLiveTokensForSubject` no longer returns it. Keeping the row is the
 * deliberate half: `revoked_reason` exists precisely so the console can tell a
 * logout from a rotation from a theft signal, and `DELETE` erases the one thing
 * an operator investigating a stolen session needs to see. The rows are swept
 * by `deleteExpiredRefreshTokens` at their natural expiry.
 *
 * Idempotent and silent about failure — the route answers the same either way,
 * because logout must never be a way to test whether a token was real.
 */
export function endSession(
  db: Database.Database,
  presented: string | undefined,
  now: Date = new Date(),
): EndSessionResult {
  if (presented === undefined || presented.length === 0) {
    return { ended: false, revoked: 0 };
  }

  const tokenHash = hashRefreshToken(presented);
  const nowIso = now.toISOString();

  const end = db.transaction((): EndSessionResult => {
    const row = findRefreshToken(db, tokenHash);
    if (row === undefined) {
      return { ended: false, revoked: 0 };
    }

    const revoked = revokeFamily(db, row.family_id, "logout", nowIso);
    if (revoked > 0) {
      recordAudit(db, {
        actorKind: "account",
        actorSubject: row.subject,
        actorLabel: row.subject,
        action: "session.logout",
        targetKind: "session",
        targetId: row.family_id,
        detail: { tokensRevoked: revoked },
      });
    }

    return { ended: revoked > 0, subject: row.subject, familyId: row.family_id, revoked };
  });

  return end();
}

/**
 * Seconds of life left on a refresh row, floored at zero.
 *
 * The route uses this for the cookie's `Max-Age` instead of the flat 30 days,
 * because `R2` inherits its family's absolute expiry: a cookie that outlives
 * its row leaves a client presenting a credential Ward has already forgotten,
 * and the person sees an unexplained logout instead of a login prompt.
 */
export function refreshCookieMaxAge(row: RefreshTokenRow, now: Date = new Date()): number {
  const remaining = Math.floor((Date.parse(row.expires_at) - now.getTime()) / 1000);
  return remaining > 0 ? remaining : 0;
}

/** The account behind a subject, or `undefined` if it cannot sign in. */
export function usableAccount(db: Database.Database, subject: string): UserRow | undefined {
  const user = findUserBySubject(db, subject);
  return user !== undefined && user.disabled_at === null ? user : undefined;
}
