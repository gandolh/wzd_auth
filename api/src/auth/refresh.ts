import type Database from "better-sqlite3";

import { recordAudit } from "../db/audit-log.js";
import {
  claimRefreshToken,
  findRefreshToken,
  generateRefreshToken,
  hashRefreshToken,
  insertRefreshToken,
  listFamily,
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
 *
 * ## …except for one case that is *not* a replay: the same-token race
 *
 * "There is no information anywhere that distinguishes them" was too strong.
 * Two tabs of the same app firing `/refresh` at the same instant present the
 * **same** `R1`; one wins the claim and one loses it, and the loser used to burn
 * the family down microseconds after the winner had already written `R2` into
 * the cookie jar. Reproduced: two concurrent refreshes, statuses `200` and
 * `401`, and zero live tokens left for the subject. The `200` had set cookies
 * for an `R2` that was revoked immediately after, so the client believed it held
 * a fresh 30-day credential and was dead on its next refresh.
 *
 * `handleReuse` therefore asks one question before it revokes anything: **is
 * the family's live tip the direct successor of the token just presented, and
 * was it issued within `REFRESH_RACE_GRACE_SECONDS`?** If so this is a race, the
 * family is left alone, and the row written is `session.refresh_raced`. If not —
 * no live tip, or a tip that belongs to a later rotation, or one older than the
 * grace window — it is the theft signal exactly as before.
 *
 * Two things make the carve-out safe here specifically. The estate is
 * sub-paths on **one origin**, so every tab shares one cookie jar: the losing
 * tab's `401` costs nothing because the winning tab has already stored `R2` for
 * all of them. And the check is *narrow* — a thief replaying a token whose
 * family has moved on by even one rotation still sees the whole family die,
 * because the live tip is then not their token's successor.
 *
 * The **wire is identical** in both cases: `401 invalid_refresh`, no hint. The
 * distinction belongs in `audit_log` and nowhere else — telling a caller "that
 * was just a race" confirms the token was genuine, which is the oracle the
 * uniform `401` exists to close.
 */

/**
 * How long after a rotation a re-presentation of the spent token is treated as
 * a race rather than as theft.
 *
 * Ten seconds. It has to cover a browser firing two tabs' refreshes in the same
 * tick plus a slow response, and it has to be far shorter than any plausible
 * gap before a thief gets round to using a copied cookie. Every second of it is
 * a second in which a genuinely stolen `R1` is answered `401` without the family
 * dying — so it is deliberately the smallest window that covers the concurrency
 * it exists for, not the largest one that would still feel safe.
 */
export const REFRESH_RACE_GRACE_SECONDS = 10;

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
      /**
       * A replay. The family is already revoked by the time this returns, and
       * audited **if the sweep actually killed something** — see the note on
       * the guard in `handleReuse`.
       */
      status: "reuse_detected";
      subject: string;
      familyId: string;
      /**
       * How many live tokens the sweep killed. `0` if the family was already
       * dead, which is also the caller's signal that nothing happened and no
       * alarm should be raised.
       */
      revoked: number;
    }
  | {
      /**
       * A **benign** re-presentation of a token that was spent moments ago and
       * whose successor is still live: two tabs refreshing at once. The family
       * is deliberately left untouched and `session.refresh_raced` is on the
       * record. The route must still answer the same opaque `401` — see the
       * module header.
       */
      status: "refresh_raced";
      subject: string;
      familyId: string;
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

/** Extras a caller may thread into a rotation. Purely additive. */
export interface RotationOptions {
  /**
   * The presenter's client address, as `lockoutKeyFor` derives it.
   *
   * Recorded in `detail.ip` on `session.reuse_detected` and
   * `session.refresh_raced`. Those are the two rows an operator is meant to act
   * on, and without an address they cannot tell a stranger abroad from their
   * own laptop double-firing a refresh — while the far less interesting
   * `session.login_failed` has carried `detail.ip` all along.
   */
  presentedBy?: string;
}

/**
 * Present a refresh token and rotate it.
 *
 * Every database write below happens inside one `better-sqlite3` transaction,
 * so a rotation is all-or-nothing: there is no state in which `R1` is spent but
 * `R2` was never stored, which would silently log the person out. **The access
 * token must be minted by the caller *before* this is called** — see the note
 * on ordering in `routes/auth.ts`: a mint that fails after the claim has
 * committed leaves the client still holding `R1`, and its next refresh burns the
 * family. Minting first wastes a JWS in the rare case the claim then fails,
 * which is cheap.
 */
export function rotateRefreshToken(
  db: Database.Database,
  presented: string,
  now: Date = new Date(),
  options: RotationOptions = {},
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
      return handleReuse(db, row, nowIso, options.presentedBy);
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

function handleReuse(
  db: Database.Database,
  row: RefreshTokenRow,
  nowIso: string,
  presentedBy: string | undefined,
): RotationOutcome {
  const raced = raceSuccessor(db, row, nowIso);

  if (raced !== undefined) {
    /**
     * A race, not a theft. **Nothing is revoked**, so the winning tab's `R2`
     * stays live and the session survives; the losing tab simply gets the same
     * opaque `401` and, because the estate is one origin with one cookie jar,
     * it is already holding `R2` anyway.
     *
     * Its own action, so an operator reading `audit_log` can tell this apart
     * from the alarm they are supposed to act on. Same `detail` discipline as
     * below: no token, no hash.
     */
    recordAudit(db, {
      actorKind: "system",
      actorLabel: "ward",
      action: "session.refresh_raced",
      targetKind: "session",
      targetId: row.family_id,
      detail: {
        subject: row.subject,
        ip: presentedBy ?? null,
        presentedIssuedAt: row.issued_at,
        presentedUsedAt: row.used_at,
        successorIssuedAt: raced.issued_at,
      },
    });

    return { status: "refresh_raced", subject: row.subject, familyId: row.family_id };
  }

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
   *
   * **Guarded on `revoked > 0`.** `/refresh` is deliberately exempt from the IP
   * lockout, so without the guard anybody holding one spent token could write
   * an unbounded number of rows: 25 replays measured 25 rows and 25 `warn`
   * lines, on an unauthenticated route. The second replay of a family that is
   * already dead did nothing, so it is not an event — and the flood was
   * drowning the operator's only alert channel, which made a genuine theft
   * indistinguishable from noise. One row per family is the whole signal.
   */
  if (revoked > 0) {
    recordAudit(db, {
      actorKind: "system",
      actorLabel: "ward",
      action: "session.reuse_detected",
      targetKind: "session",
      targetId: row.family_id,
      detail: {
        subject: row.subject,
        ip: presentedBy ?? null,
        tokensRevoked: revoked,
        presentedIssuedAt: row.issued_at,
        presentedUsedAt: row.used_at,
      },
    });
  }

  return {
    status: "reuse_detected",
    subject: row.subject,
    familyId: row.family_id,
    revoked,
  };
}

/**
 * The live token `presented`'s rotation created, if this re-presentation is a
 * race rather than theft. `undefined` means "treat it as theft".
 *
 * Three conditions, all of them necessary:
 *
 *  1. **Nobody has rotated since.** If any other member of the family was spent
 *     at or after `presented.used_at`, then the family's live tip belongs to a
 *     *later* rotation and `presented` is not its parent — which is a token
 *     arriving two or more rotations late, not two tabs firing at once. The
 *     comparison is `>=` rather than `>` deliberately: two rotations landing in
 *     the same millisecond then read as theft, which is the direction to fail
 *     in. This is also what makes the check independent of `issued_at` ordering,
 *     which is only millisecond-precise.
 *  2. **There is a live tip at all** — unspent, unrevoked, unexpired. A family
 *     with none has either been swept already or is entirely spent, and in
 *     neither case is there a session left to protect.
 *  3. **The tip is fresh**, within `REFRESH_RACE_GRACE_SECONDS`. A replay long
 *     after the rotation is not concurrency; it is somebody who has been sitting
 *     on a copy.
 */
function raceSuccessor(
  db: Database.Database,
  presented: RefreshTokenRow,
  nowIso: string,
): RefreshTokenRow | undefined {
  if (presented.used_at === null) return undefined;

  const presentedUsedAt = Date.parse(presented.used_at);
  const now = Date.parse(nowIso);
  if (Number.isNaN(presentedUsedAt) || Number.isNaN(now)) return undefined;

  let tip: RefreshTokenRow | undefined;

  for (const member of listFamily(db, presented.family_id)) {
    if (member.token_hash === presented.token_hash) continue;

    // (1) Somebody else in this family has already rotated since.
    if (member.used_at !== null && Date.parse(member.used_at) >= presentedUsedAt) {
      return undefined;
    }

    // (2) The tip. A well-formed family has at most one.
    if (
      member.used_at === null &&
      member.revoked_at === null &&
      Date.parse(member.expires_at) > now
    ) {
      tip = member;
    }
  }

  if (tip === undefined) return undefined;

  // (3)
  if (now - Date.parse(tip.issued_at) > REFRESH_RACE_GRACE_SECONDS * 1000) return undefined;

  return tip;
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
 * Seconds of life left on a refresh row, floored at **one**.
 *
 * The route uses this for the cookie's `Max-Age` instead of the flat 30 days,
 * because `R2` inherits its family's absolute expiry: a cookie that outlives
 * its row leaves a client presenting a credential Ward has already forgotten,
 * and the person sees an unexplained logout instead of a login prompt.
 *
 * `Math.max(1, …)` for the same reason `checkLockout` uses it on `Retry-After`:
 * `Max-Age=0` is not "expires immediately", it is the exact instruction used to
 * **delete** a cookie. A rotation in the family's final second floors to zero
 * and would tell the browser to throw the cookie away, which is a different
 * event from letting it lapse. Cosmetic at a 30-day family lifetime — the end
 * state, re-authenticate, is intended at the absolute cap either way — but it
 * would matter the moment a shorter lifetime were configured.
 */
export function refreshCookieMaxAge(row: RefreshTokenRow, now: Date = new Date()): number {
  return Math.max(1, Math.floor((Date.parse(row.expires_at) - now.getTime()) / 1000));
}

/**
 * The subject a presented refresh token belongs to, whatever state its row is
 * in — spent, revoked, expired — or `undefined` if the hash is unknown.
 *
 * Exists so `routes/auth.ts` can mint the access token **before** opening the
 * rotation transaction without hashing the token itself. Emphatically **not** an
 * authorisation check: it says who a token names, not whether it may be used.
 * Only `rotateRefreshToken` decides that.
 */
export function subjectForRefreshToken(
  db: Database.Database,
  presented: string,
): string | undefined {
  return findRefreshToken(db, hashRefreshToken(presented))?.subject;
}

/** The account and the refresh family a presented token belongs to. */
export interface PresentedSession {
  subject: string;
  familyId: string;
}

/**
 * Peek at both the subject and the **family** behind a presented refresh token.
 *
 * `/refresh` mints the access token *before* rotating (so a mint failure leaves
 * no spent row behind), which means it needs the `sid` before the rotation has
 * told it anything. Rotation preserves `family_id` — that is what makes a family
 * a family — so the presented token's family is the successor's family, and
 * reading it here is sound rather than a guess.
 *
 * A **lookup, not an authorisation check.** It says nothing about whether the
 * token is live, unexpired or unrevoked; `rotateRefreshToken` decides all of
 * that and remains the only thing that may. Do not let a caller treat a result
 * here as permission to proceed.
 */
export function sessionForRefreshToken(
  db: Database.Database,
  presented: string,
): PresentedSession | undefined {
  const row = findRefreshToken(db, hashRefreshToken(presented));
  if (row === undefined) return undefined;
  return { subject: row.subject, familyId: row.family_id };
}

/** The account behind a subject, or `undefined` if it cannot sign in. */
export function usableAccount(db: Database.Database, subject: string): UserRow | undefined {
  const user = findUserBySubject(db, subject);
  return user !== undefined && user.disabled_at === null ? user : undefined;
}
