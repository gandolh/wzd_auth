import type Database from "better-sqlite3";
import { grantsBySlug } from "../db/grants.js";
import { listFamily, listLiveTokensForSubject } from "../db/refresh-tokens.js";
import { findUserBySubject } from "../db/users.js";

/**
 * The one code path that answers "is this session live, and what may it do".
 *
 * `routes/introspect.ts` establishes *who* — it verifies a compact JWS and gets
 * a `sub` — and then hands that subject here. Everything after the signature is
 * decided in this file, once, so there is exactly one answer to "is this live"
 * rather than one per caller. Nothing in here touches Fastify, HTTP or the
 * token layer, which is what makes it directly testable against an in-memory
 * database.
 *
 * Deliberately free of Fastify so brief 05's console can ask the same question
 * of the same code rather than reimplementing the liveness rule next door.
 *
 * ## Why authority is resolved here and not carried in the token
 *
 * `corpus/wiki/decisions-tokens.md` forbids permissions in the access token: a
 * token minted before a grant changed would carry stale authority for its whole
 * 15 minutes. Resolving grants on every introspection instead means a
 * permission change lands in the **same 30-second window a revocation does**.
 * That is the entire reason this function returns more than a boolean, and it
 * is why `tokens/mint.ts` has no parameter for extra claims.
 *
 * ## What "live" can and cannot be established from
 *
 * A Ward access token carries `sub`, `jti`, `iat`, `exp`, `iss`, `aud` and
 * **not a family id**. `jti` is a fresh `randomUUID()` that is never persisted
 * anywhere (confirmed: no column in the schema holds one), so there is no
 * stored mapping from an access token to the refresh family it was minted
 * alongside. Nothing in this brief can create one — `tokens/**` and `db/**`
 * belong to briefs 02 and 01.
 *
 * So the strongest **correct** statement available is the account-level one:
 *
 * > an account with no live refresh token has no live session.
 *
 * That is what `hasLiveSession` implements, and it is sound because every
 * access token Ward mints is minted alongside a refresh row — at login and at
 * every rotation — so an account holding a usable access token and zero live
 * refresh rows is an account whose session was ended.
 *
 * **What it therefore catches** — every case where the account has no live
 * family left: logout on a single-session account, a reuse-detection family
 * sweep, an administrative revoke-all, a lapsed family, a deleted account, and
 * (separately, below) a disabled account.
 *
 * **What it cannot catch, stated plainly** — one family revoked while *another*
 * family for the same subject is still live. Two devices, sign out on one: the
 * signed-out device's access token keeps introspecting `active: true` until it
 * expires, because from here it is indistinguishable from the other device's.
 * The exposure is bounded by the access token's 15 minutes rather than by the
 * 30-second cache, and it only matters against a token that was **already
 * stolen** — logout clears the cookie, so an honest client holds nothing
 * afterwards. That is the same threat model `decisions-tokens.md` accepts for
 * the cache window, but the window here is longer and that difference is real.
 * Closing it needs a `jti`-to-family link written at mint time, which is a
 * schema change and a change to `tokens/**`: brief 01 and 02 territory.
 *
 * A partial strengthening was considered and **rejected**: refusing any token
 * whose `iat` is later than the newest live refresh row's `issued_at`, since a
 * token minted after every live family's last rotation cannot belong to one of
 * them. It is sound today and catches roughly half of the two-family orderings,
 * but it rests on `routes/auth.ts` minting the access token strictly *before*
 * inserting the refresh row — an invariant in a file this brief does not own,
 * whose failure mode is spuriously signing a legitimate person out of six apps.
 * A rule that can log the owner out to close half of a stolen-token window is
 * the wrong trade, and a half-measure documented as a whole one is worse than
 * the honest limitation. Recorded so the next person does not have to rederive
 * it.
 */

/**
 * Every role an account holds, keyed by app slug — `{ atrium: ["admin"] }`.
 *
 * An app absent from the map means **no access to that app at all**; holding a
 * Ward account confers nothing on its own. An app present with an empty array
 * cannot occur, because a grant row always carries a role.
 *
 * A **set** rather than a single role: one person legitimately holds several
 * roles in one app (`grants`' primary key is the whole triple), so a consumer
 * tests membership and never compares equality. Role strings are opaque —
 * Ward stores them and never interprets them, and neither does this module.
 */
export type GrantsByApp = Record<string, string[]>;

/**
 * A live session, with the identity and the authority an app is entitled to.
 *
 * **Every field, justified — the acceptance criterion is that there is no
 * field an app cannot justify needing:**
 *
 * - `active` — the question that was asked. An app gates the request on it.
 * - `subject` — the stable opaque id every app keys its own rows on, and the
 *   only correct join key for "this person's data". An app *could* read it out
 *   of the token it already verified; it is echoed here so an app never has to
 *   decode a JWT to find out who it is talking to, and so the two answers
 *   cannot disagree.
 * - `username` — the canonical identifier, needed to render "signed in as …"
 *   without six apps keeping their own copy of a mutable field. It is the
 *   display name the estate agreed on; `subject` is deliberately unreadable.
 * - `grants` — the authority, which is the whole reason this endpoint returns
 *   more than a boolean (see the header).
 *
 * **What is deliberately absent, and must stay absent:** `password_hash`,
 * `email`, `email_verified`, `created_at`, `disabled_at`, session or family
 * ids, refresh-token state, and anything else on the `users` row. An app has no
 * use for a credential, and a contact address is Ward's to hold — six copies of
 * an address is six places to leak it from and six places to forget to update.
 * Nothing here says *why* a session is dead either, for the same reason
 * `/login` gives one answer to two failures: a diagnosis is an oracle.
 */
export interface ActiveSession {
  readonly active: true;
  readonly subject: string;
  readonly username: string;
  readonly grants: GrantsByApp;
}

/**
 * Not live — and that is the entire answer.
 *
 * Disabled, revoked, lapsed, deleted, expired, forged and absent all produce
 * this identical object, so the response cannot be read as an oracle for which
 * of those it was. The operator sees the distinction in the audit log and the
 * server log; the caller does not.
 */
export interface InactiveSession {
  readonly active: false;
}

/** The introspection answer. Brief 08's `@ward/client` consumes this verbatim. */
export type SessionResolution = ActiveSession | InactiveSession;

/**
 * The single inactive answer, shared and frozen.
 *
 * One value rather than an object literal per branch, so "never leaks why"
 * holds by construction: there is no per-branch object for a future edit to
 * quietly add a `reason` field to.
 */
export const INACTIVE: InactiveSession = Object.freeze({ active: false });

/**
 * Whether the account holds any refresh token that is neither revoked nor
 * lapsed — one indexed read against `refresh_tokens_subject_idx`.
 *
 * See the header for exactly what this does and does not establish. It is
 * account-scoped by necessity, not by choice.
 *
 * `listLiveTokensForSubject` materialises the rows rather than counting them.
 * That is fine and deliberate: the row count per account is the number of
 * devices signed in — single digits — and rotation revokes the predecessor, so
 * a family contributes exactly one live row. Reusing brief 01's query module
 * keeps a second copy of this table's liveness rule from existing, which is
 * worth more here than one avoided allocation.
 */
export function hasLiveSession(
  db: Database.Database,
  subject: string,
  now: string = new Date().toISOString(),
): boolean {
  return listLiveTokensForSubject(db, subject, now).length > 0;
}

/**
 * Whether **one specific refresh family** still holds a live member.
 *
 * This is the check that makes per-device revocation real, and it is why the
 * access token carries a `sid` claim. `hasLiveSession` above can only answer
 * "does this account have *any* live session", so before `sid` existed, signing
 * out one device left that device's access token introspecting as live for its
 * full 15 minutes while a second device kept the account alive. That broke the
 * one feature the self-service UI exists for — "sign out my other devices" —
 * against an attacker who by hypothesis is actively using the token.
 *
 * A family contributes exactly one live row, because rotation revokes the
 * predecessor as it issues the successor. So this is an indexed read over a
 * handful of rows, and "no live member" means the family was logged out,
 * swept by reuse detection, revoked by an admin, or has simply lapsed.
 */
export function hasLiveFamily(
  db: Database.Database,
  familyId: string,
  subject: string,
  now: string = new Date().toISOString(),
): boolean {
  // The predicate is deliberately identical to `listLiveTokensForSubject`'s
  // (`revoked_at IS NULL AND expires_at > ?`) and does NOT also require
  // `used_at IS NULL`. Rotation sets `used_at` and `revoked_at` together, so in
  // normal operation the two agree — but "live" must mean one thing in this
  // codebase, and a stricter check here could report a family dead while the
  // account-scoped view reported it live. If that predicate ever changes, both
  // change together.
  /**
   * **The family must belong to this subject.**
   *
   * At the one real call site the pairing is already trustworthy: Ward reads
   * `sub` and `sid` off the *same* verified token, so mismatching them means
   * forging a signature. But that safety lives in the caller, not here, and a
   * later caller assembling the pair from two sources would get an unsound
   * answer with no signal at all. Brief 09's "sign out my other devices" is
   * exactly that shape — a subject from a session, a family id from a request.
   *
   * One comparison on rows already fetched makes this safe to hold wrong,
   * rather than merely unlikely to be held wrong.
   */
  return listFamily(db, familyId).some(
    (row) => row.subject === subject && row.revoked_at === null && row.expires_at > now,
  );
}

/**
 * Resolve a verified subject into the introspection answer.
 *
 * The caller has already established authentication — a valid signature, a
 * pinned issuer and audience, an unexpired `exp`. This decides **liveness and
 * authority**, which is the distinction the glossary's "Introspection" entry
 * exists to keep sharp: a signature stays valid for the full 15 minutes after a
 * session is revoked, so a signature alone is never permission to proceed.
 *
 * Three indexed reads at most, in order of how decisive and how cheap they are:
 *
 *  1. `users` by primary key — does the account exist, and is it disabled.
 *  2. `refresh_tokens` by `subject` — does any live session remain.
 *  3. `grants` by the primary key's leading column — what may they do.
 *
 * Read (3) runs only for a live session, so a revoked or disabled account costs
 * two reads and no grant lookup. There is no join and no per-app query: the
 * whole estate's authority for one person comes back in the third read, which
 * is what "no N+1 across six apps" means in practice.
 */
export function resolveSession(
  db: Database.Database,
  subject: string,
  sessionId: string,
  now: string = new Date().toISOString(),
): SessionResolution {
  const user = findUserBySubject(db, subject);

  // A subject with no row is a deleted account, or a correctly-signed token for
  // a subject that never existed. Subjects are never recycled, so this can
  // never resolve to somebody else later.
  if (user === undefined) return INACTIVE;

  /**
   * **Disabling an account makes every app reject it on its next
   * introspection**, and this line is the whole mechanism. `setDisabled` does
   * not revoke refresh rows — `db/users.ts` says so explicitly and calls the
   * revoke a separate write — so a disabled account can still hold a live
   * family, and checking the flag here is what makes the door locked rather
   * than merely marked.
   */
  if (user.disabled_at !== null) return INACTIVE;

  /**
   * **Liveness is scoped to this session, not to the account.**
   *
   * `sessionId` is the token's `sid` — the family it was minted under. Checking
   * the family rather than the account is what lets one device be signed out
   * while another stays live: the revoked device's token still verifies for the
   * rest of its 15 minutes, and this is the line that stops it counting.
   *
   * The account-wide `hasLiveSession` is deliberately still exported for
   * callers asking "is anybody signed in", but it must not be the introspection
   * answer — it cannot tell one revoked family from a second live one.
   */
  if (!hasLiveFamily(db, sessionId, subject, now)) return INACTIVE;

  return {
    active: true,
    // From the row, not from the claim. `sub` was verified so the two agree
    // today; reading the row means they cannot drift if that ever changes.
    subject: user.subject,
    // As the person typed it — `users.username` is display, `username_folded`
    // carries uniqueness and is nobody else's business.
    username: user.username,
    grants: grantsBySlug(db, subject),
  };
}
