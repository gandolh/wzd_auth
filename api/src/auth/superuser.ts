import { createHash, createHmac, randomBytes, timingSafeEqual } from "node:crypto";

import { wardSecureCookies } from "./cookie.js";

/**
 * The break-glass superuser and the console session it opens.
 *
 * Read `corpus/wiki/decisions-admin.md` before changing anything here. Two
 * privileged identities exist in this estate and they are **not**
 * interchangeable:
 *
 * - The **superuser** is this file. It lives only in `WARD_ADMIN_USERNAME` /
 *   `WARD_ADMIN_PASSWORD`, has **no row in `users`**, no subject and no grants,
 *   and reaches Ward's console and nothing else. It is used when something is
 *   broken.
 * - The **owner account** is an ordinary account holding explicit admin grants
 *   across the apps. It is what actually runs atrium, newspapper and the rest,
 *   it is created *through* the console (brief 05), and it is revocable,
 *   rotatable and auditable — which is exactly what the superuser is not.
 *
 * ## Two properties this module exists to hold structurally
 *
 * **1. Nothing here reads or writes the database as an identity.** The
 * credential check is a comparison against two environment strings; there is no
 * lookup, no row, no mirror table, and this brief creates none. The only
 * database call anywhere on the console-login path is the `audit_log` insert the
 * route makes, and `audit_log` deliberately has no foreign keys precisely so the
 * superuser — which has nothing to reference — can appear in it.
 *
 * **2. A console session is not a JWT and cannot be made into one.** The token
 * is `wcs_` followed by base64url random bytes. A compact JWS is three
 * base64url segments separated by two `.` characters; neither the prefix nor the
 * base64url alphabet contains `.`, so this string cannot parse as one — and
 * because it is not signed by Ward's key and carries no claims, no verifier in
 * the estate can be talked into accepting it. That is the whole point.
 * `decisions-admin.md` rejected the alternative — a reserved sentinel subject
 * inside a normal access token, which apps would be *instructed* to reject —
 * because it holds only while all six apps remember to implement the rejection.
 * It fails on discipline. This fails safe.
 *
 * Corollary, and the rule for anyone extending this file: **do not import
 * `../tokens/`**. Nothing this module emits should be parseable as, or
 * verifiable by, the token layer. A `superuser.test.ts` case imports
 * `verifyWardAccessToken` to prove that negative; production code here must
 * not.
 *
 * ## Rotating the password
 *
 * **Editing `.env` and restarting Ward. There is deliberately no UI for it**,
 * and none should be added: `decisions-admin.md` records that friction as
 * correct for a credential of this kind. The values are read through
 * `config.ts`, which resolves the environment exactly once at import, so a
 * running process cannot see a new password — and cannot be tricked into
 * reading one. Consequences worth stating plainly, because they are the price
 * of the break-glass design and not oversights:
 *
 * - The credential **cannot be revoked** without a redeploy. Its only
 *   observability is the audit trail `routes/console.ts` writes on every login
 *   attempt, success or failure.
 * - A restart also drops every console session, because the store below is in
 *   memory. That is the desired behaviour: a rotation should end the sessions
 *   the old password opened, and for a break-glass credential losing sessions on
 *   restart costs nothing.
 */

/** The cookie the console session travels in. */
export const CONSOLE_COOKIE_NAME = "ward_console";

/**
 * The cookie's `Path`, in browser-visible terms.
 *
 * Ward is reverse-proxied at `/ward-api/*` and the prefix is stripped before
 * Fastify sees it, so the routes in `routes/console.ts` are registered at
 * `/console/...` while the browser sees `/ward-api/console/...`. This constant
 * is the browser's view, because `Path` is a browser-side matching rule.
 *
 * The scope is doing real work. The estate is a **single origin** with every app
 * on a sub-path, so a cookie at `Path=/` is sent to all six
 * (`wiki/decisions.md`). Scoping this one to the console subtree means the
 * console session is never even *transmitted* to atrium, newspapper or prm — the
 * "console only" property is enforced by three separate independent things: no
 * grants (the design), not a JWT (the format), and never sent (the scope).
 */
export const CONSOLE_COOKIE_PATH = "/ward-api/console";

/**
 * Idle timeout. A console session that goes 15 minutes without a request is
 * gone, and the next request with its cookie is a clean 401.
 *
 * Short on purpose: this is the session of a credential that cannot be revoked,
 * so the only bound available on a stolen or forgotten one is time. 15 minutes
 * matches the access-token lifetime the estate already reasoned about, which
 * keeps one number in the operator's head instead of two.
 */
export const CONSOLE_SESSION_IDLE_TIMEOUT_SECONDS = 15 * 60;

/**
 * Absolute cap, regardless of activity: four hours.
 *
 * The idle timeout alone bounds an abandoned session but not an actively used
 * one, and "actively used" includes a page left open polling something. Four
 * hours is longer than any real break-glass session and shorter than a day, so
 * a session cannot quietly outlive the incident that opened it.
 */
export const CONSOLE_SESSION_ABSOLUTE_LIFETIME_SECONDS = 4 * 60 * 60;

/**
 * How many sessions the store will hold at once.
 *
 * There is exactly one console credential and therefore one administrator
 * (`decisions-admin.md`: console access cannot be delegated), so the real number
 * is one or two — a laptop and a phone. The cap exists because the store is a
 * process-lifetime `Map` fed by an unauthenticated endpoint: without it, a
 * script that knows the password could grow it without bound. Eviction is
 * least-recently-seen first, so the session in front of the operator is the last
 * one to go.
 */
const MAX_CONSOLE_SESSIONS = 16;

/**
 * A console session, as everything outside this module sees it.
 *
 * **Note what is absent: there is no subject, no username and no grants field,**
 * and none may be added. A console session identifies the break-glass
 * credential, which is not an account; a `subject` here would be the sentinel
 * that `decisions-admin.md` rejected, arriving through a side door. `id` is a
 * non-secret handle for the audit log — never the token.
 */
export interface ConsoleSession {
  /** Non-secret. Safe to log; this is what `audit_log.target_id` carries. */
  id: string;
  createdAt: Date;
  lastSeenAt: Date;
  /** When it dies if nothing else happens. Slides on every request. */
  idleExpiresAt: Date;
  /** When it dies however busy it is. Fixed at creation. */
  absoluteExpiresAt: Date;
}

/** What `openConsoleSession()` hands back: the secret once, and the session. */
export interface OpenedConsoleSession {
  /**
   * The bearer value for the cookie. Returned exactly once and never stored in
   * recoverable form — the store below keeps only `sha256(token)`.
   */
  token: string;
  session: ConsoleSession;
}

interface StoredSession {
  id: string;
  createdAt: number;
  lastSeenAt: number;
  absoluteDeadline: number;
}

/**
 * The store: in memory, keyed by `sha256(token)`.
 *
 * The brief allows in memory or a table, and in memory is the better answer
 * here for a reason beyond convenience — a table would mean the superuser has
 * *rows*, which is the one thing `decisions-admin.md` says it must not have.
 * Keeping it out of SQLite keeps "no row anywhere" literally true and keeps the
 * acceptance test that asserts it honest.
 *
 * Keyed by digest rather than by the token itself for the same reason
 * `refresh_tokens` stores a hash: the token is 256 bits of CSPRNG output, so an
 * unsalted SHA-256 is the right primitive (there is no low-entropy secret to
 * stretch), and a heap dump, a debugger or a stray `console.log(sessions)` then
 * yields nothing replayable.
 */
const sessions = new Map<string, StoredSession>();

/**
 * A per-process HMAC key over the credential comparison.
 *
 * `timingSafeEqual` throws on a length mismatch, and a plain length check
 * *before* it is itself the timing oracle it was meant to remove — a wrong-length
 * password would answer measurably sooner than a right-length one, which leaks
 * the password's length. Hashing both sides to a fixed 32 bytes first removes
 * the branch entirely: every comparison is 32 bytes against 32 bytes, whatever
 * was submitted.
 *
 * Keyed rather than bare SHA-256 because the inputs are a human-chosen password,
 * not a random token. A bare digest of the expected value is precomputable from
 * a wordlist; keyed with bytes that never leave this process and change on every
 * restart, it is not. The key is never exported, logged or persisted.
 */
const COMPARISON_KEY = randomBytes(32);

function fingerprint(value: string): Buffer {
  return createHmac("sha256", COMPARISON_KEY).update(value, "utf8").digest();
}

/** Constant-time over fixed-length digests, for inputs of any length. */
function fingerprintsMatch(presented: string, expected: string): boolean {
  return timingSafeEqual(fingerprint(presented), fingerprint(expected));
}

function tokenDigest(token: string): string {
  return createHash("sha256").update(token, "utf8").digest("hex");
}

/**
 * Compare a submitted username and password against the environment.
 *
 * **Nothing is read from the database.** The environment arrives through a
 * *dynamic* import of `config.js`, following the pattern `db/connection.ts` and
 * `tokens/service.ts` both document: `config.ts` validates with zod at import
 * time and can `process.exit(1)`, so a static import here would be hoisted and
 * would take down anything that merely imported this module's cookie helpers.
 *
 * Both halves are fingerprinted and compared before either result is consulted,
 * and the two booleans are combined bitwise rather than with `&&`, so the answer
 * takes the same path whether the username was wrong, the password was wrong, or
 * both. There is no user-existence oracle to worry about — there is exactly one
 * credential — but "which half did I get right" is one, and this closes it.
 */
export async function checkSuperuserCredentials(
  username: string,
  password: string,
): Promise<boolean> {
  const { WARD_ADMIN_USERNAME, WARD_ADMIN_PASSWORD } = await import("../config.js");

  const usernameMatches = fingerprintsMatch(username, WARD_ADMIN_USERNAME);
  const passwordMatches = fingerprintsMatch(password, WARD_ADMIN_PASSWORD);

  return (Number(usernameMatches) & Number(passwordMatches)) === 1;
}

/**
 * Whether the console cookie should carry `Secure`, derived from
 * `WARD_PUBLIC_ORIGIN`.
 *
 * Same rule brief 03 applies to the session cookies — and now literally the
 * same code. This function used to test `WARD_PUBLIC_ORIGIN.startsWith("https:")`
 * on its own, which dropped the loopback half of the rule the comment claimed to
 * implement and so **failed open** where its sibling fails closed: for
 * `http://gandolh.ro` — a well-formed origin `config.ts` accepts, since it does
 * not restrict `http:` to loopback — `secureCookiesFor` returns `true` and this
 * returned `false`, shipping the cookie that carries the non-revocable
 * break-glass session over plain HTTP to a real hostname with no `Secure` at
 * all. `secureCookiesFor`'s reasoning is the correct one: keep `Secure` and let
 * the cookie break loudly rather than travel in the clear.
 *
 * Derived from the configured origin rather than from the request, because a
 * request header is attacker-controlled and this decides whether a credential
 * may travel in clear text. `wardSecureCookies` keeps the `config.js` import
 * **dynamic** for the reason that module documents — a static one is hoisted and
 * would run zod validation, and its `process.exit(1)`, merely because something
 * imported a cookie helper.
 */
export async function consoleCookieSecure(): Promise<boolean> {
  return wardSecureCookies();
}

function view(stored: StoredSession): ConsoleSession {
  /**
   * Clamped to the absolute deadline.
   *
   * The *enforcement* was always right — `expired()` below checks both bounds,
   * so a busy session does die at the four-hour cap. The reported value was not:
   * a session 3h59m old reported an `idleExpiresAt` fifteen minutes out, five
   * minutes past its own `absoluteExpiresAt`. That value flows into
   * `GET /console/session` and the login response, so the console UI would have
   * shown a countdown promising time the session does not have — during what is,
   * by construction, an incident.
   */
  const idleExpiresAt = Math.min(
    stored.lastSeenAt + CONSOLE_SESSION_IDLE_TIMEOUT_SECONDS * 1000,
    stored.absoluteDeadline,
  );

  return {
    id: stored.id,
    createdAt: new Date(stored.createdAt),
    lastSeenAt: new Date(stored.lastSeenAt),
    idleExpiresAt: new Date(idleExpiresAt),
    absoluteExpiresAt: new Date(stored.absoluteDeadline),
  };
}

function expired(stored: StoredSession, now: number): boolean {
  return (
    now >= stored.absoluteDeadline ||
    now - stored.lastSeenAt >= CONSOLE_SESSION_IDLE_TIMEOUT_SECONDS * 1000
  );
}

function prune(now: number): void {
  for (const [digest, stored] of sessions) {
    if (expired(stored, now)) sessions.delete(digest);
  }
}

/**
 * Mint a fresh console session. The caller has already verified the credential;
 * this function does not check anything, and must not be exported to a route
 * that has not.
 *
 * The token is `wcs_` + 32 random bytes base64url — 256 bits, the same budget as
 * a refresh token, and shaped so it can never be mistaken for a JWT (see the
 * module header). The prefix is there so the value is greppable in an incident
 * and recognisable to a secret scanner.
 */
export function openConsoleSession(): OpenedConsoleSession {
  const now = Date.now();
  prune(now);

  // Least-recently-seen eviction, after pruning, so the cap only ever bites on
  // genuinely live sessions.
  while (sessions.size >= MAX_CONSOLE_SESSIONS) {
    let oldestDigest: string | undefined;
    let oldestSeen = Infinity;
    for (const [digest, stored] of sessions) {
      if (stored.lastSeenAt < oldestSeen) {
        oldestSeen = stored.lastSeenAt;
        oldestDigest = digest;
      }
    }
    if (oldestDigest === undefined) break;
    sessions.delete(oldestDigest);
  }

  const token = `wcs_${randomBytes(32).toString("base64url")}`;
  const stored: StoredSession = {
    id: randomBytes(16).toString("hex"),
    createdAt: now,
    lastSeenAt: now,
    absoluteDeadline: now + CONSOLE_SESSION_ABSOLUTE_LIFETIME_SECONDS * 1000,
  };
  sessions.set(tokenDigest(token), stored);

  return { token, session: view(stored) };
}

/**
 * Look up a presented token and, if it is live, slide its idle window.
 *
 * `undefined` for every failure — unknown, expired, malformed, an access token
 * someone pasted into the wrong cookie — with no distinction between them, so
 * the guard has one answer to give and no oracle to relay.
 *
 * There is no clock parameter, deliberately. Brief 02 shipped a verify path
 * whose every claim check was caller-overridable, including the current time,
 * and the fix was to make the dangerous inputs *not expressible* rather than to
 * document them. The same reasoning applies to a session deadline: tests move
 * time with `vi.setSystemTime`, production cannot move it at all.
 */
export function resolveConsoleSession(token: string): ConsoleSession | undefined {
  const now = Date.now();
  const digest = tokenDigest(token);
  const stored = sessions.get(digest);

  if (stored === undefined) return undefined;
  if (expired(stored, now)) {
    sessions.delete(digest);
    return undefined;
  }

  stored.lastSeenAt = now;
  return view(stored);
}

/**
 * Drop a session. Returns the session that was dropped so the caller can name
 * its `id` in the audit log, or `undefined` if there was nothing to drop —
 * which makes logout idempotent rather than an error.
 */
export function closeConsoleSession(token: string): ConsoleSession | undefined {
  const digest = tokenDigest(token);
  const stored = sessions.get(digest);
  if (stored === undefined) return undefined;
  sessions.delete(digest);
  return view(stored);
}

/** Live session count, after pruning. For tests and for the console's own view. */
export function activeConsoleSessionCount(): number {
  prune(Date.now());
  return sessions.size;
}

/** Empty the store. Tests only; nothing in the running service calls it. */
export function resetConsoleSessionsForTests(): void {
  sessions.clear();
}

/**
 * Read the console cookie out of a raw `Cookie` header.
 *
 * Hand-rolled because Ward has no cookie plugin and this brief may not add a
 * dependency — and because the job is genuinely this small. It reads **only**
 * `ward_console` and ignores every other cookie on the header, which matters:
 * `Path=/` in this estate means the access-token cookie is on almost every
 * request, and the guard must never be able to see it, let alone act on it.
 */
export function readConsoleCookie(cookieHeader: string | undefined): string | undefined {
  if (!cookieHeader) return undefined;

  for (const part of cookieHeader.split(";")) {
    const separator = part.indexOf("=");
    if (separator === -1) continue;
    if (part.slice(0, separator).trim() !== CONSOLE_COOKIE_NAME) continue;
    const raw = part.slice(separator + 1).trim();
    try {
      return decodeURIComponent(raw);
    } catch {
      // A malformed percent escape is not our cookie. Treat it as absent.
      return undefined;
    }
  }
  return undefined;
}

function attributes(secure: boolean): string {
  return [
    `Path=${CONSOLE_COOKIE_PATH}`,
    "HttpOnly",
    // Strict, not Lax. The console is same-origin and has no inbound links from
    // anywhere, so nothing legitimate arrives cross-site — and every route
    // behind this cookie changes authority (creating accounts, issuing grants),
    // which is precisely the shape that wants CSRF closed at the cookie rather
    // than mitigated by a token. Brief 03's session cookies are Lax because a
    // top-level navigation into an app must carry them; nothing navigates into
    // the console.
    "SameSite=Strict",
    ...(secure ? ["Secure"] : []),
  ].join("; ");
}

/**
 * The `Set-Cookie` value for a new console session.
 *
 * **A session cookie: no `Max-Age`, no `Expires`.** Two reasons. It dies when
 * the browser closes, which is right for break-glass. And the server-side idle
 * timeout is the only deadline that matters, so publishing a second one to the
 * browser would mean two clocks to keep in agreement — with the sliding idle
 * window it would need re-sending on every response, and a stale copy would let
 * the browser hold a cookie the server has already forgotten.
 */
export function consoleSessionSetCookie(token: string, options: { secure: boolean }): string {
  return `${CONSOLE_COOKIE_NAME}=${encodeURIComponent(token)}; ${attributes(options.secure)}`;
}

/**
 * The `Set-Cookie` value that removes it. The attributes must match the ones it
 * was set with — `Path` in particular — or the browser deletes nothing and keeps
 * sending the old cookie.
 */
export function consoleSessionClearCookie(options: { secure: boolean }): string {
  return `${CONSOLE_COOKIE_NAME}=; ${attributes(options.secure)}; Max-Age=0`;
}
