/**
 * Failed-attempt lockout, keyed on the client address.
 *
 * ## Keyed on IP, never on username — and that is the load-bearing part
 *
 * Newspapper's reasoning generalises: a username-keyed lockout hands any
 * stranger a way to lock a real person out of their own account indefinitely,
 * for free, by submitting wrong passwords for a name they read off a byline.
 * The measure that was supposed to protect the account becomes the attack. An
 * address-keyed counter costs the attacker their own connectivity instead, and
 * the population here is the owner plus a few known people, so a shared address
 * being throttled together is a cost worth paying.
 *
 * ## No artificial delay
 *
 * There is deliberately no `await sleep(...)` anywhere in this module or in its
 * callers. Holding a connection open for a second per failed attempt **is** the
 * denial of service the lockout exists to prevent: a few hundred concurrent
 * failures would occupy the event loop and Ward's socket budget while doing
 * nothing, and Ward is the runtime dependency of all six apps. Refuse
 * immediately with a `429` and a `Retry-After` and let the client wait.
 *
 * ## Fastify-free on purpose
 *
 * Nothing here imports Fastify, `config.js`, or the database. Brief 06 applies
 * the same counter to the superuser console login, and a shared module that
 * drags a web framework or the environment validation along with it would
 * couple two unrelated surfaces. The caller derives the key; `lockoutKeyFor`
 * below is offered as the one-liner for doing that correctly.
 *
 * ## In-memory, and it resets on restart
 *
 * State lives in one `Map` in this process. A restart therefore forgives every
 * counter, which is fine: the window is 15 minutes and a restart is not
 * something an attacker can cause. It is *not* fine to grow this into a table
 * without thinking — a write per failed login on the estate's only anonymous
 * endpoint is a much more attractive amplification target than a bounded map.
 */

/**
 * Failures tolerated before the next attempt is refused.
 *
 * Five, per the brief. Note how that reads on the wire: attempts 1–5 get a
 * `401`, and the **sixth** request is the one that earns the `429`, because the
 * check runs before the attempt rather than after it.
 */
export const LOCKOUT_MAX_FAILURES = 5;

/**
 * How long a counter survives, in seconds, and therefore how long a lockout
 * lasts once it trips.
 *
 * Every failure pushes the expiry out to `now + window`, so the window slides:
 * an attacker cannot sit on 5 failures and get a free attempt every 15 minutes
 * by timing them at the boundary.
 */
export const LOCKOUT_WINDOW_SECONDS = 15 * 60;

/**
 * Hard ceiling on tracked addresses.
 *
 * **An uncapped map is the memory-exhaustion DoS this module is supposed to be
 * defending against.** One failed login from each of a million spoofed
 * addresses is cheap to send and, uncapped, would be a million entries Ward
 * holds forever. With a cap, the worst an attacker achieves by flooding
 * addresses is evicting other addresses' counters — which is a *weaker* attack
 * than the one they already have (attempting logins directly), so the trade is
 * strictly in our favour.
 *
 * 10 000 entries is roughly a megabyte and far past what this estate sees.
 */
export const LOCKOUT_MAX_ENTRIES = 10_000;

/** The answer to "may this address attempt a login right now?". */
export interface LockoutDecision {
  allowed: boolean;
  /** Whole seconds, at least 1, and set **only** when `allowed === false`. */
  retryAfterSeconds?: number;
}

interface Entry {
  failures: number;
  /** Epoch milliseconds. The counter is gone once the clock passes this. */
  expiresAt: number;
}

/**
 * Insertion-ordered, which is what makes the eviction below an O(1) `next()`
 * on the iterator rather than a scan for the oldest key.
 */
const entries = new Map<string, Entry>();

/**
 * Whether `key` may attempt a login.
 *
 * Pure with respect to the counter — calling it does not record anything, so a
 * route may call it as its first line without that itself counting as an
 * attempt. It does drop the entry if the window has passed, which is the lazy
 * half of expiry (`recordFailure` does the bulk sweep).
 */
export function checkLockout(key: string): LockoutDecision {
  const now = Date.now();
  const entry = entries.get(key);

  if (entry === undefined) {
    return { allowed: true };
  }

  if (entry.expiresAt <= now) {
    entries.delete(key);
    return { allowed: true };
  }

  if (entry.failures < LOCKOUT_MAX_FAILURES) {
    return { allowed: true };
  }

  // `Math.max(1, ...)` because `Retry-After: 0` reads as "retry immediately",
  // which is the opposite of what a locked-out client should be told, and a
  // sub-second remainder floors to zero.
  const retryAfterSeconds = Math.max(1, Math.ceil((entry.expiresAt - now) / 1000));
  return { allowed: false, retryAfterSeconds };
}

/**
 * Count one failed attempt against `key`.
 *
 * Call this for **any** credential rejection — unknown username, wrong
 * password, wrong superuser password. Not for a malformed request body: that is
 * a client bug rather than a guess, and counting it means a broken integration
 * locks its own users out.
 */
export function recordFailure(key: string): void {
  const now = Date.now();
  const existing = entries.get(key);

  if (existing !== undefined && existing.expiresAt > now) {
    existing.failures += 1;
    existing.expiresAt = now + LOCKOUT_WINDOW_SECONDS * 1000;
    return;
  }

  // A new entry (or a resurrected expired one). Make room first so the map can
  // never exceed the cap, then insert — which also puts this key at the back of
  // the insertion order, where eviction reaches it last.
  entries.delete(key);
  makeRoom(now);
  entries.set(key, { failures: 1, expiresAt: now + LOCKOUT_WINDOW_SECONDS * 1000 });
}

/**
 * Forget `key`'s failures. Called on every **successful** authentication.
 *
 * Without this, a person who mistypes their password four times and then gets
 * it right stays one failure away from a lockout for the next quarter of an
 * hour — the counter has to mean "unexplained failures", not "failures".
 */
export function clearFailures(key: string): void {
  entries.delete(key);
}

/**
 * Drop all state. **Tests only** — nothing in the running service calls it.
 *
 * The map is module-level, so without this a test that earns a `429` from
 * `127.0.0.1` leaves the next test in the same worker locked out. Call it in a
 * `beforeEach`.
 */
export function resetLockoutForTests(): void {
  entries.clear();
}

/**
 * The number of tracked addresses. Exported for the cap test; not a metric.
 */
export function lockoutEntryCountForTests(): number {
  return entries.size;
}

/**
 * Evict until there is space for one more entry: expired first, then oldest.
 */
function makeRoom(now: number): void {
  if (entries.size < LOCKOUT_MAX_ENTRIES) return;

  for (const [key, entry] of entries) {
    if (entry.expiresAt <= now) entries.delete(key);
  }

  // Still full: every entry is live, so this is a flood. Evict from the front,
  // which is the least recently *created* key. Losing a live counter is
  // acceptable (see LOCKOUT_MAX_ENTRIES); an unbounded map is not.
  while (entries.size >= LOCKOUT_MAX_ENTRIES) {
    const oldest = entries.keys().next();
    if (oldest.done === true) break;
    entries.delete(oldest.value);
  }
}

/**
 * The lockout key for an HTTP request, given the socket peer and whatever
 * `X-Forwarded-For` arrived.
 *
 * ## Why this is not just `request.ip`
 *
 * Ward binds loopback and Caddy reverse-proxies `/ward-api/*` to it, so
 * **every** request's socket peer is `127.0.0.1`. Fastify's `request.ip` is the
 * socket peer unless `trustProxy` is configured, and it is not — so keying on
 * `request.ip` would give the entire internet one shared counter, and the sixth
 * failed login anywhere in the estate would lock out everybody. That is a
 * self-inflicted outage dressed as a security control.
 *
 * ## Why trusting the header here is safe, and only here
 *
 * The header is honoured **only when the peer is loopback**. On this box
 * loopback means the request came through Caddy, and Caddy *appends* the peer
 * it observed to any inbound `X-Forwarded-For`. So the **last** element is the
 * address Caddy actually saw, and a client that sends
 * `X-Forwarded-For: 1.2.3.4` to spoof its way out of a lockout only succeeds in
 * prepending a value nobody reads. Taking the first element — the usual
 * "original client" convention — would be exactly the spoofable choice.
 *
 * If the peer is *not* loopback then Ward is reachable directly, the header has
 * no trusted proxy behind it, and it is ignored entirely in favour of the real
 * socket address.
 *
 * @example
 * const key = lockoutKeyFor(request.socket.remoteAddress, request.headers["x-forwarded-for"]);
 */
export function lockoutKeyFor(
  socketAddress: string | undefined | null,
  forwardedFor: string | string[] | undefined,
): string {
  const peer = normaliseAddress(socketAddress);

  if (peer !== undefined && !isLoopback(peer)) {
    return peer;
  }

  const forwarded = lastForwardedAddress(forwardedFor);
  if (forwarded !== undefined) {
    return forwarded;
  }

  // No usable address at all — a Unix socket, or a peer the runtime did not
  // report. One shared bucket is the safe fallback: it throttles rather than
  // letting the attempt through uncounted.
  return peer ?? "unknown";
}

function lastForwardedAddress(forwardedFor: string | string[] | undefined): string | undefined {
  if (forwardedFor === undefined) return undefined;

  // Node collapses repeated headers into an array for most headers; joining and
  // re-splitting handles both shapes with one code path.
  const flat = Array.isArray(forwardedFor) ? forwardedFor.join(",") : forwardedFor;
  const parts = flat
    .split(",")
    .map((part) => normaliseAddress(part))
    .filter((part): part is string => part !== undefined);

  return parts.length > 0 ? parts[parts.length - 1] : undefined;
}

/**
 * Trim, strip an IPv6 zone or an IPv4-mapped prefix, lowercase.
 *
 * `::ffff:127.0.0.1` and `127.0.0.1` are the same address and must not be two
 * counters — otherwise an attacker gets 2× the attempts by picking a stack.
 */
function normaliseAddress(address: string | undefined | null): string | undefined {
  if (address === undefined || address === null) return undefined;

  let value = address.trim().toLowerCase();
  if (value.length === 0) return undefined;

  // `[::1]:1234` and `[::1]` — some proxies bracket IPv6 in X-Forwarded-For.
  const bracketed = /^\[([^\]]+)\](?::\d+)?$/.exec(value);
  if (bracketed?.[1] !== undefined) value = bracketed[1];

  if (value.startsWith("::ffff:")) value = value.slice("::ffff:".length);

  // An IPv6 scope id (`fe80::1%eth0`) is not part of the address identity.
  const percent = value.indexOf("%");
  if (percent !== -1) value = value.slice(0, percent);

  return value.length > 0 ? value : undefined;
}

function isLoopback(address: string): boolean {
  return address === "::1" || address === "127.0.0.1" || address.startsWith("127.");
}
