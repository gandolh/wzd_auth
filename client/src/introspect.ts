import { WardConfigurationError, WardUnavailableError } from "./errors.js";
import { DEFAULT_INTROSPECTION_CACHE_TTL_MS } from "./claims.js";
import type { SessionResolution } from "./session.js";

/**
 * Asking Ward whether a session is live and what it may do, with the caching
 * and stampede-collapsing every one of six apps needs identically.
 *
 * `corpus/wiki/decisions-tokens.md`: local verification establishes
 * *authentication*; this establishes *liveness and authority*, and each app
 * caches that answer briefly. **30 seconds is the number that matters** — it
 * is what a revocation waits on, and it is a completely different cache from
 * `verify.ts`'s JWKS cache (see that file's header for why conflating the two
 * is the mistake to avoid).
 */

export interface IntrospectorOptions {
  /**
   * Ward's `POST /introspect` endpoint, fully qualified — e.g.
   * `new URL("/ward-api/introspect", "https://gandolh.ro")`, or
   * `http://127.0.0.1:PORT/introspect` against a local test server.
   */
  introspectUrl: URL;
  /**
   * This app's Ward app key — the value of Ward's `x-ward-app-key` header.
   *
   * **Required, and there is no default.** `POST /introspect` refuses every
   * request that does not carry one, so an app without a key cannot
   * authenticate anybody at all. It is required rather than optional
   * specifically so that omitting it is a compile error in the consuming app
   * rather than a `401` discovered in production: a missing key is not a
   * degraded mode, it is a total outage for that app, and the type system is
   * the cheapest place to catch it.
   *
   * Issued from Ward's console (`POST /console/apps/:slug/keys`) and shown
   * exactly once. It is a **secret** and belongs in the app's server-side
   * environment — never in a bundle, a client-side config object, or anything
   * a browser receives.
   */
  appKey: string;
  /** Injectable fetch — the seam that lets a test point this at a local server, or a staging Ward. Defaults to the global `fetch`. */
  fetch?: typeof fetch;
  /** How long a resolved answer is trusted, per token. Defaults to `DEFAULT_INTROSPECTION_CACHE_TTL_MS` (30s) — do not raise this in production. */
  cacheTtlMs?: number;
  /** Request timeout in ms. Defaults to 5000. */
  timeoutMs?: number;
  /** Clock, injectable for tests. Defaults to `Date.now`. Vitest fake timers intercept `Date.now` directly, so this rarely needs overriding. */
  now?: () => number;
}

interface CacheEntry {
  result: SessionResolution;
  expiresAt: number;
}

/**
 * A `token -> introspect()` function with a private 30-second cache and
 * in-flight collapsing, keyed **per token** (not per subject or session id):
 * two different tokens — even for the same session — never share a cache
 * entry, because each token is independently verified and this cache only
 * ever holds an answer this instance actually received for that exact value.
 *
 * ## Fail closed, always
 *
 * When the underlying request fails — a network error, a timeout, or any
 * response that is not Ward's documented `200` — this throws
 * `WardUnavailableError` and **does not** fall back to an expired cache entry.
 * Ward being unreachable already means nobody can log in; serving a stale
 * "was live 40 seconds ago" answer would additionally mean revocation stops
 * working exactly when Ward is in the worst shape to notice. A `500` is
 * treated identically to a network error — Ward's own contract is "always
 * `200`", so anything else means Ward is broken, never that the session died.
 *
 * ## Stampede collapsing
 *
 * Concurrent calls for the same (still-uncached) token share one in-flight
 * request rather than each issuing their own — the scenario the brief calls
 * out by name: fifty requests hitting a cold token on six apps must not become
 * six stampedes against Ward.
 */
export function createIntrospector(
  options: IntrospectorOptions,
): (token: string) => Promise<SessionResolution> {
  const fetchImpl = options.fetch ?? fetch;
  const cacheTtlMs = options.cacheTtlMs ?? DEFAULT_INTROSPECTION_CACHE_TTL_MS;
  const timeoutMs = options.timeoutMs ?? 5_000;
  const now = options.now ?? Date.now;

  const cache = new Map<string, CacheEntry>();
  const inflight = new Map<string, Promise<SessionResolution>>();

  async function callWard(token: string): Promise<SessionResolution> {
    let response: Response;
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), timeoutMs);
    try {
      try {
        response = await fetchImpl(options.introspectUrl, {
          method: "POST",
          headers: {
            "content-type": "application/json",
            // The app's own credential, distinct from the user's token in the
            // body below. Ward checks this first and refuses before doing any
            // work on an unauthenticated caller's behalf.
            "x-ward-app-key": options.appKey,
          },
          body: JSON.stringify({ accessToken: token }),
          signal: controller.signal,
        });
      } catch (cause) {
        throw new WardUnavailableError("introspection request failed", { cause });
      }
    } finally {
      clearTimeout(timer);
    }

    // Ward's contract is "always 200, always cache-control: no-store". Any
    // other status — a 500 included — means Ward is broken, not that the
    // session is dead. See the class comment: this must fail closed, not read
    // as `active: false`.
    // A 401 is the one status with a specific cause worth naming: Ward
    // received the request and rejected *this app's* key. Retrying will not
    // help and Ward is not down — the key is absent, wrong, or revoked.
    // `WardConfigurationError` extends `WardUnavailableError`, so this still
    // fails closed everywhere the broader class already did.
    if (response.status === 401) {
      throw new WardConfigurationError(
        "Ward rejected this app's key (401). Check WARD_APP_KEY: it is absent, wrong, or has been revoked in Ward's console.",
      );
    }

    if (response.status !== 200) {
      throw new WardUnavailableError(`introspect returned unexpected status ${response.status}`);
    }

    let body: unknown;
    try {
      body = await response.json();
    } catch (cause) {
      throw new WardUnavailableError("introspect response was not valid JSON", { cause });
    }

    if (
      typeof body !== "object" ||
      body === null ||
      typeof (body as { active?: unknown }).active !== "boolean"
    ) {
      throw new WardUnavailableError("introspect response did not match Ward's contract");
    }

    const parsed = body as {
      active: boolean;
      subject?: unknown;
      username?: unknown;
      grants?: unknown;
    };

    if (!parsed.active) return { active: false };

    if (typeof parsed.subject !== "string" || typeof parsed.username !== "string") {
      throw new WardUnavailableError("introspect response was active but missing subject/username");
    }

    return {
      active: true,
      subject: parsed.subject,
      username: parsed.username,
      grants: (parsed.grants as Record<string, string[]>) ?? {},
    };
  }

  return function introspect(token: string): Promise<SessionResolution> {
    const cached = cache.get(token);
    if (cached && cached.expiresAt > now()) {
      return Promise.resolve(cached.result);
    }

    const existing = inflight.get(token);
    if (existing) return existing;

    const promise = callWard(token)
      .then((result) => {
        cache.set(token, { result, expiresAt: now() + cacheTtlMs });
        return result;
      })
      .finally(() => {
        inflight.delete(token);
      });

    inflight.set(token, promise);
    return promise;
  };
}
