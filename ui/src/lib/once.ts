/**
 * Run an async operation **at most once per key**, sharing the result.
 *
 * This exists for one specific bug, and it is not a hypothetical one.
 *
 * `GET /ward-api/verify` **spends** its token: it marks the address confirmed
 * and deletes the row, so a second call answers `invalid_token`. `main.tsx`
 * runs under `StrictMode`, which double-invokes effects in development
 * precisely to surface effects that are not safe to run twice — so the naive
 * `Verify` page reports "this link is not valid" for a link that worked
 * perfectly one millisecond earlier. The same shape threatens `/refresh`,
 * where two concurrent rotations are the multi-tab race that cost brief 03 two
 * review rounds.
 *
 * The memo is **per key and permanent for the page's lifetime**, which is the
 * opposite of the de-duplication in `session.ts`: there, the in-flight promise
 * is cleared once it settles, because reading a session again should ask again.
 * Here, asking again is the bug. A key that has been spent stays spent.
 *
 * Failures are memoised too, deliberately. A rejected verification means the
 * token was consumed or was never valid; retrying it cannot succeed, and a
 * caller that retried would spend another attempt against an endpoint fed by
 * whatever was in somebody's URL bar.
 *
 * Kept as a standalone function rather than inline in the page because it is
 * the whole correctness argument for that page, and a correctness argument
 * that cannot be tested without a DOM is a comment.
 */
export function onceByKey<K, V>(operation: (key: K) => Promise<V>): (key: K) => Promise<V> {
  const started = new Map<K, Promise<V>>();
  return (key: K): Promise<V> => {
    let attempt = started.get(key);
    if (attempt === undefined) {
      attempt = operation(key);
      started.set(key, attempt);
    }
    return attempt;
  };
}
