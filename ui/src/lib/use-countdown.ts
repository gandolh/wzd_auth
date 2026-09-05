import { useCallback, useSyncExternalStore } from "react";

/**
 * Seconds remaining until a wall-clock deadline, ticking down to zero.
 *
 * **The parameter is a deadline, not a duration**, and that is deliberate on
 * two counts.
 *
 * The first is drift. A `setInterval` that subtracts one every second drifts
 * under load and stops entirely when a background tab is throttled, so
 * somebody who switched away during a lockout would come back to a form still
 * telling them to wait four minutes. Recomputing the remainder from
 * `Date.now()` makes a throttled tab merely coarse rather than wrong, and it is
 * correct again the instant it wakes.
 *
 * The second is identity. A duration cannot restart a countdown that has
 * already run out: a second `429` carrying the same `retryAfterSeconds` is an
 * unchanged dependency, the effect does not re-run, and the submit button stays
 * enabled through a live lockout. A deadline is a different number every time,
 * so a fresh refusal always restarts the clock.
 *
 * `undefined` means no wait is in progress, and the hook then does nothing at
 * all — no timer, no state churn.
 */
export function useCountdown(deadline: number | undefined): number {
  // A wall clock counting down to `deadline` is exactly the "external system
  // that changes over time" `useSyncExternalStore` exists for: React needs to
  // be told both how to be notified something may have changed (`subscribe`)
  // and how to read the current value when it asks (`getSnapshot`). Neither
  // seeds state with a `setState` call of its own — there is no state here at
  // all — so there is nothing for `set-state-in-effect` to flag, and reading
  // `Date.now()` inside `getSnapshot` is the one place the render-purity rule
  // means to allow it: that function's whole job is reporting the current
  // value of something outside React.
  const subscribe = useCallback(
    (onStoreChange: () => void): (() => void) => {
      if (deadline === undefined) return () => {};
      // Twice a second, so the displayed number changes within half a second
      // of being true rather than up to a second late.
      const timer = setInterval(() => {
        if (Date.now() >= deadline) clearInterval(timer);
        onStoreChange();
      }, 500);
      return () => {
        clearInterval(timer);
      };
    },
    [deadline],
  );

  const getSnapshot = useCallback((): number => {
    if (deadline === undefined) return 0;
    return Math.max(0, Math.ceil((deadline - Date.now()) / 1000));
  }, [deadline]);

  return useSyncExternalStore(subscribe, getSnapshot);
}

/** A deadline `seconds` from now, for `useCountdown`. */
export function deadlineIn(seconds: number): number {
  return Date.now() + seconds * 1000;
}
