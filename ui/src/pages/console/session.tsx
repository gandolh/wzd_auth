/**
 * The console's session, and the two hooks every screen uses to talk to Ward.
 *
 * ## Why the session lives here and not in each screen
 *
 * A dead console session is not a per-screen error. If each screen rendered its
 * own "unauthorized" message, an operator would be left clicking around a
 * console that can no longer do anything, reading a different flavour of the
 * same failure on every page. So a `401` from anywhere unwinds to one place and
 * the whole console drops back to its sign-in screen with the reason stated.
 *
 * ## The countdown, and why nothing polls
 *
 * The console session has a sliding 15-minute idle window and a fixed absolute
 * lifetime, both enforced server-side. `GET /console/session` reports them —
 * and **touching it slides the idle window**, which means a UI that polled it
 * on a timer would keep the estate's break-glass session alive forever and
 * quietly delete the idle timeout. So this polls nothing.
 *
 * Instead every successful console request calls {@link ConsoleContext.touch},
 * which moves the local deadline forward by exactly the window the server just
 * moved it by. Real activity keeps the session alive because real activity is
 * requests; an operator who walks away sees the countdown reach zero and is
 * asked to sign in again, which is what the server would have told them.
 */

import { createContext, useCallback, useContext, useMemo, useRef, useState } from "react";
import type { ReactNode } from "react";

import type { ConsoleSessionView } from "../../console-api.js";
import { isUnauthorized, messageFor, useLoadable, type Loadable } from "./ui.js";

interface ConsoleContextValue {
  /** Everything up to and including the `console` segment. Prefix every link. */
  basePath: string;
  /** Called on a `401`. Drops the console back to its sign-in screen. */
  onUnauthorized: () => void;
  /** Slide the local idle deadline; called after every successful request. */
  touch: () => void;
  /** Say what just happened, including "nothing changed". */
  announce: (message: string) => void;
}

const ConsoleContext = createContext<ConsoleContextValue | undefined>(undefined);

export function ConsoleProvider({
  value,
  children,
}: {
  value: ConsoleContextValue;
  children: ReactNode;
}): React.JSX.Element {
  return <ConsoleContext.Provider value={value}>{children}</ConsoleContext.Provider>;
}

export function useConsole(): ConsoleContextValue {
  const value = useContext(ConsoleContext);
  if (value === undefined) {
    // A programming error rather than a runtime condition: every console screen
    // is rendered inside the provider by `routes.tsx`.
    throw new Error("Ward console: a screen was rendered outside ConsoleProvider");
  }
  return value;
}

/**
 * Load a value for a screen, with the console's session handling applied.
 *
 * `key` is everything the load depends on, as one string — a subject, a slug, a
 * serialised filter. Changing it reloads; so does the returned `reload`, which
 * every mutation calls, because a console showing a stale grant tells an
 * operator that access was removed when it was not.
 */
export function useConsoleLoad<T>(
  key: string,
  load: () => Promise<T>,
): { result: Loadable<T>; reload: () => void } {
  // `touch` needs no "latest ref" idiom to stay fresh in `wrapped` below: it
  // comes from `routes.tsx`'s `useCallback(() => { setSession(...) }, [])`,
  // a stable identity for the console's lifetime, so it can simply be a
  // dependency like any other value `wrapped` closes over.
  const { onUnauthorized, touch } = useConsole();

  const wrapped = useCallback(async (): Promise<T> => {
    const data = await load();
    touch();
    return data;
  }, [load, touch]);

  return useLoadable(key, wrapped, onUnauthorized);
}

/**
 * Run a write, once at a time, and report what actually happened.
 *
 * `describe` turns the response into the sentence the operator reads, and it
 * takes the whole response on purpose: the API reports a no-op honestly
 * (`created:false`, `removed:0`, `changed:false`) and writes **no audit row**
 * for one, so the console has to be able to say "already so" rather than
 * claiming a change the log will not corroborate.
 */
export function useWriter(): {
  busy: boolean;
  error: string | undefined;
  clearError: () => void;
  run: <T>(action: () => Promise<T>, describe: (result: T) => string) => Promise<boolean>;
} {
  const { onUnauthorized, touch, announce } = useConsole();
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | undefined>(undefined);
  const inFlight = useRef(false);

  const run = useCallback(
    async <T,>(action: () => Promise<T>, describe: (result: T) => string): Promise<boolean> => {
      // Guarded against a double submit rather than relying on a disabled
      // button: on a surface where every write changes authority, two grants
      // issued by one impatient double-click is a confusing audit trail even
      // though the API itself is idempotent.
      if (inFlight.current) return false;
      inFlight.current = true;
      setBusy(true);
      setError(undefined);
      try {
        const result = await action();
        touch();
        announce(describe(result));
        return true;
      } catch (thrown) {
        if (isUnauthorized(thrown)) {
          onUnauthorized();
          return false;
        }
        setError(messageFor(thrown));
        return false;
      } finally {
        inFlight.current = false;
        setBusy(false);
      }
    },
    [announce, onUnauthorized, touch],
  );

  return {
    busy,
    error,
    clearError: useCallback(() => {
      setError(undefined);
    }, []),
    run,
  };
}

/** Build the context value once per identity of its parts. */
export function useConsoleContextValue(parts: ConsoleContextValue): ConsoleContextValue {
  const { basePath, onUnauthorized, touch, announce } = parts;
  return useMemo(
    () => ({ basePath, onUnauthorized, touch, announce }),
    [basePath, onUnauthorized, touch, announce],
  );
}

export type { ConsoleSessionView };
