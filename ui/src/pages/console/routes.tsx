/**
 * The whole admin console, as one element.
 *
 * ## The contract with brief 09
 *
 * This file is the only thing the two UI briefs share. Brief 09 owns the router
 * and the design tokens; brief 10 owns everything under `pages/console/` and
 * exports it here as a single `<ConsoleRoutes />`, which brief 09 mounts under
 * `/console` inside a wrapper carrying `data-ward-surface="console"`. Neither
 * brief edits a file the other owns.
 *
 * **This component does not declare nested `<Route>`s.** A descendant `<Routes>`
 * with relative paths only matches deeper URLs when the parent route was
 * declared with a splat, and the contract does not say whether it was — getting
 * that wrong yields a console that renders blank for every URL but its index,
 * discovered only at integration. So the pathname is parsed here instead (see
 * `nav.ts`), which works under `path="/console/*"`, under `path="/console"`, and
 * inside a layout route alike. The only thing it needs from the router is
 * `useLocation`.
 *
 * ## It is superuser-only, and there is no second path
 *
 * There is exactly one console credential and therefore exactly one
 * administrator, permanently (`corpus/wiki/decisions-admin.md`). Nothing here
 * checks *which* identity got through, because there is only one, and nothing
 * here offers an alternative way in. An ordinary account's access token cannot
 * open any of it: the API's console session is not a JWT at all, so the
 * credentials of the estate's apps are not the same kind of thing as the
 * credential for this surface.
 *
 * ## Why nothing polls
 *
 * `GET /console/session` slides the server's idle window, so a UI polling it on
 * a timer would keep the estate's break-glass session alive indefinitely and
 * quietly delete the 15-minute idle timeout. The countdown in the top bar is
 * therefore computed locally and moved forward only by real requests — see
 * `session.tsx`.
 */

import { useCallback, useEffect, useRef, useState } from "react";
import { Link, useLocation } from "react-router-dom";

import { consoleApi, type ConsoleSessionView } from "../../console-api.js";
import "./console.css";
import { AccountDetailScreen } from "./AccountDetail.js";
import { AccountsScreen } from "./Accounts.js";
import { AppDetailScreen } from "./AppDetail.js";
import { AppsScreen } from "./Apps.js";
import { AuditScreen } from "./Audit.js";
import { ConsoleLogin } from "./Login.js";
import { consoleHref, parseConsoleLocation, railSectionFor, type ConsoleView } from "./nav.js";
import { sessionRemaining } from "./format.js";
import { ConsoleProvider, useConsoleContextValue } from "./session.js";
import { useAnnounce } from "./ui.js";

/** How often the countdown re-renders. Nothing is fetched on this tick. */
const TICK_MS = 10_000;

/** Said both when a request comes back `401` and when the local clock runs out first. */
const IDLE_TIMEOUT_MESSAGE =
  "The console session ended — it idled out, hit its four-hour ceiling, or Ward was restarted. Sign in again.";

export function ConsoleRoutes(): React.JSX.Element {
  const location = useLocation();
  const { basePath, view } = parseConsoleLocation(location.pathname);

  /** `undefined` while the first `GET /session` is in flight. */
  const [session, setSession] = useState<ConsoleSessionView | null | undefined>(undefined);
  const [signedOutBecause, setSignedOutBecause] = useState<string | undefined>(undefined);
  const [now, setNow] = useState(() => Date.now());
  const { announce, region } = useAnnounce();

  // Is there already a live session? Asked once, on mount. A `401` here is the
  // ordinary case — an operator arriving at the console cold — and not an error
  // worth showing.
  useEffect(() => {
    let live = true;
    consoleApi.session().then(
      (value) => {
        if (live) setSession(value);
      },
      () => {
        if (live) setSession(null);
      },
    );
    return () => {
      live = false;
    };
  }, []);

  const onUnauthorized = useCallback(() => {
    setSession(null);
    setSignedOutBecause(IDLE_TIMEOUT_MESSAGE);
  }, []);

  /**
   * Move the local idle deadline forward by the window the server just moved it
   * by. Called after every successful console request, which is the only thing
   * that actually slides it server-side.
   */
  const touch = useCallback(() => {
    setSession((current) => {
      if (current === null || current === undefined) return current;
      const at = Date.now();
      return {
        ...current,
        lastSeenAt: new Date(at).toISOString(),
        idleExpiresAt: new Date(at + current.idleTimeoutSeconds * 1000).toISOString(),
      };
    });
  }, []);

  const context = useConsoleContextValue({ basePath, onUnauthorized, touch, announce });

  // The local deadline reached zero. The server would refuse the next request
  // anyway; saying so before the operator types into a form that will fail is
  // the honest order. This is derived at render rather than pushed into
  // `session` via an effect: the local clock running out doesn't need its own
  // `setState` call, only a render that treats the countdown as the console
  // treats a real `401` (see the `session === null || expiredLocally` check
  // below, and the matching `IDLE_TIMEOUT_MESSAGE` copy).
  const remaining =
    session === null || session === undefined ? undefined : sessionRemaining(session, now);
  const remainingSeconds = remaining?.seconds;
  const expiredLocally = remainingSeconds !== undefined && remainingSeconds <= 0;

  // The countdown. A render every ten seconds, no request. Stops for good
  // once the local deadline has passed — there is nothing left to count down
  // to, and `session` itself is left untouched (see above) rather than nulled
  // out just to make this effect's own dependency stop it.
  useEffect(() => {
    if (session === null || session === undefined || expiredLocally) return;
    const timer = setInterval(() => {
      setNow(Date.now());
    }, TICK_MS);
    return () => {
      clearInterval(timer);
    };
  }, [session, expiredLocally]);

  if (session === undefined) {
    return (
      <div className="wc" data-ward-surface="console">
        <div className="wc-hazard" />
        <div className="wc-main">
          <p className="wc-lede">Checking for a console session…</p>
        </div>
      </div>
    );
  }

  if (session === null || expiredLocally) {
    return (
      <ConsoleLogin
        notice={expiredLocally ? IDLE_TIMEOUT_MESSAGE : signedOutBecause}
        onSignedIn={(value) => {
          setSignedOutBecause(undefined);
          setSession(value);
          setNow(Date.now());
        }}
      />
    );
  }

  return (
    // The attribute is also on brief 09's wrapper. It is set here too because it
    // is what re-points the token palette, and a console that silently rendered
    // in the login page's light livery would be exactly the confusion the
    // separate identity exists to prevent.
    <div className="wc" data-ward-surface="console">
      <TopBar
        basePath={basePath}
        remaining={remaining}
        onSignedOut={() => {
          setSession(null);
          setSignedOutBecause("Signed out of the console.");
        }}
      />
      <div className="wc-hazard" />
      <ConsoleProvider value={context}>
        <div className="wc-body">
          <Rail basePath={basePath} view={view} />
          <main className="wc-main">
            <div className="wc-main-inner">
              <Screen view={view} basePath={basePath} />
            </div>
          </main>
        </div>
        {region}
      </ConsoleProvider>
    </div>
  );
}

function TopBar({
  basePath,
  remaining,
  onSignedOut,
}: {
  basePath: string;
  remaining: { text: string; low: boolean } | undefined;
  onSignedOut: () => void;
}): React.JSX.Element {
  const [busy, setBusy] = useState(false);
  const mounted = useRef(true);
  useEffect(() => {
    mounted.current = true;
    return () => {
      mounted.current = false;
    };
  }, []);

  return (
    <div className="wc-topbar">
      <p className="wc-wordmark">
        <Link to={consoleHref(basePath, { kind: "accounts" })}>Ward console</Link>
      </p>
      <span className="wc-standing">
        Break-glass credential — every route here changes authority
      </span>
      <div className="wc-topbar-right">
        {remaining === undefined ? null : (
          <span className="wc-countdown" data-low={remaining.low ? "true" : "false"}>
            Session {remaining.text}
          </span>
        )}
        <button
          type="button"
          className="wc-btn"
          disabled={busy}
          onClick={() => {
            setBusy(true);
            // `POST /console/logout` is ungated and idempotent, so a failure
            // here still leaves the console in a clean state: the cookie is
            // cleared by the response, and the UI drops to the gate either way.
            void consoleApi.logout().finally(() => {
              if (mounted.current) setBusy(false);
              onSignedOut();
            });
          }}
        >
          {busy ? "Signing out…" : "Sign out"}
        </button>
      </div>
    </div>
  );
}

function Rail({ basePath, view }: { basePath: string; view: ConsoleView }): React.JSX.Element {
  const current = railSectionFor(view);
  const entries: { section: "accounts" | "apps" | "audit"; label: string; view: ConsoleView }[] = [
    { section: "accounts", label: "Accounts", view: { kind: "accounts" } },
    { section: "apps", label: "Apps", view: { kind: "apps" } },
    { section: "audit", label: "Audit log", view: { kind: "audit" } },
  ];

  return (
    <nav className="wc-rail" aria-label="Console sections">
      {entries.map((entry) => (
        <Link
          key={entry.section}
          to={consoleHref(basePath, entry.view)}
          aria-current={current === entry.section ? "page" : undefined}
        >
          {entry.label}
        </Link>
      ))}
    </nav>
  );
}

function Screen({ view, basePath }: { view: ConsoleView; basePath: string }): React.JSX.Element {
  switch (view.kind) {
    case "accounts":
      return <AccountsScreen />;
    case "account":
      return <AccountDetailScreen subject={view.subject} />;
    case "apps":
      return <AppsScreen />;
    case "app":
      return <AppDetailScreen slug={view.slug} />;
    case "audit":
      return <AuditScreen />;
    case "unknown":
      return (
        <>
          <div className="wc-head">
            <h1>No such console page</h1>
          </div>
          <p className="wc-lede">
            <code>{view.rest.join("/")}</code> is not a console screen.{" "}
            <Link to={consoleHref(basePath, { kind: "accounts" })}>Go to accounts</Link>.
          </p>
        </>
      );
  }
}
