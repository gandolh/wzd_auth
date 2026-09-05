import { BrowserRouter, Link, Navigate, Route, Routes } from "react-router-dom";

import { Threshold } from "./components/Threshold.js";
import { WARD_BASENAME } from "./lib/next.js";
import { Account } from "./pages/Account.js";
import { Login } from "./pages/Login.js";
import { Register } from "./pages/Register.js";
import { Verify } from "./pages/Verify.js";
import { ConsoleRoutes } from "./pages/console/routes.js";
import "./ward.css";

/**
 * Ward's router. Brief 09 owns this file.
 *
 * ## The contract with brief 10
 *
 * **Brief 10 owns everything under `pages/console/` and exposes it as one
 * `<ConsoleRoutes />`**; this file mounts it under `/console/*` and wraps that
 * subtree in `data-ward-surface="console"` so the console tokens apply. Neither
 * brief edits a file the other owns to add a screen, and nothing here reaches
 * into the console's pages.
 *
 * The wrapper is a `<div>` rather than an attribute on something the console
 * renders, because the token re-pointing has to be an **ancestor** of every
 * console element for `var(--ward-*)` to resolve to the dark palette. Putting
 * it here also means the console cannot forget it, and brief 10's own reasoning
 * for the dark surface is a safety property — someone reaching for break-glass
 * should be able to see that they have — so it should not depend on every
 * console page remembering a class name.
 *
 * ## The basename
 *
 * `/ward`, matching Vite's `base`. So `<Link to="/login">` navigates to
 * `/ward/login`. Two consequences that cost time when forgotten:
 *
 * - Router paths in this app are written **without** the `/ward` prefix. See
 *   `loginRouteFor` versus `loginUrlFor` in `lib/next.ts`; the two exist
 *   because mixing them produces `/ward/ward/login`.
 * - A redirect to somewhere *outside* this SPA — which is what `?next=` almost
 *   always is — must be `window.location.assign`, not a router navigation.
 *   React Router would render a 404 inside Ward instead of leaving it.
 *
 * ## Why the entry route is the login page
 *
 * `/ward` alone lands on `/ward/login`. The alternative — introspect, then
 * choose between the account page and the login form — costs a request on the
 * one path that has to be fast, and gets it wrong for the overwhelmingly
 * common case, which is somebody arriving here because an app sent them.
 * `/ward/account` handles a signed-out visitor perfectly well on its own.
 */
export function App(): React.JSX.Element {
  return (
    <BrowserRouter basename={WARD_BASENAME}>
      <Routes>
        <Route path="/" element={<Navigate to="/login" replace />} />
        <Route path="/login" element={<Login />} />
        <Route path="/register" element={<Register />} />
        <Route path="/verify" element={<Verify />} />
        <Route path="/account" element={<Account />} />
        <Route
          path="/console/*"
          element={
            <div data-ward-surface="console">
              <ConsoleRoutes />
            </div>
          }
        />
        <Route path="*" element={<NotFound />} />
      </Routes>
    </BrowserRouter>
  );
}

/**
 * A 404 inside Ward, which in practice means a mistyped URL or a stale link.
 *
 * It offers sign-in rather than a link to every page, because there are only
 * four pages and three of them need something a person arriving by mistake does
 * not have: an app slug, a verification token, or a session.
 */
function NotFound(): React.JSX.Element {
  return (
    <Threshold>
      <h1>Nothing here</h1>
      <p className="ward-lede">
        That address isn&apos;t one of Ward&apos;s pages. If you were on your way somewhere, sign in
        and you&apos;ll be sent on.
      </p>
      <p className="ward-prose">
        <Link className="ward-link" to="/login">
          Sign in
        </Link>
      </p>
    </Threshold>
  );
}
