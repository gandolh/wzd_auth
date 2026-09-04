import { ConsoleRoutes } from "./pages/console/routes.js";

/**
 * PLACEHOLDER — **brief 09 owns this file and replaces it.**
 *
 * It exists so the workspace typechecks while both UI briefs are being written
 * in parallel, and so the one contract between them is written down rather than
 * guessed at:
 *
 * **Brief 09 owns the router. Brief 10 owns everything under `pages/console/`
 * and exposes it as a single `<ConsoleRoutes />` element**, exported from
 * `pages/console/routes.tsx`. That way neither brief has to edit a file the
 * other owns to add a screen, and the console's routes stay the console's
 * business.
 *
 * Brief 09: mount `<ConsoleRoutes />` under `/console` inside your router, keep
 * the login/register/verify/account pages at the top level, and wrap the
 * console subtree in `data-ward-surface="console"` (see `tokens.css` — the
 * console is deliberately a different visual identity, which brief 10 states as
 * a safety property rather than a preference).
 */
export function App(): React.JSX.Element {
  return (
    <main>
      <p>Ward UI — not built yet. Brief 09 replaces this file.</p>
      <ConsoleRoutes />
    </main>
  );
}
