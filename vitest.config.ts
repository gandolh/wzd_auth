import { defineConfig } from "vitest/config";

/**
 * One Vitest project at the repo root rather than per-workspace configs.
 *
 * Ward's tests are all Node-side today and share one concern — the database
 * layer and the token layer both want a real `better-sqlite3` and a real
 * `jose`, not a browser environment — so a single root project keeps `npm test`
 * meaning one thing. `ui/` (brief 09) will need a different environment; when
 * it does, that is the moment to split this into projects, not before.
 *
 * `pool: "forks"` because `better-sqlite3` is a native addon: worker threads
 * sharing one addon instance across tests is the class of flake that is
 * miserable to debug, and process isolation costs a few hundred milliseconds
 * on a suite this size.
 */
export default defineConfig({
  test: {
    /**
     * `ui/` is included as of brief 09. The header above says a UI test suite
     * would be the moment to split this into projects — that moment has not
     * arrived, because **no DOM environment is configured and brief 09 did not
     * add one**: everything under `ui/` that is tested here is pure logic (the
     * `?next=` allowlist, the API error mapping, the retry-after formatting),
     * which runs in Node exactly as the API's tests do. The first component
     * test that needs a document is the thing that justifies `jsdom` and a
     * per-project environment; adding either before then would slow the whole
     * suite down for no coverage.
     */
    include: ["api/**/*.test.ts", "client/**/*.test.ts", "ui/**/*.test.ts", "ui/**/*.test.tsx"],
    exclude: ["**/node_modules/**", "**/dist/**"],
    pool: "forks",
  },
});
