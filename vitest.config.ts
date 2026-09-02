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
    include: ["api/**/*.test.ts", "client/**/*.test.ts"],
    exclude: ["**/node_modules/**", "**/dist/**"],
    pool: "forks",
  },
});
