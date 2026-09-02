import { existsSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, resolve } from "node:path";
import { z } from "zod";

/**
 * Ward's runtime configuration: resolved from the environment once, validated
 * at import time, and exported as plain constants.
 *
 * Every variable is REQUIRED and nothing falls back to a working-but-wrong
 * value. That rule is inherited from atrium's D29, which exists because an app
 * in this estate booted happily with an empty library and never told anyone —
 * a service that starts misconfigured is worse than one that refuses to start,
 * because the failure surfaces days later as "where did my books go" instead
 * of immediately as a line on stderr. `HOST` is the single variable with a
 * default, and it defaults in the *safe* direction (see below), so an absent
 * value cannot widen Ward's exposure.
 *
 * Importing this module can terminate the process. That is deliberate: the
 * check has to happen before anything opens a socket or a database handle, and
 * an import is the only hook that is guaranteed to run first. Keep this module
 * dependency-free apart from zod — anything it imports would run before the
 * environment has been validated.
 *
 * The .env contract, including which module reads each variable, is documented
 * in `.env.example` at the repo root.
 */

/**
 * Anchor every path to this source file rather than `process.cwd()`. Under
 * `tsx` in development this file is `api/src/config.ts`; in production pm2
 * runs the build at `api/dist/config.js` — both sit one level below `api/`, so
 * the same two `resolve` calls land on the same directories either way. cwd
 * would not: pm2 sets it to whatever the ecosystem file says, and an operator
 * running a script from a subdirectory would silently get different paths.
 */
const HERE = dirname(fileURLToPath(import.meta.url)); // api/src (dev) or api/dist (built)
const API_ROOT = resolve(HERE, "..");
const REPO_ROOT = resolve(API_ROOT, "..");

/**
 * Load the single repo-root `.env` into process.env before validating.
 *
 * `process.loadEnvFile` is the Node ≥21 builtin — dotenv would be a dependency
 * that buys nothing here. Best-effort on purpose: in production the variables
 * come from pm2's environment rather than a file on disk, so a missing `.env`
 * is a normal state and not an error. The schema below is the real gate; this
 * is only a convenience for development.
 */
const ENV_FILE = resolve(REPO_ROOT, ".env");
if (existsSync(ENV_FILE)) {
  process.loadEnvFile(ENV_FILE);
}

/**
 * `.min(1)` on every string is not decoration: an unset variable and
 * `WARD_ADMIN_PASSWORD=` are the same mistake, and only the length check
 * catches the second one. Without it, an empty admin password would parse
 * cleanly and Ward would boot with a credential that anyone can guess by
 * submitting nothing.
 */
const envSchema = z.object({
  /** Loopback port Caddy reverse-proxies `/ward-api/*` to. */
  PORT: z.coerce.number().int().positive().max(65_535),

  /**
   * Defaults to loopback, and this is the one deliberate default in the file.
   *
   * Atrium binds `0.0.0.0` and its "Caddy is the only way in" assumption
   * therefore rests entirely on the VPS firewall — one `ufw` rule away from
   * the identity service for six apps being reachable from the internet
   * directly, bypassing every header and rate limit Caddy applies. Ward does
   * not repeat that: the kernel refuses off-host connections whether or not
   * the firewall is configured, so the two controls have to fail together
   * rather than one of them being load-bearing alone.
   *
   * Still overridable, because a container needs `0.0.0.0` to be reachable at
   * all — but that has to be an explicit, visible act in the `.env`, not the
   * behaviour you get by forgetting to set anything.
   */
  HOST: z.string().min(1).default("127.0.0.1"),

  /** better-sqlite3 database file. Relative values resolve against the repo root. */
  WARD_DB_PATH: z.string().min(1),

  /**
   * The break-glass superuser (decisions-admin.md). Environment-only, with no
   * row in any table — which is exactly why it belongs in this file and not in
   * a seed script: it is configuration, and it is the only credential that
   * still works when the database is empty, corrupted, or has had its last
   * admin removed.
   */
  WARD_ADMIN_USERNAME: z.string().min(1),
  WARD_ADMIN_PASSWORD: z.string().min(1),

  /** Ed25519 private key Ward alone holds. Relative values resolve against the repo root. */
  WARD_SIGNING_KEY_PATH: z.string().min(1),

  /**
   * The estate's single public origin. Validated as a *bare* origin —
   * scheme + host + optional port, nothing else — for two reasons.
   *
   * First, it becomes the `iss` claim on every access token (brief 02), and
   * `iss` is compared as an exact string by six verifiers. Ward minting
   * `https://gandolh.ro/` while an app expects `https://gandolh.ro` rejects
   * every token in the estate, with a mismatch that reads as "auth is broken"
   * rather than as a stray character. Trailing slashes are therefore stripped
   * before validation rather than rejected, since that one is a typo, not a
   * misunderstanding.
   *
   * Second, the name means what the glossary says it means: the browser's
   * origin, the thing that decides cookie scope. Someone setting the API base
   * URL (`https://gandolh.ro/ward-api`) here would produce tokens whose `iss`
   * looks plausible and cookies scoped to the wrong place — so a value
   * carrying a path is refused outright instead of being quietly trimmed to
   * its origin, because trimming would hide a genuine misunderstanding of
   * which URL was being asked for.
   */
  WARD_PUBLIC_ORIGIN: z
    .string()
    .min(1)
    .transform((value) => value.trim().replace(/\/+$/, ""))
    .refine(
      (value) => {
        let url: URL;
        try {
          url = new URL(value);
        } catch {
          return false;
        }
        return (url.protocol === "https:" || url.protocol === "http:") && url.origin === value;
      },
      {
        message:
          'must be a bare origin — scheme://host[:port], lowercase, with no path, query or fragment (e.g. "https://gandolh.ro")',
      },
    ),
});

const parsed = envSchema.safeParse(process.env);
if (!parsed.success) {
  const lines = parsed.error.issues.map(
    (issue) => `  - ${issue.path.join(".") || "(env)"}: ${issue.message}`,
  );
  /**
   * Fail fast and loudly. Written straight to stderr because the Fastify
   * logger does not exist yet, and boxed because this message is read at 2am
   * through a pm2 log tail where it has to be findable among restart noise.
   * Each line names the offending variable — an operator should not have to
   * diff `.env` against `.env.example` to learn which one is wrong.
   */
  console.error(
    "\n============================================================\n" +
      "  Ward: invalid or missing environment configuration.\n" +
      "  Set these variables (copy .env.example to .env) and retry:\n\n" +
      lines.join("\n") +
      "\n============================================================\n",
  );
  process.exit(1);
}

const env = parsed.data;

/** Read by `api/src/index.ts` to bind the Fastify listener. */
export const PORT: number = env.PORT;
export const HOST: string = env.HOST;

/**
 * Both file paths are resolved against the repo root rather than left as
 * given, so that everything downstream — better-sqlite3, the key loader, log
 * lines, error messages — deals in one unambiguous absolute path. A relative
 * `WARD_DB_PATH` that resolved against cwd would mean pm2 and a hand-run
 * script open two different database files while both look correct.
 */
/** Read today by `api/src/db/connection.ts` — `getDb()` opens the database at this path. */
export const WARD_DB_PATH: string = resolve(REPO_ROOT, env.WARD_DB_PATH);
/** Not read yet — reserved for `api/src/tokens/`, which brief 02 has not written. */
export const WARD_SIGNING_KEY_PATH: string = resolve(REPO_ROOT, env.WARD_SIGNING_KEY_PATH);

/**
 * Read by the console session code (brief 06). Note what these are NOT: they
 * are not an account, and nothing in this process should look them up, mirror
 * them into a table, or grant them anything. "Console only" falls out of the
 * superuser having no grants, not out of a check somewhere.
 */
export const WARD_ADMIN_USERNAME: string = env.WARD_ADMIN_USERNAME;
export const WARD_ADMIN_PASSWORD: string = env.WARD_ADMIN_PASSWORD;

/** Not read yet — reserved for token minting (brief 02), which will use it as the `iss` claim. */
export const WARD_PUBLIC_ORIGIN: string = env.WARD_PUBLIC_ORIGIN;
