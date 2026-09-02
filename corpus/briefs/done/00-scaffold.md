# Task 00 — Scaffold, rename, and the environment contract

## Context

The repo has a corpus and nothing else. This brief creates the service the other
fifteen build on, and renames the repo to match
[the decision](../../wiki/decisions.md#the-service-is-called-ward).

Two engineering choices are made here and must be **recorded as decisions** when
this lands, because both reverse a pattern used elsewhere in the estate:

- **Raw `better-sqlite3`, not Knex.** Atrium moved to Knex and its own D47
  records the cost: three correctness properties held only because two
  statements could not interleave, and all three broke. Ward's hot path is
  session lookup under concurrency. Synchronous is the safer default here.
- **`node:crypto` scrypt for passwords, not argon2.** Zero new dependencies,
  already proven in atrium. There are no hashes to migrate
  ([full prune](../../wiki/decisions-accounts.md)), so nothing constrains this
  but taste. Note argon2id as the considered alternative.

## Files you OWN

- The repo rename `wzd_auth` → `ward` (directory + `package.json` name)
- `package.json`, `tsconfig.base.json`, `.gitignore`, `.nvmrc`, `.env.example`
- `api/` — workspace scaffold, `src/index.ts`, `src/app.ts`, `src/config.ts`
- `ui/`, `client/` — empty workspace scaffolds only, no code
- `README.md`

## Files you must NOT touch

`corpus/**` except adding a `log.md` line. Every other brief's files.

## What to do

1. **Rename.** `git mv` the directory, update `package.json`. The service is
   Ward everywhere; `wzd_auth` survives nowhere.
2. **Three npm workspaces** — `api`, `ui`, `client` — ESM, Node ≥22, pinned
   exact dependency versions (estate convention, no carets).
3. **Fastify + `better-sqlite3`.** A migration runner using **static imports**,
   not a scanned directory — atrium's D47 records why a directory source breaks
   across `.ts` in dev and `.js` in `dist/`.
4. **`config.ts` validates the whole environment with zod at import and exits
   non-zero on anything missing or malformed.** No silent defaults. Atrium's D29
   exists because an app booted open with an empty library and never prompted.
   Required: `PORT`, `HOST`, `WARD_DB_PATH`, `WARD_ADMIN_USERNAME`,
   `WARD_ADMIN_PASSWORD`, `WARD_SIGNING_KEY_PATH`, `WARD_PUBLIC_ORIGIN`.
5. **`HOST` defaults to `127.0.0.1`, not `0.0.0.0`.** Atrium binds all
   interfaces and its "Caddy is the only way in" assumption rests on the
   firewall alone. Ward does not repeat that.
6. `GET /health` — the only route this brief adds.
7. `.env.example` documents every variable **and its reader**. A settable
   variable that changes nothing costs the next person an afternoon.

## Acceptance

- `npm run dev` boots; `GET /health` answers; a missing env var kills the boot
  with a message naming it.
- The process listens on loopback by default — verified, not assumed.
- No file, path, script or doc still says `wzd_auth`.
- Two decisions recorded: better-sqlite3-over-Knex, and scrypt-over-argon2.

---

## Outcome — landed 2026-09-02

Built by five parallel agents against pinned contracts, then reviewed by three
scoped finders and one fix round. All acceptance criteria met except the
directory rename, deferred by the owner (see below).

**What exists:** three npm workspaces (`api` with code, `ui` and `client` as
empty scaffolds), a zod-validated fail-closed environment contract, raw
`better-sqlite3` with a static-import migration runner, and `GET /health` on
loopback. Verified, not assumed: missing env var exits 1 naming the variable;
`ss` shows `127.0.0.1` only and an off-host curl is refused; a copy of `ward.db`
alone contains `ward_migrations` after a clean stop.

**Deviation — the repo directory is still `wzd_auth`.** The owner deferred the
rename because it moves the directory their editor and session are open in.
`package.json` is `ward` and no other file references the old name; one
deliberate note in `README.md` records that the directory has not moved yet.
Everything else in acceptance bullet 3 is met.

**Deviation — no test framework.** Brief 00 wired a `test` script but no runner,
so the loopback and fail-closed properties are verified by hand and nothing
guards them against regression. Brief 01 is the natural place to land a runner,
since it is the first brief with logic worth asserting on.

### Contracts for dependent briefs

```ts
// api/src/config.ts — importing this module validates the environment and can
// process.exit(1). All paths arrive absolute; do not re-resolve against cwd.
export const PORT, HOST, WARD_DB_PATH, WARD_ADMIN_USERNAME,
              WARD_ADMIN_PASSWORD, WARD_SIGNING_KEY_PATH, WARD_PUBLIC_ORIGIN;

// api/src/db/connection.ts
export function openDatabase(dbPath: string): Database.Database;  // pure, no config
export async function getDb(): Promise<Database.Database>;        // lazy singleton
export function closeDb(): void;                                  // checkpoints the WAL

// api/src/db/migrate.ts
export function runMigrations(db: Database.Database): void;       // synchronous

// api/src/db/migrations/index.ts
export interface Migration { name: string; up(db: Database.Database): void; }
export const MIGRATIONS: Migration[];   // ships EMPTY — brief 01 appends the baseline

// api/src/app.ts
export async function buildApp(): Promise<FastifyInstance>;       // no side effects
```

**`getDb()` is async on purpose** and this is the one contract most likely to
surprise. It resolves `WARD_DB_PATH` through a *dynamic* `import("../config.js")`
so that importing this module has no side effects — a static import is hoisted
and would run config's validation (and its `process.exit`) on a bare
`import { openDatabase }`, which is exactly what broke the first attempt. A test
that wants `:memory:` calls `openDatabase` directly and never touches config.

**Adding the baseline migration (brief 01):** create
`api/src/db/migrations/<UTC timestamp>-baseline.ts` exporting
`up(db): void`, import it in `migrations/index.ts` **with a `.js` suffix**, and
append to `MIGRATIONS`. `up()` runs inside a transaction the runner owns — a
nested `db.transaction()` is safe (SAVEPOINT), raw `BEGIN`/`COMMIT` is not, and
throwing is how it requests a rollback. Array order is run order; never rename
or reorder an applied entry, which the runner now enforces in both directions.

**Gotcha for any later table rebuild:** `PRAGMA foreign_keys` is a no-op inside
a transaction, so `up()` cannot disable FK enforcement for a 12-step rebuild.
Pure `CREATE TABLE` is unaffected.

**Registering a route (briefs 02–06):** write
`async function xRoutes(app: FastifyInstance)` and add
`await app.register(xRoutes)` inside `buildApp()`. Keep registration
side-effect-free so `buildApp()` stays callable in tests via `app.inject()`.
Boot order is config → db → migrations complete → listen; anything needing setup
(loading the signing key, warming JWKS) slots in after migrations, before listen.

### Review findings fixed before landing

Two Critical, both caught by review rather than by the gates:

1. **`.gitignore` did not cover the Ed25519 signing key** whose default path
   `.env.example` itself suggests (`api/data/signing-key.pem`). One `git add -A`
   would have committed the estate's only signing key. Now ignored by extension
   and directory; `.env.*` variants covered too.
2. **`db.close()` was never called on shutdown**, so SQLite never ran its
   close-time WAL checkpoint. Measured: `ward.db` at 4096 bytes with **zero
   tables** after a full boot→serve→SIGTERM cycle — every pm2 restart. A backup
   copying `ward.db` alone would have captured nothing and reported success.
   Recorded as a decision, since the fix looks like removable cleanup.

Also fixed: `openDatabase` was untestable by construction (see above); the
runner could not detect a renamed migration; the migration-author contract
stated a false constraint about nested transactions; `@types/node` was pinned
two majors ahead of the runtime.

**Accepted, not fixed:** no test framework (above); `typescript` pinned to
6.0.3 rather than 7.0.2 because `typescript-eslint` peer-requires `<6.1.0` —
revisit when that ecosystem catches up to the TS 7 native port.
