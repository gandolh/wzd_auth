---
summary: The locked engineering calls made while building — the raw better-sqlite3 driver and why Knex was rejected, scrypt over argon2id, the loopback bind default, and the WAL checkpoint that makes a database backup honest.
updated: 2026-09-02
---

# Decisions — implementation

The calls made *while building*, as distinct from the design calls that preceded
any code. Same bar as [decisions.md](./decisions.md): **hard to reverse**,
**surprising without context**, **a genuine trade-off** with real alternatives
that were rejected.

This page exists because [decisions.md](./decisions.md) is a design record and
was already near the corpus line cap when the first brief landed. Foundational
scope stays there; accounts in [decisions-accounts.md](./decisions-accounts.md),
sessions in [decisions-tokens.md](./decisions-tokens.md), privilege in
[decisions-admin.md](./decisions-admin.md).

## Raw `better-sqlite3`, not Knex
_2026-09-02, brief 00_ — Ward talks to SQLite through the driver directly.
Queries are written as SQL.

**Rejected: Knex**, which atrium uses and which would have been the estate's
path of least resistance. Atrium's own **D47** records what it cost there: three
correctness properties held only because two statements could not interleave,
and **all three broke** when a query builder made them able to. Ward's hot path
is session lookup under concurrency — every request from every app introspects —
so the property atrium lost is the property Ward most needs. `better-sqlite3` is
synchronous, which is not a limitation here but the mechanism: a statement
cannot interleave with another because there is no await point inside it.

The cost accepted: no query builder, so every query is hand-written SQL and
every schema change is a hand-written migration. At this schema's size — five
tables — that is a smaller cost than the class of bug it removes.

## Migrations are a static import list, never a directory scan
_2026-09-02, brief 00_ — `api/src/db/migrations/index.ts` holds a hand-maintained
array. Adding a migration means importing it and appending to that array.

A directory-scanning migration source reads files off disk at runtime and picks
a loader by extension. That does not survive this build: in development the
migrations are `.ts` executed by `tsx`, in production they are `.js` under
`dist/`, and `tsc` does not copy `.ts` sources into its output — so a scan finds
a **different set of files depending on how the process was started**. Listing
them statically means the compiler resolves them, they land in `dist/` like any
other module, and dev and production run byte-identical migration code.

Array order is run order; new entries go at the end. **Never rename or reorder
an applied entry** — the name is the recorded identity in `ward_migrations`, so
a rename re-runs a migration that has already been applied. This is enforced in
both directions by the runner, not merely documented.

## `node:crypto` scrypt for passwords, not argon2id
_2026-09-02, brief 00_ — Password hashing uses scrypt from Node's standard
library. No dependency is added for it.

**Rejected: argon2id**, which is the current recommendation and would be the
default answer to "what should hash these passwords". Three things decide it the
other way here. It is a native dependency, and Ward's whole value is being a
small service that six apps can rely on staying up — a native build that fails
on a Node upgrade takes the estate's login with it. Atrium already proves scrypt
works in this estate. And the [full prune](./decisions-accounts.md) means there
are **no existing hashes to migrate**, so nothing but taste constrains the
choice, in either direction.

The honest statement of the trade: argon2id resists GPU attack better, and for a
population of the owner plus a few known people behind a login page on one VPS,
that margin buys less than a zero-dependency standard-library primitive does.
Revisit if Ward ever holds accounts for strangers at volume — the prune means a
rehash-on-next-login migration is always available.

## Ward binds loopback by default
_2026-09-02, brief 00_ — `HOST` defaults to `127.0.0.1`. Caddy reverse-proxies
to it over loopback on the same box.

**Rejected: `0.0.0.0`**, which is what atrium does. Atrium's "Caddy is the only
way in" assumption therefore rests on the firewall alone — one misconfigured
rule and the API is directly reachable. Binding loopback makes that assumption
true in the kernel rather than in a policy file. Widening it is still one
explicit `HOST=` away for anyone who genuinely needs it.

## The database handle is closed on shutdown, and that is a backup decision
_2026-09-02, brief 00, found in review_ — `shutdown()` closes the SQLite handle
before exit. This looks like ordinary cleanup before `process.exit` and is not.

SQLite in WAL mode runs its checkpoint **on close**. Without that close,
committed data stays in `ward.db-wal` and the `ward.db` file itself can be
empty — measured at 4096 bytes with **zero tables** after a full
boot → serve → SIGTERM cycle, which is every pm2 restart and every deploy.

This matters because the operator is told, correctly, that the database "is the
only copy of who anybody is — back it up." A backup that copies `ward.db` alone
would have captured nothing and reported success. **Brief 11 must back up all
three files together** — `ward.db`, `ward.db-wal`, `ward.db-shm` — and must not
treat the sidecars as disposable while the process is running.

Recorded as a decision rather than a bug fix because the tempting cleanup —
"`process.exit` closes everything anyway, drop the redundant `close()`" — is
wrong for a reason nothing in the code makes visible.
