# Task 01 — Schema and data layer

## Context

Ward owns credentials, account identity and **grants**
([decision](../../wiki/decisions.md)). Every other brief reads and writes
through this layer. Nothing here is migrated from anywhere — the cutover is a
[full prune](../../wiki/decisions-accounts.md).

Read [glossary.md](../../wiki/glossary.md) first. **Subject**, **Grant**,
**Superuser** and **Owner account** all mean something specific, and the
superuser deliberately has **no row in any of these tables**.

## Files you OWN

- `api/src/db/**` — schema, migrations, and one module per table
- `api/src/db/migrations/**`

## Files you must NOT touch

`api/src/config.ts` (brief 00), every route file, `api/src/auth/**`.

## What to do

One baseline migration creating:

1. **`users`** — `subject` (opaque, primary identity, **never recycled**),
   `username` (unique, canonical identifier), `password_hash`, `email`
   (nullable), `email_verified`, `created_at`, `disabled_at`.
   The **subject is the contract** with six apps: stable forever, opaque, and
   reusing one silently hands one person's data to another. Generate it as 128+
   bits of randomness, not a counter.
2. **`apps`** — `slug` (`atrium`, `newspapper`, `prm`, …), `name`,
   `public_registration` (boolean, **default false** — closed by default), and
   the baseline role granted on self-signup.
3. **`grants`** — `(subject, app_slug, role)`. A person may hold **several roles
   in one app**, so this is a set: unique on all three columns together, not on
   `(subject, app_slug)`. Role strings are stored **opaquely**; Ward never
   interprets them.
4. **`refresh_tokens`** — `token_hash`, `subject`, `family_id`, `issued_at`,
   `expires_at`, `used_at`, `revoked_at`. Rotation and reuse detection (brief
   03) need the family; revoking is deleting or flagging rows here. **Store a
   hash of the token, never the token.**
5. **`verification_tokens`** — for public registration (brief 07). prm already
   ships an equivalent table; crib its shape.
6. **`audit_log`** — actor, action, target, timestamp, and enough context to
   answer "who granted this and when". The console surfaces it (brief 10).

Foreign keys **on**, enforced per connection. Pin the pool to one connection —
`foreign_keys` is per-connection and this is what keeps exclusivity.

## Acceptance

- A fresh database migrates cleanly; running the migration twice is safe.
- A subject collision is impossible in practice, and there is a test asserting
  two accounts never share one.
- Two roles for one person in one app is representable; a duplicate
  `(subject, app, role)` is rejected by the schema, not by application code.
- No table has a row for the superuser, and a comment in the schema says why.

---

## Outcome — landed 2026-09-02

Six tables in one baseline migration, plus a thin query module per table. All
acceptance criteria met, with tests for each. The implementing agent was killed
mid-run by a quota limit **after** finishing the work but **before** reporting,
so the contracts below were reconstructed from the code by the controller
rather than handed over — treat them as verified against source, not as an
author's summary.

### Tables

`users` · `apps` · `grants` · `refresh_tokens` · `verification_tokens` ·
`audit_log`, plus brief 00's `ward_migrations`.

### The load-bearing choices

- **`subject` is `randomBytes(16)`** — 128 bits, hex, CSPRNG, and the immutable
  PRIMARY KEY. A username rename does not touch it, which is the whole point of
  having it. `NewUser.subject` accepts an override, used only by test fixtures
  and reserved for the cutover; **brief 07 must not expose it to a caller.**
- **`grants` PRIMARY KEY is the full triple** `(subject, app_slug, role)`, so
  one person holds several roles in one app and a duplicate is refused by the
  database. Proven by a test that bypasses the module with a raw `INSERT`.
- **`users.username_folded`** is `NOT NULL UNIQUE`, folded NFKC + lowercase in
  JS. This folds beyond ASCII, which `COLLATE NOCASE` would not — so `Ärger`
  and `ärger` cannot become two accounts.
- **`apps.public_registration`** is `NOT NULL DEFAULT 0` at the DDL level, and a
  CHECK forbids opening registration without naming a `baseline_role`. The flag
  fails safe by construction, not by convention.
- **Tokens are stored as `sha256(token)`**, never the token. Unsalted SHA-256 is
  correct here specifically because the inputs are 256-bit random values — there
  is no low-entropy secret to stretch.
- **`audit_log` has no foreign keys at all**, deliberately: it must outlive what
  it describes, and its actor may be the superuser, which has no row anywhere.
- **Timestamps** are `strftime('%Y-%m-%dT%H:%M:%fZ','now')` in every table,
  byte-identical to JS `toISOString()`, so TEXT comparison sorts correctly.
  Keep this format for any new column; a mixed representation is a bug factory.
- **Rotation is atomic.** `claimRefreshToken` and `revokeFamily` are each a
  single `UPDATE ... WHERE ... RETURNING`. With one synchronous connection, two
  concurrent presentations of the same token cannot both succeed — which is
  what brief 03's reuse detection rests on.

### Review findings fixed before closeout

- **`grantTargetId` collided.** It joined components with `:`, but role strings
  are explicitly opaque and unrestricted — the tests deliberately grant one
  containing `:`. So two distinct triples could produce the same `target_id`,
  silently breaking the console's "everything that happened to this grant"
  filter, which is the one job `audit_log` exists to do. Now encoded
  unambiguously and round-trip tested. **The fix was to change the encoding, not
  to restrict what a role may contain** — role opacity is locked in
  [decisions-accounts.md](../../wiki/decisions-accounts.md).
- **`grants.granted_by` was nullable** while the schema comment promised it
  answers "who granted this" even if the log is pruned. Now `NOT NULL`, and
  `NewGrant.grantedBy` is required.

### Note for whoever edits the baseline

The baseline migration was **edited in place** during this fix round. That was
safe only because no persistent database existed yet — every applied copy was a
scratch database in a test. **It freezes the moment brief 11 deploys.** After
that, a schema change is a new migration appended to `MIGRATIONS`, never an edit
to this file: the runner records the name, so an edit to an applied migration is
silently skipped on every existing database.
