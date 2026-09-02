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
