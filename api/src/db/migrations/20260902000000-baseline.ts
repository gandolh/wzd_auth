import type Database from "better-sqlite3";

/**
 * The baseline schema: every table Ward has.
 *
 * ## Conventions that hold across all six tables
 *
 * **Every table is `STRICT`.** SQLite's default is dynamic typing — a `TEXT`
 * column happily stores the integer `1`, and a `TEXT` timestamp column happily
 * stores a millisecond epoch that sorts correctly against nothing else in the
 * table. Ward's rows are read by six apps and by a human with the sqlite3 CLI
 * open at 3am; a column that says TEXT holding TEXT is worth the one line.
 *
 * **Timestamps are ISO-8601 UTC strings**, defaulted with
 * `strftime('%Y-%m-%dT%H:%M:%fZ','now')`, which produces byte-identical output
 * to JavaScript's `new Date().toISOString()`. That format sorts lexicographically
 * in the same order it sorts chronologically, so `ORDER BY` needs no conversion,
 * and it is the format `ward_migrations.applied_at` already uses. A nullable
 * timestamp is the estate's "has this happened yet" flag — `used_at`,
 * `revoked_at`, `disabled_at`, `consumed_at` — because it answers *when* as well
 * as *whether*, and the audit trail wants both.
 *
 * **Booleans are `INTEGER` constrained to `(0, 1)`.** SQLite has no boolean
 * type, and `better-sqlite3` refuses to bind a JavaScript boolean, so every
 * writer passes `0` or `1`; the CHECK is what stops a `2` from being written by
 * hand and read back as truthy forever after.
 *
 * ## WHY THE SUPERUSER HAS NO ROW IN ANY TABLE BELOW
 *
 * Ward has two privileged identities and they are deliberately not the same
 * thing (`corpus/wiki/decisions-admin.md`):
 *
 *  - The **superuser** is `WARD_ADMIN_USERNAME` / `WARD_ADMIN_PASSWORD` in
 *    Ward's `.env`. It is break-glass. **It has no `users` row, no subject and
 *    no grants**, and no migration below seeds one.
 *  - The **owner account** is an ordinary `users` row holding explicit admin
 *    grants across every app. That is the daily driver.
 *
 * Seeding a first-admin row on first boot is the obvious design and was
 * rejected on purpose. A row can be disabled, revoked, or deleted — by a
 * mistaken click in the console this schema exists to serve — and a recovery
 * mechanism that can be locked out is not a recovery mechanism. Keeping the
 * superuser in the environment means it still works when this database is
 * empty, corrupt, or has had its last admin removed. Because access in this
 * estate *is* a grant and the superuser has none, "the superuser can administer
 * Ward and reach nothing else" needs no enforcement code: it is what the absence
 * of a row already means.
 *
 * Two consequences are visible in the DDL and are not oversights:
 * `grants.granted_by` and `audit_log.actor_subject` are **not** foreign keys
 * into `users`, because the actor of a grant is very often an identity that has
 * no row to point at. If a later migration ever adds those constraints, it will
 * make the superuser's own actions unrecordable.
 *
 * If you are here to add a "seed the admin" migration: read
 * `corpus/wiki/decisions-admin.md` first, and revisit that decision explicitly
 * rather than around it.
 */
export function up(db: Database.Database): void {
  // ---------------------------------------------------------------------
  // users — one row per account. The subject is the estate-wide contract.
  // ---------------------------------------------------------------------
  //
  // `subject` is the primary key rather than a surrogate integer because it is
  // the only identifier that leaves this service: six apps key their own rows
  // on it and those rows outlive everything else about the account. It is
  // opaque (128 bits of `randomBytes`, see `../users.ts`), stable across a
  // username change, and **never recycled** — reissuing a subject silently
  // hands one person's reading history, notes and favourites to another, and no
  // app can detect that happening. Making it the PRIMARY KEY means the database
  // itself refuses a second row with the same subject, so a broken generator is
  // a loud failure rather than a quiet data leak.
  //
  // `username` is the canonical identifier (decisions-accounts.md, Q13): atrium
  // and newspapper already key on it, and email identifies nobody here because
  // it is optional. `username_folded` carries the uniqueness constraint instead
  // of `username` itself so that `Alice` and `alice` collide. It is written by
  // `../users.ts` as `username.normalize("NFKC").toLowerCase()` — JavaScript's
  // fold rather than SQLite's `lower()` or a `COLLATE NOCASE` index, both of
  // which only fold ASCII A–Z and would let `Ä`/`ä` register twice. Being NOT
  // NULL is the safety net: a writer that forgets to fold fails loudly at the
  // insert instead of quietly disabling the constraint.
  //
  // `email` is nullable on purpose. It is collected and verified only on the
  // public registration path; accounts the owner issues skip it entirely, and
  // the accepted cost is that those accounts have no recovery channel.
  db.exec(`
    CREATE TABLE users (
      subject         TEXT    PRIMARY KEY,
      username        TEXT    NOT NULL,
      username_folded TEXT    NOT NULL UNIQUE,
      password_hash   TEXT    NOT NULL,
      email           TEXT,
      email_verified  INTEGER NOT NULL DEFAULT 0 CHECK (email_verified IN (0, 1)),
      created_at      TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
      updated_at      TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
      disabled_at     TEXT,

      CHECK (username <> ''),
      CHECK (username_folded <> ''),
      -- An unverified address is fine; a verified NULL is a bug that would let
      -- a password-reset flow trust an address that was never collected.
      CHECK (email_verified = 0 OR email IS NOT NULL)
    ) STRICT
  `);

  // Login looks accounts up by folded username; the UNIQUE constraint above
  // already provides that index, so nothing extra is needed for it. This one
  // serves the console's "who has an unverified address" and the registration
  // path's "is this address already spoken for" queries.
  db.exec(`CREATE INDEX users_email_idx ON users (email) WHERE email IS NOT NULL`);

  // ---------------------------------------------------------------------
  // apps — the estate's relying parties. Registration is closed by default.
  // ---------------------------------------------------------------------
  //
  // `public_registration` defaults to 0 and the default is the whole point
  // (decisions-accounts.md, Q16). The alternative — registration open at Ward
  // with each app opting out — fails in the wrong direction: a newly added app
  // would be reachable by strangers until somebody remembered to close it. This
  // flag fails safe, so forgetting leaves the app unreachable rather than open.
  //
  // `baseline_role` is the single role a self-registering stranger receives,
  // and *only* that role — reaching any other app, or any higher role, requires
  // a grant the owner issues. The CHECK is the other half of failing safe: an
  // app cannot be opened to the public without stating what a stranger gets,
  // so "open" and "confers nothing / confers admin by omission" cannot coexist.
  db.exec(`
    CREATE TABLE apps (
      slug                TEXT    PRIMARY KEY,
      name                TEXT    NOT NULL,
      public_registration INTEGER NOT NULL DEFAULT 0 CHECK (public_registration IN (0, 1)),
      baseline_role       TEXT,
      created_at          TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
      updated_at          TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),

      -- Slugs appear in grant rows, in URLs and in six apps' configuration.
      -- Pinning them to lower case here stops 'Atrium' and 'atrium' becoming
      -- two apps that look like one.
      CHECK (slug <> '' AND slug = lower(slug)),
      CHECK (name <> ''),
      CHECK (baseline_role IS NULL OR baseline_role <> ''),
      CHECK (public_registration = 0 OR baseline_role IS NOT NULL)
    ) STRICT
  `);

  // ---------------------------------------------------------------------
  // grants — (subject, app, role). The security boundary of the estate.
  // ---------------------------------------------------------------------
  //
  // Holding a Ward account confers nothing. Without a row here for a given app,
  // a valid account cannot use that app at all — which is why the estate can
  // afford public registration at one app without exposing the other five.
  //
  // **This is a set, not a mapping.** The primary key is all three columns
  // together, never `(subject, app_slug)`: one person holds several roles in
  // one app, so every app's check is set membership rather than equality
  // (decisions-accounts.md, Q15). Making the triple the PRIMARY KEY is what
  // makes a duplicate impossible — the *database* rejects it, so an
  // application-code guard that someone forgets, or a race between two console
  // clicks that slips between a SELECT and an INSERT, cannot produce two
  // identical grants.
  //
  // **`role` is opaque and Ward never interprets it.** Ward knows the triple
  // `(cristian, prm, admin)`; it does not know what an admin may do, and that
  // line is load-bearing — putting the meaning of permissions here would mean
  // redeploying the identity service every time any of six apps grows a
  // capability. There is deliberately no roles table and no enum: a role is
  // whatever string the owning app decided it was.
  //
  // **There is no wildcard grant.** Even the owner account holds one explicit
  // row per app, so a newly added app is reachable by nobody until someone says
  // otherwise, and the six rows are six auditable facts.
  //
  // `granted_by` is TEXT with **no foreign key**, and that is the superuser
  // consequence spelled out at the top of this file: the identity that issues
  // the very first grants is the break-glass superuser, which has no `users`
  // row to reference. It holds a subject when an account issued the grant and
  // the sentinel `'superuser'` when the console did. `audit_log` carries the
  // full story; this column exists so the answer to "who granted this and when"
  // survives even if the log is ever pruned.
  //
  // It is **NOT NULL**, and that is the whole reason it exists: a NULL here is
  // a grant that answers "who granted this" with a shrug, which defeats the
  // sentence above it. There is always an answer — a subject when an account
  // issued it, and the `'superuser'` sentinel for the break-glass case, which
  // is exactly what that sentinel is for. Enforced in the schema rather than in
  // `../grants.ts` because a caller that forgets should fail, and a guard in
  // application code is a guard the next caller can skip.
  db.exec(`
    CREATE TABLE grants (
      subject    TEXT NOT NULL REFERENCES users (subject) ON DELETE CASCADE,
      app_slug   TEXT NOT NULL REFERENCES apps (slug) ON DELETE CASCADE,
      role       TEXT NOT NULL,
      granted_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
      granted_by TEXT NOT NULL,

      PRIMARY KEY (subject, app_slug, role),
      CHECK (role <> '')
    ) STRICT
  `);

  // Introspection answers "what are this session's grants" on every request
  // from every app, and it is the hot path — the PRIMARY KEY's leading column
  // is `subject`, so that lookup is already served. This index serves the other
  // direction, which is the console's: everyone who can reach a given app.
  db.exec(`CREATE INDEX grants_app_slug_idx ON grants (app_slug, role)`);

  // ---------------------------------------------------------------------
  // refresh_tokens — one row per issued refresh token. Rotation + families.
  // ---------------------------------------------------------------------
  //
  // **The token itself is never stored.** The column is `token_hash`, a SHA-256
  // hex digest of the opaque token (`../refresh-tokens.ts`). A refresh token is
  // a bearer credential with a 30-day life; storing it in plaintext means a read
  // of this file — a leaked backup, a stray `.sql` dump — is a login as every
  // account that has an unexpired session. SHA-256 with no salt or stretching is
  // the right primitive here and not a shortcut: the input is 256 bits of
  // `randomBytes`, so there is no dictionary to attack and nothing for a slow
  // KDF to buy. (Passwords are the opposite case, and use scrypt.)
  //
  // The hash is the PRIMARY KEY, which means lookup on presentation is the
  // index seek, and a duplicate hash is impossible by construction.
  //
  // **`family_id` is what makes reuse detection work.** Every token minted by
  // rotating an existing one inherits its family. Presenting a token whose
  // `used_at` is already set is a theft signal — the legitimate client and the
  // thief both hold descendants of the same root — and the response is to kill
  // the whole family, which is one indexed write:
  //
  //     UPDATE refresh_tokens
  //        SET revoked_at = ?, revoked_reason = 'reuse_detected'
  //      WHERE family_id = ? AND revoked_at IS NULL
  //
  // Killing the family rather than the presented token is the point: revoking
  // only the replayed token leaves whichever party stole it holding a live one.
  //
  // `used_at` and `revoked_at` are separate and both nullable because they
  // answer different questions. `used_at` records that this token was spent in
  // an ordinary rotation — normal, expected, and the thing reuse detection
  // tests. `revoked_at` records that it was killed. A token can be both: spent
  // legitimately, then revoked when its family was later burned down.
  //
  // `revoked_reason` exists so the console can tell an ordinary rotation from a
  // logout from an actual theft signal. Without it every dead row looks alike,
  // and the one event an operator most needs to see is invisible.
  db.exec(`
    CREATE TABLE refresh_tokens (
      token_hash     TEXT PRIMARY KEY,
      subject        TEXT NOT NULL REFERENCES users (subject) ON DELETE CASCADE,
      family_id      TEXT NOT NULL,
      issued_at      TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
      expires_at     TEXT NOT NULL,
      used_at        TEXT,
      revoked_at     TEXT,
      revoked_reason TEXT CHECK (
        revoked_reason IS NULL
        OR revoked_reason IN ('rotated', 'logout', 'reuse_detected', 'admin', 'expired')
      ),

      CHECK (token_hash <> ''),
      CHECK (family_id <> ''),
      -- A reason without a revocation is a writer that set one and forgot the
      -- other; the pair is what the console renders.
      CHECK ((revoked_at IS NULL) = (revoked_reason IS NULL))
    ) STRICT
  `);

  // The family sweep above, and the console's "kill every session for this
  // account", are both single indexed writes because of these two.
  db.exec(`CREATE INDEX refresh_tokens_family_idx ON refresh_tokens (family_id)`);
  db.exec(`CREATE INDEX refresh_tokens_subject_idx ON refresh_tokens (subject)`);
  // Expired rows are swept on a schedule rather than left to accumulate; a
  // 30-day token that is never presented again is otherwise immortal.
  db.exec(`CREATE INDEX refresh_tokens_expires_at_idx ON refresh_tokens (expires_at)`);

  // ---------------------------------------------------------------------
  // verification_tokens — the public registration and recovery path.
  // ---------------------------------------------------------------------
  //
  // Shape cribbed from `public-resource-map`'s `verification_token` and
  // `reset_token` tables, which already ship this flow: an id, the account it
  // belongs to, the token, an expiry, a single-use marker and a created stamp,
  // with the token unique and the account indexed.
  //
  // Two deliberate departures from prm's version:
  //
  //  1. **The token is hashed, not stored.** prm keeps the raw token in the
  //     row. It is a bearer credential mailed to an inbox, and one that grants
  //     a password reset is a login; the same argument as `refresh_tokens`
  //     applies, and there is no reason to make Ward's copy the weaker one.
  //  2. **One table with a `purpose`, not two near-identical tables.** prm's
  //     `verification_token` and `reset_token` differ only in what consuming
  //     them does. Collapsing them means the expiry sweep, the single-use
  //     check and the rate-limit query are each written once.
  //
  // `email` is the address the token was actually sent to, kept on the row
  // rather than read back from `users.email` at consumption time. That is what
  // makes "verify a change of address" expressible — the new address lives here
  // until it is confirmed, so `users.email` is never overwritten by an address
  // nobody has proved they can read — and it keeps the audit answer to "where
  // did this go" true even if the account's address changes afterwards.
  db.exec(`
    CREATE TABLE verification_tokens (
      id          TEXT NOT NULL PRIMARY KEY,
      subject     TEXT NOT NULL REFERENCES users (subject) ON DELETE CASCADE,
      purpose     TEXT NOT NULL CHECK (purpose IN ('email_verify', 'password_reset')),
      email       TEXT NOT NULL,
      token_hash  TEXT NOT NULL UNIQUE,
      expires_at  TEXT NOT NULL,
      consumed_at TEXT,
      created_at  TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),

      CHECK (email <> ''),
      CHECK (token_hash <> '')
    ) STRICT
  `);

  db.exec(`CREATE INDEX verification_tokens_subject_idx ON verification_tokens (subject, purpose)`);
  db.exec(`CREATE INDEX verification_tokens_expires_at_idx ON verification_tokens (expires_at)`);

  // ---------------------------------------------------------------------
  // audit_log — who did what to whom, and when. Append-only.
  // ---------------------------------------------------------------------
  //
  // The console (brief 10) renders this, and the question it has to answer is
  // "who granted this, and when" — so an actor, an action, a target and a
  // timestamp are the minimum, and `detail` carries whatever else the event
  // needs without a migration per event type.
  //
  // **Nothing in this table is a foreign key, and every part of that is
  // deliberate.** Two separate reasons, both of which would be undone by a
  // well-meaning later migration that "tightens" the schema:
  //
  //  1. The most important actor in this table — the superuser issuing the
  //     estate's first grants — has no `users` row to reference (see the top of
  //     this file). An FK on `actor_subject` makes the console's own actions
  //     unrecordable.
  //  2. An audit row must outlive what it describes. `grants` and
  //     `refresh_tokens` cascade away when an account is deleted, and they
  //     should; the record that the account *was* deleted, and by whom, is the
  //     one row that must survive it. An FK with any ON DELETE behaviour either
  //     destroys that record or blocks the delete.
  //
  // `id` is an INTEGER PRIMARY KEY — a rowid alias — because this is the one
  // table where insertion order is the ordering the reader wants and two events
  // in the same millisecond still need to be distinguishable. `at` is what the
  // console displays; `id` is what it pages on.
  //
  // `action` is an opaque dotted verb (`grant.create`, `user.disable`,
  // `session.revoke`, `superuser.login`). No enum and no CHECK: a new event type
  // must not need a migration, and the console renders unknown actions as
  // themselves rather than hiding them.
  db.exec(`
    CREATE TABLE audit_log (
      id            INTEGER PRIMARY KEY,
      at            TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
      actor_kind    TEXT NOT NULL CHECK (actor_kind IN ('superuser', 'account', 'system')),
      actor_subject TEXT,
      actor_label   TEXT NOT NULL,
      action        TEXT NOT NULL,
      target_kind   TEXT CHECK (
        target_kind IS NULL
        OR target_kind IN ('user', 'app', 'grant', 'session', 'token')
      ),
      target_id     TEXT,
      detail        TEXT,

      CHECK (action <> ''),
      CHECK (actor_label <> ''),
      -- Only an account has a subject. A 'superuser' or 'system' row carrying
      -- one would be claiming an account row exists for an identity that has
      -- none, which is the exact confusion decisions-admin.md exists to prevent.
      CHECK ((actor_subject IS NOT NULL) = (actor_kind = 'account')),
      CHECK ((target_id IS NULL) = (target_kind IS NULL))
    ) STRICT
  `);

  // Newest-first is the console's default view, and `id DESC` is the same order
  // as `at DESC` without depending on clock monotonicity.
  db.exec(`CREATE INDEX audit_log_at_idx ON audit_log (at DESC, id DESC)`);
  // "Everything this account did" and "everything that happened to this thing"
  // are the two filters the console offers.
  db.exec(`CREATE INDEX audit_log_actor_idx ON audit_log (actor_subject, id DESC)`);
  db.exec(`CREATE INDEX audit_log_target_idx ON audit_log (target_kind, target_id, id DESC)`);
}
