import type Database from "better-sqlite3";

/**
 * `app_keys` — the per-app service credential that turns `/introspect` from an
 * anonymous endpoint into an attributable one.
 *
 * ## Why this table exists at all
 *
 * `routes/introspect.ts` was written against the premise that the endpoint is
 * "not reachable from the internet in the deployed topology", and rests two
 * decisions on it: no client authentication, and no rate limit. The premise is
 * false. `vps-deploy/stacks/ward.ts` serves the whole API with
 * `handle_path /ward-api/*` on the public origin, so `POST /ward-api/introspect`
 * is reachable by anyone — and, as written, it would do an Ed25519 signature
 * verification plus three indexed reads for every anonymous caller that asked,
 * with nothing counting the asks.
 *
 * A key per app fixes the attributability half, which is the half that has to
 * come first: once every call carries a key, an anonymous caller is refused
 * **before** any crypto or database work happens, every call names the app that
 * made it, and one leaked app configuration is one `UPDATE` to contain instead
 * of a signing-key rotation that signs the whole estate out.
 *
 * It deliberately does **not** narrow what introspection returns — a keyed call
 * still gets the whole estate's grant map for that subject. Scoping the answer
 * to the calling app is the obvious next move and was considered and declined
 * for now; it changes the response contract that `@ward/client` and the app
 * integrations are built against, and it is a separate decision from "who is
 * allowed to ask".
 *
 * ## The key is never stored
 *
 * `key_hash` is `sha256(key)` in hex, exactly as `refresh_tokens.token_hash` is,
 * and for exactly the reason the baseline gives there: the input is 256 bits of
 * `randomBytes`, so there is no dictionary to attack and a slow KDF buys
 * nothing, but a leaked copy of `ward.db` must not be a working credential for
 * six apps. Passwords are the opposite case and stay on scrypt.
 *
 * `id` is the non-secret handle — 16 random bytes of hex, the same shape as a
 * refresh family id. It is what the console renders, what an audit row points
 * at, and what an operator names when revoking. The key itself is shown exactly
 * once, at creation, and is not recoverable afterwards.
 *
 * ## `last_used_at` is coarse on purpose
 *
 * This column is the difference between rotating a key safely and taking an app
 * down, so it earns its place — but `/introspect` is the hot path of the entire
 * estate, and a write per request would turn the credential table into a write
 * amplifier fed by ordinary traffic. `db/app-keys.ts` therefore stamps it at
 * most once an hour per key, throttled in process, so the common case is zero
 * writes. It answers "is this key still in use", which is the question a
 * rotation asks. It does not answer "when exactly was the last call", and must
 * not be read as if it did.
 *
 * ## `created_by` carries no foreign key
 *
 * The same superuser consequence the baseline spells out for
 * `grants.granted_by`: the identity that issues the estate's first app keys is
 * the break-glass superuser, which has no `users` row to point at. It holds the
 * `'superuser'` sentinel today and could hold a subject later.
 *
 * ## Deleting an app deletes its keys
 *
 * `ON DELETE CASCADE`, matching `grants`. Removing an app removes everyone's
 * access to it; leaving behind keys that authenticate as an app that no longer
 * exists would be a credential with no owner and no console page to find it on.
 */
export function up(db: Database.Database): void {
  db.exec(`
    CREATE TABLE app_keys (
      id           TEXT NOT NULL PRIMARY KEY,
      app_slug     TEXT NOT NULL REFERENCES apps (slug) ON DELETE CASCADE,

      -- What an operator reads on the console list to tell two keys for the
      -- same app apart: "atrium production", "atrium laptop". Not a secret and
      -- not an identifier — the id is the identifier.
      label        TEXT NOT NULL,

      -- sha256(key), hex. Never the key. UNIQUE so that lookup on presentation
      -- is an index seek and a duplicate is impossible by construction, the
      -- same shape as refresh_tokens.token_hash.
      key_hash     TEXT NOT NULL UNIQUE,

      created_at   TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
      created_by   TEXT NOT NULL,

      -- Coarse. See the header: stamped at most hourly, never per request.
      last_used_at TEXT,

      -- The estate's "has this happened yet" flag: answers when as well as
      -- whether. A revoked key is kept rather than deleted so that the audit
      -- trail still has a row to point at.
      revoked_at   TEXT,

      CHECK (id <> ''),
      CHECK (label <> ''),
      CHECK (created_by <> ''),
      -- A hex sha256 digest and nothing else. This is the column an
      -- authentication decision is made on, so a short or empty value must not
      -- be storable by hand.
      CHECK (length(key_hash) = 64)
    ) STRICT
  `);

  // The console's direction: every key for one app, newest first. Presentation
  // lookup goes through the UNIQUE index on key_hash and does not need this.
  db.exec(`CREATE INDEX app_keys_app_slug_idx ON app_keys (app_slug, created_at)`);
}
