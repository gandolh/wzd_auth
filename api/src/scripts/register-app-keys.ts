import { randomBytes } from "node:crypto";
import { readFileSync, readdirSync, existsSync } from "node:fs";
import { join, resolve } from "node:path";

import { openDatabase } from "../db/connection.js";
import { runMigrations } from "../db/migrate.js";
import { createApp, getApp } from "../db/apps.js";
import { hashAppKey, looksLikeAppKey } from "../db/app-keys.js";

/**
 * `npm run register-app-keys` — adopt app keys that already exist elsewhere.
 *
 * ## Why this exists, and why it is not the normal path
 *
 * The normal path is the console: an operator mints a key, Ward shows it once,
 * and it is pasted into that app's deploy secrets. `createAppKey` mints its own
 * value precisely so that no caller can register a key Ward did not generate —
 * which is the right default, because a key chosen elsewhere is a key whose
 * entropy Ward cannot vouch for.
 *
 * That default has one gap, and it is the situation the estate is actually in:
 * **the console requires a running Ward, and the deploy requires the keys.**
 * `vps-deploy` refuses to bring an app up without `WARD_APP_KEY`, so a cold
 * start needs the keys to exist before the console that would mint them does.
 * This command closes that loop, once, and is expected to be unnecessary
 * afterwards.
 *
 * It is deliberately narrow about what it will accept:
 *
 *   • the value must look like a Ward key (`wak_` + material), so a placeholder
 *     or a truncated paste is refused rather than stored;
 *   • only `sha256(key)` is written, exactly as the console path does — this
 *     script does not make the plaintext any more persistent than it already is;
 *   • an app that already has a live key with the same digest is left alone, so
 *     re-running is safe.
 *
 * ## Usage
 *
 *   node api/dist/scripts/register-app-keys.js --from ../vps-deploy/secrets
 *   node api/dist/scripts/register-app-keys.js atrium=wak_… prm=wak_…
 *
 * `--from <dir>` reads every `<stack>.env` in a vps-deploy secrets directory and
 * takes its `WARD_APP_KEY`. The stack name is mapped to the app slug by
 * `SLUG_FOR_STACK` below, because two of them disagree: the deploy calls prm's
 * stack `public-resource-map` while Ward's app slug is `prm`.
 */

/** The deploy's stack name → Ward's `apps.slug`, where the two differ. */
const SLUG_FOR_STACK: Record<string, string> = {
  "public-resource-map": "prm",
};

/** Display names for apps this script has to create because they are absent. */
const NAME_FOR_SLUG: Record<string, string> = {
  atrium: "Atrium",
  prm: "Public Resource Map",
  "sports-app": "sports-app",
  "imbatranim-os": "ImbatranimOS",
  newspapper: "Newspapper",
};

interface Pair {
  slug: string;
  key: string;
  source: string;
}

function envValue(text: string, key: string): string | undefined {
  for (const line of text.split(/\r?\n/)) {
    const trimmed = line.trim();
    if (trimmed.startsWith("#")) continue;
    const eq = trimmed.indexOf("=");
    if (eq === -1) continue;
    if (trimmed.slice(0, eq).trim() !== key) continue;
    return trimmed.slice(eq + 1).trim().replace(/^["']|["']$/g, "");
  }
  return undefined;
}

function pairsFromSecretsDir(dir: string): Pair[] {
  const out: Pair[] = [];
  for (const file of readdirSync(dir).sort()) {
    if (!file.endsWith(".env") || file === "vps.env") continue;
    const stack = file.slice(0, -".env".length);
    const key = envValue(readFileSync(join(dir, file), "utf8"), "WARD_APP_KEY");
    if (!key) continue;
    out.push({ slug: SLUG_FOR_STACK[stack] ?? stack, key, source: file });
  }
  return out;
}

function main(): void {
  const argv = process.argv.slice(2);
  const pairs: Pair[] = [];

  for (let i = 0; i < argv.length; i++) {
    const arg = argv[i]!;
    if (arg === "--from") {
      const dir = resolve(argv[++i] ?? "");
      if (!existsSync(dir)) throw new Error(`No such secrets directory: ${dir}`);
      pairs.push(...pairsFromSecretsDir(dir));
      continue;
    }
    const eq = arg.indexOf("=");
    if (eq === -1) throw new Error(`Expected <slug>=<key> or --from <dir>, got "${arg}".`);
    pairs.push({ slug: arg.slice(0, eq), key: arg.slice(eq + 1), source: "argv" });
  }

  if (pairs.length === 0) {
    throw new Error("Nothing to register. Pass --from <secrets dir> or <slug>=<key> pairs.");
  }

  const db = openDatabase(process.env.WARD_DB_PATH ?? "api/data/ward.db");
  runMigrations(db);

  const insert = db.prepare(
    `INSERT INTO app_keys (id, app_slug, label, key_hash, created_by)
     VALUES (?, ?, ?, ?, ?)`,
  );
  const liveWithHash = db.prepare<[string, string]>(
    `SELECT id FROM app_keys WHERE app_slug = ? AND key_hash = ? AND revoked_at IS NULL`,
  );

  for (const { slug, key, source } of pairs) {
    if (!looksLikeAppKey(key)) {
      console.error(`✗ ${slug}: not a Ward app key (expected a "wak_" prefix) — from ${source}`);
      process.exitCode = 1;
      continue;
    }

    if (!getApp(db, slug)) {
      createApp(db, { slug, name: NAME_FOR_SLUG[slug] ?? slug });
      console.log(`  created app "${slug}"`);
    }

    const digest = hashAppKey(key);
    if (liveWithHash.get(slug, digest)) {
      console.log(`= ${slug}: already registered — left alone`);
      continue;
    }

    insert.run(randomBytes(16).toString("hex"), slug, `bootstrap (${source})`, digest, "register-app-keys");
    // The plaintext is never printed: it already lives in the deploy secrets and
    // in the app's environment, and a third copy in a terminal scrollback is a
    // third place it can leak from.
    console.log(`✓ ${slug}: registered ${key.slice(0, 12)}…`);
  }

  db.close();
}

try {
  main();
} catch (err) {
  console.error(`register-app-keys: ${(err as Error).message}`);
  process.exit(1);
}
