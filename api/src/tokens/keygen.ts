import { generateKeyPairSync } from "node:crypto";
import { mkdir, writeFile } from "node:fs/promises";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { loadKeySet, previousSigningKeyPath, SigningKeyError } from "./keys.js";

/**
 * `npm run keygen` — create Ward's Ed25519 signing key. Once, on purpose, by a
 * human.
 *
 * This exists because `keys.ts` refuses to generate a key implicitly in any
 * environment. A key that appears by itself on restart invalidates every access
 * token in the estate simultaneously, which does not present as "a new key" but
 * as six apps logging everyone out for no visible reason, on a schedule nobody
 * wrote down. So generation is separated from running: this command is the only
 * thing in the repository that can bring a signing key into existence.
 *
 * Usage:
 *
 *     npm run keygen                      # writes to WARD_SIGNING_KEY_PATH
 *     npm run keygen -- /path/to/key.pem  # writes to an explicit path
 *     npm run keygen -- --force           # overwrite an existing key (see below)
 *
 * With no path argument it reads `WARD_SIGNING_KEY_PATH` from the environment
 * via `config.js`, which means the usual `.env` has to be complete. That is
 * deliberate — the key belongs at the path the running service will look in,
 * and a key written somewhere else is a key that does not work. Pass a path
 * explicitly when there is no `.env` yet.
 *
 * **It refuses to overwrite.** `--force` exists for the one case where an
 * operator genuinely means to destroy the estate's current signing key, and it
 * still prints what it is about to do. Overwriting the live key signs out every
 * account in every app at once, with no way back — the *rotation* procedure in
 * `keys.ts` exists precisely so that replacing a key never has to do that.
 */

export interface GenerateSigningKeyResult {
  /** Absolute path written. */
  path: string;
  /** RFC 7638 thumbprint of the new key — the `kid` that will appear in the JWKS. */
  kid: string;
}

/**
 * Write a fresh Ed25519 private key in PKCS#8 PEM form.
 *
 * Created with `wx` unless `force`, so refusing to overwrite is the filesystem's
 * atomic guarantee rather than a check-then-write race. Mode 0600 from the
 * moment the file exists: it is never briefly world-readable.
 */
export async function generateSigningKeyFile(
  path: string,
  options: { force?: boolean } = {},
): Promise<GenerateSigningKeyResult> {
  const { privateKey } = generateKeyPairSync("ed25519");
  const pem = privateKey.export({ type: "pkcs8", format: "pem" }) as string;

  await mkdir(dirname(path), { recursive: true });
  try {
    await writeFile(path, pem, { encoding: "utf8", mode: 0o600, flag: options.force ? "w" : "wx" });
  } catch (cause) {
    if ((cause as NodeJS.ErrnoException).code === "EEXIST") {
      throw new SigningKeyError(
        `refusing to overwrite the existing signing key at ${path}.\n\n` +
          `Replacing a live signing key invalidates every access token in the estate at once.\n` +
          `To ROTATE without signing anyone out:\n\n` +
          `    mv ${path} ${previousSigningKeyPath(path)}\n` +
          `    npm run keygen\n` +
          `    # restart Ward; wait at least 15 minutes; then remove the .previous key\n\n` +
          `If you really do mean to destroy this key, pass --force.`,
        { cause },
      );
    }
    throw new SigningKeyError(`could not write a signing key to ${path}.`, { cause });
  }

  // Read it back through the ordinary loader. If the file Ward is about to
  // depend on cannot be loaded by the code that will load it, the operator
  // should find out now and not at the next restart.
  const keySet = await loadKeySet(path);
  return { path, kid: keySet.current.kid };
}

async function main(argv: string[]): Promise<number> {
  const force = argv.includes("--force");
  const positional = argv.filter((arg) => !arg.startsWith("--"));

  let path: string;
  if (positional.length > 0) {
    path = resolve(process.cwd(), positional[0] as string);
  } else {
    // Dynamic, so that `--help`-ish misuse and the explicit-path form do not
    // require a complete `.env` just to be told what went wrong.
    const { WARD_SIGNING_KEY_PATH } = await import("../config.js");
    path = WARD_SIGNING_KEY_PATH;
  }

  try {
    const { kid } = await generateSigningKeyFile(path, { force });
    process.stdout.write(
      `\nWard signing key written.\n\n` +
        `  path : ${path}\n` +
        `  kid  : ${kid}\n` +
        `  mode : 0600\n\n` +
        `This is the estate's ONLY signing key. Every access token for every app is\n` +
        `signed with it, and the public half is served at /.well-known/jwks.json.\n\n` +
        `  * It is gitignored (*.pem, *.key, api/data/) and must stay that way.\n` +
        `  * Back it up SEPARATELY from the repository, somewhere you would still\n` +
        `    have after losing this machine. There is no way to recreate it, and a\n` +
        `    replacement signs every account in the estate out at once.\n` +
        `  * Never copy it into an app. Apps verify with the public key; only Ward\n` +
        `    signs (wiki/decisions-tokens.md).\n\n`,
    );
    return 0;
  } catch (err) {
    process.stderr.write(
      `\nkeygen failed.\n\n${err instanceof Error ? err.message : String(err)}\n\n`,
    );
    return 1;
  }
}

// Run only when executed directly (`tsx src/tokens/keygen.ts`), never on import —
// tests import `generateSigningKeyFile` from here.
if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  process.exitCode = await main(process.argv.slice(2));
}
