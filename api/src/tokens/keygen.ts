import { generateKeyPairSync } from "node:crypto";
import { chmod, mkdir, stat, writeFile } from "node:fs/promises";
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
  /**
   * The permission bits `stat` reports **after** writing — the ones actually on
   * the inode, not the ones that were asked for. Should be `0o600`; anything
   * else is a fact the operator has to be told rather than one to smooth over.
   */
  mode: number;
}

/**
 * Write a fresh Ed25519 private key in PKCS#8 PEM form.
 *
 * Created with `wx` unless `force`, so refusing to overwrite is the filesystem's
 * atomic guarantee rather than a check-then-write race. Mode 0600 from the
 * moment the file exists: it is never briefly world-readable.
 *
 * **`writeFile`'s `mode` applies only when the file is created**, which made
 * `--force` unable to tighten anything: a forced overwrite dropped fresh
 * private key bytes into whatever permissions the existing file already had,
 * and the CLI printed `0600` regardless. The realistic sequence is an operator
 * restoring the key from a backup or a `cp` under umask 022 — 0644 — and then
 * running `npm run keygen -- --force`; the loader never checked either, so
 * every other local account on the box could read Ward's signing key and mint
 * EdDSA tokens for any subject that all six verifiers would accept. So the
 * mode is set **explicitly after the write, on both paths**, and then read back
 * off the inode so the caller reports what is true rather than what was
 * intended. (`keys.loadKeySet` now also warns at boot on a key that is group-
 * or world-accessible, which is the other half of the same hole.)
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

  // Not conditional on `force`: on the create path it is a no-op, and on the
  // overwrite path it is the only thing that tightens an inode that already
  // existed. Cheap either way, and it removes the branch that was the bug.
  try {
    await chmod(path, 0o600);
  } catch (cause) {
    throw new SigningKeyError(
      `wrote a signing key to ${path} but could not set its permissions to 0600. ` +
        `Fix it by hand before starting Ward: chmod 600 ${path}`,
      { cause },
    );
  }

  // Read it back through the ordinary loader. If the file Ward is about to
  // depend on cannot be loaded by the code that will load it, the operator
  // should find out now and not at the next restart.
  const keySet = await loadKeySet(path);
  const mode = (await stat(path)).mode & 0o777;
  return { path, kid: keySet.current.kid, mode };
}

/** `0600`, for a banner. */
function formatMode(mode: number): string {
  return `0${mode.toString(8).padStart(3, "0")}`;
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
    const { kid, mode } = await generateSigningKeyFile(path, { force });
    // The observed mode, never a constant. Printing `0600` unconditionally is
    // what let a 0644 key look hardened.
    const modeWarning =
      mode === 0o600
        ? ""
        : `\n  !! WARNING: the key file is mode ${formatMode(mode)}, NOT 0600.\n` +
          `  !! Ward's private signing key is readable or writable by another account\n` +
          `  !! on this machine, which is enough to mint tokens for any subject.\n` +
          `  !! Fix it now:  chmod 600 ${path}\n`;
    process.stdout.write(
      `\nWard signing key written.\n\n` +
        `  path : ${path}\n` +
        `  kid  : ${kid}\n` +
        `  mode : ${formatMode(mode)}\n` +
        modeWarning +
        `\n` +
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
