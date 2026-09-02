import { readFile } from "node:fs/promises";
import { createPrivateKey, createPublicKey, type KeyObject } from "node:crypto";
import { basename, dirname, extname, join } from "node:path";
import { calculateJwkThumbprint } from "jose";
import type { JSONWebKeySet, JWK } from "jose";
import { ACCESS_TOKEN_ALG, SIGNING_KEY_CURVE } from "./claims.js";

/**
 * Loading Ward's Ed25519 signing keys off disk, and deriving the public JWKS
 * from them.
 *
 * ## Ward never generates a key on its own, in any environment
 *
 * A missing or unreadable key file is a hard boot failure everywhere — there is
 * no development shortcut that quietly creates one. The reason is the failure
 * mode of the alternative: a key that regenerates on restart invalidates every
 * live token in the estate at once, which does not look like "a new key", it
 * looks like an outage, and it looks like an outage that recurs on every deploy
 * without anyone ever changing the code that causes it. Refusing to start is
 * loud, immediate and unambiguous; the operator reads one line and runs
 * `npm run keygen`. Creating a key is an explicit human act, once, and the
 * result gets backed up (see `keygen.ts`).
 *
 * Note there is no `NODE_ENV` branch here and there is not meant to be one.
 * `config.ts` deliberately has no notion of environment (brief 00), and a rule
 * that is the same everywhere cannot be got wrong by being deployed with the
 * wrong flag set.
 *
 * ## Private material cannot reach the JWKS
 *
 * The published JWKS is not filtered out of the private key — it is built from
 * a *separate* `node:crypto` public `KeyObject`, whose `export({format:"jwk"})`
 * has no `d` parameter to leak in the first place, and then each JWK is
 * assembled field by field from an explicit allowlist rather than by spreading
 * anything. `assertPublicJwk` is the belt to that pair of braces and throws at
 * load time — at boot, not at request time — if a private parameter ever
 * appears. The route (`routes/jwks.ts`) is never handed a `WardSigningKey` at
 * all; it only ever sees the frozen `JSONWebKeySet`.
 *
 * ## Key rotation — the procedure
 *
 * The JWKS publishes up to two keys: **current** (which signs) and **previous**
 * (which only verifies). That is what makes a rotation not sign the estate out:
 * tokens minted by the old key stay verifiable until they expire on their own.
 *
 * The previous key lives at a path *derived* from `WARD_SIGNING_KEY_PATH` —
 * `signing-key.pem` implies `signing-key.previous.pem` beside it — rather than
 * in a second environment variable. `config.ts` is brief 00's contract and this
 * brief does not get to add to it; a naming convention also means a rotation is
 * three file operations on the server with no `.env` edit and no pm2 env
 * reload, which is one fewer thing to get wrong at the point of highest risk.
 *
 * To rotate:
 *
 * 1. `mv api/data/signing-key.pem api/data/signing-key.previous.pem`
 * 2. `npm run keygen` — writes a fresh current key. (It refuses to overwrite,
 *    which is why step 1 comes first and why no `--force` is needed here.)
 * 3. Restart Ward. New tokens are signed by the new key; both keys are
 *    published, so tokens signed by the old one still verify.
 * 4. **Wait at least one access-token lifetime — 15 minutes** (see
 *    `ACCESS_TOKEN_TTL_SECONDS`). After that no unexpired token anywhere in the
 *    estate was signed by the old key. In practice wait longer than the
 *    strict minimum, because `@ward/client` caches the JWKS: an app that
 *    fetched the key set before step 3 keeps using it for its cache window.
 * 5. `rm api/data/signing-key.previous.pem` and restart. The JWKS drops back to
 *    one key.
 *
 * Dropping the previous key earlier than step 4's window is the mistake that
 * signs people out; leaving it in place indefinitely is merely untidy, and is
 * the safe direction to err in.
 */

/** Thrown for every failure in this module. Its message is written to be read by an operator. */
export class SigningKeyError extends Error {
  override readonly name = "SigningKeyError";

  constructor(message: string, options?: { cause?: unknown }) {
    super(message, options);
  }
}

/** One loaded key: the private half for signing, the public half as a JWK, and their shared `kid`. */
export interface WardSigningKey {
  /**
   * RFC 7638 JWK thumbprint of the public key, base64url. Derived from the key
   * material itself, so it is stable across restarts, identical in every
   * process that loads the same file, and impossible to get out of sync with
   * the key it names. A counter or a timestamp would have none of those
   * properties.
   */
  readonly kid: string;
  /** Node `KeyObject`. `jose` accepts it directly as a signing key. Never leaves this process. */
  readonly privateKey: KeyObject;
  /** The published form. Public parameters only — see `assertPublicJwk`. */
  readonly publicJwk: JWK;
}

/** The keys Ward is running with: one signer, and up to one extra verifier during a rotation. */
export interface WardKeySet {
  /** The key that signs. Always present. */
  readonly current: WardSigningKey;
  /** Present only during a rotation; verifies, never signs. */
  readonly previous?: WardSigningKey;
  /**
   * Exactly what `GET /.well-known/jwks.json` serves, deep-frozen. Current
   * first, then previous. Contains public parameters only, by construction.
   */
  readonly jwks: JSONWebKeySet;
}

/**
 * Where the previous key lives, given the current key's path: `.previous`
 * inserted before the extension, in the same directory.
 *
 * `/data/signing-key.pem` → `/data/signing-key.previous.pem`
 * `/data/signing-key`     → `/data/signing-key.previous`
 */
export function previousSigningKeyPath(currentPath: string): string {
  const ext = extname(currentPath);
  const stem = basename(currentPath, ext);
  return join(dirname(currentPath), `${stem}.previous${ext}`);
}

/**
 * The only JWK parameters Ward ever publishes.
 *
 * An allowlist rather than a denylist, because a denylist has to be kept in
 * step with every private parameter every key type might ever add (`d`, `k`,
 * `p`, `q`, `dp`, `dq`, `qi`, `priv`, …) and is wrong the first time it is not.
 */
const PUBLIC_JWK_PARAMETERS = ["kty", "crv", "x", "alg", "use", "kid"] as const;

/**
 * Refuse to publish anything that is not exactly a public Ed25519 JWK.
 *
 * This is a boot-time assertion on a value that was already constructed to be
 * safe. It is here because the cost of it firing is a service that does not
 * start, and the cost of it being absent, once, is Ward's private key served
 * over HTTP to anything that asks — which is not a bug that gets noticed by
 * anyone friendly.
 */
function assertPublicJwk(jwk: Record<string, unknown>): void {
  for (const key of Object.keys(jwk)) {
    if (!(PUBLIC_JWK_PARAMETERS as readonly string[]).includes(key)) {
      throw new SigningKeyError(
        `refusing to publish a JWK carrying an unexpected parameter "${key}" — only ` +
          `${PUBLIC_JWK_PARAMETERS.join(", ")} may ever appear in Ward's JWKS`,
      );
    }
  }
  if (jwk["kty"] !== "OKP" || jwk["crv"] !== SIGNING_KEY_CURVE) {
    throw new SigningKeyError(
      `refusing to publish a JWK that is not a public ${SIGNING_KEY_CURVE} key ` +
        `(got kty=${String(jwk["kty"])}, crv=${String(jwk["crv"])})`,
    );
  }
  if (typeof jwk["x"] !== "string" || jwk["x"].length === 0) {
    throw new SigningKeyError("refusing to publish a JWK with no public key parameter");
  }
}

/**
 * Parse one PEM into a `WardSigningKey`.
 *
 * `label` names the file in every error, because "the signing key is broken" is
 * a much worse thing to read at 2am than "the previous signing key is broken".
 */
async function toSigningKey(pem: string, path: string, label: string): Promise<WardSigningKey> {
  let privateKey: KeyObject;
  try {
    privateKey = createPrivateKey(pem);
  } catch (cause) {
    throw new SigningKeyError(
      `${label} at ${path} is not a readable private key. Ward signs with a PKCS#8 ` +
        `Ed25519 private key in PEM form ("-----BEGIN PRIVATE KEY-----"). ` +
        `Create one with: npm run keygen`,
      { cause },
    );
  }

  if (privateKey.asymmetricKeyType !== "ed25519") {
    throw new SigningKeyError(
      `${label} at ${path} is a ${privateKey.asymmetricKeyType ?? "non-asymmetric"} key, but ` +
        `Ward signs with ${SIGNING_KEY_CURVE} only (EdDSA — see wiki/decisions-tokens.md, ` +
        `"Only Ward can sign"). Replace the file with an Ed25519 key: npm run keygen`,
    );
  }

  // Derive the public half as its own KeyObject and export *that*. This is the
  // step that makes leaking `d` structurally impossible rather than merely
  // unlikely: the object being exported does not contain a private key.
  const exported = createPublicKey(privateKey).export({ format: "jwk" }) as Record<string, unknown>;

  const kid = await calculateJwkThumbprint({
    kty: "OKP",
    crv: String(exported["crv"]),
    x: String(exported["x"]),
  });

  // Assembled field by field from the allowlist. Never `...exported`.
  const publicJwk: Record<string, unknown> = {
    kty: exported["kty"],
    crv: exported["crv"],
    x: exported["x"],
    // `alg` and `use` are what let `createLocalJWKSet` refuse to hand this key
    // to anything but an EdDSA signature check — a second, independent barrier
    // against the HMAC-confusion attack alongside the pinned `algorithms` list.
    alg: ACCESS_TOKEN_ALG,
    use: "sig",
    kid,
  };
  assertPublicJwk(publicJwk);

  return Object.freeze({ kid, privateKey, publicJwk: Object.freeze(publicJwk) as JWK });
}

/**
 * Read one key file, converting the interesting `fs` failures into messages
 * that name the fix. "ENOENT" on its own has cost somebody an hour before.
 */
async function readKeyFile(path: string, label: string): Promise<string> {
  try {
    return await readFile(path, "utf8");
  } catch (cause) {
    const code = (cause as NodeJS.ErrnoException).code;
    if (code === "ENOENT") {
      throw new SigningKeyError(
        `${label} not found at ${path}.\n\n` +
          `Ward refuses to start without one, and never generates one for you — a key that\n` +
          `appears on restart invalidates every access token in the estate and reads as an\n` +
          `outage. Create it once, deliberately:\n\n` +
          `    npm run keygen\n\n` +
          `The file is gitignored. Back it up somewhere that is not this repository.`,
        { cause },
      );
    }
    if (code === "EACCES" || code === "EPERM") {
      throw new SigningKeyError(
        `${label} at ${path} exists but cannot be read by this process (${code}). ` +
          `The key should be mode 0600 and owned by the user Ward runs as.`,
        { cause },
      );
    }
    if (code === "EISDIR") {
      throw new SigningKeyError(
        `${label} path ${path} is a directory, not a key file. Check WARD_SIGNING_KEY_PATH.`,
        { cause },
      );
    }
    throw new SigningKeyError(`${label} at ${path} could not be read.`, { cause });
  }
}

/**
 * Load the key set from disk. Pure with respect to Ward's configuration — it
 * takes the path, so tests and `keygen` can drive it without importing
 * `config.js` and triggering its `process.exit`.
 *
 * The current key is required. The previous key is loaded only if its file
 * exists, and if it exists it must be valid: a rotation half-done is a state an
 * operator needs told about, not one to shrug off.
 */
export async function loadKeySet(currentPath: string): Promise<WardKeySet> {
  const current = await toSigningKey(
    await readKeyFile(currentPath, "Ward's signing key"),
    currentPath,
    "Ward's signing key",
  );

  const previousPath = previousSigningKeyPath(currentPath);
  let previous: WardSigningKey | undefined;
  try {
    previous = await toSigningKey(
      await readFile(previousPath, "utf8"),
      previousPath,
      "Ward's previous signing key",
    );
  } catch (err) {
    if ((err as NodeJS.ErrnoException).code !== "ENOENT") {
      if (err instanceof SigningKeyError) throw err;
      throw new SigningKeyError(
        `Ward's previous signing key at ${previousPath} exists but could not be read. ` +
          `Remove it to publish only the current key, or fix its permissions.`,
        { cause: err },
      );
    }
    // No previous key: the ordinary steady state, not a rotation. Nothing to say.
  }

  // A previous key identical to the current one would put two entries with the
  // same `kid` in the JWKS, and `createLocalJWKSet` requires exactly one match —
  // every verification in the estate would fail with "multiple matching keys".
  // Almost certainly a `cp` where step 1 of the rotation wanted a `mv`.
  if (previous && previous.kid === current.kid) {
    throw new SigningKeyError(
      `Ward's previous signing key at ${previousPath} is the same key as the current one ` +
        `(kid ${current.kid}). Publishing it twice would make every JWKS lookup ambiguous. ` +
        `Delete it, or complete the rotation with a genuinely new current key.`,
    );
  }

  const keys = previous ? [current.publicJwk, previous.publicJwk] : [current.publicJwk];
  const jwks: JSONWebKeySet = Object.freeze({ keys: Object.freeze(keys) as JWK[] });

  return Object.freeze({ current, previous, jwks });
}
