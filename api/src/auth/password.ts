import { randomBytes, scrypt as scryptCallback, timingSafeEqual } from "node:crypto";
import { promisify } from "node:util";

/**
 * Password hashing and verification — `node:crypto` scrypt, no dependency.
 *
 * **scrypt rather than argon2id is a recorded decision**
 * (`corpus/wiki/decisions-implementation.md`, "node:crypto scrypt for
 * passwords, not argon2id"). The short version: argon2id is the better
 * primitive and resists GPU attack more strongly, but it is a native build, and
 * Ward's entire value is being the small service six apps can rely on staying
 * up — a native addon that fails to compile on a Node upgrade takes the whole
 * estate's login with it. Atrium already proves scrypt works here, and the full
 * prune means there are no existing hashes constraining the choice. Do not swap
 * this out without reopening that decision.
 *
 * Two hard rules for anything that edits this file:
 *
 *  1. **Every comparison goes through `timingSafeEqual`.** A `===` on two hex
 *     strings leaks the length of the matching prefix, one byte at a time, to
 *     anyone who can measure the response.
 *  2. **Never short-circuit before the KDF runs.** `verifyPassword` derives a
 *     key even when the stored value is unparseable, and `spendDummyHash`
 *     exists so the *unknown username* path costs the same as the wrong
 *     password path. Skipping the work when the answer is already known is
 *     exactly how a login endpoint becomes an account-enumeration oracle.
 */

const scrypt = promisify(scryptCallback) as (
  password: string | Buffer,
  salt: string | Buffer,
  keylen: number,
  options: { N: number; r: number; p: number; maxmem: number },
) => Promise<Buffer>;

/**
 * The scrypt work factors.
 *
 * `N = 2^14` at `r = 8` needs `128 * N * r` = 16 MiB of memory per hash and
 * lands around 40–70 ms on the VPS this runs on. That is the useful shape: slow
 * enough to make offline guessing expensive, fast enough that a login does not
 * hold a connection open long enough to become its own denial of service.
 *
 * `maxmem` is passed explicitly rather than left to default. Node's default is
 * 32 MiB, which `128 * N * r` sits *exactly* at for `N = 2^15` — so raising `N`
 * one notch without touching this line fails at runtime with an opaque OpenSSL
 * error rather than simply being slower. Naming a ceiling with headroom means
 * the next person to turn the dial gets a hash that works.
 *
 * **These parameters are not stored in the hash string.** The stored format is
 * `saltHex:hashHex` and nothing else, per the brief. The consequence is that
 * changing any constant below invalidates every existing hash: a stored value
 * derived at the old cost will simply stop matching, and the only migration
 * available is rehash-on-next-login (verify with the old parameters, then
 * `setPasswordHash` with the new ones). If that day comes, add a version prefix
 * to the format first — the parse below already rejects anything that is not
 * exactly two colon-separated fields, so a versioned value cannot be mistaken
 * for a valid one.
 */
const SCRYPT_N = 16_384;
const SCRYPT_R = 8;
const SCRYPT_P = 1;
const SCRYPT_MAXMEM = 64 * 1024 * 1024;

/** Derived key length in bytes. */
const KEY_BYTES = 64;

/** Per-password salt length in bytes. 128 bits from the OS CSPRNG. */
const SALT_BYTES = 16;

/**
 * The shortest password Ward will hash.
 *
 * Enforced at **hash** time, not at verify time — `verifyPassword` deliberately
 * has no length rule at all. A short submitted password cannot match any stored
 * hash anyway, so checking its length on the login path would only buy a
 * different error message while adding a branch that runs before the KDF.
 */
export const MIN_PASSWORD_LENGTH = 8;

/**
 * The longest password Ward will accept, in UTF-16 code units.
 *
 * scrypt's cost is dominated by `N` rather than by the input length, so this is
 * not about the KDF: it is about not copying a multi-megabyte request body into
 * a Buffer on an unauthenticated endpoint. 1024 is far past any real password
 * and far short of anything that costs measurable memory.
 */
export const MAX_PASSWORD_LENGTH = 1024;

/** Thrown by `hashPassword` for input that must never reach the database. */
export class PasswordPolicyError extends Error {
  /** A stable machine-readable code, so a route need not match on the message. */
  readonly code: "password_too_short" | "password_too_long";

  constructor(code: "password_too_short" | "password_too_long", message: string) {
    super(message);
    this.name = "PasswordPolicyError";
    this.code = code;
  }
}

/**
 * Hash a password for storage. Returns `saltHex:hashHex`.
 *
 * Throws `PasswordPolicyError` outside `MIN_PASSWORD_LENGTH ..
 * MAX_PASSWORD_LENGTH`. Brief 07 (registration) and any password-change route
 * are the callers; both should surface `error.code` rather than the message.
 *
 * The salt is fresh per call, which is why the same password hashed twice gives
 * two different values — and why a stolen `ward.db` cannot be attacked with one
 * precomputed table across every account at once.
 */
export async function hashPassword(password: string): Promise<string> {
  if (password.length < MIN_PASSWORD_LENGTH) {
    throw new PasswordPolicyError(
      "password_too_short",
      `password must be at least ${MIN_PASSWORD_LENGTH} characters`,
    );
  }
  if (password.length > MAX_PASSWORD_LENGTH) {
    throw new PasswordPolicyError(
      "password_too_long",
      `password must be at most ${MAX_PASSWORD_LENGTH} characters`,
    );
  }

  const salt = randomBytes(SALT_BYTES);
  const derived = await derive(password, salt);
  return `${salt.toString("hex")}:${derived.toString("hex")}`;
}

/**
 * Verify a password against a stored `saltHex:hashHex` value.
 *
 * **Always runs scrypt**, including when `stored` is not a value this module
 * produced — a fixture hash, a hand-edited row, a value from some future
 * versioned format. An unparseable stored value returns `false` after paying
 * the same cost as a real comparison, so "this account's hash is malformed" is
 * not something an attacker can time.
 *
 * Never throws for bad input. A login route wants an answer, not an exception
 * whose stack trace it then has to keep out of the log.
 */
export async function verifyPassword(password: string, stored: string): Promise<boolean> {
  const parsed = parseStored(stored);

  // A parse failure still gets a salt and an expected digest of the right
  // length, so the work below is identical either way. `parsed !== undefined`
  // is re-tested at the end rather than here so that no early `return` can
  // skip the KDF.
  const salt = parsed?.salt ?? randomBytes(SALT_BYTES);
  const expected = parsed?.hash ?? Buffer.alloc(KEY_BYTES);

  const actual = await derive(password, salt);

  // `timingSafeEqual` throws on a length mismatch rather than returning false,
  // so the lengths have to agree before it is called. Comparing lengths is not
  // a leak: the digest length is a constant of this module, not a secret.
  if (actual.length !== expected.length) {
    return false;
  }

  return timingSafeEqual(actual, expected) && parsed !== undefined;
}

/**
 * A stored-format value that no password matches, with a fresh random salt.
 *
 * Exported so a test can assert *structurally* that the unknown-username path
 * spends a hash, rather than relying on a wall-clock measurement.
 */
export const DUMMY_STORED_HASH: string = `${randomBytes(SALT_BYTES).toString(
  "hex",
)}:${"00".repeat(KEY_BYTES)}`;

/**
 * Spend a hash on a password that has no account to compare it against, and
 * return `false`.
 *
 * This is the whole defence against account enumeration by timing, and atrium
 * does the same thing. Without it, `POST /login` answers in under a millisecond
 * for a username that does not exist and in ~50 ms for one that does — which
 * means anyone with a wordlist can enumerate the estate's accounts from the
 * response time alone, with no error message to go on and nothing in the logs
 * that looks unusual.
 *
 * It derives a key over the *submitted* password with a random salt and then
 * fails a `timingSafeEqual` against a digest of the correct length, so the work
 * is byte-for-byte the work a real verification does.
 *
 * The return type is the literal `false` so a call site cannot accidentally
 * treat it as a credential check that might succeed.
 */
export async function spendDummyHash(password: string): Promise<false> {
  await verifyPassword(password, DUMMY_STORED_HASH);
  return false;
}

async function derive(password: string, salt: Buffer): Promise<Buffer> {
  // The password is passed as a string and encoded UTF-8 by the binding.
  // Deliberately NOT Unicode-normalised: normalising would change the hash of
  // every password containing a composed character, and this codebase has no
  // stored hashes to be compatible with in either direction. `foldUsername`
  // normalises the *username* because two usernames that look identical is a
  // real problem; two byte-different passwords are not.
  return scrypt(password, salt, KEY_BYTES, {
    N: SCRYPT_N,
    r: SCRYPT_R,
    p: SCRYPT_P,
    maxmem: SCRYPT_MAXMEM,
  });
}

interface ParsedHash {
  salt: Buffer;
  hash: Buffer;
}

/**
 * Split `saltHex:hashHex` into buffers, or `undefined` if it is not that.
 *
 * Strict on purpose: exactly two fields, both non-empty valid hex, and the
 * digest exactly `KEY_BYTES` long. `Buffer.from(s, "hex")` silently truncates
 * at the first non-hex character — `"zz"` parses as an empty buffer and
 * `"ab!cd"` as a single byte — so the round-trip length check below is what
 * actually rejects junk. Without it a stored value of `"z:z"` would produce two
 * empty buffers, and an empty-vs-empty `timingSafeEqual` returns **true**:
 * every password would match.
 */
function parseStored(stored: string): ParsedHash | undefined {
  const parts = stored.split(":");
  if (parts.length !== 2) return undefined;

  const [saltHex, hashHex] = parts as [string, string];
  const salt = fromHex(saltHex);
  const hash = fromHex(hashHex);
  if (salt === undefined || hash === undefined) return undefined;
  if (salt.length === 0 || hash.length !== KEY_BYTES) return undefined;

  return { salt, hash };
}

/** `Buffer.from(value, "hex")`, but `undefined` rather than a silent truncation. */
function fromHex(value: string): Buffer | undefined {
  const buffer = Buffer.from(value, "hex");
  return buffer.length * 2 === value.length ? buffer : undefined;
}
